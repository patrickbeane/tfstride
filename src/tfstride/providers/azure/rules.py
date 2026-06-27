from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import (
    RuleContribution,
    RuleDetector,
    RuleEvaluationContext,
    build_rule_contribution,
)
from tfstride.analysis.rule_registry import RuleRegistry, default_rule_registry
from tfstride.models import BoundaryType, Finding
from tfstride.providers.azure.app_service_rules import AzureAppServiceRuleDetectors
from tfstride.providers.azure.key_vault_rules import AzureKeyVaultRuleDetectors
from tfstride.providers.azure.mssql_rules import AzureMssqlRuleDetectors
from tfstride.providers.azure.postgresql_rules import AzurePostgresqlRuleDetectors
from tfstride.providers.azure.private_endpoint_rules import AzurePrivateEndpointPostureRuleDetectors
from tfstride.providers.azure.rbac_rules import AzureCustomRoleRuleDetectors
from tfstride.providers.azure.resource_decoration.public_exposure import is_risky_public_compute_path
from tfstride.providers.azure.resource_facts import AzureResourceFacts, azure_facts
from tfstride.providers.azure.resource_types import AZURE_COMPUTE_RESOURCE_TYPES, AzureResourceType
from tfstride.providers.azure.resource_utils import azure_reference_key, azure_resource_references

AZURE_RULE_GROUP_IDS: tuple[tuple[str, ...], ...] = (
    (
        "azure-public-compute-broad-ingress",
        "azure-storage-container-public-access",
        "azure-storage-account-nested-public-access-enabled",
        "azure-storage-account-shared-key-enabled",
        "azure-storage-account-minimum-tls-below-1-2",
        "azure-storage-account-public-network-unrestricted",
        "azure-storage-account-missing-private-endpoint",
        "azure-key-vault-public-network-access",
        "azure-key-vault-missing-private-endpoint",
        "azure-key-vault-privileged-access",
        "azure-key-vault-purge-protection-disabled",
        "azure-custom-role-wildcard-management-plane",
        "azure-custom-role-authorization-management",
        "azure-custom-role-broad-management-plane",
        "azure-custom-role-broad-data-plane",
        "azure-custom-role-subscription-assignable-scope",
        "azure-managed-identity-broad-rbac",
        "azure-public-workload-sensitive-resource-access",
        "azure-app-service-public-network-access-not-disabled",
        "azure-app-service-minimum-tls-below-1-2",
        "azure-app-service-minimum-tls-unknown",
        "azure-app-service-managed-identity-missing",
        "azure-app-service-vnet-integration-missing",
        "azure-sql-public-network-access-enabled",
        "azure-sql-missing-private-endpoint",
        "azure-sql-firewall-broad-public-access",
        "azure-sql-minimum-tls-below-1-2",
        "azure-sql-security-alert-policy-disabled",
        "azure-private-endpoint-public-fallback",
        "azure-postgresql-public-network-access-enabled",
        "azure-postgresql-firewall-broad-public-access",
        "azure-postgresql-weak-tls-or-ssl",
        "azure-postgresql-geo-backup-disabled",
    ),
    (),
    (),
    (),
    (),
    (),
)


class AzureComputeRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_compute_broad_ingress(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for virtual_machine in context.inventory.by_type(*AZURE_COMPUTE_RESOURCE_TYPES):
            facts = azure_facts(virtual_machine)
            risky_paths = [path for path in facts.public_compute_exposure_paths if is_risky_public_compute_path(path)]
            if not virtual_machine.public_exposure or not risky_paths:
                continue
            boundary = context.boundary_index.get(
                (BoundaryType.INTERNET_TO_SERVICE, "internet", virtual_machine.address)
            )
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=1,
            )
            network_interfaces = _path_values(risky_paths, "network_interfaces")
            public_ip_resources = _path_values(risky_paths, "public_ip_resources")
            public_ips = _path_values(risky_paths, "public_ips")
            network_security_groups = _path_values(risky_paths, "network_security_groups")
            network_security_rules = _path_values(risky_paths, "network_security_rules")
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            virtual_machine.address,
                            *network_interfaces,
                            *public_ip_resources,
                            *network_security_groups,
                        ]
                    ),
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{virtual_machine.display_name} has a public-IP path and the effective Azure NSG "
                        "decisions across its subnet and network interface permit administrative access or "
                        "all ports from internet sources. This exposes the guest to direct probing and "
                        "credential attacks."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "public_ip_path",
                            _public_ip_path_evidence(virtual_machine.address, network_interfaces, public_ips),
                        ),
                        evidence_item(
                            "network_security_path",
                            _network_security_path_evidence(
                                virtual_machine.address,
                                network_interfaces,
                                network_security_groups,
                            ),
                        ),
                        evidence_item("network_security_rules", network_security_rules),
                        evidence_item("public_exposure_reasons", virtual_machine.public_exposure_reasons),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


class AzureManagedIdentityRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_broad_rbac(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for identity in _managed_identity_resources(context.inventory):
            facts = azure_facts(identity)
            assignments = [
                assignment
                for assignment in facts.managed_identity_role_assignments
                if _is_broad_managed_identity_assignment(assignment)
            ]
            if not assignments:
                continue
            signals = _assignment_breadth_signals(assignments)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=3 if "broad_builtin_role" in signals else 2,
                data_sensitivity=2 if "sensitive_resource_scope" in signals else 1,
                lateral_movement=1,
                blast_radius=2 if "subscription_scope" in signals else 1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            identity.address,
                            *_assignment_values(assignments, "source"),
                            *_assignment_values(assignments, "target_resource_address"),
                        ]
                    ),
                    trust_boundary_id=None,
                    rationale=(
                        f"{identity.display_name} has Azure role assignments with broad scope or high-impact "
                        "built-in roles. These grants expand what the managed identity can do if the workload "
                        "or deployment path using it is compromised."
                    ),
                    evidence=collect_evidence(
                        evidence_item("managed_identity", _managed_identity_evidence(identity)),
                        evidence_item("role_assignments", _describe_role_assignments(assignments)),
                        evidence_item("breadth_signals", signals),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_public_workload_sensitive_resource_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        public_workloads_by_identity = _public_workloads_by_identity_address(context.inventory)
        findings: list[Finding] = []
        for identity in _managed_identity_resources(context.inventory):
            public_workloads = public_workloads_by_identity.get(identity.address, [])
            if not public_workloads:
                continue
            assignments = [
                assignment
                for assignment in azure_facts(identity).managed_identity_role_assignments
                if _assignment_grants_sensitive_resource_access(assignment)
            ]
            if not assignments:
                continue
            boundary = _first_public_workload_boundary(public_workloads, context)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=3 if "broad_builtin_role" in _assignment_breadth_signals(assignments) else 2,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=2,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            *(workload.address for workload in public_workloads),
                            *([] if identity in public_workloads else [identity.address]),
                            *_assignment_values(assignments, "source"),
                            *_assignment_values(assignments, "target_resource_address"),
                        ]
                    ),
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{identity.display_name} is usable by an internet-exposed Azure workload and has a "
                        "deterministic role assignment to a sensitive Azure resource. This creates a clear "
                        "public workload to sensitive resource path if the workload identity is abused."
                    ),
                    evidence=collect_evidence(
                        evidence_item("public_workloads", _public_workload_evidence(public_workloads)),
                        evidence_item("managed_identity", _managed_identity_evidence(identity)),
                        evidence_item("sensitive_resource_assignments", _describe_role_assignments(assignments)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


class AzureStorageRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_container_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for container in context.inventory.by_type(AzureResourceType.STORAGE_CONTAINER):
            if not container.public_exposure:
                continue
            facts = azure_facts(container)
            account_address = facts.resolved_storage_account_address
            boundary = (
                context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", account_address))
                if account_address
                else None
            )
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[address for address in (account_address, container.address) if address],
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{container.display_name} permits anonymous `{facts.container_access_type}` access "
                        "through a storage account that allows nested public access and unrestricted public "
                        "network reachability."
                    ),
                    evidence=collect_evidence(
                        evidence_item("public_exposure_reasons", container.public_exposure_reasons),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_nested_public_access_enabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_account_boolean_posture(
            context,
            rule_id,
            predicate=lambda facts: facts.allow_nested_items_to_be_public is True,
            rationale=(
                "permits containers and blobs to opt into anonymous public access. This account-level setting "
                "allows a subordinate container configuration to expose stored data."
            ),
            evidence_key="public_access_posture",
            evidence_values=lambda facts: ["allow_nested_items_to_be_public is true"],
            privilege_breadth=1,
        )

    def detect_shared_key_enabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_account_boolean_posture(
            context,
            rule_id,
            predicate=lambda facts: facts.shared_access_key_enabled is True,
            rationale=(
                "permits Shared Key authorization. Account keys provide broad data-plane authority and are "
                "harder to constrain and attribute than Microsoft Entra ID identities."
            ),
            evidence_key="authorization_posture",
            evidence_values=lambda facts: ["shared_access_key_enabled is true"],
            privilege_breadth=2,
        )

    def detect_minimum_tls_below_1_2(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for account in context.inventory.by_type(AzureResourceType.STORAGE_ACCOUNT):
            facts = azure_facts(account)
            tls_version = facts.min_tls_version
            if not _tls_version_below_1_2(tls_version):
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=account.direct_internet_reachable,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[account.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{account.display_name} accepts `{tls_version}` as its minimum protocol version. "
                        "Deprecated TLS versions weaken transport protection for storage data-plane requests."
                    ),
                    evidence=collect_evidence(
                        evidence_item("transport_posture", [f"min_tls_version is {tls_version}"]),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_unrestricted_public_network(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for account in context.inventory.by_type(AzureResourceType.STORAGE_ACCOUNT):
            facts = azure_facts(account)
            default_action = facts.network_default_action
            if (
                facts.public_network_access_enabled is not True
                or default_action is None
                or default_action.strip().lower() != "allow"
            ):
                continue
            boundary = context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", account.address))
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[account.address],
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{account.display_name} enables its public network endpoint with an effective "
                        f"`{default_action}` default action. Storage data-plane endpoints are reachable "
                        "without a default-deny network boundary."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "network_posture",
                            [
                                "public_network_access_enabled is true",
                                f"effective default_action is {default_action}",
                                (
                                    f"network rule source is {facts.network_rule_source_address}"
                                    if facts.network_rule_source_address
                                    else "network rule source is account default"
                                ),
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def _detect_account_boolean_posture(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
        *,
        predicate: Callable[[AzureResourceFacts], bool],
        rationale: str,
        evidence_key: str,
        evidence_values: Callable[[AzureResourceFacts], list[str]],
        privilege_breadth: int,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for account in context.inventory.by_type(AzureResourceType.STORAGE_ACCOUNT):
            facts = azure_facts(account)
            if not predicate(facts):
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=account.direct_internet_reachable,
                privilege_breadth=privilege_breadth,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[account.address],
                    trust_boundary_id=None,
                    rationale=f"{account.display_name} {rationale}",
                    evidence=collect_evidence(
                        evidence_item(evidence_key, evidence_values(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def build_azure_rule_contribution(
    finding_factory: FindingFactory,
    metadata_registry: RuleRegistry | None = None,
) -> RuleContribution:
    compute_detectors = AzureComputeRuleDetectors(finding_factory)
    app_service_detectors = AzureAppServiceRuleDetectors(finding_factory)
    storage_detectors = AzureStorageRuleDetectors(finding_factory)
    key_vault_detectors = AzureKeyVaultRuleDetectors(finding_factory)
    custom_role_detectors = AzureCustomRoleRuleDetectors(finding_factory)
    managed_identity_detectors = AzureManagedIdentityRuleDetectors(finding_factory)
    mssql_detectors = AzureMssqlRuleDetectors(finding_factory)
    postgresql_detectors = AzurePostgresqlRuleDetectors(finding_factory)
    private_endpoint_detectors = AzurePrivateEndpointPostureRuleDetectors(finding_factory)
    detectors_by_rule_id: Mapping[str, RuleDetector] = {
        "azure-public-compute-broad-ingress": compute_detectors.detect_public_compute_broad_ingress,
        "azure-storage-container-public-access": storage_detectors.detect_public_container_access,
        "azure-storage-account-nested-public-access-enabled": (storage_detectors.detect_nested_public_access_enabled),
        "azure-storage-account-shared-key-enabled": storage_detectors.detect_shared_key_enabled,
        "azure-storage-account-minimum-tls-below-1-2": storage_detectors.detect_minimum_tls_below_1_2,
        "azure-storage-account-public-network-unrestricted": (storage_detectors.detect_unrestricted_public_network),
        "azure-storage-account-missing-private-endpoint": (
            private_endpoint_detectors.detect_storage_account_missing_private_endpoint
        ),
        "azure-key-vault-public-network-access": key_vault_detectors.detect_public_network_access,
        "azure-key-vault-missing-private-endpoint": (
            private_endpoint_detectors.detect_key_vault_missing_private_endpoint
        ),
        "azure-key-vault-privileged-access": key_vault_detectors.detect_privileged_access,
        "azure-key-vault-purge-protection-disabled": (key_vault_detectors.detect_purge_protection_disabled),
        "azure-custom-role-wildcard-management-plane": (custom_role_detectors.detect_wildcard_management_plane),
        "azure-custom-role-authorization-management": custom_role_detectors.detect_authorization_management,
        "azure-custom-role-broad-management-plane": custom_role_detectors.detect_broad_management_plane,
        "azure-custom-role-broad-data-plane": custom_role_detectors.detect_broad_data_plane,
        "azure-custom-role-subscription-assignable-scope": (custom_role_detectors.detect_subscription_assignable_scope),
        "azure-managed-identity-broad-rbac": managed_identity_detectors.detect_broad_rbac,
        "azure-public-workload-sensitive-resource-access": (
            managed_identity_detectors.detect_public_workload_sensitive_resource_access
        ),
        "azure-app-service-public-network-access-not-disabled": (
            app_service_detectors.detect_public_network_access_not_disabled
        ),
        "azure-app-service-minimum-tls-below-1-2": app_service_detectors.detect_minimum_tls_below_1_2,
        "azure-app-service-minimum-tls-unknown": app_service_detectors.detect_minimum_tls_unknown,
        "azure-app-service-managed-identity-missing": app_service_detectors.detect_managed_identity_missing,
        "azure-app-service-vnet-integration-missing": app_service_detectors.detect_vnet_integration_missing,
        "azure-sql-public-network-access-enabled": mssql_detectors.detect_public_network_access_enabled,
        "azure-sql-missing-private-endpoint": (private_endpoint_detectors.detect_sql_server_missing_private_endpoint),
        "azure-sql-firewall-broad-public-access": mssql_detectors.detect_broad_firewall_access,
        "azure-sql-minimum-tls-below-1-2": mssql_detectors.detect_minimum_tls_below_1_2,
        "azure-sql-security-alert-policy-disabled": mssql_detectors.detect_security_alert_policy_disabled,
        "azure-private-endpoint-public-fallback": (private_endpoint_detectors.detect_private_endpoint_public_fallback),
        "azure-postgresql-public-network-access-enabled": postgresql_detectors.detect_public_network_access_enabled,
        "azure-postgresql-firewall-broad-public-access": postgresql_detectors.detect_broad_firewall_access,
        "azure-postgresql-weak-tls-or-ssl": postgresql_detectors.detect_weak_tls_or_ssl,
        "azure-postgresql-geo-backup-disabled": postgresql_detectors.detect_geo_backup_disabled,
    }
    resolved_metadata_registry = metadata_registry if metadata_registry is not None else default_rule_registry()
    return build_rule_contribution(
        (
            tuple((rule_id, detectors_by_rule_id[rule_id]) for rule_id in rule_group)
            for rule_group in AZURE_RULE_GROUP_IDS
        ),
        resolved_metadata_registry,
    )


def _managed_identity_resources(inventory) -> list[Any]:
    return inventory.by_type(*AZURE_COMPUTE_RESOURCE_TYPES, AzureResourceType.USER_ASSIGNED_IDENTITY)


def _is_broad_managed_identity_assignment(assignment: Mapping[str, Any]) -> bool:
    if not _assignment_has_known_role_and_principal(assignment):
        return False
    return bool(
        _assignment_breadth_signal_set(assignment)
        & {"broad_builtin_role", "subscription_scope", "resource_group_scope"}
    )


def _assignment_grants_sensitive_resource_access(assignment: Mapping[str, Any]) -> bool:
    if not _assignment_has_known_role_and_principal(assignment):
        return False
    if "sensitive_resource_scope" not in _assignment_breadth_signal_set(assignment):
        return False
    return _role_name(assignment) in _SENSITIVE_RESOURCE_ACCESS_ROLE_NAMES


def _assignment_has_known_role_and_principal(assignment: Mapping[str, Any]) -> bool:
    return bool(
        assignment.get("principal_id")
        and (assignment.get("role_definition_name") or assignment.get("role_definition_id"))
    )


def _assignment_breadth_signal_set(assignment: Mapping[str, Any]) -> set[str]:
    return {str(signal) for signal in assignment.get("breadth_signals", []) if signal}


def _assignment_breadth_signals(assignments: list[Mapping[str, Any]]) -> list[str]:
    return _dedupe_strings(
        signal for assignment in assignments for signal in assignment.get("breadth_signals", []) if signal
    )


def _assignment_values(assignments: list[Mapping[str, Any]], key: str) -> list[str]:
    return _dedupe_strings(str(assignment[key]) for assignment in assignments if assignment.get(key))


def _describe_role_assignments(assignments: list[Mapping[str, Any]]) -> list[str]:
    return [
        "; ".join(
            part
            for part in (
                f"source={assignment.get('source')}",
                f"role={assignment.get('role_definition_name') or assignment.get('role_definition_id')}",
                f"scope={assignment.get('scope')}",
                f"scope_kind={assignment.get('scope_kind')}",
                f"target={assignment.get('target_resource_address')}",
                f"signals={','.join(str(signal) for signal in assignment.get('breadth_signals', []))}",
            )
            if part and not part.endswith("=None") and not part.endswith("=")
        )
        for assignment in assignments
    ]


def _managed_identity_evidence(identity) -> list[str]:
    facts = azure_facts(identity)
    return [
        value
        for value in (
            f"address={identity.address}",
            f"identity_type={facts.identity_type}" if facts.identity_type else None,
            f"principal_id={facts.principal_id}" if facts.principal_id else None,
            f"client_id={facts.client_id}" if facts.client_id else None,
        )
        if value
    ]


def _public_workloads_by_identity_address(inventory) -> dict[str, list[Any]]:
    identity_by_reference = _identity_resources_by_reference(inventory)
    public_workloads_by_identity: dict[str, list[Any]] = {}
    for workload in inventory.by_type(*AZURE_COMPUTE_RESOURCE_TYPES):
        if not workload.public_exposure:
            continue
        facts = azure_facts(workload)
        if facts.has_system_assigned_identity and facts.principal_id:
            public_workloads_by_identity.setdefault(workload.address, []).append(workload)
        for reference in facts.attached_identity_references:
            identity = identity_by_reference.get(azure_reference_key(reference))
            if identity is None:
                continue
            _append_unique_resource(public_workloads_by_identity.setdefault(identity.address, []), workload)
    return public_workloads_by_identity


def _identity_resources_by_reference(inventory) -> dict[str, Any]:
    references: dict[str, Any] = {}
    for identity in inventory.by_type(AzureResourceType.USER_ASSIGNED_IDENTITY):
        for reference in azure_resource_references(identity):
            references.setdefault(reference, identity)
    return references


def _append_unique_resource(resources: list[Any], resource: Any) -> None:
    if all(existing.address != resource.address for existing in resources):
        resources.append(resource)


def _public_workload_evidence(workloads: list[Any]) -> list[str]:
    return [
        "; ".join(
            part
            for part in (
                f"address={workload.address}",
                "public_exposure=true",
                f"public_exposure_reasons={','.join(workload.public_exposure_reasons)}"
                if workload.public_exposure_reasons
                else None,
            )
            if part
        )
        for workload in workloads
    ]


def _first_public_workload_boundary(public_workloads: list[Any], context: RuleEvaluationContext):
    for workload in public_workloads:
        boundary = context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", workload.address))
        if boundary is not None:
            return boundary
    return None


def _role_name(assignment: Mapping[str, Any]) -> str:
    return str(assignment.get("role_definition_name") or "").strip().lower()


def _dedupe_strings(values) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value).strip()
        if text and text not in seen:
            deduped.append(text)
            seen.add(text)
    return deduped


_SENSITIVE_RESOURCE_ACCESS_ROLE_NAMES = frozenset(
    {
        "contributor",
        "key vault administrator",
        "key vault certificates officer",
        "key vault crypto officer",
        "key vault data access administrator",
        "key vault secrets officer",
        "owner",
        "storage account contributor",
        "storage blob data contributor",
        "storage blob data owner",
    }
)


def _path_values(paths: list[dict[str, Any]], key: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for path in paths:
        for value in path.get(key, []):
            text = str(value)
            if not text or text in seen:
                continue
            seen.add(text)
            values.append(text)
    return values


def _public_ip_path_evidence(
    virtual_machine_address: str,
    network_interfaces: list[str],
    public_ips: list[str],
) -> list[str]:
    if not public_ips:
        return []
    nic_text = ", ".join(network_interfaces) if network_interfaces else "exported VM public IP"
    return [f"{virtual_machine_address} -> {nic_text} -> {public_ip}" for public_ip in public_ips]


def _network_security_path_evidence(
    virtual_machine_address: str,
    network_interfaces: list[str],
    network_security_groups: list[str],
) -> list[str]:
    if not network_security_groups:
        return []
    nic_text = ", ".join(network_interfaces) if network_interfaces else "virtual machine network path"
    return [
        f"{virtual_machine_address} -> {nic_text} -> {network_security_group}"
        for network_security_group in network_security_groups
    ]


def _tls_version_below_1_2(value: str | None) -> bool:
    if value is None:
        return False
    normalized = value.strip().upper().replace(".", "_")
    return normalized in {"TLS1_0", "TLS1_1"}
