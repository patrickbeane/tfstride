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
from tfstride.providers.azure.key_vault_rules import AzureKeyVaultRuleDetectors
from tfstride.providers.azure.resource_decoration.public_exposure import is_risky_public_compute_path
from tfstride.providers.azure.resource_facts import AzureResourceFacts, azure_facts
from tfstride.providers.azure.resource_types import AZURE_COMPUTE_RESOURCE_TYPES, AzureResourceType

AZURE_RULE_GROUP_IDS: tuple[tuple[str, ...], ...] = (
    (
        "azure-public-compute-broad-ingress",
        "azure-storage-container-public-access",
        "azure-storage-account-nested-public-access-enabled",
        "azure-storage-account-shared-key-enabled",
        "azure-storage-account-minimum-tls-below-1-2",
        "azure-storage-account-public-network-unrestricted",
        "azure-key-vault-public-network-access",
        "azure-key-vault-privileged-access",
        "azure-key-vault-purge-protection-disabled",
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
    storage_detectors = AzureStorageRuleDetectors(finding_factory)
    key_vault_detectors = AzureKeyVaultRuleDetectors(finding_factory)
    detectors_by_rule_id: Mapping[str, RuleDetector] = {
        "azure-public-compute-broad-ingress": compute_detectors.detect_public_compute_broad_ingress,
        "azure-storage-container-public-access": storage_detectors.detect_public_container_access,
        "azure-storage-account-nested-public-access-enabled": (storage_detectors.detect_nested_public_access_enabled),
        "azure-storage-account-shared-key-enabled": storage_detectors.detect_shared_key_enabled,
        "azure-storage-account-minimum-tls-below-1-2": storage_detectors.detect_minimum_tls_below_1_2,
        "azure-storage-account-public-network-unrestricted": (storage_detectors.detect_unrestricted_public_network),
        "azure-key-vault-public-network-access": key_vault_detectors.detect_public_network_access,
        "azure-key-vault-privileged-access": key_vault_detectors.detect_privileged_access,
        "azure-key-vault-purge-protection-disabled": (key_vault_detectors.detect_purge_protection_disabled),
    }
    resolved_metadata_registry = metadata_registry if metadata_registry is not None else default_rule_registry()
    return build_rule_contribution(
        (
            tuple((rule_id, detectors_by_rule_id[rule_id]) for rule_id in rule_group)
            for rule_group in AZURE_RULE_GROUP_IDS
        ),
        resolved_metadata_registry,
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
