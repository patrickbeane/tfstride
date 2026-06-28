from __future__ import annotations

from collections.abc import Callable

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, Finding
from tfstride.providers.azure.resource_facts import AzureResourceFacts, azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.resource_utils import tls_version_below_1_2

_MIN_STORAGE_RECOVERY_RETENTION_DAYS = 7


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
            if not tls_version_below_1_2(tls_version):
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

    def detect_customer_managed_key_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for account in context.inventory.by_type(AzureResourceType.STORAGE_ACCOUNT):
            facts = azure_facts(account)
            cmk_state = _customer_managed_key_state(facts)
            if cmk_state == "configured":
                continue
            unknown = cmk_state == "unknown"
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=1 if unknown else 2,
                lateral_movement=0,
                blast_radius=0 if unknown else 1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[account.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{account.display_name} relies on Azure-managed storage encryption keys or does not "
                        "expose deterministic customer-managed key evidence in the Terraform plan. Azure Storage "
                        "is encrypted by default; this finding concerns customer key ownership, rotation, and "
                        "separation-of-duties controls."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _storage_target_evidence(account)),
                        evidence_item("encryption_ownership", _customer_managed_key_evidence(facts, cmk_state)),
                        evidence_item(
                            "posture_uncertainty",
                            _storage_uncertainty_evidence(facts, "customer_managed_key"),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_infrastructure_encryption_not_enabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for account in context.inventory.by_type(AzureResourceType.STORAGE_ACCOUNT):
            facts = azure_facts(account)
            enabled = facts.storage_infrastructure_encryption_enabled
            if enabled is True:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=1,
                lateral_movement=0,
                blast_radius=1 if enabled is False else 0,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[account.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{account.display_name} does not explicitly enable infrastructure encryption for "
                        "additional encryption-at-rest depth. Azure Storage default encryption remains in place; "
                        "this finding tracks defense-in-depth posture."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _storage_target_evidence(account)),
                        evidence_item(
                            "infrastructure_encryption",
                            _storage_bool_evidence(
                                "infrastructure_encryption_enabled",
                                enabled,
                                unknown_label="unknown",
                            ),
                        ),
                        evidence_item(
                            "posture_uncertainty",
                            _storage_uncertainty_evidence(facts, "infrastructure_encryption_enabled"),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_blob_versioning_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for account in context.inventory.by_type(AzureResourceType.STORAGE_ACCOUNT):
            facts = azure_facts(account)
            enabled = facts.storage_blob_versioning_enabled
            if enabled is True:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=1 if enabled is None else 2,
                lateral_movement=0,
                blast_radius=0 if enabled is None else 1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[account.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{account.display_name} does not have deterministic blob versioning enabled. "
                        "Reduced object version history limits recovery options after overwrite, deletion, "
                        "or destructive change."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _storage_target_evidence(account)),
                        evidence_item(
                            "versioning_posture",
                            _storage_bool_evidence("blob_properties.versioning_enabled", enabled),
                        ),
                        evidence_item(
                            "posture_uncertainty",
                            _storage_uncertainty_evidence(facts, "blob_properties.versioning_enabled"),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_blob_soft_delete_insufficient(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_storage_retention_posture(
            context,
            rule_id,
            days_selector=lambda facts: facts.storage_blob_delete_retention_days,
            evidence_key="blob_soft_delete_posture",
            field_path="blob_properties.delete_retention_policy.days",
            rationale=(
                "does not have deterministic blob soft delete retention that meets the minimum recovery "
                "threshold. Short or absent blob delete retention reduces recovery options after accidental "
                "or malicious blob deletion."
            ),
        )

    def detect_container_soft_delete_insufficient(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_storage_retention_posture(
            context,
            rule_id,
            days_selector=lambda facts: facts.storage_container_delete_retention_days,
            evidence_key="container_soft_delete_posture",
            field_path="blob_properties.container_delete_retention_policy.days",
            rationale=(
                "does not have deterministic container soft delete retention that meets the minimum recovery "
                "threshold. Short or absent container delete retention reduces recovery options after container "
                "deletion."
            ),
        )

    def detect_point_in_time_restore_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_storage_retention_posture(
            context,
            rule_id,
            days_selector=lambda facts: facts.storage_blob_restore_policy_days,
            evidence_key="point_in_time_restore_posture",
            field_path="blob_properties.restore_policy.days",
            rationale=(
                "does not have deterministic point-in-time restore configured for the minimum recovery "
                "threshold. Missing or short restore policy limits recovery from destructive blob changes."
            ),
        )

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

    def _detect_storage_retention_posture(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
        *,
        days_selector: Callable[[AzureResourceFacts], int | None],
        evidence_key: str,
        field_path: str,
        rationale: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for account in context.inventory.by_type(AzureResourceType.STORAGE_ACCOUNT):
            facts = azure_facts(account)
            days = days_selector(facts)
            unknown = _storage_field_unknown(facts, field_path)
            if days is not None and days >= _MIN_STORAGE_RECOVERY_RETENTION_DAYS:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=1 if unknown else 2,
                lateral_movement=0,
                blast_radius=0 if unknown else 1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[account.address],
                    trust_boundary_id=None,
                    rationale=f"{account.display_name} {rationale}",
                    evidence=collect_evidence(
                        evidence_item("target_resource", _storage_target_evidence(account)),
                        evidence_item(evidence_key, _retention_evidence(field_path, days, unknown=unknown)),
                        evidence_item("posture_uncertainty", _storage_uncertainty_evidence(facts, field_path)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _storage_target_evidence(account) -> list[str]:
    return [f"address={account.address}", f"type={account.resource_type}"]


def _customer_managed_key_state(facts: AzureResourceFacts) -> str:
    if facts.storage_customer_managed_key_id:
        return "configured"
    if _storage_field_unknown(facts, "customer_managed_key"):
        return "unknown"
    return "not_configured"


def _customer_managed_key_evidence(facts: AzureResourceFacts, cmk_state: str) -> list[str]:
    values = [f"customer_managed_key_state={cmk_state}"]
    if facts.storage_customer_managed_key_id:
        values.append(f"key_vault_key_id={facts.storage_customer_managed_key_id}")
    else:
        values.append("key_vault_key_id is unset")
    if facts.storage_customer_managed_key_identity_id:
        values.append(f"user_assigned_identity_id={facts.storage_customer_managed_key_identity_id}")
    values.append("Azure Storage encryption by default is still enabled; this finding concerns customer key control")
    return values


def _storage_bool_evidence(field_path: str, value: bool | None, *, unknown_label: str = "unknown") -> list[str]:
    if value is True:
        state = "enabled"
    elif value is False:
        state = "disabled"
    else:
        state = unknown_label
    return [f"{field_path} is {state}"]


def _retention_evidence(field_path: str, days: int | None, *, unknown: bool) -> list[str]:
    if unknown:
        state = "unknown"
    elif days is None:
        state = "disabled_or_missing"
    elif days < _MIN_STORAGE_RECOVERY_RETENTION_DAYS:
        state = "short"
    else:
        state = "configured"
    values = [
        f"{field_path}_state={state}",
        f"minimum_retention_days={_MIN_STORAGE_RECOVERY_RETENTION_DAYS}",
    ]
    if days is not None:
        values.insert(1, f"retention_days={days}")
    return values


def _storage_uncertainty_evidence(facts: AzureResourceFacts, field_path: str) -> list[str]:
    return [uncertainty for uncertainty in facts.storage_posture_uncertainties if field_path in uncertainty]


def _storage_field_unknown(facts: AzureResourceFacts, field_path: str) -> bool:
    return bool(_storage_uncertainty_evidence(facts, field_path))
