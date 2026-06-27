from __future__ import annotations

from collections.abc import Callable

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.azure.private_endpoint_index import (
    build_azure_private_endpoint_index,
)
from tfstride.providers.azure.public_network import (
    PUBLIC_NETWORK_FALLBACK_DISABLED,
    PUBLIC_NETWORK_FALLBACK_ENABLED,
    PUBLIC_NETWORK_FALLBACK_UNKNOWN,
)
from tfstride.providers.azure.resource_facts import AzureResourceFacts, azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_PRIVATE_ENDPOINT_TARGET_TYPES = (
    AzureResourceType.STORAGE_ACCOUNT,
    AzureResourceType.KEY_VAULT,
    AzureResourceType.MSSQL_SERVER,
)


class AzurePrivateEndpointPostureRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_storage_account_missing_private_endpoint(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_missing_private_endpoint(
            context,
            rule_id,
            resource_type=AzureResourceType.STORAGE_ACCOUNT,
            rationale=lambda resource: (
                f"{resource.display_name} does not have a resolved private endpoint and may remain reachable "
                "through public Azure Storage data-plane endpoints. Network rules can reduce exposure, but they "
                "are not equivalent to private-endpoint-only access unless public network fallback is disabled."
            ),
        )

    def detect_key_vault_missing_private_endpoint(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_missing_private_endpoint(
            context,
            rule_id,
            resource_type=AzureResourceType.KEY_VAULT,
            rationale=lambda resource: (
                f"{resource.display_name} does not have a resolved private endpoint and may allow public "
                "Key Vault data-plane access depending on firewall settings. This finding does not claim "
                "secret exposure; identity authorization is evaluated separately."
            ),
        )

    def detect_sql_server_missing_private_endpoint(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_missing_private_endpoint(
            context,
            rule_id,
            resource_type=AzureResourceType.MSSQL_SERVER,
            rationale=lambda resource: (
                f"{resource.display_name} does not have a resolved private endpoint and may expose database "
                "access through public Azure SQL endpoints when public network fallback is enabled or unknown."
            ),
        )

    def detect_private_endpoint_public_fallback(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        index = build_azure_private_endpoint_index(context.inventory)
        findings: list[Finding] = []
        for resource in context.inventory.by_type(*_PRIVATE_ENDPOINT_TARGET_TYPES):
            facts = azure_facts(resource)
            if facts.public_network_fallback_state == PUBLIC_NETWORK_FALLBACK_DISABLED:
                continue
            coverage = index.coverage_for(resource)
            if not coverage.has_private_endpoint:
                continue
            severity_reasoning = _private_endpoint_posture_severity(
                facts,
                has_private_endpoint=True,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses([resource.address, *coverage.private_endpoint_addresses]),
                    trust_boundary_id=None,
                    rationale=(
                        f"{resource.display_name} has a resolved private endpoint, but public network access is "
                        "still enabled or not explicitly disabled. Private Endpoint coverage does not guarantee "
                        "private-only access while public network fallback remains enabled or unknown."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(resource)),
                        evidence_item("public_network_fallback", _public_network_fallback_evidence(facts)),
                        evidence_item("private_endpoints", list(coverage.private_endpoint_addresses)),
                        evidence_item("private_endpoint_subresources", list(coverage.subresource_names)),
                        evidence_item("network_acl_posture", _network_acl_evidence(facts)),
                        evidence_item("fallback_uncertainty", _fallback_uncertainty_evidence(resource, facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def _detect_missing_private_endpoint(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
        *,
        resource_type: str,
        rationale: Callable[[NormalizedResource], str],
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        index = build_azure_private_endpoint_index(context.inventory)
        findings: list[Finding] = []
        for resource in context.inventory.by_type(resource_type):
            facts = azure_facts(resource)
            if facts.public_network_fallback_state == PUBLIC_NETWORK_FALLBACK_DISABLED:
                continue
            coverage = index.coverage_for(resource)
            if coverage.has_private_endpoint:
                continue
            severity_reasoning = _private_endpoint_posture_severity(
                facts,
                has_private_endpoint=False,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[resource.address],
                    trust_boundary_id=None,
                    rationale=rationale(resource),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(resource)),
                        evidence_item("public_network_fallback", _public_network_fallback_evidence(facts)),
                        evidence_item(
                            "private_endpoint_coverage",
                            ["no resolved private endpoint targets this resource"],
                        ),
                        evidence_item("network_acl_posture", _network_acl_evidence(facts)),
                        evidence_item("fallback_uncertainty", _fallback_uncertainty_evidence(resource, facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _private_endpoint_posture_severity(
    facts: AzureResourceFacts,
    *,
    has_private_endpoint: bool,
):
    default_deny = _network_default_action_is_deny(facts.network_default_action)
    fallback_state = facts.public_network_fallback_state
    if has_private_endpoint:
        return build_severity_reasoning(
            internet_exposure=fallback_state == PUBLIC_NETWORK_FALLBACK_ENABLED and not default_deny,
            privilege_breadth=0,
            data_sensitivity=1,
            lateral_movement=0,
            blast_radius=1 if fallback_state == PUBLIC_NETWORK_FALLBACK_ENABLED and not default_deny else 0,
        )
    if fallback_state == PUBLIC_NETWORK_FALLBACK_ENABLED:
        return build_severity_reasoning(
            internet_exposure=not default_deny,
            privilege_breadth=0,
            data_sensitivity=2 if not default_deny else 1,
            lateral_movement=0,
            blast_radius=1 if not default_deny else 0,
        )
    return build_severity_reasoning(
        internet_exposure=False,
        privilege_breadth=0,
        data_sensitivity=2 if not default_deny else 1,
        lateral_movement=0,
        blast_radius=1 if not default_deny else 0,
    )


def _target_resource_evidence(resource: NormalizedResource) -> list[str]:
    return [f"address={resource.address}", f"type={resource.resource_type}"]


def _public_network_fallback_evidence(facts: AzureResourceFacts) -> list[str]:
    values = [f"public_network_fallback_state={facts.public_network_fallback_state}"]
    if facts.public_network_access_enabled is True:
        values.append("public_network_access_enabled is true")
    elif facts.public_network_access_enabled is False:
        values.append("public_network_access_enabled is false")
    else:
        values.append("public_network_access_enabled is unknown")
    return values


def _network_acl_evidence(facts: AzureResourceFacts) -> list[str]:
    values = []
    if facts.network_default_action:
        values.append(f"effective default_action is {facts.network_default_action}")
    if facts.network_rule_source_address:
        values.append(f"network rule source is {facts.network_rule_source_address}")
    return values


def _fallback_uncertainty_evidence(
    resource: NormalizedResource,
    facts: AzureResourceFacts,
) -> list[str]:
    if facts.public_network_fallback_state != PUBLIC_NETWORK_FALLBACK_UNKNOWN:
        return []
    uncertainties = [
        uncertainty
        for uncertainty in _posture_uncertainties(resource, facts)
        if "public_network_access_enabled" in uncertainty
    ]
    if uncertainties:
        return uncertainties
    return ["public_network_access_enabled is not represented in planned values"]


def _posture_uncertainties(
    resource: NormalizedResource,
    facts: AzureResourceFacts,
) -> list[str]:
    if resource.resource_type == AzureResourceType.STORAGE_ACCOUNT:
        return facts.storage_posture_uncertainties
    if resource.resource_type == AzureResourceType.KEY_VAULT:
        return facts.key_vault_network_uncertainties
    if resource.resource_type == AzureResourceType.MSSQL_SERVER:
        return facts.mssql_posture_uncertainties
    return []


def _network_default_action_is_deny(default_action: str | None) -> bool:
    return bool(default_action and default_action.strip().lower() == "deny")
