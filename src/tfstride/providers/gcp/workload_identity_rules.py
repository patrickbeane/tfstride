from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from typing import Any

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.identity import PrincipalType, PrivilegeCategory, PrivilegeConfidence, PrivilegedAccessGrant
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.coercion import dedupe_strings
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_HIGH_IMPACT_CATEGORIES = frozenset(
    {
        PrivilegeCategory.FULL_ADMIN,
        PrivilegeCategory.IAM_ADMIN,
        PrivilegeCategory.POLICY_ADMIN,
        PrivilegeCategory.ROLE_ASSIGNMENT,
        PrivilegeCategory.PRIVILEGE_ESCALATION,
    }
)
_DATA_ACCESS_CATEGORIES = frozenset(
    {
        PrivilegeCategory.DATA_ADMIN,
        PrivilegeCategory.SECRETS_ADMIN,
        PrivilegeCategory.KEY_ADMIN,
    }
)
_CONTROL_PLANE_CATEGORIES = frozenset(
    {
        PrivilegeCategory.COMPUTE_ADMIN,
        PrivilegeCategory.NETWORK_ADMIN,
        PrivilegeCategory.AUDIT_ADMIN,
    }
)


class GcpWorkloadIdentityRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_pool_wide_service_account_impersonation(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for service_account in context.inventory.by_type(GcpResourceType.SERVICE_ACCOUNT):
            paths = _active_pool_wide_paths(service_account)
            if not paths:
                continue
            severity_reasoning = _broad_trust_severity(paths, context)
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=_path_affected_resources(service_account, paths),
                    trust_boundary_id=None,
                    rationale=(
                        f"{service_account.display_name} grants service-account impersonation to a pool-wide "
                        "Workload Identity Federation principal set. Every identity admitted by the represented "
                        "active provider can enter this trust path, subject to any provider or IAM conditions "
                        "shown in the evidence."
                    ),
                    evidence=collect_evidence(
                        evidence_item("federation_trust_path", _path_evidence(paths)),
                        evidence_item("federation_provider", _provider_evidence(paths)),
                        evidence_item("federation_conditions", _condition_evidence(paths, context)),
                        evidence_item(
                            "unresolved_federation_paths",
                            gcp_facts(service_account).workload_identity_federation_trust_path_uncertainties,
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_active_provider_unconditioned_broad_trust(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        paths_by_provider: dict[str, list[tuple[NormalizedResource, Mapping[str, Any]]]] = defaultdict(list)
        for service_account in context.inventory.by_type(GcpResourceType.SERVICE_ACCOUNT):
            for path in _active_pool_wide_paths(service_account):
                if not _provider_condition_is_deterministically_absent(path, context):
                    continue
                provider_address = _known_string(path.get("provider_address"))
                if provider_address is not None:
                    paths_by_provider[provider_address].append((service_account, path))

        findings: list[Finding] = []
        for provider_address, entries in sorted(paths_by_provider.items()):
            paths = [path for _, path in entries]
            service_accounts = [service_account for service_account, _ in entries]
            provider = context.inventory.get_by_address(provider_address)
            provider_name = provider.display_name if provider is not None else provider_address
            severity_reasoning = _unconditioned_provider_severity(paths)
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [provider_address]
                        + [
                            address
                            for service_account, path in entries
                            for address in _path_affected_resources(service_account, [path])
                        ]
                    ),
                    trust_boundary_id=None,
                    rationale=(
                        f"{provider_name} is active and participates in pool-wide service-account trust without "
                        "a deterministic provider attribute condition. The provider admission boundary therefore "
                        "does not add a Terraform-visible identity constraint beyond the upstream identity provider "
                        "and any service-account IAM conditions."
                    ),
                    evidence=collect_evidence(
                        evidence_item("federation_trust_path", _path_evidence(paths)),
                        evidence_item("federation_provider", _provider_evidence(paths)),
                        evidence_item("federation_conditions", _condition_evidence(paths, context)),
                        evidence_item(
                            "target_service_accounts",
                            [
                                f"address={service_account.address}; "
                                f"email={gcp_facts(service_account).service_account_email or 'unknown'}"
                                for service_account in service_accounts
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_federated_privileged_service_account_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for service_account in context.inventory.by_type(GcpResourceType.SERVICE_ACCOUNT):
            paths = _active_federation_paths(service_account)
            if not paths:
                continue
            assignments = _privileged_assignments_for_service_account(service_account, context)
            if not assignments:
                continue
            grants = tuple(grant for _, grant in assignments)
            severity_reasoning = _privileged_chain_severity(grants)
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            *_path_affected_resources(service_account, paths),
                            *(resource.address for resource, _ in assignments),
                            *(grant.assignment_scope.source_address for grant in grants),
                        ]
                    ),
                    trust_boundary_id=None,
                    rationale=(
                        f"{service_account.display_name} is reachable through an active, exact Workload Identity "
                        f"Federation trust path and also receives privileged access: {_grant_summary(grants)}. "
                        "An admitted external identity could inherit those privileges through service-account "
                        "impersonation, subject to the represented provider and IAM conditions."
                    ),
                    evidence=collect_evidence(
                        evidence_item("federation_trust_path", _path_evidence(paths)),
                        evidence_item("federation_provider", _provider_evidence(paths)),
                        evidence_item("federation_conditions", _condition_evidence(paths, context)),
                        evidence_item("privileged_access", _privileged_access_evidence(assignments)),
                        evidence_item("privilege_categories", _privilege_category_evidence(grants)),
                        evidence_item("permission_patterns", _permission_pattern_evidence(grants)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _active_federation_paths(resource: NormalizedResource) -> list[Mapping[str, Any]]:
    return [
        path
        for path in gcp_facts(resource).workload_identity_federation_trust_paths
        if path.get("pool_state") == "enabled" and path.get("provider_state") == "enabled"
    ]


def _active_pool_wide_paths(resource: NormalizedResource) -> list[Mapping[str, Any]]:
    return [
        path
        for path in _active_federation_paths(resource)
        if path.get("member_kind") == "principal_set"
        and path.get("principal_selector") == "pool"
        and path.get("principal_value") == "*"
    ]


def _provider_condition_is_deterministically_absent(
    path: Mapping[str, Any],
    context: RuleEvaluationContext,
) -> bool:
    status, _ = _provider_condition_status(path, context)
    return status == "not_configured"


def _privileged_assignments_for_service_account(
    service_account: NormalizedResource,
    context: RuleEvaluationContext,
) -> list[tuple[NormalizedResource, PrivilegedAccessGrant]]:
    email = gcp_facts(service_account).service_account_email
    if email is None:
        return []
    assignments: list[tuple[NormalizedResource, PrivilegedAccessGrant]] = []
    for resource in context.inventory.resources:
        for grant in gcp_facts(resource).privileged_access_grants:
            if grant.confidence != PrivilegeConfidence.HIGH or grant.has_uncertainty:
                continue
            if grant.principal.principal_type != PrincipalType.SERVICE_ACCOUNT:
                continue
            if _service_account_email(grant.principal.identifier) == email:
                assignments.append((resource, grant))
    return sorted(
        assignments,
        key=lambda item: (
            item[0].address,
            item[1].role_name or "",
            item[1].assignment_scope.value or "",
        ),
    )


def _service_account_email(value: object) -> str | None:
    text = _known_string(value)
    if text is None:
        return None
    if text.startswith("serviceAccount:"):
        text = text.removeprefix("serviceAccount:")
    if "/serviceAccounts/" in text:
        text = text.split("/serviceAccounts/", 1)[1].split("/", 1)[0]
    if "@" not in text or not text.endswith(".gserviceaccount.com"):
        return None
    return text


def _broad_trust_severity(
    paths: list[Mapping[str, Any]],
    context: RuleEvaluationContext,
):
    explicitly_unconditioned = any(
        _provider_condition_status(path, context)[0] == "not_configured"
        and not _condition_present(path.get("iam_condition"))
        for path in paths
    )
    return build_severity_reasoning(
        internet_exposure=False,
        privilege_breadth=3 if explicitly_unconditioned else 2,
        data_sensitivity=0,
        lateral_movement=2 if explicitly_unconditioned else 1,
        blast_radius=2 if explicitly_unconditioned else 1,
    )


def _unconditioned_provider_severity(paths: list[Mapping[str, Any]]):
    iam_conditioned = all(_condition_present(path.get("iam_condition")) for path in paths)
    return build_severity_reasoning(
        internet_exposure=False,
        privilege_breadth=2 if iam_conditioned else 3,
        data_sensitivity=0,
        lateral_movement=1 if iam_conditioned else 2,
        blast_radius=1 if iam_conditioned else 2,
    )


def _privileged_chain_severity(grants: tuple[PrivilegedAccessGrant, ...]):
    categories = _grant_categories(grants)
    high_impact = bool(categories & _HIGH_IMPACT_CATEGORIES)
    data_access = bool(categories & _DATA_ACCESS_CATEGORIES)
    control_plane = bool(categories & _CONTROL_PLANE_CATEGORIES)
    broad_scope = any(grant.has_broad_scope for grant in grants)
    return build_severity_reasoning(
        internet_exposure=False,
        privilege_breadth=3 if high_impact else 2,
        data_sensitivity=2 if data_access else 0,
        lateral_movement=2 if high_impact else 1 if control_plane or data_access else 0,
        blast_radius=3 if broad_scope else 1,
    )


def _condition_present(value: object) -> bool:
    if isinstance(value, Mapping):
        return bool(value)
    return _known_string(value) is not None


def _path_affected_resources(
    service_account: NormalizedResource,
    paths: list[Mapping[str, Any]],
) -> list[str]:
    return dedupe_addresses(
        [
            service_account.address,
            *(
                str(path.get(key) or "")
                for path in paths
                for key in ("pool_address", "provider_address", "iam_resource_address")
            ),
        ]
    )


def _path_evidence(paths: list[Mapping[str, Any]]) -> list[str]:
    return dedupe_strings(
        f"member={path.get('member')}; role={path.get('role')}; "
        f"pool={path.get('pool_resource_name')}; provider={path.get('provider_address')}; "
        f"service_account={path.get('service_account_email')}"
        for path in paths
    )


def _provider_evidence(paths: list[Mapping[str, Any]]) -> list[str]:
    return dedupe_strings(
        f"address={path.get('provider_address')}; type={path.get('provider_type')}; "
        f"state={path.get('provider_state')}; issuer={path.get('provider_issuer_uri')}; "
        f"mapping_key={path.get('provider_mapping_key')}"
        for path in paths
    )


def _condition_evidence(
    paths: list[Mapping[str, Any]],
    context: RuleEvaluationContext,
) -> list[str]:
    values: list[str] = []
    for path in paths:
        provider_condition_status, provider_condition = _provider_condition_status(path, context)
        iam_condition = path.get("iam_condition")
        if isinstance(iam_condition, Mapping):
            iam_condition_value = _known_string(iam_condition.get("expression")) or "configured"
        else:
            iam_condition_value = "not_configured"
        values.append(
            f"provider={path.get('provider_address')}; "
            f"attribute_condition_state={provider_condition_status}; "
            f"attribute_condition={provider_condition}; iam_condition={iam_condition_value}"
        )
    return dedupe_strings(values)


def _provider_condition_status(
    path: Mapping[str, Any],
    context: RuleEvaluationContext,
) -> tuple[str, str]:
    condition = _known_string(path.get("provider_attribute_condition"))
    if condition is not None:
        return "configured", condition
    provider_address = _known_string(path.get("provider_address"))
    provider = context.inventory.get_by_address(provider_address) if provider_address is not None else None
    if provider is None:
        return "unknown", "unknown"
    if any(
        "attribute_condition" in uncertainty
        for uncertainty in gcp_facts(provider).workload_identity_pool_posture_uncertainties
    ):
        return "unknown", "unknown"
    return "not_configured", "not_configured"


def _privileged_access_evidence(
    assignments: list[tuple[NormalizedResource, PrivilegedAccessGrant]],
) -> list[str]:
    values: list[str] = []
    for resource, grant in assignments:
        categories = ", ".join(category.value for category in grant.privilege_categories)
        values.append(
            f"source={resource.address}; role={grant.role_name or 'unknown'}; "
            f"scope={grant.assignment_scope.scope_kind.value}; "
            f"scope_value={grant.assignment_scope.value or 'unknown'}; categories=[{categories}]"
        )
    return dedupe_strings(values)


def _grant_categories(grants: tuple[PrivilegedAccessGrant, ...]) -> set[PrivilegeCategory]:
    return {category for grant in grants for category in grant.privilege_categories}


def _privilege_category_evidence(grants: tuple[PrivilegedAccessGrant, ...]) -> list[str]:
    return sorted(category.value for category in _grant_categories(grants))


def _permission_pattern_evidence(grants: tuple[PrivilegedAccessGrant, ...]) -> list[str]:
    return dedupe_strings(pattern for grant in grants for pattern in grant.permission_patterns)


def _grant_summary(grants: tuple[PrivilegedAccessGrant, ...]) -> str:
    categories = _privilege_category_evidence(grants)
    return ", ".join(categories) if categories else "privileged access"


def _known_string(value: object) -> str | None:
    if value in (None, ""):
        return None
    normalized = str(value).strip()
    return normalized or None
