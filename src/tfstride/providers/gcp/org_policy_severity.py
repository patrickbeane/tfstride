from __future__ import annotations

from tfstride.analysis.finding_helpers import build_severity_reasoning
from tfstride.models import NormalizedResource, SeverityReasoning
from tfstride.providers.gcp.org_policy_guardrails import (
    ORG_POLICY_ALLOWED_MEMBER_DOMAINS,
    ORG_POLICY_DISABLE_SERVICE_ACCOUNT_KEY_CREATION,
    ORG_POLICY_REQUIRE_OS_LOGIN,
    ORG_POLICY_STORAGE_PUBLIC_ACCESS_PREVENTION,
    ORG_POLICY_VM_EXTERNAL_IP_ACCESS,
    GcpOrgPolicyGuardrail,
    GcpOrgPolicyGuardrailIndex,
)


def guardrail_adjusted_severity_reasoning(
    index: GcpOrgPolicyGuardrailIndex,
    resource: NormalizedResource,
    *,
    constraints: tuple[str, ...],
    internet_exposure: bool,
    privilege_breadth: int,
    data_sensitivity: int,
    lateral_movement: int,
    blast_radius: int,
) -> SeverityReasoning:
    active_constraints = {
        constraint for constraint in constraints if _has_active_guardrail(index, resource, constraint)
    }

    if ORG_POLICY_ALLOWED_MEMBER_DOMAINS in active_constraints:
        internet_exposure = False
        privilege_breadth = _decrement(privilege_breadth)
        blast_radius = _decrement(blast_radius)
    if ORG_POLICY_STORAGE_PUBLIC_ACCESS_PREVENTION in active_constraints:
        internet_exposure = False
        blast_radius = _decrement(blast_radius)
    if ORG_POLICY_VM_EXTERNAL_IP_ACCESS in active_constraints:
        internet_exposure = False
        lateral_movement = _decrement(lateral_movement)
        blast_radius = _decrement(blast_radius)
    if ORG_POLICY_REQUIRE_OS_LOGIN in active_constraints:
        privilege_breadth = _decrement(privilege_breadth)
        lateral_movement = _decrement(lateral_movement)
        blast_radius = _decrement(blast_radius)
    if ORG_POLICY_DISABLE_SERVICE_ACCOUNT_KEY_CREATION in active_constraints:
        privilege_breadth = _decrement(privilege_breadth)
        lateral_movement = _decrement(lateral_movement)
        blast_radius = _decrement(blast_radius)

    return build_severity_reasoning(
        internet_exposure=internet_exposure,
        privilege_breadth=privilege_breadth,
        data_sensitivity=data_sensitivity,
        lateral_movement=lateral_movement,
        blast_radius=blast_radius,
    )


def _has_active_guardrail(
    index: GcpOrgPolicyGuardrailIndex,
    resource: NormalizedResource,
    constraint: str,
) -> bool:
    return any(
        _is_active_guardrail(guardrail)
        for guardrail in index.effective_guardrails_for_resource(resource, constraint=constraint)
    )


def _is_active_guardrail(guardrail: GcpOrgPolicyGuardrail) -> bool:
    if guardrail.restore_default:
        return False
    if guardrail.enforced is True:
        return True
    if guardrail.allowed_values or guardrail.denied_values:
        return True
    return any(
        rule.get("enforced") is True
        or rule.get("allow_all") is False
        or rule.get("deny_all") is True
        or bool(rule.get("allowed_values"))
        or bool(rule.get("denied_values"))
        for rule in guardrail.rules
    )


def _decrement(value: int) -> int:
    return max(0, value - 1)
