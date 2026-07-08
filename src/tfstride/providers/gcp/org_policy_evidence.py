from __future__ import annotations

from tfstride.analysis.finding_helpers import evidence_item
from tfstride.models import EvidenceItem, NormalizedResource
from tfstride.providers.gcp.org_policy_guardrails import (
    GcpOrgPolicyGuardrail,
    GcpOrgPolicyGuardrailIndex,
)


def organization_guardrail_evidence(
    index: GcpOrgPolicyGuardrailIndex,
    resource: NormalizedResource,
    *constraints: str,
) -> EvidenceItem | None:
    values: list[str] = []
    for constraint in constraints:
        values.extend(
            _guardrail_evidence_value(guardrail)
            for guardrail in index.effective_guardrails_for_resource(resource, constraint=constraint)
        )
    return evidence_item("organization_guardrails", values)


def _guardrail_evidence_value(guardrail: GcpOrgPolicyGuardrail) -> str:
    parts = [
        f"constraint={guardrail.constraint}",
        f"scope={guardrail.scope.label}",
        f"source={guardrail.resource.address}",
    ]
    if guardrail.enforced is not None:
        parts.append(f"enforced={str(guardrail.enforced).lower()}")
    if guardrail.inherit_from_parent is not None:
        parts.append(f"inherit_from_parent={str(guardrail.inherit_from_parent).lower()}")
    if guardrail.restore_default:
        parts.append("restore_default=true")
    if guardrail.allowed_values:
        parts.append("allowed_values=" + ",".join(guardrail.allowed_values[:5]))
    if guardrail.denied_values:
        parts.append("denied_values=" + ",".join(guardrail.denied_values[:5]))
    return "; ".join(parts)
