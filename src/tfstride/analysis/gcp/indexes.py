from __future__ import annotations

from tfstride.analysis.gcp.iam_inheritance import GcpIamInheritanceIndex, empty_gcp_iam_inheritance_index
from tfstride.analysis.gcp.org_policy_guardrails import (
    GcpOrgPolicyGuardrailIndex,
    empty_gcp_org_policy_guardrail_index,
)
from tfstride.analysis.indexes import AnalysisIndexes


def gcp_iam_inheritance_index(indexes: AnalysisIndexes) -> GcpIamInheritanceIndex:
    extension = indexes.provider_extension
    if extension is None:
        return empty_gcp_iam_inheritance_index()
    value = getattr(extension, "iam_inheritance", None)
    if value is None:
        return empty_gcp_iam_inheritance_index()
    return value


def gcp_org_policy_guardrail_index(indexes: AnalysisIndexes) -> GcpOrgPolicyGuardrailIndex:
    extension = indexes.provider_extension
    if extension is None:
        return empty_gcp_org_policy_guardrail_index()
    value = getattr(extension, "org_policy_guardrails", None)
    if value is None:
        return empty_gcp_org_policy_guardrail_index()
    return value
