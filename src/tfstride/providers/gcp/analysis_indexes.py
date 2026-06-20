from __future__ import annotations

from dataclasses import dataclass

from tfstride.analysis.gcp.iam_inheritance import (
    GcpIamInheritanceIndex,
    build_gcp_iam_inheritance_index,
    empty_gcp_iam_inheritance_index,
)
from tfstride.analysis.gcp.org_policy_guardrails import (
    GcpOrgPolicyGuardrailIndex,
    build_gcp_org_policy_guardrail_index,
    empty_gcp_org_policy_guardrail_index,
)
from tfstride.analysis.indexes import AnalysisIndexes
from tfstride.models import ResourceInventory


@dataclass(frozen=True, slots=True)
class GcpAnalysisIndexes:
    iam_inheritance: GcpIamInheritanceIndex
    org_policy_guardrails: GcpOrgPolicyGuardrailIndex


_EMPTY_GCP_ANALYSIS_INDEXES = GcpAnalysisIndexes(
    iam_inheritance=empty_gcp_iam_inheritance_index(),
    org_policy_guardrails=empty_gcp_org_policy_guardrail_index(),
)


def build_gcp_analysis_indexes(inventory: ResourceInventory) -> GcpAnalysisIndexes:
    return GcpAnalysisIndexes(
        iam_inheritance=build_gcp_iam_inheritance_index(inventory.resources),
        org_policy_guardrails=build_gcp_org_policy_guardrail_index(inventory.resources),
    )


def gcp_analysis_indexes(indexes: AnalysisIndexes) -> GcpAnalysisIndexes:
    if indexes.provider_extension is None:
        return _EMPTY_GCP_ANALYSIS_INDEXES
    return indexes.require_provider_extension(GcpAnalysisIndexes)


def gcp_iam_inheritance_index(indexes: AnalysisIndexes) -> GcpIamInheritanceIndex:
    return gcp_analysis_indexes(indexes).iam_inheritance


def gcp_org_policy_guardrail_index(indexes: AnalysisIndexes) -> GcpOrgPolicyGuardrailIndex:
    return gcp_analysis_indexes(indexes).org_policy_guardrails
