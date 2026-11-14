from __future__ import annotations

from dataclasses import dataclass

from tfstride.analysis.indexes import AnalysisIndexes
from tfstride.models import ResourceInventory
from tfstride.providers.gcp.gcs_grant_evaluation import GcsGrantConstraintContext
from tfstride.providers.gcp.iam_inheritance import (
    GcpIamInheritanceIndex,
    build_gcp_iam_inheritance_index,
    empty_gcp_iam_inheritance_index,
)
from tfstride.providers.gcp.kms_authorization import GcpKmsAuthorizationContext
from tfstride.providers.gcp.org_policy_guardrails import (
    GcpOrgPolicyGuardrailIndex,
    build_gcp_org_policy_guardrail_index,
    empty_gcp_org_policy_guardrail_index,
)
from tfstride.providers.gcp.resource_types import GcpResourceType


@dataclass(frozen=True, slots=True)
class GcpAnalysisIndexes:
    """Dependencies for one preparation/evaluation; prepare again after resource mutations.

    GCS decoration builds its own context after each stage's prerequisites, and
    operation-gap collection builds a separate context per collection invocation.
    """

    iam_inheritance: GcpIamInheritanceIndex
    org_policy_guardrails: GcpOrgPolicyGuardrailIndex
    gcs_grant_context: GcsGrantConstraintContext | None = None
    kms_authorization_context: GcpKmsAuthorizationContext | None = None


_EMPTY_GCP_ANALYSIS_INDEXES = GcpAnalysisIndexes(
    iam_inheritance=empty_gcp_iam_inheritance_index(),
    org_policy_guardrails=empty_gcp_org_policy_guardrail_index(),
)


def build_gcp_analysis_indexes(inventory: ResourceInventory) -> GcpAnalysisIndexes:
    return GcpAnalysisIndexes(
        iam_inheritance=build_gcp_iam_inheritance_index(inventory.resources),
        org_policy_guardrails=build_gcp_org_policy_guardrail_index(inventory.resources),
        gcs_grant_context=(
            GcsGrantConstraintContext.build(inventory.resources)
            if inventory.by_type(GcpResourceType.STORAGE_BUCKET)
            else None
        ),
        kms_authorization_context=(
            GcpKmsAuthorizationContext.build(inventory.resources)
            if inventory.by_type(GcpResourceType.KMS_CRYPTO_KEY, GcpResourceType.KMS_KEY_RING)
            else None
        ),
    )


def gcp_analysis_indexes(indexes: AnalysisIndexes) -> GcpAnalysisIndexes:
    extension = indexes.provider_extension
    if not isinstance(extension, GcpAnalysisIndexes):
        return _EMPTY_GCP_ANALYSIS_INDEXES
    return extension


def gcp_iam_inheritance_index(indexes: AnalysisIndexes) -> GcpIamInheritanceIndex:
    return gcp_analysis_indexes(indexes).iam_inheritance


def gcp_gcs_grant_context(
    indexes: AnalysisIndexes | None, inventory: ResourceInventory
) -> GcsGrantConstraintContext | None:
    """Use prepared dependencies; callers omitting the provider extension get fresh ones."""
    if indexes is not None and isinstance(indexes.provider_extension, GcpAnalysisIndexes):
        return indexes.provider_extension.gcs_grant_context
    if inventory.provider != "gcp" or not inventory.by_type(GcpResourceType.STORAGE_BUCKET):
        return None
    return GcsGrantConstraintContext.build(inventory.resources)


def gcp_org_policy_guardrail_index(indexes: AnalysisIndexes) -> GcpOrgPolicyGuardrailIndex:
    return gcp_analysis_indexes(indexes).org_policy_guardrails


def gcp_kms_authorization_context(
    indexes: AnalysisIndexes | None, inventory: ResourceInventory
) -> GcpKmsAuthorizationContext | None:
    """Reuse prepared KMS dependencies, or construct fresh ones for standalone callers."""
    if indexes is not None and isinstance(indexes.provider_extension, GcpAnalysisIndexes):
        prepared = indexes.provider_extension.kms_authorization_context
        if prepared is not None:
            return prepared
    if inventory.provider != "gcp" or not inventory.by_type(
        GcpResourceType.KMS_CRYPTO_KEY, GcpResourceType.KMS_KEY_RING
    ):
        return None
    return GcpKmsAuthorizationContext.build(inventory.resources)
