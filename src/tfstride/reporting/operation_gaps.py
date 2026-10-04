"""Allowlisted gap output and static explanations, without evidence-value lookups."""

from __future__ import annotations

import re

from tfstride.analysis.operation_gaps import OperationGap, OperationGapFamily, OperationGapResults
from tfstride.reporting.report_contract import (
    OperationGapFamilyPayload,
    OperationGapPayload,
    OperationGapResultsPayload,
)

# Explanations are owned by the reporter, never copied from evaluator messages,
# policy conditions, expressions, or arbitrary resource metadata.
_AWS_EXPLANATIONS: dict[str, tuple[str, str]] = {
    "identity_policy_document_unavailable": (
        "An attached identity-policy document is unavailable in the modeled input.",
        "Include the attached policy document in the analyzed input where supported, or review it separately.",
    ),
    "identity_policy_incomplete": (
        "The runtime identity's policy evidence is incomplete or cannot be fully interpreted.",
        "Check the identity's inline and attached policy documents for missing or unsupported statements.",
    ),
    "bucket_policy_incomplete": (
        "The bucket-policy evidence cannot be fully evaluated for this operation and scope.",
        "Check the bucket-policy document and its modeled association with this bucket.",
    ),
    "bucket_policy_target_unresolved": (
        "A bucket-policy source cannot be associated with a unique modeled bucket.",
        "Resolve the policy's bucket reference to the intended modeled bucket.",
    ),
    "bucket_policy_sources_conflict": (
        "Multiple bucket-policy sources prevent a single policy assessment.",
        "Check which policy source applies to this bucket and resolve conflicting modeled associations.",
    ),
    "runtime_identity_unresolved": (
        "The workload's configured runtime identity could not be resolved.",
        "Include the runtime role in the modeled input and resolve the workload's task-role reference.",
    ),
    "runtime_identity_ambiguous": (
        "The workload's runtime-identity reference has multiple modeled candidates.",
        "Disambiguate the task-role reference so it identifies exactly one runtime role.",
    ),
    "runtime_identity_arn_unresolved": (
        "The runtime role's exact ARN is unavailable.",
        "Provide modeled identity evidence that resolves the runtime role's exact ARN.",
    ),
    "target_arn_unresolved": (
        "The modeled bucket's exact ARN is unavailable.",
        "Resolve the bucket's name or ARN in the modeled input before evaluating the grant's scope.",
    ),
    "target_ambiguous": (
        "The target identity matches multiple modeled buckets.",
        "Resolve duplicate or ambiguous bucket identities before assessing this relationship.",
    ),
    "target_not_modeled": (
        "The grant's target has no matching resource in the modeled input.",
        "Include the intended target in the analyzed input where supported, or assess that relationship separately.",
    ),
    "ownership_unresolved": (
        "The runtime identity and bucket cannot be assigned a definite account relationship.",
        "Resolve account ownership for the role and bucket to establish which cross-account prerequisites apply.",
    ),
    "cross_partition_authorization_unsupported": (
        "Authorization across the modeled AWS partitions is unsupported.",
        "Verify the role and bucket partitions and assess any cross-partition relationship separately.",
    ),
    "permissions_boundary_intersection_unmodeled": (
        "The runtime role has a permissions boundary whose intersection with this grant is not modeled.",
        "Review the boundary together with the identity and bucket policies for this operation and scope.",
    ),
    "permissions_boundary_unresolved": (
        "The runtime role's permissions-boundary evidence is unresolved.",
        "Resolve the role's permissions-boundary reference and review its constraints for this operation and scope.",
    ),
    "policy_condition_unresolved": (
        "A policy condition affecting this operation and scope could not be evaluated.",
        "Review the condition at the referenced policy source against the intended request context.",
    ),
    "deny_applicability_unresolved": (
        "An explicit deny may apply, but its applicability could not be determined.",
        "Review the deny's action, resource, principal, and condition constraints for this request.",
    ),
    "resource_scope_unsupported": (
        "The grant's resource selector cannot be represented as an exact modeled scope.",
        "Resolve symbolic resource references where possible and review unsupported selectors separately.",
    ),
    "residual_scope_unrepresentable": (
        "The scope remaining after applicable denies cannot be represented by this evaluator.",
        "Review the allow and deny resource intersections for this operation without discarding the denies.",
    ),
    "principal_scope_unsupported": (
        "The policy's principal constraints cannot be evaluated for this runtime identity.",
        "Review the referenced policy's principal and condition constraints against the exact runtime role.",
    ),
    "encryption_dependency_unresolved": (
        "The bucket's encryption-key dependency could not be resolved.",
        "Resolve the bucket's encryption-key reference and include the intended key in the modeled input.",
    ),
    "encryption_dependency_ambiguous": (
        "The bucket's encryption-key reference has multiple modeled candidates.",
        "Disambiguate the key reference or alias to establish the exact encryption dependency.",
    ),
    "encryption_ownership_unresolved": (
        "Account ownership for the encryption dependency could not be established.",
        "Resolve ownership of the runtime identity and encryption key before assessing key-use prerequisites.",
    ),
    "kms_key_usage_unresolved": (
        "The key's usage is unknown, so suitability for decryption cannot be established.",
        "Resolve the modeled key usage and verify that it supports the required cryptographic operation.",
    ),
    "kms_authorization_unresolved": (
        "The runtime identity's authority to use the encryption key could not be established.",
        "Review the key policy, identity policy, and applicable KMS grants for the required key operation.",
    ),
    "kms_s3_constraint_compatibility_unresolved": (
        "Compatibility between the KMS grant constraints and this S3 read could not be established.",
        "Review the grant's encryption-context constraints against the context used by the S3 read.",
    ),
}
_GCP_EXPLANATIONS: dict[str, tuple[str, str]] = {
    "grant_ancestry_unresolved": (
        "The IAM grant's project or ancestor scope cannot be established for this bucket.",
        "Resolve the bucket's project ownership and the IAM source's project or parent links.",
    ),
    "iam_policy_document_unavailable": (
        "The IAM policy document at this modeled scope is unavailable.",
        "Include the policy_data document for this IAM source or review its bindings separately.",
    ),
    "iam_grant_source_ambiguous": (
        "The modeled IAM source cannot establish one applicable grant at this scope.",
        "Check overlapping authoritative IAM managers and the source's binding structure.",
    ),
    "iam_membership_unresolved": (
        "The IAM binding's membership may include this workload identity.",
        "Resolve the binding's members before assessing the workload's operations.",
    ),
    "iam_role_unresolved": (
        "The IAM binding's role is unresolved.",
        "Resolve the role reference to determine the operations granted by this binding.",
    ),
    "iam_condition_unresolved": (
        "An IAM condition prevents a definite conclusion for this operation.",
        "Review the binding condition against the request context for the affected operation.",
    ),
    "deny_scope_unresolved": (
        "The IAM deny policy's parent scope cannot be established for this bucket.",
        "Resolve the deny policy's parent and the bucket's modeled ancestry.",
    ),
    "deny_rule_unresolved": (
        "An IAM deny rule may constrain this operation, but its applicability is unresolved.",
        "Review the rule's principal, permission, exception, and condition evidence for this operation.",
    ),
    "custom_role_definition_unavailable": (
        "The custom role definition needed to establish granted operations is unavailable.",
        "Include the exact custom role definition or review its permissions separately.",
    ),
    "custom_role_ambiguous": (
        "The custom role reference resolves to multiple modeled definitions.",
        "Disambiguate the role reference before using its permissions.",
    ),
    "custom_role_ownership_unresolved": (
        "Ownership of the custom role or its grant scope is unresolved.",
        "Resolve the role owner and the IAM grant's project or ancestor identity.",
    ),
    "custom_role_ownership_conflict": (
        "The custom role's native identity conflicts with its modeled owner.",
        "Reconcile the role name, owner, and IAM grant scope.",
    ),
    "custom_role_lifecycle_unresolved": (
        "The custom role's active lifecycle state cannot be established.",
        "Resolve its stage and deleted state before assessing its permissions.",
    ),
    "custom_role_permissions_unavailable": (
        "The custom role's permissions are unavailable.",
        "Include its included_permissions to establish the affected operations.",
    ),
    "custom_role_permission_syntax_unsupported": (
        "The custom role contains permission syntax this evaluator cannot interpret.",
        "Review the role's included_permissions separately for the affected bucket.",
    ),
}
_AZURE_EXPLANATIONS: dict[str, tuple[str, str]] = {
    "assignment_scope_unresolved": (
        "This role assignment's scope cannot be established for the modeled storage target.",
        "Resolve the assignment scope to the storage resource or an ARM ancestor.",
    ),
    "assignment_scope_ambiguous": (
        "This role assignment's scope has multiple possible modeled targets.",
        "Disambiguate the assignment scope reference before assessing Blob authority.",
    ),
    "assignment_principal_unresolved": (
        "The assignment may apply to this workload identity, but its principal is unresolved.",
        "Resolve the assignment principal to the workload's managed identity.",
    ),
    "role_definition_unavailable": (
        "The role definition needed to establish storage operations is unavailable.",
        "Include the exact role definition or review its permissions separately.",
    ),
    "role_definition_ambiguous": (
        "The role reference resolves to multiple modeled definitions.",
        "Disambiguate the role definition reference before assessing its permissions.",
    ),
    "role_data_actions_unresolved": (
        "The custom role's Blob DataActions or exclusions are unresolved.",
        "Resolve the role's DataActions and NotDataActions for the affected assignment.",
    ),
    "role_actions_unresolved": (
        "The custom role's container-management Actions or exclusions are unresolved.",
        "Resolve the role's Actions and NotActions for container deletion.",
    ),
    "assignable_scope_unresolved": (
        "The custom role's assignable scope cannot be checked against this assignment.",
        "Resolve the role's assignableScopes and the assignment's ARM scope.",
    ),
    "assignment_condition_unresolved": (
        "The assignment condition prevents a definite conclusion for this operation.",
        "Review the condition against the request context for the affected operation.",
    ),
}
_FALLBACK_EXPLANATION = (
    "The reporting family could not complete this relationship assessment.",
    "Review the referenced evidence locations and the provider's support for this operation and scope.",
)


def serialize_operation_gaps(results: OperationGapResults) -> OperationGapResultsPayload:
    """Serialize only the public contract, including locations rather than their values.

    Do not use asdict, __dict__, metadata snapshots, or resource lookups here:
    future internal fields and policy evidence must not silently become public.
    The immutable result contract already orders and deduplicates its records.
    """
    return {
        "reporting_families": [_serialize_family(family) for family in results.reporting_families],
        "records": [_serialize_gap(gap) for gap in results.records],
    }


def _serialize_family(family: OperationGapFamily) -> OperationGapFamilyPayload:
    return {"provider": family.provider, "name": family.name}


def _serialize_gap(gap: OperationGap) -> OperationGapPayload:
    explanations = {"aws": _AWS_EXPLANATIONS, "gcp": _GCP_EXPLANATIONS, "azure": _AZURE_EXPLANATIONS}.get(
        gap.family.provider, {}
    )
    explanation, next_step = explanations.get(gap.reason_code, _FALLBACK_EXPLANATION)
    return {
        "family": _serialize_family(gap.family),
        "resource_address": gap.resource_address,
        "relationship": gap.relationship,
        "operation": gap.operation,
        "target_address": gap.target_address,
        "scope": gap.scope,
        "reason_code": gap.reason_code,
        "evidence_state": gap.evidence_state.value,
        "provenance": [
            {
                "resource_address": source.resource_address,
                "evidence_kind": source.evidence_kind.value,
                "field_path": list(source.field_path),
            }
            for source in gap.provenance
        ],
        "explanation": explanation,
        "next_step": next_step,
    }


def render_operation_gaps(results: OperationGapResults) -> list[str]:
    if not results.records:
        return []
    payload = serialize_operation_gaps(results)
    count = len(payload["records"])
    lines = [f"{count} modeled relationship{'s' if count != 1 else ''} could not be fully assessed from this plan.", ""]
    for gap in payload["records"]:
        operation = _code(gap["operation"]) if gap["operation"] else "Operation undetermined"
        target = _code(gap["target_address"]) if gap["target_address"] else "No unique modeled target established"
        scope = f"; scope {_code(gap['scope'])}" if gap["scope"] else ""
        lines.append(
            f"- {_code(gap['resource_address'])} → {target} ({operation}{scope}): "
            f"{gap['explanation']} Next: {gap['next_step']}"
        )
    return lines


def _code(value: str) -> str:
    # CommonMark code spans keep addresses/prefixes containing backticks, HTML,
    # or link syntax literal rather than turning evidence locations into markup.
    delimiter = "`" * (1 + max((len(run) for run in re.findall(r"`+", value)), default=0))
    padding = " " if value.startswith(("`", " ")) or value.endswith(("`", " ")) else ""
    return f"{delimiter}{padding}{value}{padding}{delimiter}"
