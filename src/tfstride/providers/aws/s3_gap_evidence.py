"""Structured diagnostics shared by S3 evaluators; no policy text is copied."""

from __future__ import annotations

from dataclasses import dataclass, field

from tfstride.analysis.operation_gaps import (
    OperationGap,
    OperationGapEvidenceKind,
    OperationGapEvidenceState,
    OperationGapFamily,
    OperationGapProvenance,
)
from tfstride.models import NormalizedResource
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.aws.s3_object_scopes import is_exact_s3_bucket_arn, object_scope_from_resource

S3_ACCESS = OperationGapFamily("aws", "ecs_s3_access")
S3_MUTATION = OperationGapFamily("aws", "ecs_s3_mutation")
S3_OBJECT_DELETION = OperationGapFamily("aws", "ecs_s3_object_deletion")
S3_BUCKET_TOPOLOGY = OperationGapFamily("aws", "ecs_s3_bucket_topology")
S3_PROTECTED_DATA = OperationGapFamily("aws", "ecs_s3_protected_data")
S3_GAP_FAMILIES = (S3_ACCESS, S3_MUTATION, S3_OBJECT_DELETION, S3_BUCKET_TOPOLOGY, S3_PROTECTED_DATA)

_REASON_STATES = {
    "identity_policy_document_unavailable": OperationGapEvidenceState.MISSING,
    "identity_policy_incomplete": OperationGapEvidenceState.UNKNOWN,
    "bucket_policy_incomplete": OperationGapEvidenceState.UNKNOWN,
    "bucket_policy_target_unresolved": OperationGapEvidenceState.UNKNOWN,
    "bucket_policy_sources_conflict": OperationGapEvidenceState.AMBIGUOUS,
    "runtime_identity_unresolved": OperationGapEvidenceState.UNKNOWN,
    "runtime_identity_ambiguous": OperationGapEvidenceState.AMBIGUOUS,
    "runtime_identity_arn_unresolved": OperationGapEvidenceState.UNKNOWN,
    "target_arn_unresolved": OperationGapEvidenceState.UNKNOWN,
    "target_ambiguous": OperationGapEvidenceState.AMBIGUOUS,
    "target_not_modeled": OperationGapEvidenceState.MISSING,
    "ownership_unresolved": OperationGapEvidenceState.UNKNOWN,
    "cross_partition_authorization_unsupported": OperationGapEvidenceState.UNSUPPORTED,
    "permissions_boundary_intersection_unmodeled": OperationGapEvidenceState.UNSUPPORTED,
    "permissions_boundary_unresolved": OperationGapEvidenceState.UNKNOWN,
    "policy_condition_unresolved": OperationGapEvidenceState.CONDITIONAL,
    "deny_applicability_unresolved": OperationGapEvidenceState.UNKNOWN,
    "resource_scope_unsupported": OperationGapEvidenceState.UNSUPPORTED,
    "residual_scope_unrepresentable": OperationGapEvidenceState.UNSUPPORTED,
    "principal_scope_unsupported": OperationGapEvidenceState.UNSUPPORTED,
    "encryption_dependency_unresolved": OperationGapEvidenceState.UNKNOWN,
    "encryption_dependency_ambiguous": OperationGapEvidenceState.AMBIGUOUS,
    "encryption_ownership_unresolved": OperationGapEvidenceState.UNKNOWN,
    "kms_key_usage_unresolved": OperationGapEvidenceState.UNKNOWN,
    "kms_authorization_unresolved": OperationGapEvidenceState.UNKNOWN,
    "kms_s3_constraint_compatibility_unresolved": OperationGapEvidenceState.CONDITIONAL,
}


@dataclass(slots=True)
class S3GapCollector:
    workload: NormalizedResource
    family: OperationGapFamily
    records: list[OperationGap] = field(default_factory=list)

    def add(
        self,
        reason: str,
        *,
        operation: str | None = None,
        bucket: NormalizedResource | None = None,
        scope: str | None = None,
        source: NormalizedResource | None = None,
        source_address: str | None = None,
        field_path: tuple[str | int, ...] = (),
        kind: OperationGapEvidenceKind = OperationGapEvidenceKind.MODELED_RELATIONSHIP,
    ) -> None:
        source = source or self.workload
        self.records.append(
            OperationGap(
                family=self.family,
                resource_address=self.workload.address,
                relationship="runtime_identity_to_protected_data"
                if self.family == S3_PROTECTED_DATA
                else "runtime_identity_to_storage",
                operation=operation,
                target_address=bucket.address if bucket else None,
                reason_code=reason,
                evidence_state=_REASON_STATES[reason],
                scope=_bounded_scope(scope, bucket),
                provenance=(OperationGapProvenance(source_address or source.address, kind, field_path),),
            )
        )

    def gates(
        self,
        role: NormalizedResource,
        bucket: NormalizedResource,
        context: AwsDecorationContext,
        *,
        operation: str,
        scope: str | None,
        identity_complete: bool,
        bucket_complete: bool,
    ) -> None:
        """Called only for a potentially allowed scope, never an evaluated denial."""
        facts = aws_facts(role)
        if not identity_complete:
            self.add(
                "identity_policy_document_unavailable"
                if facts.unresolved_attached_policy_arns
                else "identity_policy_incomplete",
                operation=operation,
                bucket=bucket,
                scope=scope,
                source=role,
                kind=OperationGapEvidenceKind.POLICY_DOCUMENT,
            )
        if not bucket_complete:
            self.add(
                "bucket_policy_incomplete",
                operation=operation,
                bucket=bucket,
                scope=scope,
                source=bucket,
                kind=OperationGapEvidenceKind.POLICY_DOCUMENT,
            )
        boundary = facts.iam_permissions_boundary_state
        if boundary != "not_configured":
            self.add(
                "permissions_boundary_intersection_unmodeled"
                if facts.iam_permissions_boundary_arn
                else "permissions_boundary_unresolved",
                operation=operation,
                bucket=bucket,
                scope=scope,
                source=role,
                field_path=("permissions_boundary",),
                kind=OperationGapEvidenceKind.PLANNED_VALUE,
            )
        relationship = context.index.account_identities.relationship(role, bucket)
        if relationship.same_account is None:
            self.add("ownership_unresolved", operation=operation, bucket=bucket, scope=scope, source=bucket)
        elif not relationship.partitions_match:
            self.add(
                "cross_partition_authorization_unsupported",
                operation=operation,
                bucket=bucket,
                scope=scope,
                source=bucket,
            )


def _bounded_scope(scope: str | None, bucket: NormalizedResource | None) -> str | None:
    if bucket is None or not is_exact_s3_bucket_arn(bucket.arn) or scope is None:
        return None
    assert bucket.arn is not None
    if scope != scope.strip() or any(ord(character) < 32 for character in scope):
        return None
    if scope == bucket.arn:
        return scope
    modeled = object_scope_from_resource(scope, bucket.arn)
    return modeled.resource if modeled else None
