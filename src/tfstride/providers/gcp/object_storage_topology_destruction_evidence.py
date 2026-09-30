from __future__ import annotations

from typing import Literal, Never, TypedDict

GcpGcsBucketTopologyDestructionOperation = Literal["storage.buckets.delete"]
GcpGcsBucketTopologyDestructionOperationClass = Literal["bucket_deletion"]
GcpGcsBucketTopologyDestructionInternalOperation = Literal["delete_bucket"]
GcpGcsBucketTopologyDestructionTargetGranularity = Literal["bucket_topology"]
GcpGcsBucketTopologyDestructionScopeType = Literal["project", "bucket", "folder", "organization"]
GcpGcsBucketTopologyActiveCustomRoleStage = Literal[
    "ALPHA",
    "BETA",
    "DEPRECATED",
    "EAP",
    "GA",
]


class GcpGcsBucketTopologyProjectBuiltInRoleEvidence(TypedDict):
    role_kind: Literal[
        "owner",
        "editor",
        "storage_admin",
        "storage_editor",
    ]
    role_definition_address: None
    custom_role_permissions: list[Never]
    custom_role_stage: None
    custom_role_deleted: None
    custom_role_grant_scope_compatibility_state: Literal["not_applicable"]


class GcpGcsBucketTopologyBucketBuiltInRoleEvidence(TypedDict):
    role_kind: Literal["storage_admin", "storage_editor"]
    role_definition_address: None
    custom_role_permissions: list[Never]
    custom_role_stage: None
    custom_role_deleted: None
    custom_role_grant_scope_compatibility_state: Literal["not_applicable"]


class GcpGcsBucketTopologyCustomRoleEvidence(TypedDict):
    role_kind: Literal["custom"]
    role_definition_address: str
    custom_role_permissions: list[str]
    custom_role_stage: GcpGcsBucketTopologyActiveCustomRoleStage
    custom_role_deleted: Literal[False]
    custom_role_grant_scope_compatibility_state: Literal["compatible"]


GcpGcsBucketTopologyProjectRoleEvidence = (
    GcpGcsBucketTopologyProjectBuiltInRoleEvidence | GcpGcsBucketTopologyCustomRoleEvidence
)
GcpGcsBucketTopologyBucketRoleEvidence = (
    GcpGcsBucketTopologyBucketBuiltInRoleEvidence | GcpGcsBucketTopologyCustomRoleEvidence
)


class GcpGcsBucketTopologyDestructionRecoveryEvidenceCommon(TypedDict):
    recovery_evidence_scope: Literal["gcs_bucket_soft_delete_and_empty_bucket_prerequisite"]
    bucket_emptiness_required: Literal[True]
    bucket_emptiness_state: Literal["not_established"]
    versioning_enabled: bool | None
    retention_period_seconds: int | None
    retention_policy_locked: bool | None
    out_of_plan_object_inventory_evaluated: Literal[False]
    successful_deletion_observed: Literal[False]
    restoration_observed: Literal[False]
    uncertainties: list[str]


class GcpGcsBucketSoftDeleteEnabledRecoveryEvidence(
    GcpGcsBucketTopologyDestructionRecoveryEvidenceCommon,
):
    soft_delete_state: Literal["enabled"]
    soft_delete_retention_duration_seconds: int
    bucket_recovery_state: Literal["soft_delete_recovery_configured"]


class GcpGcsBucketSoftDeleteDisabledRecoveryEvidence(
    GcpGcsBucketTopologyDestructionRecoveryEvidenceCommon,
):
    soft_delete_state: Literal["disabled"]
    soft_delete_retention_duration_seconds: Literal[0]
    bucket_recovery_state: Literal["not_established_by_modeled_gcp_gcs_bucket_evidence"]


class GcpGcsBucketSoftDeleteUnknownRecoveryEvidence(
    GcpGcsBucketTopologyDestructionRecoveryEvidenceCommon,
):
    soft_delete_state: Literal["unknown"]
    soft_delete_retention_duration_seconds: None
    bucket_recovery_state: Literal["unknown"]


class GcpGcsBucketSoftDeleteNotObservedRecoveryEvidence(
    GcpGcsBucketTopologyDestructionRecoveryEvidenceCommon,
):
    soft_delete_state: Literal["not_observed"]
    soft_delete_retention_duration_seconds: None
    bucket_recovery_state: Literal["unknown"]


GcpGcsBucketTopologyDestructionRecoveryEvidence = (
    GcpGcsBucketSoftDeleteEnabledRecoveryEvidence
    | GcpGcsBucketSoftDeleteDisabledRecoveryEvidence
    | GcpGcsBucketSoftDeleteUnknownRecoveryEvidence
    | GcpGcsBucketSoftDeleteNotObservedRecoveryEvidence
)


class GcpCloudRunGcsBucketTopologyDestructionPathCommon(TypedDict):
    workload_address: str
    workload_type: str
    service_account_email: str
    service_account_member: str
    identity_kind: Literal["cloud_run_service_account"]
    credential_context: Literal["workload_runtime"]
    bucket_address: str
    bucket_resource_type: str
    bucket_name: str
    bucket_project: str
    bucket_reference: str
    operation: Literal["storage.buckets.delete"]
    operation_class: Literal["bucket_deletion"]
    internal_operation: Literal["delete_bucket"]
    management_effect: Literal["disruption"]
    target_granularity: Literal["bucket_topology"]
    target_scope: Literal["exact_gcs_bucket"]
    target_model_evidence_addresses: list[str]
    iam_resource_address: str
    iam_resource_type: str
    iam_source_addresses: list[str]
    role: str
    matched_permissions: list[Literal["storage.buckets.delete"]]
    authorization_state: Literal["granted"]
    policy_complete: Literal[True]
    iam_manager_ambiguity_state: Literal["not_detected"]
    condition: None
    condition_state: Literal["not_configured"]
    lifecycle_compatibility_state: Literal["bucket_emptiness_not_established"]
    recovery_evidence: GcpGcsBucketTopologyDestructionRecoveryEvidence
    posture_uncertainties: list[str]


class GcpCloudRunGcsProjectBucketTopologyDestructionPath(
    GcpCloudRunGcsBucketTopologyDestructionPathCommon,
):
    scope_type: Literal["project"]
    scope: str
    resource_scope: Literal["gcs_project"]
    grant_basis: Literal["gcs_project_iam"]
    role_evidence: GcpGcsBucketTopologyProjectRoleEvidence


class GcpCloudRunGcsExactBucketTopologyDestructionPath(
    GcpCloudRunGcsBucketTopologyDestructionPathCommon,
):
    scope_type: Literal["bucket"]
    scope: str
    resource_scope: Literal["exact_gcs_bucket"]
    grant_basis: Literal["gcs_bucket_iam"]
    role_evidence: GcpGcsBucketTopologyBucketRoleEvidence


class GcpCloudRunGcsAncestorBucketTopologyDestructionPath(
    GcpCloudRunGcsBucketTopologyDestructionPathCommon,
):
    scope_type: Literal["folder", "organization"]
    scope: str
    resource_scope: Literal["gcs_folder", "gcs_organization"]
    grant_basis: Literal["gcs_folder_iam", "gcs_organization_iam"]
    role_evidence: GcpGcsBucketTopologyBucketBuiltInRoleEvidence


GcpCloudRunGcsBucketTopologyDestructionPath = (
    GcpCloudRunGcsAncestorBucketTopologyDestructionPath
    | GcpCloudRunGcsProjectBucketTopologyDestructionPath
    | GcpCloudRunGcsExactBucketTopologyDestructionPath
)
GcpCloudRunGcsBucketTopologyDestructionEvidence = GcpCloudRunGcsBucketTopologyDestructionPath
