from __future__ import annotations

from typing import Literal, TypedDict

GcpGcsObjectDeletionOperation = Literal["storage.objects.delete"]
GcpGcsObjectDeletionOperationClass = Literal[
    "logical_object_deletion",
    "generation_deletion",
]
GcpGcsObjectDeletionManagementEffect = Literal["disruption"]
GcpGcsObjectDeletionTargetGranularity = Literal[
    "object",
    "generation",
    "object_prefix",
    "bucket_object_namespace",
    "bucket_generation_namespace",
]
GcpGcsObjectDeletionScopeType = Literal["project", "bucket", "folder", "organization"]
GcpGcsObjectDeletionAuthorizationState = Literal[
    "granted",
    "denied",
    "conditional",
    "unknown",
    "not_modeled",
]
GcpGcsObjectDeletionLifecycleCompatibilityState = Literal[
    "compatible",
    "incompatible",
    "unknown",
    "not_applicable",
]


class GcpGcsObjectDeletionRecoveryEvidence(TypedDict):
    recovery_evidence_scope: Literal["gcs_versioning_soft_delete_and_retention"]
    versioning_enabled: bool | None
    soft_delete_retention_duration_seconds: int | None
    soft_delete_state: Literal[
        "enabled",
        "disabled",
        "unknown",
        "not_observed",
    ]
    retention_period_seconds: int | None
    retention_policy_locked: bool | None
    uncertainties: list[str]


class GcpCloudRunGcsObjectDeletionPathCommon(TypedDict):
    workload_address: str
    workload_type: str
    service_account_email: str
    service_account_member: str
    identity_kind: Literal["cloud_run_service_account"]
    credential_context: Literal["workload_runtime"]
    bucket_address: str
    bucket_name: str
    bucket_project: str | None
    management_effect: GcpGcsObjectDeletionManagementEffect
    target_scope: str
    target_model_evidence_addresses: list[str]
    iam_resource_address: str | None
    iam_resource_type: str | None
    role: str
    role_kind: str
    grant_basis: str
    scope_type: GcpGcsObjectDeletionScopeType
    scope: str
    iam_source_addresses: list[str]
    custom_role_permissions: list[str]
    matched_permissions: list[GcpGcsObjectDeletionOperation]
    condition: None
    condition_state: Literal["not_configured"]
    authorization_state: Literal["granted"]
    policy_complete: Literal[True]
    lifecycle_compatibility_state: GcpGcsObjectDeletionLifecycleCompatibilityState
    recovery_evidence: GcpGcsObjectDeletionRecoveryEvidence
    posture_uncertainties: list[str]


class GcpCloudRunGcsExactObjectDeletionPath(GcpCloudRunGcsObjectDeletionPathCommon):
    operation: Literal["storage.objects.delete"]
    operation_class: Literal["logical_object_deletion"]
    target_granularity: Literal["object"]
    object_name: str
    generation: None


class GcpCloudRunGcsObjectPrefixDeletionPath(GcpCloudRunGcsObjectDeletionPathCommon):
    operation: Literal["storage.objects.delete"]
    operation_class: Literal["logical_object_deletion"]
    target_granularity: Literal["object_prefix"]
    object_name: str
    generation: None


class GcpCloudRunGcsBucketObjectNamespaceDeletionPath(GcpCloudRunGcsObjectDeletionPathCommon):
    operation: Literal["storage.objects.delete"]
    operation_class: Literal["logical_object_deletion"]
    target_granularity: Literal["bucket_object_namespace"]
    object_name: None
    generation: None


class GcpCloudRunGcsGenerationDeletionPath(GcpCloudRunGcsObjectDeletionPathCommon):
    operation: Literal["storage.objects.delete"]
    operation_class: Literal["generation_deletion"]
    target_granularity: Literal["generation"]
    object_name: str
    generation: str


class GcpCloudRunGcsGenerationNamespaceDeletionPath(GcpCloudRunGcsObjectDeletionPathCommon):
    operation: Literal["storage.objects.delete"]
    operation_class: Literal["generation_deletion"]
    target_granularity: Literal["bucket_generation_namespace"]
    object_name: None
    generation: None


GcpCloudRunGcsObjectDeletionPath = (
    GcpCloudRunGcsExactObjectDeletionPath
    | GcpCloudRunGcsObjectPrefixDeletionPath
    | GcpCloudRunGcsBucketObjectNamespaceDeletionPath
    | GcpCloudRunGcsGenerationDeletionPath
    | GcpCloudRunGcsGenerationNamespaceDeletionPath
)
GcpCloudRunGcsObjectDeletionEvidence = GcpCloudRunGcsObjectDeletionPath
