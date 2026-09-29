from __future__ import annotations

from typing import TYPE_CHECKING, Literal, NotRequired, TypedDict

if TYPE_CHECKING:
    from tfstride.providers.gcp.gcs_grant_constraints import GcsPermissionConstraint

from tfstride.providers.gcp.kms_dependency_evidence import GcpKmsEncryptionDependency
from tfstride.providers.gcp.kms_evidence import GcpCloudRunKmsOperationPath

GcpGcsAccessClass = Literal["read", "write", "delete", "administrative"]
GcpGcsAccessState = Literal["granted", "conditional"]


class GcpCloudRunGcsAccessPath(TypedDict):
    workload_address: str
    workload_type: str
    service_account_email: str | None
    service_account_member: str
    identity_kind: Literal["cloud_run_service_account"]
    credential_context: Literal["workload_runtime"]
    bucket_address: str
    bucket_name: str
    bucket_project: str | None
    iam_resource_address: str | None
    role: str
    role_kind: str
    access_classes: list[GcpGcsAccessClass]
    custom_role_permissions: list[str]
    matched_permissions: list[str]
    grant_basis: Literal["storage_bucket_iam", "storage_project_iam"]
    resource_scope: Literal["exact_bucket"]
    condition: dict[str, object] | None
    condition_state: Literal["configured", "not_configured"]
    access_state: GcpGcsAccessState
    grant_project: NotRequired[str]
    permission_constraints: NotRequired[list[GcsPermissionConstraint]]


class GcpCloudRunGcsProtectedDataConvergence(TypedDict):
    workload_address: str
    workload_type: str
    service_account_email: str
    service_account_member: str
    bucket_address: str
    bucket_name: str
    key_address: str
    key_resource_name: str
    operation: Literal["cloudkms.cryptoKeyVersions.useToDecrypt"]
    access_class: Literal["read"]
    runtime_identity_match: Literal[True]
    protected_resource_match: Literal[True]
    key_identity_match: Literal[True]
    convergence_state: Literal["resolved"]
    evaluation_basis: Literal["exact_gcs_access_cmek_dependency_and_decrypt_authority"]
    access_path: GcpCloudRunGcsAccessPath
    key_operation_path: GcpCloudRunKmsOperationPath
    encryption_dependency: GcpKmsEncryptionDependency
    posture_uncertainties: list[str]
