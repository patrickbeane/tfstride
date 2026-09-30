from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

from tfstride.models import NormalizedResource
from tfstride.providers.coercion import STATE_CONFIGURED, dedupe
from tfstride.providers.gcp.custom_role_index import build_gcp_custom_role_index
from tfstride.providers.gcp.gcs_grant_evaluation import GCS_ACCESS_IAM_TYPES_BY_BASIS, gcs_path_permissions
from tfstride.providers.gcp.kms_dependency_evidence import (
    GcpKmsEncryptionDependency,
)
from tfstride.providers.gcp.kms_evidence import GcpCloudRunKmsOperationPath
from tfstride.providers.gcp.protected_data_evidence import (
    GcpCloudRunGcsAccessPath,
    GcpCloudRunGcsProtectedDataConvergence,
)
from tfstride.providers.gcp.resource_decoration.cloud_run_gcs_access_paths import current_cloud_run_gcs_access_paths
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext
from tfstride.providers.gcp.resource_types import (
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    GCP_KMS_CRYPTO_KEY_IAM_RESOURCE_TYPES,
    GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GcpResourceType,
)

_DECRYPT_PERMISSION = "cloudkms.cryptoKeyVersions.useToDecrypt"
_KMS_IAM_RESOURCE_TYPES = (
    GCP_PROJECT_IAM_RESOURCE_TYPES | GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES | GCP_KMS_CRYPTO_KEY_IAM_RESOURCE_TYPES
)
_GCS_CMEK_PATH = ["encryption", 0, "default_kms_key_name"]
_KEY_PATH_PATTERN = re.compile(
    r"^projects/(?P<project>[^/]+)/locations/(?P<location>[^/]+)/"
    r"keyRings/(?P<key_ring>[^/]+)/cryptoKeys/(?P<key>[^/]+)$"
)


class ModelCloudRunGcsProtectedDataConvergenceStage:
    name = "model_cloud_run_gcs_protected_data_convergence"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: GcpDecorationContext,
    ) -> None:
        del context
        resources_by_address = {resource.address: resource for resource in resources}
        for workload in resources:
            if workload.resource_type not in GCP_CLOUD_RUN_RESOURCE_TYPES:
                continue
            convergences, uncertainties = _protected_data_convergences(
                workload,
                resources_by_address,
            )
            facts = gcp_facts(workload)
            facts.set_cloud_run_gcs_protected_data_convergences(convergences)
            facts.extend_cloud_run_gcs_protected_data_convergence_uncertainties(uncertainties)


def _protected_data_convergences(
    workload: NormalizedResource,
    resources_by_address: Mapping[str, NormalizedResource],
) -> tuple[list[GcpCloudRunGcsProtectedDataConvergence], list[str]]:
    facts = gcp_facts(workload)
    uncertainties = [
        *facts.cloud_run_gcs_access_path_uncertainties,
        *facts.cloud_run_kms_operation_path_uncertainties,
    ]
    convergences: list[GcpCloudRunGcsProtectedDataConvergence] = []
    resources = list(resources_by_address.values())
    current_paths = current_cloud_run_gcs_access_paths(workload, resources, build_gcp_custom_role_index(resources))

    for access_path in facts.cloud_run_gcs_access_paths:
        if not _potential_payload_read(access_path):
            continue
        bucket = _access_path_bucket(
            access_path,
            workload,
            resources_by_address,
        )
        if bucket is None:
            uncertainties.append(
                f"{workload.address}: GCS access evidence does not retain "
                "an exact modeled bucket for protected-data convergence"
            )
            continue

        bucket_facts = gcp_facts(bucket)
        dependencies = bucket_facts.kms_encryption_dependencies
        uncertainties.extend(
            f"{workload.address}: {uncertainty}" for uncertainty in bucket_facts.kms_encryption_dependency_uncertainties
        )
        _append_dependency_uncertainties(
            workload,
            bucket,
            dependencies,
            uncertainties,
        )

        if not _deterministic_payload_read(
            access_path,
            workload,
            bucket,
            resources_by_address,
            current_paths,
        ):
            if dependencies:
                uncertainties.append(
                    f"{workload.address}: GCS payload-read authority to "
                    f"{bucket.address} is not deterministic for "
                    "protected-data convergence"
                )
            continue

        for dependency in dependencies:
            key = _dependency_key(
                dependency,
                bucket,
                resources_by_address,
            )
            if key is None:
                continue
            for operation_path in facts.cloud_run_kms_operation_paths:
                if not _deterministic_decrypt_path(
                    operation_path,
                    workload,
                    access_path,
                    key,
                    resources_by_address,
                ):
                    continue
                if not _dependency_matches_decrypt_path(
                    dependency,
                    operation_path,
                    key,
                ):
                    continue
                convergences.append(
                    _convergence_record(
                        workload,
                        access_path,
                        operation_path,
                        dependency,
                    )
                )

    return _dedupe_convergences(convergences), dedupe(uncertainties)


def _potential_payload_read(path: GcpCloudRunGcsAccessPath) -> bool:
    return "storage.objects.get" in gcs_path_permissions(path)


def _deterministic_payload_read(
    path: GcpCloudRunGcsAccessPath,
    workload: NormalizedResource,
    bucket: NormalizedResource,
    resources_by_address: Mapping[str, NormalizedResource],
    current_paths: list[GcpCloudRunGcsAccessPath],
) -> bool:
    workload_facts = gcp_facts(workload)
    service_account_email = workload_facts.service_account_email
    service_account_member = workload_facts.service_account_member
    iam_resource_address = path["iam_resource_address"]
    iam_resource = resources_by_address.get(iam_resource_address) if isinstance(iam_resource_address, str) else None
    bucket_facts = gcp_facts(bucket)
    return bool(
        isinstance(service_account_email, str)
        and service_account_email
        and service_account_member == f"serviceAccount:{service_account_email}"
        and path["workload_address"] == workload.address
        and path["workload_type"] == workload.resource_type
        and path["service_account_email"] == service_account_email
        and path["service_account_member"] == service_account_member
        and path["identity_kind"] == "cloud_run_service_account"
        and path["credential_context"] == "workload_runtime"
        and path["bucket_address"] == bucket.address
        and path["bucket_name"] == (bucket_facts.bucket_name or bucket.name)
        and path["bucket_project"] == bucket_facts.project
        and iam_resource is not None
        and iam_resource.provider == "gcp"
        and iam_resource.resource_type in GCS_ACCESS_IAM_TYPES_BY_BASIS.get(path["grant_basis"], frozenset())
        and path in current_paths
        and path["grant_basis"] in GCS_ACCESS_IAM_TYPES_BY_BASIS
        and path["resource_scope"] == "exact_bucket"
        and path["condition"] is None
        and path["condition_state"] == "not_configured"
        and path["access_state"] == "granted"
        and "read" in path["access_classes"]
        and _potential_payload_read(path)
    )


def _access_path_bucket(
    path: GcpCloudRunGcsAccessPath,
    workload: NormalizedResource,
    resources_by_address: Mapping[str, NormalizedResource],
) -> NormalizedResource | None:
    if path["workload_address"] != workload.address or path["workload_type"] != workload.resource_type:
        return None
    bucket = resources_by_address.get(path["bucket_address"])
    if bucket is None or bucket.provider != "gcp" or bucket.resource_type != GcpResourceType.STORAGE_BUCKET:
        return None
    return bucket


def _append_dependency_uncertainties(
    workload: NormalizedResource,
    bucket: NormalizedResource,
    dependencies: Sequence[GcpKmsEncryptionDependency],
    uncertainties: list[str],
) -> None:
    for dependency in dependencies:
        if dependency["resolution_state"] == "resolved":
            if dependency["customer_managed_encryption_state"] == "unknown":
                uncertainties.append(
                    f"{workload.address}: {bucket.address} Cloud KMS dependency has unresolved encryption ownership"
                )
            continue
        if dependency["posture_uncertainties"]:
            uncertainties.extend(
                f"{workload.address}: {bucket.address} Cloud KMS dependency "
                f"is {dependency['resolution_state']}: {uncertainty}"
                for uncertainty in dependency["posture_uncertainties"]
            )
        else:
            uncertainties.append(
                f"{workload.address}: {bucket.address} Cloud KMS dependency is {dependency['resolution_state']}"
            )


def _dependency_key(
    dependency: GcpKmsEncryptionDependency,
    bucket: NormalizedResource,
    resources_by_address: Mapping[str, NormalizedResource],
) -> NormalizedResource | None:
    if (
        dependency["resolution_state"] != "resolved"
        or dependency["customer_managed_encryption_state"] != STATE_CONFIGURED
        or dependency["dependent_address"] != bucket.address
        or dependency["dependent_resource_type"] != bucket.resource_type
        or dependency["dependency_source_address"] != bucket.address
        or dependency["dependency_source_type"] != bucket.resource_type
        or dependency["configuration_path"] != _GCS_CMEK_PATH
        or dependency["version_reference_is_explicit"]
        or dependency["key_version_address"] is not None
        or dependency["key_version_resource_name"] is not None
    ):
        return None

    key_address = dependency["key_address"]
    key = resources_by_address.get(key_address) if isinstance(key_address, str) else None
    if key is None or key.provider != "gcp" or key.resource_type != GcpResourceType.KMS_CRYPTO_KEY:
        return None
    key_resource_name = _key_resource_name(key)
    key_match = _KEY_PATH_PATTERN.fullmatch(key_resource_name) if key_resource_name is not None else None
    if (
        key_resource_name is None
        or key_match is None
        or dependency["key_resource_name"] != key_resource_name
        or dependency["key_project"] != key_match.group("project")
        or dependency["key_location"] != key_match.group("location")
        or dependency["key_ring"] != key_resource_name.rsplit("/cryptoKeys/", 1)[0]
        or dependency["key_purpose"] != gcp_facts(key).kms_purpose
        or not _dependency_candidate_is_coherent(dependency, key)
    ):
        return None
    return key


def _dependency_candidate_is_coherent(
    dependency: GcpKmsEncryptionDependency,
    key: NormalizedResource,
) -> bool:
    if dependency["candidate_targets"] != [
        {
            "address": key.address,
            "target_kind": "crypto_key",
        }
    ]:
        return False

    configured = dependency["configured_key_reference"]
    provenance = dependency["reference_provenance"]
    reference_kind = dependency["reference_kind"]
    key_resource_name = _key_resource_name(key)
    if provenance == "planned_value":
        return bool(reference_kind == "crypto_key_resource_name" and configured == key_resource_name)
    return bool(
        provenance == "configuration_reference"
        and reference_kind == "terraform_reference"
        and isinstance(configured, str)
        and configured == f"{key.address}.id"
    )


def _deterministic_decrypt_path(
    path: GcpCloudRunKmsOperationPath,
    workload: NormalizedResource,
    access_path: GcpCloudRunGcsAccessPath,
    key: NormalizedResource,
    resources_by_address: Mapping[str, NormalizedResource],
) -> bool:
    key_resource_name = _key_resource_name(key)
    key_match = _KEY_PATH_PATTERN.fullmatch(key_resource_name) if key_resource_name is not None else None
    iam_resource = resources_by_address.get(path["iam_resource_address"])
    if (
        key_resource_name is None
        or key_match is None
        or iam_resource is None
        or iam_resource.provider != "gcp"
        or iam_resource.resource_type not in _KMS_IAM_RESOURCE_TYPES
        or iam_resource.resource_type != path["iam_resource_type"]
    ):
        return False

    expected_scopes: dict[str, str] = {
        "project": key_match.group("project"),
        "key_ring": key_resource_name.rsplit("/cryptoKeys/", 1)[0],
        "crypto_key": key_resource_name,
    }
    expected_scope = expected_scopes.get(path["scope_type"])
    grant = path["iam_grant_record"]
    return bool(
        path["workload_address"] == workload.address
        and path["workload_type"] == workload.resource_type
        and path["service_account_email"] == access_path["service_account_email"]
        and path["service_account_member"] == access_path["service_account_member"]
        and path["identity_kind"] == "cloud_run_service_account"
        and path["credential_context"] == "workload_runtime"
        and path["key_address"] == key.address
        and path["key_resource_type"] == key.resource_type
        and path["key_resource_name"] == key_resource_name
        and path["key_project"] == key_match.group("project")
        and path["key_ring"] == key_resource_name.rsplit("/cryptoKeys/", 1)[0]
        and path["key_purpose"] == "ENCRYPT_DECRYPT"
        and path["operation"] == _DECRYPT_PERMISSION
        and path["operation_class"] == "decrypt"
        and path["matched_permissions"] == [_DECRYPT_PERMISSION]
        and _DECRYPT_PERMISSION in path["scope_effective_permissions"]
        and path["scope"] == expected_scope
        and path["management_state"] == "unambiguous"
        and path["condition"] is None
        and path["condition_state"] == "not_configured"
        and path["authorization_state"] == "granted"
        and path["authorization_model"] == "cloud_kms_iam"
        and path["iam_scope_is_key_version"] is False
        and access_path["service_account_member"] in path["grant_members"]
        and _grant_matches_path(grant, path)
    )


def _grant_matches_path(
    grant: Mapping[str, object],
    path: GcpCloudRunKmsOperationPath,
) -> bool:
    members = grant.get("members")
    scope_effective_permissions = grant.get("scope_effective_permissions")
    return bool(
        grant.get("source") == path["iam_resource_address"]
        and grant.get("source_type") == path["iam_resource_type"]
        and grant.get("role") == path["role"]
        and grant.get("scope_type") == path["scope_type"]
        and grant.get("scope") == path["scope"]
        and grant.get("crypto_key_address") == path["key_address"]
        and grant.get("crypto_key") == path["key_resource_name"]
        and grant.get("project") == path["key_project"]
        and grant.get("key_ring") == path["key_ring"]
        and grant.get("authorization_state") == "granted"
        and grant.get("management_state") == "unambiguous"
        and grant.get("condition_state") == "not_configured"
        and isinstance(scope_effective_permissions, list)
        and _DECRYPT_PERMISSION in scope_effective_permissions
        and isinstance(members, list)
        and path["service_account_member"] in members
    )


def _dependency_matches_decrypt_path(
    dependency: GcpKmsEncryptionDependency,
    path: GcpCloudRunKmsOperationPath,
    key: NormalizedResource,
) -> bool:
    key_resource_name = _key_resource_name(key)
    return bool(
        dependency["key_address"] == path["key_address"] == key.address
        and dependency["key_resource_name"] == path["key_resource_name"] == key_resource_name
        and dependency["key_project"] == path["key_project"]
        and dependency["key_ring"] == path["key_ring"]
        and dependency["key_purpose"] == path["key_purpose"]
    )


def _convergence_record(
    workload: NormalizedResource,
    access_path: GcpCloudRunGcsAccessPath,
    operation_path: GcpCloudRunKmsOperationPath,
    dependency: GcpKmsEncryptionDependency,
) -> GcpCloudRunGcsProtectedDataConvergence:
    service_account_email = access_path["service_account_email"]
    key_resource_name = dependency["key_resource_name"]
    assert service_account_email is not None
    assert key_resource_name is not None
    return {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "service_account_email": service_account_email,
        "service_account_member": access_path["service_account_member"],
        "bucket_address": access_path["bucket_address"],
        "bucket_name": access_path["bucket_name"],
        "key_address": operation_path["key_address"],
        "key_resource_name": key_resource_name,
        "operation": _DECRYPT_PERMISSION,
        "access_class": "read",
        "runtime_identity_match": True,
        "protected_resource_match": True,
        "key_identity_match": True,
        "convergence_state": "resolved",
        "evaluation_basis": ("exact_gcs_access_cmek_dependency_and_decrypt_authority"),
        "access_path": access_path.copy(),
        "key_operation_path": operation_path.copy(),
        "encryption_dependency": dependency.copy(),
        "posture_uncertainties": [],
    }


def _dedupe_convergences(
    convergences: Sequence[GcpCloudRunGcsProtectedDataConvergence],
) -> list[GcpCloudRunGcsProtectedDataConvergence]:
    seen: set[tuple[str, str, str, str, str, str]] = set()
    result: list[GcpCloudRunGcsProtectedDataConvergence] = []
    for convergence in convergences:
        fingerprint = (
            convergence["workload_address"],
            convergence["service_account_member"],
            convergence["bucket_address"],
            convergence["key_address"],
            convergence["access_path"]["iam_resource_address"] or "",
            convergence["key_operation_path"]["iam_resource_address"],
        )
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        result.append(convergence)
    return sorted(
        result,
        key=lambda item: (
            item["bucket_address"],
            item["key_address"],
            item["key_operation_path"]["scope_type"],
            item["key_operation_path"]["scope"],
        ),
    )


def _key_resource_name(key: NormalizedResource) -> str | None:
    facts = gcp_facts(key)
    for value in (facts.kms_crypto_key_reference, key.identifier):
        if not isinstance(value, str):
            continue
        text = value.strip().rstrip("/")
        if _KEY_PATH_PATTERN.fullmatch(text):
            return text
    return None
