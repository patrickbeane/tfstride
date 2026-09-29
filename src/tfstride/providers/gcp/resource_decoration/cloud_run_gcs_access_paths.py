from __future__ import annotations

from typing import TYPE_CHECKING

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.gcs_grant_evaluation import GcpGcsBucketGrant, evaluate_gcs_bucket_grants
from tfstride.providers.gcp.protected_data_evidence import GcpCloudRunGcsAccessPath
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext
from tfstride.providers.gcp.resource_types import GCP_CLOUD_RUN_RESOURCE_TYPES, GcpResourceType

if TYPE_CHECKING:
    from tfstride.providers.gcp.custom_roles import GcpCustomRoleIndex


class ModelCloudRunGcsAccessPathsStage:
    name = "model_cloud_run_gcs_access_paths"

    def apply(self, resources: list[NormalizedResource], context: GcpDecorationContext) -> None:
        # Delay this provider-local import to keep normalizer/plugin initialization acyclic.
        from tfstride.providers.gcp.custom_roles import build_gcp_custom_role_index

        del context
        custom_roles = build_gcp_custom_role_index(resources)
        buckets = tuple(resource for resource in resources if resource.resource_type == GcpResourceType.STORAGE_BUCKET)
        for workload in resources:
            if workload.resource_type not in GCP_CLOUD_RUN_RESOURCE_TYPES:
                continue
            paths, uncertainties = _cloud_run_gcs_access_paths(workload, buckets, custom_roles)
            facts = gcp_facts(workload)
            facts.set_cloud_run_gcs_access_paths(paths)
            facts.extend_cloud_run_gcs_access_path_uncertainties(uncertainties)


def _cloud_run_gcs_access_paths(
    workload: NormalizedResource,
    buckets: tuple[NormalizedResource, ...],
    custom_roles: GcpCustomRoleIndex,
) -> tuple[list[GcpCloudRunGcsAccessPath], list[str]]:
    service_account_member = gcp_facts(workload).service_account_member
    if not service_account_member:
        return [], [f"{workload.address}: Cloud Run service account is unresolved"]

    grants, uncertainties = evaluate_gcs_bucket_grants(service_account_member, buckets, custom_roles)
    return (
        [_access_path_record(workload, grant) for grant in grants],
        [f"{workload.address}: {uncertainty}" for uncertainty in uncertainties],
    )


def _access_path_record(workload: NormalizedResource, grant: GcpGcsBucketGrant) -> GcpCloudRunGcsAccessPath:
    return {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "service_account_email": gcp_facts(workload).service_account_email,
        "service_account_member": grant["principal"],
        "identity_kind": "cloud_run_service_account",
        "credential_context": "workload_runtime",
        "bucket_address": grant["bucket_address"],
        "bucket_name": grant["bucket_name"],
        "bucket_project": grant["bucket_project"],
        "iam_resource_address": grant["iam_resource_address"],
        "role": grant["role"],
        "role_kind": grant["role_kind"],
        "access_classes": grant["access_classes"],
        "custom_role_permissions": grant["custom_role_permissions"],
        "matched_permissions": grant["matched_permissions"],
        "grant_basis": grant["grant_basis"],
        "resource_scope": grant["resource_scope"],
        "condition": grant["condition"],
        "condition_state": grant["condition_state"],
        "access_state": grant["access_state"],
    }
