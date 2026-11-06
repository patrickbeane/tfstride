from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.gcs_grant_evaluation import (
    GcpGcsBucketGrant,
    GcsGrantConstraintContext,
    evaluate_gcs_bucket_grants,
)
from tfstride.providers.gcp.protected_data_evidence import GcpCloudRunGcsAccessPath
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext
from tfstride.providers.gcp.resource_types import GCP_CLOUD_RUN_RESOURCE_TYPES, GcpResourceType

if TYPE_CHECKING:
    from tfstride.providers.gcp.custom_roles import GcpCustomRoleIndex


class ModelCloudRunGcsAccessPathsStage:
    name = "model_cloud_run_gcs_access_paths"

    def apply(self, resources: list[NormalizedResource], context: GcpDecorationContext) -> None:
        del context
        buckets = tuple(resource for resource in resources if resource.resource_type == GcpResourceType.STORAGE_BUCKET)
        workloads = tuple(resource for resource in resources if resource.resource_type in GCP_CLOUD_RUN_RESOURCE_TYPES)
        grant_context = GcsGrantConstraintContext.build(resources) if buckets and workloads else None
        custom_roles = grant_context.custom_roles if grant_context is not None else None
        for workload in workloads:
            paths, uncertainties = _cloud_run_gcs_access_paths(
                workload, buckets, custom_roles, resources, grant_context=grant_context
            )
            facts = gcp_facts(workload)
            facts.set_cloud_run_gcs_access_paths(paths)
            facts.extend_cloud_run_gcs_access_path_uncertainties(uncertainties)


def _cloud_run_gcs_access_paths(
    workload: NormalizedResource,
    buckets: tuple[NormalizedResource, ...],
    custom_roles: GcpCustomRoleIndex | None,
    resources: Sequence[NormalizedResource],
    *,
    grant_context: GcsGrantConstraintContext | None = None,
) -> tuple[list[GcpCloudRunGcsAccessPath], list[str]]:
    service_account_member = gcp_facts(workload).service_account_member
    if not service_account_member:
        return [], [f"{workload.address}: Cloud Run service account is unresolved"]

    grants, uncertainties = evaluate_gcs_bucket_grants(
        service_account_member, buckets, custom_roles, resources=resources, context=grant_context
    )
    return (
        [_access_path_record(workload, grant) for grant in grants],
        [f"{workload.address}: {uncertainty}" for uncertainty in uncertainties],
    )


def _access_path_record(workload: NormalizedResource, grant: GcpGcsBucketGrant) -> GcpCloudRunGcsAccessPath:
    path: GcpCloudRunGcsAccessPath = {
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
    if "custom_role_evidence" in grant:
        path["custom_role_evidence"] = grant["custom_role_evidence"]
    if "grant_scope" in grant:
        path["grant_scope"] = grant["grant_scope"]
    if "grant_ancestry" in grant:
        path["grant_ancestry"] = grant["grant_ancestry"]
    if "grant_project" in grant:
        path["grant_project"] = grant["grant_project"]
    if "permission_constraints" in grant:
        path["permission_constraints"] = grant["permission_constraints"]
    return path


def current_cloud_run_gcs_access_paths(
    workload: NormalizedResource,
    resources: Sequence[NormalizedResource],
    custom_roles: GcpCustomRoleIndex | None = None,
    *,
    grant_context: GcsGrantConstraintContext | None = None,
) -> list[GcpCloudRunGcsAccessPath]:
    """Reevaluate grants; a supplied context must describe the same current resources."""
    buckets = tuple(resource for resource in resources if resource.resource_type == GcpResourceType.STORAGE_BUCKET)
    return _cloud_run_gcs_access_paths(workload, buckets, custom_roles, resources, grant_context=grant_context)[0]
