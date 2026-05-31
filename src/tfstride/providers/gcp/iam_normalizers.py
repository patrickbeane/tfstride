from __future__ import annotations

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.network_normalizers import GCP_PROVIDER
from tfstride.providers.gcp.resource_utils import first_non_empty


def normalize_project_iam_member(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    role = first_non_empty(values.get("role"))
    member = first_non_empty(values.get("member"))
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(values.get("id"), role and member and f"{role}:{member}", resource.address),
        metadata={
            GcpResourceMetadata.PROJECT.key: values.get("project"),
            GcpResourceMetadata.IAM_ROLE.key: role,
            GcpResourceMetadata.IAM_MEMBER.key: member,
            "condition": values.get("condition"),
        },
    )