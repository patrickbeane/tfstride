from __future__ import annotations

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.gcp.attributes import GcpAttr, GcpValues
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer_common import GCP_PROVIDER
from tfstride.providers.gcp.resource_utils import first_non_empty


def normalize_project_iam_custom_role(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    role_id = first_non_empty(values.get(GcpAttr.ROLE_ID), resource.name)
    project = first_non_empty(values.get(GcpAttr.PROJECT))
    name = first_non_empty(values.get(GcpAttr.NAME), _project_custom_role_name(project, role_id))
    return _normalize_custom_role(
        resource,
        identifier=first_non_empty(values.get(GcpAttr.ID), name, role_id, resource.address),
        role_id=role_id,
        name=name,
        project=project,
        organization_id=None,
    )


def normalize_organization_iam_custom_role(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    role_id = first_non_empty(values.get(GcpAttr.ROLE_ID), resource.name)
    organization_id = first_non_empty(values.get(GcpAttr.ORG_ID), values.get(GcpAttr.ORGANIZATION_ID))
    name = first_non_empty(values.get(GcpAttr.NAME), _organization_custom_role_name(organization_id, role_id))
    return _normalize_custom_role(
        resource,
        identifier=first_non_empty(values.get(GcpAttr.ID), name, role_id, resource.address),
        role_id=role_id,
        name=name,
        project=None,
        organization_id=organization_id,
    )


def _normalize_custom_role(
    resource: TerraformResource,
    *,
    identifier: str | None,
    role_id: str | None,
    name: str | None,
    project: str | None,
    organization_id: str | None,
) -> NormalizedResource:
    values = GcpValues(resource.values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(identifier, resource.address),
        metadata={
            GcpResourceMetadata.NAME: name,
            GcpResourceMetadata.PROJECT: project,
            GcpResourceMetadata.ORGANIZATION_ID: organization_id,
            GcpResourceMetadata.CUSTOM_ROLE_ID: role_id,
            GcpResourceMetadata.CUSTOM_ROLE_PERMISSIONS: values.get(GcpAttr.PERMISSIONS),
            GcpResourceMetadata.CUSTOM_ROLE_STAGE: values.get(GcpAttr.STAGE),
            "title": values.get(GcpAttr.TITLE),
            "description": values.get(GcpAttr.DESCRIPTION),
            "deleted": values.get(GcpAttr.DELETED),
        },
    )


def _project_custom_role_name(project: str | None, role_id: str | None) -> str | None:
    if not project or not role_id:
        return None
    return f"projects/{project}/roles/{role_id}"


def _organization_custom_role_name(organization_id: str | None, role_id: str | None) -> str | None:
    if not organization_id or not role_id:
        return None
    return f"organizations/{organization_id}/roles/{role_id}"
