from __future__ import annotations

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.coercion import attribute_unknown
from tfstride.providers.gcp.attributes import GcpAttr, GcpValues
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer_common import GCP_PROVIDER
from tfstride.providers.gcp.resource_utils import first_non_empty
from tfstride.resource_metadata import MetadataField


def normalize_project(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    project_id = first_non_empty(
        values.get(GcpAttr.PROJECT_ID),
        _project_from_identifier(values.get(GcpAttr.ID)),
    )
    identifier = first_non_empty(values.get(GcpAttr.ID), project_id, resource.address)
    organization_id = first_non_empty(
        values.get(GcpAttr.ORG_ID),
        values.get(GcpAttr.ORGANIZATION_ID),
        _organization_from_parent(values.get(GcpAttr.PARENT)),
    )
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=identifier,
        metadata={
            GcpResourceMetadata.NAME: project_id,
            GcpResourceMetadata.PROJECT: project_id,
            **({GcpResourceMetadata.FOLDER_ID: values.get(GcpAttr.FOLDER_ID)} if values.get(GcpAttr.FOLDER_ID) else {}),
            **(
                {GcpResourceMetadata.HIERARCHY_PARENT: values.get(GcpAttr.PARENT)} if values.get(GcpAttr.PARENT) else {}
            ),
            **hierarchy_unknown_metadata(resource),
            GcpResourceMetadata.ORGANIZATION_ID: organization_id,
            GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
        },
    )


def hierarchy_unknown_metadata(resource: TerraformResource) -> dict[MetadataField[list[str]], list[str]]:
    fields = [
        key
        for key in (
            "project",
            "project_id",
            "folder_id",
            "org_id",
            "organization_id",
            "parent",
            "network_interface",
            "id",
            "name",
            "self_link",
        )
        if attribute_unknown(resource.unknown_values, key)
    ]
    return {GcpResourceMetadata.HIERARCHY_UNKNOWN_FIELDS: fields} if fields else {}


def normalize_folder(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    identifier = first_non_empty(values.get(GcpAttr.NAME), values.get(GcpAttr.ID), resource.address)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=identifier,
        metadata={
            GcpResourceMetadata.NAME: identifier,
            GcpResourceMetadata.FOLDER_ID: identifier,
            GcpResourceMetadata.HIERARCHY_PARENT: values.get(GcpAttr.PARENT),
            **hierarchy_unknown_metadata(resource),
        },
    )


def normalize_kms_key_ring(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    name = first_non_empty(values.get(GcpAttr.NAME))
    project = first_non_empty(
        values.get(GcpAttr.PROJECT),
        _project_from_identifier(values.get(GcpAttr.ID)),
    )
    location = first_non_empty(values.get(GcpAttr.LOCATION))
    canonical_ring = _key_ring_path(project, location, name)
    identifier = first_non_empty(values.get(GcpAttr.ID), canonical_ring, resource.address)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=identifier,
        metadata={
            GcpResourceMetadata.NAME: name,
            GcpResourceMetadata.PROJECT: project,
            GcpResourceMetadata.KMS_KEY_RING: first_non_empty(
                values.get(GcpAttr.ID),
                canonical_ring,
            ),
            GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
        },
    )


def _key_ring_path(project: str | None, location: str | None, name: str | None) -> str | None:
    if not project or not location or not name or "/" in name:
        return None
    return f"projects/{project}/locations/{location}/keyRings/{name}"


def _organization_from_parent(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    parent = value.strip().strip("/")
    prefix = "organizations/"
    if not parent.startswith(prefix):
        return None
    organization_id = parent.removeprefix(prefix)
    return organization_id or None


def _project_from_identifier(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    parts = value.strip("/").split("/")
    if len(parts) > 1 and parts[0] == "projects" and parts[1]:
        return parts[1]
    return None
