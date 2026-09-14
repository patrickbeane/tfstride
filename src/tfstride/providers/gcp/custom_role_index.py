from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_types import GCP_CUSTOM_ROLE_RESOURCE_TYPES
from tfstride.providers.gcp.resource_utils import GCP_ROLE_REFERENCE_SUFFIXES, gcp_reference_key
from tfstride.providers.resource_reference_index import (
    ResourceReferenceIndex,
    ResourceReferenceResolution,
    build_resource_reference_index,
)


@dataclass(frozen=True, slots=True)
class GcpCustomRoleIndex:
    _reference_index: ResourceReferenceIndex
    permissions_by_reference: Mapping[str, tuple[str, ...]]

    def resolve(self, role: str | None) -> ResourceReferenceResolution:
        return self._reference_index.resolve(role)


def build_gcp_custom_role_index(resources: Iterable[NormalizedResource]) -> GcpCustomRoleIndex:
    custom_role_resources = tuple(
        resource for resource in resources if resource.resource_type in GCP_CUSTOM_ROLE_RESOURCE_TYPES
    )
    reference_index = build_resource_reference_index(
        custom_role_resources,
        references_for_resource=custom_role_reference_keys,
        reference_key=_custom_role_reference_key,
    )
    permissions_by_reference: dict[str, tuple[str, ...]] = {}
    for reference, candidates in reference_index.resources_by_reference.items():
        if len(candidates) != 1:
            continue
        permissions = _custom_role_permissions(candidates[0])
        if permissions:
            permissions_by_reference[reference] = permissions
    return GcpCustomRoleIndex(
        _reference_index=reference_index,
        permissions_by_reference=MappingProxyType(permissions_by_reference),
    )


def custom_role_permissions(role: str | None, custom_roles: GcpCustomRoleIndex) -> tuple[str, ...]:
    if not role:
        return ()
    return custom_roles.permissions_by_reference.get(_custom_role_reference_key(role), ())


def custom_role_reference_keys(resource: NormalizedResource) -> set[str]:
    custom_role_id = resource.get_metadata_field(GcpResourceMetadata.CUSTOM_ROLE_ID)
    project = resource.get_metadata_field(GcpResourceMetadata.PROJECT)
    organization_id = resource.get_metadata_field(GcpResourceMetadata.ORGANIZATION_ID)
    references: set[str | None] = {
        resource.address,
        f"{resource.address}.id",
        f"{resource.address}.name",
        f"{resource.address}.role_id",
        resource.identifier,
        resource.name,
        resource.get_metadata_field(GcpResourceMetadata.NAME),
        custom_role_id,
    }
    if project and custom_role_id:
        references.add(f"projects/{project}/roles/{custom_role_id}")
    if organization_id and custom_role_id:
        references.add(f"organizations/{organization_id}/roles/{custom_role_id}")
    return {_custom_role_reference_key(reference.strip()) for reference in references if reference}


def _custom_role_permissions(resource: NormalizedResource) -> tuple[str, ...]:
    permissions = resource.get_metadata_field(GcpResourceMetadata.CUSTOM_ROLE_PERMISSIONS)
    if not isinstance(permissions, list | tuple):
        return ()
    return tuple(sorted({str(permission).strip() for permission in permissions if str(permission).strip()}))


def _custom_role_reference_key(reference: str) -> str:
    return gcp_reference_key(reference, GCP_ROLE_REFERENCE_SUFFIXES)
