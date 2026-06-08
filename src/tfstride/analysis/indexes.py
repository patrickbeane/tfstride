from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from tfstride.analysis.gcp_iam_inheritance import (
    GcpIamInheritanceIndex,
    build_gcp_iam_inheritance_index,
    empty_gcp_iam_inheritance_index,
)
from tfstride.analysis.resource_concepts import (
    IDENTITY_ROLE_RESOURCE_TYPES,
    is_network_security_group_resource,
)
from tfstride.models import NormalizedResource, ResourceInventory


@dataclass(frozen=True, slots=True)
class AnalysisIndexes:
    role_index: Mapping[str, NormalizedResource]
    security_groups_by_reference: Mapping[str, NormalizedResource]
    resources_by_security_group: Mapping[str, tuple[NormalizedResource, ...]]
    public_workloads_by_security_group: Mapping[str, tuple[NormalizedResource, ...]]
    gcp_iam_inheritance: GcpIamInheritanceIndex

    def attached_security_groups(self, resource: NormalizedResource) -> list[NormalizedResource]:
        return [
            security_group
            for security_group_id in resource.security_group_ids
            if (security_group := self.security_groups_by_reference.get(security_group_id)) is not None
        ]


def build_analysis_indexes(inventory: ResourceInventory) -> AnalysisIndexes:
    resources_by_reference = _build_resource_reference_index(inventory.resources)
    security_groups_by_reference = {
        reference: resource
        for reference, resource in resources_by_reference.items()
        if is_network_security_group_resource(resource)
    }

    return AnalysisIndexes(
        role_index=_freeze_resource_map(_build_role_index(inventory)),
        security_groups_by_reference=_freeze_resource_map(security_groups_by_reference),
        resources_by_security_group=_freeze_resource_groups(
            _group_resources_by_security_group(inventory.resources)
        ),
        public_workloads_by_security_group=_freeze_resource_groups(
            _group_resources_by_security_group(
                resource for resource in inventory.resources if resource.public_exposure
            )
        ),
        gcp_iam_inheritance=(
            build_gcp_iam_inheritance_index(inventory.resources)
            if inventory.provider == "gcp"
            else empty_gcp_iam_inheritance_index()
        ),
    )


def _build_role_index(inventory: ResourceInventory) -> dict[str, NormalizedResource]:
    index: dict[str, NormalizedResource] = {}
    for role in inventory.by_type(*IDENTITY_ROLE_RESOURCE_TYPES):
        if role.arn:
            index[role.arn] = role
        index[role.address] = role
        if role.identifier:
            index[role.identifier] = role
    return index


def _build_resource_reference_index(
    resources: Iterable[NormalizedResource],
) -> dict[str, NormalizedResource]:
    index: dict[str, NormalizedResource] = {}
    for resource in resources:
        for reference in (resource.identifier, resource.arn, resource.address):
            if reference:
                index.setdefault(reference, resource)
    return index


def _group_resources_by_security_group(
    resources: Iterable[NormalizedResource],
) -> dict[str, list[NormalizedResource]]:
    grouped: dict[str, list[NormalizedResource]] = {}
    for resource in resources:
        for security_group_id in resource.security_group_ids:
            grouped.setdefault(security_group_id, []).append(resource)
    return grouped


def _freeze_resource_map(
    resource_map: dict[str, NormalizedResource],
) -> Mapping[str, NormalizedResource]:
    return MappingProxyType(dict(resource_map))


def _freeze_resource_groups(
    resource_groups: dict[str, list[NormalizedResource]],
) -> Mapping[str, tuple[NormalizedResource, ...]]:
    return MappingProxyType({
        security_group_id: tuple(resources)
        for security_group_id, resources in resource_groups.items()
    })