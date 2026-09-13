from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TypeVar

from tfstride.analysis.resource_concepts import (
    IDENTITY_ROLE_RESOURCE_TYPES,
    is_network_security_group_resource,
)
from tfstride.models import NormalizedResource, ResourceInventory
from tfstride.providers.resource_reference_index import (
    ResourceReferenceIndex,
    build_resource_reference_index,
)

_Extension = TypeVar("_Extension")
AnalysisIndexExtensionFactory = Callable[[ResourceInventory], object]


class AnalysisIndexExtensionError(TypeError):
    """Raised when provider-specific analysis indexes are unavailable or have the wrong type."""


@dataclass(frozen=True, slots=True)
class AnalysisIndexes:
    role_index: ResourceReferenceIndex
    security_groups_by_reference: ResourceReferenceIndex
    resources_by_security_group: Mapping[str, tuple[NormalizedResource, ...]]
    public_workloads_by_security_group: Mapping[str, tuple[NormalizedResource, ...]]
    provider_extension: object | None = None

    def attached_security_groups(self, resource: NormalizedResource) -> list[NormalizedResource]:
        return [
            security_group
            for security_group_id in resource.security_group_ids
            if (security_group := self.security_groups_by_reference.unique_candidate(security_group_id)) is not None
        ]

    def require_provider_extension(self, extension_type: type[_Extension]) -> _Extension:
        extension = self.provider_extension
        if isinstance(extension, extension_type):
            return extension
        actual_type = type(extension).__name__ if extension is not None else "none"
        raise AnalysisIndexExtensionError(
            f"Expected analysis index extension `{extension_type.__name__}`, found `{actual_type}`."
        )


def build_analysis_indexes(
    inventory: ResourceInventory,
    *,
    provider_extension_factory: AnalysisIndexExtensionFactory | None = None,
) -> AnalysisIndexes:
    role_index = build_resource_reference_index(
        inventory.by_type(*IDENTITY_ROLE_RESOURCE_TYPES),
        references_for_resource=_analysis_resource_references,
    )
    security_groups_by_reference = build_resource_reference_index(
        (resource for resource in inventory.resources if is_network_security_group_resource(resource)),
        references_for_resource=_analysis_resource_references,
    )

    resolved_extension_factory = (
        provider_extension_factory
        if provider_extension_factory is not None
        else _default_provider_extension_factory(inventory.provider)
    )

    return AnalysisIndexes(
        role_index=role_index,
        security_groups_by_reference=security_groups_by_reference,
        resources_by_security_group=_freeze_resource_groups(_group_resources_by_security_group(inventory.resources)),
        public_workloads_by_security_group=_freeze_resource_groups(
            _group_resources_by_security_group(resource for resource in inventory.resources if resource.public_exposure)
        ),
        provider_extension=(resolved_extension_factory(inventory) if resolved_extension_factory is not None else None),
    )


def _default_provider_extension_factory(provider: str) -> AnalysisIndexExtensionFactory | None:
    from tfstride.providers.catalog import default_provider_analysis_index_factory

    return default_provider_analysis_index_factory(provider)


def _analysis_resource_references(resource: NormalizedResource) -> tuple[str | None, ...]:
    return resource.address, resource.identifier, resource.arn


def _group_resources_by_security_group(
    resources: Iterable[NormalizedResource],
) -> dict[str, list[NormalizedResource]]:
    grouped: dict[str, list[NormalizedResource]] = {}
    for resource in resources:
        for security_group_id in resource.security_group_ids:
            grouped.setdefault(security_group_id, []).append(resource)
    return grouped


def _freeze_resource_groups(
    resource_groups: dict[str, list[NormalizedResource]],
) -> Mapping[str, tuple[NormalizedResource, ...]]:
    return MappingProxyType(
        {security_group_id: tuple(resources) for security_group_id, resources in resource_groups.items()}
    )
