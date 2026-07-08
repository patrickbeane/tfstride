from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TypeVar

from tfstride.analysis.resource_facts import analysis_facts
from tfstride.models import NormalizedResource
from tfstride.providers.gcp.resource_types import (
    GCP_FOLDER_IAM_RESOURCE_TYPES,
    GCP_IAM_GRANT_RESOURCE_TYPES,
    GCP_ORGANIZATION_IAM_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
)
from tfstride.providers.gcp.resource_utils import gcp_reference_key

_T = TypeVar("_T")

GCP_IAM_SCOPE_ORGANIZATION = "organization"
GCP_IAM_SCOPE_FOLDER = "folder"
GCP_IAM_SCOPE_PROJECT = "project"
GCP_IAM_SCOPE_RESOURCE = "resource"


@dataclass(frozen=True, slots=True)
class GcpIamScopeKey:
    scope_type: str
    identifier: str

    @property
    def label(self) -> str:
        return f"{self.scope_type}:{self.identifier}"


@dataclass(frozen=True, slots=True)
class GcpIamInheritanceIndex:
    resources_by_project: Mapping[str, tuple[NormalizedResource, ...]]
    resources_by_folder: Mapping[str, tuple[NormalizedResource, ...]]
    resources_by_organization: Mapping[str, tuple[NormalizedResource, ...]]
    descendant_resources_by_scope: Mapping[GcpIamScopeKey, tuple[NormalizedResource, ...]]
    iam_resources_by_scope: Mapping[GcpIamScopeKey, tuple[NormalizedResource, ...]]
    iam_scopes_by_address: Mapping[str, tuple[GcpIamScopeKey, ...]]
    resource_targets_by_iam_address: Mapping[str, tuple[NormalizedResource, ...]]
    unresolved_iam_resources: tuple[NormalizedResource, ...]

    def scopes_for_iam_resource(self, resource: NormalizedResource) -> tuple[GcpIamScopeKey, ...]:
        return self.iam_scopes_by_address.get(resource.address, ())

    def descendant_resources_for_scope(
        self,
        scope: GcpIamScopeKey,
    ) -> tuple[NormalizedResource, ...]:
        return self.descendant_resources_by_scope.get(scope, ())

    def descendant_resources_for_iam_resource(
        self,
        resource: NormalizedResource,
    ) -> tuple[NormalizedResource, ...]:
        descendants: list[NormalizedResource] = []
        seen: set[str] = set()
        for scope in self.scopes_for_iam_resource(resource):
            for descendant in self.descendant_resources_for_scope(scope):
                if descendant.address in seen:
                    continue
                seen.add(descendant.address)
                descendants.append(descendant)
        return tuple(descendants)

    def target_resources_for_iam_resource(
        self,
        resource: NormalizedResource,
    ) -> tuple[NormalizedResource, ...]:
        return self.resource_targets_by_iam_address.get(resource.address, ())


_EMPTY_GCP_IAM_INHERITANCE_INDEX = GcpIamInheritanceIndex(
    resources_by_project=MappingProxyType({}),
    resources_by_folder=MappingProxyType({}),
    resources_by_organization=MappingProxyType({}),
    descendant_resources_by_scope=MappingProxyType({}),
    iam_resources_by_scope=MappingProxyType({}),
    iam_scopes_by_address=MappingProxyType({}),
    resource_targets_by_iam_address=MappingProxyType({}),
    unresolved_iam_resources=(),
)


def empty_gcp_iam_inheritance_index() -> GcpIamInheritanceIndex:
    return _EMPTY_GCP_IAM_INHERITANCE_INDEX


def build_gcp_iam_inheritance_index(
    resources: Iterable[NormalizedResource],
) -> GcpIamInheritanceIndex:
    resource_tuple = tuple(resources)
    if not any(resource.provider == "gcp" for resource in resource_tuple):
        return empty_gcp_iam_inheritance_index()

    reference_index = _build_resource_reference_index(resource_tuple)
    resources_by_project = _group_resources_by_scope(resource_tuple, _resource_project)
    resources_by_folder = _group_resources_by_scope(resource_tuple, _resource_folder_id)
    resources_by_organization = _group_resources_by_scope(resource_tuple, _resource_organization_id)
    descendant_resources_by_scope = _build_descendant_resources_by_scope(
        resource_tuple,
        resources_by_project,
        resources_by_folder,
        resources_by_organization,
    )

    iam_resources_by_scope: dict[GcpIamScopeKey, list[NormalizedResource]] = {}
    iam_scopes_by_address: dict[str, list[GcpIamScopeKey]] = {}
    resource_targets_by_iam_address: dict[str, list[NormalizedResource]] = {}
    unresolved_iam_resources: list[NormalizedResource] = []

    for resource in resource_tuple:
        if resource.resource_type not in GCP_IAM_GRANT_RESOURCE_TYPES:
            continue
        resolved_scopes = _resolve_iam_resource_scopes(resource, reference_index)
        if not resolved_scopes:
            unresolved_iam_resources.append(resource)
            continue
        for scope, target in resolved_scopes:
            _append_unique(iam_scopes_by_address.setdefault(resource.address, []), scope, lambda item: item.label)
            _append_unique(iam_resources_by_scope.setdefault(scope, []), resource, lambda item: item.address)
            if target is not None:
                _append_unique(
                    resource_targets_by_iam_address.setdefault(resource.address, []),
                    target,
                    lambda item: item.address,
                )

    return GcpIamInheritanceIndex(
        resources_by_project=_freeze_resource_groups(resources_by_project),
        resources_by_folder=_freeze_resource_groups(resources_by_folder),
        resources_by_organization=_freeze_resource_groups(resources_by_organization),
        descendant_resources_by_scope=_freeze_scope_resource_groups(descendant_resources_by_scope),
        iam_resources_by_scope=_freeze_scope_resource_groups(iam_resources_by_scope),
        iam_scopes_by_address=_freeze_scope_groups(iam_scopes_by_address),
        resource_targets_by_iam_address=_freeze_resource_address_groups(resource_targets_by_iam_address),
        unresolved_iam_resources=tuple(unresolved_iam_resources),
    )


def _build_descendant_resources_by_scope(
    resources: tuple[NormalizedResource, ...],
    resources_by_project: dict[str, list[NormalizedResource]],
    resources_by_folder: dict[str, list[NormalizedResource]],
    resources_by_organization: dict[str, list[NormalizedResource]],
) -> dict[GcpIamScopeKey, list[NormalizedResource]]:
    descendants: dict[GcpIamScopeKey, list[NormalizedResource]] = {}
    for project, project_resources in resources_by_project.items():
        descendants[GcpIamScopeKey(GCP_IAM_SCOPE_PROJECT, project)] = _descendant_candidates(project_resources)
    for folder_id, folder_resources in resources_by_folder.items():
        descendants[GcpIamScopeKey(GCP_IAM_SCOPE_FOLDER, folder_id)] = _descendant_candidates(folder_resources)
    for organization_id, organization_resources in resources_by_organization.items():
        descendants[GcpIamScopeKey(GCP_IAM_SCOPE_ORGANIZATION, organization_id)] = _descendant_candidates(
            organization_resources
        )
    for resource in resources:
        if not _is_descendant_candidate(resource):
            continue
        descendants[GcpIamScopeKey(GCP_IAM_SCOPE_RESOURCE, resource.address)] = [resource]
    return descendants


def _resolve_iam_resource_scopes(
    resource: NormalizedResource,
    reference_index: Mapping[str, tuple[NormalizedResource, ...]],
) -> list[tuple[GcpIamScopeKey, NormalizedResource | None]]:
    facts = analysis_facts(resource).iam
    if resource.resource_type in GCP_PROJECT_IAM_RESOURCE_TYPES:
        project = _normalize_project_id(facts.project)
        if project:
            return [(GcpIamScopeKey(GCP_IAM_SCOPE_PROJECT, project), None)]
        return []
    if resource.resource_type in GCP_ORGANIZATION_IAM_RESOURCE_TYPES:
        organization_id = _normalize_hierarchy_id(facts.organization_id, "organizations")
        if organization_id:
            return [(GcpIamScopeKey(GCP_IAM_SCOPE_ORGANIZATION, organization_id), None)]
        return []
    if resource.resource_type in GCP_FOLDER_IAM_RESOURCE_TYPES:
        folder_id = _normalize_hierarchy_id(facts.folder_id, "folders")
        if folder_id:
            return [(GcpIamScopeKey(GCP_IAM_SCOPE_FOLDER, folder_id), None)]
        return []

    target_reference = _resource_iam_target_reference(resource)
    if not target_reference:
        return []
    targets = reference_index.get(gcp_reference_key(target_reference), ())
    return [
        (GcpIamScopeKey(GCP_IAM_SCOPE_RESOURCE, target.address), target)
        for target in targets
        if _is_descendant_candidate(target)
    ]


def _resource_iam_target_reference(resource: NormalizedResource) -> str | None:
    return analysis_facts(resource).iam.target_reference


def _build_resource_reference_index(
    resources: tuple[NormalizedResource, ...],
) -> Mapping[str, tuple[NormalizedResource, ...]]:
    grouped: dict[str, list[NormalizedResource]] = {}
    for resource in resources:
        if not _is_descendant_candidate(resource):
            continue
        for reference in _resource_reference_keys(resource):
            _append_unique(grouped.setdefault(reference, []), resource, lambda item: item.address)
    return _freeze_resource_address_groups(grouped)


def _resource_reference_keys(resource: NormalizedResource) -> tuple[str, ...]:
    facts = analysis_facts(resource).iam
    references: set[str] = {
        resource.address,
        f"{resource.address}.id",
        f"{resource.address}.name",
    }
    for value in (resource.identifier, resource.arn, facts.resource_name):
        if value:
            references.add(str(value))
    references.update(facts.reference_values)
    email = facts.service_account_email
    if email:
        references.add(email)
        references.add(f"serviceAccount:{email}")
    member = facts.service_account_member
    if member:
        references.add(member)
        if member.startswith("serviceAccount:"):
            references.add(member.removeprefix("serviceAccount:"))
    return tuple(sorted(gcp_reference_key(reference) for reference in references if str(reference).strip()))


def _group_resources_by_scope(
    resources: tuple[NormalizedResource, ...],
    scope_resolver: Callable[[NormalizedResource], str | None],
) -> dict[str, list[NormalizedResource]]:
    grouped: dict[str, list[NormalizedResource]] = {}
    for resource in resources:
        if not _is_descendant_candidate(resource):
            continue
        scope = scope_resolver(resource)
        if not scope:
            continue
        grouped.setdefault(scope, []).append(resource)
    return grouped


def _resource_project(resource: NormalizedResource) -> str | None:
    facts = analysis_facts(resource).iam
    project = _normalize_project_id(facts.project)
    if project:
        return project
    for value in _scope_candidate_values(resource):
        project = _project_from_path(value)
        if project:
            return project
    return None


def _resource_folder_id(resource: NormalizedResource) -> str | None:
    facts = analysis_facts(resource).iam
    folder_id = _normalize_hierarchy_id(facts.folder_id, "folders")
    if folder_id:
        return folder_id
    for value in _scope_candidate_values(resource):
        folder_id = _path_segment(value, "folders")
        if folder_id:
            return folder_id
    return None


def _resource_organization_id(resource: NormalizedResource) -> str | None:
    facts = analysis_facts(resource).iam
    organization_id = _normalize_hierarchy_id(facts.organization_id, "organizations")
    if organization_id:
        return organization_id
    for value in _scope_candidate_values(resource):
        organization_id = _path_segment(value, "organizations")
        if organization_id:
            return organization_id
    return None


def _scope_candidate_values(resource: NormalizedResource) -> tuple[str, ...]:
    facts = analysis_facts(resource).iam
    values: list[str] = []
    for value in (resource.identifier, facts.resource_name):
        if value:
            values.append(str(value))
    values.extend(facts.reference_values)
    return tuple(values)


def _normalize_project_id(value: object) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    if not text:
        return None
    path_project = _project_from_path(text)
    return path_project or text


def _normalize_hierarchy_id(value: object, marker: str) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    if not text:
        return None
    path_id = _path_segment(text, marker)
    return path_id or text


def _project_from_path(value: str) -> str | None:
    return _path_segment(value, "projects")


def _path_segment(value: str, marker: str) -> str | None:
    parts = [part for part in str(value).strip().split("/") if part]
    try:
        marker_index = parts.index(marker)
    except ValueError:
        return None
    value_index = marker_index + 1
    if value_index >= len(parts):
        return None
    return parts[value_index] or None


def _descendant_candidates(resources: list[NormalizedResource]) -> list[NormalizedResource]:
    return [resource for resource in resources if _is_descendant_candidate(resource)]


def _is_descendant_candidate(resource: NormalizedResource) -> bool:
    return resource.resource_type not in GCP_IAM_GRANT_RESOURCE_TYPES


def _append_unique(items: list[_T], item: _T, key_getter: Callable[[_T], str]) -> None:
    key = key_getter(item)
    if any(key_getter(existing) == key for existing in items):
        return
    items.append(item)


def _freeze_resource_groups(
    groups: dict[str, list[NormalizedResource]],
) -> Mapping[str, tuple[NormalizedResource, ...]]:
    return MappingProxyType({key: tuple(resources) for key, resources in groups.items()})


def _freeze_resource_address_groups(
    groups: Mapping[str, list[NormalizedResource]],
) -> Mapping[str, tuple[NormalizedResource, ...]]:
    return MappingProxyType({key: tuple(resources) for key, resources in groups.items()})


def _freeze_scope_resource_groups(
    groups: dict[GcpIamScopeKey, list[NormalizedResource]],
) -> Mapping[GcpIamScopeKey, tuple[NormalizedResource, ...]]:
    return MappingProxyType({key: tuple(resources) for key, resources in groups.items()})


def _freeze_scope_groups(
    groups: dict[str, list[GcpIamScopeKey]],
) -> Mapping[str, tuple[GcpIamScopeKey, ...]]:
    return MappingProxyType({key: tuple(scopes) for key, scopes in groups.items()})
