"""Modeled project/folder ancestry shared by provider-specific evaluators.

Only explicit parent links establish ancestry; missing links retain uncertainty.
Scope membership establishes ownership hierarchy, not network reachability.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_index import GcpResourceIndex
from tfstride.providers.gcp.resource_types import GcpResourceType
from tfstride.providers.gcp.resource_utils import gcp_reference_key, is_gcp_terraform_resource_address

_SCOPE = re.compile(r"(?:^|/)(projects|folders|organizations)/([^/]+)$")


@dataclass(frozen=True, slots=True)
class HierarchyScope:
    key: str
    kind: str
    resource: NormalizedResource | None = None


def resolve_hierarchy_scope(value: str, index: GcpResourceIndex, kind: str | None = None) -> HierarchyScope | None:
    reference = gcp_reference_key(value.strip().rstrip("/"), suffixes=(".project_id", ".folder_id", ".id", ".name"))
    if match := _SCOPE.search(reference):
        reference = f"{match[1]}/{match[2]}"
    if kind and "/" not in reference and not is_gcp_terraform_resource_address(reference) and "${" not in reference:
        reference = f"{kind}/{reference}"
    resolution = index.resources_by_reference.resolve(
        reference, resource_types={GcpResourceType.PROJECT, GcpResourceType.FOLDER}
    )
    if resolution.state == "ambiguous":
        return None
    selected = resolution.selected_candidate
    if selected is not None:
        if reference != selected.address and hierarchy_fields_unknown(selected, "id", "name", "project_id"):
            return None
        selected_kind = "projects" if selected.resource_type == GcpResourceType.PROJECT else "folders"
        if kind is not None and kind != selected_kind:
            return None
        return HierarchyScope(selected.address, selected_kind, selected)
    match = _SCOPE.search(reference)
    if match:
        if kind is not None and kind != match[1]:
            return None
        return HierarchyScope(f"{match[1]}/{match[2]}", match[1])
    return None


def hierarchy_fields_unknown(resource: NormalizedResource, *fields: str) -> bool:
    return bool(set(fields).intersection(resource.get_metadata_field(GcpResourceMetadata.HIERARCHY_UNKNOWN_FIELDS)))


@dataclass(frozen=True, slots=True)
class ResourceHierarchy:
    scopes: tuple[HierarchyScope, ...]
    complete: bool
    uncertainty: str | None = None

    def contains(self, scope: HierarchyScope | None) -> bool | None:
        if scope is None:
            return None
        if any(item.key == scope.key for item in self.scopes):
            return True
        if self.complete or (
            scope.kind in {"projects", "organizations"} and any(item.kind == scope.kind for item in self.scopes)
        ):
            return False
        return None


def resource_hierarchy(
    owner: NormalizedResource,
    project: str | None,
    index: GcpResourceIndex,
) -> ResourceHierarchy:
    scopes: list[HierarchyScope] = []
    if project:
        scope = resolve_hierarchy_scope(project, index, "projects")
        if scope is None:
            return ResourceHierarchy((), False, "project scope is ambiguous or unknown")
        scopes.append(scope)
        owner = scope.resource or owner

    seen = {scope.key for scope in scopes}
    while True:
        if hierarchy_fields_unknown(owner, "folder_id", "org_id", "organization_id", "parent"):
            return ResourceHierarchy(tuple(scopes), False, f"{owner.address}: hierarchy parent is unknown")
        folder = owner.get_metadata_field(GcpResourceMetadata.FOLDER_ID)
        organization = owner.get_metadata_field(GcpResourceMetadata.ORGANIZATION_ID)
        parent = owner.get_metadata_field(GcpResourceMetadata.HIERARCHY_PARENT)
        # A folder's folder_id names itself, whereas a project's names its parent.
        if owner.resource_type == GcpResourceType.FOLDER:
            value, kind = parent, None
        elif folder:
            value, kind = folder, "folders"
        elif organization:
            value, kind = organization, "organizations"
        else:
            value, kind = parent, None
        if not value:
            return ResourceHierarchy(tuple(scopes), False, "hierarchy parent is not modeled")
        scope = resolve_hierarchy_scope(value, index, kind)
        if scope is None or scope.kind not in {"folders", "organizations"}:
            return ResourceHierarchy(tuple(scopes), False, f"{owner.address}: hierarchy parent is unresolved")
        if scope.key in seen:
            return ResourceHierarchy((), False, "modeled hierarchy contains a cycle")
        seen.add(scope.key)
        scopes.append(scope)
        if scope.kind == "organizations":
            complete = owner.resource_type in {GcpResourceType.PROJECT, GcpResourceType.FOLDER}
            return ResourceHierarchy(tuple(scopes), complete)
        if scope.resource is None:
            return ResourceHierarchy(tuple(scopes), False, f"{scope.key}: folder ancestry is not modeled")
        owner = scope.resource
