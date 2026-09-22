"""Modeled hierarchy used to order hierarchical firewall policy attachments.

A policy's parent owns the policy; it is not its attachment scope. Only project
and folder parent links establish ancestry. Missing links are never evidence
that a policy attached to some other folder is unrelated.
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
_PROJECT = re.compile(r"(?:^|/)projects/([^/]+)(?:/|$)")


@dataclass(frozen=True, slots=True)
class _Scope:
    key: str
    kind: str
    resource: NormalizedResource | None = None


def _resolve_scope(value: str, index: GcpResourceIndex, kind: str | None = None) -> _Scope | None:
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
        if reference != selected.address and _unknown(selected, "id", "name", "project_id"):
            return None
        selected_kind = "projects" if selected.resource_type == GcpResourceType.PROJECT else "folders"
        if kind is not None and kind != selected_kind:
            return None
        return _Scope(selected.address, selected_kind, selected)
    match = _SCOPE.search(reference)
    if match:
        if kind is not None and kind != match[1]:
            return None
        return _Scope(f"{match[1]}/{match[2]}", match[1])
    return None


def _unknown(resource: NormalizedResource, *fields: str) -> bool:
    return bool(set(fields).intersection(resource.get_metadata_field(GcpResourceMetadata.HIERARCHY_UNKNOWN_FIELDS)))


def _project(resource: NormalizedResource) -> str | None:
    if _unknown(resource, "project", "project_id"):
        return None
    project = resource.get_metadata_field(GcpResourceMetadata.PROJECT)
    if project:
        return project
    if _unknown(resource, "id", "name", "self_link"):
        return None
    for value in (resource.identifier, resource.get_metadata_field(GcpResourceMetadata.SELF_LINK), resource.vpc_id):
        match = _PROJECT.search(value or "")
        if match:
            return match[1]
    return None


@dataclass(frozen=True, slots=True)
class FirewallPolicyHierarchy:
    # Descendant first; policy evaluation reverses these positions.
    scopes: tuple[_Scope, ...]
    complete: bool
    network_key: str | None
    uncertainty: str | None = None

    def attachment_position(self, target: str | None, index: GcpResourceIndex) -> tuple[int | None, str | None]:
        """Return a position, proven unrelated, or an explicit unresolved scope."""
        if not target:
            return None, "attachment target is missing or unknown"
        network = index.network_references.resolve(target)
        scope = _resolve_scope(target, index)
        if scope is None and (network.candidates or "/networks/" in target or "google_compute_network." in target):
            if network.state == "ambiguous" or self.network_key is None:
                return None, "attachment network scope is ambiguous or unknown"
            key = network.selected_candidate.address if network.selected_candidate else gcp_reference_key(target)
            return (0, None) if key == self.network_key else (None, None)
        if scope is None:
            return None, "attachment scope cannot be resolved"
        for position, ancestor in enumerate(self.scopes, start=1):
            if ancestor.key == scope.key:
                return position, None
        # Projects and organizations cannot be ancestors of peers of their kind.
        if scope.kind in {"projects", "organizations"} and any(item.kind == scope.kind for item in self.scopes):
            return None, None
        if self.complete:
            return None, None
        return None, self.uncertainty or "attachment ancestry is not established by the plan"


def firewall_policy_hierarchy(instance: NormalizedResource, index: GcpResourceIndex) -> FirewallPolicyHierarchy:
    network = index.network_references.resolve(instance.vpc_id, source=instance)
    if network.state == "ambiguous" or _unknown(instance, "network_interface"):
        return FirewallPolicyHierarchy((), False, None, "instance network scope is ambiguous or unknown")
    network_resource = network.selected_candidate
    network_key = network_resource.address if network_resource else gcp_reference_key(instance.vpc_id or "") or None
    # Hierarchical firewall policy follows the VPC's host project, including Shared VPC.
    owner = network_resource if network_resource and _project(network_resource) else instance
    if network_resource and _unknown(network_resource, "project"):
        return FirewallPolicyHierarchy((), False, network_key, "network project is unknown")
    project = _project(owner)
    if owner is instance and instance.vpc_id and (match := _PROJECT.search(instance.vpc_id)):
        project = match[1]
    scopes: list[_Scope] = []
    if project:
        scope = _resolve_scope(project, index, "projects")
        if scope is None:
            return FirewallPolicyHierarchy((), False, network_key, "project scope is ambiguous or unknown")
        scopes.append(scope)
        owner = scope.resource or owner

    seen = {scope.key for scope in scopes}
    while True:
        if _unknown(owner, "folder_id", "org_id", "organization_id", "parent"):
            return FirewallPolicyHierarchy(
                tuple(scopes), False, network_key, f"{owner.address}: hierarchy parent is unknown"
            )
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
            return FirewallPolicyHierarchy(tuple(scopes), False, network_key, "hierarchy parent is not modeled")
        scope = _resolve_scope(value, index, kind)
        if scope is None or scope.kind not in {"folders", "organizations"}:
            return FirewallPolicyHierarchy(
                tuple(scopes), False, network_key, f"{owner.address}: hierarchy parent is unresolved"
            )
        if scope.key in seen:
            return FirewallPolicyHierarchy((), False, network_key, "modeled hierarchy contains a cycle")
        seen.add(scope.key)
        scopes.append(scope)
        if scope.kind == "organizations":
            complete = owner.resource_type in {GcpResourceType.PROJECT, GcpResourceType.FOLDER}
            return FirewallPolicyHierarchy(tuple(scopes), complete, network_key)
        if scope.resource is None:
            return FirewallPolicyHierarchy(
                tuple(scopes), False, network_key, f"{scope.key}: folder ancestry is not modeled"
            )
        owner = scope.resource
