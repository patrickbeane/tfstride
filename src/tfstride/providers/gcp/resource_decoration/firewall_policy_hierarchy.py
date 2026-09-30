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
from tfstride.providers.gcp.resource_hierarchy import (
    HierarchyScope as _Scope,
)
from tfstride.providers.gcp.resource_hierarchy import (
    hierarchy_fields_unknown as _unknown,
)
from tfstride.providers.gcp.resource_hierarchy import (
    resolve_hierarchy_scope as _resolve_scope,
)
from tfstride.providers.gcp.resource_hierarchy import (
    resource_hierarchy,
)
from tfstride.providers.gcp.resource_index import GcpResourceIndex
from tfstride.providers.gcp.resource_utils import gcp_reference_key

_PROJECT = re.compile(r"(?:^|/)projects/([^/]+)(?:/|$)")


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
    hierarchy = resource_hierarchy(owner, project, index)
    return FirewallPolicyHierarchy(hierarchy.scopes, hierarchy.complete, network_key, hierarchy.uncertainty)
