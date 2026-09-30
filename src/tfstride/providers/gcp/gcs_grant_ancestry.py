"""Resolve GCS ownership ancestry from modeled project and folder parent links."""

from __future__ import annotations

import re
from typing import Literal

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_hierarchy import (
    HierarchyScope,
    ResourceHierarchy,
    resolve_hierarchy_scope,
    resource_hierarchy,
)
from tfstride.providers.gcp.resource_index import GcpResourceIndex
from tfstride.providers.gcp.resource_types import GCP_FOLDER_IAM_RESOURCE_TYPES, GcpResourceType
from tfstride.providers.gcp.resource_utils import gcp_reference_key, is_gcp_terraform_resource_address


def ancestor_scope(value: str | None, kind: str, index: GcpResourceIndex) -> HierarchyScope | None:
    if not value:
        return None
    reference = gcp_reference_key(value, suffixes=(".id", ".name", ".folder_id"))
    # Folder display names and provider aliases are not cloud identities.
    if not is_gcp_terraform_resource_address(reference) and not re.fullmatch(rf"(?:{kind}/)?[0-9]+", reference):
        return None
    return resolve_hierarchy_scope(value, index, kind)


def bucket_hierarchy(bucket: NormalizedResource, index: GcpResourceIndex) -> ResourceHierarchy:
    project = gcp_facts(bucket).project
    scope = resolve_hierarchy_scope(project, index, "projects") if project else None
    if scope is None or scope.resource is None or scope.resource.resource_type != GcpResourceType.PROJECT:
        return ResourceHierarchy((), False, "bucket project ownership is not established by a modeled project")
    hierarchy = resource_hierarchy(scope.resource, project, index)
    # Do not treat malformed native ancestry as a complete tree excluding other
    # grants/denies. Exact Terraform references can establish symbolic identity.
    for item in hierarchy.scopes:
        if item.kind == "projects":
            continue
        value = item.key if item.resource is None else item.resource.address
        if ancestor_scope(value, item.kind, index) is None:
            return ResourceHierarchy((), False, "modeled ancestry contains an unresolved identity")
    owner = scope.resource
    folder = owner.get_metadata_field(GcpResourceMetadata.FOLDER_ID)
    organization = owner.get_metadata_field(GcpResourceMetadata.ORGANIZATION_ID)
    parent = owner.get_metadata_field(GcpResourceMetadata.HIERARCHY_PARENT)
    if folder and organization:
        return ResourceHierarchy((), False, "project has conflicting folder and organization parents")
    if parent and (folder or organization):
        kind = "folders" if folder else "organizations"
        if ancestor_scope(parent, kind, index) != ancestor_scope(folder or organization, kind, index):
            return ResourceHierarchy((), False, "project has conflicting parent identities")
    return hierarchy


def ancestor_iam_scope(
    source: NormalizedResource,
    bucket: NormalizedResource,
    index: GcpResourceIndex,
) -> tuple[Literal["folder", "organization"], str | None, bool | None]:
    """Return the exact grant scope and its established applicability to a bucket."""
    facts = gcp_facts(source)
    kind = "folder" if source.resource_type in GCP_FOLDER_IAM_RESOURCE_TYPES else "organization"
    value = facts.folder_id if kind == "folder" else facts.organization_id
    scope = ancestor_scope(value, f"{kind}s", index) if facts.iam_scope_reference_state == "configured" else None
    return kind, scope.key if scope else None, bucket_hierarchy(bucket, index).contains(scope)
