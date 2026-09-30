"""Scope resolution and IAM-manager constraints for GCS grant candidates."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any, cast

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.custom_role_index import GcpCustomRoleIndex
from tfstride.providers.gcp.gcs_grant_ancestry import ancestor_scope, bucket_hierarchy
from tfstride.providers.gcp.iam_reference_utils import gcs_bucket_scope_name
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_decoration.iam import resolve_resource_iam_target
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_hierarchy import HierarchyScope
from tfstride.providers.gcp.resource_index import GcpResourceIndex, gcp_resource_references
from tfstride.providers.gcp.resource_types import (
    GCP_FOLDER_IAM_RESOURCE_TYPES,
    GCP_ORG_FOLDER_IAM_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.gcp.resource_utils import (
    binding_members,
    gcp_reference_key,
    is_gcp_terraform_resource_address,
    normalize_gcp_project,
)
from tfstride.providers.resource_reference_index import ResourceReferenceIndex, build_resource_reference_index


def project_reference_index(resources: Sequence[NormalizedResource]) -> ResourceReferenceIndex:
    return build_resource_reference_index(
        (resource for resource in resources if resource.resource_type == GcpResourceType.PROJECT),
        references_for_resource=gcp_resource_references,
        reference_key=lambda value: gcp_reference_key(value, (".project_id", ".id", ".name")),
    )


def project_identity(value: object, index: ResourceReferenceIndex) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    resolution = index.resolve(value)
    if resolution.state == "ambiguous":
        return None
    target = resolution.selected_candidate
    if target is not None:
        if set(target.get_metadata_field(GcpResourceMetadata.HIERARCHY_UNKNOWN_FIELDS)) & {
            "project_id",
            "id",
            "name",
        }:
            return None
        value = gcp_facts(target).project
    project = normalize_gcp_project(value)
    return project if project and re.fullmatch(r"[a-z][a-z0-9-]*|[0-9]+", project) else None


def project_scope_matches(left: str | None, right: str | None) -> bool | None:
    if left is None or right is None:
        return None
    if left == right:
        return True
    # Project numbers and IDs cannot be compared without an established alias.
    if left.isdigit() != right.isdigit():
        return None
    return False


def project_grant_candidates(
    principal: str,
    bucket: NormalizedResource,
    sources: Sequence[NormalizedResource],
    index: ResourceReferenceIndex,
    custom_roles: GcpCustomRoleIndex,
) -> tuple[list[dict[str, Any]], list[str]]:
    project = project_identity(gcp_facts(bucket).project, index)
    managers: list[tuple[NormalizedResource, bool | None]] = []
    for source in sorted(sources, key=lambda resource: resource.address):
        if source.resource_type not in GCP_PROJECT_IAM_RESOURCE_TYPES:
            continue
        facts = gcp_facts(source)
        source_project = (
            project_identity(facts.project, index) if facts.iam_scope_reference_state == "configured" else None
        )
        match = project_scope_matches(project, source_project)
        if match is not False:
            managers.append((source, match))
    candidates: list[dict[str, Any]] = []
    uncertainties: list[str] = []
    for source, match in managers:
        facts = gcp_facts(source)
        if source.resource_type == GcpResourceType.PROJECT_IAM_POLICY and facts.iam_policy_data_state != "configured":
            uncertainties.append(f"{source.address} for {bucket.address}: project IAM policy data is incomplete")
        for binding in facts.bindings:
            if principal not in binding_members(binding) and binding.get("members_state") != "unknown":
                continue
            prefix = f"{source.address} for {bucket.address}"
            if match is not True:
                uncertainties.append(f"{prefix}: project membership is unresolved")
                continue
            problem = _binding_problem(source, binding)
            if problem:
                uncertainties.append(f"{prefix}: {problem}")
                continue
            conflicts = [
                other.address
                for other, _ in managers
                if other.address != source.address and _conflicts(source, binding, other, custom_roles)
            ]
            if conflicts:
                uncertainties.append(
                    f"{prefix}: overlapping authoritative project IAM managers: {', '.join(sorted(conflicts))}"
                )
                continue
            candidates.append({**binding, "source": source.address, "grant_project": project})
    return candidates, uncertainties


def ancestor_grant_candidates(
    principal: str,
    bucket: NormalizedResource,
    sources: Sequence[NormalizedResource],
    index: GcpResourceIndex,
    custom_roles: GcpCustomRoleIndex,
) -> tuple[list[dict[str, Any]], list[str]]:
    hierarchy = bucket_hierarchy(bucket, index)
    managers: list[tuple[NormalizedResource, str, HierarchyScope | None, bool | None]] = []
    for source in sorted(sources, key=lambda item: item.address):
        if source.resource_type not in GCP_ORG_FOLDER_IAM_RESOURCE_TYPES:
            continue
        facts = gcp_facts(source)
        kind = "folders" if source.resource_type in GCP_FOLDER_IAM_RESOURCE_TYPES else "organizations"
        value = facts.folder_id if kind == "folders" else facts.organization_id
        scope = ancestor_scope(value, kind, index) if facts.iam_scope_reference_state == "configured" else None
        match = hierarchy.contains(scope)
        if match is not False:
            managers.append((source, kind, scope, match))
    grants: list[dict[str, Any]] = []
    problems: list[str] = []
    for source, kind, scope, match in managers:
        facts = gcp_facts(source)
        if source.resource_type.endswith("_iam_policy") and facts.iam_policy_data_state != "configured":
            problems.append(f"{source.address} for {bucket.address}: ancestor IAM policy data is incomplete")
        for binding in facts.bindings:
            if principal not in binding_members(binding) and binding.get("members_state") != "unknown":
                continue
            problem = _binding_problem(source, binding)
            if match is not True or scope is None or problem:
                problems.append(
                    f"{source.address} for {bucket.address}: "
                    f"{problem or hierarchy.uncertainty or 'grant ancestry is unresolved'}"
                )
                continue
            # Authoritative policies only replace grants at their own scope.
            # A parent and child grant remain independent alternatives.
            if any(
                other.address != source.address
                and other_kind == kind
                and (other_scope is None or other_scope.key == scope.key)
                and _conflicts(source, binding, other, custom_roles)
                for other, other_kind, other_scope, _ in managers
            ):
                problems.append(
                    f"{source.address} for {bucket.address}: overlapping authoritative ancestor IAM managers"
                )
                continue
            grants.append(
                {
                    **binding,
                    "source": source.address,
                    "grant_scope_kind": kind,
                    "grant_scope": scope.key,
                    "grant_ancestry": [item.key for item in hierarchy.scopes[: hierarchy.scopes.index(scope) + 1]],
                }
            )
    return grants, problems


def bucket_grant_candidates(
    principal: str,
    bucket: NormalizedResource,
    sources: Sequence[NormalizedResource],
    index: GcpResourceIndex,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Resolve current bucket IAM sources; decorated binding copies are not authority."""
    managers: list[tuple[NormalizedResource, bool | None]] = []
    for source in sources:
        if source.resource_type not in GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES:
            continue
        source_facts = gcp_facts(source)
        if source_facts.iam_scope_reference_state != "configured":
            managers.append((source, None))
            continue
        reference = source_facts.target_reference
        if (
            isinstance(reference, str)
            and re.fullmatch(r"[a-z0-9][a-z0-9._-]*[a-z0-9]", reference)
            and not is_gcp_terraform_resource_address(gcp_reference_key(reference))
            and reference != gcp_facts(bucket).bucket_name
        ):
            continue
        resolution = resolve_resource_iam_target(source, index, resource_types={GcpResourceType.STORAGE_BUCKET})
        native_name = gcs_bucket_scope_name(gcp_facts(source).target_reference)
        if native_name is not None:
            if native_name != gcp_facts(bucket).bucket_name:
                continue
            resolution = index.resources_by_reference.resolve(
                native_name, resource_types={GcpResourceType.STORAGE_BUCKET}
            )
        target = resolution.selected_candidate
        if target is not None and target.address != bucket.address:
            continue
        managers.append((source, True if target is not None else None))
    grants: list[dict[str, Any]] = []
    problems: list[str] = []
    for source, matches in managers:
        for binding in gcp_facts(source).bindings:
            if principal not in binding_members(binding):
                continue
            problem = _binding_problem(source, binding)
            if matches is not True or problem:
                problems.append(f"{source.address} for {bucket.address}: {problem or 'bucket scope is unresolved'}")
                continue
            if any(other.address != source.address and _conflicts(source, binding, other) for other, _ in managers):
                problems.append(f"{source.address} for {bucket.address}: overlapping authoritative bucket IAM managers")
                continue
            grants.append({**binding, "source": source.address})
    return grants, problems


def _binding_problem(source: NormalizedResource, binding: Mapping[str, Any]) -> str | None:
    scope = (
        "ancestor"
        if source.resource_type in GCP_ORG_FOLDER_IAM_RESOURCE_TYPES
        else "project"
        if source.resource_type in GCP_PROJECT_IAM_RESOURCE_TYPES
        else "bucket"
    )
    if source.resource_type.endswith("_iam_policy"):
        facts = gcp_facts(source)
        if facts.iam_policy_data_state != "configured":
            return f"{scope} IAM policy data is incomplete"
        # Preserve unknown policy structure instead of interpreting a partial document as complete.
        raw_bindings = facts.policy_document.get("bindings")
        if not isinstance(raw_bindings, list) or not all(_policy_binding_valid(raw) for raw in raw_bindings):
            return f"{scope} IAM policy contains unsupported binding structure"
    if any(binding.get(f"{key}_state") == "unknown" for key in ("role", "members", "condition")):
        return f"{scope} IAM role, membership, or condition is unresolved"
    if not binding.get("role"):
        return f"{scope} IAM role is unresolved"
    return None


def _policy_binding_valid(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    raw = cast(dict[str, Any], value)
    return (
        not set(raw) - {"role", "members", "condition"}
        and isinstance(raw.get("role"), str)
        and isinstance(raw.get("members"), list)
        and all(isinstance(member, str) for member in raw["members"])
        and ("condition" not in raw or isinstance(raw["condition"], dict))
    )


def _conflicts(
    source: NormalizedResource,
    binding: Mapping[str, Any],
    other: NormalizedResource,
    custom_roles: GcpCustomRoleIndex | None = None,
) -> bool:
    if any(item.resource_type.endswith("_iam_policy") for item in (source, other)):
        return True
    if not any(item.resource_type.endswith("_iam_binding") for item in (source, other)):
        return False
    other_bindings = gcp_facts(other).bindings
    if not other_bindings:
        return other.resource_type.endswith("_iam_binding")
    for other_binding in other_bindings:
        if other_binding.get("role_state") == "unknown" or not other_binding.get("role"):
            return True
        if other_binding.get("role") != binding.get("role"):
            left = str(binding.get("role") or "")
            right = str(other_binding.get("role") or "")
            if custom_roles is None or left.startswith("roles/") or right.startswith("roles/"):
                continue
            native_pattern = r"(projects|organizations)/([a-z0-9-]+)/roles/([A-Za-z0-9_.]+)"
            left_native = re.fullmatch(native_pattern, left)
            right_native = re.fullmatch(native_pattern, right)
            if (
                left_native
                and right_native
                and (
                    left_native[1] != right_native[1]
                    or left_native[3] != right_native[3]
                    or project_scope_matches(left_native[2], right_native[2]) is False
                )
            ):
                # Distinct strong names need no modeled role definition merely
                # to prove that their IAM binding managers cannot overlap.
                continue
            left_role = custom_roles.resolve(left).selected_candidate
            right_role = custom_roles.resolve(right).selected_candidate
            if left_role is not None and right_role is not None and left_role.address != right_role.address:
                continue
            # Scoped native and exact Terraform references can identify one role.
            # Ambiguous custom-role identity cannot prove managers disjoint.
        if other_binding.get("condition_state") == "unknown":
            return True
        if json.dumps(other_binding.get("condition"), sort_keys=True) == json.dumps(
            binding.get("condition"), sort_keys=True
        ):
            return True
    return False
