"""Project-local GCS grant candidates, before permission/deny evaluation."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any, cast

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import gcp_resource_references
from tfstride.providers.gcp.resource_types import GCP_PROJECT_IAM_RESOURCE_TYPES, GcpResourceType
from tfstride.providers.gcp.resource_utils import binding_members, gcp_reference_key, normalize_gcp_project
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
                if other.address != source.address and _conflicts(source, binding, other)
            ]
            if conflicts:
                uncertainties.append(
                    f"{prefix}: overlapping authoritative project IAM managers: {', '.join(sorted(conflicts))}"
                )
                continue
            candidates.append({**binding, "source": source.address, "grant_project": project})
    return candidates, uncertainties


def _binding_problem(source: NormalizedResource, binding: Mapping[str, Any]) -> str | None:
    if source.resource_type == GcpResourceType.PROJECT_IAM_POLICY:
        facts = gcp_facts(source)
        if facts.iam_policy_data_state != "configured":
            return "project IAM policy data is incomplete"
        # Preserve unknown policy structure instead of interpreting a partial document as complete.
        raw_bindings = facts.policy_document.get("bindings")
        if not isinstance(raw_bindings, list) or not all(_policy_binding_valid(raw) for raw in raw_bindings):
            return "project IAM policy contains unsupported binding structure"
    if any(binding.get(f"{key}_state") == "unknown" for key in ("role", "members", "condition")):
        return "project IAM role, membership, or condition is unresolved"
    if not binding.get("role"):
        return "project IAM role is unresolved"
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


def _conflicts(source: NormalizedResource, binding: Mapping[str, Any], other: NormalizedResource) -> bool:
    if GcpResourceType.PROJECT_IAM_POLICY in {source.resource_type, other.resource_type}:
        return True
    if GcpResourceType.PROJECT_IAM_BINDING not in {source.resource_type, other.resource_type}:
        return False
    other_bindings = gcp_facts(other).bindings
    if not other_bindings:
        return other.resource_type == GcpResourceType.PROJECT_IAM_BINDING
    for other_binding in other_bindings:
        if other_binding.get("role_state") == "unknown" or not other_binding.get("role"):
            return True
        if other_binding.get("role") != binding.get("role"):
            continue
        if other_binding.get("condition_state") == "unknown":
            return True
        if json.dumps(other_binding.get("condition"), sort_keys=True) == json.dumps(
            binding.get("condition"), sort_keys=True
        ):
            return True
    return False
