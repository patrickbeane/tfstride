"""Apply modeled IAM denies to individual GCS permissions.

Unknown conditions, principal sets, and hierarchy links retain uncertainty.
This evaluates plan-local constraints, not unobserved organization policies.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, Literal, TypedDict
from urllib.parse import unquote

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.gcs_grant_ancestry import ancestor_scope, bucket_hierarchy
from tfstride.providers.gcp.gcs_project_grants import project_identity, project_scope_matches
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpResourceIndex
from tfstride.providers.resource_reference_index import ResourceReferenceIndex


class GcsPermissionConstraint(TypedDict):
    policy_address: str
    permission: str
    state: Literal["denied", "unknown"]
    reason: str


def gcs_permission_constraints(
    principal: str,
    permission: str,
    bucket: NormalizedResource,
    policies: Sequence[NormalizedResource],
    projects: ResourceReferenceIndex,
    index: GcpResourceIndex,
) -> list[GcsPermissionConstraint]:
    evidence: list[GcsPermissionConstraint] = []
    for policy in policies:
        scope = _policy_scope(policy, bucket, projects, index)
        if scope is False:
            continue
        facts = gcp_facts(policy)
        decisions = [_rule_denies(rule, principal, permission) for rule in facts.iam_deny_policy_rules]
        # Completeness describes the policy body; parent uncertainty is already
        # represented by scope. It cannot expand a known rule's permission set.
        rule_uncertainties = [
            reason for reason in facts.iam_deny_policy_uncertainties if not reason.startswith("parent ")
        ]
        # Field uncertainty is evaluated on its own rule. Missing/malformed rules
        # can affect any permission and cannot be discarded with unrelated rules.
        structural_unknown = facts.iam_deny_policy_completeness_state != "complete" and (
            not rule_uncertainties
            or any(
                re.search(
                    r"\.deny_rule\[\d+\]\.(denied_principals|exception_principals|"
                    r"denied_permissions|exception_permissions|denial_condition) ",
                    reason,
                )
                is None
                for reason in rule_uncertainties
            )
        )
        if True in decisions and scope is True:
            evidence.append(
                {
                    "policy_address": policy.address,
                    "permission": permission,
                    "state": "denied",
                    "reason": "applicable unconditional IAM deny",
                }
            )
        elif True in decisions or None in decisions or structural_unknown:
            evidence.append(
                {
                    "policy_address": policy.address,
                    "permission": permission,
                    "state": "unknown",
                    "reason": (
                        "deny-policy scope is unresolved"
                        if scope is None
                        else "deny-policy condition, membership, or permission constraints are unresolved"
                    ),
                }
            )
    return evidence


def _policy_scope(
    policy: NormalizedResource, bucket: NormalizedResource, projects: ResourceReferenceIndex, index: GcpResourceIndex
) -> bool | None:
    facts = gcp_facts(policy)
    if facts.iam_deny_policy_parent_state != "configured":
        return None
    parent = unquote(facts.iam_deny_policy_parent or "").strip().lstrip("/")
    parent = parent.removeprefix("cloudresourcemanager.googleapis.com/")
    match = re.fullmatch(r"(projects|folders|organizations)/([^/]+)", parent)
    if not match:
        return None
    kind, value = match.groups()
    project = project_identity(gcp_facts(bucket).project, projects)
    if kind == "projects":
        return project_scope_matches(project, project_identity(value, projects))
    return bucket_hierarchy(bucket, index).contains(ancestor_scope(value, kind, index))


def _rule_denies(rule: Mapping[str, Any], principal: str, permission: str) -> bool | None:
    permission_match = _permission_match(rule, "denied_permissions", permission)
    principal_match = _principal_match(rule, "denied_principals", principal)
    exception_permission = _permission_match(rule, "exception_permissions", permission)
    exception_principal = _principal_match(rule, "exception_principals", principal)
    if permission_match is False or principal_match is False:
        return False
    if exception_permission is True or exception_principal is True:
        return False
    if None in (permission_match, principal_match, exception_permission, exception_principal):
        return None
    return True if rule.get("condition_state") == "not_configured" else None


def _values(rule: Mapping[str, Any], key: str) -> list[str] | None:
    if rule.get(f"{key}_state") not in {"configured", "not_configured"}:
        return None
    value = rule.get(key)
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        return None
    return value


def _permission_match(rule: Mapping[str, Any], key: str, permission: str) -> bool | None:
    values = _values(rule, key)
    if values is None:
        return None
    target = permission.replace("storage.", "storage.googleapis.com/", 1)
    unknown = False
    for value in values:
        match = re.fullmatch(r"([a-z0-9.-]+\.googleapis\.com)/([a-zA-Z0-9]+)\.([a-zA-Z0-9]+|\*)", value)
        if match is None:
            unknown = True
        elif value == target or (match[3] == "*" and target.startswith(f"{match[1]}/{match[2]}.")):
            return True
    return None if unknown else False


def _principal_match(rule: Mapping[str, Any], key: str, principal: str) -> bool | None:
    values = _values(rule, key)
    if values is None:
        return None
    email = principal.removeprefix("serviceAccount:") if principal.startswith("serviceAccount:") else None
    prefix = "principal://iam.googleapis.com/projects/-/serviceAccounts/"
    unknown = False
    for value in values:
        if value == "principalSet://goog/public:all" or (email and value == f"{prefix}{email}"):
            return True
        if value.startswith(prefix) and "@" in value.removeprefix(prefix) and email:
            continue
        # Numeric service-account IDs and principal sets need membership evidence.
        unknown = True
    return None if unknown else False
