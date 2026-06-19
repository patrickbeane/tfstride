from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from tfstride.analysis.resource_facts import analysis_facts
from tfstride.models import NormalizedResource
from tfstride.providers.gcp.constants import PUBLIC_GCP_IAM_MEMBERS
from tfstride.providers.gcp.resource_utils import binding_members

GCP_PUBSUB_DATA_ACCESS_ROLES = frozenset(
    {
        "roles/editor",
        "roles/owner",
        "roles/pubsub.admin",
        "roles/pubsub.editor",
        "roles/pubsub.publisher",
        "roles/pubsub.subscriber",
    }
)
GCP_BIGQUERY_DATA_ACCESS_ROLES = frozenset(
    {
        "roles/bigquery.admin",
        "roles/bigquery.dataEditor",
        "roles/bigquery.dataOwner",
        "roles/bigquery.dataViewer",
        "roles/editor",
        "roles/owner",
    }
)
GCP_SECRET_ACCESS_ROLES = frozenset(
    {
        "roles/editor",
        "roles/owner",
        "roles/secretmanager.admin",
        "roles/secretmanager.secretAccessor",
    }
)
GCP_KMS_ACCESS_ROLES = frozenset(
    {
        "roles/cloudkms.admin",
        "roles/cloudkms.cryptoKeyDecrypter",
        "roles/cloudkms.cryptoKeyEncrypterDecrypter",
        "roles/editor",
        "roles/owner",
    }
)

GCP_GCS_DATA_ACCESS_ROLES = frozenset(
    {
        "roles/editor",
        "roles/owner",
        "roles/storage.admin",
        "roles/storage.objectAdmin",
        "roles/storage.objectCreator",
        "roles/storage.objectUser",
        "roles/storage.objectViewer",
    }
)
GCP_CLOUD_SQL_DATA_ACCESS_ROLES = frozenset(
    {
        "roles/cloudsql.admin",
        "roles/cloudsql.client",
        "roles/editor",
        "roles/owner",
    }
)


@dataclass(frozen=True, slots=True)
class GcpIamMemberAssessment:
    member: str
    scope_description: str
    is_public: bool = False
    is_broad: bool = False


@dataclass(frozen=True, slots=True)
class GcpIamConditionAssessment:
    condition: Mapping[str, Any]
    category: str
    description: str
    is_constraining: bool = False


def assess_gcp_iam_condition(value: Mapping[str, Any] | None) -> GcpIamConditionAssessment | None:
    condition = _binding_condition(value)
    if not condition:
        return None
    expression = str(condition.get("expression") or "").strip()
    normalized_expression = expression.lower()
    if _expression_has_any(normalized_expression, ("request.time", "timestamp(", "duration(")):
        return GcpIamConditionAssessment(
            condition=condition,
            category="time_limited",
            description="IAM grant has a time-based condition",
            is_constraining=True,
        )
    if _expression_has_any(
        normalized_expression,
        ("resource.name", "resource.type", "resource.service", "resource.matchtag", "resource.matchtagid"),
    ):
        return GcpIamConditionAssessment(
            condition=condition,
            category="resource_scoped",
            description="IAM grant has a resource-scoping condition",
            is_constraining=True,
        )
    if _expression_has_any(
        normalized_expression,
        ("principal.", "request.auth", "google.subject", "attribute."),
    ):
        return GcpIamConditionAssessment(
            condition=condition,
            category="principal_scoped",
            description="IAM grant has a principal-scoping condition",
            is_constraining=True,
        )
    return GcpIamConditionAssessment(
        condition=condition,
        category="unclassified",
        description="IAM grant has an unclassified condition",
        is_constraining=False,
    )


def gcp_iam_condition_evidence_values(value: Mapping[str, Any] | None) -> list[str]:
    assessment = assess_gcp_iam_condition(value)
    if assessment is None:
        return []
    condition = assessment.condition
    values = [
        f"category={assessment.category}",
        f"constraining={str(assessment.is_constraining).lower()}",
    ]
    title = condition.get("title")
    if title:
        values.append(f"title={title}")
    description = condition.get("description")
    if description:
        values.append(f"description={description}")
    expression = condition.get("expression")
    if expression:
        values.append(f"expression={expression}")
    return values


def gcp_iam_condition_limited_score(
    score: int,
    value: Mapping[str, Any] | None,
    *,
    floor: int = 0,
) -> int:
    assessment = assess_gcp_iam_condition(value)
    if assessment is None or not assessment.is_constraining:
        return score
    return max(floor, score - 1)


def iam_binding_condition(
    resource: NormalizedResource,
    role: str,
    member: str,
) -> Mapping[str, Any] | None:
    matched_condition: Mapping[str, Any] | None = None
    matched = False
    for binding in analysis_facts(resource).iam.bindings:
        binding_role = str(binding.get("role") or "unknown role").strip()
        if binding_role != str(role).strip():
            continue
        if member not in binding_members(binding):
            continue
        matched = True
        condition = _binding_condition(binding)
        if condition is None:
            return None
        if matched_condition is not None and condition != matched_condition:
            return None
        matched_condition = condition
    if not matched:
        return None
    return matched_condition


def assess_gcp_sensitive_iam_member(
    member: str,
    resource_project: str | None,
) -> GcpIamMemberAssessment | None:
    normalized_member = str(member).strip()
    if not normalized_member:
        return None
    if normalized_member in PUBLIC_GCP_IAM_MEMBERS:
        return GcpIamMemberAssessment(
            member=normalized_member,
            scope_description=f"member is public GCP principal `{normalized_member}`",
            is_public=True,
            is_broad=True,
        )
    if normalized_member.startswith("domain:"):
        return GcpIamMemberAssessment(
            member=normalized_member,
            scope_description="member grants a whole Google Workspace domain",
            is_broad=True,
        )
    if normalized_member.startswith("serviceAccount:"):
        service_account_project = _service_account_project(normalized_member)
        if resource_project and service_account_project and service_account_project != resource_project:
            return GcpIamMemberAssessment(
                member=normalized_member,
                scope_description=(
                    f"service account belongs to project `{service_account_project}`, "
                    f"outside resource project `{resource_project}`"
                ),
            )
    return None


def assess_gcp_broad_iam_member(member: str) -> GcpIamMemberAssessment | None:
    normalized_member = str(member).strip()
    if not normalized_member:
        return None
    if normalized_member in PUBLIC_GCP_IAM_MEMBERS:
        return GcpIamMemberAssessment(
            member=normalized_member,
            scope_description=f"member is public GCP principal `{normalized_member}`",
            is_public=True,
            is_broad=True,
        )
    if normalized_member.startswith("domain:"):
        return GcpIamMemberAssessment(
            member=normalized_member,
            scope_description="member grants a whole Google Workspace domain",
            is_broad=True,
        )
    return None


def broad_resource_iam_bindings(
    resource: NormalizedResource,
    allowed_roles: frozenset[str],
) -> list[tuple[str, str, str, GcpIamMemberAssessment, Mapping[str, Any] | None]]:
    matches: list[tuple[str, str, str, GcpIamMemberAssessment, Mapping[str, Any] | None]] = []
    seen: set[tuple[str, str, str]] = set()
    for binding in analysis_facts(resource).iam.bindings:
        role = str(binding.get("role") or "unknown role").strip()
        if role not in allowed_roles:
            continue
        source = str(binding.get("source") or "").strip()
        for member in binding_members(binding):
            assessment = assess_gcp_broad_iam_member(member)
            if assessment is None:
                continue
            key = (source, role, assessment.member)
            if key in seen:
                continue
            seen.add(key)
            matches.append((source, role, assessment.member, assessment, _binding_condition(binding)))
    return matches


def iam_resource_binding_members(resource: NormalizedResource) -> list[tuple[str, str]]:
    bindings = analysis_facts(resource).iam.bindings
    if not bindings:
        facts = analysis_facts(resource)
        role = facts.iam.role
        member = facts.iam.member
        if role and member:
            return [(role, member)]
        return []

    members: list[tuple[str, str]] = []
    for binding in bindings:
        role = str(binding.get("role") or "unknown role")
        for member in binding_members(binding):
            members.append((role, member))
    return members


def org_folder_scope_description(resource: NormalizedResource) -> str:
    facts = analysis_facts(resource)
    if resource.resource_type.startswith("google_organization_iam_"):
        if facts.iam.organization_id:
            return f"organization scope `{facts.iam.organization_id}`"
        return "organization scope"
    if facts.iam.folder_id:
        return f"folder scope `{facts.iam.folder_id}`"
    return "folder scope"


def _service_account_project(member: str) -> str | None:
    email = member.split(":", 1)[1] if ":" in member else member
    suffix = ".iam.gserviceaccount.com"
    if not email.endswith(suffix) or "@" not in email:
        return None
    domain = email.split("@", 1)[1]
    return domain[: -len(suffix)] or None


def _binding_condition(value: Mapping[str, Any] | None) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    if "condition" in value:
        raw_condition = value.get("condition")
    elif any(key in value for key in ("title", "description", "expression")):
        raw_condition = value
    else:
        return None
    if not isinstance(raw_condition, Mapping):
        return None
    condition = {str(key): raw_value for key, raw_value in raw_condition.items() if raw_value not in (None, "", [])}
    return condition or None


def _expression_has_any(expression: str, tokens: tuple[str, ...]) -> bool:
    return any(token in expression for token in tokens)
