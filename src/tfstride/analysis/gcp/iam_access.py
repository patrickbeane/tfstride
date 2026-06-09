from __future__ import annotations

from dataclasses import dataclass

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


@dataclass(frozen=True, slots=True)
class GcpIamMemberAssessment:
    member: str
    scope_description: str
    is_public: bool = False
    is_broad: bool = False


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
) -> list[tuple[str, str, str, GcpIamMemberAssessment]]:
    matches: list[tuple[str, str, str, GcpIamMemberAssessment]] = []
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
            matches.append((source, role, assessment.member, assessment))
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


def _service_account_project(member: str) -> str | None:
    email = member.split(":", 1)[1] if ":" in member else member
    suffix = ".iam.gserviceaccount.com"
    if not email.endswith(suffix) or "@" not in email:
        return None
    domain = email.split("@", 1)[1]
    return domain[: -len(suffix)] or None