from __future__ import annotations

from dataclasses import dataclass

from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.gcp.custom_roles import (
    GcpCustomRoleIndex,
    build_gcp_custom_role_index,
    custom_role_allows_data_store_access,
    custom_role_permissions,
)
from tfstride.analysis.gcp.iam_access import (
    GCP_BIGQUERY_DATA_ACCESS_ROLES,
    GCP_CLOUD_SQL_DATA_ACCESS_ROLES,
    GCP_GCS_DATA_ACCESS_ROLES,
    GCP_KMS_ACCESS_ROLES,
    GCP_PUBSUB_DATA_ACCESS_ROLES,
    GCP_SECRET_ACCESS_ROLES,
    GcpIamMemberAssessment,
    assess_gcp_broad_iam_member,
    assess_gcp_sensitive_iam_member,
    iam_resource_binding_members,
)
from tfstride.analysis.gcp.iam_inheritance import (
    GCP_IAM_SCOPE_FOLDER,
    GCP_IAM_SCOPE_ORGANIZATION,
    GCP_IAM_SCOPE_PROJECT,
    GcpIamScopeKey,
)
from tfstride.analysis.gcp.iam_role_risk import (
    privileged_org_folder_role_risk,
    privileged_project_role_risk,
)
from tfstride.analysis.resource_facts import analysis_facts
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource

_INHERITED_GCP_IAM_SCOPE_TYPES = frozenset(
    {
        GCP_IAM_SCOPE_ORGANIZATION,
        GCP_IAM_SCOPE_FOLDER,
        GCP_IAM_SCOPE_PROJECT,
    }
)
_INHERITED_IAM_BLAST_RADIUS_MIN_DESCENDANTS = 2
_HIGH_BREADTH_INHERITED_DATA_ROLES = frozenset(
    {
        "roles/owner",
        "roles/editor",
        "roles/secretmanager.admin",
        "roles/cloudkms.admin",
        "roles/storage.admin",
        "roles/storage.objectAdmin",
        "roles/cloudsql.admin",
        "roles/bigquery.admin",
        "roles/bigquery.dataOwner",
        "roles/pubsub.admin",
        "roles/pubsub.editor",
    }
)
_INHERITED_SENSITIVE_RESOURCE_ACCESS: dict[str, tuple[frozenset[str], str, int]] = {
    "google_secret_manager_secret": (GCP_SECRET_ACCESS_ROLES, "Secret Manager secret access", 2),
    "google_kms_crypto_key": (GCP_KMS_ACCESS_ROLES, "Cloud KMS cryptographic key access", 2),
    "google_storage_bucket": (GCP_GCS_DATA_ACCESS_ROLES, "GCS object data access", 2),
    "google_sql_database_instance": (GCP_CLOUD_SQL_DATA_ACCESS_ROLES, "Cloud SQL client/admin access", 2),
    "google_bigquery_dataset": (
        GCP_BIGQUERY_DATA_ACCESS_ROLES,
        "BigQuery dataset data access",
        2,
    ),
    "google_bigquery_table": (
        GCP_BIGQUERY_DATA_ACCESS_ROLES,
        "BigQuery table data access",
        2,
    ),
    "google_pubsub_topic": (GCP_PUBSUB_DATA_ACCESS_ROLES, "Pub/Sub topic data access", 1),
    "google_pubsub_subscription": (
        GCP_PUBSUB_DATA_ACCESS_ROLES,
        "Pub/Sub subscription data access",
        1,
    ),
}


@dataclass(frozen=True, slots=True)
class _InheritedSensitiveResourceAccess:
    resource_address: str
    resource_type: str
    risk: str
    data_sensitivity: int


class GcpInheritedIamDetectors:
    def detect_inherited_iam_sensitive_resource_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        seen: set[tuple[str, str, str, str]] = set()
        inheritance_index = context.analysis_indexes.gcp_iam_inheritance
        custom_roles = build_gcp_custom_role_index(context.inventory.resources)

        for scope, iam_resources in sorted(
            inheritance_index.iam_resources_by_scope.items(),
            key=lambda item: item[0].label,
        ):
            if scope.scope_type not in _INHERITED_GCP_IAM_SCOPE_TYPES:
                continue
            descendant_resources = tuple(
                sorted(
                    inheritance_index.descendant_resources_for_scope(scope),
                    key=lambda resource: resource.address,
                )
            )
            if not descendant_resources:
                continue

            for binding in sorted(iam_resources, key=lambda resource: resource.address):
                for role, member in iam_resource_binding_members(binding):
                    access_grants = _inherited_sensitive_resource_accesses(
                        descendant_resources,
                        role,
                        custom_roles,
                    )
                    if not access_grants:
                        continue
                    finding_key = (binding.address, scope.label, role, member)
                    if finding_key in seen:
                        continue
                    seen.add(finding_key)

                    member_assessment = _assess_inherited_gcp_iam_member(member, descendant_resources)
                    severity_reasoning = build_severity_reasoning(
                        internet_exposure=bool(member_assessment and member_assessment.is_public),
                        privilege_breadth=_inherited_sensitive_resource_privilege_breadth(
                            role,
                            member_assessment,
                        ),
                        data_sensitivity=max(grant.data_sensitivity for grant in access_grants),
                        lateral_movement=1,
                        blast_radius=_inherited_sensitive_resource_blast_radius(
                            scope,
                            access_grants,
                            member_assessment,
                        ),
                    )
                    scope_description = _inherited_iam_scope_description(scope)
                    findings.append(
                        self._finding_factory.build(
                            rule_id=rule_id,
                            severity=severity_reasoning.severity,
                            affected_resources=dedupe_addresses(
                                [binding.address, *[grant.resource_address for grant in access_grants]]
                            ),
                            trust_boundary_id=None,
                            rationale=(
                                f"{binding.display_name} grants `{role}` to `{member}` at "
                                f"{scope_description}, and that inherited grant reaches "
                                f"{len(access_grants)} sensitive GCP descendant resource(s). "
                                "Project, folder, and organization IAM applies below the grant scope, "
                                "so a single ancestor binding can expose data resources beyond their "
                                "local IAM boundary."
                            ),
                            evidence=collect_evidence(
                                evidence_item(
                                    "iam_binding",
                                    [
                                        f"source={binding.address}",
                                        f"scope={scope.label}",
                                        f"member={member}",
                                        f"role={role}",
                                    ],
                                ),
                                evidence_item(
                                    "sensitive_descendants",
                                    [
                                        _inherited_sensitive_resource_access_evidence(grant)
                                        for grant in access_grants
                                    ],
                                ),
                                evidence_item(
                                    "trust_scope",
                                    [member_assessment.scope_description if member_assessment else ""],
                                ),
                                evidence_item(
                                    "custom_role_permissions",
                                    custom_role_permissions(role, custom_roles),
                                ),
                            ),
                            severity_reasoning=severity_reasoning,
                        )
                    )
        return findings

    def detect_inherited_iam_blast_radius(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        seen: set[tuple[str, str, str, str]] = set()
        inheritance_index = context.analysis_indexes.gcp_iam_inheritance
        custom_roles = build_gcp_custom_role_index(context.inventory.resources)

        for scope, iam_resources in sorted(
            inheritance_index.iam_resources_by_scope.items(),
            key=lambda item: item[0].label,
        ):
            if scope.scope_type not in _INHERITED_GCP_IAM_SCOPE_TYPES:
                continue
            descendants = tuple(
                sorted(
                    inheritance_index.descendant_resources_for_scope(scope),
                    key=lambda resource: resource.address,
                )
            )
            if not _has_inherited_iam_blast_radius(scope, descendants):
                continue

            for binding in sorted(iam_resources, key=lambda resource: resource.address):
                for role, member in iam_resource_binding_members(binding):
                    role_risk = _inherited_iam_role_risk(scope, role, custom_roles)
                    member_assessment = _assess_inherited_gcp_iam_member(member, descendants)
                    if role_risk is None and member_assessment is None:
                        continue
                    finding_key = (binding.address, scope.label, role, member)
                    if finding_key in seen:
                        continue
                    seen.add(finding_key)

                    severity_reasoning = build_severity_reasoning(
                        internet_exposure=bool(member_assessment and member_assessment.is_public),
                        privilege_breadth=_inherited_iam_blast_radius_privilege_breadth(
                            role_risk,
                            member_assessment,
                        ),
                        data_sensitivity=_inherited_iam_descendant_data_sensitivity(descendants, role_risk),
                        lateral_movement=2 if role_risk is not None else 1,
                        blast_radius=_inherited_iam_scope_blast_radius(scope, descendants, member_assessment),
                    )
                    scope_description = _inherited_iam_scope_description(scope)
                    findings.append(
                        self._finding_factory.build(
                            rule_id=rule_id,
                            severity=severity_reasoning.severity,
                            affected_resources=dedupe_addresses(
                                [binding.address, *[resource.address for resource in descendants]]
                            ),
                            trust_boundary_id=None,
                            rationale=(
                                f"{binding.display_name} grants `{role}` to `{member}` at "
                                f"{scope_description}, and that inherited grant applies to "
                                f"{len(descendants)} concrete descendant resource(s). "
                                "A high-level IAM grant with broad, external, or high-impact access increases "
                                "control-plane blast radius because compromise or misuse can affect "
                                "resources below the inherited scope."
                            ),
                            evidence=collect_evidence(
                                evidence_item(
                                    "iam_binding",
                                    [
                                        f"source={binding.address}",
                                        f"scope={scope.label}",
                                        f"member={member}",
                                        f"role={role}",
                                    ],
                                ),
                                evidence_item("role_risk", [role_risk or ""]),
                                evidence_item(
                                    "trust_scope",
                                    [member_assessment.scope_description if member_assessment else ""],
                                ),
                                evidence_item(
                                    "descendant_scope",
                                    _inherited_iam_descendant_scope_evidence(scope, descendants),
                                ),
                                evidence_item(
                                    "descendant_resource_types",
                                    _inherited_iam_descendant_type_evidence(descendants),
                                ),
                                evidence_item(
                                    "descendant_resources",
                                    _inherited_iam_descendant_resource_evidence(descendants),
                                ),
                                evidence_item(
                                    "custom_role_permissions",
                                    custom_role_permissions(role, custom_roles),
                                ),
                            ),
                            severity_reasoning=severity_reasoning,
                        )
                    )
        return findings


def _has_inherited_iam_blast_radius(
    scope: GcpIamScopeKey,
    descendants: tuple[NormalizedResource, ...],
) -> bool:
    return len(descendants) >= _INHERITED_IAM_BLAST_RADIUS_MIN_DESCENDANTS


def _inherited_iam_role_risk(
    scope: GcpIamScopeKey,
    role: str | None,
    custom_roles: GcpCustomRoleIndex,
) -> str | None:
    if scope.scope_type in {GCP_IAM_SCOPE_ORGANIZATION, GCP_IAM_SCOPE_FOLDER}:
        return privileged_org_folder_role_risk(role, custom_roles)
    return privileged_project_role_risk(role, custom_roles)


def _inherited_iam_blast_radius_privilege_breadth(
    role_risk: str | None,
    member_assessment: GcpIamMemberAssessment | None,
) -> int:
    if role_risk is not None:
        return 2
    if member_assessment is not None and member_assessment.is_broad:
        return 2
    return 1


def _inherited_iam_descendant_data_sensitivity(
    descendants: tuple[NormalizedResource, ...],
    role_risk: str | None,
) -> int:
    if role_risk is None:
        return 0
    return 2 if any(resource.data_sensitivity == "sensitive" for resource in descendants) else 0


def _inherited_iam_scope_blast_radius(
    scope: GcpIamScopeKey,
    descendants: tuple[NormalizedResource, ...],
    member_assessment: GcpIamMemberAssessment | None,
) -> int:
    if scope.scope_type in {GCP_IAM_SCOPE_ORGANIZATION, GCP_IAM_SCOPE_FOLDER}:
        return 2
    if member_assessment is not None and member_assessment.is_broad:
        return 2
    if len(descendants) >= 5 or len({resource.resource_type for resource in descendants}) >= 3:
        return 2
    return 1


def _inherited_iam_descendant_scope_evidence(
    scope: GcpIamScopeKey,
    descendants: tuple[NormalizedResource, ...],
) -> list[str]:
    projects = _descendant_scope_values(descendants, "project")
    folders = _descendant_scope_values(descendants, "folder")
    organizations = _descendant_scope_values(descendants, "organization")
    values = [
        f"scope={scope.label}",
        f"descendant_count={len(descendants)}",
        f"resource_type_count={len({resource.resource_type for resource in descendants})}",
    ]
    if projects:
        values.append(f"projects={', '.join(projects[:5])}")
    if folders:
        values.append(f"folders={', '.join(folders[:5])}")
    if organizations:
        values.append(f"organizations={', '.join(organizations[:5])}")
    return values


def _inherited_iam_descendant_type_evidence(descendants: tuple[NormalizedResource, ...]) -> list[str]:
    counts: dict[str, int] = {}
    for resource in descendants:
        counts[resource.resource_type] = counts.get(resource.resource_type, 0) + 1
    return [f"{resource_type}: {counts[resource_type]}" for resource_type in sorted(counts)]


def _inherited_iam_descendant_resource_evidence(
    descendants: tuple[NormalizedResource, ...],
    *,
    limit: int = 10,
) -> list[str]:
    addresses = [resource.address for resource in descendants]
    values = addresses[:limit]
    remaining = len(addresses) - len(values)
    if remaining > 0:
        values.append(f"and {remaining} more descendant resources")
    return values


def _descendant_scope_values(
    descendants: tuple[NormalizedResource, ...],
    scope_type: str,
) -> list[str]:
    values: set[str] = set()
    for resource in descendants:
        facts = analysis_facts(resource)
        if scope_type == "project" and facts.iam.project:
            values.add(facts.iam.project)
        elif scope_type == "folder" and facts.iam.folder_id:
            values.add(facts.iam.folder_id)
        elif scope_type == "organization" and facts.iam.organization_id:
            values.add(facts.iam.organization_id)
    return sorted(values)


def _inherited_sensitive_resource_accesses(
    descendants: tuple[NormalizedResource, ...],
    role: str,
    custom_roles: GcpCustomRoleIndex,
) -> list[_InheritedSensitiveResourceAccess]:
    grants: list[_InheritedSensitiveResourceAccess] = []
    for resource in descendants:
        access_risk = _inherited_sensitive_resource_access_risk(resource, role, custom_roles)
        if access_risk is None:
            continue
        risk, data_sensitivity = access_risk
        grants.append(
            _InheritedSensitiveResourceAccess(
                resource_address=resource.address,
                resource_type=resource.resource_type,
                risk=risk,
                data_sensitivity=data_sensitivity,
            )
        )
    return sorted(grants, key=lambda grant: grant.resource_address)


def _inherited_sensitive_resource_access_risk(
    resource: NormalizedResource,
    role: str | None,
    custom_roles: GcpCustomRoleIndex,
) -> tuple[str, int] | None:
    normalized_role = str(role or "").strip()
    if not normalized_role:
        return None
    access_profile = _INHERITED_SENSITIVE_RESOURCE_ACCESS.get(resource.resource_type)
    if access_profile is None:
        return None
    allowed_roles, risk_label, data_sensitivity = access_profile
    if normalized_role in allowed_roles:
        return (f"{risk_label} through {normalized_role}", data_sensitivity)
    if custom_role_allows_data_store_access(resource, normalized_role, custom_roles):
        return (f"{risk_label} through custom role {normalized_role}", data_sensitivity)
    return None


def _assess_inherited_gcp_iam_member(
    member: str,
    descendants: tuple[NormalizedResource, ...],
) -> GcpIamMemberAssessment | None:
    broad_assessment = assess_gcp_broad_iam_member(member)
    if broad_assessment is not None:
        return broad_assessment
    projects = sorted(
        {
            project
            for project in (analysis_facts(resource).iam.project for resource in descendants)
            if project
        }
    )
    for project in projects:
        assessment = assess_gcp_sensitive_iam_member(member, project)
        if assessment is not None:
            return assessment
    return None


def _inherited_sensitive_resource_privilege_breadth(
    role: str | None,
    member_assessment: GcpIamMemberAssessment | None,
) -> int:
    if member_assessment is not None and member_assessment.is_broad:
        return 2
    normalized_role = str(role or "").strip()
    if normalized_role in _HIGH_BREADTH_INHERITED_DATA_ROLES:
        return 2
    role_name = normalized_role.rsplit("/", 1)[-1].lower()
    if normalized_role.startswith("roles/") and "admin" in role_name:
        return 2
    return 1


def _inherited_sensitive_resource_blast_radius(
    scope: GcpIamScopeKey,
    grants: list[_InheritedSensitiveResourceAccess],
    member_assessment: GcpIamMemberAssessment | None,
) -> int:
    if scope.scope_type in {GCP_IAM_SCOPE_ORGANIZATION, GCP_IAM_SCOPE_FOLDER}:
        return 2
    if member_assessment is not None and member_assessment.is_broad:
        return 2
    if len({grant.resource_address for grant in grants}) > 1:
        return 2
    return 1


def _inherited_iam_scope_description(scope: GcpIamScopeKey) -> str:
    if scope.scope_type == GCP_IAM_SCOPE_PROJECT:
        return f"project scope `{scope.identifier}`"
    if scope.scope_type == GCP_IAM_SCOPE_FOLDER:
        return f"folder scope `{scope.identifier}`"
    if scope.scope_type == GCP_IAM_SCOPE_ORGANIZATION:
        return f"organization scope `{scope.identifier}`"
    return f"{scope.scope_type} scope `{scope.identifier}`"


def _inherited_sensitive_resource_access_evidence(
    grant: _InheritedSensitiveResourceAccess,
) -> str:
    return (
        f"resource={grant.resource_address}; type={grant.resource_type}; "
        f"risk={grant.risk}"
    )