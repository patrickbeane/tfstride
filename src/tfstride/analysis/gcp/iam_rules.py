from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from tfstride.analysis.gcp.iam_inheritance import (
    GCP_IAM_SCOPE_FOLDER,
    GCP_IAM_SCOPE_ORGANIZATION,
    GCP_IAM_SCOPE_PROJECT,
    GcpIamScopeKey,
)
from tfstride.analysis.gcp.iam_access import (
    GCP_BIGQUERY_DATA_ACCESS_ROLES,
    GCP_PUBSUB_DATA_ACCESS_ROLES,
    GcpIamMemberAssessment,
    assess_gcp_broad_iam_member as _assess_gcp_broad_iam_member,
    assess_gcp_sensitive_iam_member as _assess_gcp_sensitive_iam_member,
    iam_resource_binding_members as _iam_resource_binding_members,
)
from tfstride.analysis.gcp.custom_roles import (
    GcpCustomRoleIndex,
    build_gcp_custom_role_index,
    custom_role_allows_data_store_access,
    custom_role_permissions,
    custom_role_privilege_risk,
)
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.resource_facts import analysis_facts
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource, ResourceInventory
from tfstride.providers.gcp.constants import (
    GCP_ORG_FOLDER_IAM_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES,
    PUBLIC_GCP_IAM_MEMBERS,
)
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_utils import binding_members, gcp_reference_key

_SENSITIVE_GCP_RESOURCE_TYPES = frozenset({"google_kms_crypto_key", "google_secret_manager_secret"})
_INHERITED_GCP_IAM_SCOPE_TYPES = frozenset(
    {
        GCP_IAM_SCOPE_ORGANIZATION,
        GCP_IAM_SCOPE_FOLDER,
        GCP_IAM_SCOPE_PROJECT,
    }
)
_INHERITED_IAM_BLAST_RADIUS_MIN_DESCENDANTS = 2
_SERVICE_ACCOUNT_KEY_MAX_VALIDITY_DAYS = 180
_SECRET_ACCESS_ROLES = frozenset(
    {
        "roles/editor",
        "roles/owner",
        "roles/secretmanager.admin",
        "roles/secretmanager.secretAccessor",
    }
)
_KMS_ACCESS_ROLES = frozenset(
    {
        "roles/cloudkms.admin",
        "roles/cloudkms.cryptoKeyDecrypter",
        "roles/cloudkms.cryptoKeyEncrypterDecrypter",
        "roles/editor",
        "roles/owner",
    }
)
_GCS_DATA_ACCESS_ROLES = frozenset(
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
_CLOUD_SQL_DATA_ACCESS_ROLES = frozenset(
    {
        "roles/cloudsql.admin",
        "roles/cloudsql.client",
        "roles/editor",
        "roles/owner",
    }
)
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
_KEYED_SERVICE_ACCOUNT_DATA_RESOURCE_ACCESS = {
    "google_secret_manager_secret": (_SECRET_ACCESS_ROLES, "Secret Manager secret IAM", 2),
    "google_kms_crypto_key": (_KMS_ACCESS_ROLES, "Cloud KMS key IAM", 2),
    "google_storage_bucket": (_GCS_DATA_ACCESS_ROLES, "GCS bucket IAM", 2),
    "google_bigquery_dataset": (GCP_BIGQUERY_DATA_ACCESS_ROLES, "BigQuery dataset IAM", 2),
    "google_bigquery_table": (GCP_BIGQUERY_DATA_ACCESS_ROLES, "BigQuery table IAM", 2),
    "google_pubsub_topic": (GCP_PUBSUB_DATA_ACCESS_ROLES, "Pub/Sub topic IAM", 1),
    "google_pubsub_subscription": (GCP_PUBSUB_DATA_ACCESS_ROLES, "Pub/Sub subscription IAM", 1),
}
_PROJECT_LEVEL_DATA_ACCESS_ROLES: dict[str, tuple[str, int]] = {
    "roles/storage.objectAdmin": ("project-level GCS object administration", 2),
    "roles/storage.objectCreator": ("project-level GCS object creation", 1),
    "roles/storage.objectUser": ("project-level GCS object use", 2),
    "roles/storage.objectViewer": ("project-level GCS object read access", 2),
    "roles/secretmanager.secretAccessor": ("project-level Secret Manager secret access", 2),
    "roles/cloudkms.cryptoKeyDecrypter": ("project-level Cloud KMS decrypt access", 2),
    "roles/cloudkms.cryptoKeyEncrypterDecrypter": ("project-level Cloud KMS encrypt/decrypt access", 2),
    "roles/cloudsql.client": ("project-level Cloud SQL client access", 2),
    "roles/bigquery.dataEditor": ("project-level BigQuery data edit access", 2),
    "roles/bigquery.dataOwner": ("project-level BigQuery data ownership", 2),
    "roles/bigquery.dataViewer": ("project-level BigQuery data read access", 2),
    "roles/pubsub.publisher": ("project-level Pub/Sub publish access", 1),
    "roles/pubsub.subscriber": ("project-level Pub/Sub subscription consume access", 1),
}
_INHERITED_SENSITIVE_RESOURCE_ACCESS: dict[str, tuple[frozenset[str], str, int]] = {
    "google_secret_manager_secret": (_SECRET_ACCESS_ROLES, "Secret Manager secret access", 2),
    "google_kms_crypto_key": (_KMS_ACCESS_ROLES, "Cloud KMS cryptographic key access", 2),
    "google_storage_bucket": (_GCS_DATA_ACCESS_ROLES, "GCS object data access", 2),
    "google_sql_database_instance": (_CLOUD_SQL_DATA_ACCESS_ROLES, "Cloud SQL client/admin access", 2),
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
class _KeyedServiceAccountGrant:
    resource_address: str
    source: str
    scope: str
    role: str
    member: str
    risk: str
    data_sensitivity: int


@dataclass(frozen=True, slots=True)
class _InheritedSensitiveResourceAccess:
    resource_address: str
    resource_type: str
    risk: str
    data_sensitivity: int

_HIGH_RISK_SERVICE_ACCOUNT_ROLES: dict[str, str] = {
    "roles/iam.serviceAccountAdmin": "service account administration and IAM policy control",
    "roles/iam.serviceAccountTokenCreator": "service account token minting and impersonation",
    "roles/iam.serviceAccountUser": "service account attachment and workload impersonation",
}

_PRIVILEGED_GCP_PROJECT_ROLES: dict[str, str] = {
    "roles/owner": "full project administration",
    "roles/editor": "broad write access across most project services",
    "roles/iam.serviceAccountTokenCreator": "service account token minting and impersonation",
    "roles/iam.serviceAccountUser": "service account attachment and impersonation paths",
    "roles/iam.serviceAccountAdmin": "service account administration",
    "roles/iam.securityAdmin": "IAM policy and security-control administration",
    "roles/resourcemanager.iam.projectIamAdmin": "project IAM policy administration",
}

_PRIVILEGED_GCP_ORG_FOLDER_ROLES: dict[str, str] = {
    **_PRIVILEGED_GCP_PROJECT_ROLES,
    "roles/accesscontextmanager.policyAdmin": "access policy administration across protected resources",
    "roles/billing.admin": "billing account administration and project billing linkage control",
    "roles/iam.organizationRoleAdmin": "custom role administration at organization scope",
    "roles/orgpolicy.policyAdmin": "organization policy administration",
    "roles/resourcemanager.folderAdmin": "folder hierarchy administration",
    "roles/resourcemanager.organizationAdmin": "organization-level resource administration",
    "roles/resourcemanager.iam.projectCreator": "project creation under the organization or folder",
    "roles/resourcemanager.iam.projectDeleter": "project deletion under the organization or folder",
}


class GcpIamRuleDetectors:
    def detect_sensitive_iam_external_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()
        for resource in context.inventory.by_type(*_SENSITIVE_GCP_RESOURCE_TYPES):
            resource_facts = analysis_facts(resource)
            for binding in resource_facts.iam.bindings:
                role = str(binding.get("role") or "unknown role")
                if not _is_sensitive_gcp_resource_role(resource, role):
                    continue
                source = str(binding.get("source") or "").strip()
                for member in binding_members(binding):
                    assessment = _assess_gcp_sensitive_iam_member(member, resource_facts.iam.project)
                    if assessment is None:
                        continue
                    finding_key = (resource.address, role, assessment.member)
                    if finding_key in seen:
                        continue
                    seen.add(finding_key)

                    severity_reasoning = build_severity_reasoning(
                        internet_exposure=assessment.is_public,
                        privilege_breadth=2 if assessment.is_public or assessment.is_broad else 1,
                        data_sensitivity=2,
                        lateral_movement=1,
                        blast_radius=2 if assessment.is_public or assessment.is_broad else 1,
                    )
                    affected_resources = dedupe_addresses([resource.address, source])
                    findings.append(
                        self._finding_factory.build(
                            rule_id=rule_id,
                            severity=severity_reasoning.severity,
                            affected_resources=affected_resources,
                            trust_boundary_id=None,
                            rationale=(
                                f"{resource.display_name} grants `{role}` to `{assessment.member}` through "
                                "GCP IAM. Public, broad-domain, or foreign-project principals can access "
                                "sensitive secrets or cryptographic key operations outside the expected "
                                "project trust boundary."
                            ),
                            evidence=collect_evidence(
                                evidence_item(
                                    "iam_binding",
                                    [
                                        f"source={source}" if source else "source=unknown",
                                        f"role={role}",
                                        f"member={assessment.member}",
                                    ],
                                ),
                                evidence_item("trust_scope", [assessment.scope_description]),
                                evidence_item(
                                    "resource_policy_sources",
                                    resource_facts.iam.resource_policy_source_addresses,
                                ),
                            ),
                            severity_reasoning=severity_reasoning,
                        )
                    )
        return findings

    def detect_service_account_iam_broad_principal(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        inventory = context.inventory
        for binding in inventory.by_type(*GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES):
            target = _service_account_iam_target(binding, inventory)
            for role, member in _iam_resource_binding_members(binding):
                assessment = _assess_gcp_broad_iam_member(member)
                if assessment is None:
                    continue
                severity_reasoning = build_severity_reasoning(
                    internet_exposure=assessment.is_public,
                    privilege_breadth=2,
                    data_sensitivity=0,
                    lateral_movement=1,
                    blast_radius=2 if assessment.is_public else 1,
                )
                affected_resources = dedupe_addresses(
                    [target.address if target else "", binding.address]
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=affected_resources,
                        trust_boundary_id=None,
                        rationale=(
                            f"{binding.display_name} grants `{role}` on a GCP service account to "
                            f"`{member}`. Public or broad principals can cross the service-account "
                            "identity boundary and may gain workload impersonation paths."
                        ),
                        evidence=collect_evidence(
                            evidence_item(
                                "iam_binding",
                                [
                                    f"source={binding.address}",
                                    f"member={member}",
                                    f"role={role}",
                                ],
                            ),
                            evidence_item("trust_scope", [assessment.scope_description]),
                            evidence_item(
                                "service_account_reference",
                                [analysis_facts(binding).iam.service_account_reference or ""],
                            ),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings

    def detect_service_account_iam_privileged_role(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        inventory = context.inventory
        for binding in inventory.by_type(*GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES):
            target = _service_account_iam_target(binding, inventory)
            for role, member in _iam_resource_binding_members(binding):
                role_risk = _high_risk_service_account_role_risk(role)
                if role_risk is None:
                    continue
                broad_assessment = _assess_gcp_broad_iam_member(member)
                severity_reasoning = build_severity_reasoning(
                    internet_exposure=bool(broad_assessment and broad_assessment.is_public),
                    privilege_breadth=2,
                    data_sensitivity=0,
                    lateral_movement=2,
                    blast_radius=2,
                )
                affected_resources = dedupe_addresses(
                    [target.address if target else "", binding.address]
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=affected_resources,
                        trust_boundary_id=None,
                        rationale=(
                            f"{binding.display_name} grants the high-impact service account role `{role}` "
                            f"to `{member}`. That role enables {role_risk}, expanding privilege if the "
                            "principal is compromised or mis-scoped."
                        ),
                        evidence=collect_evidence(
                            evidence_item(
                                "iam_binding",
                                [
                                    f"source={binding.address}",
                                    f"member={member}",
                                    f"role={role}",
                                ],
                            ),
                            evidence_item("role_risk", [role_risk]),
                            evidence_item(
                                "service_account_reference",
                                [analysis_facts(binding).iam.service_account_reference or ""],
                            ),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings

    def detect_project_iam_broad_principal(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for binding in context.inventory.by_type(*GCP_PROJECT_IAM_RESOURCE_TYPES):
            for role, member in _project_iam_binding_members(binding):
                if member not in PUBLIC_GCP_IAM_MEMBERS:
                    continue
                severity_reasoning = build_severity_reasoning(
                    internet_exposure=True,
                    privilege_breadth=1,
                    data_sensitivity=0,
                    lateral_movement=1,
                    blast_radius=1,
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=[binding.address],
                        trust_boundary_id=None,
                        rationale=(
                            f"{binding.display_name} grants `{role}` to `{member}` at project scope. Public "
                            "or broadly authenticated principals can cross into the control plane without an "
                            "organization-owned identity boundary."
                        ),
                        evidence=collect_evidence(
                            evidence_item("iam_binding", [f"member={member}", f"role={role}"]),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings

    def detect_project_iam_privileged_role(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        custom_roles = build_gcp_custom_role_index(context.inventory.resources)
        for binding in context.inventory.by_type(*GCP_PROJECT_IAM_RESOURCE_TYPES):
            for role, member in _project_iam_binding_members(binding):
                role_risk = _privileged_project_role_risk(role, custom_roles)
                if role_risk is None:
                    continue
                severity_reasoning = build_severity_reasoning(
                    internet_exposure=False,
                    privilege_breadth=2,
                    data_sensitivity=0,
                    lateral_movement=2,
                    blast_radius=2,
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=[binding.address],
                        trust_boundary_id=None,
                        rationale=(
                            f"{binding.display_name} grants the high-impact GCP role `{role}` to `{member}` "
                            f"at project scope. That role enables {role_risk} and can materially expand "
                            "control-plane blast radius if the principal is compromised or mis-scoped."
                        ),
                        evidence=collect_evidence(
                            evidence_item("iam_binding", [f"member={member}", f"role={role}"]),
                            evidence_item("role_risk", [role_risk]),
                            evidence_item("custom_role_permissions", custom_role_permissions(role, custom_roles)),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings

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
                for role, member in _iam_resource_binding_members(binding):
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
                for role, member in _iam_resource_binding_members(binding):
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

    def detect_service_account_key_hygiene(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        inventory = context.inventory
        for key in inventory.by_type("google_service_account_key"):
            service_account_reference = analysis_facts(key).iam.service_account_reference
            target = _service_account_iam_target(key, inventory)
            validity_days = _service_account_key_validity_days(key)
            keepers = key.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_KEY_KEEPERS)
            keepers_configured = isinstance(keepers, dict) and bool(keepers)

            risks = ["Terraform manages a user-created service-account key"]
            if validity_days is not None and validity_days > _SERVICE_ACCOUNT_KEY_MAX_VALIDITY_DAYS:
                risks.append(
                    f"validity window is {validity_days} days and exceeds "
                    f"{_SERVICE_ACCOUNT_KEY_MAX_VALIDITY_DAYS}-day threshold"
                )
            if not keepers_configured:
                risks.append("no Terraform keepers rotation trigger observed")

            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=1,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=2 if len(risks) > 1 else 1,
            )
            validity_evidence = _service_account_key_validity_evidence(key, validity_days)
            rotation_evidence = (
                [f"keepers configured: {', '.join(sorted(str(keeper_name) for keeper_name in keepers))}"]
                if keepers_configured
                else ["no Terraform keepers rotation trigger observed"]
            )
            target_label = (
                target.address if target is not None else service_account_reference or "unknown service account"
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses([target.address if target else "", key.address]),
                    trust_boundary_id=None,
                    rationale=(
                        f"{key.display_name} creates a user-managed GCP service account key for "
                        f"`{target_label}`. User-managed service account keys are portable, long-lived "
                        "credentials that can be copied outside GCP control, so they need explicit rotation "
                        "controls or should be replaced with workload identity or impersonation flows."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "key_context",
                            [
                                f"source={key.address}",
                                f"service_account_reference={service_account_reference or ''}",
                                "key_algorithm="
                                f"{key.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_KEY_ALGORITHM) or ''}",
                                "public_key_type="
                                f"{key.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_PUBLIC_KEY_TYPE) or ''}",
                            ],
                        ),
                        evidence_item("key_risk", risks),
                        evidence_item("validity_window", validity_evidence),
                        evidence_item("rotation_control", rotation_evidence),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_service_account_key_effective_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        inventory = context.inventory
        custom_roles = build_gcp_custom_role_index(inventory.resources)
        for key in inventory.by_type("google_service_account_key"):
            target = _service_account_iam_target(key, inventory)
            grants = _keyed_service_account_effective_access_grants(
                key, target, inventory, custom_roles
            )
            if not grants:
                continue

            identity_control_plane_access = any(
                grant.scope == "service account IAM"
                or grant.scope.startswith(("project", "organization", "folder"))
                for grant in grants
            )
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=2 if identity_control_plane_access else 1,
                data_sensitivity=max(grant.data_sensitivity for grant in grants),
                lateral_movement=2 if identity_control_plane_access else 1,
                blast_radius=2,
            )
            service_account_reference = analysis_facts(key).iam.service_account_reference
            target_label = (
                target.address if target is not None else service_account_reference or "unknown service account"
            )
            principals = sorted(_service_account_key_principals(key, target))
            affected_resources = dedupe_addresses(
                [
                    target.address if target else "",
                    key.address,
                    *[grant.resource_address for grant in grants],
                    *[grant.source for grant in grants],
                ]
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=affected_resources,
                    trust_boundary_id=None,
                    rationale=(
                        f"{key.display_name} creates portable credentials for `{target_label}`, and that "
                        "service account has sensitive data access or high-impact IAM grants. A copied key "
                        "can exercise those effective permissions outside the intended workload boundary."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "key_context",
                            [
                                f"source={key.address}",
                                f"service_account_reference={service_account_reference or ''}",
                                f"resolved_service_account={target.address if target else ''}",
                            ],
                        ),
                        evidence_item("service_account_principals", principals),
                        evidence_item(
                            "effective_access",
                            [
                                _keyed_service_account_grant_evidence(grant)
                                for grant in grants
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_org_folder_iam_broad_principal(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for binding in context.inventory.by_type(*GCP_ORG_FOLDER_IAM_RESOURCE_TYPES):
            scope = _org_folder_scope_description(binding)
            for role, member in _org_folder_iam_binding_members(binding):
                assessment = _assess_gcp_broad_iam_member(member)
                if assessment is None:
                    continue
                severity_reasoning = build_severity_reasoning(
                    internet_exposure=assessment.is_public,
                    privilege_breadth=2,
                    data_sensitivity=0,
                    lateral_movement=2,
                    blast_radius=2,
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=[binding.address],
                        trust_boundary_id=None,
                        rationale=(
                            f"{binding.display_name} grants `{role}` to `{member}` at {scope}. Public or "
                            "broad-domain principals at organization or folder scope can expand access across "
                            "many descendant projects and workloads."
                        ),
                        evidence=collect_evidence(
                            evidence_item("iam_binding", [f"member={member}", f"role={role}"]),
                            evidence_item("scope", [scope]),
                            evidence_item("trust_scope", [assessment.scope_description]),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings

    def detect_org_folder_iam_privileged_role(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        custom_roles = build_gcp_custom_role_index(context.inventory.resources)
        for binding in context.inventory.by_type(*GCP_ORG_FOLDER_IAM_RESOURCE_TYPES):
            scope = _org_folder_scope_description(binding)
            for role, member in _org_folder_iam_binding_members(binding):
                role_risk = _privileged_org_folder_role_risk(role, custom_roles)
                if role_risk is None:
                    continue
                severity_reasoning = build_severity_reasoning(
                    internet_exposure=False,
                    privilege_breadth=2,
                    data_sensitivity=0,
                    lateral_movement=2,
                    blast_radius=2,
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=[binding.address],
                        trust_boundary_id=None,
                        rationale=(
                            f"{binding.display_name} grants the high-impact GCP role `{role}` to `{member}` "
                            f"at {scope}. That role enables {role_risk} across a high-level resource "
                            "boundary and can materially expand blast radius if the principal is compromised."
                        ),
                        evidence=collect_evidence(
                            evidence_item("iam_binding", [f"member={member}", f"role={role}"]),
                            evidence_item("scope", [scope]),
                            evidence_item("role_risk", [role_risk]),
                            evidence_item("custom_role_permissions", custom_role_permissions(role, custom_roles)),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings


def _is_sensitive_gcp_resource_role(resource: NormalizedResource, role: str) -> bool:
    normalized_role = str(role).strip()
    if resource.resource_type == "google_secret_manager_secret":
        return normalized_role in _SECRET_ACCESS_ROLES
    if resource.resource_type == "google_kms_crypto_key":
        return normalized_role in _KMS_ACCESS_ROLES
    return False


def _keyed_service_account_effective_access_grants(
    key: NormalizedResource,
    target: NormalizedResource | None,
    inventory: ResourceInventory,
    custom_roles: GcpCustomRoleIndex,
) -> list[_KeyedServiceAccountGrant]:
    principals = _service_account_key_principals(key, target)
    if not principals:
        return []

    grants: list[_KeyedServiceAccountGrant] = []
    seen: set[tuple[str, str, str, str]] = set()

    def add_grant(grant: _KeyedServiceAccountGrant) -> None:
        dedupe_key = (grant.resource_address, grant.source, grant.role, grant.member)
        if dedupe_key in seen:
            return
        seen.add(dedupe_key)
        grants.append(grant)

    for binding in inventory.by_type(*GCP_PROJECT_IAM_RESOURCE_TYPES):
        for role, member in _project_iam_binding_members(binding):
            if not _member_matches_service_account_principal(member, principals):
                continue
            role_risk = _privileged_project_role_risk(role, custom_roles)
            data_role_risk = _project_level_data_role_risk(role)
            if role_risk is not None:
                add_grant(
                    _KeyedServiceAccountGrant(
                        resource_address=binding.address,
                        source=binding.address,
                        scope="project IAM",
                        role=role,
                        member=member,
                        risk=role_risk,
                        data_sensitivity=0,
                    )
                )
                continue
            if data_role_risk is not None:
                risk, data_sensitivity = data_role_risk
                add_grant(
                    _KeyedServiceAccountGrant(
                        resource_address=binding.address,
                        source=binding.address,
                        scope="project IAM data access",
                        role=role,
                        member=member,
                        risk=risk,
                        data_sensitivity=data_sensitivity,
                    )
                )

    for binding in inventory.by_type(*GCP_ORG_FOLDER_IAM_RESOURCE_TYPES):
        scope = _org_folder_scope_description(binding)
        for role, member in _org_folder_iam_binding_members(binding):
            if not _member_matches_service_account_principal(member, principals):
                continue
            role_risk = _privileged_org_folder_role_risk(role, custom_roles)
            if role_risk is None:
                continue
            add_grant(
                _KeyedServiceAccountGrant(
                    resource_address=binding.address,
                    source=binding.address,
                    scope=scope,
                    role=role,
                    member=member,
                    risk=role_risk,
                    data_sensitivity=0,
                )
            )

    for binding in inventory.by_type(*GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES):
        iam_target = _service_account_iam_target(binding, inventory)
        for role, member in _iam_resource_binding_members(binding):
            if not _member_matches_service_account_principal(member, principals):
                continue
            role_risk = _high_risk_service_account_role_risk(role)
            if role_risk is None:
                continue
            add_grant(
                _KeyedServiceAccountGrant(
                    resource_address=iam_target.address if iam_target else binding.address,
                    source=binding.address,
                    scope="service account IAM",
                    role=role,
                    member=member,
                    risk=role_risk,
                    data_sensitivity=0,
                )
            )

    for resource in inventory.by_type(*tuple(_KEYED_SERVICE_ACCOUNT_DATA_RESOURCE_ACCESS)):
        allowed_roles, scope, data_sensitivity = _KEYED_SERVICE_ACCOUNT_DATA_RESOURCE_ACCESS[
            resource.resource_type
        ]
        for source, role, member in _resource_iam_binding_members(resource):
            if not _member_matches_service_account_principal(member, principals):
                continue
            if role in allowed_roles:
                risk = f"{scope} grants {role}"
            elif custom_role_allows_data_store_access(resource, role, custom_roles):
                risk = f"{scope} grants custom data-store role {role}"
            else:
                continue
            add_grant(
                _KeyedServiceAccountGrant(
                    resource_address=resource.address,
                    source=source,
                    scope=scope,
                    role=role,
                    member=member,
                    risk=risk,
                    data_sensitivity=data_sensitivity,
                )
            )

    return sorted(
        grants,
        key=lambda grant: (grant.resource_address, grant.source, grant.role, grant.member),
    )


def _service_account_key_principals(
    key: NormalizedResource,
    target: NormalizedResource | None,
) -> set[str]:
    values: list[object] = []
    if target is not None:
        target_facts = analysis_facts(target)
        values.extend(
            [
                target_facts.iam.service_account_email,
                target_facts.iam.service_account_member,
                target_facts.iam.resource_name,
            ]
        )
    key_facts = analysis_facts(key)
    values.extend(
        [
            key_facts.iam.service_account_reference,
            key.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_REFERENCE),
            key.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_ID),
            key.get_metadata_field(GcpResourceMetadata.NAME),
        ]
    )

    principals: set[str] = set()
    for value in values:
        email = _service_account_email_from_reference(value)
        if email is None:
            continue
        principals.add(email)
        principals.add(f"serviceAccount:{email}")
    return principals


def _service_account_email_from_reference(value: object) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.startswith("serviceAccount:"):
        text = text.removeprefix("serviceAccount:")
    if "/serviceAccounts/" in text:
        text = text.split("/serviceAccounts/", 1)[1].split("/", 1)[0]
    if "@" not in text or not text.endswith(".gserviceaccount.com"):
        return None
    return text


def _member_matches_service_account_principal(member: str, principals: set[str]) -> bool:
    normalized_member = str(member).strip()
    if normalized_member in principals:
        return True
    email = _service_account_email_from_reference(normalized_member)
    return bool(email and (email in principals or f"serviceAccount:{email}" in principals))


def _resource_iam_binding_members(resource: NormalizedResource) -> list[tuple[str, str, str]]:
    members: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for binding in analysis_facts(resource).iam.bindings:
        role = str(binding.get("role") or "unknown role").strip()
        source = str(binding.get("source") or "").strip()
        for member in binding_members(binding):
            normalized_member = str(member).strip()
            if not normalized_member:
                continue
            key = (source, role, normalized_member)
            if key in seen:
                continue
            seen.add(key)
            members.append(key)
    return members


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
        return _privileged_org_folder_role_risk(role, custom_roles)
    return _privileged_project_role_risk(role, custom_roles)


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
    broad_assessment = _assess_gcp_broad_iam_member(member)
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
        assessment = _assess_gcp_sensitive_iam_member(member, project)
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


def _project_level_data_role_risk(role: str | None) -> tuple[str, int] | None:
    if not role:
        return None
    return _PROJECT_LEVEL_DATA_ACCESS_ROLES.get(role.strip())


def _keyed_service_account_grant_evidence(grant: _KeyedServiceAccountGrant) -> str:
    source = grant.source if grant.source else "unknown"
    return (
        f"resource={grant.resource_address}; source={source}; scope={grant.scope}; "
        f"role={grant.role}; member={grant.member}; risk={grant.risk}"
    )


def _service_account_key_validity_days(resource: NormalizedResource) -> int | None:
    valid_after = _parse_rfc3339_timestamp(
        resource.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_KEY_VALID_AFTER)
    )
    valid_before = _parse_rfc3339_timestamp(
        resource.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_KEY_VALID_BEFORE)
    )
    if valid_after is None or valid_before is None or valid_before <= valid_after:
        return None
    return int((valid_before - valid_after).total_seconds() // 86400)


def _service_account_key_validity_evidence(
    resource: NormalizedResource,
    validity_days: int | None,
) -> list[str]:
    values = [
        "valid_after="
        f"{resource.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_KEY_VALID_AFTER) or ''}",
        "valid_before="
        f"{resource.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_KEY_VALID_BEFORE) or ''}",
    ]
    if validity_days is not None:
        values.append(f"validity_days={validity_days}")
    return values


def _parse_rfc3339_timestamp(value: object) -> datetime | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _high_risk_service_account_role_risk(role: str | None) -> str | None:
    if not role:
        return None
    normalized_role = role.strip()
    return _HIGH_RISK_SERVICE_ACCOUNT_ROLES.get(normalized_role)


def _service_account_iam_target(
    iam_resource: NormalizedResource,
    inventory: ResourceInventory,
) -> NormalizedResource | None:
    target_reference = analysis_facts(iam_resource).iam.service_account_reference
    if not target_reference:
        return None
    target_key = gcp_reference_key(target_reference)
    for service_account in inventory.by_type("google_service_account"):
        if target_key in _service_account_reference_keys(service_account):
            return service_account
    return None


def _service_account_reference_keys(resource: NormalizedResource) -> set[str]:
    facts = analysis_facts(resource)
    values = [
        resource.address,
        f"{resource.address}.id",
        f"{resource.address}.name",
        f"{resource.address}.email",
        resource.identifier,
        facts.iam.service_account_email,
        facts.iam.service_account_member,
        facts.iam.resource_name,
    ]
    keys: set[str] = set()
    for value in values:
        if value in (None, ""):
            continue
        text = str(value).strip()
        if not text:
            continue
        keys.add(gcp_reference_key(text))
        if text.startswith("serviceAccount:"):
            keys.add(gcp_reference_key(text.removeprefix("serviceAccount:")))
        else:
            keys.add(gcp_reference_key(f"serviceAccount:{text}"))
    return keys


def _project_iam_binding_members(resource: NormalizedResource) -> list[tuple[str, str]]:
    return _iam_resource_binding_members(resource)


def _org_folder_iam_binding_members(resource: NormalizedResource) -> list[tuple[str, str]]:
    return _iam_resource_binding_members(resource)


def _org_folder_scope_description(resource: NormalizedResource) -> str:
    facts = analysis_facts(resource)
    if resource.resource_type.startswith("google_organization_iam_"):
        if facts.iam.organization_id:
            return f"organization scope `{facts.iam.organization_id}`"
        return "organization scope"
    if facts.iam.folder_id:
        return f"folder scope `{facts.iam.folder_id}`"
    return "folder scope"


def _privileged_project_role_risk(
    role: str | None,
    custom_roles: GcpCustomRoleIndex | None = None,
) -> str | None:
    return _privileged_gcp_role_risk(
        role,
        predefined_roles=_PRIVILEGED_GCP_PROJECT_ROLES,
        admin_risk="admin-level control over a GCP service or project security surface",
        custom_roles=custom_roles,
    )


def _privileged_org_folder_role_risk(
    role: str | None,
    custom_roles: GcpCustomRoleIndex | None = None,
) -> str | None:
    return _privileged_gcp_role_risk(
        role,
        predefined_roles=_PRIVILEGED_GCP_ORG_FOLDER_ROLES,
        admin_risk="admin-level control over a GCP organization, folder, or descendant project surface",
        custom_roles=custom_roles,
    )


def _privileged_gcp_role_risk(
    role: str | None,
    *,
    predefined_roles: dict[str, str],
    admin_risk: str,
    custom_roles: GcpCustomRoleIndex | None = None,
) -> str | None:
    if not role:
        return None
    normalized_role = role.strip()
    if normalized_role in predefined_roles:
        return predefined_roles[normalized_role]
    role_name = normalized_role.rsplit("/", 1)[-1].lower()
    if normalized_role.startswith("roles/") and "admin" in role_name:
        return admin_risk
    if custom_roles is not None:
        return custom_role_privilege_risk(normalized_role, custom_roles)
    return None