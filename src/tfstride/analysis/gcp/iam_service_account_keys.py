from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from tfstride.analysis.finding_helpers import (
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.gcp.custom_roles import (
    GcpCustomRoleIndex,
    build_gcp_custom_role_index,
    custom_role_allows_data_store_access,
)
from tfstride.analysis.gcp.iam_access import (
    GCP_BIGQUERY_DATA_ACCESS_ROLES,
    GCP_GCS_DATA_ACCESS_ROLES,
    GCP_KMS_ACCESS_ROLES,
    GCP_PUBSUB_DATA_ACCESS_ROLES,
    GCP_SECRET_ACCESS_ROLES,
    iam_resource_binding_members,
    org_folder_scope_description,
)
from tfstride.analysis.gcp.iam_role_risk import (
    privileged_org_folder_role_risk,
    privileged_project_role_risk,
)
from tfstride.analysis.gcp.org_policy_guardrails import (
    ORG_POLICY_DISABLE_SERVICE_ACCOUNT_KEY_CREATION,
)
from tfstride.analysis.gcp.org_policy_evidence import organization_guardrail_evidence
from tfstride.analysis.gcp.org_policy_severity import guardrail_adjusted_severity_reasoning
from tfstride.analysis.gcp.iam_service_accounts import (
    high_risk_service_account_role_risk,
    service_account_iam_target,
)
from tfstride.analysis.resource_facts import analysis_facts
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource, ResourceInventory
from tfstride.providers.gcp.constants import (
    GCP_ORG_FOLDER_IAM_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES,
)
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_utils import binding_members

_SERVICE_ACCOUNT_KEY_MAX_VALIDITY_DAYS = 180
_KEYED_SERVICE_ACCOUNT_DATA_RESOURCE_ACCESS = {
    "google_secret_manager_secret": (GCP_SECRET_ACCESS_ROLES, "Secret Manager secret IAM", 2),
    "google_kms_crypto_key": (GCP_KMS_ACCESS_ROLES, "Cloud KMS key IAM", 2),
    "google_storage_bucket": (GCP_GCS_DATA_ACCESS_ROLES, "GCS bucket IAM", 2),
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


@dataclass(frozen=True, slots=True)
class _KeyedServiceAccountGrant:
    resource_address: str
    source: str
    scope: str
    role: str
    member: str
    risk: str
    data_sensitivity: int


class GcpServiceAccountKeyDetectors:
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
            target = service_account_iam_target(key, inventory)
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

            severity_reasoning = guardrail_adjusted_severity_reasoning(
                context.analysis_indexes.gcp_org_policy_guardrails,
                target or key,
                constraints=(ORG_POLICY_DISABLE_SERVICE_ACCOUNT_KEY_CREATION,),
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
                        organization_guardrail_evidence(
                            context.analysis_indexes.gcp_org_policy_guardrails,
                            target or key,
                            ORG_POLICY_DISABLE_SERVICE_ACCOUNT_KEY_CREATION,
                        ),
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
            target = service_account_iam_target(key, inventory)
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
            severity_reasoning = guardrail_adjusted_severity_reasoning(
                context.analysis_indexes.gcp_org_policy_guardrails,
                target or key,
                constraints=(ORG_POLICY_DISABLE_SERVICE_ACCOUNT_KEY_CREATION,),
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
                        organization_guardrail_evidence(
                            context.analysis_indexes.gcp_org_policy_guardrails,
                            target or key,
                            ORG_POLICY_DISABLE_SERVICE_ACCOUNT_KEY_CREATION,
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


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
        for role, member in iam_resource_binding_members(binding):
            if not _member_matches_service_account_principal(member, principals):
                continue
            role_risk = privileged_project_role_risk(role, custom_roles)
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
        scope = org_folder_scope_description(binding)
        for role, member in iam_resource_binding_members(binding):
            if not _member_matches_service_account_principal(member, principals):
                continue
            role_risk = privileged_org_folder_role_risk(role, custom_roles)
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
        iam_target = service_account_iam_target(binding, inventory)
        for role, member in iam_resource_binding_members(binding):
            if not _member_matches_service_account_principal(member, principals):
                continue
            role_risk = high_risk_service_account_role_risk(role)
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