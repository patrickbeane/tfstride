from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Literal, cast

from tfstride.models import NormalizedResource
from tfstride.providers.coercion import (
    STATE_DISABLED,
    STATE_ENABLED,
    STATE_NOT_CONFIGURED,
    dedupe,
    dedupe_strings,
)
from tfstride.providers.gcp.custom_role_index import GcpCustomRoleIndex, build_gcp_custom_role_index
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext
from tfstride.providers.gcp.resource_types import GCP_CLOUD_RUN_RESOURCE_TYPES, GcpResourceType
from tfstride.providers.gcp.structured_data_deletion_evidence import (
    GcpCloudRunFirestoreDeletionPath,
    GcpFirestoreActiveCustomRoleStage,
    GcpFirestoreDeletionRecoveryEvidence,
    GcpFirestoreExactDatabaseConditionEvidence,
)

_ENTITY_DELETE = "datastore.entities.delete"
_BULK_DELETE = "datastore.databases.bulkDelete"
_ACTIVE_CUSTOM_ROLE_STAGES = frozenset({"ALPHA", "BETA", "DEPRECATED", "EAP", "GA"})


class ModelCloudRunFirestoreEntityDeletionPathsStage:
    """Project deterministic Firestore IAM access into entity-deletion paths."""

    name = "model_cloud_run_firestore_entity_deletion_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: GcpDecorationContext,
    ) -> None:
        del context
        databases = {
            resource.address: resource
            for resource in resources
            if resource.resource_type == GcpResourceType.FIRESTORE_DATABASE
        }
        custom_roles = build_gcp_custom_role_index(resources)
        for workload in resources:
            if workload.resource_type not in GCP_CLOUD_RUN_RESOURCE_TYPES:
                continue
            paths, uncertainties = _cloud_run_firestore_entity_deletion_paths(
                workload,
                databases,
                custom_roles,
            )
            facts = gcp_facts(workload)
            facts.set_cloud_run_firestore_entity_deletion_paths(paths)
            facts.extend_cloud_run_firestore_entity_deletion_path_uncertainties(uncertainties)


def _cloud_run_firestore_entity_deletion_paths(
    workload: NormalizedResource,
    databases: Mapping[str, NormalizedResource],
    custom_roles: GcpCustomRoleIndex,
) -> tuple[list[GcpCloudRunFirestoreDeletionPath], list[str]]:
    workload_facts = gcp_facts(workload)
    paths: list[GcpCloudRunFirestoreDeletionPath] = []
    uncertainties = list(workload_facts.cloud_run_firestore_access_path_uncertainties)
    seen: set[tuple[str, str, str, str, str, str, str]] = set()

    for access_path in workload_facts.cloud_run_firestore_access_paths:
        database_address = _known_string(access_path.get("firestore_database_address"))
        database = databases.get(database_address or "")
        if database is None:
            uncertainties.append(f"{workload.address}: Firestore access path has unresolved database ancestry")
            continue

        common = _common_path_evidence(
            workload,
            database,
            access_path,
            custom_roles,
        )
        if common is None:
            uncertainties.append(f"{workload.address}: Firestore access path has incomplete deletion evidence")
            continue

        permissions = _string_values(access_path.get("matched_permissions"))
        for operation in (_ENTITY_DELETE, _BULK_DELETE):
            if not _permission_allows(permissions, operation):
                continue
            iam_resource_address = _known_string(common.get("iam_resource_address"))
            role = _known_string(common.get("role"))
            scope_type = _known_string(common.get("scope_type"))
            scope = _known_string(common.get("scope"))
            if iam_resource_address is None or role is None or scope_type is None or scope is None:
                continue
            fingerprint = (
                database.address,
                operation,
                iam_resource_address,
                role,
                scope_type,
                scope,
                json.dumps(common.get("condition"), sort_keys=True, default=str),
            )
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            paths.append(_deletion_path(common, operation))

    paths.sort(
        key=lambda path: (
            path["firestore_database_address"],
            path["operation"],
            path["scope_type"],
            path["iam_resource_address"],
            path["role"],
        )
    )
    return paths, dedupe(uncertainties)


def _common_path_evidence(
    workload: NormalizedResource,
    database: NormalizedResource,
    access_path: Mapping[str, object],
    custom_roles: GcpCustomRoleIndex,
) -> dict[str, object] | None:
    database_facts = gcp_facts(database)
    service_account_email = _known_string(access_path.get("service_account_email"))
    service_account_member = _known_string(access_path.get("service_account_member"))
    database_resource_name = _known_string(access_path.get("firestore_database_resource_name"))
    database_name = _known_string(database_facts.firestore_database_name)
    database_project = _known_string(database_facts.project)
    database_type = _known_string(database_facts.firestore_database_type)
    iam_resource_address = _known_string(access_path.get("iam_resource_address"))
    iam_resource_type = _known_string(access_path.get("iam_resource_type"))
    role = _known_string(access_path.get("role"))
    role_kind = _known_string(access_path.get("role_kind"))
    scope_type = _known_string(access_path.get("scope_type"))
    scope = _known_string(access_path.get("scope"))
    grant_basis = _known_string(access_path.get("grant_basis"))

    if (
        service_account_email is None
        or service_account_member is None
        or database_resource_name is None
        or database_name is None
        or database_project is None
        or database_type is None
        or iam_resource_address is None
        or iam_resource_type is None
        or role is None
        or role_kind is None
        or scope_type not in {"project", "database"}
        or scope is None
        or grant_basis is None
        or access_path.get("access_state") != "granted"
        or access_path.get("authorization_model") != "iam_authorized_server_api"
    ):
        return None

    if service_account_member != f"serviceAccount:{service_account_email}":
        return None
    if database_resource_name != _firestore_database_resource_name(database):
        return None
    if _known_string(access_path.get("firestore_database_address")) != database.address:
        return None

    condition: object
    condition_state: Literal["not_configured", "configured"]
    condition_evaluation: Literal["not_configured", "exact_database_scope_match"]
    resource_scope: Literal["firestore_project", "exact_firestore_database"]
    if scope_type == "project":
        if access_path.get("condition") is not None or access_path.get("condition_state") != "not_configured":
            return None
        condition = None
        condition_state = "not_configured"
        condition_evaluation = "not_configured"
        resource_scope = "firestore_project"
    else:
        condition_evidence = _condition_evidence(access_path.get("condition"))
        if condition_evidence is None or access_path.get("condition_state") != "configured":
            return None
        if access_path.get("condition_evaluation") != "exact_database_scope_match":
            return None
        condition = condition_evidence
        condition_state = "configured"
        condition_evaluation = "exact_database_scope_match"
        resource_scope = "exact_firestore_database"

    role_definition_address: str | None = None
    custom_role_stage: GcpFirestoreActiveCustomRoleStage | None = None
    custom_role_deleted: Literal[False] | None = None
    if role_kind == "custom":
        resolution = custom_roles.resolve(role)
        role_definition = resolution.selected_candidate
        if role_definition is None:
            return None
        role_facts = gcp_facts(role_definition)
        if role_facts.custom_role_deleted is not False or role_facts.custom_role_stage is None:
            return None
        stage = role_facts.custom_role_stage.upper()
        if stage not in _ACTIVE_CUSTOM_ROLE_STAGES:
            return None
        role_definition_address = role_definition.address
        custom_role_stage = cast(GcpFirestoreActiveCustomRoleStage, stage)
        custom_role_deleted = False

    recovery_evidence = _recovery_evidence(database)
    return {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "service_account_email": service_account_email,
        "service_account_member": service_account_member,
        "identity_kind": "cloud_run_service_account",
        "credential_context": "workload_runtime",
        "firestore_database_address": database.address,
        "firestore_database_resource_type": database.resource_type,
        "firestore_database_resource_name": database_resource_name,
        "firestore_database_name": database_name,
        "firestore_database_project": database_project,
        "firestore_database_type": database_type,
        "target_model_evidence_addresses": [database.address],
        "management_effect": "disruption",
        "iam_resource_address": iam_resource_address,
        "iam_resource_type": iam_resource_type,
        "iam_source_addresses": dedupe_strings([iam_resource_address, role_definition_address]),
        "role": role,
        "role_kind": role_kind,
        "role_definition_address": role_definition_address,
        "custom_role_permissions": _string_values(access_path.get("custom_role_permissions")),
        "custom_role_stage": custom_role_stage,
        "custom_role_deleted": custom_role_deleted,
        "grant_basis": grant_basis,
        "authorization_state": "granted",
        "policy_complete": True,
        "authorization_model": "iam_authorized_server_api",
        "firestore_security_rules_evaluated": False,
        "firestore_security_rules_applicability": "not_in_server_api_authorization_path",
        "lifecycle_compatibility_state": "not_applicable",
        "recovery_evidence": recovery_evidence,
        "posture_uncertainties": list(recovery_evidence["uncertainties"]),
        "scope_type": scope_type,
        "scope": scope,
        "resource_scope": resource_scope,
        "condition": condition,
        "condition_state": condition_state,
        "condition_evaluation": condition_evaluation,
    }


def _deletion_path(
    common: Mapping[str, object],
    operation: str,
) -> GcpCloudRunFirestoreDeletionPath:
    base = dict(common)
    if operation == _ENTITY_DELETE:
        base.update(
            {
                "operation": _ENTITY_DELETE,
                "operation_class": "entity_deletion",
                "target_granularity": "database_entity_namespace",
                "matched_permissions": [_ENTITY_DELETE],
            }
        )
    else:
        base.update(
            {
                "operation": _BULK_DELETE,
                "operation_class": "bulk_entity_deletion",
                "target_granularity": "database_bulk_entity_namespace",
                "matched_permissions": [_BULK_DELETE],
            }
        )
    return cast(GcpCloudRunFirestoreDeletionPath, base)


def _recovery_evidence(
    database: NormalizedResource,
) -> GcpFirestoreDeletionRecoveryEvidence:
    facts = gcp_facts(database)
    state = facts.firestore_pitr_state
    uncertainties = [
        uncertainty
        for uncertainty in facts.firestore_posture_uncertainties
        if uncertainty.startswith("point_in_time_recovery_enablement")
    ]
    if state == STATE_ENABLED:
        return {
            "recovery_evidence_scope": "firestore_point_in_time_recovery",
            "pitr_state": "enabled",
            "pitr_enabled": True,
            "historical_version_retention_state": "pitr_up_to_seven_days",
            "uncertainties": dedupe(uncertainties),
        }
    if state == STATE_DISABLED:
        return {
            "recovery_evidence_scope": "firestore_point_in_time_recovery",
            "pitr_state": "disabled",
            "pitr_enabled": False,
            "historical_version_retention_state": "native_approximately_one_hour",
            "uncertainties": dedupe(uncertainties),
        }
    if state == STATE_NOT_CONFIGURED:
        return {
            "recovery_evidence_scope": "firestore_point_in_time_recovery",
            "pitr_state": "not_configured",
            "pitr_enabled": False,
            "historical_version_retention_state": "native_approximately_one_hour",
            "uncertainties": dedupe(uncertainties),
        }
    if not uncertainties:
        uncertainties.append(f"{database.address}: Firestore PITR state is unresolved")
    return {
        "recovery_evidence_scope": "firestore_point_in_time_recovery",
        "pitr_state": "unknown",
        "pitr_enabled": None,
        "historical_version_retention_state": "unknown",
        "uncertainties": dedupe(uncertainties),
    }


def _permission_allows(permissions: Sequence[str], operation: str) -> bool:
    operation_key = operation.casefold()
    for permission in permissions:
        normalized = permission.strip().casefold()
        if normalized in {"*", "datastore.*", operation_key}:
            return True
        if operation == _ENTITY_DELETE and normalized == "datastore.entities.*":
            return True
        if operation == _BULK_DELETE and normalized == "datastore.databases.*":
            return True
    return False


def _condition_evidence(value: object) -> GcpFirestoreExactDatabaseConditionEvidence | None:
    if not isinstance(value, Mapping):
        return None
    mapping = cast(Mapping[str, object], value)
    expression = mapping.get("expression")
    if not isinstance(expression, str) or not expression.strip():
        return None
    evidence: GcpFirestoreExactDatabaseConditionEvidence = {"expression": expression}
    for field in ("title", "description"):
        item = mapping.get(field)
        if isinstance(item, str):
            evidence[field] = item
    return evidence


def _firestore_database_resource_name(database: NormalizedResource) -> str | None:
    facts = gcp_facts(database)
    identifier = _known_string(database.identifier)
    if identifier and identifier.startswith("projects/") and "/databases/" in identifier:
        return identifier
    project = _known_string(facts.project)
    name = _known_string(facts.firestore_database_name)
    if project and name and "/" not in name:
        return f"projects/{project}/databases/{name}"
    return None


def _string_values(value: object) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return [item for item in value if isinstance(item, str)]


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None
