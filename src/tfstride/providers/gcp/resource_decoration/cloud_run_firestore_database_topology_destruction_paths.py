from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, cast

from tfstride.models import NormalizedResource
from tfstride.providers.coercion import (
    STATE_DISABLED,
    STATE_ENABLED,
    STATE_NOT_CONFIGURED,
    dedupe,
)
from tfstride.providers.gcp.custom_role_index import GcpCustomRoleIndex, build_gcp_custom_role_index
from tfstride.providers.gcp.iam_reference_utils import (
    normalize_gcp_project,
)
from tfstride.providers.gcp.resource_decoration.iam import iam_bindings
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext
from tfstride.providers.gcp.resource_types import (
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.gcp.resource_utils import (
    GCP_BASIC_IAM_ROLES,
    GCP_ROLE_REFERENCE_SUFFIXES,
    binding_members,
    gcp_reference_key,
)
from tfstride.providers.gcp.structured_data_topology_destruction_evidence import (
    GcpCloudRunFirestoreDatabaseTopologyDestructionPath,
    GcpFirestoreDatabaseDeletionCompatibleConstraintEvidence,
    GcpFirestoreDatabaseDeletionConstraintEvidence,
    GcpFirestoreDatabaseTopologyDestructionRecoveryEvidence,
    GcpFirestoreExactDatabaseConditionEvidence,
    GcpFirestoreTerraformDeletionPolicyEvidence,
    GcpFirestoreTopologyActiveCustomRoleStage,
    GcpFirestoreTopologyCustomRoleEvidence,
    GcpFirestoreTopologyDatabaseBuiltInRoleEvidence,
    GcpFirestoreTopologyDatabaseRoleEvidence,
    GcpFirestoreTopologyProjectBuiltInRoleEvidence,
    GcpFirestoreTopologyProjectRoleEvidence,
)

_DELETE_DATABASE = "datastore.databases.delete"
_SERVICE_ACCOUNT_DOMAIN = ".gserviceaccount.com"
_ACTIVE_CUSTOM_ROLE_STAGES = frozenset({"ALPHA", "BETA", "DEPRECATED", "EAP", "GA"})
_DATABASE_NAME_PATTERN = re.compile(r"^projects/([^/]+)/databases/([^/]+)$")
_RESOURCE_NAME_EQUALS_LITERAL = re.compile(
    r"^\s*\(?\s*resource\.name\s*==\s*(?P<quote>[\"'])(?P<name>[^\"']+)(?P=quote)\s*\)?\s*$"
)
_LITERAL_EQUALS_RESOURCE_NAME = re.compile(
    r"^\s*\(?\s*(?P<quote>[\"'])(?P<name>[^\"']+)(?P=quote)\s*==\s*resource\.name\s*\)?\s*$"
)
_PROJECT_BUILT_IN_ROLES: dict[
    str,
    Literal[
        "owner",
        "datastore_owner",
        "datastore_admin",
        "firebase_admin",
        "firebase_develop_admin",
    ],
] = {
    "roles/owner": "owner",
    "roles/datastore.owner": "datastore_owner",
    "roles/datastore.admin": "datastore_admin",
    "roles/firebase.admin": "firebase_admin",
    "roles/firebase.developAdmin": "firebase_develop_admin",
}
_DATABASE_BUILT_IN_ROLES: dict[
    str,
    Literal[
        "datastore_owner",
        "datastore_admin",
        "firebase_admin",
        "firebase_develop_admin",
    ],
] = {
    "roles/datastore.owner": "datastore_owner",
    "roles/datastore.admin": "datastore_admin",
    "roles/firebase.admin": "firebase_admin",
    "roles/firebase.developAdmin": "firebase_develop_admin",
}
_KNOWN_NON_DELETE_ROLES = frozenset(
    {
        "roles/editor",
        "roles/viewer",
        "roles/datastore.bulkAdmin",
        "roles/datastore.editor",
        "roles/datastore.importExportAdmin",
        "roles/datastore.indexAdmin",
        "roles/datastore.user",
        "roles/datastore.viewer",
        "roles/firebase.editor",
        "roles/firebase.viewer",
        "roles/firebase.developViewer",
        "roles/firebaserules.system",
        "roles/iam.databasesAdmin",
    }
)

_ScopeType = Literal["project", "database"]
_ManagementMode = Literal[
    "authoritative_policy",
    "authoritative_role_binding",
    "additive_member",
]
_RoleEvidence = GcpFirestoreTopologyProjectRoleEvidence | GcpFirestoreTopologyDatabaseRoleEvidence


@dataclass(frozen=True, slots=True)
class _CustomRoleLifecycle:
    resource_address: str
    project: str | None
    organization_id: str | None
    stage: str | None
    deleted: bool | None
    permissions: tuple[str, ...]
    permissions_state: str | None


@dataclass(frozen=True, slots=True)
class _DatabaseTarget:
    resource: NormalizedResource
    name: str
    project: str
    database_type: str
    reference: str


@dataclass(frozen=True, slots=True)
class _IamManager:
    source_address: str
    project: str
    management_mode: _ManagementMode
    roles: tuple[str, ...]


class ModelCloudRunFirestoreDatabaseTopologyDestructionPathsStage:
    """Project deterministic Cloud Run authority to delete exact Firestore databases."""

    name = "model_cloud_run_firestore_database_topology_destruction_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: GcpDecorationContext,
    ) -> None:
        targets, target_uncertainties = _database_targets(resources)
        iam_resources = _iam_resources(resources)
        custom_roles = build_gcp_custom_role_index(resources)
        project_organizations = _project_organizations(resources)

        for workload in resources:
            if workload.resource_type not in GCP_CLOUD_RUN_RESOURCE_TYPES:
                continue
            paths, uncertainties = _cloud_run_firestore_database_topology_destruction_paths(
                workload,
                targets,
                iam_resources,
                context,
                custom_roles,
                project_organizations,
            )
            uncertainties.extend(f"{workload.address}: {message}" for message in target_uncertainties)
            facts = gcp_facts(workload)
            facts.set_cloud_run_firestore_database_topology_destruction_paths(paths)
            facts.extend_cloud_run_firestore_database_topology_destruction_path_uncertainties(dedupe(uncertainties))


def current_cloud_run_firestore_database_topology_destruction_paths(
    workload: NormalizedResource,
    database: NormalizedResource,
    resources: Sequence[NormalizedResource],
    context: GcpDecorationContext,
) -> list[GcpCloudRunFirestoreDatabaseTopologyDestructionPath]:
    """Recompute every current deterministic proof for one workload and database."""

    if (
        workload.resource_type not in GCP_CLOUD_RUN_RESOURCE_TYPES
        or database.resource_type != GcpResourceType.FIRESTORE_DATABASE
    ):
        return []
    target = _database_target(database)
    if target is None:
        return []
    paths, _uncertainties = _cloud_run_firestore_database_topology_destruction_paths(
        workload,
        (target,),
        _iam_resources(resources),
        context,
        build_gcp_custom_role_index(resources),
        _project_organizations(resources),
    )
    return paths


def _cloud_run_firestore_database_topology_destruction_paths(
    workload: NormalizedResource,
    targets: Sequence[_DatabaseTarget],
    iam_resources: Sequence[NormalizedResource],
    context: GcpDecorationContext,
    custom_roles: GcpCustomRoleIndex,
    project_organizations: Mapping[str, str],
) -> tuple[list[GcpCloudRunFirestoreDatabaseTopologyDestructionPath], list[str]]:
    del context
    workload_facts = gcp_facts(workload)
    service_account_email = _known_string(workload_facts.service_account_email)
    service_account_member = _known_string(workload_facts.service_account_member)
    if not _is_exact_service_account_identity(
        service_account_email,
        service_account_member,
    ):
        return [], [
            f"{workload.address}: Cloud Run service account is unresolved for Firestore database-deletion modeling"
        ]
    assert service_account_email is not None
    assert service_account_member is not None

    paths: list[GcpCloudRunFirestoreDatabaseTopologyDestructionPath] = []
    uncertainties: list[str] = []
    seen: set[tuple[str, str, str, str, str, str]] = set()
    for target in targets:
        constraint = _deletion_constraint_evidence(target.resource)
        if constraint["deletion_compatibility_state"] == "blocked":
            continue
        if constraint["deletion_compatibility_state"] == "unknown":
            uncertainties.extend(f"{workload.address}: {uncertainty}" for uncertainty in constraint["uncertainties"])
            continue
        compatible_constraint = cast(
            GcpFirestoreDatabaseDeletionCompatibleConstraintEvidence,
            constraint,
        )

        ambiguous_project, ambiguous_roles, manager_uncertainties = _iam_manager_ambiguities(
            target,
            iam_resources,
            custom_roles,
        )
        uncertainties.extend(
            f"{workload.address}: {message} for {target.resource.address}" for message in manager_uncertainties
        )

        for iam_resource in iam_resources:
            iam_project, scope_uncertainty = _iam_project(iam_resource, target)
            if iam_project is None:
                if scope_uncertainty is not None and _iam_resource_may_affect_member(
                    iam_resource,
                    service_account_member,
                ):
                    uncertainties.append(
                        f"{workload.address}: {iam_resource.address} Firestore IAM project scope is unresolved "
                        f"for {target.resource.address}"
                    )
                continue

            source_facts = gcp_facts(iam_resource)
            if (
                iam_resource.resource_type == GcpResourceType.PROJECT_IAM_POLICY
                and source_facts.iam_policy_data_state != "configured"
            ):
                uncertainties.append(
                    f"{workload.address}: {iam_resource.address} IAM policy_data is "
                    f"{source_facts.iam_policy_data_state or 'unresolved'} for {target.resource.address}"
                )
                continue

            for binding in iam_bindings(iam_resource):
                source = iam_resource.address
                if binding.get("role_state") == "unknown" or binding.get("members_state") == "unknown":
                    uncertainties.append(f"{workload.address}: {source} Firestore IAM role or members are unresolved")
                    continue
                if service_account_member not in binding_members(binding):
                    continue
                role = _known_string(binding.get("role"))
                if role is None:
                    uncertainties.append(f"{workload.address}: {source} Firestore IAM role is unresolved")
                    continue

                scope_type, condition, condition_uncertainty = _binding_scope(
                    binding,
                    target.reference,
                )
                if scope_type == "unrelated":
                    continue
                if scope_type not in {"project", "database"}:
                    uncertainties.append(
                        f"{workload.address}: {source} "
                        f"{condition_uncertainty or 'Firestore IAM condition is unresolved'}"
                    )
                    continue
                if scope_type == "database" and role in GCP_BASIC_IAM_ROLES:
                    uncertainties.append(
                        f"{workload.address}: {source} basic IAM role {role} cannot use conditional database scope"
                    )
                    continue

                role_evidence, role_uncertainty = _role_evidence(
                    role,
                    target.project,
                    scope_type,
                    custom_roles,
                    project_organizations,
                )
                if role_evidence is None:
                    if role_uncertainty is not None:
                        uncertainties.append(f"{workload.address}: {source} {role_uncertainty}")
                    continue

                role_key = _role_reconciliation_key(role, custom_roles)
                if ambiguous_project or role_key in ambiguous_roles:
                    continue
                scope = target.project if scope_type == "project" else target.reference
                fingerprint = (
                    target.resource.address,
                    source,
                    role_key,
                    scope_type,
                    scope,
                    _condition_fingerprint(condition),
                )
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                paths.append(
                    _topology_destruction_path(
                        workload,
                        target,
                        service_account_email,
                        service_account_member,
                        iam_resource,
                        role,
                        role_evidence,
                        scope_type,
                        scope,
                        condition,
                        compatible_constraint,
                    )
                )

    paths.sort(
        key=lambda path: (
            path["firestore_database_address"],
            path["scope_type"],
            path["iam_resource_address"],
            path["role"],
        )
    )
    return paths, dedupe(uncertainties)


def _database_targets(
    resources: Sequence[NormalizedResource],
) -> tuple[list[_DatabaseTarget], list[str]]:
    targets: list[_DatabaseTarget] = []
    uncertainties: list[str] = []
    for resource in resources:
        if resource.resource_type != GcpResourceType.FIRESTORE_DATABASE:
            continue
        target = _database_target(resource)
        if target is None:
            uncertainties.append(f"Firestore database {resource.address} has unresolved exact native identity")
            continue
        targets.append(target)
    return targets, uncertainties


def _database_target(database: NormalizedResource) -> _DatabaseTarget | None:
    facts = gcp_facts(database)
    project = normalize_gcp_project(facts.project)
    raw_name = _known_string(facts.firestore_database_name)
    database_type = _known_string(facts.firestore_database_type)
    if project is None or raw_name is None or database_type is None:
        return None

    name = raw_name
    full_name_match = _DATABASE_NAME_PATTERN.fullmatch(raw_name)
    if full_name_match is not None:
        if full_name_match.group(1) != project:
            return None
        name = full_name_match.group(2)
    if not name or "/" in name or "${" in name or name.startswith("google_"):
        return None

    reference = f"projects/{project}/databases/{name}"
    identifier = _known_string(database.identifier)
    if identifier is not None and identifier not in {database.address, raw_name, name, reference}:
        return None
    if identifier is not None and _DATABASE_NAME_PATTERN.fullmatch(identifier) and identifier != reference:
        return None
    return _DatabaseTarget(database, name, project, database_type, reference)


def _iam_manager_ambiguities(
    target: _DatabaseTarget,
    iam_resources: Sequence[NormalizedResource],
    custom_roles: GcpCustomRoleIndex,
) -> tuple[bool, set[str], list[str]]:
    managers: list[_IamManager] = []
    unresolved_managers: list[_IamManager] = []
    for iam_resource in iam_resources:
        project, scope_uncertainty = _iam_project(iam_resource, target)
        management_mode = _management_mode(iam_resource)
        bindings = iam_bindings(iam_resource)
        roles = _manager_role_keys(bindings, custom_roles)
        if project is None:
            if scope_uncertainty is not None and management_mode != "additive_member":
                unresolved_managers.append(
                    _IamManager(
                        iam_resource.address,
                        target.project,
                        management_mode,
                        roles,
                    )
                )
            continue
        managers.append(
            _IamManager(
                iam_resource.address,
                project,
                management_mode,
                roles,
            )
        )
        if management_mode != "additive_member" and _manager_has_unresolved_role(bindings):
            unresolved_managers.append(
                _IamManager(
                    iam_resource.address,
                    project,
                    management_mode,
                    roles,
                )
            )

    ambiguous_project = False
    ambiguous_roles: set[str] = set()
    uncertainties: list[str] = []
    policy_sources = {
        manager.source_address for manager in managers if manager.management_mode == "authoritative_policy"
    }
    other_sources = {
        manager.source_address for manager in managers if manager.management_mode != "authoritative_policy"
    }
    if len(policy_sources) > 1 or (policy_sources and other_sources):
        ambiguous_project = True
        uncertainties.append(
            f"effective Firestore IAM in project {target.project} is ambiguous because "
            "authoritative policy and other Terraform IAM managers overlap"
        )
    else:
        roles_at_project = sorted({role for manager in managers for role in manager.roles})
        for role in roles_at_project:
            binding_sources = {
                manager.source_address
                for manager in managers
                if manager.management_mode == "authoritative_role_binding" and role in manager.roles
            }
            member_sources = {
                manager.source_address
                for manager in managers
                if manager.management_mode == "additive_member" and role in manager.roles
            }
            if len(binding_sources) > 1 or (binding_sources and member_sources):
                ambiguous_roles.add(role)
                uncertainties.append(
                    f"effective Firestore IAM membership for role {role} in project {target.project} "
                    "is ambiguous because authoritative role bindings overlap with another Terraform IAM manager"
                )

    for manager in unresolved_managers:
        if manager.management_mode == "authoritative_policy" or not manager.roles:
            ambiguous_project = True
            uncertainties.append(
                f"effective Firestore IAM in project {target.project} is unresolved because "
                f"{manager.source_address} may be an overlapping authoritative IAM manager"
            )
            continue
        for role in manager.roles:
            ambiguous_roles.add(role)
            uncertainties.append(
                f"effective Firestore IAM membership for role {role} in project {target.project} is unresolved "
                f"because {manager.source_address} may be an overlapping authoritative IAM manager"
            )
    return ambiguous_project, ambiguous_roles, uncertainties


def _iam_project(
    iam_resource: NormalizedResource,
    target: _DatabaseTarget,
) -> tuple[str | None, str | None]:
    facts = gcp_facts(iam_resource)
    if facts.iam_scope_reference_state in {"unknown", "not_configured"}:
        return None, "scope reference is unresolved"
    project = normalize_gcp_project(facts.project)
    if project is None:
        return None, "project scope is unresolved"
    if project != target.project:
        return None, None
    return project, None


def _binding_scope(
    binding: Mapping[str, Any],
    database_resource_name: str,
) -> tuple[_ScopeType | Literal["unrelated"] | None, GcpFirestoreExactDatabaseConditionEvidence | None, str | None]:
    if binding.get("condition_state") == "unknown":
        return None, None, f"IAM condition applicability to {database_resource_name} is unknown after planning"

    raw_condition = binding.get("condition")
    if not isinstance(raw_condition, Mapping) or not raw_condition:
        if binding.get("condition_state") not in {None, "not_configured"}:
            return None, None, f"IAM condition applicability to {database_resource_name} is unresolved"
        return "project", None, None

    condition = _condition_evidence(raw_condition)
    if condition is None:
        return None, None, f"IAM condition applicability to {database_resource_name} is not deterministic"
    conditioned_resource_name = _exact_condition_resource_name(condition["expression"])
    if conditioned_resource_name is None:
        return None, None, f"IAM condition applicability to {database_resource_name} is not deterministic"
    if conditioned_resource_name == database_resource_name:
        return "database", condition, None
    if _DATABASE_NAME_PATTERN.fullmatch(conditioned_resource_name):
        return "unrelated", condition, None
    return None, None, f"IAM condition applicability to {database_resource_name} is not deterministic"


def _role_evidence(
    role: str,
    target_project: str,
    scope_type: _ScopeType,
    custom_roles: GcpCustomRoleIndex,
    project_organizations: Mapping[str, str],
) -> tuple[_RoleEvidence | None, str | None]:
    if scope_type == "project":
        role_kind = _PROJECT_BUILT_IN_ROLES.get(role)
        if role_kind is not None:
            evidence: GcpFirestoreTopologyProjectBuiltInRoleEvidence = {
                "role_kind": role_kind,
                "role_definition_address": None,
                "custom_role_permissions": [],
                "custom_role_stage": None,
                "custom_role_deleted": None,
                "custom_role_wildcard_permissions_present": False,
                "custom_role_grant_scope_compatibility_state": "not_applicable",
            }
            return evidence, None
    else:
        role_kind = _DATABASE_BUILT_IN_ROLES.get(role)
        if role_kind is not None:
            database_evidence: GcpFirestoreTopologyDatabaseBuiltInRoleEvidence = {
                "role_kind": role_kind,
                "role_definition_address": None,
                "custom_role_permissions": [],
                "custom_role_stage": None,
                "custom_role_deleted": None,
                "custom_role_wildcard_permissions_present": False,
                "custom_role_grant_scope_compatibility_state": "not_applicable",
            }
            return database_evidence, None

    if role in _KNOWN_NON_DELETE_ROLES:
        return None, None
    if role in _PROJECT_BUILT_IN_ROLES:
        return None, f"predefined IAM role {role} is incompatible with exact database condition scope"
    if not _looks_like_custom_role(role):
        return None, f"predefined IAM role {role} Firestore database-deletion coverage is unmodeled"

    resolution = custom_roles.resolve(role)
    if resolution.state == "ambiguous":
        addresses = ", ".join(candidate.address for candidate in resolution.candidates)
        return None, f"custom IAM role {role} is ambiguous across {addresses}"
    role_definition = resolution.selected_candidate
    if role_definition is None:
        return None, f"custom IAM role {role} is unresolved"
    lifecycle = _custom_role_lifecycle(role_definition)
    if lifecycle.deleted is True:
        return None, None
    if lifecycle.deleted is None:
        return None, f"custom IAM role {role} deletion state is unresolved"
    if lifecycle.stage is None:
        return None, f"custom IAM role {role} lifecycle stage is unresolved"
    stage = lifecycle.stage.upper()
    if stage == "DISABLED":
        return None, None
    if stage not in _ACTIVE_CUSTOM_ROLE_STAGES:
        return None, f"custom IAM role {role} lifecycle stage {stage} is unsupported"
    if lifecycle.permissions_state in {None, "unknown"}:
        return None, f"custom IAM role {role} permissions are unresolved"
    wildcard_permissions = tuple(permission for permission in lifecycle.permissions if "*" in permission)
    if wildcard_permissions:
        return None, (
            f"custom IAM role {role} contains unsupported wildcard permission(s): {', '.join(wildcard_permissions)}"
        )
    if _DELETE_DATABASE not in lifecycle.permissions:
        return None, None
    compatibility = _custom_role_grant_scope_compatibility(
        lifecycle,
        target_project,
        project_organizations,
    )
    if compatibility == "incompatible":
        return None, f"custom IAM role {role} is not grantable in target project {target_project}"
    if compatibility == "unknown":
        return None, (
            f"custom IAM role {role} grant scope compatibility is unresolved for target project {target_project}"
        )
    custom_evidence = GcpFirestoreTopologyCustomRoleEvidence(
        role_kind="custom",
        role_definition_address=lifecycle.resource_address,
        custom_role_permissions=list(lifecycle.permissions),
        custom_role_stage=cast(GcpFirestoreTopologyActiveCustomRoleStage, stage),
        custom_role_deleted=False,
        custom_role_wildcard_permissions_present=False,
        custom_role_grant_scope_compatibility_state="compatible",
    )
    return custom_evidence, None


def _topology_destruction_path(
    workload: NormalizedResource,
    target: _DatabaseTarget,
    service_account_email: str,
    service_account_member: str,
    iam_resource: NormalizedResource,
    role: str,
    role_evidence: _RoleEvidence,
    scope_type: _ScopeType,
    scope: str,
    condition: GcpFirestoreExactDatabaseConditionEvidence | None,
    constraint: GcpFirestoreDatabaseDeletionCompatibleConstraintEvidence,
) -> GcpCloudRunFirestoreDatabaseTopologyDestructionPath:
    role_definition_address = role_evidence["role_definition_address"]
    iam_source_addresses = [iam_resource.address]
    if role_definition_address is not None:
        iam_source_addresses.append(role_definition_address)
    recovery_evidence = _recovery_evidence(target.resource)
    terraform_policy = _terraform_deletion_policy_evidence(target.resource)
    common: dict[str, Any] = {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "service_account_email": service_account_email,
        "service_account_member": service_account_member,
        "identity_kind": "cloud_run_service_account",
        "credential_context": "workload_runtime",
        "firestore_database_address": target.resource.address,
        "firestore_database_resource_type": target.resource.resource_type,
        "firestore_database_resource_name": target.reference,
        "firestore_database_name": target.name,
        "firestore_database_project": target.project,
        "firestore_database_type": target.database_type,
        "operation": _DELETE_DATABASE,
        "operation_class": "database_deletion",
        "internal_operation": "delete_database",
        "management_effect": "disruption",
        "target_granularity": "database_topology",
        "target_scope": "exact_firestore_database",
        "target_model_evidence_addresses": [target.resource.address],
        "iam_resource_address": iam_resource.address,
        "iam_resource_type": iam_resource.resource_type,
        "iam_source_addresses": iam_source_addresses,
        "role": role,
        "matched_permissions": [_DELETE_DATABASE],
        "authorization_state": "granted",
        "policy_complete": True,
        "iam_manager_ambiguity_state": "not_detected",
        "authorization_model": "iam_authorized_server_api",
        "firestore_security_rules_evaluated": False,
        "firestore_security_rules_applicability": "not_in_server_api_authorization_path",
        "lifecycle_compatibility_state": "compatible",
        "deletion_constraint_evidence": constraint,
        "terraform_deletion_policy_evidence": terraform_policy,
        "recovery_evidence": recovery_evidence,
        "scope_type": scope_type,
        "scope": scope,
        "resource_scope": "firestore_project" if scope_type == "project" else "exact_firestore_database",
        "grant_basis": (
            "firestore_project_iam" if scope_type == "project" else "firestore_project_iam_exact_database_condition"
        ),
        "condition": condition,
        "condition_state": "not_configured" if scope_type == "project" else "configured",
        "condition_evaluation": ("not_configured" if scope_type == "project" else "exact_database_scope_match"),
        "role_evidence": role_evidence,
    }
    common["posture_uncertainties"] = dedupe(
        [
            *constraint["uncertainties"],
            *terraform_policy["uncertainties"],
            *recovery_evidence["uncertainties"],
        ]
    )
    return cast(GcpCloudRunFirestoreDatabaseTopologyDestructionPath, common)


def _deletion_constraint_evidence(
    database: NormalizedResource,
) -> GcpFirestoreDatabaseDeletionConstraintEvidence:
    facts = gcp_facts(database)
    state = facts.firestore_delete_protection_state
    enablement = facts.firestore_delete_protection_enablement
    uncertainties = [
        uncertainty
        for uncertainty in facts.firestore_posture_uncertainties
        if uncertainty.startswith("delete_protection_state")
    ]
    if enablement == STATE_ENABLED and state == "DELETE_PROTECTION_ENABLED":
        return {
            "constraint_evidence_scope": "firestore_database_delete_protection",
            "delete_protection_state": "DELETE_PROTECTION_ENABLED",
            "delete_protection_enablement": "enabled",
            "delete_protection_enabled": True,
            "provider_default_applied": False,
            "deletion_compatibility_state": "blocked",
            "uncertainties": [],
        }
    if enablement == STATE_DISABLED and state == "DELETE_PROTECTION_DISABLED":
        return {
            "constraint_evidence_scope": "firestore_database_delete_protection",
            "delete_protection_state": "DELETE_PROTECTION_DISABLED",
            "delete_protection_enablement": "disabled",
            "delete_protection_enabled": False,
            "provider_default_applied": False,
            "deletion_compatibility_state": "compatible",
            "uncertainties": [],
        }
    if enablement == STATE_NOT_CONFIGURED and state in {None, "DELETE_PROTECTION_STATE_UNSPECIFIED"}:
        default_state = cast(Literal["DELETE_PROTECTION_STATE_UNSPECIFIED"] | None, state)
        return {
            "constraint_evidence_scope": "firestore_database_delete_protection",
            "delete_protection_state": default_state,
            "delete_protection_enablement": "not_configured",
            "delete_protection_enabled": False,
            "provider_default_applied": True,
            "deletion_compatibility_state": "compatible",
            "uncertainties": [],
        }
    if not uncertainties:
        uncertainties.append(f"{database.address}: Firestore delete-protection state is unresolved")
    return {
        "constraint_evidence_scope": "firestore_database_delete_protection",
        "delete_protection_state": state,
        "delete_protection_enablement": "unknown",
        "delete_protection_enabled": None,
        "provider_default_applied": False,
        "deletion_compatibility_state": "unknown",
        "uncertainties": dedupe(uncertainties),
    }


def _terraform_deletion_policy_evidence(
    database: NormalizedResource,
) -> GcpFirestoreTerraformDeletionPolicyEvidence:
    facts = gcp_facts(database)
    state = facts.firestore_terraform_deletion_policy_state
    policy = facts.firestore_terraform_deletion_policy
    uncertainties = [
        uncertainty
        for uncertainty in facts.firestore_posture_uncertainties
        if uncertainty.startswith("deletion_policy")
    ]
    if state == "configured" and policy in {"ABANDON", "DELETE"}:
        configured_policy = cast(Literal["ABANDON", "DELETE"], policy)
        return {
            "evidence_scope": "terraform_firestore_database_deletion_policy",
            "runtime_api_authorization_effect": "none",
            "policy_state": "configured",
            "policy": configured_policy,
            "uncertainties": [],
        }
    if state == "not_configured" and policy is None:
        return {
            "evidence_scope": "terraform_firestore_database_deletion_policy",
            "runtime_api_authorization_effect": "none",
            "policy_state": "not_configured",
            "policy": None,
            "uncertainties": [],
        }
    if not uncertainties:
        uncertainties.append(f"{database.address}: Terraform deletion policy is unresolved")
    return {
        "evidence_scope": "terraform_firestore_database_deletion_policy",
        "runtime_api_authorization_effect": "none",
        "policy_state": "unknown",
        "policy": policy,
        "uncertainties": dedupe(uncertainties),
    }


def _recovery_evidence(
    database: NormalizedResource,
) -> GcpFirestoreDatabaseTopologyDestructionRecoveryEvidence:
    facts = gcp_facts(database)
    state = facts.firestore_pitr_state
    uncertainties = [
        uncertainty
        for uncertainty in facts.firestore_posture_uncertainties
        if uncertainty.startswith("point_in_time_recovery_enablement")
    ]
    uncertainties.extend(
        (
            f"{database.address}: App Engine Search and Blob entity deletion prerequisites are not established",
            f"{database.address}: Eventarc trigger impact is not evaluated",
            f"{database.address}: out-of-plan Firestore topology is not evaluated",
        )
    )
    common: dict[str, Any] = {
        "recovery_evidence_scope": "firestore_database_deletion_and_point_in_time_recovery",
        "successful_deletion_observed": False,
        "restoration_observed": False,
        "database_content_prerequisites_evaluated": False,
        "app_engine_search_and_blob_entity_prerequisite_state": "not_established",
        "eventarc_trigger_impact_evaluated": False,
        "out_of_plan_topology_evaluated": False,
    }
    if state == STATE_ENABLED:
        common.update(
            {
                "pitr_state": "enabled",
                "pitr_enabled": True,
                "historical_version_retention_state": "pitr_up_to_seven_days",
                "database_recovery_state": "not_established_by_modeled_firestore_pitr_evidence",
            }
        )
    elif state == STATE_DISABLED:
        common.update(
            {
                "pitr_state": "disabled",
                "pitr_enabled": False,
                "historical_version_retention_state": "native_approximately_one_hour",
                "database_recovery_state": "not_established_by_modeled_firestore_pitr_evidence",
            }
        )
    elif state == STATE_NOT_CONFIGURED:
        common.update(
            {
                "pitr_state": "not_configured",
                "pitr_enabled": False,
                "historical_version_retention_state": "native_approximately_one_hour",
                "database_recovery_state": "not_established_by_modeled_firestore_pitr_evidence",
            }
        )
    else:
        if not any("point_in_time_recovery_enablement" in uncertainty for uncertainty in uncertainties):
            uncertainties.append(f"{database.address}: Firestore PITR state is unresolved")
        common.update(
            {
                "pitr_state": "unknown",
                "pitr_enabled": None,
                "historical_version_retention_state": "unknown",
                "database_recovery_state": "unknown",
            }
        )
    common["uncertainties"] = dedupe(uncertainties)
    return cast(GcpFirestoreDatabaseTopologyDestructionRecoveryEvidence, common)


def _custom_role_lifecycle(resource: NormalizedResource) -> _CustomRoleLifecycle:
    facts = gcp_facts(resource)
    return _CustomRoleLifecycle(
        resource.address,
        normalize_gcp_project(facts.project),
        _normalize_organization(facts.organization_id),
        facts.custom_role_stage,
        facts.custom_role_deleted,
        tuple(sorted(set(facts.custom_role_permissions))),
        facts.custom_role_permissions_state,
    )


def _project_organizations(
    resources: Sequence[NormalizedResource],
) -> Mapping[str, str]:
    organizations: dict[str, str] = {}
    for resource in resources:
        if resource.resource_type != GcpResourceType.PROJECT:
            continue
        facts = gcp_facts(resource)
        project = normalize_gcp_project(facts.project)
        organization = _normalize_organization(facts.organization_id)
        if project is not None and organization is not None:
            organizations.setdefault(project, organization)
    return organizations


def _custom_role_grant_scope_compatibility(
    lifecycle: _CustomRoleLifecycle,
    target_project: str,
    project_organizations: Mapping[str, str],
) -> Literal["compatible", "incompatible", "unknown"]:
    if lifecycle.project is not None:
        return "compatible" if lifecycle.project == target_project else "incompatible"
    if lifecycle.organization_id is None:
        return "unknown"
    target_organization = project_organizations.get(target_project)
    if target_organization is None:
        return "unknown"
    return "compatible" if target_organization == lifecycle.organization_id else "incompatible"


def _role_reconciliation_key(
    role: str,
    custom_roles: GcpCustomRoleIndex,
) -> str:
    normalized = gcp_reference_key(role, GCP_ROLE_REFERENCE_SUFFIXES)
    resolution = custom_roles.resolve(role)
    role_definition = resolution.selected_candidate
    if role_definition is not None:
        return f"custom:{role_definition.address}"
    if resolution.state == "ambiguous":
        return f"ambiguous-custom:{normalized}"
    return f"role:{normalized}"


def _manager_role_keys(
    bindings: Sequence[Mapping[str, Any]],
    custom_roles: GcpCustomRoleIndex,
) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                _role_reconciliation_key(role, custom_roles)
                for binding in bindings
                if binding.get("role_state") != "unknown" and (role := _known_string(binding.get("role"))) is not None
            }
        )
    )


def _manager_has_unresolved_role(bindings: Sequence[Mapping[str, Any]]) -> bool:
    return any(
        binding.get("role_state") == "unknown" or _known_string(binding.get("role")) is None for binding in bindings
    )


def _iam_resource_may_affect_member(
    resource: NormalizedResource,
    member: str,
) -> bool:
    if _management_mode(resource) != "additive_member":
        return True
    return any(
        binding.get("members_state") == "unknown" or member in binding_members(binding)
        for binding in iam_bindings(resource)
    )


def _management_mode(resource: NormalizedResource) -> _ManagementMode:
    if resource.resource_type == GcpResourceType.PROJECT_IAM_POLICY:
        return "authoritative_policy"
    if resource.resource_type == GcpResourceType.PROJECT_IAM_BINDING:
        return "authoritative_role_binding"
    return "additive_member"


def _iam_resources(
    resources: Sequence[NormalizedResource],
) -> tuple[NormalizedResource, ...]:
    return tuple(resource for resource in resources if resource.resource_type in GCP_PROJECT_IAM_RESOURCE_TYPES)


def _condition_evidence(
    value: object,
) -> GcpFirestoreExactDatabaseConditionEvidence | None:
    if not isinstance(value, Mapping):
        return None
    mapping = cast(Mapping[str, object], value)
    expression = _known_string(mapping.get("expression"))
    if expression is None:
        return None
    evidence: GcpFirestoreExactDatabaseConditionEvidence = {"expression": expression}
    for field in ("title", "description"):
        item = _known_string(mapping.get(field))
        if item is not None:
            evidence[field] = item
    return evidence


def _exact_condition_resource_name(expression: str) -> str | None:
    for pattern in (_RESOURCE_NAME_EQUALS_LITERAL, _LITERAL_EQUALS_RESOURCE_NAME):
        match = pattern.fullmatch(expression)
        if match:
            return match.group("name")
    return None


def _condition_fingerprint(
    condition: GcpFirestoreExactDatabaseConditionEvidence | None,
) -> str:
    if condition is None:
        return ""
    return "\x1f".join(
        (
            condition["expression"],
            condition.get("title", ""),
            condition.get("description", ""),
        )
    )


def _is_exact_service_account_identity(
    email: str | None,
    member: str | None,
) -> bool:
    return bool(
        email
        and member == f"serviceAccount:{email}"
        and "@" in email
        and email.endswith(_SERVICE_ACCOUNT_DOMAIN)
        and "${" not in email
        and not ("google_" in email and "." in email)
    )


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _normalize_organization(value: object) -> str | None:
    text = _known_string(value)
    if text is None:
        return None
    if text.startswith("organizations/"):
        return text.removeprefix("organizations/") or None
    return text


def _looks_like_custom_role(role: str) -> bool:
    return role.startswith(("projects/", "organizations/")) or "iam_custom_role." in role
