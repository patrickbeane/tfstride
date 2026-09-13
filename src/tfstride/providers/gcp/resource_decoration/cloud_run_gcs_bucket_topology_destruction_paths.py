from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, cast

from tfstride.models import NormalizedResource
from tfstride.providers.coercion import dedupe
from tfstride.providers.gcp.iam_reference_utils import (
    custom_role_reference_keys,
    gcs_bucket_scope_name,
    gcs_bucket_target_matches,
    normalize_gcp_project,
)
from tfstride.providers.gcp.object_storage_topology_destruction_evidence import (
    GcpCloudRunGcsBucketTopologyDestructionPath,
    GcpGcsBucketTopologyActiveCustomRoleStage,
    GcpGcsBucketTopologyBucketBuiltInRoleEvidence,
    GcpGcsBucketTopologyBucketRoleEvidence,
    GcpGcsBucketTopologyCustomRoleEvidence,
    GcpGcsBucketTopologyDestructionRecoveryEvidence,
    GcpGcsBucketTopologyProjectBuiltInRoleEvidence,
    GcpGcsBucketTopologyProjectRoleEvidence,
)
from tfstride.providers.gcp.resource_decoration.iam import iam_bindings
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext
from tfstride.providers.gcp.resource_types import (
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.gcp.resource_utils import (
    GCP_ROLE_REFERENCE_SUFFIXES,
    binding_members,
    gcp_reference_key,
)

_DELETE_BUCKET = "storage.buckets.delete"
_SERVICE_ACCOUNT_DOMAIN = ".gserviceaccount.com"
_ACTIVE_CUSTOM_ROLE_STAGES = frozenset({"ALPHA", "BETA", "DEPRECATED", "EAP", "GA"})
_PROJECT_BUILT_IN_ROLES: dict[
    str,
    Literal["owner", "editor", "storage_admin", "storage_editor"],
] = {
    "roles/owner": "owner",
    "roles/editor": "editor",
    "roles/storage.admin": "storage_admin",
    "roles/storage.editor": "storage_editor",
}
_BUCKET_BUILT_IN_ROLES: dict[
    str,
    Literal["storage_admin", "storage_editor"],
] = {
    "roles/storage.admin": "storage_admin",
    "roles/storage.editor": "storage_editor",
}
_KNOWN_NON_DELETE_ROLES = frozenset(
    {
        "roles/viewer",
        "roles/storage.bucketViewer",
        "roles/storage.legacyBucketOwner",
        "roles/storage.legacyBucketReader",
        "roles/storage.legacyBucketWriter",
        "roles/storage.objectAdmin",
        "roles/storage.objectCreator",
        "roles/storage.objectUser",
        "roles/storage.objectViewer",
    }
)

_ScopeType = Literal["project", "bucket"]
_ManagementMode = Literal[
    "authoritative_policy",
    "authoritative_role_binding",
    "additive_member",
]
_RoleEvidence = GcpGcsBucketTopologyProjectRoleEvidence | GcpGcsBucketTopologyBucketRoleEvidence


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
class _BucketTarget:
    resource: NormalizedResource
    name: str
    project: str
    reference: str


@dataclass(frozen=True, slots=True)
class _IamManager:
    source_address: str
    scope_type: _ScopeType
    scope: str
    management_mode: _ManagementMode
    roles: tuple[str, ...]


class ModelCloudRunGcsBucketTopologyDestructionPathsStage:
    """Project deterministic Cloud Run authority to delete exact GCS buckets."""

    name = "model_cloud_run_gcs_bucket_topology_destruction_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: GcpDecorationContext,
    ) -> None:
        targets, target_uncertainties = _bucket_targets(resources)
        iam_resources = _iam_resources(resources)
        custom_roles = _custom_role_lifecycles_by_reference(resources)
        project_organizations = _project_organizations(resources)

        for workload in resources:
            if workload.resource_type not in GCP_CLOUD_RUN_RESOURCE_TYPES:
                continue
            paths, uncertainties = _cloud_run_gcs_bucket_topology_destruction_paths(
                workload,
                targets,
                iam_resources,
                context,
                custom_roles,
                project_organizations,
            )
            uncertainties.extend(f"{workload.address}: {message}" for message in target_uncertainties)
            facts = gcp_facts(workload)
            facts.set_cloud_run_gcs_bucket_topology_destruction_paths(paths)
            facts.extend_cloud_run_gcs_bucket_topology_destruction_path_uncertainties(dedupe(uncertainties))


def current_cloud_run_gcs_bucket_topology_destruction_paths(
    workload: NormalizedResource,
    bucket: NormalizedResource,
    resources: Sequence[NormalizedResource],
    context: GcpDecorationContext,
) -> list[GcpCloudRunGcsBucketTopologyDestructionPath]:
    """Recompute every current deterministic proof for one workload and bucket."""

    if (
        workload.resource_type not in GCP_CLOUD_RUN_RESOURCE_TYPES
        or bucket.resource_type != GcpResourceType.STORAGE_BUCKET
    ):
        return []
    target = _bucket_target(bucket)
    if target is None:
        return []
    paths, _uncertainties = _cloud_run_gcs_bucket_topology_destruction_paths(
        workload,
        (target,),
        _iam_resources(resources),
        context,
        _custom_role_lifecycles_by_reference(resources),
        _project_organizations(resources),
    )
    return paths


def _cloud_run_gcs_bucket_topology_destruction_paths(
    workload: NormalizedResource,
    targets: Sequence[_BucketTarget],
    iam_resources: Sequence[NormalizedResource],
    context: GcpDecorationContext,
    custom_roles: Mapping[str, _CustomRoleLifecycle],
    project_organizations: Mapping[str, str],
) -> tuple[list[GcpCloudRunGcsBucketTopologyDestructionPath], list[str]]:
    workload_facts = gcp_facts(workload)
    service_account_email = _known_string(workload_facts.service_account_email)
    service_account_member = _known_string(workload_facts.service_account_member)
    if not _is_exact_service_account_identity(
        service_account_email,
        service_account_member,
    ):
        return [], [f"{workload.address}: Cloud Run service account is unresolved for GCS bucket-deletion modeling"]
    assert service_account_email is not None
    assert service_account_member is not None

    paths: list[GcpCloudRunGcsBucketTopologyDestructionPath] = []
    uncertainties: list[str] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for target in targets:
        ambiguous_scopes, ambiguous_roles, manager_uncertainties = _iam_manager_ambiguities(
            target,
            iam_resources,
            context,
            custom_roles,
        )
        uncertainties.extend(
            f"{workload.address}: {message} for {target.resource.address}" for message in manager_uncertainties
        )

        for iam_resource in iam_resources:
            scope_type, scope, scope_uncertainty = _iam_scope(
                iam_resource,
                target,
                context,
            )
            if scope_type is None or scope is None:
                if scope_uncertainty is not None and _iam_resource_may_affect_member(
                    iam_resource,
                    service_account_member,
                ):
                    uncertainties.append(
                        f"{workload.address}: {iam_resource.address} GCS IAM scope is unresolved "
                        f"for {target.resource.address}"
                    )
                continue

            source_facts = gcp_facts(iam_resource)
            if (
                iam_resource.resource_type.endswith("_iam_policy")
                and source_facts.iam_policy_data_state != "configured"
            ):
                uncertainties.append(
                    f"{workload.address}: {iam_resource.address} IAM policy_data is "
                    f"{source_facts.iam_policy_data_state or 'unresolved'} for {target.resource.address}"
                )
                continue

            for binding in iam_bindings(iam_resource):
                source = _known_string(binding.get("source")) or iam_resource.address
                if binding.get("role_state") == "unknown" or binding.get("members_state") == "unknown":
                    uncertainties.append(f"{workload.address}: {source} GCS IAM role or members are unresolved")
                    continue
                if service_account_member not in binding_members(binding):
                    continue
                role = _known_string(binding.get("role"))
                if role is None:
                    uncertainties.append(f"{workload.address}: {source} GCS IAM role is unresolved")
                    continue
                condition = _condition(binding.get("condition"))
                condition_state = _known_string(binding.get("condition_state"))
                if condition is not None or condition_state not in {None, "not_configured"}:
                    uncertainties.append(
                        f"{workload.address}: {source} GCS bucket-deletion condition is not deterministic"
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
                if (scope_type, scope) in ambiguous_scopes or (
                    scope_type,
                    scope,
                    role_key,
                ) in ambiguous_roles:
                    continue
                fingerprint = (
                    target.resource.address,
                    source,
                    role_key,
                    scope_type,
                    scope,
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
                        source,
                        role,
                        role_evidence,
                        scope_type,
                        scope,
                    )
                )

    paths.sort(
        key=lambda path: (
            path["bucket_address"],
            path["scope_type"],
            path["iam_resource_address"],
            path["role"],
        )
    )
    return paths, dedupe(uncertainties)


def _bucket_targets(
    resources: Sequence[NormalizedResource],
) -> tuple[list[_BucketTarget], list[str]]:
    targets: list[_BucketTarget] = []
    uncertainties: list[str] = []
    for resource in resources:
        if resource.resource_type != GcpResourceType.STORAGE_BUCKET:
            continue
        target = _bucket_target(resource)
        if target is None:
            uncertainties.append(f"GCS bucket {resource.address} has unresolved exact native identity")
            continue
        targets.append(target)
    return targets, uncertainties


def _bucket_target(bucket: NormalizedResource) -> _BucketTarget | None:
    facts = gcp_facts(bucket)
    name = _known_string(facts.bucket_name)
    project = normalize_gcp_project(facts.project)
    if name is None or project is None or "/" in name or "${" in name or name.startswith("google_"):
        return None
    reference = _bucket_scope(name)
    identifier = _known_string(bucket.identifier)
    if identifier is not None and identifier.startswith("projects/_/buckets/") and identifier != reference:
        return None
    return _BucketTarget(bucket, name, project, reference)


def _iam_manager_ambiguities(
    target: _BucketTarget,
    iam_resources: Sequence[NormalizedResource],
    context: GcpDecorationContext,
    custom_roles: Mapping[str, _CustomRoleLifecycle],
) -> tuple[
    set[tuple[_ScopeType, str]],
    set[tuple[_ScopeType, str, str]],
    list[str],
]:
    managers: list[_IamManager] = []
    unresolved_managers: list[_IamManager] = []
    for iam_resource in iam_resources:
        scope_type, scope, scope_uncertainty = _iam_scope(
            iam_resource,
            target,
            context,
        )
        management_mode = _management_mode(iam_resource)
        bindings = iam_bindings(iam_resource)
        roles = _manager_role_keys(bindings, custom_roles)
        if scope_type is None or scope is None:
            potential_scope = _potential_unresolved_manager_scope(
                iam_resource,
                target,
                scope_uncertainty,
            )
            if potential_scope is not None and management_mode != "additive_member":
                unresolved_managers.append(
                    _IamManager(
                        iam_resource.address,
                        potential_scope[0],
                        potential_scope[1],
                        management_mode,
                        roles,
                    )
                )
            continue
        managers.append(
            _IamManager(
                iam_resource.address,
                scope_type,
                scope,
                management_mode,
                roles,
            )
        )
        if management_mode != "additive_member" and _manager_has_unresolved_role(bindings):
            unresolved_managers.append(
                _IamManager(
                    iam_resource.address,
                    scope_type,
                    scope,
                    management_mode,
                    roles,
                )
            )

    ambiguous_scopes: set[tuple[_ScopeType, str]] = set()
    ambiguous_roles: set[tuple[_ScopeType, str, str]] = set()
    uncertainties: list[str] = []
    scope_keys: set[tuple[_ScopeType, str]] = {(manager.scope_type, manager.scope) for manager in managers}
    for scope_type, scope in sorted(scope_keys):
        scoped = [manager for manager in managers if manager.scope_type == scope_type and manager.scope == scope]
        policy_sources = {
            manager.source_address for manager in scoped if manager.management_mode == "authoritative_policy"
        }
        other_sources = {
            manager.source_address for manager in scoped if manager.management_mode != "authoritative_policy"
        }
        if len(policy_sources) > 1 or (policy_sources and other_sources):
            ambiguous_scopes.add((scope_type, scope))
            uncertainties.append(
                f"effective GCS IAM at {scope_type} scope {scope} is ambiguous because "
                "authoritative policy and other Terraform IAM managers overlap"
            )
            continue

        roles_at_scope = sorted({role for manager in scoped for role in manager.roles})
        for role in roles_at_scope:
            binding_sources = {
                manager.source_address
                for manager in scoped
                if manager.management_mode == "authoritative_role_binding" and role in manager.roles
            }
            member_sources = {
                manager.source_address
                for manager in scoped
                if manager.management_mode == "additive_member" and role in manager.roles
            }
            if len(binding_sources) > 1 or (binding_sources and member_sources):
                ambiguous_roles.add((scope_type, scope, role))
                uncertainties.append(
                    f"effective GCS IAM membership for role {role} at {scope_type} scope {scope} "
                    "is ambiguous because authoritative role bindings overlap with another Terraform IAM manager"
                )

    for manager in unresolved_managers:
        if manager.management_mode == "authoritative_policy" or not manager.roles:
            ambiguous_scopes.add((manager.scope_type, manager.scope))
            uncertainties.append(
                f"effective GCS IAM at {manager.scope_type} scope {manager.scope} is unresolved "
                f"because {manager.source_address} may be an overlapping authoritative IAM manager"
            )
            continue
        for role in manager.roles:
            ambiguous_roles.add((manager.scope_type, manager.scope, role))
            uncertainties.append(
                f"effective GCS IAM membership for role {role} at {manager.scope_type} scope "
                f"{manager.scope} is unresolved because {manager.source_address} may be an overlapping "
                "authoritative IAM manager"
            )
    return ambiguous_scopes, ambiguous_roles, uncertainties


def _iam_scope(
    iam_resource: NormalizedResource,
    target: _BucketTarget,
    context: GcpDecorationContext,
) -> tuple[_ScopeType | None, str | None, str | None]:
    facts = gcp_facts(iam_resource)
    if facts.iam_scope_reference_state in {"unknown", "not_configured"}:
        return None, None, "scope reference is unresolved"
    if iam_resource.resource_type in GCP_PROJECT_IAM_RESOURCE_TYPES:
        project = normalize_gcp_project(facts.project)
        if project is None:
            return None, None, "project scope is unresolved"
        if project != target.project:
            return None, None, None
        return "project", project, None

    if iam_resource.resource_type not in GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES:
        return None, None, None
    target_reference = _known_string(facts.target_reference)
    if target_reference is None:
        return None, None, "bucket target is unresolved"
    reference = _unwrap_reference(target_reference)
    if gcs_bucket_target_matches(reference, target.resource.address, target.name):
        return "bucket", target.reference, None

    resolved = context.index.resources_by_reference.get(
        reference,
        source=iam_resource,
        resource_types={GcpResourceType.STORAGE_BUCKET},
    )
    if resolved is not None:
        if resolved.address != target.resource.address:
            return None, None, None
        return None, None, "bucket target uses an unsupported symbolic attribute"
    exact_name = gcs_bucket_scope_name(reference)
    if exact_name is not None:
        if exact_name == target.name:
            return "bucket", target.reference, None
        return None, None, None
    if reference.startswith("google_storage_bucket."):
        return None, None, "bucket target is unresolved"
    if "${" not in reference and "/" not in reference:
        return None, None, None
    return None, None, "bucket target is unresolved"


def _potential_unresolved_manager_scope(
    iam_resource: NormalizedResource,
    target: _BucketTarget,
    scope_uncertainty: str | None,
) -> tuple[_ScopeType, str] | None:
    if scope_uncertainty is None:
        return None
    if iam_resource.resource_type in GCP_PROJECT_IAM_RESOURCE_TYPES:
        return "project", target.project
    if iam_resource.resource_type in GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES:
        return "bucket", target.reference
    return None


def _role_evidence(
    role: str,
    target_project: str,
    scope_type: _ScopeType,
    custom_roles: Mapping[str, _CustomRoleLifecycle],
    project_organizations: Mapping[str, str],
) -> tuple[_RoleEvidence | None, str | None]:
    if scope_type == "project":
        role_kind = _PROJECT_BUILT_IN_ROLES.get(role)
        if role_kind is not None:
            evidence: GcpGcsBucketTopologyProjectBuiltInRoleEvidence = {
                "role_kind": role_kind,
                "role_definition_address": None,
                "custom_role_permissions": [],
                "custom_role_stage": None,
                "custom_role_deleted": None,
                "custom_role_grant_scope_compatibility_state": "not_applicable",
            }
            return evidence, None
    else:
        role_kind = _BUCKET_BUILT_IN_ROLES.get(role)
        if role_kind is not None:
            bucket_evidence: GcpGcsBucketTopologyBucketBuiltInRoleEvidence = {
                "role_kind": role_kind,
                "role_definition_address": None,
                "custom_role_permissions": [],
                "custom_role_stage": None,
                "custom_role_deleted": None,
                "custom_role_grant_scope_compatibility_state": "not_applicable",
            }
            return bucket_evidence, None

    if role in _KNOWN_NON_DELETE_ROLES:
        return None, None
    if role in _PROJECT_BUILT_IN_ROLES:
        return None, f"predefined IAM role {role} is incompatible with bucket scope"
    if not _looks_like_custom_role(role):
        return None, f"predefined IAM role {role} bucket-deletion coverage is unmodeled"

    lifecycle = custom_roles.get(gcp_reference_key(role, GCP_ROLE_REFERENCE_SUFFIXES))
    if lifecycle is None:
        return None, f"custom IAM role {role} is unresolved"
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
    if _DELETE_BUCKET not in lifecycle.permissions:
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
    custom_evidence = GcpGcsBucketTopologyCustomRoleEvidence(
        role_kind="custom",
        role_definition_address=lifecycle.resource_address,
        custom_role_permissions=list(lifecycle.permissions),
        custom_role_stage=cast(GcpGcsBucketTopologyActiveCustomRoleStage, stage),
        custom_role_deleted=False,
        custom_role_grant_scope_compatibility_state="compatible",
    )
    return custom_evidence, None


def _topology_destruction_path(
    workload: NormalizedResource,
    target: _BucketTarget,
    service_account_email: str,
    service_account_member: str,
    iam_resource: NormalizedResource,
    source: str,
    role: str,
    role_evidence: _RoleEvidence,
    scope_type: _ScopeType,
    scope: str,
) -> GcpCloudRunGcsBucketTopologyDestructionPath:
    role_definition_address = role_evidence["role_definition_address"]
    iam_source_addresses = [source]
    if role_definition_address is not None:
        iam_source_addresses.append(role_definition_address)
    common: dict[str, Any] = {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "service_account_email": service_account_email,
        "service_account_member": service_account_member,
        "identity_kind": "cloud_run_service_account",
        "credential_context": "workload_runtime",
        "bucket_address": target.resource.address,
        "bucket_resource_type": target.resource.resource_type,
        "bucket_name": target.name,
        "bucket_project": target.project,
        "bucket_reference": target.reference,
        "operation": _DELETE_BUCKET,
        "operation_class": "bucket_deletion",
        "internal_operation": "delete_bucket",
        "management_effect": "disruption",
        "target_granularity": "bucket_topology",
        "target_scope": "exact_gcs_bucket",
        "target_model_evidence_addresses": [target.resource.address],
        "iam_resource_address": iam_resource.address,
        "iam_resource_type": iam_resource.resource_type,
        "iam_source_addresses": iam_source_addresses,
        "role": role,
        "matched_permissions": [_DELETE_BUCKET],
        "authorization_state": "granted",
        "policy_complete": True,
        "iam_manager_ambiguity_state": "not_detected",
        "condition": None,
        "condition_state": "not_configured",
        "lifecycle_compatibility_state": "bucket_emptiness_not_established",
        "recovery_evidence": _recovery_evidence(target.resource),
        "scope_type": scope_type,
        "scope": scope,
        "resource_scope": "gcs_project" if scope_type == "project" else "exact_gcs_bucket",
        "grant_basis": "gcs_project_iam" if scope_type == "project" else "gcs_bucket_iam",
        "role_evidence": role_evidence,
    }
    common["posture_uncertainties"] = list(common["recovery_evidence"]["uncertainties"])
    return cast(GcpCloudRunGcsBucketTopologyDestructionPath, common)


def _recovery_evidence(
    bucket: NormalizedResource,
) -> GcpGcsBucketTopologyDestructionRecoveryEvidence:
    facts = gcp_facts(bucket)
    uncertainties = [
        *facts.gcs_versioning_uncertainties,
        *facts.gcs_soft_delete_policy_uncertainties,
        *facts.gcs_retention_policy_uncertainties,
        f"{bucket.address}: bucket emptiness is required for deletion and is not established by plan evidence",
        f"{bucket.address}: out-of-plan object inventory is not evaluated",
    ]
    common: dict[str, Any] = {
        "recovery_evidence_scope": "gcs_bucket_soft_delete_and_empty_bucket_prerequisite",
        "bucket_emptiness_required": True,
        "bucket_emptiness_state": "not_established",
        "versioning_enabled": facts.versioning_enabled,
        "retention_period_seconds": facts.gcs_retention_period_seconds,
        "retention_policy_locked": facts.gcs_retention_policy_locked,
        "out_of_plan_object_inventory_evaluated": False,
        "successful_deletion_observed": False,
        "restoration_observed": False,
    }
    soft_delete_state = facts.gcs_soft_delete_state
    duration = facts.gcs_soft_delete_retention_duration_seconds
    if soft_delete_state == "enabled" and isinstance(duration, int) and duration > 0:
        common.update(
            {
                "soft_delete_state": "enabled",
                "soft_delete_retention_duration_seconds": duration,
                "bucket_recovery_state": "soft_delete_recovery_configured",
            }
        )
    elif soft_delete_state == "disabled" and duration == 0:
        common.update(
            {
                "soft_delete_state": "disabled",
                "soft_delete_retention_duration_seconds": 0,
                "bucket_recovery_state": "not_established_by_modeled_gcp_gcs_bucket_evidence",
            }
        )
    elif soft_delete_state == "not_observed":
        uncertainties.append(
            f"{bucket.address}: soft-delete policy is not observed; the platform default is not inferred"
        )
        common.update(
            {
                "soft_delete_state": "not_observed",
                "soft_delete_retention_duration_seconds": None,
                "bucket_recovery_state": "unknown",
            }
        )
    else:
        if not facts.gcs_soft_delete_policy_uncertainties:
            uncertainties.append(f"{bucket.address}: soft-delete recovery posture is unresolved")
        common.update(
            {
                "soft_delete_state": "unknown",
                "soft_delete_retention_duration_seconds": None,
                "bucket_recovery_state": "unknown",
            }
        )
    common["uncertainties"] = dedupe(uncertainties)
    return cast(GcpGcsBucketTopologyDestructionRecoveryEvidence, common)


def _custom_role_lifecycles_by_reference(
    resources: Sequence[NormalizedResource],
) -> Mapping[str, _CustomRoleLifecycle]:
    lifecycles: dict[str, _CustomRoleLifecycle] = {}
    for resource in resources:
        if resource.resource_type not in {
            GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
            GcpResourceType.ORGANIZATION_IAM_CUSTOM_ROLE,
        }:
            continue
        facts = gcp_facts(resource)
        lifecycle = _CustomRoleLifecycle(
            resource.address,
            normalize_gcp_project(facts.project),
            _normalize_organization(facts.organization_id),
            facts.custom_role_stage,
            facts.custom_role_deleted,
            tuple(sorted(set(facts.custom_role_permissions))),
            facts.custom_role_permissions_state,
        )
        for reference in custom_role_reference_keys(resource):
            lifecycles.setdefault(reference, lifecycle)
    return lifecycles


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
    custom_roles: Mapping[str, _CustomRoleLifecycle],
) -> str:
    normalized = gcp_reference_key(role, GCP_ROLE_REFERENCE_SUFFIXES)
    lifecycle = custom_roles.get(normalized)
    if lifecycle is not None:
        return f"custom:{lifecycle.resource_address}"
    return f"role:{normalized}"


def _manager_role_keys(
    bindings: Sequence[Mapping[str, Any]],
    custom_roles: Mapping[str, _CustomRoleLifecycle],
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
    if resource.resource_type.endswith("_iam_policy"):
        return "authoritative_policy"
    if resource.resource_type.endswith("_iam_binding"):
        return "authoritative_role_binding"
    return "additive_member"


def _iam_resources(
    resources: Sequence[NormalizedResource],
) -> tuple[NormalizedResource, ...]:
    resource_types = GCP_PROJECT_IAM_RESOURCE_TYPES | GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES
    return tuple(resource for resource in resources if resource.resource_type in resource_types)


def _bucket_scope(bucket_name: str) -> str:
    return f"projects/_/buckets/{bucket_name}"


def _unwrap_reference(value: str) -> str:
    text = value.strip()
    if text.startswith("${") and text.endswith("}"):
        return text[2:-1].strip()
    return text


def _condition(value: object) -> dict[str, Any] | None:
    if isinstance(value, Mapping):
        return {str(key): item for key, item in value.items()}
    return None


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
