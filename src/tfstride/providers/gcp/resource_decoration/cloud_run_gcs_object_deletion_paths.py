from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from tfstride.models import NormalizedResource
from tfstride.providers.coercion import (
    STATE_DISABLED,
    STATE_ENABLED,
    STATE_UNKNOWN,
    dedupe,
    dedupe_strings,
)
from tfstride.providers.gcp.custom_role_index import GcpCustomRoleIndex, build_gcp_custom_role_index
from tfstride.providers.gcp.iam_reference_utils import (
    gcs_bucket_scope_name,
    gcs_bucket_target_matches,
    normalize_gcp_project,
)
from tfstride.providers.gcp.object_storage_deletion_evidence import (
    GcpCloudRunGcsBucketObjectNamespaceDeletionPath,
    GcpCloudRunGcsGenerationNamespaceDeletionPath,
    GcpCloudRunGcsObjectDeletionPath,
    GcpCloudRunGcsObjectDeletionPathCommon,
    GcpGcsObjectDeletionLifecycleCompatibilityState,
    GcpGcsObjectDeletionRecoveryEvidence,
    GcpGcsObjectDeletionScopeType,
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
    binding_members,
)

_DELETE_PERMISSION = "storage.objects.delete"
_SERVICE_ACCOUNT_DOMAIN = ".gserviceaccount.com"
_IAM_RESOURCE_TYPES = GCP_PROJECT_IAM_RESOURCE_TYPES | GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES
_DELETE_PREDEFINED_ROLES = frozenset(
    {
        "roles/storage.admin",
        "roles/storage.objectAdmin",
        "roles/storage.objectUser",
    }
)
_BUCKET_ONLY_DELETE_ROLES = frozenset(
    {
        "roles/storage.legacyBucketOwner",
        "roles/storage.legacyBucketWriter",
    }
)
_BASIC_PREDEFINED_ROLES = frozenset({"roles/editor", "roles/owner"})
_ACTIVE_CUSTOM_ROLE_STAGES = frozenset(
    {
        "ALPHA",
        "BETA",
        "DEPRECATED",
        "EAP",
        "GA",
    }
)
_QUIET_PREDEFINED_ROLES = frozenset(
    {
        "roles/viewer",
        "roles/storage.objectCreator",
        "roles/storage.objectViewer",
    }
)
_SoftDeleteState = Literal["enabled", "disabled", "unknown", "not_observed"]
_ScopeState = Literal["applicable", "unrelated", "unresolved"]
_BUCKET_SCOPE_TYPE: Literal["bucket"] = "bucket"


@dataclass(frozen=True, slots=True)
class _RoleResolution:
    role_kind: str
    state: str
    grants_delete: bool
    custom_role_permissions: tuple[str, ...] = ()
    role_definition_address: str | None = None


@dataclass(slots=True)
class _GrantCandidate:
    source_address: str
    source_type: str
    scope_type: GcpGcsObjectDeletionScopeType
    scope: str
    management_mode: str
    role: str
    role_kind: str
    custom_role_permissions: tuple[str, ...]
    role_definition_address: str | None
    authorization_state: str
    management_state: str = "unambiguous"


@dataclass(frozen=True, slots=True)
class _ManagementSource:
    source_address: str
    scope_type: GcpGcsObjectDeletionScopeType
    scope: str
    management_mode: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _UnresolvedManager:
    source_address: str
    scope_type: GcpGcsObjectDeletionScopeType
    scope: str
    management_mode: str
    roles: tuple[str, ...]


class ModelCloudRunGcsObjectDeletionPathsStage:
    name = "model_cloud_run_gcs_object_deletion_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: GcpDecorationContext,
    ) -> None:
        buckets = tuple(resource for resource in resources if resource.resource_type == GcpResourceType.STORAGE_BUCKET)
        iam_resources = tuple(resource for resource in resources if resource.resource_type in _IAM_RESOURCE_TYPES)
        resources_by_address = {resource.address: resource for resource in resources}
        custom_roles = build_gcp_custom_role_index(resources)
        for workload in resources:
            if workload.resource_type not in GCP_CLOUD_RUN_RESOURCE_TYPES:
                continue
            paths, uncertainties = _cloud_run_gcs_object_deletion_paths(
                workload,
                buckets,
                iam_resources,
                resources_by_address,
                custom_roles,
                context,
            )
            facts = gcp_facts(workload)
            facts.set_cloud_run_gcs_object_deletion_paths(paths)
            facts.extend_cloud_run_gcs_object_deletion_path_uncertainties(uncertainties)


def _cloud_run_gcs_object_deletion_paths(
    workload: NormalizedResource,
    buckets: Sequence[NormalizedResource],
    iam_resources: Sequence[NormalizedResource],
    resources_by_address: Mapping[str, NormalizedResource],
    custom_roles: GcpCustomRoleIndex,
    context: GcpDecorationContext,
) -> tuple[list[GcpCloudRunGcsObjectDeletionPath], list[str]]:
    workload_facts = gcp_facts(workload)
    email = workload_facts.service_account_email
    member = workload_facts.service_account_member
    if not _is_exact_service_account_identity(email, member):
        return [], [f"{workload.address}: Cloud Run service account identity is unresolved"]
    assert email is not None
    assert member is not None

    paths: list[GcpCloudRunGcsObjectDeletionPath] = []
    uncertainties: list[str] = []
    for bucket in buckets:
        bucket_name = _bucket_name(bucket)
        bucket_project = normalize_gcp_project(gcp_facts(bucket).project)
        if bucket_name is None or bucket_project is None:
            uncertainties.append(f"{workload.address}: GCS bucket {bucket.address} has unresolved exact ancestry")
            continue

        candidates, candidate_uncertainties = _bucket_grant_candidates(
            workload,
            bucket,
            bucket_name,
            bucket_project,
            member,
            iam_resources,
            resources_by_address,
            custom_roles,
            context,
        )
        uncertainties.extend(candidate_uncertainties)
        lifecycle_state, recovery_evidence = _recovery_evidence(bucket)
        for candidate in candidates:
            if candidate.authorization_state != "granted" or candidate.management_state != "unambiguous":
                continue
            paths.extend(
                _path_records(
                    workload,
                    email,
                    member,
                    bucket,
                    bucket_name,
                    bucket_project,
                    candidate,
                    lifecycle_state,
                    recovery_evidence,
                )
            )

    paths.sort(
        key=lambda path: (
            path["bucket_address"],
            path["operation_class"],
            path["scope_type"],
            path["iam_resource_address"] or "",
            path["role"],
        )
    )
    return _dedupe_paths(paths), dedupe(uncertainties)


def _bucket_grant_candidates(
    workload: NormalizedResource,
    bucket: NormalizedResource,
    bucket_name: str,
    bucket_project: str,
    service_account_member: str,
    iam_resources: Sequence[NormalizedResource],
    resources_by_address: Mapping[str, NormalizedResource],
    custom_roles: GcpCustomRoleIndex,
    context: GcpDecorationContext,
) -> tuple[list[_GrantCandidate], list[str]]:
    candidates: list[_GrantCandidate] = []
    management_sources: list[_ManagementSource] = []
    unresolved_managers: list[_UnresolvedManager] = []
    uncertainties: list[str] = []

    for source in iam_resources:
        scope_state, scope_type, scope = _applicable_scope(
            source,
            bucket,
            bucket_name,
            bucket_project,
            resources_by_address,
            context,
        )
        if scope_state == "unrelated":
            continue
        assert scope_type is not None
        assert scope is not None

        source_bindings = iam_bindings(source)
        management_mode = _management_mode(source)
        roles = tuple(
            sorted({role for binding in source_bindings if (role := _known_string(binding.get("role"))) is not None})
        )
        if scope_state == "unresolved":
            if management_mode != "additive_member":
                unresolved_managers.append(
                    _UnresolvedManager(
                        source.address,
                        scope_type,
                        scope,
                        management_mode,
                        roles,
                    )
                )
            if (
                _source_may_affect_runtime_deletion(
                    source,
                    source_bindings,
                    service_account_member,
                    custom_roles,
                    scope_type,
                )
                or management_mode != "additive_member"
            ):
                uncertainties.append(
                    f"{workload.address}: {source.address} IAM scope is unresolved for GCS bucket {bucket.address}"
                )
            continue

        management_sources.append(
            _ManagementSource(
                source.address,
                scope_type,
                scope,
                management_mode,
                roles,
            )
        )
        if source.resource_type.endswith("_iam_policy") and gcp_facts(source).iam_policy_data_state != "configured":
            uncertainties.append(
                f"{workload.address}: {source.address} IAM policy_data is unresolved for GCS bucket {bucket.address}"
            )
            continue

        for binding in source_bindings:
            members = binding_members(binding)
            members_unknown = _binding_members_state(binding) == "unknown"
            member_matches = service_account_member in members
            if not member_matches and not members_unknown:
                continue

            role = _known_string(binding.get("role"))
            if role is None:
                uncertainties.append(
                    f"{workload.address}: {source.address} IAM role is unresolved for GCS bucket {bucket.address}"
                )
                continue
            resolution = _resolve_role(
                role,
                custom_roles,
                scope_type=scope_type,
            )
            if resolution.state not in {"resolved", "modeled_subset"}:
                uncertainties.append(
                    f"{workload.address}: {source.address} permissions for IAM role {role} are "
                    f"{resolution.state} for GCS bucket {bucket.address}"
                )
                continue
            if not resolution.grants_delete:
                continue

            condition_state = _condition_state(binding)
            if not member_matches:
                uncertainties.append(
                    f"{workload.address}: {source.address} IAM members are unresolved for GCS bucket {bucket.address}"
                )
                authorization_state = "unknown"
            elif condition_state == "unknown":
                uncertainties.append(
                    f"{workload.address}: {source.address} IAM condition applicability is unresolved "
                    f"for GCS bucket {bucket.address}"
                )
                authorization_state = "unknown"
            elif condition_state == "configured":
                uncertainties.append(
                    f"{workload.address}: {source.address} GCS deletion authority is condition-dependent "
                    f"for bucket {bucket.address}"
                )
                authorization_state = "conditional"
            else:
                authorization_state = "granted"

            candidates.append(
                _GrantCandidate(
                    source_address=source.address,
                    source_type=source.resource_type,
                    scope_type=scope_type,
                    scope=scope,
                    management_mode=management_mode,
                    role=role,
                    role_kind=resolution.role_kind,
                    custom_role_permissions=resolution.custom_role_permissions,
                    role_definition_address=resolution.role_definition_address,
                    authorization_state=authorization_state,
                )
            )

    _apply_management_ambiguity(
        candidates,
        management_sources,
        unresolved_managers,
        uncertainties,
        bucket,
    )
    return candidates, uncertainties


def _apply_management_ambiguity(
    candidates: Sequence[_GrantCandidate],
    sources: Sequence[_ManagementSource],
    unresolved_managers: Sequence[_UnresolvedManager],
    uncertainties: list[str],
    bucket: NormalizedResource,
) -> None:
    scope_set: set[tuple[GcpGcsObjectDeletionScopeType, str]] = {
        (source.scope_type, source.scope) for source in sources
    }
    for scope_type, scope in sorted(scope_set):
        scoped = [source for source in sources if source.scope_type == scope_type and source.scope == scope]
        policy_sources = {
            source.source_address for source in scoped if source.management_mode == "authoritative_policy"
        }
        other_sources = {source.source_address for source in scoped if source.management_mode != "authoritative_policy"}
        if len(policy_sources) > 1 or (policy_sources and other_sources):
            _mark_ambiguous(candidates, scope_type, scope)
            uncertainties.append(
                f"effective GCS IAM at {scope_type} scope {scope} for {bucket.address} is ambiguous "
                "because authoritative policy and other Terraform IAM managers overlap"
            )
            continue

        roles = sorted({role for source in scoped for role in source.roles})
        for role in roles:
            binding_sources = {
                source.source_address
                for source in scoped
                if source.management_mode == "authoritative_role_binding" and role in source.roles
            }
            member_sources = {
                source.source_address
                for source in scoped
                if source.management_mode == "additive_member" and role in source.roles
            }
            if len(binding_sources) > 1 or (binding_sources and member_sources):
                _mark_ambiguous(candidates, scope_type, scope, role)
                uncertainties.append(
                    f"effective GCS IAM membership for role {role} at {scope_type} scope {scope} "
                    f"for {bucket.address} is ambiguous because authoritative role bindings overlap "
                    "with another Terraform IAM manager"
                )

    for manager in unresolved_managers:
        affected = _mark_ambiguous(
            candidates,
            manager.scope_type,
            manager.scope,
            None if manager.management_mode == "authoritative_policy" or not manager.roles else manager.roles[0],
        )
        if affected:
            uncertainties.append(
                f"effective GCS IAM at {manager.scope_type} scope {manager.scope} for {bucket.address} "
                f"is unresolved because {manager.source_address} may be an overlapping authoritative manager"
            )


def _mark_ambiguous(
    candidates: Sequence[_GrantCandidate],
    scope_type: GcpGcsObjectDeletionScopeType,
    scope: str,
    role: str | None = None,
) -> bool:
    affected = False
    for candidate in candidates:
        if candidate.scope_type != scope_type or candidate.scope != scope:
            continue
        if role is not None and candidate.role != role:
            continue
        candidate.management_state = "ambiguous"
        affected = True
    return affected


def _source_may_affect_runtime_deletion(
    source: NormalizedResource,
    bindings: Sequence[Mapping[str, object]],
    service_account_member: str,
    custom_roles: GcpCustomRoleIndex,
    scope_type: GcpGcsObjectDeletionScopeType,
) -> bool:
    if source.resource_type.endswith("_iam_policy") and gcp_facts(source).iam_policy_data_state != "configured":
        return True
    for binding in bindings:
        if service_account_member not in binding_members(binding) and _binding_members_state(binding) != "unknown":
            continue
        role = _known_string(binding.get("role"))
        if role is None:
            return True
        resolution = _resolve_role(
            role,
            custom_roles,
            scope_type=scope_type,
        )
        if resolution.state not in {"resolved", "modeled_subset"} or resolution.grants_delete:
            return True
    return False


def _applicable_scope(
    source: NormalizedResource,
    bucket: NormalizedResource,
    bucket_name: str,
    bucket_project: str,
    resources_by_address: Mapping[str, NormalizedResource],
    context: GcpDecorationContext,
) -> tuple[_ScopeState, GcpGcsObjectDeletionScopeType | None, str | None]:
    del context
    facts = gcp_facts(source)
    if source.resource_type in GCP_PROJECT_IAM_RESOURCE_TYPES:
        scope = bucket_project
        if facts.iam_scope_reference_state in {"unknown", "not_configured"}:
            return "unresolved", "project", scope
        source_project = normalize_gcp_project(facts.project)
        if source_project is None:
            return "unresolved", "project", scope
        return ("applicable", "project", scope) if source_project == bucket_project else ("unrelated", None, None)

    bucket_scope = _bucket_scope(bucket_name)
    if facts.iam_scope_reference_state in {"unknown", "not_configured"}:
        return "unresolved", "bucket", bucket_scope
    target_reference = _known_string(facts.target_reference)
    if target_reference is None:
        return "unresolved", "bucket", bucket_scope

    reference = _unwrap_reference(target_reference)
    if gcs_bucket_target_matches(reference, bucket.address, bucket_name):
        return "applicable", "bucket", bucket_scope
    if reference.startswith("google_storage_bucket."):
        parts = reference.rsplit(".", 1)
        if len(parts) != 2:
            return "unresolved", "bucket", bucket_scope
        target_address, attribute = parts
        target = resources_by_address.get(target_address)
        if target is not None and target.address != bucket.address:
            return "unrelated", None, None
        if attribute != "name" or target is None:
            return "unresolved", "bucket", bucket_scope
        return "applicable", "bucket", bucket_scope

    exact_name = gcs_bucket_scope_name(reference)
    if exact_name is not None:
        return ("applicable", "bucket", bucket_scope) if exact_name == bucket_name else ("unrelated", None, None)
    if "${" not in reference and "/" not in reference:
        return "unrelated", None, None
    return "unresolved", "bucket", bucket_scope


def _resolve_role(
    role: str,
    custom_roles: GcpCustomRoleIndex,
    *,
    scope_type: GcpGcsObjectDeletionScopeType,
) -> _RoleResolution:
    if role in _DELETE_PREDEFINED_ROLES:
        return _RoleResolution("predefined", "modeled_subset", True)
    if role in _BUCKET_ONLY_DELETE_ROLES:
        if scope_type == _BUCKET_SCOPE_TYPE:
            return _RoleResolution("predefined", "modeled_subset", True)
        return _RoleResolution("predefined", "incompatible_scope", False)
    if role in _QUIET_PREDEFINED_ROLES:
        return _RoleResolution("predefined", "resolved", False)
    if role in _BASIC_PREDEFINED_ROLES:
        return _RoleResolution("predefined", "unmodeled", False)
    if not _looks_like_custom_role(role):
        return _RoleResolution("predefined", "unmodeled", False)

    resolution = custom_roles.resolve(role)
    custom = resolution.selected_candidate
    if custom is None:
        state = "ambiguous" if resolution.state == "ambiguous" else "external_or_unresolved"
        return _RoleResolution("custom", state, False)

    facts = gcp_facts(custom)
    permissions = tuple(sorted(set(facts.custom_role_permissions)))
    if facts.custom_role_deleted is True:
        return _RoleResolution(
            "custom",
            "resolved",
            False,
            role_definition_address=custom.address,
        )
    if facts.custom_role_deleted is None:
        return _RoleResolution(
            "custom",
            "unknown_deleted_state",
            False,
            role_definition_address=custom.address,
        )

    stage = facts.custom_role_stage.upper() if facts.custom_role_stage is not None else None
    if stage is None:
        return _RoleResolution(
            "custom",
            "unknown_stage",
            False,
            role_definition_address=custom.address,
        )
    if stage == "DISABLED":
        return _RoleResolution(
            "custom",
            "resolved",
            False,
            custom_role_permissions=permissions,
            role_definition_address=custom.address,
        )
    if stage not in _ACTIVE_CUSTOM_ROLE_STAGES:
        return _RoleResolution(
            "custom",
            "unsupported_stage",
            False,
            role_definition_address=custom.address,
        )
    permissions_state = facts.custom_role_permissions_state or "unknown"
    if permissions_state != "configured":
        return _RoleResolution(
            "custom",
            permissions_state,
            False,
            role_definition_address=custom.address,
        )
    return _RoleResolution(
        "custom",
        "resolved",
        _permissions_grant_delete(permissions),
        custom_role_permissions=permissions,
        role_definition_address=custom.address,
    )


def _path_records(
    workload: NormalizedResource,
    service_account_email: str,
    service_account_member: str,
    bucket: NormalizedResource,
    bucket_name: str,
    bucket_project: str,
    candidate: _GrantCandidate,
    lifecycle_state: GcpGcsObjectDeletionLifecycleCompatibilityState,
    recovery_evidence: GcpGcsObjectDeletionRecoveryEvidence,
) -> list[GcpCloudRunGcsObjectDeletionPath]:
    target_scope = f"{_bucket_scope(bucket_name)}/objects/*"
    common: GcpCloudRunGcsObjectDeletionPathCommon = {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "service_account_email": service_account_email,
        "service_account_member": service_account_member,
        "identity_kind": "cloud_run_service_account",
        "credential_context": "workload_runtime",
        "bucket_address": bucket.address,
        "bucket_name": bucket_name,
        "bucket_project": bucket_project,
        "management_effect": "disruption",
        "target_scope": target_scope,
        "target_model_evidence_addresses": [bucket.address],
        "iam_resource_address": candidate.source_address,
        "iam_resource_type": candidate.source_type,
        "role": candidate.role,
        "role_kind": candidate.role_kind,
        "grant_basis": f"{candidate.scope_type}_iam_{candidate.management_mode}",
        "scope_type": candidate.scope_type,
        "scope": candidate.scope,
        "iam_source_addresses": dedupe_strings([candidate.source_address, candidate.role_definition_address]),
        "custom_role_permissions": list(candidate.custom_role_permissions),
        "matched_permissions": [_DELETE_PERMISSION],
        "condition": None,
        "condition_state": "not_configured",
        "authorization_state": "granted",
        "policy_complete": True,
        "lifecycle_compatibility_state": lifecycle_state,
        "recovery_evidence": recovery_evidence,
        "posture_uncertainties": list(recovery_evidence["uncertainties"]),
    }
    logical: GcpCloudRunGcsBucketObjectNamespaceDeletionPath = {
        **common,
        "operation": _DELETE_PERMISSION,
        "operation_class": "logical_object_deletion",
        "target_granularity": "bucket_object_namespace",
        "object_name": None,
        "generation": None,
    }
    generations: GcpCloudRunGcsGenerationNamespaceDeletionPath = {
        **common,
        "operation": _DELETE_PERMISSION,
        "operation_class": "generation_deletion",
        "target_granularity": "bucket_generation_namespace",
        "object_name": None,
        "generation": None,
    }
    return [logical, generations]


def _recovery_evidence(
    bucket: NormalizedResource,
) -> tuple[
    GcpGcsObjectDeletionLifecycleCompatibilityState,
    GcpGcsObjectDeletionRecoveryEvidence,
]:
    facts = gcp_facts(bucket)
    uncertainties = [
        *facts.gcs_versioning_uncertainties,
        *facts.gcs_soft_delete_policy_uncertainties,
        *facts.gcs_retention_policy_uncertainties,
    ]
    soft_delete_state = _soft_delete_state(facts.gcs_soft_delete_state)
    if soft_delete_state == "not_observed":
        uncertainties.append(
            f"{bucket.address}: soft-delete policy is not observed; the platform default is not inferred"
        )
    elif soft_delete_state == "unknown" and not facts.gcs_soft_delete_policy_uncertainties:
        uncertainties.append(f"{bucket.address}: soft-delete recovery posture is unresolved")

    retention_period = facts.gcs_retention_period_seconds
    if facts.gcs_retention_policy_uncertainties:
        lifecycle_state: GcpGcsObjectDeletionLifecycleCompatibilityState = "unknown"
    elif retention_period is not None and retention_period > 0:
        lifecycle_state = "unknown"
        uncertainties.append(
            f"{bucket.address}: retention policy does not establish the age of a targeted object or generation"
        )
    else:
        lifecycle_state = "compatible"

    evidence: GcpGcsObjectDeletionRecoveryEvidence = {
        "recovery_evidence_scope": "gcs_versioning_soft_delete_and_retention",
        "versioning_enabled": facts.versioning_enabled,
        "soft_delete_retention_duration_seconds": facts.gcs_soft_delete_retention_duration_seconds,
        "soft_delete_state": soft_delete_state,
        "retention_period_seconds": retention_period,
        "retention_policy_locked": facts.gcs_retention_policy_locked,
        "uncertainties": dedupe(uncertainties),
    }
    return lifecycle_state, evidence


def _permissions_grant_delete(permissions: Sequence[str]) -> bool:
    return any(permission in {"*", "storage.*", "storage.objects.*", _DELETE_PERMISSION} for permission in permissions)


def _condition_state(binding: Mapping[str, object]) -> str:
    if binding.get("condition_state") == "unknown":
        return "unknown"
    condition = binding.get("condition")
    return "configured" if isinstance(condition, Mapping) and condition else "not_configured"


def _binding_members_state(binding: Mapping[str, object]) -> str:
    return "unknown" if binding.get("members_state") == "unknown" else "configured"


def _management_mode(resource: NormalizedResource) -> str:
    if resource.resource_type.endswith("_iam_policy"):
        return "authoritative_policy"
    if resource.resource_type.endswith("_iam_binding"):
        return "authoritative_role_binding"
    return "additive_member"


def _bucket_name(bucket: NormalizedResource) -> str | None:
    name = _known_string(gcp_facts(bucket).bucket_name)
    if name is None or "/" in name or "${" in name or name.startswith("google_"):
        return None
    return name


def _bucket_scope(bucket_name: str) -> str:
    return f"projects/_/buckets/{bucket_name}"


def _unwrap_reference(value: str) -> str:
    text = value.strip()
    if text.startswith("${") and text.endswith("}"):
        return text[2:-1].strip()
    return text


def _soft_delete_state(value: str | None) -> _SoftDeleteState:
    if value == STATE_ENABLED:
        return "enabled"
    if value == STATE_DISABLED:
        return "disabled"
    if value == "not_observed":
        return "not_observed"
    return STATE_UNKNOWN


def _is_exact_service_account_identity(email: str | None, member: str | None) -> bool:
    return bool(
        email
        and member == f"serviceAccount:{email}"
        and "@" in email
        and email.endswith(_SERVICE_ACCOUNT_DOMAIN)
        and "${" not in email
        and not ("google_" in email and "." in email)
    )


def _looks_like_custom_role(role: str) -> bool:
    return role.startswith(("projects/", "organizations/")) or "iam_custom_role." in role


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _dedupe_paths(
    paths: Sequence[GcpCloudRunGcsObjectDeletionPath],
) -> list[GcpCloudRunGcsObjectDeletionPath]:
    result: list[GcpCloudRunGcsObjectDeletionPath] = []
    for path in paths:
        if path not in result:
            result.append(path)
    return result
