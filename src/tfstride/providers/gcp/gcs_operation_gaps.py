"""Current, scoped Cloud Run to GCS authorization gaps over modeled buckets."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

from tfstride.analysis.operation_gaps import (
    OperationGap,
    OperationGapEvidenceKind,
    OperationGapEvidenceState,
    OperationGapFamily,
    OperationGapProvenance,
    OperationGapResults,
)
from tfstride.models import NormalizedResource, ResourceInventory
from tfstride.providers.gcp.gcs_custom_role_evaluation import assess_inherited_gcs_custom_role
from tfstride.providers.gcp.gcs_grant_ancestry import ancestor_iam_scope
from tfstride.providers.gcp.gcs_grant_constraints import GcsPermissionConstraint, gcs_permission_constraints
from tfstride.providers.gcp.gcs_grant_evaluation import (
    MODELED_GCS_OBJECT_PERMISSIONS,
    GcsGrantConstraintContext,
    modeled_gcs_role_permissions,
)
from tfstride.providers.gcp.gcs_project_grants import project_identity, project_scope_matches
from tfstride.providers.gcp.iam_reference_utils import gcs_bucket_scope_name
from tfstride.providers.gcp.resource_decoration.iam import resolve_resource_iam_target
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import (
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    GCP_ORG_FOLDER_IAM_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.gcp.resource_utils import binding_members

GCS_ACCESS = OperationGapFamily("gcp", "cloud_run_gcs_access")
GCS_MUTATION = OperationGapFamily("gcp", "cloud_run_gcs_mutation")
GCS_OBJECT_DELETION = OperationGapFamily("gcp", "cloud_run_gcs_object_deletion")
GCS_BUCKET_TOPOLOGY = OperationGapFamily("gcp", "cloud_run_gcs_bucket_topology")
GCS_GAP_FAMILIES = (GCS_ACCESS, GCS_MUTATION, GCS_OBJECT_DELETION, GCS_BUCKET_TOPOLOGY)

_IAM_TYPES = GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES | GCP_PROJECT_IAM_RESOURCE_TYPES | GCP_ORG_FOLDER_IAM_RESOURCE_TYPES
_ACTIVE_CUSTOM_ROLE_STAGES = frozenset({"ALPHA", "BETA", "DEPRECATED", "EAP", "GA"})
_MUTATION_OPERATIONS = frozenset(
    {
        "storage.objects.compose",
        "storage.objects.create",
        "storage.objects.move",
        "storage.objects.restore",
        "storage.objects.rewrite",
        "storage.objects.update",
    }
)
_STATES: dict[str, OperationGapEvidenceState] = {
    "grant_ancestry_unresolved": OperationGapEvidenceState.UNKNOWN,
    "iam_policy_document_unavailable": OperationGapEvidenceState.MISSING,
    "iam_grant_source_ambiguous": OperationGapEvidenceState.AMBIGUOUS,
    "iam_membership_unresolved": OperationGapEvidenceState.UNKNOWN,
    "iam_role_unresolved": OperationGapEvidenceState.UNKNOWN,
    "iam_condition_unresolved": OperationGapEvidenceState.CONDITIONAL,
    "deny_scope_unresolved": OperationGapEvidenceState.UNKNOWN,
    "deny_rule_unresolved": OperationGapEvidenceState.UNKNOWN,
    "custom_role_definition_unavailable": OperationGapEvidenceState.MISSING,
    "custom_role_ambiguous": OperationGapEvidenceState.AMBIGUOUS,
    "custom_role_ownership_unresolved": OperationGapEvidenceState.UNKNOWN,
    "custom_role_ownership_conflict": OperationGapEvidenceState.AMBIGUOUS,
    "custom_role_lifecycle_unresolved": OperationGapEvidenceState.UNKNOWN,
    "custom_role_permissions_unavailable": OperationGapEvidenceState.UNKNOWN,
    "custom_role_permission_syntax_unsupported": OperationGapEvidenceState.UNSUPPORTED,
}


def collect_gcs_operation_gaps(inventory: ResourceInventory) -> OperationGapResults:
    """Rebuild current scope, role, and deny evidence for each invocation."""
    if inventory.provider != "gcp":
        return OperationGapResults()
    resources = tuple(inventory.resources)
    context = GcsGrantConstraintContext.build(resources)
    buckets = inventory.by_type(GcpResourceType.STORAGE_BUCKET)
    sources = tuple(source for source in resources if source.resource_type in _IAM_TYPES)
    records: list[OperationGap] = []
    for workload in resources:
        if workload.resource_type not in GCP_CLOUD_RUN_RESOURCE_TYPES:
            continue
        principal = gcp_facts(workload).service_account_member
        if not principal:
            continue
        for bucket in buckets:
            bindings, _ = context.bindings(principal, bucket)
            for source in sources:
                scope_state = _scope_applies(source, bucket, context)
                if scope_state is False:
                    continue
                facts = gcp_facts(source)
                if source.resource_type.endswith("_iam_policy") and facts.iam_policy_data_state != "configured":
                    _add(
                        records,
                        workload,
                        bucket,
                        source,
                        "iam_policy_document_unavailable",
                        None,
                        ("policy_data",),
                        OperationGapEvidenceKind.POLICY_DOCUMENT,
                    )
                    continue
                for binding in facts.bindings:
                    if not _may_match_member(binding, principal):
                        continue
                    _binding_gaps(records, workload, bucket, source, binding, bindings, principal, scope_state, context)
    return OperationGapResults(GCS_GAP_FAMILIES, tuple(records))


def _binding_gaps(
    records: list[OperationGap],
    workload: NormalizedResource,
    bucket: NormalizedResource,
    source: NormalizedResource,
    binding: Mapping[str, object],
    accepted: Sequence[Mapping[str, object]],
    principal: str,
    scope_state: bool | None,
    context: GcsGrantConstraintContext,
) -> None:
    role = binding.get("role")
    if binding.get("members_state") == "unknown" and principal not in binding_members(binding):
        _add(records, workload, bucket, source, "iam_membership_unresolved", None, ("members",))
        return
    if not isinstance(role, str) or not role or binding.get("role_state") == "unknown":
        _add(records, workload, bucket, source, "iam_role_unresolved", None, ("role",))
        return
    accepted_here = any(
        candidate.get("source") == source.address
        and candidate.get("role") == role
        and principal in binding_members(candidate)
        for candidate in accepted
    )
    if scope_state is True and not accepted_here and binding.get("condition_state") != "unknown":
        _add(records, workload, bucket, source, "iam_grant_source_ambiguous", None)
        return
    inherited = source.resource_type in GCP_PROJECT_IAM_RESOURCE_TYPES | GCP_ORG_FOLDER_IAM_RESOURCE_TYPES
    definition: NormalizedResource | None = None
    if inherited and _custom_role_reference(role) and scope_state is True:
        assessment = assess_inherited_gcs_custom_role(
            role, source, bucket, context.custom_roles, context.index, context.projects
        )
        definition = context.custom_roles.resolve(role).selected_candidate
        if assessment.state in {"incompatible", "inactive"}:
            return  # A known non-grant or inactive role does not create uncertainty.
        if assessment.state == "unknown":
            reason = assessment.reason_code or "custom_role_definition_unavailable"
            known_permissions = (
                _modeled_permissions(gcp_facts(definition).custom_role_permissions)
                if definition is not None
                and gcp_facts(definition).custom_role_permissions_state == "configured"
                and reason
                in {
                    "custom_role_ownership_unresolved",
                    "custom_role_ownership_conflict",
                    "custom_role_lifecycle_unresolved",
                }
                else ()
            )
            if known_permissions:
                for permission in known_permissions:
                    _add_if_not_denied(
                        records, workload, bucket, definition or source, principal, permission, reason, context
                    )
            elif (
                definition is not None
                and gcp_facts(definition).custom_role_permissions_state == "configured"
                and reason
                in {
                    "custom_role_ownership_unresolved",
                    "custom_role_ownership_conflict",
                    "custom_role_lifecycle_unresolved",
                }
            ):
                return  # The known role has no operation in these reporting families.
            else:
                _add(
                    records,
                    workload,
                    bucket,
                    definition or source,
                    reason,
                    None,
                    ("role",) if definition is None else (),
                )
            return
        permissions = _modeled_permissions(assessment.permissions)
    elif _custom_role_reference(role) and scope_state is not True:
        permissions = ()  # Ownership cannot be assessed before grant applicability.
    elif _custom_role_reference(role):
        resolution = context.custom_roles.resolve(role)
        definition = resolution.selected_candidate
        if definition is None:
            _add(
                records,
                workload,
                bucket,
                source,
                "custom_role_ambiguous" if resolution.state == "ambiguous" else "custom_role_definition_unavailable",
                None,
                ("role",),
            )
            return
        role_facts = gcp_facts(definition)
        stage = role_facts.custom_role_stage.upper() if role_facts.custom_role_stage else None
        if role_facts.custom_role_deleted is True or stage == "DISABLED":
            return
        if role_facts.custom_role_permissions_state != "configured":
            _add(records, workload, bucket, definition, "custom_role_permissions_unavailable", None)
            return
        permissions = _modeled_permissions(role_facts.custom_role_permissions)
        if not permissions:
            return
        if role_facts.custom_role_deleted is not False or stage not in _ACTIVE_CUSTOM_ROLE_STAGES:
            for permission in permissions:
                _add_if_not_denied(
                    records,
                    workload,
                    bucket,
                    definition,
                    principal,
                    permission,
                    "custom_role_lifecycle_unresolved",
                    context,
                )
            return
    else:
        permissions = _modeled_permissions(modeled_gcs_role_permissions(role, context.custom_roles))
        if source.resource_type in GCP_PROJECT_IAM_RESOURCE_TYPES | GCP_ORG_FOLDER_IAM_RESOURCE_TYPES and role in {
            "roles/editor",
            "roles/owner",
        }:
            return  # Inherited basic-role semantics are a standing model limitation.
    if role in {"roles/storage.admin", "roles/storage.editor"} and scope_state is not False:
        permissions = (*permissions, "storage.buckets.delete")
    if scope_state is None:
        if permissions:
            for permission in permissions:
                _add_if_not_denied(
                    records, workload, bucket, source, principal, permission, "grant_ancestry_unresolved", context
                )
        else:
            _add(records, workload, bucket, source, "grant_ancestry_unresolved", None)
        return
    condition = binding.get("condition")
    condition_unknown = binding.get("condition_state") == "unknown"
    for permission in permissions:
        decisions = gcs_permission_constraints(
            principal, permission, bucket, context.deny_policies, context.projects, context.index
        )
        if any(decision["state"] == "denied" for decision in decisions):
            continue
        if condition not in (None, {}, []) or condition_unknown:
            _add(records, workload, bucket, source, "iam_condition_unresolved", permission, ("condition",))
        _record_unknown_denies(records, workload, bucket, source, permission, decisions, context)


def _add_if_not_denied(
    records: list[OperationGap],
    workload: NormalizedResource,
    bucket: NormalizedResource,
    source: NormalizedResource,
    principal: str,
    permission: str,
    reason: str,
    context: GcsGrantConstraintContext,
) -> None:
    decisions = gcs_permission_constraints(
        principal, permission, bucket, context.deny_policies, context.projects, context.index
    )
    if any(decision["state"] == "denied" for decision in decisions):
        return
    _add(records, workload, bucket, source, reason, permission)
    _record_unknown_denies(records, workload, bucket, source, permission, decisions, context)


def _record_unknown_denies(
    records: list[OperationGap],
    workload: NormalizedResource,
    bucket: NormalizedResource,
    source: NormalizedResource,
    permission: str,
    decisions: Sequence[GcsPermissionConstraint],
    context: GcsGrantConstraintContext,
) -> None:
    for decision in decisions:
        if decision["state"] == "unknown":
            policy = next((item for item in context.resources if item.address == decision["policy_address"]), source)
            _add(records, workload, bucket, policy, decision["reason_code"], permission)


def _scope_applies(
    source: NormalizedResource, bucket: NormalizedResource, context: GcsGrantConstraintContext
) -> bool | None:
    facts = gcp_facts(source)
    if source.resource_type in GCP_ORG_FOLDER_IAM_RESOURCE_TYPES:
        return ancestor_iam_scope(source, bucket, context.index)[2]
    if source.resource_type in GCP_PROJECT_IAM_RESOURCE_TYPES:
        return project_scope_matches(
            project_identity(facts.project, context.projects),
            project_identity(gcp_facts(bucket).project, context.projects),
        )
    if facts.iam_scope_reference_state != "configured":
        return None
    target = facts.target_reference
    native = gcs_bucket_scope_name(target)
    if native is not None and native != gcp_facts(bucket).bucket_name:
        return False
    resolution = resolve_resource_iam_target(source, context.index, resource_types={GcpResourceType.STORAGE_BUCKET})
    selected = resolution.selected_candidate
    if selected is not None:
        return selected.address == bucket.address
    return None


def _may_match_member(binding: Mapping[str, object], principal: str) -> bool:
    return principal in binding_members(binding) or binding.get("members_state") == "unknown"


def _custom_role_reference(role: str) -> bool:
    return not role.startswith("roles/")


def _modeled_permissions(permissions: Sequence[str]) -> tuple[str, ...]:
    if any(value in {"*", "storage.*", "storage.objects.*"} for value in permissions):
        return tuple(sorted(MODELED_GCS_OBJECT_PERMISSIONS))
    return tuple(value for value in permissions if value in MODELED_GCS_OBJECT_PERMISSIONS | {"storage.buckets.delete"})


def _families(permission: str | None) -> tuple[OperationGapFamily, ...]:
    if permission is None:
        return GCS_GAP_FAMILIES
    if permission == "storage.buckets.delete":
        return (GCS_BUCKET_TOPOLOGY,)
    if not permission.startswith("storage.objects."):
        return ()
    if permission == "storage.objects.delete":
        return (GCS_ACCESS, GCS_OBJECT_DELETION)
    if permission in _MUTATION_OPERATIONS:
        return (GCS_ACCESS, GCS_MUTATION)
    return (GCS_ACCESS,)


def _add(
    records: list[OperationGap],
    workload: NormalizedResource,
    bucket: NormalizedResource,
    source: NormalizedResource,
    reason: str,
    permission: str | None,
    field_path: tuple[str | int, ...] = (),
    kind: OperationGapEvidenceKind = OperationGapEvidenceKind.MODELED_RELATIONSHIP,
) -> None:
    name = gcp_facts(bucket).bucket_name
    scope = f"gs://{name}" if isinstance(name, str) and re.fullmatch(r"[a-z0-9][a-z0-9._-]*[a-z0-9]", name) else None
    for family in _families(permission):
        records.append(
            OperationGap(
                family=family,
                resource_address=workload.address,
                relationship="runtime_identity_to_storage",
                operation=permission,
                target_address=bucket.address,
                scope=scope,
                reason_code=reason,
                evidence_state=_STATES[reason],
                provenance=(OperationGapProvenance(source.address, kind, field_path),),
            )
        )
