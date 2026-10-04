"""Plan-local App Service to Blob authorization gaps over modeled storage targets."""

from __future__ import annotations

from collections.abc import Sequence

from tfstride.analysis.operation_gaps import (
    OperationGap,
    OperationGapEvidenceKind,
    OperationGapEvidenceState,
    OperationGapFamily,
    OperationGapProvenance,
    OperationGapResults,
)
from tfstride.models import NormalizedResource, ResourceInventory, TerraformReferenceResolutionState
from tfstride.providers.azure.arm_control_plane_authorization import (
    is_modeled_arm_builtin_role,
    model_arm_control_plane_action_authority,
)
from tfstride.providers.azure.arm_scope import (
    assignment_condition_state,
    assignment_field_unknown,
    azure_arm_scope_contains,
    resolve_assignment_scope,
    resource_arm_id,
    role_assignable_scope_state,
)
from tfstride.providers.azure.blob_operation_authority import (
    AzureBlobDataGrant,
    blob_data_grant,
    evaluate_blob_operation_authority,
)
from tfstride.providers.azure.resource_decoration.workload_identities import workload_managed_identities
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext, AzureResourceIndexBuilder
from tfstride.providers.azure.resource_types import AZURE_APP_SERVICE_RESOURCE_TYPES, AzureResourceType

BLOB_ACCESS = OperationGapFamily("azure", "app_service_blob_access")
BLOB_MUTATION = OperationGapFamily("azure", "app_service_blob_mutation")
BLOB_DELETION = OperationGapFamily("azure", "app_service_blob_deletion")
BLOB_TOPOLOGY = OperationGapFamily("azure", "app_service_storage_container_topology")
BLOB_GAP_FAMILIES = (BLOB_ACCESS, BLOB_MUTATION, BLOB_DELETION, BLOB_TOPOLOGY)

_CONTAINER_DELETE = "Microsoft.Storage/storageAccounts/blobServices/containers/delete"
_BLOB_PREFIX = "microsoft.storage/storageaccounts/blobservices/containers/blobs/"
_BUILT_IN_OPERATIONS: dict[str, tuple[str, ...]] = {
    "blob_data_reader": (_BLOB_PREFIX + "read",),
    "blob_data_contributor": (_BLOB_PREFIX + "read", _BLOB_PREFIX + "write", _BLOB_PREFIX + "delete"),
    "blob_data_owner": (
        _BLOB_PREFIX + "read",
        _BLOB_PREFIX + "write",
        _BLOB_PREFIX + "delete",
        _BLOB_PREFIX + "deleteblobversion/action",
        _BLOB_PREFIX + "permanentdelete/action",
    ),
}
_STATES: dict[str, OperationGapEvidenceState] = {
    "assignment_scope_unresolved": OperationGapEvidenceState.UNKNOWN,
    "assignment_scope_ambiguous": OperationGapEvidenceState.AMBIGUOUS,
    "assignment_principal_unresolved": OperationGapEvidenceState.UNKNOWN,
    "role_definition_unavailable": OperationGapEvidenceState.MISSING,
    "role_definition_ambiguous": OperationGapEvidenceState.AMBIGUOUS,
    "role_data_actions_unresolved": OperationGapEvidenceState.UNKNOWN,
    "role_actions_unresolved": OperationGapEvidenceState.UNKNOWN,
    "assignable_scope_unresolved": OperationGapEvidenceState.UNKNOWN,
    "assignment_condition_unresolved": OperationGapEvidenceState.CONDITIONAL,
}
_FIELDS: dict[str, tuple[str, ...]] = {
    "assignment_scope_unresolved": ("scope",),
    "assignment_scope_ambiguous": ("scope",),
    "assignment_principal_unresolved": ("principal_id",),
    "role_definition_unavailable": ("role_definition_id",),
    "role_definition_ambiguous": ("role_definition_id",),
    "role_data_actions_unresolved": ("permissions",),
    "role_actions_unresolved": ("permissions",),
    "assignable_scope_unresolved": ("assignable_scopes",),
    "assignment_condition_unresolved": ("condition",),
}


def collect_blob_operation_gaps(inventory: ResourceInventory) -> OperationGapResults:
    """Rebuild current identity, assignment, scope, and role evidence per call."""
    if inventory.provider != "azure":
        return OperationGapResults()
    context = AzureDecorationContext(AzureResourceIndexBuilder().build(list(inventory.resources)))
    resources = tuple(inventory.resources)
    assignments = tuple(item for item in resources if item.resource_type == AzureResourceType.ROLE_ASSIGNMENT)
    targets = tuple(
        item
        for item in resources
        if item.resource_type in {AzureResourceType.STORAGE_ACCOUNT, AzureResourceType.STORAGE_CONTAINER}
    )
    accounts = tuple(item for item in targets if item.resource_type == AzureResourceType.STORAGE_ACCOUNT)
    records: list[OperationGap] = []
    for workload in resources:
        if workload.resource_type not in AZURE_APP_SERVICE_RESOURCE_TYPES:
            continue
        identities, _ = workload_managed_identities(workload, context)
        for identity, _kind in identities:
            principal = azure_facts(identity).principal_id
            if not principal:
                continue
            for assignment in assignments:
                assignment_principal = azure_facts(assignment).principal_id
                if assignment_principal and assignment_principal.casefold() != principal.casefold():
                    continue
                if not assignment_principal and not any(
                    candidate.address == identity.address
                    for candidate in assignment.reference_resolution("principal_id").targets
                ):
                    continue
                for target in targets:
                    _blob_gaps(records, workload, identity, principal, assignment, target, accounts, context)
                    if target.resource_type == AzureResourceType.STORAGE_CONTAINER:
                        _topology_gaps(records, workload, identity, principal, assignment, target, context)
    return OperationGapResults(BLOB_GAP_FAMILIES, tuple(records))


def _blob_gaps(
    records: list[OperationGap],
    workload: NormalizedResource,
    identity: NormalizedResource,
    principal: str,
    assignment: NormalizedResource,
    target: NormalizedResource,
    accounts: Sequence[NormalizedResource],
    context: AzureDecorationContext,
) -> None:
    if not _candidate_scope(assignment, target, context):
        return
    assessment = evaluate_blob_operation_authority(assignment, target, context, principal_id=principal)
    if assessment.state in {"granted", "not_granted", "unrelated"}:
        return
    grant, grant_uncertainty = blob_data_grant(assignment, context)
    if grant is None and grant_uncertainty is None:
        return  # Known role permissions contain no modeled Blob DataAction.
    facts = azure_facts(assignment)
    if (
        grant is None
        and not assignment_field_unknown(assignment, "role_definition_id")
        and not assignment_field_unknown(assignment, "role_definition_name")
        and is_modeled_arm_builtin_role(facts.role_definition_name, facts.role_definition_id)
    ):
        return  # A modeled ARM-only role does not imply missing Blob DataActions.
    reason, source = _blob_reason(assignment, target, assessment.state, grant, grant_uncertainty, context)
    if reason is None:
        return
    skip_namespace = target.resource_type == AzureResourceType.STORAGE_CONTAINER and _account_covers_assignment(
        assignment, target, accounts, context
    )
    operations = _grant_operations(grant)
    if not operations:
        families = (BLOB_DELETION,) if skip_namespace else _families(None, target)
        _add(records, workload, identity, target, source, reason, None, families)
        return
    for operation in operations:
        families = _families(operation, target)
        if skip_namespace:
            families = tuple(family for family in families if family == BLOB_DELETION)
        _add(records, workload, identity, target, source, reason, operation, families)


def _topology_gaps(
    records: list[OperationGap],
    workload: NormalizedResource,
    identity: NormalizedResource,
    principal: str,
    assignment: NormalizedResource,
    container: NormalizedResource,
    context: AzureDecorationContext,
) -> None:
    if not _candidate_scope(assignment, container, context):
        return
    data_grant, _ = blob_data_grant(assignment, context)
    if data_grant is not None and data_grant.role_kind == "blob_data_reader":
        return  # This known data-only role has no ARM container-delete action.
    target_id = resource_arm_id(container)
    if target_id is None:
        return
    assessment = model_arm_control_plane_action_authority(
        assignment, context, principal_id=principal, target_arm_id=target_id, requested_actions=(_CONTAINER_DELETE,)
    )
    if assessment.state != "unknown":
        return
    reason, source = _topology_reason(assignment, container, assessment.reason_code, context)
    if reason is not None:
        _add(records, workload, identity, container, source, reason, _CONTAINER_DELETE, (BLOB_TOPOLOGY,))


def _blob_reason(
    assignment: NormalizedResource,
    target: NormalizedResource,
    state: str,
    grant: AzureBlobDataGrant | None,
    grant_uncertainty: str | None,
    context: AzureDecorationContext,
) -> tuple[str | None, NormalizedResource]:
    facts = azure_facts(assignment)
    if not facts.principal_id:
        return "assignment_principal_unresolved", assignment
    scope = resolve_assignment_scope(assignment, context, resource_arm_id(target))
    if scope.state != "resolved":
        return _scope_reason(assignment, context), assignment
    if grant is None:
        if grant_uncertainty is None:
            return None, assignment
        return _role_reason(assignment, context)
    if grant.role_definition_address:
        definition = context.index.resources_by_address[grant.role_definition_address]
        if role_assignable_scope_state(definition, scope.arm_scope) == "unknown":
            return "assignable_scope_unresolved", definition
        if role_assignable_scope_state(definition, scope.arm_scope) == "outside_assignable_scope":
            return None, definition
    if state == "conditional" or assignment_condition_state(assignment) != "not_configured":
        return "assignment_condition_unresolved", assignment
    return None, assignment


def _topology_reason(
    assignment: NormalizedResource,
    target: NormalizedResource,
    code: str | None,
    context: AzureDecorationContext,
) -> tuple[str | None, NormalizedResource]:
    if code == "assignment_principal_unresolved":
        return "assignment_principal_unresolved", assignment
    if code == "assignment_scope_unresolved":
        return _scope_reason(assignment, context), assignment
    if code == "assignment_condition_unresolved":
        return "assignment_condition_unresolved", assignment
    role_id = azure_facts(assignment).role_definition_id
    role = context.index.resolve(role_id, source=assignment, resource_types={AzureResourceType.ROLE_DEFINITION})
    if code == "assignable_scope_unresolved":
        if role is not None:
            scope = resolve_assignment_scope(assignment, context, resource_arm_id(target))
            if role_assignable_scope_state(role, scope.arm_scope) == "outside_assignable_scope":
                return None, role
        return "assignable_scope_unresolved", role or assignment
    if code == "role_actions_unresolved" and role is not None:
        role_facts = azure_facts(role)
        if any(
            value == "permissions is unknown after planning"
            or ".actions is unknown" in value
            or ".not_actions is unknown" in value
            for value in role_facts.role_definition_uncertainties
        ):
            return "role_actions_unresolved", role
    if (
        code == "role_actions_unresolved"
        and role_id
        and (
            context.index.resources_by_reference.resolve(
                role_id, source=assignment, resource_types={AzureResourceType.ROLE_DEFINITION}
            ).state
            == "ambiguous"
        )
    ):
        return "role_definition_ambiguous", assignment
    if code == "role_actions_unresolved":
        return "role_definition_unavailable", assignment
    return None, assignment


def _role_reason(assignment: NormalizedResource, context: AzureDecorationContext) -> tuple[str, NormalizedResource]:
    facts = azure_facts(assignment)
    role_id = facts.role_definition_id
    if role_id:
        resolution = context.index.resources_by_reference.resolve(
            role_id, source=assignment, resource_types={AzureResourceType.ROLE_DEFINITION}
        )
        if resolution.state == "ambiguous":
            return "role_definition_ambiguous", assignment
        definition = resolution.selected_candidate
        if definition is not None:
            return "role_data_actions_unresolved", definition
    return "role_definition_unavailable", assignment


def _scope_reason(assignment: NormalizedResource, context: AzureDecorationContext) -> str:
    resolution = assignment.reference_resolution("scope")
    if resolution.state == TerraformReferenceResolutionState.AMBIGUOUS:
        return "assignment_scope_ambiguous"
    raw_scope = azure_facts(assignment).role_assignment_scope
    if raw_scope and context.index.resources_by_reference.resolve(raw_scope, source=assignment).state == "ambiguous":
        return "assignment_scope_ambiguous"
    return "assignment_scope_unresolved"


def _candidate_scope(
    assignment: NormalizedResource, target: NormalizedResource, context: AzureDecorationContext
) -> bool:
    target_id = resource_arm_id(target)
    scope = resolve_assignment_scope(assignment, context, target_id)
    if scope.state == "unrelated":
        return False
    if scope.state == "resolved":
        return True
    resolution = assignment.reference_resolution("scope")
    return any(item.address == target.address for item in resolution.targets)


def _account_covers_assignment(
    assignment: NormalizedResource,
    target: NormalizedResource,
    accounts: Sequence[NormalizedResource],
    context: AzureDecorationContext,
) -> bool:
    target_id = resource_arm_id(target)
    return bool(
        target_id
        and any(
            account_id
            and azure_arm_scope_contains(account_id, target_id)
            and resolve_assignment_scope(assignment, context, account_id).state == "resolved"
            for account in accounts
            if (account_id := resource_arm_id(account))
        )
    )


def _grant_operations(grant: AzureBlobDataGrant | None) -> tuple[str, ...]:
    if grant is None:
        return ()
    if grant.role_kind == "custom":
        return grant.matched_data_actions
    return _BUILT_IN_OPERATIONS.get(grant.role_kind, ())


def _families(operation: str | None, target: NormalizedResource) -> tuple[OperationGapFamily, ...]:
    if operation is None:
        return (
            (BLOB_ACCESS, BLOB_MUTATION, BLOB_DELETION)
            if target.resource_type == AzureResourceType.STORAGE_CONTAINER
            else (BLOB_ACCESS, BLOB_MUTATION)
        )
    lowered = operation.casefold()
    if lowered.endswith(("/delete", "/deleteblobversion/action", "/permanentdelete/action")):
        return (
            (BLOB_ACCESS, BLOB_DELETION)
            if target.resource_type == AzureResourceType.STORAGE_CONTAINER
            else (BLOB_ACCESS,)
        )
    if lowered.endswith(("/write", "/add/action", "/move/action")):
        return BLOB_ACCESS, BLOB_MUTATION
    return (BLOB_ACCESS,)


def _add(
    records: list[OperationGap],
    workload: NormalizedResource,
    identity: NormalizedResource,
    target: NormalizedResource,
    source: NormalizedResource,
    reason: str,
    operation: str | None,
    families: Sequence[OperationGapFamily],
) -> None:
    scope = resource_arm_id(target)
    field_path = _FIELDS[reason]
    if source is identity:
        field_path = ("principal_id",)
    for family in families:
        records.append(
            OperationGap(
                family=family,
                resource_address=workload.address,
                relationship="runtime_identity_to_storage",
                operation=operation,
                target_address=target.address,
                scope=scope,
                reason_code=reason,
                evidence_state=_STATES[reason],
                provenance=(
                    OperationGapProvenance(source.address, OperationGapEvidenceKind.PLANNED_VALUE, field_path),
                ),
            )
        )
