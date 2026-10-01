from __future__ import annotations

from collections.abc import Mapping

from tfstride.models import NormalizedResource
from tfstride.providers.azure.arm_scope import azure_arm_scope_contains, resource_arm_id
from tfstride.providers.azure.blob_operation_authority import (
    AzureBlobAuthorityResult,
    AzureBlobDataGrant,
    evaluate_blob_operation_authority,
)
from tfstride.providers.azure.key_vault_evidence import AzureKeyVaultRuntimeIdentityKind
from tfstride.providers.azure.protected_data_evidence import (
    AzureAppServiceStorageAccessPath,
)
from tfstride.providers.azure.resource_decoration.workload_identities import workload_managed_identities
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import AZURE_APP_SERVICE_RESOURCE_TYPES, AzureResourceType
from tfstride.providers.coercion import dedupe


class ModelAppServiceStorageAccessPathsStage:
    name = "model_app_service_storage_access_paths"

    def apply(self, resources: list[NormalizedResource], context: AzureDecorationContext) -> None:
        for workload in resources:
            if workload.resource_type not in AZURE_APP_SERVICE_RESOURCE_TYPES:
                continue
            paths, uncertainties = current_app_service_storage_access_paths(workload, context)
            facts = azure_facts(workload)
            facts.set_app_service_storage_access_paths(paths)
            facts.extend_app_service_storage_access_path_uncertainties(uncertainties)


def current_app_service_storage_access_paths(
    workload: NormalizedResource,
    context: AzureDecorationContext,
) -> tuple[list[AzureAppServiceStorageAccessPath], list[str]]:
    """Project current per-assignment Blob authority into the existing path schema."""
    workload_facts = azure_facts(workload)
    identities, identity_uncertainties = workload_managed_identities(workload, context)
    uncertainties = [
        *identity_uncertainties,
        *[f"{workload.address}: {value}" for value in workload_facts.managed_identity_uncertainties],
    ]
    paths: list[AzureAppServiceStorageAccessPath] = []

    assignments = sorted(
        (
            resource
            for resource in context.index.resources_by_address.values()
            if resource.resource_type == AzureResourceType.ROLE_ASSIGNMENT
        ),
        key=lambda resource: resource.address,
    )
    targets = sorted(
        (
            resource
            for resource in context.index.resources_by_address.values()
            if resource.resource_type in {AzureResourceType.STORAGE_ACCOUNT, AzureResourceType.STORAGE_CONTAINER}
        ),
        key=lambda resource: resource.address,
    )
    for identity, identity_kind in sorted(identities, key=lambda item: item[0].address):
        if identity_kind == "user_assigned" and not any(
            context.index.resolve(reference, source=workload, resource_types={AzureResourceType.USER_ASSIGNED_IDENTITY})
            is identity
            for reference in workload_facts.attached_identity_references
        ):
            uncertainties.append(f"{workload.address}: {identity.address} current identity attachment is unresolved")
            continue
        principal = azure_facts(identity).principal_id
        if not principal:
            continue
        for assignment in assignments:
            assignment_principal = azure_facts(assignment).principal_id
            if assignment_principal and assignment_principal.casefold() != principal.casefold():
                continue
            alternatives: list[tuple[NormalizedResource, AzureBlobAuthorityResult]] = []
            for target in targets:
                assessment = evaluate_blob_operation_authority(assignment, target, context, principal_id=principal)
                uncertainties.extend(
                    f"{workload.address}: {assignment.address} target {target.address}: {value}"
                    for value in assessment.uncertainties
                )
                if assessment.state in {"granted", "conditional"}:
                    alternatives.append((target, assessment))
            # An account path already represents its Blob namespace. Keep the
            # legacy account presentation rather than also emitting its containers.
            account_ids = [
                resource_arm_id(target)
                for target, _ in alternatives
                if target.resource_type == AzureResourceType.STORAGE_ACCOUNT
            ]
            for target, assessment in alternatives:
                target_id = resource_arm_id(target)
                if (
                    target.resource_type == AzureResourceType.STORAGE_CONTAINER
                    and target_id
                    and any(
                        account_id and azure_arm_scope_contains(account_id, target_id) for account_id in account_ids
                    )
                ):
                    continue
                assert assessment.grant is not None
                paths.append(
                    _access_path_record(
                        workload, identity, identity_kind, assignment, target, assessment.grant, context, assessment
                    )
                )

    return _dedupe_dicts(paths), dedupe(uncertainties)


def storage_access_path_allows_payload_read(path: Mapping[str, object]) -> bool:
    """Test the payload-read operation of an evaluated path, excluding tag reads."""
    if (
        path.get("access_state") != "granted"
        or path.get("condition_state") != "not_configured"
        or path.get("condition") is not None
    ):
        return False
    if path.get("role_kind") in {"blob_data_reader", "blob_data_contributor", "blob_data_owner"}:
        return True
    actions = path.get("matched_data_actions")
    return (
        path.get("role_kind") == "custom"
        and isinstance(actions, (list, tuple))
        and any(
            isinstance(action, str)
            and action.casefold() == "microsoft.storage/storageaccounts/blobservices/containers/blobs/read"
            for action in actions
        )
    )


def _access_path_record(
    workload: NormalizedResource,
    identity: NormalizedResource,
    identity_kind: AzureKeyVaultRuntimeIdentityKind,
    assignment: NormalizedResource,
    target: NormalizedResource,
    grant: AzureBlobDataGrant,
    context: AzureDecorationContext,
    assessment: AzureBlobAuthorityResult,
) -> AzureAppServiceStorageAccessPath:
    identity_facts = azure_facts(identity)
    assignment_facts = azure_facts(assignment)
    storage_account = _storage_account_for_target(target, context)
    condition = assignment_facts.role_assignment_condition
    record: AzureAppServiceStorageAccessPath = {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "identity_address": identity.address,
        "identity_kind": identity_kind,
        "principal_id": identity_facts.principal_id,
        "credential_context": "workload_runtime",
        "storage_resource_address": target.address,
        "storage_resource_type": target.resource_type,
        "storage_resource_id": target.identifier,
        "storage_account_address": storage_account.address if storage_account else None,
        "storage_account_id": azure_facts(storage_account).storage_account_id if storage_account else None,
        "container_address": target.address if target.resource_type == AzureResourceType.STORAGE_CONTAINER else None,
        "role_assignment_address": assignment.address,
        "role_definition_name": grant.role_name,
        "role_definition_id": assignment_facts.role_definition_id,
        "role_kind": grant.role_kind,
        "access_classes": list(grant.access_classes),
        "grant_basis": grant.grant_basis,
        "evaluation_basis": "modeled_rbac_assignment",
        "resource_scope": (
            "exact_storage_container"
            if target.resource_type == AzureResourceType.STORAGE_CONTAINER
            else "exact_storage_account"
        ),
        "assignment_scope": assignment_facts.role_assignment_scope,
        "assignment_scope_kind": assessment.assignment_scope_kind,
        "condition": condition,
        "condition_state": "configured" if condition else "not_configured",
        "access_state": "conditional" if condition else "granted",
        "role_definition_address": grant.role_definition_address,
        "custom_role_data_actions": list(grant.permission_patterns),
        "custom_role_not_data_actions": list(grant.not_permission_patterns),
        "matched_data_actions": list(grant.matched_data_actions),
        "excluded_data_actions": list(grant.excluded_data_actions),
    }
    return record


def _storage_account_for_target(
    target: NormalizedResource,
    context: AzureDecorationContext,
) -> NormalizedResource | None:
    if target.resource_type == AzureResourceType.STORAGE_ACCOUNT:
        return target
    account = context.index.resolve(
        azure_facts(target).storage_account_reference,
        source=target,
        resource_types={AzureResourceType.STORAGE_ACCOUNT},
    )
    if account is None or account.resource_type != AzureResourceType.STORAGE_ACCOUNT:
        return None
    return account


def _dedupe_dicts(
    values: list[AzureAppServiceStorageAccessPath],
) -> list[AzureAppServiceStorageAccessPath]:
    result: list[AzureAppServiceStorageAccessPath] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result
