from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Literal

from tfstride.models import NormalizedResource
from tfstride.providers.azure.object_storage_deletion_evidence import (
    AzureAppServiceBlobDeletionPath,
    AzureAppServiceBlobDeletionPathCommon,
    AzureAppServiceBlobVersionNamespaceDeletionPath,
    AzureAppServiceContainerBlobNamespaceDeletionPath,
    AzureBlobDeletionOperation,
    AzureBlobDeletionRecoveryEvidence,
)
from tfstride.providers.azure.protected_data_evidence import (
    AzureAppServiceStorageAccessPath,
)
from tfstride.providers.azure.resource_decoration.app_service_storage_access_paths import (
    storage_assignment_may_grant_blob_deletion,
)
from tfstride.providers.azure.resource_decoration.workload_identities import (
    workload_managed_identities,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import (
    AZURE_APP_SERVICE_RESOURCE_TYPES,
    AzureResourceType,
)
from tfstride.providers.coercion import dedupe, dedupe_strings

_DELETE_CURRENT_BLOB: Literal["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"] = (
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"
)
_DELETE_BLOB_VERSION: Literal[
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/deleteBlobVersion/action"
] = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/deleteBlobVersion/action"
_PERMANENT_DELETE: Literal["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/permanentDelete/action"] = (
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/permanentDelete/action"
)
_OPERATION_ORDER: tuple[AzureBlobDeletionOperation, ...] = (
    _DELETE_CURRENT_BLOB,
    _DELETE_BLOB_VERSION,
    _PERMANENT_DELETE,
)
_OPERATION_BY_CASEFOLDED_VALUE = {operation.casefold(): operation for operation in _OPERATION_ORDER}
_BUILT_IN_OPERATIONS: dict[str, tuple[AzureBlobDeletionOperation, ...]] = {
    "blob_data_contributor": (_DELETE_CURRENT_BLOB,),
    "blob_data_owner": _OPERATION_ORDER,
}
_STORAGE_ACCOUNT_ID_PATTERN = re.compile(
    r"/subscriptions/[^/]+/resourceGroups/[^/]+/providers/"
    r"Microsoft\.Storage/storageAccounts/[^/]+/?\Z",
    re.IGNORECASE,
)
_STORAGE_CONTAINER_ID_PATTERN = re.compile(
    r"/subscriptions/[^/]+/resourceGroups/[^/]+/providers/"
    r"Microsoft\.Storage/storageAccounts/[^/]+/blobServices/default/containers/[^/]+/?\Z",
    re.IGNORECASE,
)
_RECOVERY_UNCERTAINTY_PREFIXES = (
    "is_hns_enabled ",
    "blob_properties.versioning_enabled ",
    "blob_properties.delete_retention_policy.days ",
    "blob_properties.delete_retention_policy.permanent_delete_enabled ",
)


class ModelAppServiceBlobDeletionPathsStage:
    """Project deterministic Storage Blob deletion authority onto App Services."""

    name = "model_app_service_blob_deletion_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AzureDecorationContext,
    ) -> None:
        containers = tuple(
            resource for resource in resources if resource.resource_type == AzureResourceType.STORAGE_CONTAINER
        )
        for workload in resources:
            if workload.resource_type not in AZURE_APP_SERVICE_RESOURCE_TYPES:
                continue
            paths, uncertainties = _app_service_blob_deletion_paths(
                workload,
                containers,
                context,
            )
            facts = azure_facts(workload)
            facts.set_app_service_blob_deletion_paths(paths)
            facts.extend_app_service_blob_deletion_path_uncertainties(uncertainties)


def _app_service_blob_deletion_paths(
    workload: NormalizedResource,
    containers: Sequence[NormalizedResource],
    context: AzureDecorationContext,
) -> tuple[list[AzureAppServiceBlobDeletionPath], list[str]]:
    facts = azure_facts(workload)
    current_identities = _current_workload_identities(workload, context)
    paths: list[AzureAppServiceBlobDeletionPath] = []
    uncertainties = _deletion_relevant_access_uncertainties(
        workload,
        context,
    )

    for access_path in facts.app_service_storage_access_paths:
        operations = storage_access_path_deletion_operations(access_path)
        if not operations:
            continue
        if not _access_path_identity_is_current(access_path, current_identities):
            uncertainties.append(
                f"{workload.address}: Storage Blob deletion access path from "
                f"{access_path['role_assignment_address']} no longer has an exact current runtime identity"
            )
            continue
        if (
            access_path["access_state"] != "granted"
            or access_path["condition_state"] != "not_configured"
            or access_path["condition"] is not None
        ):
            uncertainties.append(
                f"{workload.address}: {access_path['role_assignment_address']} Storage Blob deletion "
                "authority requires condition evaluation"
            )
            continue

        account, target_containers, target_uncertainty = _access_path_targets(
            access_path,
            containers,
            context,
        )
        if target_uncertainty is not None:
            uncertainties.append(f"{workload.address}: {target_uncertainty}")
        if account is None:
            continue

        recovery_evidence = _recovery_evidence(account)
        for container in target_containers:
            for operation in operations:
                if operation == _PERMANENT_DELETE:
                    uncertainty = _permanent_delete_uncertainty(
                        workload,
                        account,
                        container,
                    )
                    if uncertainty is not None:
                        uncertainties.append(uncertainty)
                    continue
                record = _standard_path_record(
                    workload,
                    access_path,
                    account,
                    container,
                    operation,
                    recovery_evidence,
                )
                if record is not None:
                    paths.append(record)

    paths.sort(
        key=lambda path: (
            path["storage_account_address"],
            path["container_address"] or "",
            path["operation"],
            path["identity_address"],
            path["role_assignment_address"],
        )
    )
    return _dedupe_paths(paths), dedupe(uncertainties)


def _deletion_relevant_access_uncertainties(
    workload: NormalizedResource,
    context: AzureDecorationContext,
) -> list[str]:
    workload_facts = azure_facts(workload)
    identities, _identity_uncertainties = workload_managed_identities(
        workload,
        context,
    )
    relevant_assignment_addresses: set[str] = set()
    for identity, _identity_kind in identities:
        for assignment in azure_facts(identity).managed_identity_role_assignments:
            source_address = _known_string(assignment.get("source"))
            assignment_resource = context.index.resolve(
                source_address,
                source=identity,
                resource_types={AzureResourceType.ROLE_ASSIGNMENT},
            )
            if (
                assignment_resource is not None
                and assignment_resource.resource_type == AzureResourceType.ROLE_ASSIGNMENT
                and storage_assignment_may_grant_blob_deletion(
                    assignment,
                    assignment_resource,
                    context,
                )
            ):
                relevant_assignment_addresses.add(assignment_resource.address)

    return [
        uncertainty
        for uncertainty in workload_facts.app_service_storage_access_path_uncertainties
        if any(assignment_address in uncertainty for assignment_address in relevant_assignment_addresses)
    ]


def _current_workload_identities(
    workload: NormalizedResource,
    context: AzureDecorationContext,
) -> dict[str, tuple[str, str]]:
    identities, _uncertainties = workload_managed_identities(workload, context)
    result: dict[str, tuple[str, str]] = {}
    for identity, identity_kind in identities:
        principal_id = _known_string(azure_facts(identity).principal_id)
        if principal_id is not None:
            result[identity.address] = (identity_kind, principal_id)
    return result


def _access_path_identity_is_current(
    access_path: AzureAppServiceStorageAccessPath,
    current_identities: Mapping[str, tuple[str, str]],
) -> bool:
    current = current_identities.get(access_path["identity_address"])
    principal_id = _known_string(access_path["principal_id"])
    return bool(
        current is not None
        and principal_id is not None
        and current[0] == access_path["identity_kind"]
        and _same_identifier(current[1], principal_id)
    )


def storage_access_path_deletion_operations(
    access_path: AzureAppServiceStorageAccessPath,
) -> tuple[AzureBlobDeletionOperation, ...]:
    if access_path["role_kind"] != "custom":
        return _BUILT_IN_OPERATIONS.get(access_path["role_kind"], ())

    matched = {
        canonical
        for value in access_path["matched_data_actions"]
        if (canonical := _OPERATION_BY_CASEFOLDED_VALUE.get(value.casefold())) is not None
    }
    return tuple(operation for operation in _OPERATION_ORDER if operation in matched)


def _access_path_targets(
    access_path: AzureAppServiceStorageAccessPath,
    containers: Sequence[NormalizedResource],
    context: AzureDecorationContext,
) -> tuple[NormalizedResource | None, tuple[NormalizedResource, ...], str | None]:
    account_address = _known_string(access_path["storage_account_address"])
    account = context.index.resolve(
        account_address,
        resource_types={AzureResourceType.STORAGE_ACCOUNT},
    )
    if (
        account is None
        or account.resource_type != AzureResourceType.STORAGE_ACCOUNT
        or not _same_identifier(
            azure_facts(account).storage_account_id,
            access_path["storage_account_id"],
        )
        or not _is_exact_storage_account_id(azure_facts(account).storage_account_id)
    ):
        return (
            None,
            (),
            f"{access_path['role_assignment_address']} does not retain exact current Storage Account ancestry",
        )

    if access_path["resource_scope"] == "exact_storage_container":
        container_address = _known_string(access_path["container_address"])
        container = context.index.resolve(
            container_address,
            source=account,
            resource_types={AzureResourceType.STORAGE_CONTAINER},
        )
        if not _container_belongs_to_account(container, account):
            return (
                None,
                (),
                f"{access_path['role_assignment_address']} does not retain exact current container ancestry",
            )
        assert container is not None
        if (
            access_path["storage_resource_address"] != container.address
            or access_path["storage_resource_type"] != AzureResourceType.STORAGE_CONTAINER
            or not _same_identifier(
                access_path["storage_resource_id"],
                container.identifier,
            )
        ):
            return (
                None,
                (),
                f"{access_path['role_assignment_address']} does not retain its exact current container target",
            )
        return account, (container,), None

    if (
        access_path["resource_scope"] != "exact_storage_account"
        or access_path["storage_resource_address"] != account.address
        or access_path["storage_resource_type"] != AzureResourceType.STORAGE_ACCOUNT
        or not _same_identifier(
            access_path["storage_resource_id"],
            azure_facts(account).storage_account_id,
        )
    ):
        return (
            None,
            (),
            f"{access_path['role_assignment_address']} does not retain its exact current Storage Account target",
        )

    return (
        account,
        tuple(container for container in containers if _container_belongs_to_account(container, account)),
        None,
    )


def _container_belongs_to_account(
    container: NormalizedResource | None,
    account: NormalizedResource,
) -> bool:
    if container is None or container.resource_type != AzureResourceType.STORAGE_CONTAINER:
        return False
    container_facts = azure_facts(container)
    account_id = azure_facts(account).storage_account_id
    container_id = container_facts.storage_container_resource_manager_id
    if not _is_exact_storage_container_id(container_id) or not _is_exact_storage_account_id(account_id):
        return False
    assert container_id is not None
    assert account_id is not None
    return bool(
        container_facts.resolved_storage_account_address == account.address
        and container_id.casefold().startswith(f"{account_id.rstrip('/')}/blobServices/default/containers/".casefold())
    )


def _recovery_evidence(
    account: NormalizedResource,
) -> AzureBlobDeletionRecoveryEvidence:
    facts = azure_facts(account)
    uncertainties = [
        uncertainty
        for uncertainty in facts.storage_posture_uncertainties
        if uncertainty.startswith(_RECOVERY_UNCERTAINTY_PREFIXES)
    ]
    return {
        "recovery_evidence_scope": "azure_blob_versioning_and_soft_delete",
        "versioning_enabled": facts.storage_blob_versioning_enabled,
        "blob_delete_retention_days": facts.storage_blob_delete_retention_days,
        "permanent_delete_enabled": facts.storage_blob_permanent_delete_enabled,
        "hierarchical_namespace_enabled": facts.storage_hierarchical_namespace_enabled,
        "uncertainties": uncertainties,
    }


def _standard_path_record(
    workload: NormalizedResource,
    access_path: AzureAppServiceStorageAccessPath,
    account: NormalizedResource,
    container: NormalizedResource,
    operation: Literal[
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/deleteBlobVersion/action",
    ],
    recovery_evidence: AzureBlobDeletionRecoveryEvidence,
) -> AzureAppServiceBlobDeletionPath | None:
    if operation == _DELETE_BLOB_VERSION:
        if recovery_evidence["hierarchical_namespace_enabled"] is True:
            return None
        lifecycle_state: Literal["compatible", "unknown"] = (
            "unknown" if recovery_evidence["hierarchical_namespace_enabled"] is None else "compatible"
        )
    else:
        lifecycle_state = "compatible"

    common = _common_path_values(
        workload,
        access_path,
        account,
        container,
        operation,
        recovery_evidence,
    )
    if operation == _DELETE_CURRENT_BLOB:
        current_path: AzureAppServiceContainerBlobNamespaceDeletionPath = {
            **common,
            "operation": _DELETE_CURRENT_BLOB,
            "operation_class": "logical_blob_deletion",
            "management_effect": "disruption",
            "target_granularity": "container_blob_namespace",
            "blob_name": None,
            "blob_version": None,
            "snapshot": None,
            "lifecycle_compatibility_state": lifecycle_state,
        }
        return current_path

    version_path: AzureAppServiceBlobVersionNamespaceDeletionPath = {
        **common,
        "operation": _DELETE_BLOB_VERSION,
        "operation_class": "blob_version_deletion",
        "management_effect": "disruption",
        "target_granularity": "container_blob_version_namespace",
        "blob_name": None,
        "blob_version": None,
        "snapshot": None,
        "lifecycle_compatibility_state": lifecycle_state,
    }
    return version_path


def _common_path_values(
    workload: NormalizedResource,
    access_path: AzureAppServiceStorageAccessPath,
    account: NormalizedResource,
    container: NormalizedResource,
    operation: AzureBlobDeletionOperation,
    recovery_evidence: AzureBlobDeletionRecoveryEvidence,
) -> AzureAppServiceBlobDeletionPathCommon:
    role_definition_address = _known_string(access_path["role_definition_address"])
    authorization_sources = [access_path["role_assignment_address"]]
    if role_definition_address is not None:
        authorization_sources.append(role_definition_address)
    principal_id = _known_string(access_path["principal_id"])
    assert principal_id is not None
    container_id = azure_facts(container).storage_container_resource_manager_id
    account_id = azure_facts(account).storage_account_id
    assert container_id is not None
    assert account_id is not None
    return {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "identity_address": access_path["identity_address"],
        "identity_kind": access_path["identity_kind"],
        "principal_id": principal_id,
        "credential_context": "workload_runtime",
        "storage_account_address": account.address,
        "storage_account_id": account_id,
        "container_address": container.address,
        "container_resource_id": container_id,
        "target_scope": f"{container_id.rstrip('/')}/blobs/*",
        "target_model_evidence_addresses": [account.address, container.address],
        "role_assignment_address": access_path["role_assignment_address"],
        "role_definition_name": access_path["role_definition_name"],
        "role_definition_id": access_path["role_definition_id"],
        "role_definition_address": role_definition_address,
        "grant_basis": access_path["grant_basis"],
        "assignment_scope": access_path["assignment_scope"],
        "assignment_scope_kind": access_path["assignment_scope_kind"],
        "authorization_source_addresses": dedupe_strings(authorization_sources),
        "matched_data_actions": [operation],
        "excluded_data_actions": list(access_path["excluded_data_actions"]),
        "condition": None,
        "condition_state": "not_configured",
        "authorization_state": "granted",
        "policy_complete": True,
        "recovery_evidence": recovery_evidence,
        "posture_uncertainties": list(recovery_evidence["uncertainties"]),
    }


def _permanent_delete_uncertainty(
    workload: NormalizedResource,
    account: NormalizedResource,
    container: NormalizedResource,
) -> str | None:
    permanent_delete_enabled = azure_facts(account).storage_blob_permanent_delete_enabled
    if permanent_delete_enabled is False:
        return None
    if permanent_delete_enabled is None:
        return (
            f"{workload.address}: permanent Blob deletion authority over {container.address} "
            f"is unresolved because {account.address} permanent-delete feature state is unknown"
        )
    return (
        f"{workload.address}: permanent Blob deletion authority over {container.address} requires "
        "an exact modeled soft-deleted blob version or snapshot target"
    )


def _is_exact_storage_account_id(value: str | None) -> bool:
    return bool(value and _STORAGE_ACCOUNT_ID_PATTERN.fullmatch(value.rstrip("/")))


def _is_exact_storage_container_id(value: str | None) -> bool:
    return bool(value and _STORAGE_CONTAINER_ID_PATTERN.fullmatch(value.rstrip("/")))


def _same_identifier(left: str | None, right: str | None) -> bool:
    return bool(left and right and left.strip().rstrip("/").casefold() == right.strip().rstrip("/").casefold())


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _dedupe_paths(
    paths: Sequence[AzureAppServiceBlobDeletionPath],
) -> list[AzureAppServiceBlobDeletionPath]:
    result: list[AzureAppServiceBlobDeletionPath] = []
    for path in paths:
        if path not in result:
            result.append(path)
    return result
