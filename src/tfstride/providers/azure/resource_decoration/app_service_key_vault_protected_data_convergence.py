from __future__ import annotations

from collections.abc import Sequence
from typing import Literal, cast

from tfstride.models import NormalizedResource
from tfstride.providers.azure.key_vault_dependency_evidence import (
    AzureKeyVaultEncryptionDependency,
)
from tfstride.providers.azure.key_vault_evidence import (
    AzureAppServiceKeyVaultOperationPath,
    AzureKeyVaultRuntimeIdentityKind,
)
from tfstride.providers.azure.protected_data_evidence import (
    AzureAppServiceServiceBusAccessPath,
    AzureAppServiceServiceBusProtectedDataConvergence,
    AzureAppServiceStorageAccessPath,
    AzureAppServiceStorageProtectedDataConvergence,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import (
    AZURE_APP_SERVICE_RESOURCE_TYPES,
    AzureResourceType,
)
from tfstride.providers.coercion import STATE_CONFIGURED, dedupe

_PLAINTEXT_OPERATIONS = frozenset({"decrypt", "unwrap"})
_EXPECTED_KEY_OPERATION = {
    "decrypt": "decrypt",
    "unwrap": "unwrapKey",
}
_SERVICE_BUS_TARGET_TYPES = frozenset(
    {
        AzureResourceType.SERVICE_BUS_NAMESPACE,
        AzureResourceType.SERVICE_BUS_QUEUE,
        AzureResourceType.SERVICE_BUS_TOPIC,
        AzureResourceType.SERVICE_BUS_SUBSCRIPTION,
    }
)


class ModelAppServiceKeyVaultProtectedDataConvergenceStage:
    name = "model_app_service_key_vault_protected_data_convergence"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AzureDecorationContext,
    ) -> None:
        for workload in resources:
            if workload.resource_type not in AZURE_APP_SERVICE_RESOURCE_TYPES:
                continue
            storage_convergences, storage_uncertainties = _storage_convergences(
                workload,
                context,
            )
            service_bus_convergences, service_bus_uncertainties = _service_bus_convergences(workload, context)
            facts = azure_facts(workload)
            facts.set_app_service_storage_protected_data_convergences(storage_convergences)
            facts.extend_app_service_storage_protected_data_convergence_uncertainties(storage_uncertainties)
            facts.set_app_service_service_bus_protected_data_convergences(service_bus_convergences)
            facts.extend_app_service_service_bus_protected_data_convergence_uncertainties(service_bus_uncertainties)


def _storage_convergences(
    workload: NormalizedResource,
    context: AzureDecorationContext,
) -> tuple[list[AzureAppServiceStorageProtectedDataConvergence], list[str]]:
    workload_facts = azure_facts(workload)
    uncertainties = list(workload_facts.app_service_storage_access_path_uncertainties)
    convergences: list[AzureAppServiceStorageProtectedDataConvergence] = []

    for access_path in workload_facts.app_service_storage_access_paths:
        if "read" not in access_path["access_classes"]:
            continue
        account, ancestry_uncertainty = _storage_account_for_access(
            access_path,
            context,
        )
        if ancestry_uncertainty is not None:
            uncertainties.append(f"{workload.address}: {ancestry_uncertainty}")
        if account is None:
            continue

        dependencies = azure_facts(account).key_vault_encryption_dependencies
        uncertainties.extend(
            f"{workload.address}: {uncertainty}"
            for uncertainty in azure_facts(account).key_vault_encryption_dependency_uncertainties
        )
        _append_dependency_uncertainties(
            workload,
            account,
            dependencies,
            uncertainties,
        )
        if not _deterministic_storage_read(
            access_path,
            workload,
            account,
            context,
        ):
            if dependencies:
                uncertainties.append(
                    f"{workload.address}: Storage payload-read authority to "
                    f"{access_path['storage_resource_address']} is not deterministic "
                    "for protected-data convergence"
                )
            continue

        for dependency in dependencies:
            key, dependency_uncertainty = _resolved_dependency_key(
                dependency,
                account,
                context,
            )
            if dependency_uncertainty is not None:
                uncertainties.append(f"{workload.address}: {account.address} {dependency_uncertainty}")
            if key is None:
                continue
            matching_paths = _matching_plaintext_paths(
                workload,
                access_path["identity_address"],
                access_path["identity_kind"],
                access_path["principal_id"],
                key,
                dependency,
                context,
            )
            if not matching_paths:
                _append_operation_uncertainties(
                    workload,
                    key,
                    workload_facts.app_service_key_vault_operation_path_uncertainties,
                    uncertainties,
                )
                continue
            convergences.extend(
                _storage_convergence_record(
                    workload,
                    access_path,
                    operation_path,
                    dependency,
                )
                for operation_path in matching_paths
            )

    return _dedupe_storage_convergences(convergences), dedupe(uncertainties)


def _service_bus_convergences(
    workload: NormalizedResource,
    context: AzureDecorationContext,
) -> tuple[list[AzureAppServiceServiceBusProtectedDataConvergence], list[str]]:
    workload_facts = azure_facts(workload)
    uncertainties = list(workload_facts.app_service_service_bus_access_path_uncertainties)
    convergences: list[AzureAppServiceServiceBusProtectedDataConvergence] = []

    for access_path in workload_facts.app_service_service_bus_access_paths:
        if "receive" not in access_path["access_classes"]:
            continue
        namespace, ancestry_uncertainty = _service_bus_namespace_for_access(
            access_path,
            context,
        )
        if ancestry_uncertainty is not None:
            uncertainties.append(f"{workload.address}: {ancestry_uncertainty}")
        if namespace is None:
            continue

        dependencies = azure_facts(namespace).key_vault_encryption_dependencies
        uncertainties.extend(
            f"{workload.address}: {uncertainty}"
            for uncertainty in azure_facts(namespace).key_vault_encryption_dependency_uncertainties
        )
        _append_dependency_uncertainties(
            workload,
            namespace,
            dependencies,
            uncertainties,
        )
        if not _deterministic_service_bus_receive(
            access_path,
            workload,
            namespace,
            context,
        ):
            if dependencies:
                uncertainties.append(
                    f"{workload.address}: Service Bus receive authority to "
                    f"{access_path['service_bus_resource_address']} is not deterministic "
                    "for protected-data convergence"
                )
            continue

        for dependency in dependencies:
            key, dependency_uncertainty = _resolved_dependency_key(
                dependency,
                namespace,
                context,
            )
            if dependency_uncertainty is not None:
                uncertainties.append(f"{workload.address}: {namespace.address} {dependency_uncertainty}")
            if key is None:
                continue
            matching_paths = _matching_plaintext_paths(
                workload,
                access_path["identity_address"],
                access_path["identity_kind"],
                access_path["principal_id"],
                key,
                dependency,
                context,
            )
            if not matching_paths:
                _append_operation_uncertainties(
                    workload,
                    key,
                    workload_facts.app_service_key_vault_operation_path_uncertainties,
                    uncertainties,
                )
                continue
            convergences.extend(
                _service_bus_convergence_record(
                    workload,
                    access_path,
                    operation_path,
                    dependency,
                )
                for operation_path in matching_paths
            )

    return _dedupe_service_bus_convergences(convergences), dedupe(uncertainties)


def _storage_account_for_access(
    path: AzureAppServiceStorageAccessPath,
    context: AzureDecorationContext,
) -> tuple[NormalizedResource | None, str | None]:
    target = context.index.resources_by_address.get(path["storage_resource_address"])
    account_address = path["storage_account_address"]
    account = context.index.resources_by_address.get(account_address) if account_address is not None else None
    if (
        target is None
        or target.provider != "azure"
        or target.resource_type
        not in {
            AzureResourceType.STORAGE_ACCOUNT,
            AzureResourceType.STORAGE_CONTAINER,
        }
        or account is None
        or account.provider != "azure"
        or account.resource_type != AzureResourceType.STORAGE_ACCOUNT
    ):
        return None, "Storage access path does not retain an exact modeled account ancestry"

    account_id = azure_facts(account).storage_account_id
    if (
        account_id is None
        or not _same_identifier(path["storage_account_id"], account_id)
        or not _same_identifier(path["storage_resource_id"], target.identifier)
    ):
        return None, "Storage access path account or target identity is unresolved"

    if target.resource_type == AzureResourceType.STORAGE_ACCOUNT:
        if (
            target.address != account.address
            or path["resource_scope"] != "exact_storage_account"
            or path["container_address"] is not None
        ):
            return None, "Storage account access path has conflicting parent evidence"
        return account, None

    target_account_address = azure_facts(target).resolved_storage_account_address
    if (
        path["resource_scope"] != "exact_storage_container"
        or path["container_address"] != target.address
        or target_account_address != account.address
    ):
        return None, "Storage container ancestry does not resolve to the dependency account"
    return account, None


def _service_bus_namespace_for_access(
    path: AzureAppServiceServiceBusAccessPath,
    context: AzureDecorationContext,
) -> tuple[NormalizedResource | None, str | None]:
    target = context.index.resources_by_address.get(path["service_bus_resource_address"])
    namespace_address = path["service_bus_namespace_address"]
    namespace = context.index.resources_by_address.get(namespace_address) if namespace_address is not None else None
    if (
        target is None
        or target.provider != "azure"
        or target.resource_type not in _SERVICE_BUS_TARGET_TYPES
        or namespace is None
        or namespace.provider != "azure"
        or namespace.resource_type != AzureResourceType.SERVICE_BUS_NAMESPACE
    ):
        return None, "Service Bus access path does not retain an exact modeled namespace ancestry"

    namespace_id = azure_facts(namespace).service_bus_namespace_id
    if (
        namespace_id is None
        or not _same_identifier(path["service_bus_namespace_id"], namespace_id)
        or not _same_identifier(
            path["service_bus_resource_id"],
            _service_bus_resource_id(target),
        )
    ):
        return None, "Service Bus access path namespace or target identity is unresolved"

    if target.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE:
        if (
            target.address != namespace.address
            or path["resource_scope"] != "exact_service_bus_namespace"
            or any(
                value is not None
                for value in (
                    path["queue_address"],
                    path["topic_address"],
                    path["subscription_address"],
                )
            )
        ):
            return None, "Service Bus namespace access path has conflicting child evidence"
        return namespace, None

    if azure_facts(target).resolved_service_bus_namespace_address != namespace.address:
        return None, "Service Bus child ancestry does not resolve to the dependency namespace"
    if target.resource_type == AzureResourceType.SERVICE_BUS_QUEUE:
        valid = bool(
            path["resource_scope"] == "exact_service_bus_queue"
            and path["queue_address"] == target.address
            and path["topic_address"] is None
            and path["subscription_address"] is None
        )
    elif target.resource_type == AzureResourceType.SERVICE_BUS_TOPIC:
        valid = bool(
            path["resource_scope"] == "exact_service_bus_topic"
            and path["queue_address"] is None
            and path["topic_address"] == target.address
            and path["subscription_address"] is None
        )
    else:
        topic_address = azure_facts(target).resolved_service_bus_topic_address
        valid = bool(
            path["resource_scope"] == "exact_service_bus_subscription"
            and path["queue_address"] is None
            and path["topic_address"] == topic_address
            and path["subscription_address"] == target.address
            and topic_address is not None
        )
    if not valid:
        return None, "Service Bus child access evidence conflicts with native ancestry"
    return namespace, None


def _deterministic_storage_read(
    path: AzureAppServiceStorageAccessPath,
    workload: NormalizedResource,
    account: NormalizedResource,
    context: AzureDecorationContext,
) -> bool:
    assignment = context.index.resources_by_address.get(path["role_assignment_address"])
    return bool(
        path["workload_address"] == workload.address
        and path["workload_type"] == workload.resource_type
        and _runtime_identity_matches(
            workload,
            path["identity_address"],
            path["identity_kind"],
            path["principal_id"],
            context,
        )
        and path["credential_context"] == "workload_runtime"
        and path["storage_account_address"] == account.address
        and path["evaluation_basis"] == "modeled_rbac_assignment"
        and path["condition"] is None
        and path["condition_state"] == "not_configured"
        and path["access_state"] == "granted"
        and "read" in path["access_classes"]
        and assignment is not None
        and assignment.provider == "azure"
        and assignment.resource_type == AzureResourceType.ROLE_ASSIGNMENT
    )


def _deterministic_service_bus_receive(
    path: AzureAppServiceServiceBusAccessPath,
    workload: NormalizedResource,
    namespace: NormalizedResource,
    context: AzureDecorationContext,
) -> bool:
    assignment = context.index.resources_by_address.get(path["role_assignment_address"])
    return bool(
        path["workload_address"] == workload.address
        and path["workload_type"] == workload.resource_type
        and _runtime_identity_matches(
            workload,
            path["identity_address"],
            path["identity_kind"],
            path["principal_id"],
            context,
        )
        and path["credential_context"] == "workload_runtime"
        and path["service_bus_namespace_address"] == namespace.address
        and path["evaluation_basis"] == "modeled_rbac_assignment"
        and path["condition"] is None
        and path["condition_state"] == "not_configured"
        and path["access_state"] == "granted"
        and "receive" in path["access_classes"]
        and assignment is not None
        and assignment.provider == "azure"
        and assignment.resource_type == AzureResourceType.ROLE_ASSIGNMENT
    )


def _runtime_identity_matches(
    workload: NormalizedResource,
    identity_address: str,
    identity_kind: AzureKeyVaultRuntimeIdentityKind,
    principal_id: str | None,
    context: AzureDecorationContext,
) -> bool:
    if principal_id is None:
        return False
    identity = context.index.resources_by_address.get(identity_address)
    if identity_kind == "system_assigned":
        return bool(
            identity is workload
            and identity_address == workload.address
            and _same_identifier(azure_facts(workload).principal_id, principal_id)
        )
    workload_facts = azure_facts(workload)
    attached_addresses = set(workload_facts.resolved_attached_identity_addresses)
    for reference in workload_facts.attached_identity_references:
        attached_identity = context.index.resolve(
            reference,
            source=workload,
            resource_types={AzureResourceType.USER_ASSIGNED_IDENTITY},
        )
        if (
            attached_identity is not None
            and attached_identity.resource_type == AzureResourceType.USER_ASSIGNED_IDENTITY
        ):
            attached_addresses.add(attached_identity.address)
    return bool(
        identity is not None
        and identity.provider == "azure"
        and identity.resource_type == AzureResourceType.USER_ASSIGNED_IDENTITY
        and identity.address in attached_addresses
        and _same_identifier(azure_facts(identity).principal_id, principal_id)
    )


def _append_dependency_uncertainties(
    workload: NormalizedResource,
    dependent: NormalizedResource,
    dependencies: Sequence[AzureKeyVaultEncryptionDependency],
    uncertainties: list[str],
) -> None:
    for dependency in dependencies:
        if dependency["resolution_state"] == "resolved":
            if dependency["customer_managed_key_state"] == "unknown":
                uncertainties.append(
                    f"{workload.address}: {dependent.address} Key Vault dependency "
                    "has unresolved customer-managed key state"
                )
            continue
        if dependency["posture_uncertainties"]:
            uncertainties.extend(
                f"{workload.address}: {dependent.address} Key Vault dependency "
                f"is {dependency['resolution_state']}: {uncertainty}"
                for uncertainty in dependency["posture_uncertainties"]
            )
        else:
            uncertainties.append(
                f"{workload.address}: {dependent.address} Key Vault dependency is {dependency['resolution_state']}"
            )


def _resolved_dependency_key(
    dependency: AzureKeyVaultEncryptionDependency,
    dependent: NormalizedResource,
    context: AzureDecorationContext,
) -> tuple[NormalizedResource | None, str | None]:
    if dependency["resolution_state"] != "resolved":
        return None, None
    if dependency["customer_managed_key_state"] != STATE_CONFIGURED:
        return None, None
    if (
        dependency["dependent_address"] != dependent.address
        or dependency["dependent_resource_type"] != dependent.resource_type
    ):
        return None, "resolved dependency does not match its protected parent"

    key_address = dependency["key_address"]
    key = context.index.resources_by_address.get(key_address) if key_address is not None else None
    if (
        key is None
        or key.provider != "azure"
        or key.resource_type != AzureResourceType.KEY_VAULT_KEY
        or dependency["candidate_key_addresses"] != [key.address]
    ):
        return None, "resolved dependency does not retain one exact modeled Key Vault key"

    source = context.index.resources_by_address.get(dependency["dependency_source_address"])
    if (
        source is None
        or source.provider != "azure"
        or source.resource_type != dependency["dependency_source_type"]
        or not _dependency_source_matches_parent(source, dependent)
    ):
        return None, "resolved dependency source does not match the protected parent"

    key_facts = azure_facts(key)
    vault_address = key_facts.resolved_key_vault_address
    vault = context.index.resources_by_address.get(vault_address) if vault_address is not None else None
    vault_facts = azure_facts(vault) if vault is not None else None
    if (
        vault is None
        or vault.provider != "azure"
        or vault.resource_type != AzureResourceType.KEY_VAULT
        or dependency["key_vault_address"] != vault.address
        or not _same_identifier(
            dependency["key_vault_id"],
            vault_facts.key_vault_id if vault_facts is not None else None,
        )
        or not _same_identifier(
            dependency["key_vault_uri"],
            vault_facts.key_vault_uri if vault_facts is not None else None,
        )
        or dependency["key_name"] != key_facts.key_vault_key_name
        or not _dependency_target_matches_key(dependency, key)
        or not _dependency_reference_contract_is_coherent(dependency, key)
    ):
        return None, "resolved dependency key or vault identity is internally inconsistent"
    return key, None


def _dependency_source_matches_parent(
    source: NormalizedResource,
    dependent: NormalizedResource,
) -> bool:
    if dependent.resource_type == AzureResourceType.STORAGE_ACCOUNT:
        return source.address == dependent.address
    if dependent.resource_type != AzureResourceType.SERVICE_BUS_NAMESPACE:
        return False
    if source.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE:
        return source.address == dependent.address
    return bool(
        source.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE_CUSTOMER_MANAGED_KEY
        and azure_facts(source).resolved_service_bus_namespace_address == dependent.address
    )


def _dependency_target_matches_key(
    dependency: AzureKeyVaultEncryptionDependency,
    key: NormalizedResource,
) -> bool:
    facts = azure_facts(key)
    if not _same_identifier(
        dependency["key_versionless_uri"],
        facts.key_vault_key_versionless_uri,
    ) or not _optional_identifiers_agree(
        dependency["key_versionless_resource_id"],
        facts.key_vault_key_versionless_resource_id,
    ):
        return False
    if dependency["target_kind"] == "key":
        return True
    return bool(
        dependency["target_kind"] == "key_version"
        and _same_identifier(dependency["key_uri"], facts.key_vault_key_uri)
        and _optional_identifiers_agree(
            dependency["key_resource_id"],
            facts.key_vault_key_resource_id,
        )
        and dependency["key_version"] == facts.key_vault_key_version
    )


def _dependency_reference_contract_is_coherent(
    dependency: AzureKeyVaultEncryptionDependency,
    key: NormalizedResource,
) -> bool:
    configured = dependency["configured_key_reference"]
    target_kind = dependency["target_kind"]
    provenance = dependency["reference_provenance"]
    reference_kind = dependency["reference_kind"]
    if configured is None or target_kind not in {"key", "key_version"}:
        return False
    if provenance == "planned_value":
        if target_kind == "key":
            return bool(
                reference_kind == "versionless_uri"
                and _same_identifier(
                    configured,
                    dependency["key_versionless_uri"],
                )
            )
        return bool(reference_kind == "versioned_uri" and _same_identifier(configured, dependency["key_uri"]))
    if provenance != "configuration_reference" or reference_kind != "terraform_reference":
        return False
    if target_kind == "key":
        return configured == f"{key.address}.versionless_id"
    return configured == f"{key.address}.id"


def _matching_plaintext_paths(
    workload: NormalizedResource,
    identity_address: str,
    identity_kind: AzureKeyVaultRuntimeIdentityKind,
    principal_id: str | None,
    key: NormalizedResource,
    dependency: AzureKeyVaultEncryptionDependency,
    context: AzureDecorationContext,
) -> list[AzureAppServiceKeyVaultOperationPath]:
    if principal_id is None:
        return []
    paths = [
        path
        for path in azure_facts(workload).app_service_key_vault_operation_paths
        if path["operation"] in _PLAINTEXT_OPERATIONS
        and _deterministic_plaintext_path(
            path,
            workload,
            identity_address,
            identity_kind,
            principal_id,
            key,
            dependency,
            context,
        )
    ]
    return sorted(
        paths,
        key=lambda path: (
            path["operation"],
            path["grant_source_address"],
            path["scope_type"],
            path["scope_arm_id"] or "",
        ),
    )


def _deterministic_plaintext_path(
    path: AzureAppServiceKeyVaultOperationPath,
    workload: NormalizedResource,
    identity_address: str,
    identity_kind: AzureKeyVaultRuntimeIdentityKind,
    principal_id: str,
    key: NormalizedResource,
    dependency: AzureKeyVaultEncryptionDependency,
    context: AzureDecorationContext,
) -> bool:
    operation = path["operation"]
    if operation not in _PLAINTEXT_OPERATIONS:
        return False
    plaintext_operation = operation
    expected_key_operation = _EXPECTED_KEY_OPERATION[plaintext_operation]
    grant_source = context.index.resources_by_address.get(path["grant_source_address"])
    key_facts = azure_facts(key)
    grant = path["authorization_grant_record"]
    return bool(
        path["workload_address"] == workload.address
        and path["workload_type"] == workload.resource_type
        and path["identity_address"] == identity_address
        and path["identity_kind"] == identity_kind
        and _same_identifier(path["principal_id"], principal_id)
        and _runtime_identity_matches(
            workload,
            identity_address,
            identity_kind,
            principal_id,
            context,
        )
        and path["credential_context"] == "workload_runtime"
        and path["key_address"] == key.address
        and path["key_resource_type"] == key.resource_type
        and path["key_vault_address"] == key_facts.resolved_key_vault_address
        and path["key_name"] == key_facts.key_vault_key_name
        and path["key_identity_state"] == key_facts.key_vault_key_identity_state
        and _optional_identifiers_agree(path["key_uri"], key_facts.key_vault_key_uri)
        and _same_identifier(
            path["key_versionless_uri"],
            key_facts.key_vault_key_versionless_uri,
        )
        and _optional_identifiers_agree(
            path["key_resource_id"],
            key_facts.key_vault_key_resource_id,
        )
        and _optional_identifiers_agree(
            path["key_versionless_resource_id"],
            key_facts.key_vault_key_versionless_resource_id,
        )
        and path["key_version"] == key_facts.key_vault_key_version
        and path["operation_class"] == "plaintext_recovery"
        and path["matched_key_operation"] == expected_key_operation
        and expected_key_operation.casefold() in {value.casefold() for value in path["key_operations"]}
        and path["authorization_model_state"] == "active"
        and path["authorization_state"] == "granted"
        and path["condition"] is None
        and path["condition_state"] == "not_configured"
        and path["condition_applicability_state"] == "not_configured"
        and grant_source is not None
        and grant_source.provider == "azure"
        and grant_source.resource_type == path["grant_source_type"]
        and grant["grant_source_address"] == path["grant_source_address"]
        and grant["authorization_state"] == "granted"
        and grant["condition_state"] == "not_configured"
        and grant["key_address"] == key.address
        and _same_identifier(grant["principal_id"], principal_id)
        and _dependency_matches_operation_path(dependency, path)
    )


def _dependency_matches_operation_path(
    dependency: AzureKeyVaultEncryptionDependency,
    path: AzureAppServiceKeyVaultOperationPath,
) -> bool:
    if (
        dependency["key_address"] != path["key_address"]
        or dependency["key_vault_address"] != path["key_vault_address"]
        or not _same_identifier(
            dependency["key_versionless_uri"],
            path["key_versionless_uri"],
        )
        or not _optional_identifiers_agree(
            dependency["key_versionless_resource_id"],
            path["key_versionless_resource_id"],
        )
    ):
        return False
    if dependency["target_kind"] == "key":
        return True
    return bool(
        dependency["target_kind"] == "key_version"
        and _same_identifier(dependency["key_uri"], path["key_uri"])
        and _optional_identifiers_agree(
            dependency["key_resource_id"],
            path["key_resource_id"],
        )
        and dependency["key_version"] == path["key_version"]
    )


def _append_operation_uncertainties(
    workload: NormalizedResource,
    key: NormalizedResource,
    path_uncertainties: Sequence[str],
    uncertainties: list[str],
) -> None:
    uncertainties.extend(
        f"{workload.address}: plaintext-recovery authority for {key.address} is unresolved: {uncertainty}"
        for uncertainty in path_uncertainties
    )


def _storage_convergence_record(
    workload: NormalizedResource,
    access_path: AzureAppServiceStorageAccessPath,
    operation_path: AzureAppServiceKeyVaultOperationPath,
    dependency: AzureKeyVaultEncryptionDependency,
) -> AzureAppServiceStorageProtectedDataConvergence:
    principal_id = access_path["principal_id"]
    account_address = access_path["storage_account_address"]
    account_id = access_path["storage_account_id"]
    versionless_uri = dependency["key_versionless_uri"]
    assert principal_id is not None
    assert account_address is not None
    assert account_id is not None
    assert versionless_uri is not None
    return {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "identity_address": access_path["identity_address"],
        "identity_kind": access_path["identity_kind"],
        "principal_id": principal_id,
        "storage_resource_address": access_path["storage_resource_address"],
        "storage_account_address": account_address,
        "storage_account_id": account_id,
        "key_address": operation_path["key_address"],
        "key_uri": (dependency["key_uri"] if dependency["target_kind"] == "key_version" else None),
        "key_versionless_uri": versionless_uri,
        "operation": cast(
            Literal["decrypt", "unwrap"],
            operation_path["operation"],
        ),
        "access_class": "read",
        "runtime_identity_match": True,
        "protected_resource_match": True,
        "key_identity_match": True,
        "convergence_state": "resolved",
        "evaluation_basis": ("exact_storage_access_key_vault_dependency_and_plaintext_recovery_authority"),
        "access_path": access_path.copy(),
        "key_operation_path": operation_path.copy(),
        "encryption_dependency": dependency.copy(),
        "posture_uncertainties": [],
    }


def _service_bus_convergence_record(
    workload: NormalizedResource,
    access_path: AzureAppServiceServiceBusAccessPath,
    operation_path: AzureAppServiceKeyVaultOperationPath,
    dependency: AzureKeyVaultEncryptionDependency,
) -> AzureAppServiceServiceBusProtectedDataConvergence:
    principal_id = access_path["principal_id"]
    namespace_address = access_path["service_bus_namespace_address"]
    namespace_id = access_path["service_bus_namespace_id"]
    versionless_uri = dependency["key_versionless_uri"]
    assert principal_id is not None
    assert namespace_address is not None
    assert namespace_id is not None
    assert versionless_uri is not None
    return {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "identity_address": access_path["identity_address"],
        "identity_kind": access_path["identity_kind"],
        "principal_id": principal_id,
        "service_bus_resource_address": access_path["service_bus_resource_address"],
        "service_bus_resource_type": access_path["service_bus_resource_type"],
        "service_bus_namespace_address": namespace_address,
        "service_bus_namespace_id": namespace_id,
        "key_address": operation_path["key_address"],
        "key_uri": (dependency["key_uri"] if dependency["target_kind"] == "key_version" else None),
        "key_versionless_uri": versionless_uri,
        "operation": cast(
            Literal["decrypt", "unwrap"],
            operation_path["operation"],
        ),
        "access_class": "receive",
        "runtime_identity_match": True,
        "protected_resource_match": True,
        "key_identity_match": True,
        "convergence_state": "resolved",
        "evaluation_basis": ("exact_service_bus_receive_key_vault_dependency_and_plaintext_recovery_authority"),
        "access_path": access_path.copy(),
        "key_operation_path": operation_path.copy(),
        "encryption_dependency": dependency.copy(),
        "posture_uncertainties": [],
    }


def _dedupe_storage_convergences(
    values: Sequence[AzureAppServiceStorageProtectedDataConvergence],
) -> list[AzureAppServiceStorageProtectedDataConvergence]:
    seen: set[tuple[str, str, str, str, str, str]] = set()
    result: list[AzureAppServiceStorageProtectedDataConvergence] = []
    for value in values:
        fingerprint = (
            value["identity_address"],
            value["storage_resource_address"],
            value["key_address"],
            value["operation"],
            value["access_path"]["role_assignment_address"],
            value["key_operation_path"]["grant_source_address"],
        )
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        result.append(value)
    return sorted(
        result,
        key=lambda value: (
            value["storage_resource_address"],
            value["key_address"],
            value["operation"],
            value["identity_address"],
        ),
    )


def _dedupe_service_bus_convergences(
    values: Sequence[AzureAppServiceServiceBusProtectedDataConvergence],
) -> list[AzureAppServiceServiceBusProtectedDataConvergence]:
    seen: set[tuple[str, str, str, str, str, str]] = set()
    result: list[AzureAppServiceServiceBusProtectedDataConvergence] = []
    for value in values:
        fingerprint = (
            value["identity_address"],
            value["service_bus_resource_address"],
            value["key_address"],
            value["operation"],
            value["access_path"]["role_assignment_address"],
            value["key_operation_path"]["grant_source_address"],
        )
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        result.append(value)
    return sorted(
        result,
        key=lambda value: (
            value["service_bus_resource_address"],
            value["key_address"],
            value["operation"],
            value["identity_address"],
        ),
    )


def _service_bus_resource_id(resource: NormalizedResource) -> str | None:
    facts = azure_facts(resource)
    if resource.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE:
        return facts.service_bus_namespace_id
    return facts.service_bus_entity_id


def _same_identifier(left: str | None, right: str | None) -> bool:
    return bool(left and right and left.strip().rstrip("/").casefold() == right.strip().rstrip("/").casefold())


def _optional_identifiers_agree(left: str | None, right: str | None) -> bool:
    if left is None and right is None:
        return True
    return _same_identifier(left, right)
