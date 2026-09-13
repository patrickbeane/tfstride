from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from tfstride.models import NormalizedResource
from tfstride.providers.azure.key_vault_evidence import (
    AzureKeyVaultRuntimeIdentityKind,
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
from tfstride.providers.azure.structured_data_deletion_evidence import (
    AzureAppServiceCosmosDbAccountItemDeletionPath,
    AzureAppServiceCosmosDbContainerItemDeletionPath,
    AzureAppServiceCosmosDbDatabaseItemDeletionPath,
    AzureAppServiceCosmosDbItemDeletionPath,
    AzureAppServiceCosmosDbItemDeletionPathCommon,
    AzureCosmosDbItemDeletionRecoveryEvidence,
)
from tfstride.providers.coercion import (
    STATE_CONFIGURED,
    STATE_NOT_CONFIGURED,
    dedupe,
    dedupe_strings,
)

_ITEM_DELETE: Literal["Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/delete"] = (
    "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/delete"
)
_ITEM_DELETE_CASEFOLDED = _ITEM_DELETE.casefold()


@dataclass(frozen=True, slots=True)
class _CosmosDbTarget:
    target: NormalizedResource
    account: NormalizedResource
    database: NormalizedResource | None
    container: NormalizedResource | None


class ModelAppServiceCosmosDbItemDeletionPathsStage:
    """Project deterministic Cosmos DB item-deletion authority onto App Services."""

    name = "model_app_service_cosmosdb_item_deletion_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AzureDecorationContext,
    ) -> None:
        for workload in resources:
            if workload.resource_type not in AZURE_APP_SERVICE_RESOURCE_TYPES:
                continue
            paths, uncertainties = _app_service_cosmosdb_item_deletion_paths(
                workload,
                context,
            )
            facts = azure_facts(workload)
            facts.set_app_service_cosmosdb_item_deletion_paths(paths)
            facts.extend_app_service_cosmosdb_item_deletion_path_uncertainties(
                uncertainties,
            )


def _app_service_cosmosdb_item_deletion_paths(
    workload: NormalizedResource,
    context: AzureDecorationContext,
) -> tuple[list[AzureAppServiceCosmosDbItemDeletionPath], list[str]]:
    facts = azure_facts(workload)
    current_identities = _current_workload_identities(workload, context)
    paths: list[AzureAppServiceCosmosDbItemDeletionPath] = []
    uncertainties = list(facts.app_service_cosmosdb_access_path_uncertainties)

    for access_path in facts.app_service_cosmosdb_access_paths:
        if not _access_path_allows_item_deletion(access_path):
            continue
        path, uncertainty = _item_deletion_path(
            workload,
            access_path,
            current_identities,
            context,
        )
        if uncertainty is not None:
            uncertainties.append(f"{workload.address}: {uncertainty}")
        if path is not None:
            paths.append(path)

    paths.sort(
        key=lambda path: (
            path["cosmosdb_account_address"],
            path["cosmosdb_resource_address"],
            path["identity_address"],
            path["role_assignment_address"],
        )
    )
    return _dedupe_paths(paths), dedupe(uncertainties)


def _current_workload_identities(
    workload: NormalizedResource,
    context: AzureDecorationContext,
) -> dict[str, tuple[AzureKeyVaultRuntimeIdentityKind, str]]:
    identities, _uncertainties = workload_managed_identities(workload, context)
    result: dict[str, tuple[AzureKeyVaultRuntimeIdentityKind, str]] = {}
    for identity, identity_kind in identities:
        principal_id = _known_string(azure_facts(identity).principal_id)
        typed_kind = _identity_kind(identity_kind)
        if principal_id is not None and typed_kind is not None:
            result[identity.address] = (typed_kind, principal_id)
    return result


def _access_path_allows_item_deletion(
    access_path: Mapping[str, Any],
) -> bool:
    return any(
        action.casefold() == _ITEM_DELETE_CASEFOLDED
        for action in _string_values(access_path.get("matched_data_actions"))
    )


def _item_deletion_path(
    workload: NormalizedResource,
    access_path: Mapping[str, Any],
    current_identities: Mapping[
        str,
        tuple[AzureKeyVaultRuntimeIdentityKind, str],
    ],
    context: AzureDecorationContext,
) -> tuple[AzureAppServiceCosmosDbItemDeletionPath | None, str | None]:
    if (
        access_path.get("workload_address") != workload.address
        or access_path.get("workload_type") != workload.resource_type
        or access_path.get("credential_context") != "workload_runtime"
        or access_path.get("access_state") != "granted"
        or access_path.get("authorization_model") != "cosmosdb_for_nosql_native_rbac"
        or access_path.get("grant_basis") != "cosmosdb_for_nosql_native_role_assignment"
        or access_path.get("evaluation_basis") != "modeled_native_rbac_assignment"
        or access_path.get("assignment_scope_state") != "resolved"
        or access_path.get("assignable_scope_compatibility_state") != "resolved"
    ):
        return None, "Cosmos DB item-deletion access path is no longer deterministic"

    identity_address = _known_string(access_path.get("identity_address"))
    principal_id = _known_string(access_path.get("principal_id"))
    identity_kind = _identity_kind(access_path.get("identity_kind"))
    current_identity = current_identities.get(identity_address or "")
    if (
        identity_address is None
        or principal_id is None
        or identity_kind is None
        or current_identity is None
        or current_identity[0] != identity_kind
        or not _same_identifier(current_identity[1], principal_id)
    ):
        return None, "Cosmos DB item-deletion access path has no exact current runtime identity"

    target, target_uncertainty = _current_target(access_path, context)
    if target is None:
        return None, target_uncertainty

    role_assignment_address = _known_string(access_path.get("role_assignment_address"))
    role_definition_reference = _known_string(access_path.get("role_definition_reference"))
    assignment_scope = _known_string(access_path.get("assignment_scope"))
    role_kind = _deletion_role_kind(access_path.get("role_kind"))
    if (
        role_assignment_address is None
        or role_definition_reference is None
        or assignment_scope is None
        or role_kind is None
    ):
        return None, "Cosmos DB item-deletion authorization evidence is incomplete"

    assignment = context.index.resolve(
        role_assignment_address,
        source=workload,
        resource_types={AzureResourceType.COSMOSDB_SQL_ROLE_ASSIGNMENT},
    )
    if assignment is None or assignment.resource_type != AzureResourceType.COSMOSDB_SQL_ROLE_ASSIGNMENT:
        return None, "Cosmos DB item-deletion role assignment is unavailable"

    role_definition_address = _known_string(access_path.get("role_definition_address"))
    if role_kind == "custom":
        role_definition = context.index.resolve(
            role_definition_address,
            source=assignment,
            resource_types={AzureResourceType.COSMOSDB_SQL_ROLE_DEFINITION},
        )
        if role_definition is None or role_definition.resource_type != AzureResourceType.COSMOSDB_SQL_ROLE_DEFINITION:
            return None, "custom Cosmos DB item-deletion role definition is unavailable"
    elif role_definition_address is not None:
        return (
            None,
            "built-in Cosmos DB item-deletion evidence names a custom role definition",
        )

    account_id = _known_string(azure_facts(target.account).cosmosdb_account_id)
    if account_id is None:
        return None, "Cosmos DB item-deletion target account identity is unresolved"

    recovery_evidence = _recovery_evidence(target.account)
    common: AzureAppServiceCosmosDbItemDeletionPathCommon = {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "identity_address": identity_address,
        "identity_kind": identity_kind,
        "principal_id": principal_id,
        "credential_context": "workload_runtime",
        "cosmosdb_account_address": target.account.address,
        "cosmosdb_account_id": account_id,
        "operation": _ITEM_DELETE,
        "operation_class": "item_deletion",
        "management_effect": "disruption",
        "role_assignment_address": role_assignment_address,
        "role_assignment_id": _known_string(access_path.get("role_assignment_id")),
        "role_definition_reference": role_definition_reference,
        "role_definition_address": role_definition_address,
        "role_definition_name": _known_string(access_path.get("role_definition_name")),
        "role_kind": role_kind,
        "role_data_actions": _string_values(access_path.get("role_data_actions")),
        "matched_data_actions": [_ITEM_DELETE],
        "grant_basis": "cosmosdb_for_nosql_native_role_assignment",
        "evaluation_basis": "modeled_native_rbac_assignment",
        "authorization_source_addresses": dedupe_strings([role_assignment_address, role_definition_address]),
        "assignment_scope": assignment_scope,
        "assignment_scope_state": "resolved",
        "assignable_scope_compatibility_state": "resolved",
        "authorization_state": "granted",
        "policy_complete": True,
        "authorization_model": "cosmosdb_for_nosql_native_rbac",
        "lifecycle_compatibility_state": "not_applicable",
        "recovery_evidence": recovery_evidence,
        "posture_uncertainties": list(recovery_evidence["uncertainties"]),
    }
    return _scoped_path(common, target), None


def _current_target(
    access_path: Mapping[str, Any],
    context: AzureDecorationContext,
) -> tuple[_CosmosDbTarget | None, str | None]:
    account_address = _known_string(access_path.get("cosmosdb_account_address"))
    account = context.index.resolve(
        account_address,
        resource_types={AzureResourceType.COSMOSDB_ACCOUNT},
    )
    if (
        account is None
        or account.resource_type != AzureResourceType.COSMOSDB_ACCOUNT
        or not _same_identifier(
            azure_facts(account).cosmosdb_account_id,
            _known_string(access_path.get("cosmosdb_account_id")),
        )
    ):
        return None, "Cosmos DB item-deletion path has unresolved account ancestry"

    scope_type = access_path.get("scope_type")
    database: NormalizedResource | None = None
    container: NormalizedResource | None = None
    if scope_type in {"database", "container"}:
        database_address = _known_string(access_path.get("cosmosdb_database_address"))
        database = context.index.resolve(
            database_address,
            source=account,
            resource_types={AzureResourceType.COSMOSDB_SQL_DATABASE},
        )
        if (
            database is None
            or database.resource_type != AzureResourceType.COSMOSDB_SQL_DATABASE
            or azure_facts(database).resolved_cosmosdb_account_address != account.address
            or not _same_identifier(
                azure_facts(database).cosmosdb_sql_database_id,
                _known_string(access_path.get("cosmosdb_database_id")),
            )
            or azure_facts(database).cosmosdb_sql_database_name != access_path.get("cosmosdb_database_name")
        ):
            return None, "Cosmos DB item-deletion path has unresolved database ancestry"

    if scope_type == "container":
        container_address = _known_string(access_path.get("cosmosdb_container_address"))
        container = context.index.resolve(
            container_address,
            source=database,
            resource_types={AzureResourceType.COSMOSDB_SQL_CONTAINER},
        )
        if (
            database is None
            or container is None
            or container.resource_type != AzureResourceType.COSMOSDB_SQL_CONTAINER
            or azure_facts(container).resolved_cosmosdb_account_address != account.address
            or azure_facts(container).resolved_cosmosdb_database_address != database.address
            or not _same_identifier(
                azure_facts(container).cosmosdb_sql_container_id,
                _known_string(access_path.get("cosmosdb_container_id")),
            )
            or azure_facts(container).cosmosdb_sql_container_name != access_path.get("cosmosdb_container_name")
        ):
            return None, "Cosmos DB item-deletion path has unresolved container ancestry"

    if scope_type == "account":
        target = account
    elif scope_type == "database" and database is not None:
        target = database
    elif scope_type == "container" and container is not None:
        target = container
    else:
        return None, "Cosmos DB item-deletion path has unsupported target scope"
    if (
        access_path.get("cosmosdb_resource_address") != target.address
        or access_path.get("cosmosdb_resource_type") != target.resource_type
        or not _same_identifier(
            _cosmosdb_resource_id(target),
            _known_string(access_path.get("cosmosdb_resource_id")),
        )
        or access_path.get("resource_scope") != _target_scope(target)
    ):
        return None, "Cosmos DB item-deletion path does not retain its exact target"
    return _CosmosDbTarget(target, account, database, container), None


def _scoped_path(
    common: AzureAppServiceCosmosDbItemDeletionPathCommon,
    target: _CosmosDbTarget,
) -> AzureAppServiceCosmosDbItemDeletionPath:
    target_addresses = [target.account.address]
    if target.database is not None:
        target_addresses.append(target.database.address)
    if target.container is not None:
        target_addresses.append(target.container.address)

    if target.container is not None and target.database is not None:
        database_facts = azure_facts(target.database)
        container_facts = azure_facts(target.container)
        path: AzureAppServiceCosmosDbContainerItemDeletionPath = {
            **common,
            "scope_type": "container",
            "target_granularity": "container_item_namespace",
            "target_scope": "exact_cosmosdb_for_nosql_container",
            "target_model_evidence_addresses": target_addresses,
            "cosmosdb_resource_address": target.container.address,
            "cosmosdb_resource_type": target.container.resource_type,
            "cosmosdb_resource_id": _required_resource_id(target.container),
            "cosmosdb_database_address": target.database.address,
            "cosmosdb_database_id": _required_resource_id(target.database),
            "cosmosdb_database_name": _required_string(database_facts.cosmosdb_sql_database_name),
            "cosmosdb_container_address": target.container.address,
            "cosmosdb_container_id": _required_resource_id(target.container),
            "cosmosdb_container_name": _required_string(container_facts.cosmosdb_sql_container_name),
        }
        return path

    if target.database is not None:
        database_facts = azure_facts(target.database)
        database_path: AzureAppServiceCosmosDbDatabaseItemDeletionPath = {
            **common,
            "scope_type": "database",
            "target_granularity": "database_item_namespace",
            "target_scope": "exact_cosmosdb_for_nosql_database",
            "target_model_evidence_addresses": target_addresses,
            "cosmosdb_resource_address": target.database.address,
            "cosmosdb_resource_type": target.database.resource_type,
            "cosmosdb_resource_id": _required_resource_id(target.database),
            "cosmosdb_database_address": target.database.address,
            "cosmosdb_database_id": _required_resource_id(target.database),
            "cosmosdb_database_name": _required_string(database_facts.cosmosdb_sql_database_name),
            "cosmosdb_container_address": None,
            "cosmosdb_container_id": None,
            "cosmosdb_container_name": None,
        }
        return database_path

    account_path: AzureAppServiceCosmosDbAccountItemDeletionPath = {
        **common,
        "scope_type": "account",
        "target_granularity": "account_item_namespace",
        "target_scope": "exact_cosmosdb_for_nosql_account",
        "target_model_evidence_addresses": target_addresses,
        "cosmosdb_resource_address": target.account.address,
        "cosmosdb_resource_type": target.account.resource_type,
        "cosmosdb_resource_id": _required_resource_id(target.account),
        "cosmosdb_database_address": None,
        "cosmosdb_database_id": None,
        "cosmosdb_database_name": None,
        "cosmosdb_container_address": None,
        "cosmosdb_container_id": None,
        "cosmosdb_container_name": None,
    }
    return account_path


def _recovery_evidence(
    account: NormalizedResource,
) -> AzureCosmosDbItemDeletionRecoveryEvidence:
    facts = azure_facts(account)
    uncertainties = [
        uncertainty for uncertainty in facts.cosmosdb_posture_uncertainties if uncertainty.startswith("backup")
    ]
    configuration_state = facts.cosmosdb_backup_configuration_state
    backup_type = _known_string(facts.cosmosdb_backup_type)

    if configuration_state == STATE_NOT_CONFIGURED:
        return {
            "recovery_evidence_scope": "cosmosdb_backup_policy",
            "backup_posture_state": "provider_default_periodic",
            "backup_configuration_state": "not_configured",
            "backup_type": "Periodic",
            "backup_tier": None,
            "backup_interval_minutes": 240,
            "backup_retention_hours": 8,
            "backup_storage_redundancy": "Geo",
            "uncertainties": uncertainties,
        }

    if configuration_state == STATE_CONFIGURED and backup_type is not None and backup_type.casefold() == "continuous":
        return {
            "recovery_evidence_scope": "cosmosdb_backup_policy",
            "backup_posture_state": "continuous",
            "backup_configuration_state": "configured",
            "backup_type": "Continuous",
            "backup_tier": _known_string(facts.cosmosdb_backup_tier),
            "backup_interval_minutes": None,
            "backup_retention_hours": None,
            "backup_storage_redundancy": None,
            "uncertainties": uncertainties,
        }

    if (
        configuration_state == STATE_CONFIGURED
        and backup_type is not None
        and backup_type.casefold() == "periodic"
        and facts.cosmosdb_backup_tier is None
    ):
        return {
            "recovery_evidence_scope": "cosmosdb_backup_policy",
            "backup_posture_state": "periodic",
            "backup_configuration_state": "configured",
            "backup_type": "Periodic",
            "backup_tier": None,
            "backup_interval_minutes": facts.cosmosdb_backup_interval_minutes,
            "backup_retention_hours": facts.cosmosdb_backup_retention_hours,
            "backup_storage_redundancy": _known_string(facts.cosmosdb_backup_storage_redundancy),
            "uncertainties": uncertainties,
        }

    return {
        "recovery_evidence_scope": "cosmosdb_backup_policy",
        "backup_posture_state": "unknown",
        "backup_configuration_state": ("configured" if configuration_state == STATE_CONFIGURED else "unknown"),
        "backup_type": backup_type,
        "backup_tier": _known_string(facts.cosmosdb_backup_tier),
        "backup_interval_minutes": facts.cosmosdb_backup_interval_minutes,
        "backup_retention_hours": facts.cosmosdb_backup_retention_hours,
        "backup_storage_redundancy": _known_string(facts.cosmosdb_backup_storage_redundancy),
        "uncertainties": uncertainties,
    }


def _identity_kind(value: object) -> AzureKeyVaultRuntimeIdentityKind | None:
    if value == "system_assigned":
        return "system_assigned"
    if value == "user_assigned":
        return "user_assigned"
    return None


def _deletion_role_kind(
    value: object,
) -> Literal["built_in_data_contributor", "custom"] | None:
    if value == "built_in_data_contributor":
        return "built_in_data_contributor"
    if value == "custom":
        return "custom"
    return None


def _cosmosdb_resource_id(resource: NormalizedResource) -> str | None:
    facts = azure_facts(resource)
    if resource.resource_type == AzureResourceType.COSMOSDB_ACCOUNT:
        return _known_string(facts.cosmosdb_account_id)
    if resource.resource_type == AzureResourceType.COSMOSDB_SQL_DATABASE:
        return _known_string(facts.cosmosdb_sql_database_id)
    if resource.resource_type == AzureResourceType.COSMOSDB_SQL_CONTAINER:
        return _known_string(facts.cosmosdb_sql_container_id)
    return None


def _required_resource_id(resource: NormalizedResource) -> str:
    value = _cosmosdb_resource_id(resource)
    assert value is not None
    return value


def _required_string(value: object) -> str:
    result = _known_string(value)
    assert result is not None
    return result


def _target_scope(resource: NormalizedResource) -> str:
    if resource.resource_type == AzureResourceType.COSMOSDB_SQL_DATABASE:
        return "exact_cosmosdb_for_nosql_database"
    if resource.resource_type == AzureResourceType.COSMOSDB_SQL_CONTAINER:
        return "exact_cosmosdb_for_nosql_container"
    return "exact_cosmosdb_for_nosql_account"


def _same_identifier(left: str | None, right: str | None) -> bool:
    return bool(left and right and left.strip().rstrip("/").casefold() == right.strip().rstrip("/").casefold())


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item.strip()]


def _dedupe_paths(
    paths: Sequence[AzureAppServiceCosmosDbItemDeletionPath],
) -> list[AzureAppServiceCosmosDbItemDeletionPath]:
    result: list[AzureAppServiceCosmosDbItemDeletionPath] = []
    for path in paths:
        if path not in result:
            result.append(path)
    return result
