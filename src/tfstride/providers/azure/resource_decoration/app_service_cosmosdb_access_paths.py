from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.azure.resource_decoration.workload_identities import workload_managed_identities
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import AZURE_APP_SERVICE_RESOURCE_TYPES, AzureResourceType
from tfstride.providers.coercion import dedupe

_ACCESS_CLASS_ORDER = (
    "metadata_read",
    "read",
    "entity_write",
    "entity_delete",
    "stored_procedure_execution",
    "conflict_management",
)
_CONTAINER_WILDCARD = "microsoft.documentdb/databaseaccounts/sqldatabases/containers/*"
_ITEM_WILDCARD = "microsoft.documentdb/databaseaccounts/sqldatabases/containers/items/*"


@dataclass(frozen=True, slots=True)
class _CosmosDbDataAction:
    name: str
    access_classes: tuple[str, ...]
    wildcard_level: str | None = None


_COSMOSDB_DATA_ACTIONS = (
    _CosmosDbDataAction(
        "Microsoft.DocumentDB/databaseAccounts/readMetadata",
        ("metadata_read",),
    ),
    _CosmosDbDataAction(
        "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/create",
        ("entity_write",),
        "item",
    ),
    _CosmosDbDataAction(
        "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/read",
        ("read",),
        "item",
    ),
    _CosmosDbDataAction(
        "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/replace",
        ("entity_write",),
        "item",
    ),
    _CosmosDbDataAction(
        "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/upsert",
        ("entity_write",),
        "item",
    ),
    _CosmosDbDataAction(
        "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/delete",
        ("entity_delete",),
        "item",
    ),
    _CosmosDbDataAction(
        "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/unmask",
        ("read",),
        "item",
    ),
    _CosmosDbDataAction(
        "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/executeQuery",
        ("read",),
        "container",
    ),
    _CosmosDbDataAction(
        "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/readChangeFeed",
        ("read",),
        "container",
    ),
    _CosmosDbDataAction(
        "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/executeStoredProcedure",
        ("stored_procedure_execution",),
        "container",
    ),
    _CosmosDbDataAction(
        "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/manageConflicts",
        ("conflict_management",),
        "container",
    ),
)


@dataclass(frozen=True, slots=True)
class _CosmosDbScopeTarget:
    target: NormalizedResource
    account: NormalizedResource
    database: NormalizedResource | None = None
    container: NormalizedResource | None = None


class ModelAppServiceCosmosDbAccessPathsStage:
    name = "model_app_service_cosmosdb_access_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AzureDecorationContext,
    ) -> None:
        assignments = tuple(
            resource
            for resource in resources
            if resource.resource_type == AzureResourceType.COSMOSDB_SQL_ROLE_ASSIGNMENT
        )
        for workload in resources:
            if workload.resource_type not in AZURE_APP_SERVICE_RESOURCE_TYPES:
                continue
            paths, uncertainties = _app_service_cosmosdb_access_paths(
                workload,
                assignments,
                context,
            )
            facts = azure_facts(workload)
            facts.set_app_service_cosmosdb_access_paths(paths)
            facts.extend_app_service_cosmosdb_access_path_uncertainties(uncertainties)


def _app_service_cosmosdb_access_paths(
    workload: NormalizedResource,
    assignments: tuple[NormalizedResource, ...],
    context: AzureDecorationContext,
) -> tuple[list[dict[str, Any]], list[str]]:
    workload_facts = azure_facts(workload)
    identities, identity_uncertainties = workload_managed_identities(workload, context)
    uncertainties = [
        *identity_uncertainties,
        *[f"{workload.address}: {value}" for value in workload_facts.managed_identity_uncertainties],
    ]
    paths: list[dict[str, Any]] = []

    for assignment in assignments:
        if azure_facts(assignment).cosmosdb_sql_principal_id is None:
            uncertainties.append(f"{workload.address}: {assignment.address} native RBAC principal is unresolved")

    for identity, identity_kind in identities:
        principal_id = azure_facts(identity).principal_id
        for assignment in assignments:
            assignment_facts = azure_facts(assignment)
            if not _same_identifier(
                assignment_facts.cosmosdb_sql_principal_id,
                principal_id,
            ):
                continue
            uncertainties.extend(
                f"{workload.address}: {value}" for value in assignment_facts.cosmosdb_sql_rbac_uncertainties
            )
            path, path_uncertainty = _access_path_record(
                workload,
                identity,
                identity_kind,
                assignment,
                context,
            )
            if path_uncertainty:
                uncertainties.append(f"{workload.address}: {assignment.address} {path_uncertainty}")
            if path is not None:
                paths.append(path)

    paths = _dedupe_dicts(paths)
    paths.sort(
        key=lambda path: (
            str(path["cosmosdb_resource_address"]),
            str(path["role_assignment_address"]),
            str(path["identity_address"]),
        )
    )
    return paths, dedupe(uncertainties)


def _access_path_record(
    workload: NormalizedResource,
    identity: NormalizedResource,
    identity_kind: str,
    assignment: NormalizedResource,
    context: AzureDecorationContext,
) -> tuple[dict[str, Any] | None, str | None]:
    facts = azure_facts(assignment)
    if facts.cosmosdb_sql_role_assignment_scope_state != "resolved":
        return (
            None,
            "native RBAC scope does not resolve to an exact modeled Cosmos DB for NoSQL target",
        )
    if facts.cosmosdb_sql_assignable_scope_compatibility_state != "resolved":
        return None, "native role assignable-scope compatibility is unresolved or outside scope"

    scope_target, target_uncertainty = _scope_target(assignment, context)
    if scope_target is None:
        return None, target_uncertainty

    role_kind = facts.cosmosdb_sql_role_kind
    if role_kind not in {
        "built_in_data_reader",
        "built_in_data_contributor",
        "custom",
    }:
        return None, "native role is unresolved"
    if role_kind == "custom" and not facts.resolved_cosmosdb_sql_role_definition_address:
        return None, "custom native role definition is unresolved"

    role_data_actions = tuple(action.strip() for action in facts.cosmosdb_sql_role_data_actions if action.strip())
    matched_data_actions = _matched_data_actions(role_data_actions)
    if not matched_data_actions:
        return None, None

    identity_facts = azure_facts(identity)
    account_facts = azure_facts(scope_target.account)
    database_facts = azure_facts(scope_target.database) if scope_target.database is not None else None
    container_facts = azure_facts(scope_target.container) if scope_target.container is not None else None
    return (
        {
            "workload_address": workload.address,
            "workload_type": workload.resource_type,
            "identity_address": identity.address,
            "identity_kind": identity_kind,
            "principal_id": identity_facts.principal_id,
            "credential_context": "workload_runtime",
            "cosmosdb_resource_address": scope_target.target.address,
            "cosmosdb_resource_type": scope_target.target.resource_type,
            "cosmosdb_resource_id": _cosmosdb_resource_id(scope_target.target),
            "cosmosdb_account_address": scope_target.account.address,
            "cosmosdb_account_id": account_facts.cosmosdb_account_id,
            "cosmosdb_database_address": (scope_target.database.address if scope_target.database is not None else None),
            "cosmosdb_database_id": (database_facts.cosmosdb_sql_database_id if database_facts is not None else None),
            "cosmosdb_database_name": (
                database_facts.cosmosdb_sql_database_name if database_facts is not None else None
            ),
            "cosmosdb_container_address": (
                scope_target.container.address if scope_target.container is not None else None
            ),
            "cosmosdb_container_id": (
                container_facts.cosmosdb_sql_container_id if container_facts is not None else None
            ),
            "cosmosdb_container_name": (
                container_facts.cosmosdb_sql_container_name if container_facts is not None else None
            ),
            "role_assignment_address": assignment.address,
            "role_assignment_id": facts.cosmosdb_sql_role_assignment_id,
            "role_definition_reference": facts.cosmosdb_sql_role_definition_reference,
            "role_definition_address": facts.resolved_cosmosdb_sql_role_definition_address,
            "role_definition_name": facts.cosmosdb_sql_role_definition_name,
            "role_kind": role_kind,
            "role_data_actions": list(role_data_actions),
            "matched_data_actions": list(matched_data_actions),
            "access_classes": _access_classes(matched_data_actions),
            "grant_basis": "cosmosdb_for_nosql_native_role_assignment",
            "evaluation_basis": "modeled_native_rbac_assignment",
            "scope_type": facts.cosmosdb_sql_role_assignment_scope_kind,
            "resource_scope": _resource_scope(scope_target.target),
            "assignment_scope": facts.cosmosdb_sql_role_assignment_scope,
            "assignment_scope_state": facts.cosmosdb_sql_role_assignment_scope_state,
            "assignable_scope_compatibility_state": (facts.cosmosdb_sql_assignable_scope_compatibility_state),
            "access_state": "granted",
            "authorization_model": "cosmosdb_for_nosql_native_rbac",
        },
        None,
    )


def _scope_target(
    assignment: NormalizedResource,
    context: AzureDecorationContext,
) -> tuple[_CosmosDbScopeTarget | None, str | None]:
    facts = azure_facts(assignment)
    account = _resolved_resource(
        facts.resolved_cosmosdb_account_address,
        AzureResourceType.COSMOSDB_ACCOUNT,
        context,
    )
    if account is None:
        return None, "resolved Cosmos DB for NoSQL account is unavailable"

    scope_kind = facts.cosmosdb_sql_role_assignment_scope_kind
    if scope_kind == "account":
        return _CosmosDbScopeTarget(account, account), None

    database = _resolved_resource(
        facts.resolved_cosmosdb_database_address,
        AzureResourceType.COSMOSDB_SQL_DATABASE,
        context,
    )
    if database is None or azure_facts(database).resolved_cosmosdb_account_address != account.address:
        return None, "resolved Cosmos DB for NoSQL database ancestry is incomplete"
    if scope_kind == "database":
        return _CosmosDbScopeTarget(database, account, database), None

    container = _resolved_resource(
        facts.resolved_cosmosdb_container_address,
        AzureResourceType.COSMOSDB_SQL_CONTAINER,
        context,
    )
    if (
        scope_kind != "container"
        or container is None
        or azure_facts(container).resolved_cosmosdb_account_address != account.address
        or azure_facts(container).resolved_cosmosdb_database_address != database.address
    ):
        return None, "resolved Cosmos DB for NoSQL container ancestry is incomplete"
    return _CosmosDbScopeTarget(container, account, database, container), None


def _resolved_resource(
    address: str | None,
    resource_type: str,
    context: AzureDecorationContext,
) -> NormalizedResource | None:
    resource = context.index.resolve(
        address,
        resource_types={resource_type},
    )
    if resource is None or resource.address != address or resource.resource_type != resource_type:
        return None
    return resource


def _matched_data_actions(
    permission_patterns: tuple[str, ...],
) -> tuple[str, ...]:
    return tuple(
        action.name
        for action in _COSMOSDB_DATA_ACTIONS
        if any(_action_matches_pattern(action, pattern) for pattern in permission_patterns)
    )


def _action_matches_pattern(
    action: _CosmosDbDataAction,
    pattern: str,
) -> bool:
    normalized = pattern.strip().casefold()
    if normalized == action.name.casefold():
        return True
    if normalized == _CONTAINER_WILDCARD:
        return action.wildcard_level == "container"
    if normalized == _ITEM_WILDCARD:
        return action.wildcard_level == "item"
    return False


def _access_classes(actions: tuple[str, ...]) -> list[str]:
    classes = {
        access_class
        for action in _COSMOSDB_DATA_ACTIONS
        if action.name in actions
        for access_class in action.access_classes
    }
    return [access_class for access_class in _ACCESS_CLASS_ORDER if access_class in classes]


def _cosmosdb_resource_id(resource: NormalizedResource) -> str | None:
    facts = azure_facts(resource)
    if resource.resource_type == AzureResourceType.COSMOSDB_ACCOUNT:
        return facts.cosmosdb_account_id
    if resource.resource_type == AzureResourceType.COSMOSDB_SQL_DATABASE:
        return facts.cosmosdb_sql_database_id
    if resource.resource_type == AzureResourceType.COSMOSDB_SQL_CONTAINER:
        return facts.cosmosdb_sql_container_id
    return None


def _resource_scope(target: NormalizedResource) -> str:
    if target.resource_type == AzureResourceType.COSMOSDB_SQL_DATABASE:
        return "exact_cosmosdb_for_nosql_database"
    if target.resource_type == AzureResourceType.COSMOSDB_SQL_CONTAINER:
        return "exact_cosmosdb_for_nosql_container"
    return "exact_cosmosdb_for_nosql_account"


def _same_identifier(left: str | None, right: str | None) -> bool:
    return bool(left and right and left.strip().casefold() == right.strip().casefold())


def _dedupe_dicts(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result
