from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from tfstride.models import NormalizedResource
from tfstride.providers.azure.arm_control_plane_authorization import (
    AzureArmControlPlaneAuthorityResult,
    azure_arm_scope_contains,
    model_arm_control_plane_action_authority,
)
from tfstride.providers.azure.arm_control_plane_evidence import AzureArmControlPlaneGrant
from tfstride.providers.azure.key_vault_evidence import AzureKeyVaultRuntimeIdentityKind
from tfstride.providers.azure.resource_decoration.workload_identities import (
    workload_managed_identities,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import (
    AZURE_APP_SERVICE_RESOURCE_TYPES,
    AzureResourceType,
)
from tfstride.providers.azure.structured_data_topology_destruction_evidence import (
    AzureAppServiceCosmosDbAccountTopologyDeletionPath,
    AzureAppServiceCosmosDbContainerTopologyDeletionPath,
    AzureAppServiceCosmosDbDatabaseTopologyDeletionPath,
    AzureAppServiceCosmosDbTopologyDestructionPath,
    AzureAppServiceCosmosDbTopologyDestructionPathCommon,
    AzureCosmosDbAccountDeletionAuthorizationGrant,
    AzureCosmosDbContainerDeletionAuthorizationGrant,
    AzureCosmosDbDatabaseDeletionAuthorizationGrant,
    AzureCosmosDbTopologyBuiltInRoleEvidence,
    AzureCosmosDbTopologyContinuousBackupRecoveryEvidence,
    AzureCosmosDbTopologyCustomRoleEvidence,
    AzureCosmosDbTopologyDestructionAuthorizationGrantCommon,
    AzureCosmosDbTopologyDestructionOperation,
    AzureCosmosDbTopologyDestructionRecoveryEvidence,
    AzureCosmosDbTopologyManagementLockNotObserved,
    AzureCosmosDbTopologyPeriodicBackupRecoveryEvidence,
    AzureCosmosDbTopologyProviderDefaultBackupRecoveryEvidence,
    AzureCosmosDbTopologyRecoveryEvidenceCommon,
    AzureCosmosDbTopologyRoleEvidence,
    AzureCosmosDbTopologyUnknownBackupRecoveryEvidence,
)
from tfstride.providers.coercion import (
    STATE_CONFIGURED,
    STATE_NOT_CONFIGURED,
    dedupe,
    dedupe_strings,
)

_DELETE_ACCOUNT: Literal["Microsoft.DocumentDB/databaseAccounts/delete"] = (
    "Microsoft.DocumentDB/databaseAccounts/delete"
)
_DELETE_DATABASE: Literal["Microsoft.DocumentDB/databaseAccounts/sqlDatabases/delete"] = (
    "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/delete"
)
_DELETE_CONTAINER: Literal["Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/delete"] = (
    "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/delete"
)

_COSMOSDB_TARGET_TYPES = frozenset(
    {
        AzureResourceType.COSMOSDB_ACCOUNT,
        AzureResourceType.COSMOSDB_SQL_DATABASE,
        AzureResourceType.COSMOSDB_SQL_CONTAINER,
    }
)
_ACCOUNT_ID_PATTERN = re.compile(
    r"^/subscriptions/[^/]+/resourcegroups/[^/]+/providers/"
    r"microsoft\.documentdb/databaseaccounts/[^/]+$",
    re.IGNORECASE,
)

_TargetKind = Literal["account", "database", "container"]
_LockEvaluationState = Literal["not_observed", "blocking", "unknown"]


@dataclass(frozen=True, slots=True)
class _RuntimeIdentity:
    resource: NormalizedResource
    kind: AzureKeyVaultRuntimeIdentityKind
    principal_id: str


@dataclass(frozen=True, slots=True)
class _TopologyTarget:
    resource: NormalizedResource
    kind: _TargetKind
    resource_id: str
    account: NormalizedResource
    account_id: str
    database: NormalizedResource | None = None
    database_id: str | None = None
    database_name: str | None = None
    container_name: str | None = None


@dataclass(frozen=True, slots=True)
class _LockEvaluation:
    state: _LockEvaluationState
    applicable_lock_addresses: tuple[str, ...] = ()
    applicable_lock_levels: tuple[str, ...] = ()
    uncertainties: tuple[str, ...] = ()


class ModelAppServiceCosmosDbTopologyDestructionPathsStage:
    """Project exact Cosmos DB control-plane deletion authority onto App Services."""

    name = "model_app_service_cosmosdb_topology_destruction_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AzureDecorationContext,
    ) -> None:
        targets, target_uncertainties = _topology_targets(resources, context)
        locks = tuple(resource for resource in resources if resource.resource_type == AzureResourceType.MANAGEMENT_LOCK)
        lock_evaluations = {
            target.resource.address: _management_lock_evaluation(
                target,
                locks,
                context,
            )
            for target in targets
        }
        assignments = tuple(
            resource for resource in resources if resource.resource_type == AzureResourceType.ROLE_ASSIGNMENT
        )

        for workload in resources:
            if workload.resource_type not in AZURE_APP_SERVICE_RESOURCE_TYPES:
                continue
            paths, uncertainties = _app_service_cosmosdb_topology_destruction_paths(
                workload,
                targets,
                target_uncertainties,
                lock_evaluations,
                assignments,
                context,
            )
            facts = azure_facts(workload)
            facts.set_app_service_cosmosdb_topology_destruction_paths(paths)
            facts.extend_app_service_cosmosdb_topology_destruction_path_uncertainties(
                uncertainties,
            )


def current_app_service_cosmosdb_topology_destruction_paths(
    workload: NormalizedResource,
    target_resource: NormalizedResource,
    resources: Sequence[NormalizedResource],
    context: AzureDecorationContext,
) -> list[AzureAppServiceCosmosDbTopologyDestructionPath]:
    """Recompute every current deterministic proof for one workload and target."""

    if (
        workload.resource_type not in AZURE_APP_SERVICE_RESOURCE_TYPES
        or target_resource.resource_type not in _COSMOSDB_TARGET_TYPES
    ):
        return []

    target, _uncertainty = _topology_target(target_resource, context)
    if target is None:
        return []
    locks = tuple(resource for resource in resources if resource.resource_type == AzureResourceType.MANAGEMENT_LOCK)
    lock_evaluation = _management_lock_evaluation(target, locks, context)
    paths, _uncertainties = _app_service_cosmosdb_topology_destruction_paths(
        workload,
        (target,),
        (),
        {target.resource.address: lock_evaluation},
        tuple(resource for resource in resources if resource.resource_type == AzureResourceType.ROLE_ASSIGNMENT),
        context,
    )
    return paths


def _app_service_cosmosdb_topology_destruction_paths(
    workload: NormalizedResource,
    targets: Sequence[_TopologyTarget],
    target_uncertainties: Sequence[str],
    lock_evaluations: Mapping[str, _LockEvaluation],
    assignments: Sequence[NormalizedResource],
    context: AzureDecorationContext,
) -> tuple[list[AzureAppServiceCosmosDbTopologyDestructionPath], list[str]]:
    identities, identity_uncertainties = workload_managed_identities(
        workload,
        context,
    )
    uncertainties = [
        *identity_uncertainties,
        *(f"{workload.address}: {uncertainty}" for uncertainty in azure_facts(workload).managed_identity_uncertainties),
        *(f"{workload.address}: {uncertainty}" for uncertainty in target_uncertainties),
    ]
    runtime_identities = tuple(
        _RuntimeIdentity(identity, kind, principal_id)
        for identity, kind in identities
        if (principal_id := _known_string(azure_facts(identity).principal_id)) is not None
    )
    if not runtime_identities:
        return [], dedupe(uncertainties)

    paths: list[AzureAppServiceCosmosDbTopologyDestructionPath] = []
    for target in targets:
        lock_evaluation = lock_evaluations[target.resource.address]
        if lock_evaluation.state == "blocking":
            continue
        if lock_evaluation.state == "unknown":
            uncertainties.extend(
                f"{workload.address}: {target.resource.address}: {uncertainty}"
                for uncertainty in lock_evaluation.uncertainties
            )
            continue

        operation = _operation(target.kind)
        recovery = _recovery_evidence(target.account)
        for identity in runtime_identities:
            for assignment in assignments:
                result = model_arm_control_plane_action_authority(
                    assignment,
                    context,
                    principal_id=identity.principal_id,
                    target_arm_id=target.resource_id,
                    requested_actions=(operation,),
                )
                _record_result_uncertainties(
                    workload,
                    target,
                    result,
                    uncertainties,
                )
                if result.grant is None:
                    continue
                path = _topology_path(
                    workload,
                    identity,
                    target,
                    result.grant,
                    recovery,
                )
                if path is None:
                    uncertainties.append(
                        f"{workload.address}: {assignment.address} returned "
                        "incoherent Cosmos DB topology-deletion evidence for "
                        f"{target.resource.address}"
                    )
                    continue
                paths.append(path)
                uncertainties.extend(
                    f"{workload.address}: {target.resource.address}: {value}" for value in path["posture_uncertainties"]
                )

    paths.sort(
        key=lambda path: (
            path["cosmosdb_resource_address"],
            path["operation"],
            path["identity_address"],
            path["role_assignment_address"],
        )
    )
    return _dedupe_paths(paths), dedupe(uncertainties)


def _record_result_uncertainties(
    workload: NormalizedResource,
    target: _TopologyTarget,
    result: AzureArmControlPlaneAuthorityResult,
    uncertainties: list[str],
) -> None:
    if result.state != "unknown":
        return
    uncertainties.extend(
        f"{workload.address}: {target.resource.address}: {uncertainty}" for uncertainty in result.uncertainties
    )


def _topology_targets(
    resources: Sequence[NormalizedResource],
    context: AzureDecorationContext,
) -> tuple[list[_TopologyTarget], list[str]]:
    targets: list[_TopologyTarget] = []
    uncertainties: list[str] = []
    for resource in resources:
        if resource.resource_type not in _COSMOSDB_TARGET_TYPES:
            continue
        target, uncertainty = _topology_target(resource, context)
        if target is not None:
            targets.append(target)
        elif uncertainty is not None:
            uncertainties.append(uncertainty)
    targets.sort(key=lambda target: target.resource.address)
    return targets, dedupe(uncertainties)


def _topology_target(
    resource: NormalizedResource,
    context: AzureDecorationContext,
) -> tuple[_TopologyTarget | None, str | None]:
    if resource.resource_type == AzureResourceType.COSMOSDB_ACCOUNT:
        return _account_target(resource)
    if resource.resource_type == AzureResourceType.COSMOSDB_SQL_DATABASE:
        return _database_target(resource, context)
    if resource.resource_type == AzureResourceType.COSMOSDB_SQL_CONTAINER:
        return _container_target(resource, context)
    return None, None


def _account_target(
    account: NormalizedResource,
) -> tuple[_TopologyTarget | None, str | None]:
    account_id = _exact_account_id(azure_facts(account).cosmosdb_account_id)
    if account_id is None:
        return None, f"{account.address}: exact Cosmos DB account ARM identity is unresolved"
    return (
        _TopologyTarget(
            resource=account,
            kind="account",
            resource_id=account_id,
            account=account,
            account_id=account_id,
        ),
        None,
    )


def _database_target(
    database: NormalizedResource,
    context: AzureDecorationContext,
) -> tuple[_TopologyTarget | None, str | None]:
    facts = azure_facts(database)
    account = context.index.resources_by_address.get(
        facts.resolved_cosmosdb_account_address or "",
    )
    if account is None or account.resource_type != AzureResourceType.COSMOSDB_ACCOUNT:
        return None, f"{database.address}: exact Cosmos DB account ancestry is unresolved"

    account_id = _exact_account_id(azure_facts(account).cosmosdb_account_id)
    database_id = _known_arm_id(facts.cosmosdb_sql_database_id)
    database_name = _known_string(facts.cosmosdb_sql_database_name)
    if account_id is None or database_id is None or database_name is None:
        return None, f"{database.address}: exact Cosmos DB SQL database ARM identity is unresolved"
    expected_id = f"{account_id}/sqlDatabases/{database_name}"
    if not _same_identifier(database_id, expected_id):
        return (
            None,
            f"{database.address}: Cosmos DB SQL database identity and account ancestry are incoherent",
        )
    return (
        _TopologyTarget(
            resource=database,
            kind="database",
            resource_id=database_id,
            account=account,
            account_id=account_id,
            database=database,
            database_id=database_id,
            database_name=database_name,
        ),
        None,
    )


def _container_target(
    container: NormalizedResource,
    context: AzureDecorationContext,
) -> tuple[_TopologyTarget | None, str | None]:
    facts = azure_facts(container)
    database = context.index.resources_by_address.get(
        facts.resolved_cosmosdb_database_address or "",
    )
    account = context.index.resources_by_address.get(
        facts.resolved_cosmosdb_account_address or "",
    )
    if (
        database is None
        or database.resource_type != AzureResourceType.COSMOSDB_SQL_DATABASE
        or account is None
        or account.resource_type != AzureResourceType.COSMOSDB_ACCOUNT
        or azure_facts(database).resolved_cosmosdb_account_address != account.address
    ):
        return None, f"{container.address}: exact Cosmos DB SQL database ancestry is unresolved"

    database_target, _uncertainty = _database_target(database, context)
    if database_target is None or database_target.account.address != account.address:
        return (
            None,
            f"{container.address}: Cosmos DB SQL database identity and account ancestry are incoherent",
        )

    container_id = _known_arm_id(facts.cosmosdb_sql_container_id)
    container_name = _known_string(facts.cosmosdb_sql_container_name)
    if container_id is None or container_name is None:
        return None, f"{container.address}: exact Cosmos DB SQL container ARM identity is unresolved"
    expected_id = f"{database_target.resource_id}/containers/{container_name}"
    if not _same_identifier(container_id, expected_id):
        return (
            None,
            f"{container.address}: Cosmos DB SQL container identity and database ancestry are incoherent",
        )
    return (
        _TopologyTarget(
            resource=container,
            kind="container",
            resource_id=container_id,
            account=account,
            account_id=database_target.account_id,
            database=database,
            database_id=database_target.resource_id,
            database_name=database_target.database_name,
            container_name=container_name,
        ),
        None,
    )


def _management_lock_evaluation(
    target: _TopologyTarget,
    locks: Sequence[NormalizedResource],
    context: AzureDecorationContext,
) -> _LockEvaluation:
    blocking_addresses: list[str] = []
    blocking_levels: list[str] = []
    uncertainties: list[str] = []
    for lock in locks:
        scope_state = _management_lock_scope_state(lock, target, context)
        if scope_state == "unrelated":
            continue
        lock_facts = azure_facts(lock)
        if scope_state == "unknown":
            uncertainties.extend(
                f"{lock.address}: {uncertainty}"
                for uncertainty in (
                    lock_facts.management_lock_uncertainties or ["management-lock scope applicability is unresolved"]
                )
            )
            continue

        lock_level = _blocking_lock_level(lock_facts.management_lock_level)
        if lock_level is None:
            uncertainties.extend(
                f"{lock.address}: {uncertainty}"
                for uncertainty in (
                    lock_facts.management_lock_uncertainties or ["management-lock level is unsupported or unresolved"]
                )
            )
            continue
        blocking_addresses.append(lock.address)
        blocking_levels.append(lock_level)

    if blocking_addresses:
        return _LockEvaluation(
            state="blocking",
            applicable_lock_addresses=tuple(dedupe(blocking_addresses)),
            applicable_lock_levels=tuple(dedupe(blocking_levels)),
        )
    if uncertainties:
        return _LockEvaluation(
            state="unknown",
            uncertainties=tuple(dedupe(uncertainties)),
        )
    return _LockEvaluation(state="not_observed")


def _management_lock_scope_state(
    lock: NormalizedResource,
    target: _TopologyTarget,
    context: AzureDecorationContext,
) -> Literal["applicable", "unrelated", "unknown"]:
    scope = _known_string(azure_facts(lock).management_lock_scope)
    if scope is None:
        return "unknown"

    if scope.startswith("/"):
        normalized_scope = _known_arm_id(scope)
        if normalized_scope is None:
            return "unknown"
        if normalized_scope.casefold().startswith(
            "/providers/microsoft.management/managementgroups/",
        ):
            return "unknown"
        return "applicable" if azure_arm_scope_contains(normalized_scope, target.resource_id) else "unrelated"

    scope_resource = context.index.resolve(scope, source=lock)
    if scope_resource is None:
        return "unknown"
    scope_arm_id = _cosmosdb_resource_arm_id(scope_resource)
    if scope_arm_id is None:
        return "unknown"
    return "applicable" if azure_arm_scope_contains(scope_arm_id, target.resource_id) else "unrelated"


def _blocking_lock_level(
    value: object,
) -> Literal["CanNotDelete", "ReadOnly"] | None:
    normalized = _known_string(value)
    if normalized is None:
        return None
    key = normalized.casefold().replace("_", "").replace("-", "").replace(" ", "")
    if key == "cannotdelete":
        return "CanNotDelete"
    if key == "readonly":
        return "ReadOnly"
    return None


def _cosmosdb_resource_arm_id(resource: NormalizedResource) -> str | None:
    facts = azure_facts(resource)
    if resource.resource_type == AzureResourceType.COSMOSDB_ACCOUNT:
        return _exact_account_id(facts.cosmosdb_account_id)
    if resource.resource_type == AzureResourceType.COSMOSDB_SQL_DATABASE:
        return _known_arm_id(facts.cosmosdb_sql_database_id)
    if resource.resource_type == AzureResourceType.COSMOSDB_SQL_CONTAINER:
        return _known_arm_id(facts.cosmosdb_sql_container_id)
    return None


def _recovery_evidence(
    account: NormalizedResource,
) -> AzureCosmosDbTopologyDestructionRecoveryEvidence:
    facts = azure_facts(account)
    uncertainties = dedupe([value for value in facts.cosmosdb_posture_uncertainties if value.startswith("backup")])
    common: AzureCosmosDbTopologyRecoveryEvidenceCommon = {
        "recovery_evidence_scope": ("cosmosdb_topology_deletion_and_backup_policy"),
        "successful_deletion_observed": False,
        "restoration_observed": False,
        "immediate_restoration_established": False,
        "restore_target_evaluated": False,
        "out_of_plan_restore_resources_evaluated": False,
        "uncertainties": uncertainties,
    }
    configuration_state = facts.cosmosdb_backup_configuration_state
    backup_type = _known_string(facts.cosmosdb_backup_type)

    if configuration_state == STATE_NOT_CONFIGURED:
        return AzureCosmosDbTopologyProviderDefaultBackupRecoveryEvidence(
            **common,
            backup_posture_state="provider_default_periodic",
            backup_configuration_state="not_configured",
            backup_type="Periodic",
            backup_tier=None,
            backup_interval_minutes=240,
            backup_retention_hours=8,
            backup_storage_redundancy="Geo",
            topology_recovery_state="periodic_backup_recovery_configured",
        )

    if configuration_state == STATE_CONFIGURED and backup_type is not None and backup_type.casefold() == "continuous":
        return AzureCosmosDbTopologyContinuousBackupRecoveryEvidence(
            **common,
            backup_posture_state="continuous",
            backup_configuration_state="configured",
            backup_type="Continuous",
            backup_tier=_known_string(facts.cosmosdb_backup_tier),
            backup_interval_minutes=None,
            backup_retention_hours=None,
            backup_storage_redundancy=None,
            topology_recovery_state="continuous_backup_recovery_configured",
        )

    if (
        configuration_state == STATE_CONFIGURED
        and backup_type is not None
        and backup_type.casefold() == "periodic"
        and facts.cosmosdb_backup_tier is None
    ):
        return AzureCosmosDbTopologyPeriodicBackupRecoveryEvidence(
            **common,
            backup_posture_state="periodic",
            backup_configuration_state="configured",
            backup_type="Periodic",
            backup_tier=None,
            backup_interval_minutes=facts.cosmosdb_backup_interval_minutes,
            backup_retention_hours=facts.cosmosdb_backup_retention_hours,
            backup_storage_redundancy=_known_string(
                facts.cosmosdb_backup_storage_redundancy,
            ),
            topology_recovery_state="periodic_backup_recovery_configured",
        )

    return AzureCosmosDbTopologyUnknownBackupRecoveryEvidence(
        **common,
        backup_posture_state="unknown",
        backup_configuration_state=("configured" if configuration_state == STATE_CONFIGURED else "unknown"),
        backup_type=backup_type,
        backup_tier=_known_string(facts.cosmosdb_backup_tier),
        backup_interval_minutes=facts.cosmosdb_backup_interval_minutes,
        backup_retention_hours=facts.cosmosdb_backup_retention_hours,
        backup_storage_redundancy=_known_string(
            facts.cosmosdb_backup_storage_redundancy,
        ),
        topology_recovery_state="unknown",
    )


def _topology_path(
    workload: NormalizedResource,
    identity: _RuntimeIdentity,
    target: _TopologyTarget,
    grant: AzureArmControlPlaneGrant,
    recovery: AzureCosmosDbTopologyDestructionRecoveryEvidence,
) -> AzureAppServiceCosmosDbTopologyDestructionPath | None:
    operation = _operation(target.kind)
    grant_common = _authorization_grant_common(
        grant,
        identity,
        target,
        operation,
    )
    if grant_common is None:
        return None

    common = _path_common(
        workload,
        identity,
        target,
        grant,
        recovery,
    )
    if target.kind == "account":
        authorization = AzureCosmosDbAccountDeletionAuthorizationGrant(
            **grant_common,
            requested_actions=[_DELETE_ACCOUNT],
            matched_actions=[_DELETE_ACCOUNT],
        )
        return AzureAppServiceCosmosDbAccountTopologyDeletionPath(
            **common,
            cosmosdb_resource_kind="account",
            operation=_DELETE_ACCOUNT,
            operation_class="account_deletion",
            internal_operation="delete_account",
            target_granularity="account_topology",
            target_scope="exact_cosmosdb_account",
            cosmosdb_database_address=None,
            cosmosdb_database_id=None,
            cosmosdb_database_name=None,
            cosmosdb_container_address=None,
            cosmosdb_container_id=None,
            cosmosdb_container_name=None,
            authorization_grant=authorization,
        )

    database = target.database
    database_id = target.database_id
    database_name = target.database_name
    if database is None or database_id is None or database_name is None:
        return None

    if target.kind == "database":
        authorization = AzureCosmosDbDatabaseDeletionAuthorizationGrant(
            **grant_common,
            requested_actions=[_DELETE_DATABASE],
            matched_actions=[_DELETE_DATABASE],
        )
        return AzureAppServiceCosmosDbDatabaseTopologyDeletionPath(
            **common,
            cosmosdb_resource_kind="database",
            operation=_DELETE_DATABASE,
            operation_class="database_deletion",
            internal_operation="delete_database",
            target_granularity="database_topology",
            target_scope="exact_cosmosdb_sql_database",
            cosmosdb_database_address=database.address,
            cosmosdb_database_id=database_id,
            cosmosdb_database_name=database_name,
            cosmosdb_container_address=None,
            cosmosdb_container_id=None,
            cosmosdb_container_name=None,
            authorization_grant=authorization,
        )

    container_name = target.container_name
    if container_name is None:
        return None
    authorization = AzureCosmosDbContainerDeletionAuthorizationGrant(
        **grant_common,
        requested_actions=[_DELETE_CONTAINER],
        matched_actions=[_DELETE_CONTAINER],
    )
    return AzureAppServiceCosmosDbContainerTopologyDeletionPath(
        **common,
        cosmosdb_resource_kind="container",
        operation=_DELETE_CONTAINER,
        operation_class="container_deletion",
        internal_operation="delete_container",
        target_granularity="container_topology",
        target_scope="exact_cosmosdb_sql_container",
        cosmosdb_database_address=database.address,
        cosmosdb_database_id=database_id,
        cosmosdb_database_name=database_name,
        cosmosdb_container_address=target.resource.address,
        cosmosdb_container_id=target.resource_id,
        cosmosdb_container_name=container_name,
        authorization_grant=authorization,
    )


def _path_common(
    workload: NormalizedResource,
    identity: _RuntimeIdentity,
    target: _TopologyTarget,
    grant: AzureArmControlPlaneGrant,
    recovery: AzureCosmosDbTopologyDestructionRecoveryEvidence,
) -> AzureAppServiceCosmosDbTopologyDestructionPathCommon:
    role_definition_address = _known_string(grant["role_definition_address"])
    lock_evidence = AzureCosmosDbTopologyManagementLockNotObserved(
        lock_evidence_scope="plan_local_cosmosdb_arm_ancestry",
        modeled_management_lock_state="not_observed",
        applicable_lock_addresses=[],
        applicable_lock_levels=[],
        external_management_locks_evaluated=False,
        deletion_compatibility_state="compatible",
        uncertainties=[],
    )
    return AzureAppServiceCosmosDbTopologyDestructionPathCommon(
        workload_address=workload.address,
        workload_type=workload.resource_type,
        identity_address=identity.resource.address,
        identity_kind=identity.kind,
        principal_id=identity.principal_id,
        credential_context="workload_runtime",
        cosmosdb_account_address=target.account.address,
        cosmosdb_account_id=target.account_id,
        cosmosdb_resource_address=target.resource.address,
        cosmosdb_resource_type=target.resource.resource_type,
        cosmosdb_resource_id=target.resource_id,
        target_model_evidence_addresses=_target_evidence_addresses(target),
        management_effect="disruption",
        authorization_evidence_kind="azure_rbac_action",
        role_assignment_address=grant["source_address"],
        authorization_source_addresses=dedupe_strings(
            [grant["source_address"], role_definition_address],
        ),
        authorization_state="granted",
        modeled_allow_evidence_complete=True,
        condition=None,
        condition_state="not_configured",
        lifecycle_compatibility_state="compatible",
        management_lock_evidence=lock_evidence,
        recovery_evidence=recovery,
        descendant_impact_evaluated=False,
        out_of_plan_topology_evaluated=False,
        posture_uncertainties=list(recovery["uncertainties"]),
    )


def _authorization_grant_common(
    grant: AzureArmControlPlaneGrant,
    identity: _RuntimeIdentity,
    target: _TopologyTarget,
    operation: AzureCosmosDbTopologyDestructionOperation,
) -> AzureCosmosDbTopologyDestructionAuthorizationGrantCommon | None:
    principal_id = _known_string(grant["principal_id"])
    role_evidence = _role_evidence(grant)
    if (
        principal_id is None
        or not _same_identifier(principal_id, identity.principal_id)
        or not _same_identifier(grant["target_arm_id"], target.resource_id)
        or grant["requested_actions"] != [operation]
        or grant["matched_actions"] != [operation]
        or grant["excluded_actions"]
        or grant["principal_state"] != "resolved"
        or grant["assignment_scope_state"] != "resolved"
        or grant["assignment_condition"] is not None
        or grant["assignment_condition_version"] is not None
        or grant["assignment_condition_state"] != "not_configured"
        or grant["role_definition_condition_state"] != "not_configured"
        or grant["delegation_constraint_kind"] != "none"
        or grant["allowed_role_definition_ids"]
        or grant["authorization_state"] != "granted"
        or grant["deny_assignments_evaluated"] is not False
        or grant["evaluation_basis"] != "modeled_arm_control_plane_authority"
        or role_evidence is None
    ):
        return None
    return {
        "source_address": grant["source_address"],
        "principal_id": principal_id,
        "principal_type": grant["principal_type"],
        "principal_state": "resolved",
        "assignment_scope_type": grant["assignment_scope_type"],
        "assignment_scope": grant["assignment_scope"],
        "assignment_scope_arm_id": grant["assignment_scope_arm_id"],
        "assignment_scope_state": "resolved",
        "target_arm_id": target.resource_id,
        "role_definition_name": grant["role_definition_name"],
        "role_definition_id": grant["role_definition_id"],
        "role_evidence": role_evidence,
        "role_actions": list(grant["role_actions"]),
        "role_not_actions": list(grant["role_not_actions"]),
        "excluded_actions": [],
        "assignment_condition": None,
        "assignment_condition_version": None,
        "assignment_condition_state": "not_configured",
        "role_definition_condition_state": "not_configured",
        "delegation_constraint_kind": "none",
        "allowed_role_definition_ids": [],
        "authorization_state": "granted",
        "deny_assignments_evaluated": False,
        "evaluation_basis": "modeled_arm_control_plane_authority",
        "cosmosdb_native_data_actions_authorization_effect": ("not_used_for_arm_topology_deletion"),
    }


def _role_evidence(
    grant: AzureArmControlPlaneGrant,
) -> AzureCosmosDbTopologyRoleEvidence | None:
    role_definition_address = _known_string(grant["role_definition_address"])
    if (
        grant["role_kind"] == "built_in"
        and grant["role_resolution_state"] == "modeled_subset"
        and role_definition_address is None
        and grant["assignable_scope_compatibility_state"] == "not_applicable"
    ):
        return AzureCosmosDbTopologyBuiltInRoleEvidence(
            role_kind="built_in",
            role_resolution_state="modeled_subset",
            role_definition_address=None,
            assignable_scope_compatibility_state="not_applicable",
        )
    if (
        grant["role_kind"] == "custom"
        and grant["role_resolution_state"] == "resolved"
        and role_definition_address is not None
        and grant["assignable_scope_compatibility_state"] == "resolved"
    ):
        return AzureCosmosDbTopologyCustomRoleEvidence(
            role_kind="custom",
            role_resolution_state="resolved",
            role_definition_address=role_definition_address,
            assignable_scope_compatibility_state="resolved",
        )
    return None


def _target_evidence_addresses(target: _TopologyTarget) -> list[str]:
    if target.kind == "account":
        return [target.account.address]
    if target.kind == "database":
        return [target.account.address, target.resource.address]
    assert target.database is not None
    return [
        target.account.address,
        target.database.address,
        target.resource.address,
    ]


def _operation(
    kind: _TargetKind,
) -> AzureCosmosDbTopologyDestructionOperation:
    if kind == "account":
        return _DELETE_ACCOUNT
    if kind == "database":
        return _DELETE_DATABASE
    return _DELETE_CONTAINER


def _exact_account_id(value: object) -> str | None:
    normalized = _known_arm_id(value)
    if normalized is None or _ACCOUNT_ID_PATTERN.fullmatch(normalized) is None:
        return None
    return normalized


def _known_arm_id(value: object) -> str | None:
    normalized = _known_string(value)
    if normalized is None or not normalized.startswith("/"):
        return None
    return normalized.rstrip("/")


def _same_identifier(left: object, right: object) -> bool:
    left_value = _known_string(left)
    right_value = _known_string(right)
    return bool(left_value and right_value and left_value.rstrip("/").casefold() == right_value.rstrip("/").casefold())


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _dedupe_paths(
    paths: Sequence[AzureAppServiceCosmosDbTopologyDestructionPath],
) -> list[AzureAppServiceCosmosDbTopologyDestructionPath]:
    result: list[AzureAppServiceCosmosDbTopologyDestructionPath] = []
    for path in paths:
        if path not in result:
            result.append(path)
    return result
