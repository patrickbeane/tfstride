from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import cast

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.azure.app_service_ingress_helpers import app_service_ingress
from tfstride.providers.azure.resource_decoration.app_service_cosmosdb_topology_destruction_paths import (
    current_app_service_cosmosdb_topology_destruction_paths,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext, AzureResourceIndexBuilder
from tfstride.providers.azure.resource_types import AZURE_APP_SERVICE_RESOURCE_TYPES, AzureResourceType
from tfstride.providers.azure.structured_data_topology_destruction_evidence import (
    AzureAppServiceCosmosDbTopologyDestructionPath,
)

_DELETE_ACCOUNT = "Microsoft.DocumentDB/databaseAccounts/delete"
_DELETE_DATABASE = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/delete"
_DELETE_CONTAINER = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/delete"
_COSMOSDB_TARGET_TYPES = frozenset(
    {
        AzureResourceType.COSMOSDB_ACCOUNT,
        AzureResourceType.COSMOSDB_SQL_DATABASE,
        AzureResourceType.COSMOSDB_SQL_CONTAINER,
    }
)
_AUTHORIZATION_RELATIONSHIP_FIELDS = (
    "workload_address",
    "workload_type",
    "identity_address",
    "identity_kind",
    "principal_id",
    "credential_context",
    "cosmosdb_account_address",
    "cosmosdb_account_id",
    "cosmosdb_resource_address",
    "cosmosdb_resource_type",
    "cosmosdb_resource_id",
    "cosmosdb_resource_kind",
    "target_model_evidence_addresses",
    "operation",
    "operation_class",
    "internal_operation",
    "management_effect",
    "authorization_evidence_kind",
    "target_granularity",
    "target_scope",
    "role_assignment_address",
    "authorization_source_addresses",
    "authorization_state",
    "modeled_allow_evidence_complete",
    "condition",
    "condition_state",
)
_EXPECTED_RESOURCE_KINDS = {
    AzureResourceType.COSMOSDB_ACCOUNT: "account",
    AzureResourceType.COSMOSDB_SQL_DATABASE: "database",
    AzureResourceType.COSMOSDB_SQL_CONTAINER: "container",
}
_EXPECTED_TARGET_CONTRACTS: dict[str, tuple[str, str, str, str, str]] = {
    AzureResourceType.COSMOSDB_ACCOUNT: (
        _DELETE_ACCOUNT,
        "account_deletion",
        "delete_account",
        "account_topology",
        "exact_cosmosdb_account",
    ),
    AzureResourceType.COSMOSDB_SQL_DATABASE: (
        _DELETE_DATABASE,
        "database_deletion",
        "delete_database",
        "database_topology",
        "exact_cosmosdb_sql_database",
    ),
    AzureResourceType.COSMOSDB_SQL_CONTAINER: (
        _DELETE_CONTAINER,
        "container_deletion",
        "delete_container",
        "container_topology",
        "exact_cosmosdb_sql_container",
    ),
}


class AzureAppServiceCosmosDbTopologyDisruptionRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_app_service_cosmosdb_topology_disruption(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        resources = list(context.inventory.resources)
        decoration_context = AzureDecorationContext(AzureResourceIndexBuilder().build(resources))
        findings: list[Finding] = []
        for workload in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            workload_facts = azure_facts(workload)
            ingress = app_service_ingress(workload, context)
            if not ingress.is_public:
                continue

            paths: list[AzureAppServiceCosmosDbTopologyDestructionPath] = []
            seen_keys: set[tuple[str, ...]] = set()
            for cached_path in workload_facts.app_service_cosmosdb_topology_destruction_paths:
                current_path = _current_topology_path(
                    cached_path,
                    workload,
                    context,
                    decoration_context,
                )
                if current_path is None:
                    continue
                key = _authorization_relationship_key(current_path)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                paths.append(current_path)
            if not paths:
                continue

            target_addresses = _path_string_values(paths, "cosmosdb_resource_address")
            account_addresses = _path_string_values(paths, "cosmosdb_account_address")
            identity_addresses = _path_string_values(paths, "identity_address")
            authorization_sources = _path_string_values(paths, "authorization_source_addresses")
            target_model_evidence = _path_string_values(paths, "target_model_evidence_addresses")
            has_account_scope = any(path.get("cosmosdb_resource_kind") == "account" for path in paths)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2 if has_account_scope else 1,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=2 if has_account_scope or len(target_addresses) > 1 else 1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            workload.address,
                            *(address for address in identity_addresses if address != workload.address),
                            *account_addresses,
                            *target_addresses,
                            *target_model_evidence,
                            *authorization_sources,
                        ]
                    ),
                    trust_boundary_id=None,
                    rationale=_rationale(workload, len(target_addresses), paths),
                    evidence=collect_evidence(
                        *ingress.evidence,
                        evidence_item("runtime_identity", _runtime_identity_evidence(paths)),
                        evidence_item(
                            "cosmosdb_topology_destruction_paths",
                            _topology_path_evidence(paths),
                        ),
                        evidence_item(
                            "cosmosdb_topology_authorization_evidence",
                            _authorization_evidence(paths),
                        ),
                        evidence_item(
                            "cosmosdb_management_lock_evidence",
                            _management_lock_evidence(paths),
                        ),
                        evidence_item(
                            "cosmosdb_backup_recovery_evidence",
                            _recovery_evidence(paths),
                        ),
                        evidence_item(
                            "cosmosdb_topology_destruction_path_uncertainties",
                            _current_path_uncertainties(paths),
                        ),
                        evidence_item("assessment_scope", _assessment_scope()),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _current_topology_path(
    cached_path: Mapping[str, object],
    workload: NormalizedResource,
    context: RuleEvaluationContext,
    decoration_context: AzureDecorationContext,
) -> AzureAppServiceCosmosDbTopologyDestructionPath | None:
    if not _cached_path_is_coherent(cached_path, workload):
        return None

    resource_address = _known_string(cached_path.get("cosmosdb_resource_address"))
    if resource_address is None:
        return None
    target = context.inventory.get_by_address(resource_address)
    if target is None or target.provider != "azure" or target.resource_type not in _COSMOSDB_TARGET_TYPES:
        return None

    current_paths = current_app_service_cosmosdb_topology_destruction_paths(
        workload,
        target,
        list(context.inventory.resources),
        decoration_context,
    )
    return next(
        (
            current_path
            for current_path in current_paths
            if _authorization_relationship_matches(cached_path, current_path)
        ),
        None,
    )


def _cached_path_is_coherent(
    path: Mapping[str, object],
    workload: NormalizedResource,
) -> bool:
    target_type = _known_string(path.get("cosmosdb_resource_type"))
    target_kind = _EXPECTED_RESOURCE_KINDS.get(target_type or "")
    contract = _EXPECTED_TARGET_CONTRACTS.get(target_type or "")
    resource_address = _known_string(path.get("cosmosdb_resource_address"))
    account_address = _known_string(path.get("cosmosdb_account_address"))
    if target_kind is None or contract is None or resource_address is None or account_address is None:
        return False
    expected_evidence = [account_address]
    if target_type in {
        AzureResourceType.COSMOSDB_SQL_DATABASE,
        AzureResourceType.COSMOSDB_SQL_CONTAINER,
    }:
        database_address = _known_string(path.get("cosmosdb_database_address"))
        if database_address is None:
            return False
        expected_evidence.append(database_address)
    if target_type == AzureResourceType.COSMOSDB_SQL_CONTAINER:
        expected_evidence.append(resource_address)
    elif target_type == AzureResourceType.COSMOSDB_SQL_DATABASE:
        expected_evidence[-1] = resource_address
    else:
        expected_evidence = [resource_address]

    return bool(
        path.get("workload_address") == workload.address
        and path.get("workload_type") == workload.resource_type
        and path.get("identity_kind") in {"system_assigned", "user_assigned"}
        and path.get("credential_context") == "workload_runtime"
        and path.get("cosmosdb_account_address") == account_address
        and path.get("cosmosdb_resource_address") == resource_address
        and path.get("cosmosdb_resource_type") == target_type
        and path.get("cosmosdb_resource_kind") == target_kind
        and path.get("operation") == contract[0]
        and path.get("operation_class") == contract[1]
        and path.get("internal_operation") == contract[2]
        and path.get("management_effect") == "disruption"
        and path.get("authorization_evidence_kind") == "azure_rbac_action"
        and path.get("target_granularity") == contract[3]
        and path.get("target_scope") == contract[4]
        and path.get("target_model_evidence_addresses") == expected_evidence
        and path.get("authorization_state") == "granted"
        and path.get("modeled_allow_evidence_complete") is True
        and path.get("condition") is None
        and path.get("condition_state") == "not_configured"
        and path.get("lifecycle_compatibility_state") == "compatible"
    )


def _authorization_relationship_matches(
    cached_path: Mapping[str, object],
    current_path: Mapping[str, object],
) -> bool:
    return all(cached_path.get(field) == current_path.get(field) for field in _AUTHORIZATION_RELATIONSHIP_FIELDS)


def _authorization_relationship_key(path: Mapping[str, object]) -> tuple[str, ...]:
    return tuple(repr(path.get(field)) for field in _AUTHORIZATION_RELATIONSHIP_FIELDS)


def _path_string_values(paths: Sequence[Mapping[str, object]], key: str) -> list[str]:
    values: set[str] = set()
    for path in paths:
        value = path.get(key)
        if key in {"authorization_source_addresses", "target_model_evidence_addresses"}:
            if isinstance(value, list):
                values.update(item for item in value if isinstance(item, str) and item)
        elif isinstance(value, str) and value:
            values.add(value)
    return sorted(values)


def _current_path_uncertainties(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted({uncertainty for path in paths for uncertainty in _string_values(path.get("posture_uncertainties"))})


def _runtime_identity_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"identity_address={path.get('identity_address')}",
                    f"identity_kind={path.get('identity_kind')}",
                    f"principal_id={path.get('principal_id')}",
                    "credential_context=workload_runtime",
                    "authorization_state=granted",
                )
            )
            for path in paths
        }
    )


def _topology_path_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"target_address={path.get('cosmosdb_resource_address')}",
                    f"target_type={path.get('cosmosdb_resource_type')}",
                    f"target_id={path.get('cosmosdb_resource_id')}",
                    f"account_address={path.get('cosmosdb_account_address')}",
                    f"operation={path.get('operation')}",
                    f"operation_class={path.get('operation_class')}",
                    f"target_granularity={path.get('target_granularity')}",
                    f"target_scope={path.get('target_scope')}",
                    f"target_model_evidence_addresses={','.join(_string_values(path.get('target_model_evidence_addresses'))) or 'none'}",
                    f"role_assignment_address={path.get('role_assignment_address')}",
                    f"authorization_sources={','.join(_string_values(path.get('authorization_source_addresses'))) or 'none'}",
                    f"authorization_state={path.get('authorization_state')}",
                    "operation_evaluation=deterministic_allowed",
                )
            )
            for path in paths
        }
    )


def _authorization_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        grant = path.get("authorization_grant")
        if not isinstance(grant, Mapping):
            continue
        grant_map = cast(Mapping[str, object], grant)
        role_evidence = grant_map.get("role_evidence")
        role_map: Mapping[str, object] = (
            cast(Mapping[str, object], role_evidence) if isinstance(role_evidence, Mapping) else {}
        )
        values.add(
            "; ".join(
                (
                    f"target_address={path.get('cosmosdb_resource_address')}",
                    f"assignment_scope_type={grant_map.get('assignment_scope_type')}",
                    f"assignment_scope_arm_id={grant_map.get('assignment_scope_arm_id')}",
                    f"role_kind={role_map.get('role_kind', 'unknown')}",
                    f"role_definition_address={role_map.get('role_definition_address') or 'none'}",
                    f"role_definition_name={grant_map.get('role_definition_name') or 'unknown'}",
                    f"role_actions={','.join(_string_values(grant_map.get('role_actions'))) or 'none'}",
                    f"role_not_actions={','.join(_string_values(grant_map.get('role_not_actions'))) or 'none'}",
                    f"requested_actions={','.join(_string_values(grant_map.get('requested_actions')))}",
                    f"matched_actions={','.join(_string_values(grant_map.get('matched_actions')))}",
                    f"native_data_actions_effect={grant_map.get('cosmosdb_native_data_actions_authorization_effect')}",
                    "condition_state=not_configured",
                    "authorization_state=granted",
                )
            )
        )
    return sorted(values)


def _management_lock_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        lock = path.get("management_lock_evidence")
        if not isinstance(lock, Mapping):
            continue
        lock_map = cast(Mapping[str, object], lock)
        values.add(
            "; ".join(
                (
                    f"target_address={path.get('cosmosdb_resource_address')}",
                    f"modeled_management_lock_state={lock_map.get('modeled_management_lock_state')}",
                    f"applicable_lock_addresses={','.join(_string_values(lock_map.get('applicable_lock_addresses'))) or 'none'}",
                    f"applicable_lock_levels={','.join(_string_values(lock_map.get('applicable_lock_levels'))) or 'none'}",
                    f"external_management_locks_evaluated={_display(lock_map.get('external_management_locks_evaluated'))}",
                    f"deletion_compatibility_state={lock_map.get('deletion_compatibility_state')}",
                    f"uncertainties={','.join(_string_values(lock_map.get('uncertainties'))) or 'none'}",
                )
            )
        )
    return sorted(values)


def _recovery_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        recovery = path.get("recovery_evidence")
        if not isinstance(recovery, Mapping):
            continue
        recovery_map = cast(Mapping[str, object], recovery)
        posture = _known_string(recovery_map.get("backup_posture_state")) or "unknown"
        tier, interval, retention, redundancy = _backup_posture_field_values(recovery_map, posture)
        values.add(
            "; ".join(
                (
                    f"target_address={path.get('cosmosdb_resource_address')}",
                    f"backup_posture_state={posture}",
                    f"backup_configuration_state={_known_string(recovery_map.get('backup_configuration_state')) or 'unknown'}",
                    f"backup_type={_known_string(recovery_map.get('backup_type')) or 'unknown'}",
                    f"backup_tier={tier}",
                    f"backup_interval_minutes={interval}",
                    f"backup_retention_hours={retention}",
                    f"backup_storage_redundancy={redundancy}",
                    f"topology_recovery_state={recovery_map.get('topology_recovery_state') or 'unknown'}",
                    f"successful_deletion_observed={_display(recovery_map.get('successful_deletion_observed'))}",
                    f"restoration_observed={_display(recovery_map.get('restoration_observed'))}",
                    f"immediate_restoration_established={_display(recovery_map.get('immediate_restoration_established'))}",
                    f"restore_target_evaluated={_display(recovery_map.get('restore_target_evaluated'))}",
                    f"out_of_plan_restore_resources_evaluated={_display(recovery_map.get('out_of_plan_restore_resources_evaluated'))}",
                    f"uncertainties={','.join(_string_values(recovery_map.get('uncertainties'))) or 'none'}",
                )
            )
        )
    return sorted(values)


def _backup_posture_field_values(
    recovery: Mapping[str, object],
    posture: str,
) -> tuple[str, str, str, str]:
    if posture == "continuous":
        return (
            _known_string(recovery.get("backup_tier")) or "unknown",
            "not_applicable",
            "not_applicable",
            "not_applicable",
        )
    if posture in {"periodic", "provider_default_periodic"}:
        return (
            "not_applicable",
            _display(recovery.get("backup_interval_minutes")),
            _display(recovery.get("backup_retention_hours")),
            _known_string(recovery.get("backup_storage_redundancy")) or "unknown",
        )
    return (
        _known_string(recovery.get("backup_tier")) or "unknown",
        _display(recovery.get("backup_interval_minutes")),
        _display(recovery.get("backup_retention_hours")),
        _known_string(recovery.get("backup_storage_redundancy")) or "unknown",
    )


def _assessment_scope() -> list[str]:
    return [
        (
            "establishes=deterministic Azure RBAC control-plane deletion-action authority over exact modeled "
            "Cosmos DB account, SQL database, or SQL container topology with Denial of Service effect"
        ),
        (
            "recovery_evidence=plan-local Cosmos DB backup posture; successful deletion, restoration, immediate "
            "item-level undo, and out-of-plan descendants are not established"
        ),
        (
            "does_not_establish=Cosmos DB native data-plane authorization, database contents, or topology outside "
            "the modeled Terraform plan"
        ),
    ]


def _rationale(
    workload: NormalizedResource,
    target_count: int,
    paths: Sequence[Mapping[str, object]],
) -> str:
    target_text = "target" if target_count == 1 else "targets"
    operations = _operation_text(paths)
    return (
        f"{workload.display_name} permits external ingress within the evidenced scope and its App Service runtime identity "
        "has deterministic "
        f"Azure RBAC control-plane deletion authority ({operations}) across {target_count} exact modeled Cosmos DB "
        f"topology {target_text}. A compromise could request deletion of those modeled account, database, or "
        "container topologies. Backup posture qualifies possible recovery evidence but does not establish successful "
        "deletion, restoration, immediate item-level undo, or impact to out-of-plan descendants."
    )


def _operation_text(paths: Sequence[Mapping[str, object]]) -> str:
    operations = {
        _known_string(path.get("operation")) for path in paths if _known_string(path.get("operation")) is not None
    }
    ordered = [
        operation for operation in (_DELETE_ACCOUNT, _DELETE_DATABASE, _DELETE_CONTAINER) if operation in operations
    ]
    return ", ".join(ordered)


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in cast(list[object], value) if isinstance(item, str) and item]


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _display(value: object) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)
