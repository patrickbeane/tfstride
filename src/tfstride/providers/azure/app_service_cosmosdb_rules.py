from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

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
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import (
    AZURE_APP_SERVICE_RESOURCE_TYPES,
    AzureResourceType,
)
from tfstride.providers.coercion import STATE_CONFIGURED, STATE_NOT_CONFIGURED

_ITEM_DELETE_OPERATION = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/delete"
_ITEM_DELETE_ACTION = _ITEM_DELETE_OPERATION.casefold()
_MUTATION_OPERATION_ORDER = ("create", "update")
_MUTATION_ACTION_OPERATIONS: dict[str, tuple[str, ...]] = {
    ("microsoft.documentdb/databaseaccounts/sqldatabases/containers/items/create"): ("create",),
    ("microsoft.documentdb/databaseaccounts/sqldatabases/containers/items/replace"): ("update",),
    ("microsoft.documentdb/databaseaccounts/sqldatabases/containers/items/upsert"): ("create", "update"),
}
_CONTAINER_WILDCARD = "microsoft.documentdb/databaseaccounts/sqldatabases/containers/*"
_ITEM_WILDCARD = "microsoft.documentdb/databaseaccounts/sqldatabases/containers/items/*"
_ITEM_READ_ACTION = "microsoft.documentdb/databaseaccounts/sqldatabases/containers/items/read"
_ITEM_UNMASK_ACTION = "microsoft.documentdb/databaseaccounts/sqldatabases/containers/items/unmask"
_EXECUTE_QUERY_ACTION = "microsoft.documentdb/databaseaccounts/sqldatabases/containers/executequery"
_READ_CHANGE_FEED_ACTION = "microsoft.documentdb/databaseaccounts/sqldatabases/containers/readchangefeed"
_READ_CAPABILITY_ORDER = ("point_read", "query", "change_feed_read")
_MUTATING_ROLE_KINDS = frozenset({"built_in_data_contributor", "custom"})
_READING_ROLE_KINDS = frozenset({"built_in_data_reader", "built_in_data_contributor", "custom"})
_SCOPE_CONTRACTS: dict[str, tuple[str, str]] = {
    "account": (
        AzureResourceType.COSMOSDB_ACCOUNT,
        "exact_cosmosdb_for_nosql_account",
    ),
    "database": (
        AzureResourceType.COSMOSDB_SQL_DATABASE,
        "exact_cosmosdb_for_nosql_database",
    ),
    "container": (
        AzureResourceType.COSMOSDB_SQL_CONTAINER,
        "exact_cosmosdb_for_nosql_container",
    ),
}
_SCOPE_BLAST_RADIUS = {
    "account": 3,
    "database": 2,
    "container": 1,
}


@dataclass(frozen=True, slots=True)
class _CosmosDbReadProfile:
    capabilities: tuple[str, ...]
    matched_actions: tuple[str, ...]
    unmask: bool


class AzureAppServiceCosmosDbRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_app_service_cosmosdb_mutation_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            ingress = app_service_ingress(app, context)
            if not ingress.is_public:
                continue

            mutation_paths = [
                path
                for path in azure_facts(app).app_service_cosmosdb_access_paths
                if _is_deterministic_mutation_path(path, app, context)
            ]
            if not mutation_paths:
                continue

            target_addresses = _path_string_values(
                mutation_paths,
                "cosmosdb_resource_address",
            )
            account_addresses = _path_string_values(
                mutation_paths,
                "cosmosdb_account_address",
            )
            database_addresses = _path_string_values(
                mutation_paths,
                "cosmosdb_database_address",
            )
            container_addresses = _path_string_values(
                mutation_paths,
                "cosmosdb_container_address",
            )
            identity_addresses = _path_string_values(
                mutation_paths,
                "identity_address",
            )
            assignment_addresses = _path_string_values(
                mutation_paths,
                "role_assignment_address",
            )
            role_definition_addresses = _path_string_values(
                mutation_paths,
                "role_definition_address",
            )
            operations = _mutation_operations(mutation_paths)
            scope_types = _scope_types(mutation_paths)
            has_read_access = any("read" in _string_values(path.get("access_classes")) for path in mutation_paths)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=1,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=max(
                    max(_SCOPE_BLAST_RADIUS[scope_type] for scope_type in scope_types),
                    2 if len(target_addresses) > 1 else 1,
                ),
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            app.address,
                            *(address for address in identity_addresses if address != app.address),
                            *account_addresses,
                            *database_addresses,
                            *container_addresses,
                            *target_addresses,
                            *assignment_addresses,
                            *role_definition_addresses,
                        ]
                    ),
                    trust_boundary_id=None,
                    rationale=_mutation_rationale(
                        app,
                        operations,
                        scope_types,
                        len(target_addresses),
                        has_read_access=has_read_access,
                    ),
                    evidence=collect_evidence(
                        *ingress.evidence,
                        evidence_item(
                            "runtime_identity",
                            _runtime_identity_evidence(mutation_paths),
                        ),
                        evidence_item(
                            "cosmosdb_mutation_paths",
                            _mutation_path_evidence(mutation_paths),
                        ),
                        evidence_item(
                            "scope_breadth",
                            _scope_breadth_evidence(mutation_paths),
                        ),
                        evidence_item(
                            "custom_role_actions",
                            _custom_role_action_evidence(mutation_paths),
                        ),
                        evidence_item(
                            "assessment_scope",
                            [
                                (
                                    "establishes=deterministic Cosmos DB for NoSQL native "
                                    "RBAC grant containing exact item mutation DataActions"
                                ),
                                (
                                    "does_not_establish=Cosmos DB network reachability or "
                                    "successful operations after independent network controls"
                                ),
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_public_app_service_cosmosdb_item_disruption(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            app_facts = azure_facts(app)
            ingress = app_service_ingress(app, context)
            if not ingress.is_public:
                continue

            deletion_paths = [
                path
                for path in app_facts.app_service_cosmosdb_item_deletion_paths
                if _is_current_item_deletion_path(path, app, context)
            ]
            if not deletion_paths:
                continue

            target_addresses = _path_string_values(
                deletion_paths,
                "cosmosdb_resource_address",
            )
            account_addresses = _path_string_values(
                deletion_paths,
                "cosmosdb_account_address",
            )
            database_addresses = _path_string_values(
                deletion_paths,
                "cosmosdb_database_address",
            )
            container_addresses = _path_string_values(
                deletion_paths,
                "cosmosdb_container_address",
            )
            identity_addresses = _path_string_values(
                deletion_paths,
                "identity_address",
            )
            authorization_addresses = _deletion_authorization_addresses(
                deletion_paths,
            )
            scope_types = _scope_types(deletion_paths)
            blast_radius = max(
                max(_SCOPE_BLAST_RADIUS[scope_type] for scope_type in scope_types),
                2 if len(target_addresses) > 1 else 1,
            )
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=blast_radius,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            app.address,
                            *(address for address in identity_addresses if address != app.address),
                            *account_addresses,
                            *database_addresses,
                            *container_addresses,
                            *target_addresses,
                            *authorization_addresses,
                        ]
                    ),
                    trust_boundary_id=None,
                    rationale=_item_disruption_rationale(
                        app,
                        scope_types,
                        len(target_addresses),
                    ),
                    evidence=collect_evidence(
                        *ingress.evidence,
                        evidence_item(
                            "runtime_identity",
                            _runtime_identity_evidence(deletion_paths),
                        ),
                        evidence_item(
                            "cosmosdb_item_deletion_paths",
                            _item_deletion_path_evidence(deletion_paths),
                        ),
                        evidence_item(
                            "recovery_posture",
                            _item_deletion_recovery_evidence(deletion_paths),
                        ),
                        evidence_item(
                            "scope_breadth",
                            _scope_breadth_evidence(deletion_paths),
                        ),
                        evidence_item(
                            "cosmosdb_item_deletion_path_uncertainties",
                            _item_deletion_uncertainties(
                                deletion_paths,
                                app_facts.app_service_cosmosdb_item_deletion_path_uncertainties,
                            ),
                        ),
                        evidence_item(
                            "assessment_scope",
                            [
                                (
                                    "establishes=deterministic Cosmos DB for NoSQL "
                                    "native RBAC item-delete authority over exact "
                                    "modeled item namespaces"
                                ),
                                (
                                    "recovery_evidence=plan-local Cosmos DB backup "
                                    "posture; successful deletion, irreversible loss, "
                                    "and successful restoration are not established"
                                ),
                                (
                                    "does_not_establish=Cosmos DB network reachability, "
                                    "specific item identities, or successful operations "
                                    "after independent network controls"
                                ),
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_public_app_service_cosmosdb_read_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            ingress = app_service_ingress(app, context)
            if not ingress.is_public:
                continue

            component_paths = [
                path
                for path in azure_facts(app).app_service_cosmosdb_access_paths
                if _is_deterministic_read_component_path(path, app, context)
            ]
            retrieval_paths = [path for path in component_paths if _path_read_profile(path).capabilities]
            if not retrieval_paths:
                continue
            read_paths = [
                path
                for path in component_paths
                if path in retrieval_paths
                or any(
                    _same_runtime_principal(path, retrieval_path) and _path_scopes_overlap(path, retrieval_path)
                    for retrieval_path in retrieval_paths
                )
            ]

            target_addresses = _path_string_values(
                retrieval_paths,
                "cosmosdb_resource_address",
            )
            account_addresses = _path_string_values(
                read_paths,
                "cosmosdb_account_address",
            )
            database_addresses = _path_string_values(
                read_paths,
                "cosmosdb_database_address",
            )
            container_addresses = _path_string_values(
                read_paths,
                "cosmosdb_container_address",
            )
            identity_addresses = _path_string_values(
                read_paths,
                "identity_address",
            )
            assignment_addresses = _path_string_values(
                read_paths,
                "role_assignment_address",
            )
            role_definition_addresses = _path_string_values(
                read_paths,
                "role_definition_address",
            )
            read_profile = _read_profile(read_paths)
            scope_types = _scope_types(retrieval_paths)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=1,
                data_sensitivity=3 if read_profile.unmask else 2,
                lateral_movement=1,
                blast_radius=max(
                    max(_SCOPE_BLAST_RADIUS[scope_type] for scope_type in scope_types),
                    2 if len(target_addresses) > 1 else 1,
                ),
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            app.address,
                            *(address for address in identity_addresses if address != app.address),
                            *account_addresses,
                            *database_addresses,
                            *container_addresses,
                            *target_addresses,
                            *assignment_addresses,
                            *role_definition_addresses,
                        ]
                    ),
                    trust_boundary_id=None,
                    rationale=_read_rationale(
                        app,
                        read_profile,
                        scope_types,
                        len(target_addresses),
                    ),
                    evidence=collect_evidence(
                        *ingress.evidence,
                        evidence_item(
                            "runtime_identity",
                            _runtime_identity_evidence(read_paths),
                        ),
                        evidence_item(
                            "cosmosdb_read_paths",
                            _read_path_evidence(read_paths),
                        ),
                        evidence_item(
                            "capability_profile",
                            _read_capability_profile_evidence(read_profile),
                        ),
                        evidence_item(
                            "scope_breadth",
                            _scope_breadth_evidence(retrieval_paths),
                        ),
                        evidence_item(
                            "custom_role_actions",
                            _read_custom_role_action_evidence(read_paths),
                        ),
                        evidence_item(
                            "assessment_scope",
                            [
                                (
                                    "establishes=deterministic Cosmos DB for NoSQL native RBAC grant "
                                    "containing item-read or change-feed retrieval DataActions"
                                ),
                                (
                                    "query_semantics=executeQuery establishes query retrieval only when "
                                    "readChangeFeed is also granted"
                                ),
                                ("readMetadata=metadata only; does not retrieve stored item data"),
                                (
                                    "items_unmask=severity modifier when retrieval authority exists; "
                                    "not standalone retrieval authority"
                                ),
                                (
                                    "does_not_establish=Cosmos DB network reachability or successful "
                                    "operations after independent network controls"
                                ),
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _is_current_item_deletion_path(
    path: Mapping[str, Any],
    app: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    scope_type = _known_string(path.get("scope_type"))
    scope_contract = _SCOPE_CONTRACTS.get(scope_type or "")
    granularity_by_scope = {
        "account": "account_item_namespace",
        "database": "database_item_namespace",
        "container": "container_item_namespace",
    }
    if (
        path.get("workload_address") != app.address
        or path.get("workload_type") != app.resource_type
        or path.get("credential_context") != "workload_runtime"
        or path.get("operation") != _ITEM_DELETE_OPERATION
        or path.get("operation_class") != "item_deletion"
        or path.get("management_effect") != "disruption"
        or path.get("matched_data_actions") != [_ITEM_DELETE_OPERATION]
        or path.get("grant_basis") != "cosmosdb_for_nosql_native_role_assignment"
        or path.get("evaluation_basis") != "modeled_native_rbac_assignment"
        or path.get("authorization_state") != "granted"
        or path.get("policy_complete") is not True
        or path.get("authorization_model") != "cosmosdb_for_nosql_native_rbac"
        or path.get("assignment_scope_state") != "resolved"
        or path.get("assignable_scope_compatibility_state") != "resolved"
        or path.get("lifecycle_compatibility_state") != "not_applicable"
        or path.get("role_kind") not in _MUTATING_ROLE_KINDS
        or scope_contract is None
        or path.get("target_scope") != scope_contract[1]
        or path.get("target_granularity") != granularity_by_scope.get(scope_type or "")
        or path.get("cosmosdb_resource_type") != scope_contract[0]
    ):
        return False

    assignment = _resource_by_address(
        context,
        path.get("role_assignment_address"),
        expected_type=AzureResourceType.COSMOSDB_SQL_ROLE_ASSIGNMENT,
    )
    if assignment is None or not _target_relationship_is_exact(path, assignment, context):
        return False
    if not _source_item_deletion_access_path_is_current(path, app, context):
        return False
    if not _authorization_sources_are_current(path):
        return False
    if not _target_model_evidence_is_current(path):
        return False

    account = _resource_by_address(
        context,
        path.get("cosmosdb_account_address"),
        expected_type=AzureResourceType.COSMOSDB_ACCOUNT,
    )
    return account is not None and _item_recovery_evidence_is_current(path, account)


def _source_item_deletion_access_path_is_current(
    path: Mapping[str, Any],
    app: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    copied_keys = (
        "workload_address",
        "workload_type",
        "identity_address",
        "identity_kind",
        "principal_id",
        "credential_context",
        "cosmosdb_account_address",
        "cosmosdb_account_id",
        "cosmosdb_database_address",
        "cosmosdb_database_id",
        "cosmosdb_database_name",
        "cosmosdb_container_address",
        "cosmosdb_container_id",
        "cosmosdb_container_name",
        "cosmosdb_resource_address",
        "cosmosdb_resource_type",
        "cosmosdb_resource_id",
        "role_assignment_address",
        "role_assignment_id",
        "role_definition_reference",
        "role_definition_address",
        "role_definition_name",
        "role_kind",
        "role_data_actions",
        "grant_basis",
        "evaluation_basis",
        "assignment_scope",
        "assignment_scope_state",
        "assignable_scope_compatibility_state",
        "authorization_model",
        "scope_type",
    )
    for source_path in azure_facts(app).app_service_cosmosdb_access_paths:
        if (
            not _is_deterministic_access_path(source_path, app, context)
            or path.get("target_scope") != source_path.get("resource_scope")
            or any(path.get(key) != source_path.get(key) for key in copied_keys)
            or "entity_delete" not in _string_values(source_path.get("access_classes"))
        ):
            continue
        matched_actions = {
            action.strip().casefold() for action in _string_values(source_path.get("matched_data_actions"))
        }
        if _ITEM_DELETE_ACTION in matched_actions and _role_actions_allow_action(
            _string_values(source_path.get("role_data_actions")),
            _ITEM_DELETE_ACTION,
        ):
            return True
    return False


def _authorization_sources_are_current(path: Mapping[str, Any]) -> bool:
    assignment_address = _known_string(path.get("role_assignment_address"))
    role_definition_address = _known_string(path.get("role_definition_address"))
    if assignment_address is None:
        return False
    expected = [assignment_address]
    if path.get("role_kind") == "custom":
        if role_definition_address is None:
            return False
        expected.append(role_definition_address)
    elif role_definition_address is not None:
        return False
    return _string_values(path.get("authorization_source_addresses")) == expected


def _target_model_evidence_is_current(path: Mapping[str, Any]) -> bool:
    expected = [_known_string(path.get("cosmosdb_account_address"))]
    if path.get("scope_type") in {"database", "container"}:
        expected.append(_known_string(path.get("cosmosdb_database_address")))
    if path.get("scope_type") == "container":
        expected.append(_known_string(path.get("cosmosdb_container_address")))
    return all(expected) and _string_values(path.get("target_model_evidence_addresses")) == expected


def _item_recovery_evidence_is_current(
    path: Mapping[str, Any],
    account: NormalizedResource,
) -> bool:
    recovery = path.get("recovery_evidence")
    if not isinstance(recovery, Mapping):
        return False
    expected = _current_item_recovery_evidence(account)
    return dict(recovery) == expected and _string_values(path.get("posture_uncertainties")) == expected["uncertainties"]


def _current_item_recovery_evidence(
    account: NormalizedResource,
) -> dict[str, object]:
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


def _is_deterministic_mutation_path(
    path: Mapping[str, Any],
    app: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    return (
        bool(_path_mutation_operations(path))
        and path.get("role_kind") in _MUTATING_ROLE_KINDS
        and _is_deterministic_access_path(
            path,
            app,
            context,
        )
    )


def _is_deterministic_read_component_path(
    path: Mapping[str, Any],
    app: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    profile = _path_read_profile(path)
    return (
        bool(profile.capabilities or profile.matched_actions)
        and path.get("role_kind") in _READING_ROLE_KINDS
        and _is_deterministic_access_path(
            path,
            app,
            context,
        )
    )


def _is_deterministic_access_path(
    path: Mapping[str, Any],
    app: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    scope_type = _known_string(path.get("scope_type"))
    scope_contract = _SCOPE_CONTRACTS.get(scope_type or "")
    if (
        path.get("workload_address") != app.address
        or path.get("workload_type") != app.resource_type
        or path.get("identity_kind") not in {"system_assigned", "user_assigned"}
        or path.get("credential_context") != "workload_runtime"
        or path.get("grant_basis") != "cosmosdb_for_nosql_native_role_assignment"
        or path.get("evaluation_basis") != "modeled_native_rbac_assignment"
        or path.get("authorization_model") != "cosmosdb_for_nosql_native_rbac"
        or path.get("access_state") != "granted"
        or path.get("assignment_scope_state") != "resolved"
        or path.get("assignable_scope_compatibility_state") != "resolved"
        or scope_contract is None
        or path.get("resource_scope") != scope_contract[1]
        or path.get("cosmosdb_resource_type") != scope_contract[0]
    ):
        return False

    identity_address = _known_string(path.get("identity_address"))
    principal_id = _known_string(path.get("principal_id"))
    target_address = _known_string(path.get("cosmosdb_resource_address"))
    assignment_address = _known_string(path.get("role_assignment_address"))
    role_name = _known_string(path.get("role_definition_name"))
    role_reference = _known_string(path.get("role_definition_reference"))
    assignment_scope = _known_string(path.get("assignment_scope"))
    if not all(
        (
            identity_address,
            principal_id,
            target_address,
            assignment_address,
            role_name,
            role_reference,
            assignment_scope,
        )
    ):
        return False

    identity = _resource_by_address(
        context,
        identity_address,
        expected_types=(
            *AZURE_APP_SERVICE_RESOURCE_TYPES,
            AzureResourceType.USER_ASSIGNED_IDENTITY,
        ),
    )
    assignment = _resource_by_address(
        context,
        assignment_address,
        expected_type=AzureResourceType.COSMOSDB_SQL_ROLE_ASSIGNMENT,
    )
    if identity is None or assignment is None:
        return False
    if not _same_identifier(azure_facts(identity).principal_id, principal_id):
        return False
    app_facts = azure_facts(app)
    if path.get("identity_kind") == "system_assigned":
        if identity.address != app.address or app_facts.has_system_assigned_identity is not True:
            return False
    elif path.get("identity_kind") == "user_assigned":
        if (
            identity.resource_type != AzureResourceType.USER_ASSIGNED_IDENTITY
            or app_facts.has_user_assigned_identity is not True
            or not _user_identity_is_attached(app_facts, identity.address)
        ):
            return False
    else:
        return False

    assignment_facts = azure_facts(assignment)
    role_data_actions = _string_values(path.get("role_data_actions"))
    if (
        not _same_identifier(
            assignment_facts.cosmosdb_sql_principal_id,
            principal_id,
        )
        or assignment_facts.cosmosdb_sql_role_assignment_scope != assignment_scope
        or assignment_facts.cosmosdb_sql_role_assignment_scope_kind != scope_type
        or assignment_facts.cosmosdb_sql_role_assignment_scope_state != "resolved"
        or assignment_facts.cosmosdb_sql_assignable_scope_compatibility_state != "resolved"
        or assignment_facts.cosmosdb_sql_role_kind != path.get("role_kind")
        or assignment_facts.cosmosdb_sql_role_definition_reference != role_reference
        or assignment_facts.cosmosdb_sql_role_definition_name != role_name
        or assignment_facts.cosmosdb_sql_role_data_actions != role_data_actions
    ):
        return False

    if not _target_relationship_is_exact(
        path,
        assignment,
        context,
    ):
        return False

    role_definition_address = _known_string(path.get("role_definition_address"))
    if path.get("role_kind") == "custom":
        role_definition = _resource_by_address(
            context,
            role_definition_address,
            expected_type=AzureResourceType.COSMOSDB_SQL_ROLE_DEFINITION,
        )
        if (
            role_definition is None
            or assignment_facts.resolved_cosmosdb_sql_role_definition_address != role_definition.address
            or azure_facts(role_definition).cosmosdb_sql_role_definition_data_actions != role_data_actions
        ):
            return False
    return True


def _target_relationship_is_exact(
    path: Mapping[str, Any],
    assignment: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    assignment_facts = azure_facts(assignment)
    scope_type = _known_string(path.get("scope_type"))
    target_address = _known_string(path.get("cosmosdb_resource_address"))
    account_address = _known_string(path.get("cosmosdb_account_address"))
    target = _resource_by_address(context, target_address)
    account = _resource_by_address(
        context,
        account_address,
        expected_type=AzureResourceType.COSMOSDB_ACCOUNT,
    )
    if (
        target is None
        or account is None
        or assignment_facts.resolved_cosmosdb_account_address != account.address
        or path.get("cosmosdb_account_id") != azure_facts(account).cosmosdb_account_id
        or path.get("cosmosdb_resource_type") != target.resource_type
        or path.get("cosmosdb_resource_id") != _cosmosdb_resource_id(target)
    ):
        return False

    database_address = _known_string(path.get("cosmosdb_database_address"))
    container_address = _known_string(path.get("cosmosdb_container_address"))
    if scope_type == "account":
        return (
            target.address == account.address
            and database_address is None
            and container_address is None
            and assignment_facts.resolved_cosmosdb_database_address is None
            and assignment_facts.resolved_cosmosdb_container_address is None
        )

    database = _resource_by_address(
        context,
        database_address,
        expected_type=AzureResourceType.COSMOSDB_SQL_DATABASE,
    )
    if (
        database is None
        or azure_facts(database).resolved_cosmosdb_account_address != account.address
        or assignment_facts.resolved_cosmosdb_database_address != database.address
        or path.get("cosmosdb_database_id") != azure_facts(database).cosmosdb_sql_database_id
        or path.get("cosmosdb_database_name") != azure_facts(database).cosmosdb_sql_database_name
    ):
        return False
    if scope_type == "database":
        return (
            target.address == database.address
            and container_address is None
            and assignment_facts.resolved_cosmosdb_container_address is None
        )

    container = _resource_by_address(
        context,
        container_address,
        expected_type=AzureResourceType.COSMOSDB_SQL_CONTAINER,
    )
    return bool(
        scope_type == "container"
        and container is not None
        and target.address == container.address
        and azure_facts(container).resolved_cosmosdb_account_address == account.address
        and azure_facts(container).resolved_cosmosdb_database_address == database.address
        and assignment_facts.resolved_cosmosdb_container_address == container.address
        and path.get("cosmosdb_container_id") == azure_facts(container).cosmosdb_sql_container_id
        and path.get("cosmosdb_container_name") == azure_facts(container).cosmosdb_sql_container_name
    )


def _path_read_profile(path: Mapping[str, Any]) -> _CosmosDbReadProfile:
    role_data_actions = _string_values(path.get("role_data_actions"))
    allowed_actions = {
        normalized
        for action in _string_values(path.get("matched_data_actions"))
        if (normalized := action.strip().casefold()) and _role_actions_allow_action(role_data_actions, normalized)
    }
    has_item_read = _ITEM_READ_ACTION in allowed_actions
    has_change_feed = _READ_CHANGE_FEED_ACTION in allowed_actions
    has_query = _EXECUTE_QUERY_ACTION in allowed_actions and has_change_feed
    capabilities = tuple(
        capability
        for capability, enabled in (
            ("point_read", has_item_read),
            ("query", has_query),
            ("change_feed_read", has_change_feed),
        )
        if enabled
    )
    matched_actions = tuple(
        action
        for action, enabled in (
            (_ITEM_READ_ACTION, has_item_read),
            (_EXECUTE_QUERY_ACTION, _EXECUTE_QUERY_ACTION in allowed_actions),
            (_READ_CHANGE_FEED_ACTION, has_change_feed),
            (_ITEM_UNMASK_ACTION, _ITEM_UNMASK_ACTION in allowed_actions),
        )
        if enabled
    )
    return _CosmosDbReadProfile(
        capabilities=capabilities,
        matched_actions=matched_actions,
        unmask=_ITEM_UNMASK_ACTION in allowed_actions,
    )


def _read_profile(paths: list[dict[str, Any]]) -> _CosmosDbReadProfile:
    profiles = [_path_read_profile(path) for path in paths]
    capabilities = {capability for profile in profiles for capability in profile.capabilities}
    if any(
        _same_runtime_principal(left, right)
        and _path_scopes_overlap(left, right)
        and _EXECUTE_QUERY_ACTION in _path_read_profile(left).matched_actions
        and _READ_CHANGE_FEED_ACTION in _path_read_profile(right).matched_actions
        for left in paths
        for right in paths
    ):
        capabilities.add("query")
    matched_actions = {action for profile in profiles for action in profile.matched_actions}
    return _CosmosDbReadProfile(
        capabilities=tuple(capability for capability in _READ_CAPABILITY_ORDER if capability in capabilities),
        matched_actions=tuple(
            action
            for action in (
                _ITEM_READ_ACTION,
                _EXECUTE_QUERY_ACTION,
                _READ_CHANGE_FEED_ACTION,
                _ITEM_UNMASK_ACTION,
            )
            if action in matched_actions
        ),
        unmask=any(profile.unmask for profile in profiles),
    )


def _same_runtime_principal(
    left: Mapping[str, Any],
    right: Mapping[str, Any],
) -> bool:
    return (
        left.get("identity_address") == right.get("identity_address")
        and left.get("identity_kind") == right.get("identity_kind")
        and _same_identifier(
            _known_string(left.get("principal_id")),
            _known_string(right.get("principal_id")),
        )
    )


def _user_identity_is_attached(facts: object, address: str) -> bool:
    resolved = getattr(facts, "resolved_attached_identity_addresses", [])
    references = getattr(facts, "attached_identity_references", [])
    if isinstance(resolved, list) and address in resolved:
        return True
    return isinstance(references, list) and any(
        isinstance(reference, str) and (reference == address or reference.startswith(f"{address}."))
        for reference in references
    )


def _path_scopes_overlap(
    left: Mapping[str, Any],
    right: Mapping[str, Any],
) -> bool:
    return _path_scope_contains(left, right) or _path_scope_contains(right, left)


def _path_scope_contains(
    parent: Mapping[str, Any],
    child: Mapping[str, Any],
) -> bool:
    if parent.get("cosmosdb_account_address") != child.get("cosmosdb_account_address"):
        return False
    scope_type = parent.get("scope_type")
    if scope_type == "account":
        return True
    if scope_type == "database":
        return parent.get("cosmosdb_resource_address") == child.get("cosmosdb_database_address")
    if scope_type == "container":
        return parent.get("cosmosdb_resource_address") == child.get("cosmosdb_container_address")
    return False


def _path_mutation_operations(path: Mapping[str, Any]) -> list[str]:
    access_classes = set(_string_values(path.get("access_classes")))
    role_data_actions = _string_values(path.get("role_data_actions"))
    operations: set[str] = set()
    for matched_action in _string_values(path.get("matched_data_actions")):
        normalized = matched_action.strip().casefold()
        action_operations = _MUTATION_ACTION_OPERATIONS.get(normalized)
        if (
            action_operations is None
            or "entity_write" not in access_classes
            or not _role_actions_allow_action(role_data_actions, normalized)
        ):
            continue
        operations.update(action_operations)
    return [operation for operation in _MUTATION_OPERATION_ORDER if operation in operations]


def _role_actions_allow_action(
    role_data_actions: list[str],
    normalized_action: str,
) -> bool:
    for action in role_data_actions:
        normalized = action.strip().casefold()
        if normalized == normalized_action:
            return True
        if normalized == _ITEM_WILDCARD and normalized_action.startswith(
            "microsoft.documentdb/databaseaccounts/sqldatabases/containers/items/"
        ):
            return True
        if normalized == _CONTAINER_WILDCARD and normalized_action in {
            _EXECUTE_QUERY_ACTION,
            _READ_CHANGE_FEED_ACTION,
        }:
            return True
    return False


def _mutation_operations(paths: list[dict[str, Any]]) -> list[str]:
    operations = {operation for path in paths for operation in _path_mutation_operations(path)}
    return [operation for operation in _MUTATION_OPERATION_ORDER if operation in operations]


def _scope_types(paths: list[dict[str, Any]]) -> list[str]:
    values = {value for path in paths if (value := _known_string(path.get("scope_type"))) in _SCOPE_CONTRACTS}
    return [scope_type for scope_type in ("account", "database", "container") if scope_type in values]


def _item_disruption_rationale(
    app: NormalizedResource,
    scope_types: list[str],
    target_count: int,
) -> str:
    return (
        f"{app.display_name} permits external ingress within the evidenced scope and its "
        "runtime managed identity has deterministic Azure Cosmos DB for NoSQL native "
        f"RBAC item-delete authority across {target_count} exact modeled item "
        f"namespace target(s). {_scope_impact(scope_types)} A compromise through an "
        "allowed public application path could delete stored items using the workload "
        "identity and disrupt data availability. Current Cosmos DB backup posture is "
        "reported as plan-local recovery evidence; it does not establish a specific "
        "item deletion, irreversible loss, or successful restoration. This does not "
        "mean that the Cosmos DB for NoSQL account, database, or container is itself "
        "public; Cosmos DB network controls remain separate from the evaluated workload "
        "ingress restrictions."
    )


def _item_deletion_path_evidence(paths: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"operation={path['operation']}",
                    f"operation_class={path['operation_class']}",
                    f"management_effect={path['management_effect']}",
                    f"target_address={path['cosmosdb_resource_address']}",
                    f"target_type={path['cosmosdb_resource_type']}",
                    f"target_id={path['cosmosdb_resource_id']}",
                    f"target_granularity={path['target_granularity']}",
                    f"target_scope={path['target_scope']}",
                    f"account_address={path['cosmosdb_account_address']}",
                    (f"database_address={path.get('cosmosdb_database_address') or 'not_applicable'}"),
                    (f"container_address={path.get('cosmosdb_container_address') or 'not_applicable'}"),
                    f"role_assignment_address={path['role_assignment_address']}",
                    f"role_definition_name={path.get('role_definition_name') or 'unknown'}",
                    f"role_kind={path['role_kind']}",
                    (f"matched_data_actions={','.join(_string_values(path.get('matched_data_actions')))}"),
                    f"scope_type={path['scope_type']}",
                    f"assignment_scope={path['assignment_scope']}",
                    "assignment_scope_state=resolved",
                    "assignable_scope_compatibility_state=resolved",
                    "authorization_state=granted",
                    "policy_complete=true",
                    "authorization_model=cosmosdb_for_nosql_native_rbac",
                )
            )
            for path in paths
        }
    )


def _item_deletion_recovery_evidence(
    paths: list[dict[str, Any]],
) -> list[str]:
    values: set[str] = set()
    for path in paths:
        recovery = path.get("recovery_evidence")
        if not isinstance(recovery, Mapping):
            continue
        posture = _known_string(recovery.get("backup_posture_state")) or "unknown"
        tier, interval, retention, redundancy = _backup_posture_field_values(
            recovery,
            posture,
        )
        values.add(
            "; ".join(
                (
                    f"target_address={path['cosmosdb_resource_address']}",
                    f"operation={path['operation']}",
                    f"backup_posture_state={posture}",
                    (
                        "backup_configuration_state="
                        f"{_known_string(recovery.get('backup_configuration_state')) or 'unknown'}"
                    ),
                    f"backup_type={_known_string(recovery.get('backup_type')) or 'unknown'}",
                    f"backup_tier={tier}",
                    f"backup_interval_minutes={interval}",
                    f"backup_retention_hours={retention}",
                    f"backup_storage_redundancy={redundancy}",
                    f"recovery_state={_item_recovery_state(posture)}",
                    "successful_restore_established=false",
                    "irreversible_loss_established=false",
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
            _display_value(recovery.get("backup_interval_minutes")),
            _display_value(recovery.get("backup_retention_hours")),
            _known_string(recovery.get("backup_storage_redundancy")) or "unknown",
        )
    return (
        _known_string(recovery.get("backup_tier")) or "unknown",
        _display_value(recovery.get("backup_interval_minutes")),
        _display_value(recovery.get("backup_retention_hours")),
        _known_string(recovery.get("backup_storage_redundancy")) or "unknown",
    )


def _item_deletion_uncertainties(
    paths: list[dict[str, Any]],
    aggregate_uncertainties: list[str],
) -> list[str]:
    return sorted(
        {
            *aggregate_uncertainties,
            *(uncertainty for path in paths for uncertainty in _string_values(path.get("posture_uncertainties"))),
        }
    )


def _item_recovery_state(posture: str) -> str:
    return {
        "continuous": "continuous_backup_configured",
        "periodic": "periodic_backup_configured",
        "provider_default_periodic": "provider_default_periodic_backup",
    }.get(posture, "recovery_posture_unknown")


def _display_value(value: object) -> str:
    if isinstance(value, int):
        return str(value)
    return "unknown"


def _deletion_authorization_addresses(
    paths: list[dict[str, Any]],
) -> list[str]:
    return sorted({address for path in paths for address in _string_values(path.get("authorization_source_addresses"))})


def _read_rationale(
    app: NormalizedResource,
    profile: _CosmosDbReadProfile,
    scope_types: list[str],
    target_count: int,
) -> str:
    rationale = (
        f"{app.display_name} permits external ingress within the evidenced scope and its "
        "runtime managed identity has deterministic Azure Cosmos DB for NoSQL native "
        f"RBAC grants that can {_read_capability_summary(profile.capabilities)} across "
        f"{target_count} exact modeled target(s). A compromise through an allowed "
        "public application path could attempt the modeled retrieval operations using "
        f"the workload identity. {_scope_impact(scope_types)} "
    )
    if profile.unmask:
        rationale += (
            "The same grants include items/unmask, which can reveal original values "
            "otherwise protected by Dynamic Data Masking and increases the modeled data "
            "sensitivity; unmask does not independently establish retrieval authority. "
        )
    return rationale + (
        "This does not mean that the Cosmos DB for NoSQL account, database, or container "
        "is itself public; Cosmos DB network controls remain separate from the evaluated workload "
        "ingress restrictions."
    )


def _read_capability_summary(capabilities: tuple[str, ...]) -> str:
    values: list[str] = []
    if "point_read" in capabilities:
        values.append("read specific item data")
    if "query" in capabilities:
        values.append("execute queries with the required change-feed permission")
    if "change_feed_read" in capabilities:
        values.append("read the container change feed")
    if len(values) == 1:
        return values[0]
    return ", ".join(values[:-1]) + f", and {values[-1]}"


def _mutation_rationale(
    app: NormalizedResource,
    operations: list[str],
    scope_types: list[str],
    target_count: int,
    *,
    has_read_access: bool,
) -> str:
    rationale = (
        f"{app.display_name} permits external ingress within the evidenced scope and its "
        "runtime managed identity has deterministic Azure Cosmos DB for NoSQL native "
        f"RBAC grants for item {', '.join(operations)} operations across "
        f"{target_count} exact modeled target(s). A compromise through an allowed "
        "public application path could mutate items using the workload identity. "
        f"{_scope_impact(scope_types)} "
        "This does not mean that the Cosmos DB for NoSQL account, database, or "
        "container is itself public; Cosmos DB network controls remain separate from the "
        "evaluated workload ingress restrictions."
    )
    if not has_read_access:
        rationale += " The modeled mutation grants do not establish item read access or information disclosure."
    return rationale


def _scope_impact(scope_types: list[str]) -> str:
    if "account" in scope_types:
        return "At least one account-scoped grant can reach databases and containers throughout the modeled account."
    if "database" in scope_types:
        return "The broadest modeled grant is database-scoped and can reach containers within that exact database."
    return "The modeled grants are limited to exact container scopes."


def _runtime_identity_evidence(paths: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"identity_address={path['identity_address']}",
                    f"identity_kind={path['identity_kind']}",
                    f"principal_id={path['principal_id']}",
                    f"role_definition_name={path['role_definition_name']}",
                    f"role_kind={path['role_kind']}",
                    "credential_context=workload_runtime",
                )
            )
            for path in paths
        }
    )


def _read_path_evidence(paths: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"target_address={path['cosmosdb_resource_address']}",
                    f"target_type={path['cosmosdb_resource_type']}",
                    f"target_id={path.get('cosmosdb_resource_id') or 'unknown'}",
                    f"account_address={path['cosmosdb_account_address']}",
                    (f"database_address={path.get('cosmosdb_database_address') or 'not_applicable'}"),
                    (f"container_address={path.get('cosmosdb_container_address') or 'not_applicable'}"),
                    f"role_assignment_address={path['role_assignment_address']}",
                    f"role_definition_name={path['role_definition_name']}",
                    f"role_kind={path['role_kind']}",
                    (f"read_capabilities={','.join(_path_read_profile(path).capabilities) or 'none'}"),
                    (f"matched_read_actions={','.join(_path_read_profile(path).matched_actions)}"),
                    f"items_unmask_modifier={str(_path_read_profile(path).unmask).lower()}",
                    f"scope_type={path['scope_type']}",
                    f"assignment_scope={path['assignment_scope']}",
                    f"resource_scope={path['resource_scope']}",
                    "assignment_scope_state=resolved",
                    "assignable_scope_compatibility_state=resolved",
                    "access_state=granted",
                    "authorization_model=cosmosdb_for_nosql_native_rbac",
                )
            )
            for path in paths
        }
    )


def _read_capability_profile_evidence(
    profile: _CosmosDbReadProfile,
) -> list[str]:
    return [
        "; ".join(
            (
                f"read_capabilities={','.join(profile.capabilities)}",
                f"matched_read_actions={','.join(profile.matched_actions)}",
                f"items_unmask_modifier={str(profile.unmask).lower()}",
            )
        )
    ]


def _mutation_path_evidence(paths: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"target_address={path['cosmosdb_resource_address']}",
                    f"target_type={path['cosmosdb_resource_type']}",
                    f"target_id={path.get('cosmosdb_resource_id') or 'unknown'}",
                    f"account_address={path['cosmosdb_account_address']}",
                    (f"database_address={path.get('cosmosdb_database_address') or 'not_applicable'}"),
                    (f"container_address={path.get('cosmosdb_container_address') or 'not_applicable'}"),
                    f"role_assignment_address={path['role_assignment_address']}",
                    f"role_definition_name={path['role_definition_name']}",
                    f"role_kind={path['role_kind']}",
                    (f"mutation_operations={','.join(_path_mutation_operations(path))}"),
                    (f"matched_data_actions={','.join(_mutation_data_actions(path))}"),
                    f"scope_type={path['scope_type']}",
                    f"assignment_scope={path['assignment_scope']}",
                    f"resource_scope={path['resource_scope']}",
                    "assignment_scope_state=resolved",
                    "assignable_scope_compatibility_state=resolved",
                    "access_state=granted",
                    "authorization_model=cosmosdb_for_nosql_native_rbac",
                )
            )
            for path in paths
        }
    )


def _mutation_data_actions(path: Mapping[str, Any]) -> list[str]:
    return [
        action
        for action in _string_values(path.get("matched_data_actions"))
        if action.strip().casefold() in _MUTATION_ACTION_OPERATIONS
    ]


def _scope_breadth_evidence(paths: list[dict[str, Any]]) -> list[str]:
    counts = {
        scope_type: sum(path.get("scope_type") == scope_type for path in paths)
        for scope_type in ("account", "database", "container")
    }
    broadest = next(scope_type for scope_type in ("account", "database", "container") if counts[scope_type])
    return [
        "; ".join(
            (
                f"account_scoped_grants={counts['account']}",
                f"database_scoped_grants={counts['database']}",
                f"container_scoped_grants={counts['container']}",
                f"broadest_scope={broadest}",
                f"blast_radius_factor={_SCOPE_BLAST_RADIUS[broadest]}",
            )
        )
    ]


def _read_custom_role_action_evidence(paths: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"role_definition_address={path['role_definition_address']}",
                    (f"role_data_actions={','.join(_string_values(path.get('role_data_actions')))}"),
                    (f"matched_read_actions={','.join(_path_read_profile(path).matched_actions)}"),
                    f"items_unmask_modifier={str(_path_read_profile(path).unmask).lower()}",
                )
            )
            for path in paths
            if path.get("role_kind") == "custom"
        }
    )


def _custom_role_action_evidence(paths: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"role_definition_address={path['role_definition_address']}",
                    (f"role_data_actions={','.join(_string_values(path.get('role_data_actions')))}"),
                    (f"matched_mutation_actions={','.join(_mutation_data_actions(path))}"),
                )
            )
            for path in paths
            if path.get("role_kind") == "custom"
        }
    )


def _resource_by_address(
    context: RuleEvaluationContext,
    address: object,
    *,
    expected_type: str | None = None,
    expected_types: tuple[str, ...] = (),
) -> NormalizedResource | None:
    if not isinstance(address, str) or not address:
        return None
    resource = context.inventory.get_by_address(address)
    if resource is None:
        return None
    allowed_types = expected_types or ((expected_type,) if expected_type is not None else ())
    if allowed_types and resource.resource_type not in allowed_types:
        return None
    return resource


def _cosmosdb_resource_id(resource: NormalizedResource) -> str | None:
    facts = azure_facts(resource)
    if resource.resource_type == AzureResourceType.COSMOSDB_ACCOUNT:
        return facts.cosmosdb_account_id
    if resource.resource_type == AzureResourceType.COSMOSDB_SQL_DATABASE:
        return facts.cosmosdb_sql_database_id
    if resource.resource_type == AzureResourceType.COSMOSDB_SQL_CONTAINER:
        return facts.cosmosdb_sql_container_id
    return None


def _path_string_values(paths: list[dict[str, Any]], key: str) -> list[str]:
    return sorted({value for path in paths if (value := _known_string(path.get(key))) is not None})


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _same_identifier(left: str | None, right: str | None) -> bool:
    return bool(left and right and left.strip().casefold() == right.strip().casefold())
