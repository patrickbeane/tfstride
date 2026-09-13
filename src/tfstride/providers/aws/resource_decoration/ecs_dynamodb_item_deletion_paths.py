from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any, cast

from tfstride.models import (
    NormalizedResource,
    TerraformReferenceProvenance,
    TerraformReferenceResolutionState,
)
from tfstride.providers.aws.reference_resolution import (
    assess_symbolic_reference,
    symbolic_reference_target,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.aws.structured_data_deletion_evidence import (
    AwsDynamoDbBatchWriteDeletePolicyStatementEvidence,
    AwsDynamoDbDeleteItemPolicyStatementEvidence,
    AwsDynamoDbDeletionPolicyStatementEvidence,
    AwsDynamoDbItemDeletionRecoveryEvidence,
    AwsDynamoDbPartiQlDeletePolicyStatementEvidence,
    AwsEcsDynamoDbBatchWriteDeletePath,
    AwsEcsDynamoDbDeleteItemPath,
    AwsEcsDynamoDbItemDeletionPath,
    AwsEcsDynamoDbPartiQlDeletePath,
)
from tfstride.providers.coercion import (
    STATE_DISABLED,
    STATE_ENABLED,
    STATE_NOT_CONFIGURED,
    dedupe,
)

_ECS_TASK_DEFINITION = "aws_ecs_task_definition"
_ECS_SERVICE = "aws_ecs_service"
_DYNAMODB_TABLE = "aws_dynamodb_table"
_IAM_ROLE = "aws_iam_role"


@dataclass(frozen=True, slots=True)
class _OperationDefinition:
    operation: str
    operation_class: str
    internal_operation: str


_OPERATION_DEFINITIONS = (
    _OperationDefinition(
        "dynamodb:DeleteItem",
        "item_deletion",
        "delete_item",
    ),
    _OperationDefinition(
        "dynamodb:PartiQLDelete",
        "item_deletion",
        "partiql_delete",
    ),
    _OperationDefinition(
        "dynamodb:BatchWriteItem",
        "batch_item_deletion",
        "batch_write_delete",
    ),
)
_OPERATION_NAMES = frozenset(definition.operation for definition in _OPERATION_DEFINITIONS)


class ModelEcsDynamoDbItemDeletionPathsStage:
    name = "model_ecs_dynamodb_item_deletion_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AwsDecorationContext,
    ) -> None:
        for task_definition in resources:
            if task_definition.resource_type != _ECS_TASK_DEFINITION:
                continue
            paths, uncertainties = _task_definition_deletion_paths(
                task_definition,
                context,
            )
            facts = aws_facts(task_definition)
            facts.set_ecs_dynamodb_item_deletion_paths(paths)
            facts.extend_ecs_dynamodb_item_deletion_path_uncertainties(
                uncertainties,
            )


class ProjectEcsDynamoDbItemDeletionPathsOntoServicesStage:
    name = "project_ecs_dynamodb_item_deletion_paths_onto_services"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AwsDecorationContext,
    ) -> None:
        for service in resources:
            if service.resource_type != _ECS_SERVICE:
                continue

            service_facts = aws_facts(service)
            paths: list[AwsEcsDynamoDbItemDeletionPath] = []
            uncertainties = [
                f"{service.address}: task definition reference {reference} is "
                "unresolved for DynamoDB item-deletion path projection"
                for reference in service_facts.unresolved_task_definition_references
            ]
            for task_definition_address in service_facts.resolved_task_definition_addresses:
                task_definition = context.index.ecs_task_definitions.get(
                    task_definition_address,
                    source=service,
                )
                if task_definition is None:
                    uncertainties.append(
                        f"{service.address}: resolved task definition "
                        f"{task_definition_address} is unavailable for DynamoDB "
                        "item-deletion path projection"
                    )
                    continue

                task_facts = aws_facts(task_definition)
                uncertainties.extend(
                    task_facts.ecs_dynamodb_item_deletion_path_uncertainties,
                )
                paths.extend(
                    _service_path(service, task_definition, path)
                    for path in task_facts.ecs_dynamodb_item_deletion_paths
                )

            service_facts.set_ecs_dynamodb_item_deletion_paths(paths)
            service_facts.extend_ecs_dynamodb_item_deletion_path_uncertainties(
                dedupe(uncertainties),
            )


def _task_definition_deletion_paths(
    task_definition: NormalizedResource,
    context: AwsDecorationContext,
) -> tuple[list[AwsEcsDynamoDbItemDeletionPath], list[str]]:
    task_facts = aws_facts(task_definition)
    task_role_reference = task_facts.task_role_arn
    if task_role_reference is None:
        return [], _task_role_resolution_uncertainties(task_definition)

    task_role = context.index.role_index.get(task_role_reference, source=task_definition)
    if task_role is None or task_role.resource_type != _IAM_ROLE:
        if _task_role_configuration_reference_observed(task_definition):
            return (
                [],
                [
                    f"{task_definition.address}: task role relationship is "
                    "ambiguous or unresolved for DynamoDB item-deletion paths"
                ],
            )
        return (
            [],
            [
                f"{task_definition.address}: task role {task_role_reference} is "
                "not modeled for DynamoDB item-deletion paths"
            ],
        )
    if not _task_role_relationship_is_exact(
        task_definition,
        task_role,
        context,
    ):
        return [], []

    role_facts = aws_facts(task_role)
    if not _identity_policy_complete(task_role):
        uncertainties = [
            f"{task_definition.address}: task role {task_role.address} has "
            "incomplete identity-policy evidence for DynamoDB item-deletion paths"
        ]
        uncertainties.extend(
            f"{task_definition.address}: {uncertainty}" for uncertainty in role_facts.iam_policy_posture_uncertainties
        )
        return [], dedupe(uncertainties)

    paths: list[AwsEcsDynamoDbItemDeletionPath] = []
    uncertainties = (
        list(task_facts.ecs_dynamodb_access_path_uncertainties) if _role_may_include_deletion_action(task_role) else []
    )
    for source_path in task_facts.ecs_dynamodb_access_paths:
        if not _source_path_is_current(
            source_path,
            task_definition,
            task_role,
            context,
        ):
            if _path_may_contain_deletion_evidence(source_path):
                uncertainties.append(
                    f"{task_definition.address}: copied DynamoDB access evidence "
                    "is not current enough for an item-deletion path"
                )
            continue

        table_address = _known_string(source_path.get("dynamodb_table_address"))
        if table_address is None:
            continue
        table = context.index.resources_by_address.get(table_address)
        if table is None:
            continue

        for definition in _OPERATION_DEFINITIONS:
            path, operation_uncertainties = _operation_path(
                task_definition,
                task_role,
                table,
                source_path,
                definition,
                context,
            )
            if path is not None:
                paths.append(path)
            uncertainties.extend(operation_uncertainties)

    paths.sort(
        key=lambda path: (
            path["dynamodb_table_address"],
            path["operation"],
            path["role_address"],
        )
    )
    return paths, dedupe(uncertainties)


def _operation_path(
    task_definition: NormalizedResource,
    task_role: NormalizedResource,
    table: NormalizedResource,
    source_path: Mapping[str, Any],
    definition: _OperationDefinition,
    context: AwsDecorationContext,
) -> tuple[AwsEcsDynamoDbItemDeletionPath | None, list[str]]:
    operation = definition.operation
    denied_actions = _string_values(source_path.get("denied_actions"))
    unknown_actions = _string_values(source_path.get("unknown_actions"))
    matched_actions = _string_values(source_path.get("matched_actions"))

    if operation in denied_actions:
        return None, []
    if operation in unknown_actions:
        return (
            None,
            [
                f"{task_definition.address}: {operation} authority on "
                f"{table.address} requires unresolved or conditional policy "
                "evaluation"
            ],
        )
    if operation not in matched_actions:
        return None, []

    statement_records = _mapping_records(source_path.get("policy_statements"))
    if statement_records is None:
        return (
            None,
            [
                f"{task_definition.address}: {operation} authority on "
                f"{table.address} has malformed policy-statement evidence"
            ],
        )

    matching_records = [
        record for record in statement_records if operation in _string_values(record.get("matched_actions"))
    ]
    if any(
        _known_string(record.get("effect")) == "deny" and record.get("conditional") is True
        for record in matching_records
    ):
        return (
            None,
            [
                f"{task_definition.address}: {operation} authority on "
                f"{table.address} requires conditional deny evaluation"
            ],
        )
    if any(
        _known_string(record.get("effect")) == "deny" and record.get("conditional") is False
        for record in matching_records
    ):
        return None, []

    policy_statements: list[AwsDynamoDbDeletionPolicyStatementEvidence] = []
    for record in matching_records:
        statement = _deterministic_statement(
            record,
            operation,
            table,
            task_role,
            context,
        )
        if statement is not None:
            policy_statements.append(statement)

    if not policy_statements:
        return (
            None,
            [
                f"{task_definition.address}: {operation} authority on "
                f"{table.address} lacks an unconditional exact-table allow"
            ],
        )

    table_arn = aws_facts(table).dynamodb_table_arn
    table_name = table.identifier
    task_role_reference = _task_role_evidence_reference(
        task_definition,
        task_role,
    )
    table_references = sorted(
        {reference for statement in policy_statements for reference in statement["matching_resources"]},
        key=str.casefold,
    )
    if table_name is None or task_role_reference is None or not table_references:
        return (
            None,
            [f"{task_definition.address}: {operation} target or runtime identity is unresolved"],
        )
    table_reference = table_arn if table_arn is not None and table_arn in table_references else table_references[0]

    recovery = _recovery_evidence(table)
    posture_uncertainties = list(recovery["uncertainties"])
    operation_uncertainties = [
        f"{task_definition.address}: {table.address} {operation} recovery evidence is uncertain: {uncertainty}"
        for uncertainty in posture_uncertainties
    ]
    common: dict[str, object] = {
        "workload_address": task_definition.address,
        "workload_type": task_definition.resource_type,
        "task_definition_address": task_definition.address,
        "task_definition_arn": task_definition.arn,
        "internet_facing_load_balancers": [],
        "role_kind": "ecs_task_role",
        "credential_context": "workload_runtime",
        "role_address": task_role.address,
        "role_reference": task_role_reference,
        "role_arn": task_role.arn,
        "dynamodb_table_address": table.address,
        "dynamodb_table_resource_type": table.resource_type,
        "dynamodb_table_name": table_name,
        "dynamodb_table_reference": table_reference,
        "dynamodb_table_arn": table_arn,
        "target_granularity": "table_item_namespace",
        "target_scope": "exact_table_item_namespace",
        "target_model_evidence_addresses": [table.address],
        "management_effect": "disruption",
        "authorization_source_addresses": _identity_policy_sources(task_role),
        "evaluation_basis": "modeled_identity_policy",
        "authorization_state": "allowed",
        "role_policy_complete": True,
        "policy_action_patterns": sorted(
            {pattern for statement in policy_statements for pattern in statement["matching_action_patterns"]},
            key=str.casefold,
        ),
        "policy_resources": table_references,
        "resource_scopes": ["exact_table"],
        "explicit_deny": False,
        "conditional_evaluation_required": False,
        "lifecycle_compatibility_state": "not_applicable",
        "recovery_evidence": recovery,
        "posture_uncertainties": posture_uncertainties,
    }

    if operation == "dynamodb:DeleteItem":
        return (
            cast(
                AwsEcsDynamoDbDeleteItemPath,
                {
                    **common,
                    "operation": operation,
                    "operation_class": "item_deletion",
                    "internal_operation": "delete_item",
                    "matched_actions": [operation],
                    "policy_statements": policy_statements,
                },
            ),
            operation_uncertainties,
        )
    if operation == "dynamodb:PartiQLDelete":
        return (
            cast(
                AwsEcsDynamoDbPartiQlDeletePath,
                {
                    **common,
                    "operation": operation,
                    "operation_class": "item_deletion",
                    "internal_operation": "partiql_delete",
                    "matched_actions": [operation],
                    "policy_statements": policy_statements,
                },
            ),
            operation_uncertainties,
        )
    return (
        cast(
            AwsEcsDynamoDbBatchWriteDeletePath,
            {
                **common,
                "operation": operation,
                "operation_class": "batch_item_deletion",
                "internal_operation": "batch_write_delete",
                "matched_actions": [operation],
                "policy_statements": policy_statements,
                "batch_write_includes_put_capability": True,
            },
        ),
        operation_uncertainties,
    )


def _deterministic_statement(
    record: Mapping[str, Any],
    operation: str,
    table: NormalizedResource,
    task_role: NormalizedResource,
    context: AwsDecorationContext,
) -> AwsDynamoDbDeletionPolicyStatementEvidence | None:
    matching_resources = _string_values(record.get("matching_resources"))
    if (
        _known_string(record.get("effect")) != "allow"
        or record.get("conditional") is not False
        or record.get("conditions") != []
        or not matching_resources
        or not all(
            _table_reference_matches(
                task_role,
                table,
                reference,
                context,
            )
            for reference in matching_resources
        )
        or _string_values(record.get("resource_scopes")) != ["exact_table"]
    ):
        return None

    matching_patterns = [
        pattern
        for pattern in _string_values(record.get("matching_action_patterns"))
        if fnmatchcase(operation.casefold(), pattern.casefold())
    ]
    actions = _string_values(record.get("actions"))
    resources = _string_values(record.get("resources"))
    if not matching_patterns or not actions or not set(matching_resources) <= set(resources):
        return None

    common: dict[str, object] = {
        "effect": "allow",
        "actions": actions,
        "matching_action_patterns": matching_patterns,
        "resources": resources,
        "matching_resources": matching_resources,
        "resource_scopes": ["exact_table"],
        "conditions": [],
        "conditional": False,
    }
    if operation == "dynamodb:DeleteItem":
        return cast(
            AwsDynamoDbDeleteItemPolicyStatementEvidence,
            {**common, "matched_actions": [operation]},
        )
    if operation == "dynamodb:PartiQLDelete":
        return cast(
            AwsDynamoDbPartiQlDeletePolicyStatementEvidence,
            {**common, "matched_actions": [operation]},
        )
    if operation == "dynamodb:BatchWriteItem":
        return cast(
            AwsDynamoDbBatchWriteDeletePolicyStatementEvidence,
            {**common, "matched_actions": [operation]},
        )
    return None


def _source_path_is_current(
    path: Mapping[str, Any],
    task_definition: NormalizedResource,
    task_role: NormalizedResource,
    context: AwsDecorationContext,
) -> bool:
    table_address = _known_string(path.get("dynamodb_table_address"))
    table = context.index.resources_by_address.get(table_address) if table_address is not None else None
    if table is None or table.resource_type != _DYNAMODB_TABLE:
        return False

    table_arn = aws_facts(table).dynamodb_table_arn
    task_role_reference = aws_facts(task_definition).task_role_arn
    table_reference = _known_string(path.get("dynamodb_target_arn"))
    expected_role_value = task_role.arn or task_role_reference
    expected_table_value = table_arn or table_reference
    return bool(
        task_role_reference is not None
        and table_reference is not None
        and _task_role_relationship_is_exact(
            task_definition,
            task_role,
            context,
        )
        and _table_reference_matches(
            task_role,
            table,
            table_reference,
            context,
        )
        and path.get("workload_address") == task_definition.address
        and path.get("workload_type") == task_definition.resource_type
        and path.get("role_kind") == "ecs_task_role"
        and path.get("credential_context") == "workload_runtime"
        and path.get("role_address") == task_role.address
        and path.get("role_arn") == expected_role_value
        and path.get("role_policy_complete") is True
        and path.get("evaluation_basis") == "modeled_identity_policy"
        and path.get("dynamodb_target_kind") == "table"
        and path.get("dynamodb_target_scope") == "exact_table"
        and path.get("dynamodb_table_arn") == expected_table_value
        and path.get("dynamodb_table_name") == table.identifier
        and path.get("dynamodb_index_name") is None
        and path.get("dynamodb_index_arn") is None
        and "exact_table" in _string_values(path.get("resource_scopes"))
    )


def _task_role_evidence_reference(
    task_definition: NormalizedResource,
    task_role: NormalizedResource,
) -> str | None:
    current = aws_facts(task_definition).task_role_arn
    if task_role.arn is not None and current == task_role.arn:
        return current
    for resolution in task_definition.reference_resolutions:
        if (
            resolution.path != ("task_role_arn",)
            or resolution.state != TerraformReferenceResolutionState.SYMBOLIC
            or resolution.provenance != TerraformReferenceProvenance.CONFIGURATION_REFERENCE
            or len(resolution.targets) != 1
        ):
            continue
        target = resolution.targets[0]
        if target.address == task_role.address and target.reference.endswith(".arn"):
            return target.reference
    return None


def _task_role_relationship_is_exact(
    task_definition: NormalizedResource,
    task_role: NormalizedResource,
    context: AwsDecorationContext,
) -> bool:
    reference = aws_facts(task_definition).task_role_arn
    if reference is None:
        return False
    if task_role.arn is not None and reference == task_role.arn:
        return True
    symbolic = symbolic_reference_target(
        task_definition,
        context.index,
        "task_role_arn",
        expected_resource_types={_IAM_ROLE},
        expected_reference_suffixes={".arn"},
    )
    return bool(symbolic is not None and symbolic.address == task_role.address and reference == task_role.address)


def _task_role_configuration_reference_observed(
    task_definition: NormalizedResource,
) -> bool:
    return any(
        resolution.path == ("task_role_arn",)
        and resolution.provenance == TerraformReferenceProvenance.CONFIGURATION_REFERENCE
        for resolution in task_definition.reference_resolutions
    )


def _task_role_resolution_uncertainties(
    task_definition: NormalizedResource,
) -> list[str]:
    uncertainties = [
        f"{task_definition.address}: task role reference {reference} is unresolved for DynamoDB item-deletion paths"
        for reference in aws_facts(task_definition).unresolved_task_role_arns
    ]
    if any(
        resolution.path == ("task_role_arn",)
        and resolution.provenance == TerraformReferenceProvenance.CONFIGURATION_REFERENCE
        and resolution.state
        in {
            TerraformReferenceResolutionState.AMBIGUOUS,
            TerraformReferenceResolutionState.UNRESOLVED,
            TerraformReferenceResolutionState.UNSUPPORTED,
        }
        for resolution in task_definition.reference_resolutions
    ):
        uncertainties.append(
            f"{task_definition.address}: task role configuration "
            "reference is ambiguous or unresolved for DynamoDB "
            "item-deletion paths"
        )
    return dedupe(uncertainties)


def _table_reference_matches(
    task_role: NormalizedResource,
    table: NormalizedResource,
    reference: str,
    context: AwsDecorationContext,
) -> bool:
    table_arn = aws_facts(table).dynamodb_table_arn or table.arn
    if table_arn is not None and reference == table_arn:
        return True

    candidates: set[str] = set()
    uncertain = False
    for source in _identity_policy_resources(task_role, context):
        assessment = assess_symbolic_reference(
            source,
            context.index,
            reference,
            expected_resource_types={_DYNAMODB_TABLE},
            expected_reference_suffixes={".arn"},
        )
        if assessment.state == "resolved" and assessment.target is not None:
            candidates.add(assessment.target.address)
        elif assessment.state == "uncertain":
            uncertain = True
    return not uncertain and candidates == {table.address}


def _identity_policy_resources(
    role: NormalizedResource,
    context: AwsDecorationContext,
) -> list[NormalizedResource]:
    facts = aws_facts(role)
    resources = [role]
    for address in (
        *facts.inline_policy_resource_addresses,
        *facts.attached_policy_addresses,
    ):
        source = context.index.resources_by_address.get(address)
        if source is not None:
            resources.append(source)
    return resources


def _role_may_include_deletion_action(role: NormalizedResource) -> bool:
    return any(
        any(
            fnmatchcase(operation.casefold(), action.casefold())
            for operation in _OPERATION_NAMES
            for action in statement.actions
        )
        for statement in role.policy_statements
    )


def _identity_policy_complete(role: NormalizedResource) -> bool:
    facts = aws_facts(role)
    return bool(
        facts.iam_policy_completeness_state == "complete"
        and not facts.unresolved_attached_policy_arns
        and all(
            statement.effect.strip().casefold() in {"allow", "deny"}
            and bool(statement.actions)
            and bool(statement.resources)
            and not statement.principal_entries
            for statement in role.policy_statements
        )
    )


def _identity_policy_sources(role: NormalizedResource) -> list[str]:
    facts = aws_facts(role)
    return dedupe(
        [
            role.address,
            *facts.inline_policy_resource_addresses,
            *facts.attached_policy_addresses,
        ]
    )


def _recovery_evidence(
    table: NormalizedResource,
) -> AwsDynamoDbItemDeletionRecoveryEvidence:
    facts = aws_facts(table)
    uncertainties = [
        uncertainty for uncertainty in facts.dynamodb_posture_uncertainties if "point_in_time_recovery" in uncertainty
    ]
    state = facts.dynamodb_pitr_state
    days = facts.dynamodb_pitr_recovery_period_days
    if state == STATE_ENABLED:
        if days is not None and days <= 0:
            uncertainties.append("point_in_time_recovery.recovery_period_in_days is not positive")
            days = None
        return {
            "recovery_evidence_scope": "dynamodb_point_in_time_recovery",
            "pitr_state": "enabled",
            "pitr_enabled": True,
            "pitr_recovery_period_days": days,
            "uncertainties": dedupe(uncertainties),
        }
    if state == STATE_DISABLED:
        return {
            "recovery_evidence_scope": "dynamodb_point_in_time_recovery",
            "pitr_state": "disabled",
            "pitr_enabled": False,
            "pitr_recovery_period_days": None,
            "uncertainties": dedupe(uncertainties),
        }
    if state == STATE_NOT_CONFIGURED:
        return {
            "recovery_evidence_scope": "dynamodb_point_in_time_recovery",
            "pitr_state": "not_configured",
            "pitr_enabled": False,
            "pitr_recovery_period_days": None,
            "uncertainties": dedupe(uncertainties),
        }
    if not uncertainties:
        uncertainties.append("point_in_time_recovery posture is unresolved for item-deletion recovery evidence")
    return {
        "recovery_evidence_scope": "dynamodb_point_in_time_recovery",
        "pitr_state": "unknown",
        "pitr_enabled": None,
        "pitr_recovery_period_days": None,
        "uncertainties": dedupe(uncertainties),
    }


def _service_path(
    service: NormalizedResource,
    task_definition: NormalizedResource,
    path: AwsEcsDynamoDbItemDeletionPath,
) -> AwsEcsDynamoDbItemDeletionPath:
    projected = dict(path)
    projected["workload_address"] = service.address
    projected["workload_type"] = service.resource_type
    projected["task_definition_address"] = task_definition.address
    projected["task_definition_arn"] = task_definition.arn
    projected["internet_facing_load_balancers"] = aws_facts(service).internet_facing_load_balancer_addresses
    return cast(AwsEcsDynamoDbItemDeletionPath, projected)


def _path_may_contain_deletion_evidence(path: Mapping[str, Any]) -> bool:
    return bool(
        _OPERATION_NAMES & set(_string_values(path.get("matched_actions")))
        or _OPERATION_NAMES & set(_string_values(path.get("denied_actions")))
        or _OPERATION_NAMES & set(_string_values(path.get("unknown_actions")))
    )


def _mapping_records(
    value: object,
) -> list[Mapping[str, Any]] | None:
    if not isinstance(value, list):
        return None
    records: list[Mapping[str, Any]] = []
    for item in cast(list[object], value):
        if not isinstance(item, Mapping):
            return None
        records.append(cast(Mapping[str, Any], item))
    return records


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted(
        {item for item in value if isinstance(item, str) and item},
        key=str.casefold,
    )
