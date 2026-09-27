from __future__ import annotations

from collections.abc import Mapping, Sequence
from fnmatch import fnmatchcase
from typing import cast

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import (
    Finding,
    NormalizedResource,
    TerraformReferenceProvenance,
    TerraformReferenceResolutionState,
)
from tfstride.providers.aws.ecs_path_rule_helpers import (
    internet_boundary_id,
    path_string_values,
    verified_public_service_ingress,
)
from tfstride.providers.aws.resource_facts import AwsResourceFacts, aws_facts
from tfstride.providers.aws.structured_data_deletion_evidence import (
    AwsDynamoDbItemDeletionRecoveryEvidence,
    AwsEcsDynamoDbItemDeletionPath,
)
from tfstride.providers.coercion import (
    STATE_DISABLED,
    STATE_ENABLED,
    STATE_NOT_CONFIGURED,
    dedupe,
)

_AWS_DYNAMODB_TABLE = "aws_dynamodb_table"
_AWS_ECS_SERVICE = "aws_ecs_service"
_AWS_ECS_TASK_DEFINITION = "aws_ecs_task_definition"
_AWS_IAM_ROLE = "aws_iam_role"
_OPERATION_ORDER = (
    "dynamodb:DeleteItem",
    "dynamodb:PartiQLDelete",
    "dynamodb:BatchWriteItem",
)
_OPERATION_DEFINITIONS = {
    "dynamodb:DeleteItem": (
        "item_deletion",
        "delete_item",
        False,
    ),
    "dynamodb:PartiQLDelete": (
        "item_deletion",
        "partiql_delete",
        False,
    ),
    "dynamodb:BatchWriteItem": (
        "batch_item_deletion",
        "batch_write_delete",
        True,
    ),
}
_EXCLUDED_PROJECTION_FIELDS = frozenset(
    {
        "workload_address",
        "workload_type",
        "internet_facing_load_balancers",
    }
)


class AwsEcsDynamoDbItemDisruptionRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_service_item_disruption(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for service in context.inventory.by_type(_AWS_ECS_SERVICE):
            service_facts = aws_facts(service)
            paths = [
                path
                for path in service_facts.ecs_dynamodb_item_deletion_paths
                if _is_current_deterministic_path(path, service, context)
            ]
            if not paths:
                continue

            ingress = verified_public_service_ingress(service, context)
            paths = ingress.current_workload_paths(paths)
            load_balancer_addresses = ingress.load_balancer_addresses
            if not load_balancer_addresses or not paths:
                continue

            task_definition_addresses = path_string_values(
                paths,
                "task_definition_address",
            )
            role_addresses = path_string_values(paths, "role_address")
            table_addresses = path_string_values(
                paths,
                "dynamodb_table_address",
            )
            operations = _operations(paths)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=2 if len(table_addresses) > 1 else 1,
            )
            affected_resources = [
                *ingress.resource_addresses,
                service.address,
                *task_definition_addresses,
                *role_addresses,
                *table_addresses,
            ]
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=list(dict.fromkeys(affected_resources)),
                    trust_boundary_id=internet_boundary_id(
                        load_balancer_addresses,
                        context,
                    ),
                    rationale=_rationale(
                        service,
                        operations,
                        len(table_addresses),
                    ),
                    evidence=collect_evidence(
                        evidence_item("network_path", ingress.network_path),
                        *ingress.evidence,
                        evidence_item(
                            "task_definitions",
                            [f"address={address}" for address in task_definition_addresses],
                        ),
                        evidence_item(
                            "task_roles",
                            _task_role_evidence(paths),
                        ),
                        evidence_item(
                            "dynamodb_item_deletion_paths",
                            _deletion_path_evidence(paths),
                        ),
                        evidence_item(
                            "recovery_evidence",
                            _recovery_evidence(paths),
                        ),
                        evidence_item(
                            "dynamodb_item_deletion_path_uncertainties",
                            service_facts.ecs_dynamodb_item_deletion_path_uncertainties,
                        ),
                        evidence_item(
                            "assessment_scope",
                            _assessment_scope(operations),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _is_current_deterministic_path(
    path: AwsEcsDynamoDbItemDeletionPath,
    service: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    operation = path.get("operation")
    expected_definition = _OPERATION_DEFINITIONS.get(operation)
    if expected_definition is None:
        return False
    operation_class, internal_operation, batch_put_capability = expected_definition

    task_definition = _resource_for_path(
        path,
        "task_definition_address",
        _AWS_ECS_TASK_DEFINITION,
        context,
    )
    role = _resource_for_path(path, "role_address", _AWS_IAM_ROLE, context)
    table = _resource_for_path(
        path,
        "dynamodb_table_address",
        _AWS_DYNAMODB_TABLE,
        context,
    )
    if task_definition is None or role is None or table is None:
        return False

    service_facts = aws_facts(service)
    task_facts = aws_facts(task_definition)
    table_facts = aws_facts(table)
    if (
        task_definition.address not in service_facts.resolved_task_definition_addresses
        or path.get("workload_address") != service.address
        or path.get("workload_type") != service.resource_type
        or path.get("task_definition_address") != task_definition.address
        or path.get("task_definition_arn") != task_definition.arn
        or path.get("role_address") != role.address
        or path.get("role_arn") != role.arn
        or path.get("dynamodb_table_address") != table.address
        or path.get("dynamodb_table_resource_type") != table.resource_type
        or path.get("dynamodb_table_name") != table.identifier
        or path.get("dynamodb_table_arn") != table_facts.dynamodb_table_arn
        or path.get("operation_class") != operation_class
        or path.get("internal_operation") != internal_operation
        or path.get("matched_actions") != [operation]
        or path.get("target_granularity") != "table_item_namespace"
        or path.get("target_scope") != "exact_table_item_namespace"
        or path.get("target_model_evidence_addresses") != [table.address]
        or path.get("management_effect") != "disruption"
        or path.get("role_kind") != "ecs_task_role"
        or path.get("credential_context") != "workload_runtime"
        or path.get("authorization_state") != "allowed"
        or path.get("evaluation_basis") != "modeled_identity_policy"
        or path.get("role_policy_complete") is not True
        or path.get("resource_scopes") != ["exact_table"]
        or path.get("explicit_deny") is not False
        or path.get("conditional_evaluation_required") is not False
        or path.get("lifecycle_compatibility_state") != "not_applicable"
        or not _batch_capability_is_coherent(
            path,
            batch_put_capability=batch_put_capability,
        )
        or not _task_role_relationship_is_current(
            path,
            task_definition,
            role,
        )
        or not _table_reference_is_current(path, table, role, context)
        or not _authorization_sources_are_current(path, role, context)
        or not _policy_evidence_is_current(path, operation, table, role, context)
        or not _source_access_path_is_current(
            path,
            operation,
            task_facts,
            table,
            role,
            context,
        )
        or not _recovery_evidence_is_current(path, table_facts)
        or not _matches_current_task_path(
            path,
            task_facts.ecs_dynamodb_item_deletion_paths,
        )
    ):
        return False
    return True


def _resource_for_path(
    path: Mapping[str, object],
    key: str,
    expected_type: str,
    context: RuleEvaluationContext,
) -> NormalizedResource | None:
    address = path.get(key)
    resource = context.inventory.get_by_address(address) if isinstance(address, str) else None
    if resource is None or resource.provider != "aws" or resource.resource_type != expected_type:
        return None
    return resource


def _task_role_relationship_is_current(
    path: Mapping[str, object],
    task_definition: NormalizedResource,
    role: NormalizedResource,
) -> bool:
    role_reference = _known_string(path.get("role_reference"))
    current_reference = aws_facts(task_definition).task_role_arn
    if role_reference is None or current_reference is None:
        return False
    if role.arn is not None and current_reference == role.arn and role_reference == role.arn:
        return True
    return bool(
        current_reference == role.address
        and _configuration_reference_resolves_to(
            task_definition,
            role_reference,
            role,
            expected_suffix=".arn",
            expected_path=("task_role_arn",),
        )
    )


def _table_reference_is_current(
    path: Mapping[str, object],
    table: NormalizedResource,
    role: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    reference = _known_string(path.get("dynamodb_table_reference"))
    if reference is None:
        return False
    table_arn = aws_facts(table).dynamodb_table_arn
    if table_arn is not None and reference == table_arn:
        return True

    candidates: set[str] = set()
    observed = False
    for source in _current_authorization_sources(role, context):
        state = _configuration_reference_state(
            source,
            reference,
            table,
            expected_suffix=".arn",
        )
        if state == "uncertain":
            return False
        if state == "resolved":
            observed = True
            candidates.add(table.address)
    return observed and candidates == {table.address}


def _configuration_reference_resolves_to(
    source: NormalizedResource,
    reference: str,
    target: NormalizedResource,
    *,
    expected_suffix: str,
    expected_path: tuple[str | int, ...] | None = None,
) -> bool:
    return (
        _configuration_reference_state(
            source,
            reference,
            target,
            expected_suffix=expected_suffix,
            expected_path=expected_path,
        )
        == "resolved"
    )


def _configuration_reference_state(
    source: NormalizedResource,
    reference: str,
    target: NormalizedResource,
    *,
    expected_suffix: str,
    expected_path: tuple[str | int, ...] | None = None,
) -> str:
    if not reference.endswith(expected_suffix):
        return "not_observed"

    observed = False
    resolved = False
    for resolution in source.reference_resolutions:
        if resolution.provenance != TerraformReferenceProvenance.CONFIGURATION_REFERENCE or (
            expected_path is not None and resolution.path != expected_path
        ):
            continue
        mentioned = reference in resolution.references or any(
            candidate.reference == reference for candidate in resolution.targets
        )
        if not mentioned:
            continue
        observed = True
        if resolution.state != TerraformReferenceResolutionState.SYMBOLIC or len(resolution.targets) != 1:
            return "uncertain"
        candidate = resolution.targets[0]
        if (
            candidate.address != target.address
            or candidate.reference != reference
            or not candidate.reference.endswith(expected_suffix)
        ):
            return "uncertain"
        resolved = True
    if resolved:
        return "resolved"
    return "uncertain" if observed else "not_observed"


def _authorization_sources_are_current(
    path: Mapping[str, object],
    role: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    expected = [source.address for source in _current_authorization_sources(role, context)]
    return path.get("authorization_source_addresses") == expected


def _current_authorization_sources(
    role: NormalizedResource,
    context: RuleEvaluationContext,
) -> list[NormalizedResource]:
    role_facts = aws_facts(role)
    sources = [role]
    for address in (
        *role_facts.inline_policy_resource_addresses,
        *role_facts.attached_policy_addresses,
    ):
        source = context.inventory.get_by_address(address)
        if source is not None and source.provider == "aws":
            sources.append(source)
    return list({source.address: source for source in sources}.values())


def _policy_evidence_is_current(
    path: Mapping[str, object],
    operation: str,
    table: NormalizedResource,
    role: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    role_facts = aws_facts(role)
    if role_facts.iam_policy_completeness_state != "complete" or role_facts.unresolved_attached_policy_arns:
        return False

    policy_resources = _string_values_exact(path.get("policy_resources"))
    action_patterns = _string_values_exact(
        path.get("policy_action_patterns"),
    )
    records = _mapping_records(path.get("policy_statements"))
    if (
        policy_resources is None
        or not policy_resources
        or action_patterns is None
        or not action_patterns
        or records is None
        or not records
        or not all(
            _reference_matches_table(
                reference,
                table,
                role,
                context,
            )
            for reference in policy_resources
        )
        or not all(fnmatchcase(operation.casefold(), pattern.casefold()) for pattern in action_patterns)
    ):
        return False

    for record in records:
        matching_resources = _string_values_exact(
            record.get("matching_resources"),
        )
        matching_patterns = _string_values_exact(
            record.get("matching_action_patterns"),
        )
        actions = _string_values_exact(record.get("actions"))
        resources = _string_values_exact(record.get("resources"))
        if (
            record.get("effect") != "allow"
            or record.get("matched_actions") != [operation]
            or record.get("resource_scopes") != ["exact_table"]
            or record.get("conditions") != []
            or record.get("conditional") is not False
            or matching_resources is None
            or not matching_resources
            or matching_patterns is None
            or not matching_patterns
            or actions is None
            or not actions
            or resources is None
            or not resources
            or not set(matching_resources) <= set(resources)
            or not all(
                _reference_matches_table(
                    reference,
                    table,
                    role,
                    context,
                )
                for reference in matching_resources
            )
            or not all(fnmatchcase(operation.casefold(), pattern.casefold()) for pattern in matching_patterns)
        ):
            return False
    return True


def _source_access_path_is_current(
    path: Mapping[str, object],
    operation: str,
    task_facts: AwsResourceFacts,
    table: NormalizedResource,
    role: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    copied_records = _mapping_records(path.get("policy_statements"))
    if copied_records is None or not copied_records:
        return False
    for source_path in task_facts.ecs_dynamodb_access_paths:
        if (
            source_path.get("workload_address") != path.get("task_definition_address")
            or source_path.get("workload_type") != _AWS_ECS_TASK_DEFINITION
            or source_path.get("role_address") != path.get("role_address")
            or source_path.get("role_kind") != "ecs_task_role"
            or source_path.get("credential_context") != "workload_runtime"
            or source_path.get("dynamodb_table_address") != path.get("dynamodb_table_address")
            or source_path.get("dynamodb_target_kind") != "table"
            or source_path.get("dynamodb_target_scope") != "exact_table"
            or not _source_access_target_is_current(
                source_path,
                table,
                role,
                context,
            )
            or source_path.get("access_state") != "allowed"
            or source_path.get("modeled_access_state") != "allowed"
            or source_path.get("role_policy_complete") is not True
            or operation not in _string_values(source_path.get("matched_actions"))
            or operation in _string_values(source_path.get("denied_actions"))
            or operation in _string_values(source_path.get("unknown_actions"))
        ):
            continue
        current_records = _mapping_records(source_path.get("policy_statements"))
        if current_records is None:
            continue
        if all(
            any(
                _copied_statement_matches_source(
                    copied,
                    current,
                    operation,
                )
                for current in current_records
            )
            for copied in copied_records
        ):
            return True
    return False


def _source_access_target_is_current(
    source_path: Mapping[str, object],
    table: NormalizedResource,
    role: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    target_reference = _known_string(source_path.get("dynamodb_target_arn"))
    table_reference = _known_string(source_path.get("dynamodb_table_arn"))
    return bool(
        target_reference is not None
        and table_reference is not None
        and _reference_matches_table(
            target_reference,
            table,
            role,
            context,
        )
        and _reference_matches_table(
            table_reference,
            table,
            role,
            context,
        )
    )


def _copied_statement_matches_source(
    copied: Mapping[str, object],
    current: Mapping[str, object],
    operation: str,
) -> bool:
    return bool(
        current.get("effect") == copied.get("effect") == "allow"
        and operation in _string_values(current.get("matched_actions"))
        and copied.get("matched_actions") == [operation]
        and set(_string_values(current.get("actions"))) == set(_string_values(copied.get("actions")))
        and set(_string_values(current.get("matching_action_patterns")))
        >= set(_string_values(copied.get("matching_action_patterns")))
        and set(_string_values(current.get("resources"))) == set(_string_values(copied.get("resources")))
        and current.get("matching_resources") == copied.get("matching_resources")
        and current.get("resource_scopes") == copied.get("resource_scopes")
        and current.get("conditions") == copied.get("conditions") == []
        and current.get("conditional") is False
        and copied.get("conditional") is False
    )


def _reference_matches_table(
    reference: str,
    table: NormalizedResource,
    role: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    table_arn = aws_facts(table).dynamodb_table_arn
    if table_arn is not None and reference == table_arn:
        return True
    return any(
        _configuration_reference_resolves_to(
            source,
            reference,
            table,
            expected_suffix=".arn",
        )
        for source in _current_authorization_sources(role, context)
    )


def _batch_capability_is_coherent(
    path: Mapping[str, object],
    *,
    batch_put_capability: bool,
) -> bool:
    if batch_put_capability:
        return path.get("batch_write_includes_put_capability") is True
    return "batch_write_includes_put_capability" not in path


def _recovery_evidence_is_current(
    path: Mapping[str, object],
    table_facts: AwsResourceFacts,
) -> bool:
    actual = path.get("recovery_evidence")
    if not isinstance(actual, Mapping):
        return False
    expected = _current_recovery_evidence(table_facts)
    return (
        dict(cast(Mapping[str, object], actual)) == expected
        and path.get("posture_uncertainties") == expected["uncertainties"]
    )


def _current_recovery_evidence(
    table_facts: AwsResourceFacts,
) -> AwsDynamoDbItemDeletionRecoveryEvidence:
    uncertainties = [
        uncertainty
        for uncertainty in table_facts.dynamodb_posture_uncertainties
        if "point_in_time_recovery" in uncertainty
    ]
    state = table_facts.dynamodb_pitr_state
    days = table_facts.dynamodb_pitr_recovery_period_days
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


def _matches_current_task_path(
    projected_path: Mapping[str, object],
    current_paths: Sequence[Mapping[str, object]],
) -> bool:
    projected_keys = set(projected_path) - _EXCLUDED_PROJECTION_FIELDS
    for current_path in current_paths:
        current_keys = set(current_path) - _EXCLUDED_PROJECTION_FIELDS
        if projected_keys != current_keys:
            continue
        if all(projected_path[key] == current_path[key] for key in projected_keys):
            return True
    return False


def _operations(
    paths: Sequence[Mapping[str, object]],
) -> list[str]:
    return [operation for operation in _OPERATION_ORDER if any(path.get("operation") == operation for path in paths)]


def _task_role_evidence(
    paths: Sequence[Mapping[str, object]],
) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"address={path.get('role_address')}",
                    f"reference={path.get('role_reference')}",
                    f"arn={path.get('role_arn') or 'unknown'}",
                    "role_kind=ecs_task_role",
                    "credential_context=workload_runtime",
                    "authorization_state=allowed",
                )
            )
            for path in paths
        }
    )


def _deletion_path_evidence(
    paths: Sequence[Mapping[str, object]],
) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"table_address={path.get('dynamodb_table_address')}",
                    f"table_name={path.get('dynamodb_table_name')}",
                    f"table_reference={path.get('dynamodb_table_reference')}",
                    f"table_arn={path.get('dynamodb_table_arn') or 'unknown'}",
                    f"operation={path.get('operation')}",
                    f"operation_class={path.get('operation_class')}",
                    f"internal_operation={path.get('internal_operation')}",
                    f"target_granularity={path.get('target_granularity')}",
                    f"target_scope={path.get('target_scope')}",
                    f"task_definition={path.get('task_definition_address')}",
                    f"task_role={path.get('role_address')}",
                    f"matched_actions={','.join(_string_values(path.get('matched_actions')))}",
                    f"authorization_sources={','.join(_string_values(path.get('authorization_source_addresses'))) or 'none'}",
                    f"policy_action_patterns={','.join(_string_values(path.get('policy_action_patterns'))) or 'none'}",
                    f"policy_resources={','.join(_string_values(path.get('policy_resources'))) or 'none'}",
                    f"batch_write_includes_put_capability={str(path.get('batch_write_includes_put_capability') is True).lower()}",
                    "authorization_state=allowed",
                    "operation_evaluation=deterministic_allowed",
                )
            )
            for path in paths
        }
    )


def _recovery_evidence(
    paths: Sequence[Mapping[str, object]],
) -> list[str]:
    values: set[str] = set()
    for path in paths:
        recovery = path.get("recovery_evidence")
        if not isinstance(recovery, Mapping):
            continue
        recovery_map = cast(Mapping[str, object], recovery)
        state = recovery_map.get("pitr_state")
        if state == "enabled":
            recovery_state = "point_in_time_recovery_enabled"
        elif state in {"disabled", "not_configured"}:
            recovery_state = "point_in_time_recovery_not_enabled"
        else:
            recovery_state = "recovery_posture_unknown"
        values.add(
            "; ".join(
                (
                    f"table_address={path.get('dynamodb_table_address')}",
                    f"operation={path.get('operation')}",
                    f"recovery_state={recovery_state}",
                    f"pitr_state={state}",
                    f"pitr_enabled={str(recovery_map.get('pitr_enabled')).lower()}",
                    f"pitr_recovery_period_days={recovery_map.get('pitr_recovery_period_days')}",
                    f"uncertainties={','.join(_string_values(recovery_map.get('uncertainties'))) or 'none'}",
                    "successful_recovery_not_established=true",
                )
            )
        )
    return sorted(values)


def _assessment_scope(operations: Sequence[str]) -> list[str]:
    return [
        (
            f"establishes=deterministic {_operation_text(operations)} authority "
            "for an ECS task role over exact modeled DynamoDB table item namespaces with Denial of Service effect"
        ),
        (
            "does_not_establish=specific item keys, invocation of a deleting API request, successful deletion, "
            "irreversible removal, or successful point-in-time recovery"
        ),
    ]


def _rationale(
    service: NormalizedResource,
    operations: Sequence[str],
    table_count: int,
) -> str:
    table_text = "table" if table_count == 1 else "tables"
    return (
        f"{service.display_name} is reachable through an internet-facing load balancer and its ECS task role has "
        f"deterministic DynamoDB item-deletion authority ({_operation_text(operations)}) across {table_count} exact "
        f"modeled DynamoDB {table_text}. A compromise of the public workload could delete items within those table "
        "namespaces and disrupt structured-data availability. Point-in-time recovery posture is preserved as "
        "provider-native recovery evidence; it does not establish a specific item target, successful deletion, "
        "irreversible removal, or successful recovery."
    )


def _operation_text(operations: Sequence[str]) -> str:
    if len(operations) == 1:
        return operations[0]
    if len(operations) == 2:
        return f"{operations[0]} and {operations[1]}"
    return ", ".join(operations[:-1]) + f", and {operations[-1]}"


def _mapping_records(
    value: object,
) -> list[Mapping[str, object]] | None:
    if not isinstance(value, list):
        return None
    records: list[Mapping[str, object]] = []
    for item in cast(list[object], value):
        if not isinstance(item, Mapping):
            return None
        records.append(cast(Mapping[str, object], item))
    return records


def _string_values_exact(value: object) -> list[str] | None:
    if not isinstance(value, list):
        return None
    values: list[str] = []
    for item in cast(list[object], value):
        if not isinstance(item, str) or not item:
            return None
        values.append(item)
    return values


def _string_values(value: object) -> list[str]:
    values = _string_values_exact(value)
    return values if values is not None else []


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None
