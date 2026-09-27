from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import cast

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.aws.ecs_path_rule_helpers import (
    internet_boundary_id,
    path_string_values,
    verified_public_service_ingress,
)
from tfstride.providers.aws.resource_decoration.ecs_dynamodb_table_topology_destruction_paths import (
    current_ecs_dynamodb_table_topology_destruction_path,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import (
    AwsDecorationContext,
    AwsResourceIndexBuilder,
)
from tfstride.providers.aws.structured_data_topology_destruction_evidence import (
    AwsEcsDynamoDbTableTopologyDestructionPath,
)

_AWS_ECS_SERVICE = "aws_ecs_service"
_AWS_ECS_TASK_DEFINITION = "aws_ecs_task_definition"
_AWS_IAM_ROLE = "aws_iam_role"
_AWS_DYNAMODB_TABLE = "aws_dynamodb_table"
_DELETE_TABLE = "dynamodb:DeleteTable"

# These fields identify the projected relationship. Recovery and other posture
# records are deliberately excluded so current descriptive evidence can refresh.
_AUTHORIZATION_RELATIONSHIP_FIELDS = (
    "workload_address",
    "workload_type",
    "task_definition_address",
    "role_kind",
    "credential_context",
    "role_address",
    "role_provider_config_key",
    "table_address",
    "table_resource_type",
    "table_provider_config_key",
    "operation",
    "operation_class",
    "internal_operation",
    "management_effect",
    "target_granularity",
    "target_scope",
    "target_model_evidence_addresses",
    "account_relationship",
    "same_account",
)


class AwsEcsDynamoDbTableTopologyDisruptionRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_service_table_topology_disruption(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        decoration_context = AwsDecorationContext(
            AwsResourceIndexBuilder().build(list(context.inventory.resources)),
        )
        findings: list[Finding] = []
        for service in context.inventory.by_type(_AWS_ECS_SERVICE):
            service_facts = aws_facts(service)
            current_paths: list[AwsEcsDynamoDbTableTopologyDestructionPath] = []
            seen_keys: set[tuple[str, ...]] = set()
            for cached_path in service_facts.ecs_dynamodb_table_topology_destruction_paths:
                current_path = _current_deterministic_path(
                    cached_path,
                    service,
                    context,
                    decoration_context,
                )
                if current_path is None:
                    continue
                key = _authorization_relationship_key(current_path)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                current_paths.append(current_path)

            if not current_paths:
                continue

            ingress = verified_public_service_ingress(service, context)
            current_paths = ingress.current_workload_paths(current_paths)
            load_balancer_addresses = ingress.load_balancer_addresses
            if not load_balancer_addresses or not current_paths:
                continue

            task_definition_addresses = path_string_values(
                current_paths,
                "task_definition_address",
            )
            role_addresses = path_string_values(current_paths, "role_address")
            table_addresses = path_string_values(
                current_paths,
                "table_address",
            )
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=3,
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
                    rationale=_rationale(service, len(table_addresses)),
                    evidence=collect_evidence(
                        evidence_item("network_path", ingress.network_path),
                        *ingress.evidence,
                        evidence_item(
                            "task_definitions",
                            [f"address={address}" for address in task_definition_addresses],
                        ),
                        evidence_item(
                            "task_roles",
                            _task_role_evidence(current_paths),
                        ),
                        evidence_item(
                            "dynamodb_table_topology_destruction_paths",
                            _topology_path_evidence(current_paths),
                        ),
                        evidence_item(
                            "table_deletion_constraint_evidence",
                            _constraint_evidence(current_paths),
                        ),
                        evidence_item(
                            "table_deletion_recovery_evidence",
                            _recovery_evidence(current_paths),
                        ),
                        evidence_item(
                            "dynamodb_table_topology_destruction_path_uncertainties",
                            _current_path_uncertainties(current_paths),
                        ),
                        evidence_item(
                            "assessment_scope",
                            _assessment_scope(),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _current_deterministic_path(
    cached_path: AwsEcsDynamoDbTableTopologyDestructionPath,
    service: NormalizedResource,
    context: RuleEvaluationContext,
    decoration_context: AwsDecorationContext,
) -> AwsEcsDynamoDbTableTopologyDestructionPath | None:
    if not _cached_path_is_coherent(cached_path):
        return None

    task_definition = _resource_for_path(
        cached_path,
        "task_definition_address",
        _AWS_ECS_TASK_DEFINITION,
        context,
    )
    role = _resource_for_path(
        cached_path,
        "role_address",
        _AWS_IAM_ROLE,
        context,
    )
    table = _resource_for_path(
        cached_path,
        "table_address",
        _AWS_DYNAMODB_TABLE,
        context,
    )
    if task_definition is None or role is None or table is None:
        return None

    service_facts = aws_facts(service)
    if (
        cached_path.get("workload_address") != service.address
        or cached_path.get("workload_type") != service.resource_type
        or task_definition.address not in service_facts.resolved_task_definition_addresses
    ):
        return None

    current_task_path = current_ecs_dynamodb_table_topology_destruction_path(
        task_definition,
        table,
        decoration_context,
    )
    if current_task_path is None:
        return None

    current_path = dict(current_task_path)
    current_path["workload_address"] = service.address
    current_path["workload_type"] = service.resource_type
    current_path["task_definition_address"] = task_definition.address
    current_path["internet_facing_load_balancers"] = service_facts.internet_facing_load_balancer_addresses
    if not _authorization_relationship_matches(cached_path, current_path):
        return None
    if not _authorization_proof_sources_are_current(cached_path, current_path):
        return None
    return cast(AwsEcsDynamoDbTableTopologyDestructionPath, current_path)


def _cached_path_is_coherent(
    path: Mapping[str, object],
) -> bool:
    table_address = path.get("table_address")
    return bool(
        isinstance(table_address, str)
        and table_address
        and path.get("role_kind") == "ecs_task_role"
        and path.get("credential_context") == "workload_runtime"
        and path.get("operation") == _DELETE_TABLE
        and path.get("operation_class") == "table_deletion"
        and path.get("internal_operation") == "delete_table"
        and path.get("management_effect") == "disruption"
        and path.get("target_granularity") == "table_topology"
        and path.get("target_scope") == "exact_dynamodb_table"
        and path.get("target_model_evidence_addresses") == [table_address]
        and path.get("authorization_state") == "allowed"
        and path.get("matched_actions") == [_DELETE_TABLE]
        and path.get("identity_policy_complete") is True
        and path.get("table_policy_complete") is True
        and path.get("explicit_deny") is False
        and path.get("conditional_evaluation_required") is False
        and path.get("lifecycle_compatibility_state") == "compatible"
        and bool(_authorization_proof_sources(path))
    )


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


def _authorization_relationship_matches(
    cached_path: Mapping[str, object],
    current_path: Mapping[str, object],
) -> bool:
    return all(cached_path.get(field) == current_path.get(field) for field in _AUTHORIZATION_RELATIONSHIP_FIELDS)


def _authorization_relationship_key(
    path: Mapping[str, object],
) -> tuple[str, ...]:
    return tuple(repr(path.get(field)) for field in _AUTHORIZATION_RELATIONSHIP_FIELDS)


def _authorization_proof_sources(
    path: Mapping[str, object],
) -> frozenset[tuple[str, str]] | None:
    raw_statements = path.get("authorization_statements")
    if not isinstance(raw_statements, list) or not raw_statements:
        return None

    sources: set[tuple[str, str]] = set()
    for raw_statement in cast(list[object], raw_statements):
        if not isinstance(raw_statement, Mapping):
            return None
        statement = cast(Mapping[str, object], raw_statement)
        source_address = statement.get("source_address")
        source_kind = statement.get("source_kind")
        if not isinstance(source_address, str) or source_kind not in {"identity_policy", "table_policy"}:
            return None
        assert isinstance(source_kind, str)
        sources.add((source_address, source_kind))
    return frozenset(sources)


def _authorization_proof_sources_are_current(
    cached_path: Mapping[str, object],
    current_path: Mapping[str, object],
) -> bool:
    cached_sources = _authorization_proof_sources(cached_path)
    current_sources = _authorization_proof_sources(current_path)
    return cached_sources is not None and current_sources is not None and cached_sources <= current_sources


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


def _topology_path_evidence(
    paths: Sequence[Mapping[str, object]],
) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"table_address={path.get('table_address')}",
                    f"table_name={path.get('table_name')}",
                    f"table_reference={path.get('table_reference')}",
                    f"table_arn={path.get('table_arn') or 'unknown'}",
                    f"operation={path.get('operation')}",
                    f"operation_class={path.get('operation_class')}",
                    f"target_granularity={path.get('target_granularity')}",
                    f"target_scope={path.get('target_scope')}",
                    f"task_definition={path.get('task_definition_address')}",
                    f"task_role={path.get('role_address')}",
                    f"grant_basis={path.get('grant_basis')}",
                    f"account_relationship={path.get('account_relationship')}",
                    f"authorization_sources={','.join(_string_values(path.get('authorization_source_addresses'))) or 'none'}",
                    f"matched_actions={','.join(_string_values(path.get('matched_actions')))}",
                    "authorization_state=allowed",
                    "operation_evaluation=deterministic_allowed",
                )
            )
            for path in paths
        }
    )


def _constraint_evidence(
    paths: Sequence[Mapping[str, object]],
) -> list[str]:
    values: set[str] = set()
    for path in paths:
        constraint = path.get("deletion_constraint_evidence")
        if not isinstance(constraint, Mapping):
            continue
        constraint_map = cast(Mapping[str, object], constraint)
        values.add(
            "; ".join(
                (
                    f"table_address={path.get('table_address')}",
                    f"deletion_protection_state={_display(constraint_map.get('deletion_protection_state'))}",
                    f"deletion_protection_enabled={_display(constraint_map.get('deletion_protection_enabled'))}",
                    f"provider_default_applied={_display(constraint_map.get('provider_default_applied'))}",
                    f"deletion_compatibility_state={_display(constraint_map.get('deletion_compatibility_state'))}",
                    f"uncertainties={','.join(_string_values(constraint_map.get('uncertainties'))) or 'none'}",
                )
            )
        )
    return sorted(values)


def _recovery_evidence(
    paths: Sequence[Mapping[str, object]],
) -> list[str]:
    values: set[str] = set()
    for path in paths:
        recovery = path.get("recovery_evidence")
        if not isinstance(recovery, Mapping):
            continue
        recovery_map = cast(Mapping[str, object], recovery)
        values.add(
            "; ".join(
                (
                    f"table_address={path.get('table_address')}",
                    f"pitr_state={_display(recovery_map.get('pitr_state'))}",
                    f"pitr_enabled={_display(recovery_map.get('pitr_enabled'))}",
                    f"pitr_recovery_period_days={_display(recovery_map.get('pitr_recovery_period_days'))}",
                    f"table_recovery_state={_display(recovery_map.get('table_recovery_state'))}",
                    f"restore_target_kind={_display(recovery_map.get('restore_target_kind'))}",
                    f"successful_deletion_observed={_display(recovery_map.get('successful_deletion_observed'))}",
                    f"restoration_observed={_display(recovery_map.get('restoration_observed'))}",
                    f"runtime_table_state_evaluated={_display(recovery_map.get('runtime_table_state_evaluated'))}",
                    f"descendant_impact_evaluated={_display(recovery_map.get('descendant_impact_evaluated'))}",
                    f"out_of_plan_table_topology_evaluated={_display(recovery_map.get('out_of_plan_table_topology_evaluated'))}",
                    f"uncertainties={','.join(_string_values(recovery_map.get('uncertainties'))) or 'none'}",
                )
            )
        )
    return sorted(values)


def _current_path_uncertainties(
    paths: Sequence[Mapping[str, object]],
) -> list[str]:
    return sorted({uncertainty for path in paths for uncertainty in _string_values(path.get("posture_uncertainties"))})


def _assessment_scope() -> list[str]:
    return [
        (
            "establishes=deterministic dynamodb:DeleteTable authority for an ECS "
            "task role over exact modeled DynamoDB table topology with Denial of "
            "Service effect"
        ),
        (
            "does_not_establish=table emptiness, successful deletion, item or "
            "replica impact, restoration, or authority over out-of-plan table "
            "topology"
        ),
    ]


def _rationale(
    service: NormalizedResource,
    table_count: int,
) -> str:
    table_text = "table" if table_count == 1 else "tables"
    return (
        f"{service.display_name} is reachable through an internet-facing load "
        "balancer and its ECS task role has deterministic DynamoDB table-topology "
        f"deletion authority (dynamodb:DeleteTable) across {table_count} exact "
        f"modeled DynamoDB {table_text}. A compromise of the public workload "
        "could request deletion of those table topologies, subject to provider "
        "deletion prerequisites. Point-in-time recovery posture is preserved as "
        "provider-native evidence; it does not establish table emptiness, "
        "successful deletion, item or replica impact, restoration, or out-of-plan "
        "table topology."
    )


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in cast(list[object], value) if isinstance(item, str) and item]


def _display(value: object) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)
