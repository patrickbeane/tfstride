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
from tfstride.providers.aws.messaging_topology_destruction_evidence import (
    AwsEcsMessagingTopologyDestructionPath,
    AwsMessagingTopologyDestructionOperation,
)
from tfstride.providers.aws.resource_decoration.ecs_messaging_topology_destruction_paths import (
    current_messaging_topology_destruction_path,
)
from tfstride.providers.aws.resource_facts import AwsResourceFacts, aws_facts
from tfstride.providers.aws.resource_index import (
    AwsDecorationContext,
    AwsResourceIndexBuilder,
)
from tfstride.resource_helpers import parse_aws_account_id

_AWS_ECS_SERVICE = "aws_ecs_service"
_AWS_ECS_TASK_DEFINITION = "aws_ecs_task_definition"
_AWS_IAM_ROLE = "aws_iam_role"
_AWS_SQS_QUEUE = "aws_sqs_queue"
_AWS_SNS_TOPIC = "aws_sns_topic"
_DELETE_QUEUE: AwsMessagingTopologyDestructionOperation = "sqs:DeleteQueue"
_DELETE_TOPIC: AwsMessagingTopologyDestructionOperation = "sns:DeleteTopic"
_OPERATION_ORDER = (_DELETE_QUEUE, _DELETE_TOPIC)
_EXPECTED_OPERATION = {
    _DELETE_QUEUE: (
        "queue_deletion",
        "delete_queue",
        "queue_topology",
        "exact_sqs_queue",
        _AWS_SQS_QUEUE,
    ),
    _DELETE_TOPIC: (
        "topic_deletion",
        "delete_topic",
        "topic_topology",
        "exact_sns_topic",
        _AWS_SNS_TOPIC,
    ),
}
_EXCLUDED_PROJECTION_FIELDS = frozenset(
    {
        "workload_address",
        "workload_type",
        "internet_facing_load_balancers",
    }
)


class AwsEcsMessagingTopologyDisruptionRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_service_topology_disruption(
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
            paths = [
                path
                for path in service_facts.ecs_messaging_topology_destruction_paths
                if _is_current_deterministic_path(
                    path,
                    service,
                    context,
                    decoration_context,
                )
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
            target_addresses = path_string_values(
                paths,
                "messaging_resource_address",
            )
            operations = _operations(paths)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2,
                data_sensitivity=1,
                lateral_movement=1,
                blast_radius=2 if len(target_addresses) > 1 else 1,
            )
            affected_resources = [
                *ingress.resource_addresses,
                service.address,
                *task_definition_addresses,
                *role_addresses,
                *target_addresses,
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
                    rationale=_rationale(service, operations, len(target_addresses)),
                    evidence=collect_evidence(
                        evidence_item("network_path", ingress.network_path),
                        *ingress.evidence,
                        evidence_item(
                            "task_definitions",
                            [f"address={address}" for address in task_definition_addresses],
                        ),
                        evidence_item("task_roles", _task_role_evidence(paths)),
                        evidence_item(
                            "messaging_topology_destruction_paths",
                            _topology_path_evidence(paths),
                        ),
                        evidence_item(
                            "topology_deletion_outcome_evidence",
                            _outcome_evidence(paths),
                        ),
                        evidence_item(
                            "messaging_topology_destruction_path_uncertainties",
                            service_facts.ecs_messaging_topology_destruction_path_uncertainties,
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
    path: AwsEcsMessagingTopologyDestructionPath,
    service: NormalizedResource,
    context: RuleEvaluationContext,
    decoration_context: AwsDecorationContext,
) -> bool:
    operation = path.get("operation")
    expected = _EXPECTED_OPERATION.get(operation)
    if expected is None:
        return False
    operation_class, internal_operation, granularity, scope, target_type = expected

    task_definition = _resource_for_path(
        path,
        "task_definition_address",
        _AWS_ECS_TASK_DEFINITION,
        context,
    )
    role = _resource_for_path(path, "role_address", _AWS_IAM_ROLE, context)
    target = _resource_for_path(
        path,
        "messaging_resource_address",
        target_type,
        context,
    )
    if task_definition is None or role is None or target is None:
        return False

    service_facts = aws_facts(service)
    target_facts = aws_facts(target)
    target_arn = target.arn
    if not isinstance(target_arn, str) or not target_arn:
        return False
    target_name = _target_name(target, target_arn)
    current_task_path = current_messaging_topology_destruction_path(
        task_definition,
        target,
        operation,
        decoration_context,
    )
    if current_task_path is None:
        return False

    if (
        task_definition.address not in service_facts.resolved_task_definition_addresses
        or not _task_role_relationship_is_current(path, task_definition, role)
        or path.get("workload_address") != service.address
        or path.get("workload_type") != service.resource_type
        or path.get("task_definition_address") != task_definition.address
        or path.get("task_definition_arn") != task_definition.arn
        or path.get("role_kind") != "ecs_task_role"
        or path.get("credential_context") != "workload_runtime"
        or path.get("role_address") != role.address
        or path.get("role_arn") != role.arn
        or path.get("same_account") is not True
        or _same_account(role.arn, target_arn) is not True
        or path.get("messaging_resource_address") != target.address
        or path.get("messaging_resource_type") != target.resource_type
        or path.get("messaging_resource_name") != target_name
        or path.get("messaging_resource_arn") != target_arn
        or path.get("target_model_evidence_addresses") != [target.address]
        or path.get("operation_class") != operation_class
        or path.get("internal_operation") != internal_operation
        or path.get("target_granularity") != granularity
        or path.get("target_scope") != scope
        or path.get("management_effect") != "disruption"
        or path.get("evaluation_basis") != "modeled_identity_and_messaging_resource_policies"
        or path.get("authorization_state") != "allowed"
        or path.get("identity_policy_complete") is not True
        or path.get("resource_policy_complete") is not True
        or path.get("explicit_deny") is not False
        or path.get("conditional_evaluation_required") is not False
        or path.get("lifecycle_compatibility_state") != "compatible"
        or path.get("posture_uncertainties") != []
        or path.get("outcome_evidence") != _current_outcome_evidence()
        or not _target_identity_is_current(path, target, target_facts, target_type)
        or not _matches_current_task_path(
            path,
            (current_task_path,),
        )
    ):
        return False
    return True


def _target_identity_is_current(
    path: Mapping[str, object],
    target: NormalizedResource,
    target_facts: AwsResourceFacts,
    target_type: str,
) -> bool:
    if target_type == _AWS_SQS_QUEUE:
        queue_url = getattr(target_facts, "sqs_queue_url", None)
        return bool(
            path.get("messaging_service") == "sqs"
            and path.get("queue_address") == target.address
            and path.get("queue_name") == _target_name(target, cast(str, target.arn))
            and path.get("queue_arn") == target.arn
            and path.get("queue_url") == queue_url
            and path.get("topic_address") is None
            and path.get("topic_name") is None
            and path.get("topic_arn") is None
        )
    return bool(
        path.get("messaging_service") == "sns"
        and path.get("topic_address") == target.address
        and path.get("topic_name") == _target_name(target, cast(str, target.arn))
        and path.get("topic_arn") == target.arn
        and path.get("queue_address") is None
        and path.get("queue_name") is None
        and path.get("queue_arn") is None
        and path.get("queue_url") is None
    )


def _task_role_relationship_is_current(
    path: Mapping[str, object],
    task_definition: NormalizedResource,
    role: NormalizedResource,
) -> bool:
    path_reference = path.get("role_reference")
    current_reference = aws_facts(task_definition).task_role_arn
    if not isinstance(path_reference, str) or not isinstance(current_reference, str):
        return False
    if role.arn is not None and current_reference == role.arn:
        return path_reference == role.arn
    if current_reference != role.address or not path_reference.endswith(".arn"):
        return False

    observed = False
    resolved = False
    for resolution in task_definition.reference_resolutions:
        if (
            resolution.path != ("task_role_arn",)
            or resolution.provenance != TerraformReferenceProvenance.CONFIGURATION_REFERENCE
            or path_reference not in resolution.references
            and not any(target.reference == path_reference for target in resolution.targets)
        ):
            continue
        observed = True
        if (
            resolution.state != TerraformReferenceResolutionState.SYMBOLIC
            or len(resolution.targets) != 1
            or resolution.targets[0].address != role.address
            or resolution.targets[0].reference != path_reference
        ):
            return False
        resolved = True
    return observed and resolved


def _matches_current_task_path(
    projected_path: Mapping[str, object],
    current_paths: Sequence[Mapping[str, object]],
) -> bool:
    projected_keys = set(projected_path) - _EXCLUDED_PROJECTION_FIELDS
    for current_path in current_paths:
        current_keys = set(current_path) - _EXCLUDED_PROJECTION_FIELDS
        if projected_keys == current_keys and all(projected_path[key] == current_path[key] for key in projected_keys):
            return True
    return False


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


def _same_account(role_arn: str | None, target_arn: str | None) -> bool | None:
    if role_arn is None or target_arn is None:
        return None
    role_account = parse_aws_account_id(role_arn)
    target_account = parse_aws_account_id(target_arn)
    role_partition = _arn_partition(role_arn)
    target_partition = _arn_partition(target_arn)
    if role_account is None or target_account is None or role_partition is None or role_partition != target_partition:
        return None
    return role_account == target_account


def _arn_partition(value: str) -> str | None:
    parts = value.split(":", 2)
    return parts[1] if len(parts) == 3 and parts[0] == "arn" else None


def _target_name(target: NormalizedResource, target_arn: str) -> str:
    if isinstance(target.identifier, str) and target.identifier:
        return target.identifier
    return target_arn.rsplit(":", 1)[-1]


def _current_outcome_evidence() -> dict[str, object]:
    return {
        "outcome_evidence_scope": "plan_local_messaging_topology_deletion_authority",
        "successful_deletion_observed": False,
        "recovery_state": "not_established_by_modeled_aws_messaging_topology_evidence",
        "descendant_impact_evaluated": False,
        "out_of_plan_topology_evaluated": False,
        "uncertainties": [],
    }


def _operations(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return [operation for operation in _OPERATION_ORDER if any(path.get("operation") == operation for path in paths)]


def _task_role_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"address={path.get('role_address')}",
                    f"arn={path.get('role_arn')}",
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
                    f"target_address={path.get('messaging_resource_address')}",
                    f"target_type={path.get('messaging_resource_type')}",
                    f"target_name={path.get('messaging_resource_name')}",
                    f"target_arn={path.get('messaging_resource_arn')}",
                    f"operation={path.get('operation')}",
                    f"operation_class={path.get('operation_class')}",
                    f"target_granularity={path.get('target_granularity')}",
                    f"target_scope={path.get('target_scope')}",
                    f"task_definition={path.get('task_definition_address')}",
                    f"task_role={path.get('role_address')}",
                    f"authorization_sources={','.join(_string_values(path.get('authorization_source_addresses'))) or 'none'}",
                    f"authorization_bases={','.join(_string_values(path.get('authorization_bases'))) or 'none'}",
                    "same_account=true",
                    "authorization_state=allowed",
                    "operation_evaluation=deterministic_allowed",
                )
            )
            for path in paths
        }
    )


def _outcome_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        outcome = path.get("outcome_evidence")
        if not isinstance(outcome, Mapping):
            continue
        outcome_map = cast(Mapping[str, object], outcome)
        values.add(
            "; ".join(
                (
                    f"target_address={path.get('messaging_resource_address')}",
                    f"operation={path.get('operation')}",
                    f"outcome_evidence_scope={outcome_map.get('outcome_evidence_scope')}",
                    f"successful_deletion_observed={outcome_map.get('successful_deletion_observed')}",
                    f"recovery_state={outcome_map.get('recovery_state')}",
                    f"descendant_impact_evaluated={outcome_map.get('descendant_impact_evaluated')}",
                    f"out_of_plan_topology_evaluated={outcome_map.get('out_of_plan_topology_evaluated')}",
                )
            )
        )
    return sorted(values)


def _assessment_scope(operations: Sequence[str]) -> list[str]:
    return [
        (
            f"establishes=deterministic {_operation_text(operations)} authority for an ECS task role over exact "
            "modeled SQS queue or SNS topic topology with Denial of Service effect"
        ),
        (
            "does_not_establish=successful topology deletion, descendant-resource impact, recovery, or out-of-plan "
            "messaging topology"
        ),
    ]


def _rationale(
    service: NormalizedResource,
    operations: Sequence[str],
    target_count: int,
) -> str:
    if operations == [_DELETE_QUEUE]:
        impact = "delete exact modeled SQS queues"
    elif operations == [_DELETE_TOPIC]:
        impact = "delete exact modeled SNS topics"
    else:
        impact = "delete exact modeled SQS queues or SNS topics"
    return (
        f"{service.display_name} is reachable through an internet-facing load balancer and its ECS task role has "
        f"deterministic messaging topology-deletion authority ({_operation_text(operations)}) across {target_count} "
        f"exact modeled messaging target(s). A compromise of the public workload could {impact}, disrupting messaging "
        "topology and availability. This is plan-local authorization evidence; it does not establish successful "
        "deletion, descendant-resource impact, recovery, or out-of-plan topology."
    )


def _operation_text(operations: Sequence[str]) -> str:
    if len(operations) == 1:
        return operations[0]
    return " and ".join(operations)


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in cast(list[object], value) if isinstance(item, str)]
