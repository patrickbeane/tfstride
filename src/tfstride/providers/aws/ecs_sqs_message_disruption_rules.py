from __future__ import annotations

from collections.abc import Mapping, Sequence
from fnmatch import fnmatchcase
from typing import Literal, cast

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, IAMPolicyStatement, NormalizedResource
from tfstride.providers.aws.ecs_path_rule_helpers import (
    internet_boundary_id,
    path_string_values,
    verified_public_service_ingress,
)
from tfstride.providers.aws.message_removal_evidence import (
    AwsEcsSqsMessageRemovalPath,
    AwsSqsMessageRemovalDeliveryEvidence,
)
from tfstride.providers.aws.resource_decoration.ecs_sqs_message_removal_paths import (
    sqs_queue_policy_operation_is_complete,
)
from tfstride.providers.aws.resource_facts import AwsResourceFacts, aws_facts
from tfstride.providers.coercion import dedupe
from tfstride.resource_helpers import parse_aws_account_id

_AWS_ECS_SERVICE = "aws_ecs_service"
_AWS_ECS_TASK_DEFINITION = "aws_ecs_task_definition"
_AWS_IAM_ROLE = "aws_iam_role"
_AWS_SQS_QUEUE = "aws_sqs_queue"
_RECEIVE = "sqs:ReceiveMessage"
_DELETE = "sqs:DeleteMessage"
_PURGE = "sqs:PurgeQueue"
_OPERATION_ORDER = (_DELETE, _PURGE)
_EXPECTED_OPERATION = {
    _DELETE: (
        "received_message_deletion",
        "delete_received_message",
        "queue_received_message_namespace",
        "exact_queue_received_message_namespace",
    ),
    _PURGE: (
        "queue_message_purge",
        "purge_queue_messages",
        "queue_message_namespace",
        "exact_queue_message_namespace",
    ),
}
_EXCLUDED_PROJECTION_FIELDS = frozenset(
    {
        "workload_address",
        "workload_type",
        "internet_facing_load_balancers",
    }
)


class AwsEcsSqsMessageDisruptionRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_service_message_disruption(
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
                for path in service_facts.ecs_sqs_message_removal_paths
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
            queue_addresses = path_string_values(paths, "queue_address")
            operations = _operations(paths)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2 if _PURGE in operations else 1,
                data_sensitivity=1,
                lateral_movement=1,
                blast_radius=2 if len(queue_addresses) > 1 else 1,
            )
            affected_resources = [
                *ingress.resource_addresses,
                service.address,
                *task_definition_addresses,
                *role_addresses,
                *queue_addresses,
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
                        len(queue_addresses),
                    ),
                    evidence=collect_evidence(
                        evidence_item("network_path", ingress.network_path),
                        *ingress.evidence,
                        evidence_item(
                            "task_definitions",
                            [f"address={address}" for address in task_definition_addresses],
                        ),
                        evidence_item("task_roles", _task_role_evidence(paths)),
                        evidence_item(
                            "sqs_message_removal_paths",
                            _removal_path_evidence(paths),
                        ),
                        evidence_item(
                            "delivery_and_recovery_evidence",
                            _delivery_evidence(paths),
                        ),
                        evidence_item(
                            "sqs_message_removal_path_uncertainties",
                            service_facts.ecs_sqs_message_removal_path_uncertainties,
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
    path: AwsEcsSqsMessageRemovalPath,
    service: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    operation = path.get("operation")
    expected = _EXPECTED_OPERATION.get(operation)
    if expected is None:
        return False
    operation_class, internal_operation, target_granularity, target_scope = expected

    task_definition = _resource_for_path(
        path,
        "task_definition_address",
        _AWS_ECS_TASK_DEFINITION,
        context,
    )
    role = _resource_for_path(path, "role_address", _AWS_IAM_ROLE, context)
    queue = _resource_for_path(path, "queue_address", _AWS_SQS_QUEUE, context)
    if task_definition is None or role is None or queue is None:
        return False

    service_facts = aws_facts(service)
    task_facts = aws_facts(task_definition)
    queue_facts = aws_facts(queue)
    expected_queue_name = queue.identifier
    if not isinstance(expected_queue_name, str) or not expected_queue_name:
        expected_queue_name = queue.arn.rsplit(":", 1)[-1] if queue.arn else None

    if (
        task_definition.address not in service_facts.resolved_task_definition_addresses
        or not _task_role_relationship_is_current(task_facts, role)
        or path.get("workload_address") != service.address
        or path.get("workload_type") != service.resource_type
        or path.get("task_definition_address") != task_definition.address
        or path.get("task_definition_arn") != task_definition.arn
        or path.get("role_kind") != "ecs_task_role"
        or path.get("credential_context") != "workload_runtime"
        or path.get("role_address") != role.address
        or path.get("role_arn") != role.arn
        or path.get("queue_address") != queue.address
        or path.get("queue_resource_type") != queue.resource_type
        or path.get("queue_name") != expected_queue_name
        or path.get("queue_arn") != queue.arn
        or path.get("queue_url") != queue_facts.sqs_queue_url
        or path.get("operation_class") != operation_class
        or path.get("internal_operation") != internal_operation
        or path.get("target_granularity") != target_granularity
        or path.get("target_scope") != target_scope
        or path.get("management_effect") != "disruption"
        or path.get("authorization_state") != "allowed"
        or path.get("explicit_deny") is not False
        or path.get("conditional_evaluation_required") is not False
        or path.get("lifecycle_compatibility_state") != "not_applicable"
        or path.get("target_model_evidence_addresses") != _current_model_evidence_addresses(queue_facts, queue.address)
        or not _delivery_evidence_is_current(path, queue, queue_facts)
        or not _operation_authorizations_are_current(
            path,
            operation,
            role,
            queue,
            context,
        )
        or not _matches_current_task_path(
            path,
            task_facts.ecs_sqs_message_removal_paths,
        )
    ):
        return False
    return True


def _task_role_relationship_is_current(
    task_facts: AwsResourceFacts,
    role: NormalizedResource,
) -> bool:
    reference = task_facts.task_role_arn
    return bool(
        reference is not None
        and reference
        in {
            role.address,
            role.identifier,
            role.arn,
        }
    )


def _operation_authorizations_are_current(
    path: AwsEcsSqsMessageRemovalPath,
    operation: str,
    role: NormalizedResource,
    queue: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    removal = path.get("removal_authorization")
    if not isinstance(removal, Mapping):
        return False
    removal_map = cast(Mapping[str, object], removal)
    authorizations: list[Mapping[str, object]] = [removal_map]
    if not _authorization_is_current(
        removal_map,
        operation,
        role,
        queue,
        context,
    ):
        return False

    if operation == _DELETE:
        receive = path.get("receive_authorization")
        if not isinstance(receive, Mapping):
            return False
        receive_map = cast(Mapping[str, object], receive)
        if (
            path.get("prerequisite_operation") != _RECEIVE
            or path.get("receipt_handle_source") != "runtime_receive_response"
            or path.get("receipt_handle_value") is not None
            or not _authorization_is_current(
                receive_map,
                _RECEIVE,
                role,
                queue,
                context,
            )
        ):
            return False
        authorizations.insert(0, receive_map)
    elif not (
        path.get("prerequisite_operation") is None
        and path.get("receipt_handle_source") is None
        and path.get("receipt_handle_value") is None
        and "receive_authorization" not in path
    ):
        return False

    return bool(
        path.get("authorization_source_addresses") == _authorization_source_addresses(authorizations)
        and not _current_policy_has_applicable_deny(
            role,
            queue,
            operation,
        )
        and (
            operation != _DELETE
            or not _current_policy_has_applicable_deny(
                role,
                queue,
                _RECEIVE,
            )
        )
    )


def _authorization_source_addresses(
    authorizations: Sequence[Mapping[str, object]],
) -> list[str]:
    return dedupe(
        source
        for authorization in authorizations
        for key in (
            "identity_policy_source_addresses",
            "queue_policy_source_addresses",
        )
        for source in _string_values(authorization.get(key))
    )


def _current_policy_has_applicable_deny(
    role: NormalizedResource,
    queue: NormalizedResource,
    operation: str,
) -> bool:
    for statement in role.policy_statements:
        if _deny_statement_may_apply(statement, operation, queue):
            return True
    for statement in queue.policy_statements:
        if _principal_match(
            sorted(entry.value for entry in statement.principal_entries if entry.kind.casefold() in {"aws", "unknown"}),
            role.arn,
        ) is not None and _deny_statement_may_apply(statement, operation, queue):
            return True
    return False


def _deny_statement_may_apply(
    statement: IAMPolicyStatement,
    operation: str,
    queue: NormalizedResource,
) -> bool:
    if statement.effect.strip().casefold() != "deny" or not any(
        fnmatchcase(operation.casefold(), action.casefold()) for action in statement.actions
    ):
        return False
    return any(_resource_targets_queue(resource, queue) is not False for resource in statement.resources)


def _authorization_is_current(
    authorization: Mapping[str, object],
    operation: str,
    role: NormalizedResource,
    queue: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    if operation not in {_RECEIVE, _DELETE, _PURGE}:
        return False
    role_facts = aws_facts(role)
    queue_facts = aws_facts(queue)
    same_account = _same_account(role.arn, queue.arn)
    identity_records = _mapping_records(authorization.get("identity_policy_statements"))
    queue_records = _mapping_records(authorization.get("queue_policy_statements"))
    bases = _string_values_exact(authorization.get("authorization_bases"))
    if (
        same_account is None
        or identity_records is None
        or queue_records is None
        or bases is None
        or authorization.get("queue_address") != queue.address
        or authorization.get("queue_resource_type") != queue.resource_type
        or authorization.get("queue_arn") != queue.arn
        or authorization.get("principal_address") != role.address
        or authorization.get("principal_arn") != role.arn
        or authorization.get("principal_kind") != "iam_role"
        or authorization.get("operation") != operation
        or authorization.get("matched_actions") != [operation]
        or authorization.get("authorization_state") != "allowed"
        or authorization.get("same_account") is not same_account
        or authorization.get("identity_policy_complete") is not True
        or authorization.get("queue_policy_complete") is not True
        or authorization.get("explicit_deny") is not False
        or authorization.get("conditional_evaluation_required") is not False
        or authorization.get("evaluation_scope") != "modeled_identity_and_sqs_queue_policies"
        or role_facts.iam_policy_completeness_state != "complete"
        or role_facts.unresolved_attached_policy_arns
        or queue_facts.sqs_queue_policy_state == "unknown"
        or not sqs_queue_policy_operation_is_complete(queue, operation)
        or authorization.get("identity_policy_source_addresses") != _identity_policy_sources(role)
        or authorization.get("queue_policy_source_addresses") != _queue_policy_sources(queue)
        or not _authorization_basis_is_coherent(
            bases,
            same_account=same_account,
            has_identity_records=bool(identity_records),
            has_queue_records=bool(queue_records),
            identity_required=authorization.get("identity_policy_required"),
            queue_required=authorization.get("queue_policy_required"),
        )
        or not all(
            _statement_record_is_current(
                record,
                operation,
                role,
                queue,
                "identity_policy",
                context,
            )
            for record in identity_records
        )
        or not all(
            _statement_record_is_current(
                record,
                operation,
                role,
                queue,
                "queue_policy",
                context,
            )
            for record in queue_records
        )
    ):
        return False
    return True


def _authorization_basis_is_coherent(
    bases: list[str],
    *,
    same_account: bool,
    has_identity_records: bool,
    has_queue_records: bool,
    identity_required: object,
    queue_required: object,
) -> bool:
    if same_account:
        expected_bases = [
            basis
            for basis, present in (
                ("identity_policy", has_identity_records),
                ("queue_policy_direct", has_queue_records),
            )
            if present
        ]
        return bool(
            bases == expected_bases
            and identity_required is (has_identity_records and not has_queue_records)
            and queue_required is (has_queue_records and not has_identity_records)
        )
    return bool(
        bases == ["cross_account_identity_and_queue_policy"]
        and has_identity_records
        and has_queue_records
        and identity_required is True
        and queue_required is True
    )


def _statement_record_is_current(
    record: Mapping[str, object],
    operation: str,
    role: NormalizedResource,
    queue: NormalizedResource,
    source_kind: Literal["identity_policy", "queue_policy"],
    context: RuleEvaluationContext,
) -> bool:
    actions = _string_values_exact(record.get("actions"))
    matching_patterns = _string_values_exact(record.get("matching_action_patterns"))
    resources = _string_values_exact(record.get("resources"))
    matching_resources = _string_values_exact(record.get("matching_resources"))
    principals = _string_values_exact(record.get("principals"))
    if (
        actions is None
        or not actions
        or matching_patterns is None
        or not matching_patterns
        or resources is None
        or not resources
        or matching_resources is None
        or len(matching_resources) != 1
        or principals is None
        or record.get("source_kind") != source_kind
        or record.get("source_address") != (role.address if source_kind == "identity_policy" else queue.address)
        or record.get("effect") != "allow"
        or record.get("conditions") != []
        or record.get("conditional") is not False
        or not set(matching_resources) <= set(resources)
        or not all(fnmatchcase(operation.casefold(), pattern.casefold()) for pattern in matching_patterns)
        or _resource_targets_queue(matching_resources[0], queue) is not True
    ):
        return False

    statements = role.policy_statements if source_kind == "identity_policy" else queue.policy_statements
    for statement in statements:
        if not _statement_matches_record(
            statement,
            record,
            actions,
            resources,
            principals,
            role,
            source_kind,
        ):
            continue
        return True
    return False


def _statement_matches_record(
    statement: IAMPolicyStatement,
    record: Mapping[str, object],
    actions: list[str],
    resources: list[str],
    principals: list[str],
    role: NormalizedResource,
    source_kind: Literal["identity_policy", "queue_policy"],
) -> bool:
    if (
        statement.effect.strip().casefold() != "allow"
        or statement.actions != actions
        or statement.resources != resources
        or statement.conditions
    ):
        return False
    current_principals = sorted(
        entry.value for entry in statement.principal_entries if entry.kind.casefold() in {"aws", "unknown"}
    )
    if current_principals != principals:
        return False
    if source_kind == "identity_policy":
        return not current_principals and record.get("principal_match") is None
    expected_match = _principal_match(current_principals, role.arn)
    return expected_match is not None and record.get("principal_match") == expected_match


def _principal_match(
    principals: Sequence[str],
    role_arn: str | None,
) -> Literal["role", "account", "wildcard"] | None:
    if role_arn is None:
        return None
    account_id = parse_aws_account_id(role_arn)
    if account_id is None:
        return None
    root_arn = f"arn:{_arn_partition(role_arn)}:iam::{account_id}:root"
    values = set(principals)
    if role_arn in values:
        return "role"
    if values & {account_id, root_arn}:
        return "account"
    if "*" in values:
        return "wildcard"
    return None


def _resource_targets_queue(
    resource: str,
    queue: NormalizedResource,
) -> bool | None:
    queue_arn = queue.arn
    if queue_arn is None:
        return False
    normalized = _unwrap_reference(resource)
    if normalized == "*":
        return True
    if normalized in {
        queue.address,
        f"{queue.address}.arn",
        f"{queue.address}.id",
        f"{queue.address}.url",
    }:
        return True
    if normalized.startswith("arn:"):
        return fnmatchcase(queue_arn, normalized)
    if normalized.startswith(("aws_sqs_queue.", "module.")) or "${" in resource:
        return None
    if "*" in normalized or "?" in normalized:
        return None
    return False


def _delivery_evidence_is_current(
    path: Mapping[str, object],
    queue: NormalizedResource,
    queue_facts: AwsResourceFacts,
) -> bool:
    actual = path.get("delivery_evidence")
    if not isinstance(actual, Mapping):
        return False
    expected = _current_delivery_evidence(queue, queue_facts)
    return bool(
        dict(cast(Mapping[str, object], actual)) == expected
        and path.get("posture_uncertainties") == expected["uncertainties"]
    )


def _current_delivery_evidence(
    queue: NormalizedResource,
    queue_facts: AwsResourceFacts,
) -> AwsSqsMessageRemovalDeliveryEvidence:
    uncertainties = list(queue_facts.sqs_posture_uncertainties)
    redrive_state = queue_facts.sqs_redrive_state
    if redrive_state not in {"configured", "not_configured", "unknown"}:
        redrive_state = "unknown"
        uncertainties.append(f"{queue.address}: SQS redrive posture is not exact after normalization")
    return {
        "delivery_evidence_scope": "sqs_retention_and_redrive_posture",
        "message_retention_seconds": queue_facts.sqs_message_retention_seconds,
        "redrive_state": cast(
            Literal["configured", "not_configured", "unknown"],
            redrive_state,
        ),
        "redrive_target_arn": queue_facts.sqs_redrive_target_arn,
        "redrive_max_receive_count": queue_facts.sqs_redrive_max_receive_count,
        "removed_message_recovery_state": ("not_established_by_modeled_sqs_delivery_controls"),
        "uncertainties": dedupe(uncertainties),
    }


def _current_model_evidence_addresses(
    queue_facts: AwsResourceFacts,
    queue_address: str,
) -> list[str]:
    return dedupe(value for value in (queue_address, queue_facts.sqs_redrive_source_address) if value is not None)


def _identity_policy_sources(role: NormalizedResource) -> list[str]:
    facts = aws_facts(role)
    return dedupe(
        [
            role.address,
            *facts.inline_policy_resource_addresses,
            *facts.attached_policy_addresses,
        ]
    )


def _queue_policy_sources(queue: NormalizedResource) -> list[str]:
    return [queue.address] if aws_facts(queue).sqs_queue_policy_state == "configured" else []


def _same_account(role_arn: str | None, queue_arn: str | None) -> bool | None:
    if role_arn is None or queue_arn is None:
        return None
    role_account = parse_aws_account_id(role_arn)
    queue_account = parse_aws_account_id(queue_arn)
    if role_account is None or queue_account is None or _arn_partition(role_arn) != _arn_partition(queue_arn):
        return None
    return role_account == queue_account


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


def _removal_path_evidence(
    paths: Sequence[Mapping[str, object]],
) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"queue_address={path.get('queue_address')}",
                    f"queue_name={path.get('queue_name')}",
                    f"queue_arn={path.get('queue_arn')}",
                    f"operation={path.get('operation')}",
                    f"operation_class={path.get('operation_class')}",
                    f"internal_operation={path.get('internal_operation')}",
                    f"target_granularity={path.get('target_granularity')}",
                    f"target_scope={path.get('target_scope')}",
                    f"prerequisite_operation={path.get('prerequisite_operation') or 'none'}",
                    f"receipt_handle_source={path.get('receipt_handle_source') or 'none'}",
                    f"task_definition={path.get('task_definition_address')}",
                    f"task_role={path.get('role_address')}",
                    f"authorization_sources={','.join(_string_values(path.get('authorization_source_addresses'))) or 'none'}",
                    f"authorization_bases={','.join(_authorization_bases(path))}",
                    "authorization_state=allowed",
                    "operation_evaluation=deterministic_allowed",
                )
            )
            for path in paths
        }
    )


def _authorization_bases(path: Mapping[str, object]) -> list[str]:
    values: list[str] = []
    for key in ("receive_authorization", "removal_authorization"):
        authorization = path.get(key)
        if not isinstance(authorization, Mapping):
            continue
        authorization_map = cast(Mapping[str, object], authorization)
        values.extend(_string_values(authorization_map.get("authorization_bases")))
    return dedupe(values)


def _delivery_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        delivery = path.get("delivery_evidence")
        if not isinstance(delivery, Mapping):
            continue
        delivery_map = cast(Mapping[str, object], delivery)
        redrive_target, redrive_max_receive_count = _rendered_redrive_fields(
            delivery_map,
        )
        values.add(
            "; ".join(
                (
                    f"queue_address={path.get('queue_address')}",
                    f"operation={path.get('operation')}",
                    f"message_retention_seconds={_display(delivery_map.get('message_retention_seconds'))}",
                    f"redrive_state={delivery_map.get('redrive_state')}",
                    f"redrive_target_arn={redrive_target}",
                    f"redrive_max_receive_count={redrive_max_receive_count}",
                    f"removed_message_recovery_state={delivery_map.get('removed_message_recovery_state')}",
                    f"uncertainties={','.join(_string_values(delivery_map.get('uncertainties'))) or 'none'}",
                    "successful_removal_not_established=true",
                    "successful_recovery_not_established=true",
                )
            )
        )
    return sorted(values)


def _rendered_redrive_fields(
    delivery: Mapping[str, object],
) -> tuple[str, str]:
    state = delivery.get("redrive_state")
    if state == "not_configured":
        return "not_applicable", "not_applicable"
    if state == "unknown":
        return "unknown", "unknown"
    return (
        _display(delivery.get("redrive_target_arn")),
        _display(delivery.get("redrive_max_receive_count")),
    )


def _assessment_scope(operations: Sequence[str]) -> list[str]:
    return [
        (
            f"establishes=deterministic {_operation_text(operations)} authority for an ECS task role over exact "
            "modeled SQS message namespaces with Denial of Service effect"
        ),
        (
            "does_not_establish=a concrete receipt handle, invocation of a removal API request, successful message "
            "removal, irreversible loss, redrive of removed messages, or successful recovery"
        ),
    ]


def _rationale(
    service: NormalizedResource,
    operations: Sequence[str],
    queue_count: int,
) -> str:
    queue_text = "queue" if queue_count == 1 else "queues"
    queue_possessive = "queue's" if queue_count == 1 else "queues'"
    if operations == [_DELETE]:
        impact = "remove messages after receiving the required runtime receipt handles"
    elif operations == [_PURGE]:
        impact = f"purge the {queue_possessive} available messages"
    else:
        impact = (
            "remove messages after receiving runtime receipt handles or purge "
            f"the {queue_possessive} available messages"
        )
    receipt_text = (
        " DeleteMessage authority includes deterministic ReceiveMessage authority for the same task role and queue; "
        "the required receipt handle would still have to come from a runtime receive response."
        if _DELETE in operations
        else ""
    )
    return (
        f"{service.display_name} is reachable through an internet-facing load balancer and its ECS task role has "
        f"deterministic SQS message-removal authority ({_operation_text(operations)}) across {queue_count} exact "
        f"modeled SQS {queue_text}. A compromise of the public workload could {impact} and disrupt messaging "
        f"availability.{receipt_text} Message retention and redrive "
        "posture are preserved as provider-native delivery evidence; they do not establish successful removal, "
        "recovery of removed messages, or irreversible loss."
    )


def _operation_text(operations: Sequence[str]) -> str:
    if len(operations) == 1:
        return operations[0]
    return " and ".join(operations)


def _mapping_records(value: object) -> list[Mapping[str, object]] | None:
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


def _unwrap_reference(value: str) -> str:
    normalized = value.strip()
    if normalized.startswith("${") and normalized.endswith("}"):
        return normalized[2:-1].strip()
    return normalized


def _arn_partition(value: str) -> str | None:
    parts = value.split(":", 2)
    return parts[1] if len(parts) == 3 and parts[0] == "arn" else None


def _display(value: object) -> str:
    return str(value) if value is not None else "unknown"
