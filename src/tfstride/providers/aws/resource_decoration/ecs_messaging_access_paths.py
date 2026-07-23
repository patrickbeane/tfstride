from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any, Literal

from tfstride.models import IAMPolicyCondition, IAMPolicyStatement, NormalizedResource
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.coercion import dedupe

MessagingService = Literal["sns", "sqs"]
AccessClass = Literal["publish", "write", "consume", "delete", "administrative"]

_ECS_TASK_DEFINITION = "aws_ecs_task_definition"
_ECS_SERVICE = "aws_ecs_service"
_ACCESS_CLASS_ORDER: tuple[AccessClass, ...] = (
    "publish",
    "write",
    "consume",
    "delete",
    "administrative",
)


@dataclass(frozen=True, slots=True)
class _MessagingAction:
    name: str
    service: MessagingService
    access_class: AccessClass


_MESSAGING_ACTIONS = (
    _MessagingAction("sns:Publish", "sns", "publish"),
    _MessagingAction("sns:ConfirmSubscription", "sns", "write"),
    _MessagingAction("sns:Subscribe", "sns", "write"),
    _MessagingAction("sns:DeleteTopic", "sns", "delete"),
    _MessagingAction("sns:AddPermission", "sns", "administrative"),
    _MessagingAction("sns:PutDataProtectionPolicy", "sns", "administrative"),
    _MessagingAction("sns:RemovePermission", "sns", "administrative"),
    _MessagingAction("sns:SetTopicAttributes", "sns", "administrative"),
    _MessagingAction("sns:TagResource", "sns", "administrative"),
    _MessagingAction("sns:UntagResource", "sns", "administrative"),
    _MessagingAction("sqs:SendMessage", "sqs", "write"),
    _MessagingAction("sqs:ReceiveMessage", "sqs", "consume"),
    _MessagingAction("sqs:ChangeMessageVisibility", "sqs", "consume"),
    _MessagingAction("sqs:DeleteMessage", "sqs", "delete"),
    _MessagingAction("sqs:DeleteQueue", "sqs", "delete"),
    _MessagingAction("sqs:PurgeQueue", "sqs", "delete"),
    _MessagingAction("sqs:AddPermission", "sqs", "administrative"),
    _MessagingAction("sqs:CancelMessageMoveTask", "sqs", "administrative"),
    _MessagingAction("sqs:RemovePermission", "sqs", "administrative"),
    _MessagingAction("sqs:SetQueueAttributes", "sqs", "administrative"),
    _MessagingAction("sqs:StartMessageMoveTask", "sqs", "administrative"),
    _MessagingAction("sqs:TagQueue", "sqs", "administrative"),
    _MessagingAction("sqs:UntagQueue", "sqs", "administrative"),
)
_ACTIONS_BY_SERVICE: dict[MessagingService, tuple[_MessagingAction, ...]] = {
    service: tuple(action for action in _MESSAGING_ACTIONS if action.service == service) for service in ("sns", "sqs")
}
_ACTION_BY_NAME = {action.name: action for action in _MESSAGING_ACTIONS}


class ModelEcsMessagingAccessPathsStage:
    name = "model_ecs_messaging_access_paths"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        for task_definition in resources:
            if task_definition.resource_type != _ECS_TASK_DEFINITION:
                continue
            paths, uncertainties = _ecs_messaging_access_paths(task_definition, context)
            facts = aws_facts(task_definition)
            facts.set_ecs_messaging_access_paths(paths)
            facts.extend_ecs_messaging_access_path_uncertainties(uncertainties)


class ProjectEcsMessagingAccessPathsOntoServicesStage:
    name = "project_ecs_messaging_access_paths_onto_services"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        for service in resources:
            if service.resource_type != _ECS_SERVICE:
                continue

            facts = aws_facts(service)
            paths: list[dict[str, Any]] = []
            uncertainties = [
                f"{service.address}: task definition reference {reference} is unresolved for "
                "messaging access-path projection"
                for reference in facts.unresolved_task_definition_references
            ]
            for task_definition_address in facts.resolved_task_definition_addresses:
                task_definition = context.index.ecs_task_definitions.get(task_definition_address)
                if task_definition is None:
                    uncertainties.append(
                        f"{service.address}: resolved task definition {task_definition_address} is unavailable "
                        "for messaging access-path projection"
                    )
                    continue
                task_facts = aws_facts(task_definition)
                uncertainties.extend(task_facts.ecs_messaging_access_path_uncertainties)
                paths.extend(
                    _service_access_path(service, task_definition, path)
                    for path in task_facts.ecs_messaging_access_paths
                )

            facts.set_ecs_messaging_access_paths(paths)
            facts.extend_ecs_messaging_access_path_uncertainties(dedupe(uncertainties))


def _service_access_path(
    service: NormalizedResource,
    task_definition: NormalizedResource,
    path: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        **path,
        "workload_address": service.address,
        "workload_type": service.resource_type,
        "task_definition_address": task_definition.address,
        "task_definition_arn": task_definition.arn,
        "internet_facing_load_balancers": aws_facts(service).internet_facing_load_balancer_addresses,
    }


def _ecs_messaging_access_paths(
    task_definition: NormalizedResource,
    context: AwsDecorationContext,
) -> tuple[list[dict[str, Any]], list[str]]:
    task_facts = aws_facts(task_definition)
    task_role_reference = task_facts.task_role_arn
    if not task_role_reference:
        return [], []

    task_role = context.index.role_index.get(task_role_reference)
    if task_role is None:
        return (
            [],
            [f"{task_definition.address}: ECS task role {task_role_reference} is not modeled in the plan"],
        )

    role_facts = aws_facts(task_role)
    uncertainties = [
        f"{task_definition.address}: {task_role.address} has unresolved attached policy {policy_arn}"
        for policy_arn in role_facts.unresolved_attached_policy_arns
    ]
    targets, target_uncertainties = _target_resources(task_role, context)
    uncertainties.extend(f"{task_definition.address}: {message}" for message in target_uncertainties)

    paths: list[dict[str, Any]] = []
    for service, target in targets:
        target_arn = target.arn
        if not target_arn:
            uncertainties.append(
                f"{task_definition.address}: messaging resource {target.address} has no resolved ARN "
                "for IAM scope matching"
            )
            continue
        statement_records = _matching_statement_records(task_role.policy_statements, service, target_arn)
        if not statement_records:
            continue
        assessment = _assess_actions(statement_records, service)
        if assessment["conditional_actions"]:
            uncertainties.append(
                f"{task_definition.address}: {task_role.address} targeting {target.address} has conditional "
                "identity-policy evidence for actions: " + ", ".join(assessment["conditional_actions"])
            )
        paths.append(
            _access_path_record(
                task_definition,
                target,
                service,
                task_role,
                statement_records,
                assessment,
                role_policy_complete=not role_facts.unresolved_attached_policy_arns,
            )
        )

    return paths, dedupe(uncertainties)


def _target_resources(
    role: NormalizedResource,
    context: AwsDecorationContext,
) -> tuple[list[tuple[MessagingService, NormalizedResource]], list[str]]:
    targets: dict[str, tuple[MessagingService, NormalizedResource]] = {}
    uncertainties: list[str] = []
    for statement in role.policy_statements:
        services = _matching_services(statement)
        if not services:
            continue
        for resource in statement.resources:
            exact_target = _exact_messaging_arn(resource)
            if exact_target is not None:
                service, target_arn = exact_target
                if service not in services:
                    continue
                target = _resource_index(context, service).get(target_arn)
                if target is None:
                    uncertainties.append(
                        f"{role.address} messaging policy targets {target_arn}, which is not modeled in the plan"
                    )
                    continue
                targets[target.address] = (service, target)
                continue
            if _could_target_messaging(resource, services):
                uncertainties.append(
                    f"{role.address} messaging policy resource {resource!r} does not identify an exact "
                    "SNS topic or SQS queue"
                )
    return [targets[address] for address in sorted(targets)], dedupe(uncertainties)


def _resource_index(
    context: AwsDecorationContext,
    service: MessagingService,
) -> dict[str, NormalizedResource]:
    if service == "sns":
        return context.index.sns_topics
    return context.index.sqs_queues


def _matching_services(statement: IAMPolicyStatement) -> set[MessagingService]:
    services: set[MessagingService] = set()
    for action in _MESSAGING_ACTIONS:
        if any(fnmatchcase(action.name.lower(), pattern.lower()) for pattern in statement.actions):
            services.add(action.service)
    return services


def _exact_messaging_arn(value: object) -> tuple[MessagingService, str] | None:
    if not isinstance(value, str) or _has_wildcard(value):
        return None
    parts = value.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn" or parts[2] not in {"sns", "sqs"}:
        return None
    _, _, service_value, region, account_id, resource_name = parts
    if not region or not account_id or not resource_name:
        return None
    if service_value == "sns" and ":" in resource_name:
        return None
    service: MessagingService = "sns" if service_value == "sns" else "sqs"
    return service, value


def _could_target_messaging(value: object, services: set[MessagingService]) -> bool:
    if not isinstance(value, str):
        return False
    lowered = value.lower()
    if value == "*":
        return True
    return any(marker in lowered for service in services for marker in (f":{service}:", f"aws_{service}_"))


def _matching_statement_records(
    statements: tuple[IAMPolicyStatement, ...],
    service: MessagingService,
    target_arn: str,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for statement in statements:
        effect = statement.effect.strip().lower()
        if effect not in {"allow", "deny"}:
            continue

        matched_actions: list[str] = []
        matching_patterns: set[str] = set()
        for action in _ACTIONS_BY_SERVICE[service]:
            action_patterns = _matching_action_patterns(statement, action.name)
            if not action_patterns:
                continue
            matched_actions.append(action.name)
            matching_patterns.update(action_patterns)
        matching_resources = {
            resource
            for resource in statement.resources
            if isinstance(resource, str) and fnmatchcase(target_arn, resource)
        }
        if not matched_actions or not matching_resources:
            continue
        records.append(
            {
                "effect": effect,
                "actions": list(statement.actions),
                "matched_actions": matched_actions,
                "matching_action_patterns": sorted(matching_patterns, key=str.lower),
                "resources": list(statement.resources),
                "matching_resources": sorted(matching_resources),
                "resource_scopes": _resource_scopes(matching_resources, target_arn, service),
                "access_classes": _access_classes(matched_actions),
                "conditions": [_condition_record(condition) for condition in statement.conditions],
                "conditional": bool(statement.conditions),
            }
        )
    return records


def _matching_action_patterns(statement: IAMPolicyStatement, action: str) -> set[str]:
    return {pattern for pattern in statement.actions if fnmatchcase(action.lower(), pattern.lower())}


def _condition_record(condition: IAMPolicyCondition) -> dict[str, Any]:
    return {
        "operator": condition.operator,
        "key": condition.key,
        "values": list(condition.values),
    }


def _assess_actions(
    records: list[dict[str, Any]],
    service: MessagingService,
) -> dict[str, list[str]]:
    allowed: list[str] = []
    denied: list[str] = []
    unknown: list[str] = []
    conditional: list[str] = []
    for action in _ACTIONS_BY_SERVICE[service]:
        matching = [record for record in records if action.name in record["matched_actions"]]
        if not matching:
            continue
        unconditional_deny = any(record["effect"] == "deny" and not record["conditional"] for record in matching)
        conditional_deny = any(record["effect"] == "deny" and record["conditional"] for record in matching)
        unconditional_allow = any(record["effect"] == "allow" and not record["conditional"] for record in matching)
        conditional_allow = any(record["effect"] == "allow" and record["conditional"] for record in matching)
        if conditional_deny or conditional_allow:
            conditional.append(action.name)
        if unconditional_deny:
            denied.append(action.name)
        elif conditional_deny:
            unknown.append(action.name)
        elif unconditional_allow:
            allowed.append(action.name)
        elif conditional_allow:
            unknown.append(action.name)
    return {
        "allowed_actions": allowed,
        "denied_actions": denied,
        "unknown_actions": unknown,
        "conditional_actions": conditional,
    }


def _access_path_record(
    task_definition: NormalizedResource,
    target: NormalizedResource,
    service: MessagingService,
    task_role: NormalizedResource,
    statement_records: list[dict[str, Any]],
    assessment: dict[str, list[str]],
    *,
    role_policy_complete: bool,
) -> dict[str, Any]:
    allow_records = [record for record in statement_records if record["effect"] == "allow"]
    deny_records = [record for record in statement_records if record["effect"] == "deny"]
    modeled_access_state = _modeled_access_state(assessment)
    access_state = _conservative_access_state(
        modeled_access_state,
        role_policy_complete=role_policy_complete,
    )
    return {
        "workload_address": task_definition.address,
        "workload_type": task_definition.resource_type,
        "messaging_service": service,
        "messaging_resource_address": target.address,
        "messaging_resource_type": target.resource_type,
        "messaging_resource_name": target.identifier or target.name,
        "messaging_resource_arn": target.arn,
        "role_kind": "ecs_task_role",
        "credential_context": "workload_runtime",
        "role_address": task_role.address,
        "role_arn": task_role.arn or aws_facts(task_definition).task_role_arn,
        "role_policy_complete": role_policy_complete,
        "evaluation_basis": "modeled_identity_policy",
        "modeled_access_state": modeled_access_state,
        "access_state": access_state,
        "access_classes": _access_classes(assessment["allowed_actions"]),
        "denied_access_classes": _access_classes(assessment["denied_actions"]),
        "unknown_access_classes": _access_classes(assessment["unknown_actions"]),
        "matched_actions": assessment["allowed_actions"],
        "denied_actions": assessment["denied_actions"],
        "unknown_actions": assessment["unknown_actions"],
        "explicit_deny": bool(deny_records),
        "conditional_evaluation_required": bool(assessment["conditional_actions"]),
        "policy_action_patterns": _statement_values(allow_records, "matching_action_patterns"),
        "policy_resources": _statement_values(allow_records, "matching_resources"),
        "deny_action_patterns": _statement_values(deny_records, "matching_action_patterns"),
        "deny_policy_resources": _statement_values(deny_records, "matching_resources"),
        "resource_scopes": _statement_values(allow_records, "resource_scopes"),
        "policy_statements": statement_records,
    }


def _modeled_access_state(assessment: Mapping[str, list[str]]) -> str:
    if assessment["allowed_actions"]:
        return "allowed"
    if assessment["unknown_actions"]:
        return "unknown"
    if assessment["denied_actions"]:
        return "denied"
    return "not_modeled"


def _conservative_access_state(modeled_access_state: str, *, role_policy_complete: bool) -> str:
    if not role_policy_complete:
        return "unknown"
    return modeled_access_state


def _access_classes(actions: list[str]) -> list[str]:
    classes = {_ACTION_BY_NAME[action].access_class for action in actions}
    return [access_class for access_class in _ACCESS_CLASS_ORDER if access_class in classes]


def _statement_values(statements: list[dict[str, Any]], key: str) -> list[str]:
    return sorted(
        {value for statement in statements for value in statement[key] if isinstance(value, str)},
        key=str.lower,
    )


def _resource_scopes(
    resources: set[str],
    target_arn: str,
    service: MessagingService,
) -> list[str]:
    scopes = {_resource_scope(resource, target_arn, service) for resource in resources}
    order = ("exact_topic", "exact_queue", "messaging_pattern", "all_resources")
    return [scope for scope in order if scope in scopes]


def _resource_scope(resource: str, target_arn: str, service: MessagingService) -> str:
    if resource == target_arn:
        return "exact_topic" if service == "sns" else "exact_queue"
    if resource == "*":
        return "all_resources"
    return "messaging_pattern"


def _has_wildcard(value: str) -> bool:
    return "*" in value or "?" in value
