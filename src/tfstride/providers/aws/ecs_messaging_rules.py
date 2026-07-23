from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding
from tfstride.providers.aws.ecs_path_rule_helpers import (
    internet_boundary_id,
    path_string_values,
    public_service_network_path,
    resolved_public_load_balancers,
)
from tfstride.providers.aws.resource_facts import aws_facts

_AWS_ECS_SERVICE = "aws_ecs_service"
_MUTATION_ACTION_CLASSES = {
    "sns:publish": "publish",
    "sns:confirmsubscription": "write",
    "sns:subscribe": "write",
    "sns:deletetopic": "delete",
    "sns:addpermission": "administrative",
    "sns:putdataprotectionpolicy": "administrative",
    "sns:removepermission": "administrative",
    "sns:settopicattributes": "administrative",
    "sns:tagresource": "administrative",
    "sns:untagresource": "administrative",
    "sqs:sendmessage": "write",
    "sqs:deletemessage": "delete",
    "sqs:deletequeue": "delete",
    "sqs:purgequeue": "delete",
    "sqs:addpermission": "administrative",
    "sqs:removepermission": "administrative",
    "sqs:setqueueattributes": "administrative",
    "sqs:tagqueue": "administrative",
    "sqs:untagqueue": "administrative",
}
_MUTATION_CLASS_ORDER = ("publish", "write", "delete", "administrative")
_MUTATION_CAPABILITIES = {
    "publish": "publish messages",
    "write": "send messages or manage subscriptions",
    "delete": "delete or purge messaging resources or data",
    "administrative": "perform administrative topic or queue changes",
}


class AwsEcsMessagingAccessRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_service_mutation_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for service in context.inventory.by_type(_AWS_ECS_SERVICE):
            mutation_paths = [
                path
                for path in aws_facts(service).ecs_messaging_access_paths
                if _is_deterministic_mutation_path(path, service.address)
            ]
            if not mutation_paths:
                continue

            load_balancer_addresses = resolved_public_load_balancers(mutation_paths, context)
            if not load_balancer_addresses:
                continue

            task_definition_addresses = path_string_values(mutation_paths, "task_definition_address")
            role_addresses = path_string_values(mutation_paths, "role_address")
            target_addresses = path_string_values(mutation_paths, "messaging_resource_address")
            mutation_classes = _mutation_classes(mutation_paths)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2 if {"delete", "administrative"} & set(mutation_classes) else 1,
                data_sensitivity=1,
                lateral_movement=1,
                blast_radius=2 if len(target_addresses) > 1 else 1,
            )
            affected_resources = [
                *load_balancer_addresses,
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
                    trust_boundary_id=internet_boundary_id(load_balancer_addresses, context),
                    rationale=(
                        f"{service.display_name} is reachable through an internet-facing load balancer and its "
                        f"ECS task role has deterministic {', '.join(mutation_classes)} access to "
                        f"{len(target_addresses)} exact modeled SNS/SQS messaging target(s). A compromise "
                        f"of the public workload could {_capability_summary(mutation_classes)}. This path does not "
                        "mean that the topic or queue itself is public."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "network_path",
                            public_service_network_path(load_balancer_addresses, service.address),
                        ),
                        evidence_item(
                            "task_definitions",
                            [f"address={address}" for address in task_definition_addresses],
                        ),
                        evidence_item("task_roles", _task_role_evidence(mutation_paths)),
                        evidence_item("messaging_mutation_paths", _mutation_path_evidence(mutation_paths)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _is_deterministic_mutation_path(path: Mapping[str, Any], service_address: str) -> bool:
    return (
        path.get("workload_type") == _AWS_ECS_SERVICE
        and path.get("workload_address") == service_address
        and all(
            isinstance(path.get(key), str) and bool(path.get(key))
            for key in (
                "task_definition_address",
                "role_address",
                "messaging_resource_address",
                "messaging_resource_arn",
            )
        )
        and path.get("messaging_resource_type") in {"aws_sns_topic", "aws_sqs_queue"}
        and path.get("role_kind") == "ecs_task_role"
        and path.get("credential_context") == "workload_runtime"
        and path.get("access_state") == "allowed"
        and path.get("modeled_access_state") == "allowed"
        and path.get("role_policy_complete") is True
        and bool(_path_mutation_classes(path))
        and bool(_mutation_actions(path))
    )


def _mutation_classes(paths: list[dict[str, Any]]) -> list[str]:
    classes = {access_class for path in paths for access_class in _path_mutation_classes(path)}
    return [access_class for access_class in _MUTATION_CLASS_ORDER if access_class in classes]


def _path_mutation_classes(path: Mapping[str, Any]) -> list[str]:
    classes = {_MUTATION_ACTION_CLASSES[action.lower()] for action in _mutation_actions(path)}
    return [access_class for access_class in _MUTATION_CLASS_ORDER if access_class in classes]


def _mutation_actions(path: Mapping[str, Any]) -> list[str]:
    return [
        action for action in _string_values(path.get("matched_actions")) if action.lower() in _MUTATION_ACTION_CLASSES
    ]


def _capability_summary(mutation_classes: list[str]) -> str:
    capabilities = [_MUTATION_CAPABILITIES[access_class] for access_class in mutation_classes]
    if len(capabilities) == 1:
        return capabilities[0]
    if len(capabilities) == 2:
        return " and ".join(capabilities)
    return ", ".join(capabilities[:-1]) + f", and {capabilities[-1]}"


def _task_role_evidence(paths: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"address={path['role_address']}",
                    f"arn={path.get('role_arn') or 'unknown'}",
                    "role_kind=ecs_task_role",
                    "credential_context=workload_runtime",
                    "role_policy_complete=true",
                )
            )
            for path in paths
        }
    )


def _mutation_path_evidence(paths: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"target_address={path['messaging_resource_address']}",
                    f"target_type={path['messaging_resource_type']}",
                    f"target_arn={path['messaging_resource_arn']}",
                    f"service={path['messaging_service']}",
                    f"task_definition={path['task_definition_address']}",
                    f"task_role={path['role_address']}",
                    f"mutation_classes={','.join(_path_mutation_classes(path))}",
                    f"actions={','.join(_mutation_actions(path))}",
                    f"resource_scopes={','.join(_string_values(path.get('resource_scopes')))}",
                    f"policy_resources={','.join(_string_values(path.get('policy_resources')))}",
                    f"denied_actions={','.join(_string_values(path.get('denied_actions'))) or 'none'}",
                    "access_state=allowed",
                    "mutation_evaluation=unconditional_identity_policy_allow",
                )
            )
            for path in paths
        }
    )


def _string_values(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]
