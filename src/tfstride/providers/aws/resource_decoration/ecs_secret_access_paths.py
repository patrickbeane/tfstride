from __future__ import annotations

from collections.abc import Mapping
from fnmatch import fnmatchcase
from typing import Any

from tfstride.models import IAMPolicyCondition, IAMPolicyStatement, NormalizedResource
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.coercion import dedupe

_ECS_TASK_DEFINITION = "aws_ecs_task_definition"
_GET_SECRET_VALUE = "secretsmanager:GetSecretValue"


class ModelEcsSecretAccessPathsStage:
    name = "model_ecs_secret_access_paths"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        for task_definition in resources:
            if task_definition.resource_type != _ECS_TASK_DEFINITION:
                continue
            paths, uncertainties = _ecs_secret_access_paths(task_definition, context)
            facts = aws_facts(task_definition)
            facts.set_ecs_secret_access_paths(paths)
            facts.extend_ecs_secret_access_path_uncertainties(uncertainties)


class ProjectEcsSecretAccessPathsOntoServicesStage:
    name = "project_ecs_secret_access_paths_onto_services"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        for service in resources:
            if service.resource_type != "aws_ecs_service":
                continue

            facts = aws_facts(service)
            projected_paths: list[dict[str, Any]] = []
            uncertainties = [
                f"{service.address}: task definition reference {reference} is unresolved for "
                "secret access-path projection"
                for reference in facts.unresolved_task_definition_references
            ]
            for task_definition_address in facts.resolved_task_definition_addresses:
                task_definition = context.index.ecs_task_definitions.get(task_definition_address)
                if task_definition is None:
                    uncertainties.append(
                        f"{service.address}: resolved task definition {task_definition_address} is unavailable "
                        "for secret access-path projection"
                    )
                    continue

                task_definition_facts = aws_facts(task_definition)
                uncertainties.extend(task_definition_facts.ecs_secret_access_path_uncertainties)
                projected_paths.extend(
                    _service_access_path(service, task_definition, path)
                    for path in task_definition_facts.ecs_secret_access_paths
                )

            facts.set_ecs_secret_access_paths(projected_paths)
            facts.extend_ecs_secret_access_path_uncertainties(dedupe(uncertainties))


def _service_access_path(
    service: NormalizedResource,
    task_definition: NormalizedResource,
    path: Mapping[str, Any],
) -> dict[str, Any]:
    service_facts = aws_facts(service)
    return {
        **path,
        "workload_address": service.address,
        "workload_type": service.resource_type,
        "task_definition_address": task_definition.address,
        "task_definition_arn": task_definition.arn,
        "internet_facing_load_balancers": service_facts.internet_facing_load_balancer_addresses,
    }


def _ecs_secret_access_paths(
    task_definition: NormalizedResource,
    context: AwsDecorationContext,
) -> tuple[list[dict[str, Any]], list[str]]:
    facts = aws_facts(task_definition)
    exact_references: list[tuple[Mapping[str, Any], str]] = []
    uncertainties: list[str] = []

    for reference in facts.ecs_secret_references:
        secret_arn = _exact_secret_arn(reference)
        if secret_arn is not None:
            exact_references.append((reference, secret_arn))
            continue
        if reference.get("reference_kind") in {"terraform", "secrets_manager_arn"}:
            uncertainties.append(
                f"{task_definition.address}: secret reference {reference.get('path') or 'unknown'} "
                "does not expose an exact Secrets Manager ARN for access-path modeling"
            )

    if not exact_references:
        return [], dedupe(uncertainties)

    execution_role_reference = facts.execution_role_arn
    if not execution_role_reference:
        uncertainties.append(
            f"{task_definition.address}: exact Secrets Manager references are configured but "
            "execution_role_arn is not represented"
        )
        return [], dedupe(uncertainties)

    execution_role = context.index.role_index.get(execution_role_reference)
    if execution_role is None:
        uncertainties.append(
            f"{task_definition.address}: ECS task execution role {execution_role_reference} is not modeled in the plan"
        )
        return [], dedupe(uncertainties)

    role_facts = aws_facts(execution_role)
    unresolved_policy_arns = role_facts.unresolved_attached_policy_arns
    uncertainties.extend(
        f"{task_definition.address}: {execution_role.address} has unresolved attached policy {policy_arn}"
        for policy_arn in unresolved_policy_arns
    )

    paths: list[dict[str, Any]] = []
    for reference, secret_arn in exact_references:
        statement_records = _matching_statement_records(execution_role.policy_statements, secret_arn)
        modeled_access_state = _modeled_access_state(statement_records)
        access_state = _conservative_access_state(
            modeled_access_state,
            role_policy_complete=not unresolved_policy_arns,
        )
        conditional_effects = sorted(
            {str(statement["effect"]) for statement in statement_records if statement["conditional"] is True}
        )
        if conditional_effects:
            uncertainties.append(
                f"{task_definition.address}: {execution_role.address} targeting {secret_arn} has conditional "
                f"{', '.join(conditional_effects)} statement evidence that requires runtime evaluation"
            )
        paths.append(
            _access_path_record(
                task_definition,
                reference,
                secret_arn,
                execution_role,
                statement_records,
                modeled_access_state=modeled_access_state,
                access_state=access_state,
                role_policy_complete=not unresolved_policy_arns,
            )
        )

    return paths, dedupe(uncertainties)


def _exact_secret_arn(reference: Mapping[str, Any]) -> str | None:
    if (
        reference.get("state") != "reference"
        or reference.get("reference_kind") != "secrets_manager_arn"
        or reference.get("is_resolved") is not True
    ):
        return None
    partition = reference.get("aws_partition")
    region = reference.get("aws_region")
    account_id = reference.get("aws_account_id")
    secret_name = reference.get("secret_name")
    if not all(isinstance(value, str) and value for value in (partition, region, account_id, secret_name)):
        return None
    secret_arn = f"arn:{partition}:secretsmanager:{region}:{account_id}:secret:{secret_name}"
    return None if _has_wildcard(secret_arn) else secret_arn


def _matching_statement_records(
    statements: tuple[IAMPolicyStatement, ...],
    secret_arn: str,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for statement in statements:
        effect = statement.effect.strip().lower()
        if effect not in {"allow", "deny"}:
            continue
        matching_actions = [
            action for action in statement.actions if fnmatchcase(_GET_SECRET_VALUE.lower(), action.lower())
        ]
        matching_resources = [
            resource
            for resource in statement.resources
            if isinstance(resource, str) and fnmatchcase(secret_arn, resource)
        ]
        if not matching_actions or not matching_resources:
            continue
        records.append(
            {
                "effect": effect,
                "actions": list(statement.actions),
                "matched_actions": [_GET_SECRET_VALUE],
                "matching_action_patterns": matching_actions,
                "resources": list(statement.resources),
                "matching_resources": matching_resources,
                "resource_scope": _resource_scope(set(matching_resources), secret_arn),
                "conditions": [_condition_record(condition) for condition in statement.conditions],
                "conditional": bool(statement.conditions),
            }
        )
    return records


def _condition_record(condition: IAMPolicyCondition) -> dict[str, Any]:
    return {
        "operator": condition.operator,
        "key": condition.key,
        "values": list(condition.values),
    }


def _modeled_access_state(statements: list[dict[str, Any]]) -> str:
    unconditional_deny = any(
        statement["effect"] == "deny" and statement["conditional"] is False for statement in statements
    )
    conditional_deny = any(
        statement["effect"] == "deny" and statement["conditional"] is True for statement in statements
    )
    unconditional_allow = any(
        statement["effect"] == "allow" and statement["conditional"] is False for statement in statements
    )
    conditional_allow = any(
        statement["effect"] == "allow" and statement["conditional"] is True for statement in statements
    )
    if unconditional_deny:
        return "denied"
    if conditional_deny:
        return "unknown"
    if unconditional_allow:
        return "allowed"
    if conditional_allow:
        return "unknown"
    return "not_modeled"


def _conservative_access_state(modeled_access_state: str, *, role_policy_complete: bool) -> str:
    if modeled_access_state == "denied":
        return "denied"
    if not role_policy_complete:
        return "unknown"
    return modeled_access_state


def _access_path_record(
    task_definition: NormalizedResource,
    reference: Mapping[str, Any],
    secret_arn: str,
    execution_role: NormalizedResource,
    statement_records: list[dict[str, Any]],
    *,
    modeled_access_state: str,
    access_state: str,
    role_policy_complete: bool,
) -> dict[str, Any]:
    allow_statements = [statement for statement in statement_records if statement["effect"] == "allow"]
    deny_statements = [statement for statement in statement_records if statement["effect"] == "deny"]
    allow_resources = {
        resource
        for statement in allow_statements
        for resource in statement["matching_resources"]
        if isinstance(resource, str)
    }
    return {
        "workload_address": task_definition.address,
        "workload_type": task_definition.resource_type,
        "secret_reference": reference.get("reference"),
        "secret_reference_path": reference.get("value_path") or reference.get("path"),
        "container_name": reference.get("container_name"),
        "setting_name": reference.get("setting_name"),
        "secret_arn": secret_arn,
        "json_key": reference.get("json_key"),
        "version_stage": reference.get("version_stage"),
        "version_id": reference.get("version_id"),
        "role_kind": "ecs_task_execution_role",
        "credential_context": "ecs_agent_secret_delivery",
        "role_address": execution_role.address,
        "role_arn": execution_role.arn or aws_facts(task_definition).execution_role_arn,
        "role_policy_complete": role_policy_complete,
        "evaluation_basis": "modeled_identity_policy",
        "modeled_access_state": modeled_access_state,
        "access_state": access_state,
        "explicit_deny": bool(deny_statements),
        "conditional_evaluation_required": any(statement["conditional"] is True for statement in statement_records),
        "matched_actions": [_GET_SECRET_VALUE] if statement_records else [],
        "policy_action_patterns": _statement_values(allow_statements, "matching_action_patterns"),
        "policy_resources": sorted(allow_resources),
        "deny_action_patterns": _statement_values(deny_statements, "matching_action_patterns"),
        "deny_policy_resources": _statement_values(deny_statements, "matching_resources"),
        "resource_scope": _resource_scope(allow_resources, secret_arn) if allow_resources else "not_applicable",
        "policy_statements": statement_records,
    }


def _statement_values(statements: list[dict[str, Any]], key: str) -> list[str]:
    return sorted(
        {value for statement in statements for value in statement[key] if isinstance(value, str)},
        key=str.lower,
    )


def _resource_scope(resources: set[str], secret_arn: str) -> str:
    if "*" in resources:
        return "all_resources"
    if any(resource != secret_arn and _has_wildcard(resource) for resource in resources):
        return "secret_pattern"
    return "exact_secret"


def _has_wildcard(value: str) -> bool:
    return "*" in value or "?" in value
