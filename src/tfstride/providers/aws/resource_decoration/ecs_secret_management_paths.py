from __future__ import annotations

from collections.abc import Sequence

from tfstride.models import NormalizedResource
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.aws.secret_management_evidence import (
    AwsEcsSecretsManagerManagementPath,
    AwsSecretsManagerManagementEffect,
    AwsSecretsManagerOperation,
    AwsSecretsManagerOperationAuthorization,
    AwsSecretsManagerOperationClass,
)
from tfstride.providers.coercion import dedupe

_ECS_TASK_DEFINITION = "aws_ecs_task_definition"
_ECS_SERVICE = "aws_ecs_service"
_SECRETS_MANAGER_SECRET = "aws_secretsmanager_secret"
_PATH_DEFINITIONS: dict[
    AwsSecretsManagerOperation,
    tuple[AwsSecretsManagerOperationClass, AwsSecretsManagerManagementEffect],
] = {
    "secretsmanager:PutSecretValue": ("value_mutation", "tampering"),
    "secretsmanager:UpdateSecret": ("value_mutation", "tampering"),
    "secretsmanager:UpdateSecretVersionStage": (
        "version_stage_mutation",
        "tampering",
    ),
    "secretsmanager:DeleteSecret": (
        "destructive_administration",
        "disruption",
    ),
}


class ModelEcsSecretsManagerManagementPathsStage:
    name = "model_ecs_secrets_manager_management_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AwsDecorationContext,
    ) -> None:
        secrets = tuple(resource for resource in resources if resource.resource_type == _SECRETS_MANAGER_SECRET)
        for task_definition in resources:
            if task_definition.resource_type != _ECS_TASK_DEFINITION:
                continue
            paths, uncertainties = _ecs_secret_management_paths(
                task_definition,
                secrets,
                context,
            )
            facts = aws_facts(task_definition)
            facts.set_ecs_secret_management_paths(paths)
            facts.extend_ecs_secret_management_path_uncertainties(uncertainties)


class ProjectEcsSecretsManagerManagementPathsOntoServicesStage:
    name = "project_ecs_secrets_manager_management_paths_onto_services"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AwsDecorationContext,
    ) -> None:
        for service in resources:
            if service.resource_type != _ECS_SERVICE:
                continue

            facts = aws_facts(service)
            paths: list[AwsEcsSecretsManagerManagementPath] = []
            uncertainties = [
                f"{service.address}: task definition reference {reference} is unresolved "
                "for Secrets Manager management-path projection"
                for reference in facts.unresolved_task_definition_references
            ]
            for task_definition_address in facts.resolved_task_definition_addresses:
                task_definition = context.index.ecs_task_definitions.get(task_definition_address, source=service)
                if task_definition is None:
                    uncertainties.append(
                        f"{service.address}: resolved task definition "
                        f"{task_definition_address} is unavailable for Secrets Manager "
                        "management-path projection"
                    )
                    continue
                task_facts = aws_facts(task_definition)
                uncertainties.extend(task_facts.ecs_secret_management_path_uncertainties)
                paths.extend(
                    _service_record(service, task_definition, path) for path in task_facts.ecs_secret_management_paths
                )

            facts.set_ecs_secret_management_paths(paths)
            facts.extend_ecs_secret_management_path_uncertainties(dedupe(uncertainties))


def _ecs_secret_management_paths(
    task_definition: NormalizedResource,
    secrets: Sequence[NormalizedResource],
    context: AwsDecorationContext,
) -> tuple[list[AwsEcsSecretsManagerManagementPath], list[str]]:
    task_facts = aws_facts(task_definition)
    task_role_reference = task_facts.task_role_arn
    if not task_role_reference:
        return (
            [],
            [
                f"{task_definition.address}: ECS task role {reference} is unresolved "
                "for Secrets Manager management-path modeling"
                for reference in task_facts.unresolved_task_role_arns
            ],
        )

    task_role = context.index.role_index.get(task_role_reference, source=task_definition)
    if task_role is None:
        return (
            [],
            [f"{task_definition.address}: ECS task role {task_role_reference} is not modeled in the plan"],
        )
    if not _is_exact_iam_role_arn(task_role.arn):
        return (
            [],
            [
                f"{task_definition.address}: ECS task role {task_role.address} "
                "has no exact IAM role ARN for Secrets Manager "
                "management-path matching"
            ],
        )

    paths: list[AwsEcsSecretsManagerManagementPath] = []
    uncertainties: list[str] = []
    for secret in secrets:
        secret_facts = aws_facts(secret)
        secret_arn = secret.arn
        if not _is_exact_secret_arn(secret_arn):
            uncertainties.append(
                f"{task_definition.address}: Secrets Manager secret {secret.address} "
                "has no exact ARN for management-path matching"
            )
            continue
        assert secret_arn is not None

        for uncertainty in secret_facts.secrets_manager_operation_authorization_uncertainties:
            if _authorization_uncertainty_applies_to_role(
                uncertainty,
                task_role,
            ):
                uncertainties.append(f"{task_definition.address}: {uncertainty}")

        for authorization in secret_facts.secrets_manager_operation_authorizations:
            if not _authorization_matches_role(authorization, task_role):
                continue
            operation = authorization["operation"]
            definition = _PATH_DEFINITIONS.get(operation)
            if definition is None:
                continue
            operation_class, management_effect = definition
            if (
                authorization["operation_class"] != operation_class
                or authorization["management_effect"] != management_effect
            ):
                uncertainties.append(
                    f"{task_definition.address}: Secrets Manager authorization for "
                    f"{operation} on {secret.address} has inconsistent operation semantics"
                )
                continue
            if (
                authorization["secret_address"] != secret.address
                or authorization["secret_resource_type"] != secret.resource_type
                or authorization["secret_arn"] != secret_arn
            ):
                uncertainties.append(
                    f"{task_definition.address}: Secrets Manager authorization for "
                    f"{operation} does not retain the exact modeled identity of "
                    f"{secret.address}"
                )
                continue

            authorization_state = authorization["authorization_state"]
            if authorization_state != "allowed":
                if authorization_state == "unknown":
                    uncertainties.append(
                        f"{task_definition.address}: {task_role.address} has unresolved "
                        f"{operation} authorization to Secrets Manager secret "
                        f"{secret.address}"
                    )
                continue
            if (
                authorization["explicit_deny"]
                or not authorization["identity_policy_complete"]
                or not authorization["resource_policy_complete"]
                or authorization["authorization_requires_condition_evaluation"]
            ):
                uncertainties.append(
                    f"{task_definition.address}: allowed {operation} authorization to "
                    f"{secret.address} does not satisfy deterministic management-path "
                    "evidence requirements"
                )
                continue

            paths.append(
                _path_record(
                    task_definition,
                    task_role,
                    secret,
                    authorization,
                )
            )

    paths.sort(
        key=lambda path: (
            path["secret_address"],
            path["management_effect"],
            path["operation"],
            path["role_address"],
        )
    )
    return paths, dedupe(uncertainties)


def _path_record(
    task_definition: NormalizedResource,
    task_role: NormalizedResource,
    secret: NormalizedResource,
    authorization: AwsSecretsManagerOperationAuthorization,
) -> AwsEcsSecretsManagerManagementPath:
    secret_facts = aws_facts(secret)
    return {
        "workload_address": task_definition.address,
        "workload_type": task_definition.resource_type,
        "task_definition_address": task_definition.address,
        "task_definition_arn": task_definition.arn,
        "secret_address": secret.address,
        "secret_resource_type": secret.resource_type,
        "secret_arn": authorization["secret_arn"],
        "secret_name": secret_facts.name,
        "operation": authorization["operation"],
        "operation_class": authorization["operation_class"],
        "management_effect": authorization["management_effect"],
        "role_kind": "ecs_task_role",
        "credential_context": "workload_runtime",
        "role_address": task_role.address,
        "role_arn": authorization["principal_arn"],
        "role_policy_complete": authorization["identity_policy_complete"],
        "authorization_state": "allowed",
        "authorization_bases": list(authorization["authorization_bases"]),
        "candidate_authorization_bases": list(authorization["candidate_authorization_bases"]),
        "evaluation_basis": "modeled_secrets_manager_authorization",
        "same_account": authorization["same_account"],
        "explicit_deny": authorization["explicit_deny"],
        "conditional_policy_evidence_present": authorization["conditional_policy_evidence_present"],
        "authorization_requires_condition_evaluation": authorization["authorization_requires_condition_evaluation"],
        "identity_policy_source_addresses": list(authorization["identity_policy_source_addresses"]),
        "secrets_manager_resource_policy_source_addresses": list(
            authorization["secrets_manager_resource_policy_source_addresses"]
        ),
        "identity_policy_statements": [statement.copy() for statement in authorization["identity_policy_statements"]],
        "resource_policy_statements": [statement.copy() for statement in authorization["resource_policy_statements"]],
        "terraform_recovery_window_in_days": (secret_facts.secrets_manager_recovery_window_in_days),
        "recovery_window_evidence_scope": "terraform_resource_deletion_only",
        "authorization_record": authorization.copy(),
    }


def _service_record(
    service: NormalizedResource,
    task_definition: NormalizedResource,
    path: AwsEcsSecretsManagerManagementPath,
) -> AwsEcsSecretsManagerManagementPath:
    return {
        **path,
        "workload_address": service.address,
        "workload_type": service.resource_type,
        "task_definition_address": task_definition.address,
        "task_definition_arn": task_definition.arn,
        "internet_facing_load_balancers": (aws_facts(service).internet_facing_load_balancer_addresses),
    }


def _authorization_matches_role(
    authorization: AwsSecretsManagerOperationAuthorization,
    role: NormalizedResource,
) -> bool:
    return bool(
        authorization["principal_address"] == role.address
        and role.arn is not None
        and authorization["principal_arn"] == role.arn
    )


def _authorization_uncertainty_applies_to_role(
    uncertainty: str,
    task_role: NormalizedResource,
) -> bool:
    return (
        task_role.address in uncertainty
        or "effective Secrets Manager resource-policy" in uncertainty
        or "exact Secrets Manager ARN" in uncertainty
        or "resource-policy target" in uncertainty
    )


def _is_exact_iam_role_arn(value: object) -> bool:
    if not isinstance(value, str) or "*" in value or "?" in value:
        return False
    parts = value.split(":", 5)
    return bool(
        len(parts) == 6
        and parts[0] == "arn"
        and parts[1]
        and parts[2] == "iam"
        and not parts[3]
        and parts[4].isdigit()
        and len(parts[4]) == 12
        and parts[5].startswith("role/")
        and len(parts[5]) > len("role/")
    )


def _is_exact_secret_arn(value: object) -> bool:
    if not isinstance(value, str) or "*" in value or "?" in value:
        return False
    parts = value.split(":", 5)
    return bool(
        len(parts) == 6
        and parts[0] == "arn"
        and parts[1]
        and parts[2] == "secretsmanager"
        and parts[3]
        and parts[4].isdigit()
        and len(parts[4]) == 12
        and parts[5].startswith("secret:")
        and len(parts[5]) > len("secret:")
    )
