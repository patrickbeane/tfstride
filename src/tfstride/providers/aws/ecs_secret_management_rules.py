from __future__ import annotations

from collections.abc import Mapping, Sequence

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import EvidenceItem, Finding, NormalizedResource
from tfstride.providers.aws.ecs_path_rule_helpers import (
    internet_boundary_id,
    path_string_values,
    verified_public_service_ingress,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.secret_management_evidence import (
    AwsEcsSecretsManagerManagementPath,
    AwsSecretsManagerManagementEffect,
    AwsSecretsManagerOperation,
    AwsSecretsManagerOperationClass,
)

_AWS_ECS_SERVICE = "aws_ecs_service"
_AWS_ECS_TASK_DEFINITION = "aws_ecs_task_definition"
_AWS_IAM_ROLE = "aws_iam_role"
_AWS_SECRETS_MANAGER_SECRET = "aws_secretsmanager_secret"

_MANAGEMENT_PATH_DEFINITIONS: dict[
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
_MANAGEMENT_OPERATION_ORDER = tuple(_MANAGEMENT_PATH_DEFINITIONS)
_AUTHORIZATION_BASES = frozenset(
    {
        "identity_policy",
        "resource_policy_direct",
        "cross_account_identity_and_resource_policy",
    }
)


class AwsEcsSecretManagementRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_service_tampering(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_public_management_access(context, rule_id, "tampering")

    def detect_public_service_disruption(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_public_management_access(context, rule_id, "disruption")

    def _detect_public_management_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
        management_effect: AwsSecretsManagerManagementEffect,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for service in context.inventory.by_type(_AWS_ECS_SERVICE):
            paths = [
                path
                for path in aws_facts(service).ecs_secret_management_paths
                if _is_deterministic_management_path(
                    path,
                    service,
                    context,
                    management_effect,
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
            secret_addresses = path_string_values(paths, "secret_address")
            operations = _management_operations(paths)
            recovery_evidence = _recovery_window_evidence(paths) if management_effect == "disruption" else []
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2 if management_effect == "disruption" else 1,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=2 if len(secret_addresses) > 1 else 1,
            )
            affected_resources = [
                *ingress.resource_addresses,
                service.address,
                *task_definition_addresses,
                *role_addresses,
                *secret_addresses,
            ]
            evidence: list[EvidenceItem | None] = [
                evidence_item("network_path", ingress.network_path),
                *ingress.evidence,
                evidence_item(
                    "task_definitions",
                    [f"address={address}" for address in task_definition_addresses],
                ),
                evidence_item("task_roles", _task_role_evidence(paths)),
                evidence_item(
                    "secret_management_paths",
                    _management_path_evidence(paths),
                ),
                evidence_item(
                    "assessment_scope",
                    _assessment_scope(operations, management_effect),
                ),
            ]
            if management_effect == "disruption":
                evidence.append(evidence_item("recovery_window", recovery_evidence))

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
                        len(secret_addresses),
                        management_effect,
                        recovery_evidence,
                    ),
                    evidence=collect_evidence(*evidence),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _is_deterministic_management_path(
    path: AwsEcsSecretsManagerManagementPath,
    service: NormalizedResource,
    context: RuleEvaluationContext,
    management_effect: AwsSecretsManagerManagementEffect,
) -> bool:
    operation = path.get("operation")
    definition = _MANAGEMENT_PATH_DEFINITIONS.get(operation)
    if definition is None or definition[1] != management_effect:
        return False

    secret_address = path.get("secret_address")
    secret = context.inventory.get_by_address(secret_address) if isinstance(secret_address, str) else None
    if secret is None or secret.resource_type != _AWS_SECRETS_MANAGER_SECRET:
        return False
    secret_facts = aws_facts(secret)
    secret_arn = secret.arn
    role_address = path.get("role_address")
    role = context.inventory.get_by_address(role_address) if isinstance(role_address, str) else None
    task_definition_address = path.get("task_definition_address")
    task_definition = (
        context.inventory.get_by_address(task_definition_address) if isinstance(task_definition_address, str) else None
    )
    authorization = path.get("authorization_record")
    authorization_bases = path.get("authorization_bases")
    if role is None or task_definition is None:
        return False

    service_facts = aws_facts(service)
    task_facts = aws_facts(task_definition)
    if (
        task_definition.address not in service_facts.resolved_task_definition_addresses
        or task_facts.task_role_arn != role.arn
    ):
        return False

    if (
        role.resource_type != _AWS_IAM_ROLE
        or task_definition.resource_type != _AWS_ECS_TASK_DEFINITION
        or not _is_exact_secret_arn(secret_arn)
        or path.get("secret_arn") != secret_arn
        or path.get("secret_resource_type") != secret.resource_type
        or path.get("secret_name") != secret_facts.name
        or path.get("workload_type") != _AWS_ECS_SERVICE
        or path.get("workload_address") != service.address
        or path.get("role_kind") != "ecs_task_role"
        or path.get("credential_context") != "workload_runtime"
        or not _is_exact_iam_role_arn(role.arn)
        or path.get("role_arn") != role.arn
        or path.get("role_policy_complete") is not True
        or path.get("authorization_state") != "allowed"
        or path.get("explicit_deny") is not False
        or path.get("authorization_requires_condition_evaluation") is not False
        or not isinstance(authorization_bases, list)
        or not authorization_bases
        or not all(isinstance(value, str) and value in _AUTHORIZATION_BASES for value in authorization_bases)
        or not isinstance(authorization, Mapping)
    ):
        return False

    if path.get("task_definition_arn") is not None and path.get("task_definition_arn") != task_definition.arn:
        return False
    if (
        path.get("terraform_recovery_window_in_days") != secret_facts.secrets_manager_recovery_window_in_days
        or path.get("recovery_window_evidence_scope") != "terraform_resource_deletion_only"
        or path.get("operation_class") != definition[0]
        or path.get("management_effect") != definition[1]
    ):
        return False

    return _authorization_record_is_current(
        authorization,
        path,
        secret,
        role,
        authorization_bases,
    )


def _authorization_record_is_current(
    authorization: Mapping[str, object],
    path: AwsEcsSecretsManagerManagementPath,
    secret: NormalizedResource,
    role: NormalizedResource,
    authorization_bases: Sequence[object],
) -> bool:
    if not any(
        dict(current_authorization) == dict(authorization)
        for current_authorization in aws_facts(secret).secrets_manager_operation_authorizations
    ):
        return False

    return (
        authorization.get("secret_address") == secret.address
        and authorization.get("secret_resource_type") == secret.resource_type
        and authorization.get("secret_arn") == secret.arn
        and authorization.get("principal_address") == role.address
        and authorization.get("principal_arn") == role.arn
        and authorization.get("principal_kind") == "iam_role"
        and authorization.get("operation") == path.get("operation")
        and authorization.get("operation_class") == path.get("operation_class")
        and authorization.get("management_effect") == path.get("management_effect")
        and authorization.get("authorization_state") == "allowed"
        and authorization.get("authorization_bases") == authorization_bases
        and authorization.get("identity_policy_complete") is True
        and authorization.get("resource_policy_complete") is True
        and authorization.get("explicit_deny") is False
        and authorization.get("authorization_requires_condition_evaluation") is False
    )


def _management_operations(
    paths: Sequence[AwsEcsSecretsManagerManagementPath],
) -> list[str]:
    return [
        operation
        for operation in _MANAGEMENT_OPERATION_ORDER
        if any(path.get("operation") == operation for path in paths)
    ]


def _task_role_evidence(
    paths: Sequence[AwsEcsSecretsManagerManagementPath],
) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"address={path['role_address']}",
                    f"arn={path['role_arn']}",
                    "role_kind=ecs_task_role",
                    "credential_context=workload_runtime",
                    f"policy_complete={str(path['role_policy_complete']).lower()}",
                )
            )
            for path in paths
        }
    )


def _management_path_evidence(
    paths: Sequence[AwsEcsSecretsManagerManagementPath],
) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"secret_address={path['secret_address']}",
                    f"secret_arn={path['secret_arn']}",
                    f"operation={path['operation']}",
                    f"operation_class={path['operation_class']}",
                    f"management_effect={path['management_effect']}",
                    f"task_definition={path['task_definition_address']}",
                    f"task_role={path['role_address']}",
                    f"authorization_state={path['authorization_state']}",
                    f"authorization_bases={','.join(path['authorization_bases'])}",
                    f"candidate_authorization_bases={','.join(path['candidate_authorization_bases']) or 'none'}",
                    f"identity_policy_sources={','.join(path['identity_policy_source_addresses']) or 'none'}",
                    "resource_policy_sources="
                    f"{','.join(path['secrets_manager_resource_policy_source_addresses']) or 'none'}",
                    f"conditional_policy_evidence_present={str(path['conditional_policy_evidence_present']).lower()}",
                    "authorization_requires_condition_evaluation="
                    f"{str(path['authorization_requires_condition_evaluation']).lower()}",
                    "operation_evaluation=deterministic_allowed",
                )
            )
            for path in paths
        }
    )


def _recovery_window_evidence(
    paths: Sequence[AwsEcsSecretsManagerManagementPath],
) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"secret_address={path['secret_address']}",
                    f"operation={path['operation']}",
                    "recovery_window_state=terraform_resource_deletion_only",
                    "terraform_recovery_window_is_not_runtime_recovery=true",
                    "terraform_recovery_window_in_days="
                    f"{path['terraform_recovery_window_in_days'] if path['terraform_recovery_window_in_days'] is not None else 'unknown'}",
                )
            )
            for path in paths
            if path["operation"] == "secretsmanager:DeleteSecret"
        }
    )


def _assessment_scope(
    operations: Sequence[str],
    management_effect: AwsSecretsManagerManagementEffect,
) -> list[str]:
    effect_text = "secret tampering" if management_effect == "tampering" else "secret disruption"
    return [
        (
            f"establishes=deterministic {_operation_text(operations)} authority "
            f"for ECS task roles with {effect_text} effect on exact modeled "
            "Secrets Manager secrets"
        ),
        (
            "does_not_establish=successful operation completion, authority over "
            "secrets outside the modeled plan, secret publicity, or plaintext "
            "disclosure"
        ),
    ]


def _rationale(
    service: NormalizedResource,
    operations: Sequence[str],
    secret_count: int,
    management_effect: AwsSecretsManagerManagementEffect,
    recovery_evidence: Sequence[str],
) -> str:
    operation_text = _operation_text(operations)
    if management_effect == "tampering":
        capability = "could replace secret values or alter version staging labels"
        consequence = "creating secret-integrity and credential-tampering potential"
        recovery = ""
    else:
        capability = "could delete Secrets Manager secrets"
        consequence = "interrupting credential delivery and secret availability"
        recovery = (
            " Terraform deletion-window evidence is preserved separately; it does not establish runtime "
            "recovery or restoration authority."
            if recovery_evidence
            else " Runtime recovery evidence is unavailable or unresolved."
        )
    return (
        f"{service.display_name} is reachable through an internet-facing load balancer and its ECS task role "
        f"has deterministic Secrets Manager {management_effect} authority ({operation_text}) on {secret_count} "
        f"exact modeled secret(s). A compromise of the public workload {capability}, {consequence}. This "
        "establishes provider-modeled secret-management authority, not proof that the secret is public, that the "
        "operation will succeed outside the modeled policy evidence, or that the workload can read plaintext."
        f"{recovery}"
    )


def _operation_text(operations: Sequence[str]) -> str:
    if len(operations) == 1:
        return operations[0]
    if len(operations) == 2:
        return f"{operations[0]} and {operations[1]}"
    return ", ".join(operations[:-1]) + f", and {operations[-1]}"


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
