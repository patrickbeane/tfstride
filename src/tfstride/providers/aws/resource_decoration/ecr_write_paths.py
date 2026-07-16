from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any

from tfstride.models import IAMPolicyStatement, NormalizedResource
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.coercion import dedupe

_ECS_TASK_DEFINITION = "aws_ecs_task_definition"
_LAMBDA_FUNCTION = "aws_lambda_function"
_ECR_PUT_IMAGE = "ecr:PutImage"
_ECR_LAYER_UPLOAD_ACTIONS = frozenset(
    {
        "ecr:CompleteLayerUpload",
        "ecr:InitiateLayerUpload",
        "ecr:UploadLayerPart",
    }
)
_ECR_PUSH_ACTIONS = (
    "ecr:BatchCheckLayerAvailability",
    "ecr:CompleteLayerUpload",
    "ecr:InitiateLayerUpload",
    _ECR_PUT_IMAGE,
    "ecr:UploadLayerPart",
)
_ECR_WRITE_ACTIONS = _ECR_LAYER_UPLOAD_ACTIONS | {_ECR_PUT_IMAGE}


@dataclass(frozen=True, slots=True)
class _RoleContext:
    reference: str
    kind: str
    credential_context: str
    runtime_credentials_available: bool


@dataclass(frozen=True, slots=True)
class _WriteGrant:
    matched_actions: tuple[str, ...]
    policy_action_patterns: tuple[str, ...]
    policy_resources: tuple[str, ...]
    resource_scope: str


class ModelWorkloadEcrWritePathsStage:
    name = "model_workload_ecr_write_paths"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        for workload in resources:
            if workload.resource_type not in {_ECS_TASK_DEFINITION, _LAMBDA_FUNCTION}:
                continue
            paths, uncertainties = _workload_ecr_write_paths(workload, context)
            facts = aws_facts(workload)
            facts.set_ecr_write_paths(paths)
            facts.extend_ecr_write_path_uncertainties(uncertainties)


def _workload_ecr_write_paths(
    workload: NormalizedResource,
    context: AwsDecorationContext,
) -> tuple[list[dict[str, Any]], list[str]]:
    facts = aws_facts(workload)
    paths: list[dict[str, Any]] = []
    uncertainties: list[str] = []
    role_contexts = _workload_role_contexts(workload)

    for image_reference in facts.container_image_references:
        repository_url = image_reference.get("ecr_repository_url")
        if image_reference.get("is_resolved") is not True or not isinstance(repository_url, str):
            continue

        repository = context.index.ecr_repositories.get(repository_url)
        if repository is None:
            uncertainties.append(
                f"{workload.address}: image {image_reference.get('path') or 'reference'} targets "
                f"ECR repository {repository_url}, which is not modeled in the plan"
            )
            continue
        if not repository.arn:
            uncertainties.append(
                f"{workload.address}: ECR repository {repository.address} has no resolved ARN for IAM scope matching"
            )
            continue

        for role_context in role_contexts:
            role = context.index.role_index.get(role_context.reference)
            if role is None:
                uncertainties.append(
                    f"{workload.address}: {role_context.kind} {role_context.reference} is not modeled in the plan"
                )
                continue

            role_uncertainties = aws_facts(role).unresolved_attached_policy_arns
            uncertainties.extend(
                f"{workload.address}: {role.address} has unresolved attached policy {policy_arn}"
                for policy_arn in role_uncertainties
            )
            grant, grant_uncertainties = _deterministic_repository_write_grant(role, repository.arn)
            uncertainties.extend(
                f"{workload.address}: {role.address} targeting {repository.address}: {uncertainty}"
                for uncertainty in grant_uncertainties
            )
            if grant is None:
                continue
            paths.append(
                _write_path_record(
                    workload,
                    image_reference,
                    repository,
                    repository_url,
                    role,
                    role_context,
                    grant,
                )
            )

    return paths, dedupe(uncertainties)


def _workload_role_contexts(workload: NormalizedResource) -> tuple[_RoleContext, ...]:
    facts = aws_facts(workload)
    if workload.resource_type == _ECS_TASK_DEFINITION:
        contexts: list[_RoleContext] = []
        if facts.task_role_arn:
            contexts.append(
                _RoleContext(
                    reference=facts.task_role_arn,
                    kind="ecs_task_role",
                    credential_context="workload_runtime",
                    runtime_credentials_available=True,
                )
            )
        if facts.execution_role_arn:
            contexts.append(
                _RoleContext(
                    reference=facts.execution_role_arn,
                    kind="ecs_execution_role",
                    credential_context="ecs_agent_control_plane",
                    runtime_credentials_available=False,
                )
            )
        return tuple(contexts)

    return tuple(
        _RoleContext(
            reference=role_reference,
            kind="lambda_execution_role",
            credential_context="workload_runtime",
            runtime_credentials_available=True,
        )
        for role_reference in workload.attached_role_arns
    )


def _deterministic_repository_write_grant(
    role: NormalizedResource,
    repository_arn: str,
) -> tuple[_WriteGrant | None, list[str]]:
    allowed_actions: set[str] = set()
    denied_actions: set[str] = set()
    conditional_allowed_actions: set[str] = set()
    conditional_denied_actions: set[str] = set()
    policy_action_patterns: set[str] = set()
    policy_resources: set[str] = set()

    for statement in role.policy_statements:
        matched_actions = _matched_write_actions(statement)
        matched_resources = _matching_resources(statement, repository_arn)
        if not matched_actions or not matched_resources:
            continue

        effect = statement.effect.strip().lower()
        if effect not in {"allow", "deny"}:
            continue
        if statement.conditions:
            if effect == "allow":
                conditional_allowed_actions.update(matched_actions)
            else:
                conditional_denied_actions.update(matched_actions)
            continue
        if effect == "deny":
            denied_actions.update(matched_actions)
            continue

        allowed_actions.update(matched_actions)
        policy_action_patterns.update(_matching_action_patterns(statement, matched_actions))
        policy_resources.update(matched_resources)

    uncertainties: list[str] = []
    conditional_allow_writes = (conditional_allowed_actions - allowed_actions) & _ECR_WRITE_ACTIONS
    if conditional_allow_writes:
        uncertainties.append(
            "conditional identity-policy allow was not treated as deterministic for actions: "
            + ", ".join(sorted(conditional_allow_writes, key=str.lower))
        )
    conditional_deny_writes = (conditional_denied_actions - denied_actions) & _ECR_WRITE_ACTIONS
    if conditional_deny_writes:
        uncertainties.append(
            "conditional identity-policy deny prevents deterministic access for actions: "
            + ", ".join(sorted(conditional_deny_writes, key=str.lower))
        )

    effective_actions = allowed_actions - denied_actions - conditional_denied_actions
    if not effective_actions & _ECR_WRITE_ACTIONS:
        return None, uncertainties

    return (
        _WriteGrant(
            matched_actions=tuple(action for action in _ECR_PUSH_ACTIONS if action in effective_actions),
            policy_action_patterns=tuple(sorted(policy_action_patterns, key=str.lower)),
            policy_resources=tuple(sorted(policy_resources)),
            resource_scope=_resource_scope(policy_resources, repository_arn),
        ),
        uncertainties,
    )


def _matched_write_actions(statement: IAMPolicyStatement) -> set[str]:
    return {
        action
        for action in _ECR_PUSH_ACTIONS
        if any(fnmatchcase(action.lower(), pattern.lower()) for pattern in statement.actions)
    }


def _matching_action_patterns(statement: IAMPolicyStatement, matched_actions: set[str]) -> set[str]:
    return {
        pattern
        for pattern in statement.actions
        if any(fnmatchcase(action.lower(), pattern.lower()) for action in matched_actions)
    }


def _matching_resources(statement: IAMPolicyStatement, repository_arn: str) -> set[str]:
    return {
        resource
        for resource in statement.resources
        if isinstance(resource, str) and fnmatchcase(repository_arn, resource)
    }


def _resource_scope(resources: set[str], repository_arn: str) -> str:
    if "*" in resources:
        return "all_resources"
    if any(resource != repository_arn and _has_wildcard(resource) for resource in resources):
        return "repository_pattern"
    return "exact_repository"


def _has_wildcard(value: str) -> bool:
    return "*" in value or "?" in value


def _write_path_record(
    workload: NormalizedResource,
    image_reference: Mapping[str, Any],
    repository: NormalizedResource,
    repository_url: str,
    role: NormalizedResource,
    role_context: _RoleContext,
    grant: _WriteGrant,
) -> dict[str, Any]:
    return {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "image_reference": image_reference.get("raw"),
        "image_reference_path": image_reference.get("path"),
        "image_tag": image_reference.get("tag"),
        "image_digest": image_reference.get("digest"),
        "image_digest_pinned": image_reference.get("digest_pinned"),
        "ecr_repository_address": repository.address,
        "ecr_repository_url": repository_url,
        "ecr_repository_arn": repository.arn,
        "role_kind": role_context.kind,
        "credential_context": role_context.credential_context,
        "runtime_credentials_available": role_context.runtime_credentials_available,
        "role_address": role.address,
        "role_arn": role.arn or role_context.reference,
        "role_policy_complete": not aws_facts(role).unresolved_attached_policy_arns,
        "grant_basis": "modeled_identity_policy",
        "can_put_image": _ECR_PUT_IMAGE in grant.matched_actions,
        "can_upload_layers": bool(_ECR_LAYER_UPLOAD_ACTIONS & set(grant.matched_actions)),
        "complete_layer_upload": _ECR_LAYER_UPLOAD_ACTIONS <= set(grant.matched_actions),
        "matched_actions": list(grant.matched_actions),
        "policy_action_patterns": list(grant.policy_action_patterns),
        "policy_resources": list(grant.policy_resources),
        "resource_scope": grant.resource_scope,
    }
