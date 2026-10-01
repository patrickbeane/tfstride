from __future__ import annotations

from typing import Literal

from tfstride.models import IAMPolicyStatement, NormalizedResource
from tfstride.providers.aws.protected_data_evidence import (
    AwsEcsS3AccessPath,
    AwsS3PolicyStatementEvidence,
    AwsS3ResourceScope,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.aws.s3_bucket_policies import S3BucketPolicySources, prepare_s3_bucket_policy_sources
from tfstride.providers.aws.s3_identity_authorization import (
    S3IdentityAuthorization,
    assess_s3_identity_policy,
    evaluate_s3_identity_authorization,
    s3_access_classes,
)
from tfstride.providers.aws.s3_object_scopes import is_exact_s3_bucket_arn, s3_resource_for_bucket
from tfstride.providers.coercion import dedupe

_ECS_TASK_DEFINITION = "aws_ecs_task_definition"
_ECS_SERVICE = "aws_ecs_service"


class ModelEcsS3AccessPathsStage:
    name = "model_ecs_s3_access_paths"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        bucket_policies = prepare_s3_bucket_policy_sources(resources, context)
        for task_definition in resources:
            if task_definition.resource_type != _ECS_TASK_DEFINITION:
                continue
            paths, uncertainties = _ecs_s3_access_paths(task_definition, context, bucket_policies)
            facts = aws_facts(task_definition)
            facts.set_ecs_s3_access_paths(paths)
            facts.extend_ecs_s3_access_path_uncertainties(uncertainties)


class ProjectEcsS3AccessPathsOntoServicesStage:
    name = "project_ecs_s3_access_paths_onto_services"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        for service in resources:
            if service.resource_type != _ECS_SERVICE:
                continue

            facts = aws_facts(service)
            paths: list[AwsEcsS3AccessPath] = []
            uncertainties = [
                f"{service.address}: task definition reference {reference} is unresolved for S3 access-path projection"
                for reference in facts.unresolved_task_definition_references
            ]
            for task_definition_address in facts.resolved_task_definition_addresses:
                task_definition = context.index.ecs_task_definitions.get(task_definition_address, source=service)
                if task_definition is None:
                    uncertainties.append(
                        f"{service.address}: resolved task definition {task_definition_address} is unavailable "
                        "for S3 access-path projection"
                    )
                    continue
                task_facts = aws_facts(task_definition)
                uncertainties.extend(task_facts.ecs_s3_access_path_uncertainties)
                paths.extend(
                    _service_access_path(service, task_definition, path) for path in task_facts.ecs_s3_access_paths
                )

            facts.set_ecs_s3_access_paths(paths)
            facts.extend_ecs_s3_access_path_uncertainties(dedupe(uncertainties))


def _service_access_path(
    service: NormalizedResource,
    task_definition: NormalizedResource,
    path: AwsEcsS3AccessPath,
) -> AwsEcsS3AccessPath:
    return {
        **path,
        "workload_address": service.address,
        "workload_type": service.resource_type,
        "task_definition_address": task_definition.address,
        "task_definition_arn": task_definition.arn,
        "internet_facing_load_balancers": aws_facts(service).internet_facing_load_balancer_addresses,
    }


def _ecs_s3_access_paths(
    task_definition: NormalizedResource,
    context: AwsDecorationContext,
    bucket_policies: dict[str, S3BucketPolicySources],
) -> tuple[list[AwsEcsS3AccessPath], list[str]]:
    task_facts = aws_facts(task_definition)
    task_role_reference = task_facts.task_role_arn
    if not task_role_reference:
        return [], []

    task_role = context.index.role_index.get(task_role_reference, source=task_definition)
    if task_role is None:
        return (
            [],
            [f"{task_definition.address}: ECS task role {task_role_reference} is not modeled in the plan"],
        )

    identity_policy = assess_s3_identity_policy(task_role)
    uncertainties = [f"{task_definition.address}: {reason}" for reason in identity_policy.uncertainties]
    target_buckets, target_uncertainties = _target_buckets(task_role, context)
    uncertainties.extend(f"{task_definition.address}: {message}" for message in target_uncertainties)

    paths: list[AwsEcsS3AccessPath] = []
    for bucket in target_buckets:
        if not is_exact_s3_bucket_arn(bucket.arn):
            uncertainties.append(
                f"{task_definition.address}: S3 bucket {bucket.address} has no resolved ARN for IAM scope matching"
            )
            continue
        authorization = evaluate_s3_identity_authorization(
            identity_policy,
            bucket,
            bucket_policies[bucket.address],
            account_relationship=context.index.account_identities.relationship(task_role, bucket),
        )
        if authorization is None:
            continue
        uncertainties.extend(f"{task_definition.address}: {reason}" for reason in authorization.uncertainties)
        paths.append(_access_path_record(task_definition, bucket, task_role, authorization))

    return paths, dedupe(uncertainties)


def _target_buckets(
    role: NormalizedResource,
    context: AwsDecorationContext,
) -> tuple[list[NormalizedResource], list[str]]:
    buckets: dict[str, NormalizedResource] = {}
    uncertainties: list[str] = []
    for statement in role.policy_statements:
        if not _has_s3_action_pattern(statement):
            continue
        for resource in statement.resources:
            bucket_arn = _exact_bucket_arn(resource)
            if bucket_arn is None:
                # Broad denies constrain already resolved targets; they do not discover new grants.
                if statement.effect.strip().lower() == "deny" and _has_wildcard(resource):
                    continue
                if statement.effect.strip().lower() == "allow":
                    for candidate in context.index.buckets.resources:
                        arn = candidate.arn
                        if not is_exact_s3_bucket_arn(arn):
                            continue
                        assert arn is not None
                        if not any(
                            s3_resource_for_bucket(resource, arn, kind) for kind in ("bucket_level", "object_level")
                        ):
                            continue
                        if context.index.buckets.get(arn) is None:
                            uncertainties.append(f"{role.address} S3 policy target {arn} is ambiguous in the plan")
                            continue
                        buckets[candidate.address] = candidate
                if not _has_wildcard(resource) or "${" in resource:
                    uncertainties.append(
                        f"{role.address} S3 policy resource {resource!r} does not identify a modeled bucket scope"
                    )
                continue
            bucket = context.index.buckets.get(bucket_arn, source=role)
            if bucket is None:
                uncertainties.append(f"{role.address} S3 policy targets {bucket_arn}, which is not modeled in the plan")
                continue
            buckets[bucket.address] = bucket
    return sorted(buckets.values(), key=lambda bucket: bucket.address), dedupe(uncertainties)


def _has_s3_action_pattern(statement: IAMPolicyStatement) -> bool:
    return any(pattern == "*" or pattern.lower().startswith("s3:") for pattern in statement.actions)


def _exact_bucket_arn(resource: str) -> str | None:
    if not isinstance(resource, str):
        return None
    marker = ":s3:::"
    marker_index = resource.find(marker)
    if not resource.startswith("arn:") or marker_index < 0:
        return None
    arn_prefix = resource[: marker_index + len(marker)]
    bucket_name = resource[marker_index + len(marker) :].split("/", 1)[0]
    if not bucket_name or _has_wildcard(bucket_name):
        return None
    return arn_prefix + bucket_name


def _access_path_record(
    task_definition: NormalizedResource,
    bucket: NormalizedResource,
    task_role: NormalizedResource,
    authorization: S3IdentityAuthorization,
) -> AwsEcsS3AccessPath:
    statement_records = authorization.statement_records
    assessment = authorization.assessment
    bucket_constraints = authorization.bucket_constraints
    allow_records = [record for record in statement_records if record["effect"] == "allow"]
    deny_records: list[AwsS3PolicyStatementEvidence] = [
        *[record for record in statement_records if record["effect"] == "deny"],
        *bucket_constraints.records,
    ]
    bucket_arn = bucket.arn
    assert bucket_arn is not None
    return {
        "workload_address": task_definition.address,
        "workload_type": task_definition.resource_type,
        "bucket_address": bucket.address,
        "bucket_name": aws_facts(bucket).bucket_name or bucket.name,
        "bucket_arn": bucket_arn,
        "role_kind": "ecs_task_role",
        "credential_context": "workload_runtime",
        "role_address": task_role.address,
        "role_arn": task_role.arn or aws_facts(task_definition).task_role_arn,
        "role_policy_complete": authorization.identity_policy.complete,
        "role_account_id": authorization.account_relationship.source.account_id,
        "bucket_account_id": authorization.account_relationship.target.account_id,
        "same_account": authorization.account_relationship.same_account,
        "evaluation_basis": "modeled_identity_policy_with_bucket_policy_constraints",
        "modeled_access_state": authorization.modeled_access_state,
        "access_state": authorization.access_state,
        "access_classes": s3_access_classes(assessment["allowed_actions"]),
        "denied_access_classes": s3_access_classes(assessment["denied_actions"]),
        "unknown_access_classes": s3_access_classes(assessment["unknown_actions"]),
        "matched_actions": assessment["allowed_actions"],
        "denied_actions": assessment["denied_actions"],
        "unknown_actions": assessment["unknown_actions"],
        "explicit_deny": bool(deny_records),
        "conditional_evaluation_required": bool(assessment["conditional_actions"]),
        "policy_action_patterns": _statement_values(allow_records, "matching_action_patterns"),
        "policy_resources": _statement_values(allow_records, "matching_resources"),
        "deny_action_patterns": _statement_values(deny_records, "matching_action_patterns"),
        "deny_policy_resources": _statement_values(deny_records, "matching_resources"),
        "resource_scopes": _statement_resource_scopes(allow_records),
        "policy_statements": statement_records,
        "scope_evaluations": assessment["scope_evaluations"],
        "bucket_policy_constraints_complete": bucket_constraints.complete,
        "bucket_policy_source_addresses": list(bucket_constraints.source_addresses),
        "bucket_policy_statements": [*bucket_constraints.records, *bucket_constraints.allow_records],
        "bucket_policy_uncertainties": list(bucket_constraints.uncertainties),
    }


def _statement_values(
    statements: list[AwsS3PolicyStatementEvidence],
    key: Literal["matching_action_patterns", "matching_resources"],
) -> list[str]:
    values = {
        value
        for statement in statements
        for value in (
            statement["matching_action_patterns"]
            if key == "matching_action_patterns"
            else statement["matching_resources"]
        )
    }
    return sorted(values, key=str.lower)


def _statement_resource_scopes(
    statements: list[AwsS3PolicyStatementEvidence],
) -> list[AwsS3ResourceScope]:
    return sorted({scope for statement in statements for scope in statement["resource_scopes"]})


def _has_wildcard(value: str) -> bool:
    return "*" in value or "?" in value
