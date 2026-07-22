from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any, Literal

from tfstride.models import IAMPolicyCondition, IAMPolicyStatement, NormalizedResource
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.coercion import dedupe

_ECS_TASK_DEFINITION = "aws_ecs_task_definition"
_ECS_SERVICE = "aws_ecs_service"
_ACCESS_CLASS_ORDER = ("read", "write", "delete", "administrative")


@dataclass(frozen=True, slots=True)
class _S3Action:
    name: str
    access_class: str
    resource_kind: Literal["bucket_level", "object_level"]


_S3_ACTIONS = (
    _S3Action("s3:GetBucketLocation", "read", "bucket_level"),
    _S3Action("s3:ListBucket", "read", "bucket_level"),
    _S3Action("s3:ListBucketMultipartUploads", "read", "bucket_level"),
    _S3Action("s3:ListBucketVersions", "read", "bucket_level"),
    _S3Action("s3:GetBucketObjectLockConfiguration", "read", "bucket_level"),
    _S3Action("s3:GetObject", "read", "object_level"),
    _S3Action("s3:GetObjectAcl", "read", "object_level"),
    _S3Action("s3:GetObjectAttributes", "read", "object_level"),
    _S3Action("s3:GetObjectLegalHold", "read", "object_level"),
    _S3Action("s3:GetObjectRetention", "read", "object_level"),
    _S3Action("s3:GetObjectTagging", "read", "object_level"),
    _S3Action("s3:GetObjectVersion", "read", "object_level"),
    _S3Action("s3:GetObjectVersionAcl", "read", "object_level"),
    _S3Action("s3:GetObjectVersionAttributes", "read", "object_level"),
    _S3Action("s3:GetObjectVersionTagging", "read", "object_level"),
    _S3Action("s3:ListMultipartUploadParts", "read", "object_level"),
    _S3Action("s3:AbortMultipartUpload", "write", "object_level"),
    _S3Action("s3:PutObject", "write", "object_level"),
    _S3Action("s3:PutObjectTagging", "write", "object_level"),
    _S3Action("s3:PutObjectVersionTagging", "write", "object_level"),
    _S3Action("s3:RestoreObject", "write", "object_level"),
    _S3Action("s3:DeleteObject", "delete", "object_level"),
    _S3Action("s3:DeleteObjectTagging", "delete", "object_level"),
    _S3Action("s3:DeleteObjectVersion", "delete", "object_level"),
    _S3Action("s3:DeleteObjectVersionTagging", "delete", "object_level"),
    _S3Action("s3:CreateBucket", "administrative", "bucket_level"),
    _S3Action("s3:DeleteBucket", "administrative", "bucket_level"),
    _S3Action("s3:DeleteBucketPolicy", "administrative", "bucket_level"),
    _S3Action("s3:PutBucketAcl", "administrative", "bucket_level"),
    _S3Action("s3:PutBucketCORS", "administrative", "bucket_level"),
    _S3Action("s3:PutBucketLogging", "administrative", "bucket_level"),
    _S3Action("s3:PutBucketNotification", "administrative", "bucket_level"),
    _S3Action("s3:PutBucketObjectLockConfiguration", "administrative", "bucket_level"),
    _S3Action("s3:PutBucketOwnershipControls", "administrative", "bucket_level"),
    _S3Action("s3:PutBucketPolicy", "administrative", "bucket_level"),
    _S3Action("s3:PutBucketPublicAccessBlock", "administrative", "bucket_level"),
    _S3Action("s3:PutBucketTagging", "administrative", "bucket_level"),
    _S3Action("s3:PutBucketVersioning", "administrative", "bucket_level"),
    _S3Action("s3:PutEncryptionConfiguration", "administrative", "bucket_level"),
    _S3Action("s3:PutLifecycleConfiguration", "administrative", "bucket_level"),
    _S3Action("s3:PutReplicationConfiguration", "administrative", "bucket_level"),
    _S3Action("s3:BypassGovernanceRetention", "administrative", "object_level"),
    _S3Action("s3:PutObjectAcl", "administrative", "object_level"),
    _S3Action("s3:PutObjectLegalHold", "administrative", "object_level"),
    _S3Action("s3:PutObjectRetention", "administrative", "object_level"),
    _S3Action("s3:PutObjectVersionAcl", "administrative", "object_level"),
)
_ACTION_BY_NAME = {action.name: action for action in _S3_ACTIONS}


class ModelEcsS3AccessPathsStage:
    name = "model_ecs_s3_access_paths"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        for task_definition in resources:
            if task_definition.resource_type != _ECS_TASK_DEFINITION:
                continue
            paths, uncertainties = _ecs_s3_access_paths(task_definition, context)
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
            paths: list[dict[str, Any]] = []
            uncertainties = [
                f"{service.address}: task definition reference {reference} is unresolved for S3 access-path projection"
                for reference in facts.unresolved_task_definition_references
            ]
            for task_definition_address in facts.resolved_task_definition_addresses:
                task_definition = context.index.ecs_task_definitions.get(task_definition_address)
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


def _ecs_s3_access_paths(
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
    target_buckets, target_uncertainties = _target_buckets(task_role, context)
    uncertainties.extend(f"{task_definition.address}: {message}" for message in target_uncertainties)

    paths: list[dict[str, Any]] = []
    for bucket in target_buckets:
        if not bucket.arn:
            uncertainties.append(
                f"{task_definition.address}: S3 bucket {bucket.address} has no resolved ARN for IAM scope matching"
            )
            continue
        statement_records = _matching_statement_records(task_role.policy_statements, bucket.arn)
        if not statement_records:
            continue
        assessment = _assess_actions(statement_records)
        if assessment["conditional_actions"]:
            uncertainties.append(
                f"{task_definition.address}: {task_role.address} targeting {bucket.address} has conditional "
                "identity-policy evidence for actions: " + ", ".join(assessment["conditional_actions"])
            )
        paths.append(
            _access_path_record(
                task_definition,
                bucket,
                task_role,
                statement_records,
                assessment,
                role_policy_complete=not role_facts.unresolved_attached_policy_arns,
            )
        )

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
                uncertainties.append(
                    f"{role.address} S3 policy resource {resource!r} does not identify an exact bucket"
                )
                continue
            bucket = context.index.buckets.get(bucket_arn)
            if bucket is None:
                uncertainties.append(f"{role.address} S3 policy targets {bucket_arn}, which is not modeled in the plan")
                continue
            buckets[bucket.address] = bucket
    return list(buckets.values()), dedupe(uncertainties)


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


def _matching_statement_records(
    statements: tuple[IAMPolicyStatement, ...],
    bucket_arn: str,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for statement in statements:
        effect = statement.effect.strip().lower()
        if effect not in {"allow", "deny"}:
            continue

        matched_actions: list[str] = []
        matching_patterns: set[str] = set()
        matching_resources: set[str] = set()
        for action in _S3_ACTIONS:
            action_patterns = _matching_action_patterns(statement, action.name)
            resources = _matching_resources(statement, bucket_arn, action.resource_kind)
            if not action_patterns or not resources:
                continue
            matched_actions.append(action.name)
            matching_patterns.update(action_patterns)
            matching_resources.update(resources)

        if not matched_actions:
            continue
        records.append(
            {
                "effect": effect,
                "actions": list(statement.actions),
                "matched_actions": matched_actions,
                "matching_action_patterns": sorted(matching_patterns, key=str.lower),
                "resources": list(statement.resources),
                "matching_resources": sorted(matching_resources),
                "resource_scopes": _resource_scopes(matching_resources, bucket_arn),
                "access_classes": _access_classes(matched_actions),
                "conditions": [_condition_record(condition) for condition in statement.conditions],
                "conditional": bool(statement.conditions),
            }
        )
    return records


def _matching_action_patterns(statement: IAMPolicyStatement, action: str) -> set[str]:
    return {pattern for pattern in statement.actions if fnmatchcase(action.lower(), pattern.lower())}


def _matching_resources(
    statement: IAMPolicyStatement,
    bucket_arn: str,
    resource_kind: Literal["bucket_level", "object_level"],
) -> set[str]:
    if resource_kind == "bucket_level":
        return {resource for resource in statement.resources if resource == bucket_arn}
    prefix = bucket_arn + "/"
    return {resource for resource in statement.resources if resource.startswith(prefix)}


def _condition_record(condition: IAMPolicyCondition) -> dict[str, Any]:
    return {
        "operator": condition.operator,
        "key": condition.key,
        "values": list(condition.values),
    }


def _assess_actions(records: list[dict[str, Any]]) -> dict[str, list[str]]:
    allowed: list[str] = []
    denied: list[str] = []
    unknown: list[str] = []
    conditional: list[str] = []
    for action in _S3_ACTIONS:
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
    bucket: NormalizedResource,
    task_role: NormalizedResource,
    statement_records: list[dict[str, Any]],
    assessment: dict[str, list[str]],
    *,
    role_policy_complete: bool,
) -> dict[str, Any]:
    allow_records = [record for record in statement_records if record["effect"] == "allow"]
    deny_records = [record for record in statement_records if record["effect"] == "deny"]
    modeled_access_state = _modeled_access_state(assessment)
    access_state = modeled_access_state if role_policy_complete else "unknown"
    return {
        "workload_address": task_definition.address,
        "workload_type": task_definition.resource_type,
        "bucket_address": bucket.address,
        "bucket_name": aws_facts(bucket).bucket_name or bucket.name,
        "bucket_arn": bucket.arn,
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


def _access_classes(actions: list[str]) -> list[str]:
    classes = {_ACTION_BY_NAME[action].access_class for action in actions}
    return [access_class for access_class in _ACCESS_CLASS_ORDER if access_class in classes]


def _statement_values(statements: list[dict[str, Any]], key: str) -> list[str]:
    return sorted(
        {value for statement in statements for value in statement[key] if isinstance(value, str)},
        key=str.lower,
    )


def _resource_scopes(resources: set[str], bucket_arn: str) -> list[str]:
    scopes = {_resource_scope(resource, bucket_arn) for resource in resources}
    order = ("exact_bucket", "all_bucket_objects", "object_prefix", "exact_object")
    return [scope for scope in order if scope in scopes]


def _resource_scope(resource: str, bucket_arn: str) -> str:
    if resource == bucket_arn:
        return "exact_bucket"
    object_path = resource[len(bucket_arn) + 1 :]
    if object_path == "*":
        return "all_bucket_objects"
    if _has_wildcard(object_path):
        return "object_prefix"
    return "exact_object"


def _has_wildcard(value: str) -> bool:
    return "*" in value or "?" in value
