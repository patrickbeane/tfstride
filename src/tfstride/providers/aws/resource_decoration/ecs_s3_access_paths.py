from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Literal, TypedDict

from tfstride.models import IAMPolicyCondition, IAMPolicyStatement, NormalizedResource
from tfstride.providers.aws.iam_permissions_boundaries import permissions_boundary_uncertainties
from tfstride.providers.aws.protected_data_evidence import (
    AwsEcsS3AccessPath,
    AwsS3AccessClass,
    AwsS3AccessState,
    AwsS3BucketPolicyStatementEvidence,
    AwsS3PolicyConditionEvidence,
    AwsS3PolicyStatementEvidence,
    AwsS3ResourceScope,
    AwsS3ScopeEvaluation,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.aws.s3_bucket_policies import (
    S3BucketPolicySources,
    prepare_s3_bucket_policy_sources,
    s3_bucket_principal_match,
)
from tfstride.providers.aws.s3_object_scopes import (
    object_scope_contains,
    object_scope_from_resource,
    object_scopes_overlap,
)
from tfstride.providers.coercion import dedupe

_ECS_TASK_DEFINITION = "aws_ecs_task_definition"
_ECS_SERVICE = "aws_ecs_service"
_ACCESS_CLASS_ORDER: tuple[AwsS3AccessClass, ...] = (
    "read",
    "write",
    "delete",
    "administrative",
)


@dataclass(frozen=True, slots=True)
class _S3Action:
    name: str
    access_class: AwsS3AccessClass
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


@dataclass(frozen=True, slots=True)
class _DenyScope:
    resource: str
    conditional: bool
    applicability_uncertain: bool


class _S3AccessAssessment(TypedDict):
    allowed_actions: list[str]
    denied_actions: list[str]
    unknown_actions: list[str]
    conditional_actions: list[str]
    scope_evaluations: list[AwsS3ScopeEvaluation]


@dataclass(frozen=True, slots=True)
class _BucketPolicyConstraints:
    records: tuple[AwsS3BucketPolicyStatementEvidence, ...]
    source_addresses: tuple[str, ...]
    complete: bool
    uncertainties: tuple[str, ...]


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

    role_facts = aws_facts(task_role)
    role_policy_complete = (
        role_facts.iam_policy_completeness_state == "complete" and not role_facts.unresolved_attached_policy_arns
    )
    uncertainties = [
        f"{task_definition.address}: {task_role.address} has unresolved attached policy {policy_arn}"
        for policy_arn in role_facts.unresolved_attached_policy_arns
    ]
    if role_facts.iam_policy_completeness_state != "complete":
        uncertainties.extend(
            f"{task_definition.address}: {task_role.address}: {reason}"
            for reason in (role_facts.iam_policy_posture_uncertainties or ["identity-policy evidence is incomplete"])
        )
    boundary_uncertainties = permissions_boundary_uncertainties(task_role, authority="S3")
    uncertainties.extend(f"{task_definition.address}: {reason}" for reason in boundary_uncertainties)
    target_buckets, target_uncertainties = _target_buckets(task_role, context)
    uncertainties.extend(f"{task_definition.address}: {message}" for message in target_uncertainties)

    paths: list[AwsEcsS3AccessPath] = []
    for bucket in target_buckets:
        if not bucket.arn:
            uncertainties.append(
                f"{task_definition.address}: S3 bucket {bucket.address} has no resolved ARN for IAM scope matching"
            )
            continue
        statement_records = _matching_statement_records(task_role.policy_statements, bucket.arn)
        if not statement_records:
            continue
        bucket_constraints = _bucket_policy_constraints(bucket_policies[bucket.address], bucket.arn, task_role)
        uncertainties.extend(f"{task_definition.address}: {reason}" for reason in bucket_constraints.uncertainties)
        applicable_denies: list[AwsS3PolicyStatementEvidence] = [record for record in bucket_constraints.records]
        assessment = _assess_actions([*statement_records, *applicable_denies], bucket.arn)
        for evaluation in assessment["scope_evaluations"]:
            if evaluation["reason"] == "partial_deny":
                reason = "allow scope is narrowed by an explicit deny; the residual object scope is not representable"
            elif evaluation["reason"] == "unsupported_resource_scope":
                reason = "allow or overlapping deny resource scope is not representable"
            else:
                continue
            uncertainties.append(
                f"{task_definition.address}: {task_role.address} targeting {bucket.address} "
                f"{evaluation['action']} on {evaluation['resource']}: {reason}"
            )
        if assessment["conditional_actions"]:
            policy_kind = (
                "identity- or bucket-policy"
                if any(record["conditional"] for record in applicable_denies)
                else "identity-policy"
            )
            uncertainties.append(
                f"{task_definition.address}: {task_role.address} targeting {bucket.address} has conditional "
                f"{policy_kind} evidence for actions: " + ", ".join(assessment["conditional_actions"])
            )
        paths.append(
            _access_path_record(
                task_definition,
                bucket,
                task_role,
                statement_records,
                assessment,
                role_policy_complete=role_policy_complete,
                permissions_boundary_compatible=not boundary_uncertainties,
                bucket_constraints=bucket_constraints,
            )
        )

    return paths, dedupe(uncertainties)


def _bucket_policy_constraints(
    sources: S3BucketPolicySources,
    bucket_arn: str,
    task_role: NormalizedResource,
) -> _BucketPolicyConstraints:
    records: list[AwsS3BucketPolicyStatementEvidence] = []
    uncertainties = list(sources.uncertainties)
    addresses = set(sources.source_addresses)
    unresolved_addresses = {source.address for source in sources.unresolved_sources}
    complete = sources.complete
    if len(sources.source_addresses) > 1:
        # A merged inline document no longer preserves individual statement provenance.
        # Conflicting authoritative policies cannot establish a deterministic constraint.
        return _BucketPolicyConstraints((), sources.source_addresses, False, sources.uncertainties)
    for source in (*sources.sources, *sources.unresolved_sources):
        unresolved_target = source.address in unresolved_addresses
        source_complete = aws_facts(source).s3_bucket_policy_completeness_state == "complete"
        if not source_complete:
            if unresolved_target:
                addresses.add(source.address)
                uncertainties.append(
                    f"{source.address}: incomplete bucket policy has an unresolved target that may affect {bucket_arn}"
                )
                uncertainties.extend(
                    f"{source.address}: {reason}" for reason in aws_facts(source).s3_bucket_policy_uncertainties
                )
                complete = False
            continue
        for statement in source.policy_statements:
            if statement.effect.strip().lower() != "deny":
                continue
            matches = _matching_statement_records((statement,), bucket_arn)
            if not matches:
                continue
            principal_match = s3_bucket_principal_match(statement, task_role.arn)
            if principal_match is None:
                continue
            if unresolved_target:
                addresses.add(source.address)
                uncertainties.extend(
                    f"{source.address}: {reason}" for reason in aws_facts(source).s3_bucket_policy_uncertainties
                )
                uncertainties.append(
                    f"{source.address}: bucket-policy deny may affect {task_role.address} on {bucket_arn}, "
                    "but its target association is unresolved"
                )
            if principal_match == "unknown":
                uncertainties.append(
                    f"{source.address}: bucket-policy deny principal applicability to {task_role.address} is unresolved"
                )
            for match in matches:
                record: AwsS3BucketPolicyStatementEvidence = {
                    **match,
                    "source_address": source.address,
                    "principal_match": principal_match,
                    "target_match": "unknown" if unresolved_target else "resolved",
                    "applicability_uncertain": unresolved_target or principal_match == "unknown",
                    "principals": [
                        {"kind": principal.kind, "value": principal.value} for principal in statement.principal_entries
                    ],
                }
                records.append(record)
    return _BucketPolicyConstraints(tuple(records), tuple(sorted(addresses)), complete, tuple(dedupe(uncertainties)))


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
                uncertainties.append(
                    f"{role.address} S3 policy resource {resource!r} does not identify an exact bucket"
                )
                continue
            bucket = context.index.buckets.get(bucket_arn, source=role)
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
) -> list[AwsS3PolicyStatementEvidence]:
    records: list[AwsS3PolicyStatementEvidence] = []
    for statement in statements:
        effect = statement.effect.strip().lower()
        if effect == "allow":
            normalized_effect: Literal["allow", "deny"] = "allow"
        elif effect == "deny":
            normalized_effect = "deny"
        else:
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
                "effect": normalized_effect,
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
    return {
        resource
        for resource in statement.resources
        if _resource_for_bucket(resource, bucket_arn, resource_kind, deny=statement.effect.strip().lower() == "deny")
        is not None
    }


def _resource_for_bucket(
    resource: str,
    bucket_arn: str,
    resource_kind: Literal["bucket_level", "object_level"],
    *,
    deny: bool,
) -> str | None:
    if resource == bucket_arn:
        return resource if resource_kind == "bucket_level" else None
    if resource.startswith(bucket_arn + "/"):
        return resource if resource_kind == "object_level" else None
    if not deny:
        return None
    if resource == "*":
        return bucket_arn if resource_kind == "bucket_level" else bucket_arn + "/*"

    # Wildcards in the bucket selector can span object-key separators too.
    # Retain potential matches as uncertainty instead of treating them as an exact namespace.
    if resource.startswith(("aws_s3_bucket.", "module.")):
        return resource
    literal_prefix = resource.split("*", 1)[0].split("?", 1)[0].split("${", 1)[0]
    if (_has_wildcard(resource) or "${" in resource) and (
        bucket_arn.startswith(literal_prefix) or literal_prefix.startswith(bucket_arn + "/")
    ):
        return resource
    return None


def _condition_record(condition: IAMPolicyCondition) -> AwsS3PolicyConditionEvidence:
    return {
        "operator": condition.operator,
        "key": condition.key,
        "values": list(condition.values),
    }


def _assess_actions(
    records: list[AwsS3PolicyStatementEvidence],
    bucket_arn: str,
) -> _S3AccessAssessment:
    allowed: list[str] = []
    denied: list[str] = []
    unknown: list[str] = []
    conditional: list[str] = []
    evaluations: list[AwsS3ScopeEvaluation] = []
    for action in _S3_ACTIONS:
        matching = [record for record in records if action.name in record["matched_actions"]]
        if not matching:
            continue
        allow_scopes: dict[str, list[AwsS3PolicyStatementEvidence]] = {}
        deny_scopes: list[_DenyScope] = []
        for record in matching:
            for resource in record["matching_resources"]:
                if (
                    _resource_for_bucket(resource, bucket_arn, action.resource_kind, deny=record["effect"] == "deny")
                    is None
                ):
                    continue
                if record["effect"] == "allow":
                    allow_scopes.setdefault(resource, []).append(record)
                else:
                    deny_scopes.append(
                        _DenyScope(resource, record["conditional"], record.get("applicability_uncertain", False))
                    )
        action_evaluations = [
            _evaluate_scope(action, resource, allows, deny_scopes, bucket_arn)
            for resource, allows in sorted(allow_scopes.items())
        ]
        evaluations.extend(action_evaluations)
        if any(evaluation["conditional_evaluation_required"] for evaluation in action_evaluations):
            conditional.append(action.name)

        # Action summaries mean that at least one complete allow scope survives.
        # Denied/uncertain namespaces remain visible in the individual evaluations.
        states = {evaluation["modeled_access_state"] for evaluation in action_evaluations}
        if "allowed" in states:
            allowed.append(action.name)
        elif "unknown" in states:
            unknown.append(action.name)
        elif "denied" in states:
            denied.append(action.name)
        elif deny_scopes:
            # Preserve deny-only evidence without turning it into an allow candidate.
            if any(not deny.conditional and not deny.applicability_uncertain for deny in deny_scopes):
                denied.append(action.name)
            else:
                unknown.append(action.name)
            if any(deny.conditional for deny in deny_scopes):
                conditional.append(action.name)
    return {
        "allowed_actions": allowed,
        "denied_actions": denied,
        "unknown_actions": unknown,
        "conditional_actions": conditional,
        "scope_evaluations": evaluations,
    }


def _evaluate_scope(
    action: _S3Action,
    resource: str,
    allows: list[AwsS3PolicyStatementEvidence],
    denies: list[_DenyScope],
    bucket_arn: str,
) -> AwsS3ScopeEvaluation:
    overlaps = [
        (deny, relationship)
        for deny in denies
        if (relationship := _deny_relationship(deny.resource, resource, bucket_arn, action.resource_kind)) != "disjoint"
    ]
    conditional_denies = sorted({deny.resource for deny, _ in overlaps if deny.conditional})
    unresolved_denies = sorted({deny.resource for deny, _ in overlaps if deny.applicability_uncertain})
    unconditional_relations = {
        relationship for deny, relationship in overlaps if not deny.conditional and not deny.applicability_uncertain
    }
    result: AwsS3ScopeEvaluation = {
        "action": action.name,
        "resource": resource,
        "modeled_access_state": "unknown",
        "reason": "conditional_allow",
        "overlapping_deny_resources": sorted({deny.resource for deny, _ in overlaps}),
        "conditional_deny_resources": conditional_denies,
        "unresolved_deny_resources": unresolved_denies,
        "conditional_evaluation_required": bool(conditional_denies) or any(record["conditional"] for record in allows),
    }
    if "covers" in unconditional_relations:
        result.update(modeled_access_state="denied", reason="explicit_deny")
    elif (
        "${" in resource
        or (action.resource_kind == "object_level" and object_scope_from_resource(resource, bucket_arn) is None)
        or any(relationship == "unknown" for _, relationship in overlaps)
    ):
        result["reason"] = "unsupported_resource_scope"
    elif "partial" in unconditional_relations:
        result["reason"] = "partial_deny"
    elif unresolved_denies:
        result["reason"] = "unresolved_deny_applicability"
    elif conditional_denies:
        result["reason"] = "conditional_deny"
    elif any(not record["conditional"] for record in allows):
        result.update(modeled_access_state="allowed", reason="unconditional_allow")
    return result


def _deny_relationship(
    deny_resource: str,
    allow_resource: str,
    bucket_arn: str,
    resource_kind: Literal["bucket_level", "object_level"],
) -> Literal["covers", "partial", "disjoint", "unknown"]:
    if deny_resource == "*":
        return "covers"
    resolved_deny = _resource_for_bucket(deny_resource, bucket_arn, resource_kind, deny=True)
    if resolved_deny is None:
        return "disjoint"
    if "${" in resolved_deny or "${" in allow_resource:
        return "unknown"
    if resolved_deny == allow_resource:
        return "covers"
    if resource_kind == "bucket_level":
        return "covers" if resolved_deny == bucket_arn else "unknown"
    if resolved_deny == bucket_arn + "/*":
        return "covers"
    deny_scope = object_scope_from_resource(resolved_deny, bucket_arn)
    allow_scope = object_scope_from_resource(allow_resource, bucket_arn)
    if deny_scope is None or allow_scope is None:
        return "unknown"
    if object_scope_contains(deny_scope, allow_scope):
        return "covers"
    return "partial" if object_scopes_overlap(deny_scope, allow_scope) else "disjoint"


def _access_path_record(
    task_definition: NormalizedResource,
    bucket: NormalizedResource,
    task_role: NormalizedResource,
    statement_records: list[AwsS3PolicyStatementEvidence],
    assessment: _S3AccessAssessment,
    *,
    role_policy_complete: bool,
    permissions_boundary_compatible: bool,
    bucket_constraints: _BucketPolicyConstraints,
) -> AwsEcsS3AccessPath:
    allow_records = [record for record in statement_records if record["effect"] == "allow"]
    deny_records: list[AwsS3PolicyStatementEvidence] = [
        *[record for record in statement_records if record["effect"] == "deny"],
        *bucket_constraints.records,
    ]
    modeled_access_state = _modeled_access_state(assessment)
    access_state: AwsS3AccessState = modeled_access_state if role_policy_complete else "unknown"
    if access_state == "allowed" and not permissions_boundary_compatible:
        access_state = "unknown"
    if not bucket_constraints.complete:
        access_state = "unknown"
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
        "role_policy_complete": role_policy_complete,
        "evaluation_basis": "modeled_identity_policy_with_bucket_policy_constraints",
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
        "resource_scopes": _statement_resource_scopes(allow_records),
        "policy_statements": statement_records,
        "scope_evaluations": assessment["scope_evaluations"],
        "bucket_policy_constraints_complete": bucket_constraints.complete,
        "bucket_policy_source_addresses": list(bucket_constraints.source_addresses),
        "bucket_policy_statements": list(bucket_constraints.records),
        "bucket_policy_uncertainties": list(bucket_constraints.uncertainties),
    }


def _modeled_access_state(assessment: _S3AccessAssessment) -> AwsS3AccessState:
    if assessment["allowed_actions"]:
        return "allowed"
    if assessment["unknown_actions"]:
        return "unknown"
    if assessment["denied_actions"]:
        return "denied"
    return "not_modeled"


def _access_classes(actions: list[str]) -> list[AwsS3AccessClass]:
    classes = {_ACTION_BY_NAME[action].access_class for action in actions}
    return [access_class for access_class in _ACCESS_CLASS_ORDER if access_class in classes]


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


def _resource_scopes(resources: set[str], bucket_arn: str) -> list[AwsS3ResourceScope]:
    scopes = {_resource_scope(resource, bucket_arn) for resource in resources}
    order = ("all_resources", "exact_bucket", "all_bucket_objects", "object_prefix", "exact_object")
    return [scope for scope in order if scope in scopes]


def _resource_scope(resource: str, bucket_arn: str) -> AwsS3ResourceScope:
    if resource == "*" or not (resource == bucket_arn or resource.startswith(bucket_arn + "/")):
        return "all_resources"
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
