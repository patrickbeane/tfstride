from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Literal, TypedDict

from tfstride.models import IAMPolicyCondition, IAMPolicyStatement, NormalizedResource
from tfstride.providers.aws.account_identity import describe_account_relationship
from tfstride.providers.aws.account_identity_evidence import AwsAccountRelationship
from tfstride.providers.aws.iam_permissions_boundaries import permissions_boundary_uncertainties
from tfstride.providers.aws.protected_data_evidence import (
    AwsS3AccessClass,
    AwsS3AccessState,
    AwsS3BucketPolicyStatementEvidence,
    AwsS3PolicyConditionEvidence,
    AwsS3PolicyStatementEvidence,
    AwsS3ResourceScope,
    AwsS3ScopeEvaluation,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.s3_bucket_policies import (
    S3BucketPolicySources,
    s3_bucket_principal_match,
)
from tfstride.providers.aws.s3_object_scopes import (
    is_exact_s3_bucket_arn,
    object_scope_contains,
    object_scope_from_resource,
    object_scope_intersection,
    object_scopes_overlap,
    s3_resource_for_bucket,
)
from tfstride.providers.coercion import dedupe

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
    allow_records: tuple[AwsS3BucketPolicyStatementEvidence, ...] = ()


@dataclass(frozen=True, slots=True)
class S3IdentityPolicyAssessment:
    role: NormalizedResource
    complete: bool
    permissions_boundary_compatible: bool
    uncertainties: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class S3IdentityAuthorization:
    """Identity-backed authority scoped to one modeled bucket and its owner.

    Scope evaluations retain operation/resource pairs and cross-account grant
    intersections. Only access_state includes completeness, ownership, and
    permissions-boundary gates. Resource-policy-only access is not synthesized.
    """

    bucket_address: str
    bucket_arn: str
    identity_policy: S3IdentityPolicyAssessment
    account_relationship: AwsAccountRelationship
    statement_records: list[AwsS3PolicyStatementEvidence]
    assessment: _S3AccessAssessment
    bucket_constraints: _BucketPolicyConstraints
    modeled_access_state: AwsS3AccessState
    access_state: AwsS3AccessState
    uncertainties: tuple[str, ...]


def modeled_s3_actions(patterns: Sequence[str]) -> tuple[tuple[str, Literal["bucket_level", "object_level"]], ...]:
    """Expand only the operations already modeled by the authority evaluator."""
    return tuple(
        (action.name, action.resource_kind)
        for action in _S3_ACTIONS
        if any(fnmatchcase(action.name.lower(), pattern.lower()) for pattern in patterns)
    )


def assess_s3_identity_policy(role: NormalizedResource) -> S3IdentityPolicyAssessment:
    """Keep identity completeness and boundary uncertainty together for consumers."""
    facts = aws_facts(role)
    complete = facts.iam_policy_completeness_state == "complete" and not facts.unresolved_attached_policy_arns
    uncertainties = [
        f"{role.address} has unresolved attached policy {policy_arn}"
        for policy_arn in facts.unresolved_attached_policy_arns
    ]
    if facts.iam_policy_completeness_state != "complete":
        uncertainties.extend(
            f"{role.address}: {reason}"
            for reason in (facts.iam_policy_posture_uncertainties or ["identity-policy evidence is incomplete"])
        )
    boundary_uncertainties = permissions_boundary_uncertainties(role, authority="S3")
    uncertainties.extend(boundary_uncertainties)
    return S3IdentityPolicyAssessment(role, complete, not boundary_uncertainties, tuple(uncertainties))


def evaluate_s3_identity_authorization(
    identity_policy: S3IdentityPolicyAssessment,
    bucket: NormalizedResource,
    bucket_policy_sources: S3BucketPolicySources,
    *,
    account_relationship: AwsAccountRelationship,
    scope_limits: Mapping[str, Sequence[str]] | None = None,
) -> S3IdentityAuthorization | None:
    """Evaluate P1's identity grants and applicable constraints for a resolved target.

    Target discovery and workload projection belong to the caller. No grant is
    synthesized for a bucket without matching modeled identity-policy evidence.
    """
    bucket_arn = bucket.arn
    if bucket.resource_type != "aws_s3_bucket" or not is_exact_s3_bucket_arn(bucket_arn):
        raise ValueError("S3 authorization requires a modeled bucket with a resolved ARN")
    assert bucket_arn is not None
    role = identity_policy.role
    statement_records = _matching_statement_records(role.policy_statements, bucket_arn)
    if not statement_records:
        return None
    constraints = _bucket_policy_constraints(bucket_policy_sources, bucket_arn, role)
    applicable_denies: list[AwsS3PolicyStatementEvidence] = list(constraints.records)
    assessment = _assess_actions(
        [*statement_records, *applicable_denies],
        bucket_arn,
        cross_account_allows=list(constraints.allow_records) if account_relationship.same_account is False else None,
        scope_limits=scope_limits,
    )
    uncertainties = list(constraints.uncertainties)
    for evaluation in assessment["scope_evaluations"]:
        if evaluation["reason"] == "partial_deny":
            reason = "allow scope is narrowed by an explicit deny; the residual object scope is not representable"
        elif evaluation["reason"] == "unsupported_resource_scope":
            reason = "allow or overlapping deny resource scope is not representable"
        else:
            continue
        uncertainties.append(
            f"{role.address} targeting {bucket.address} {evaluation['action']} on {evaluation['resource']}: {reason}"
        )
    if assessment["conditional_actions"]:
        policy_kind = (
            "identity- or bucket-policy"
            if any(record["conditional"] for record in [*applicable_denies, *constraints.allow_records])
            else "identity-policy"
        )
        uncertainties.append(
            f"{role.address} targeting {bucket.address} has conditional "
            f"{policy_kind} evidence for actions: " + ", ".join(assessment["conditional_actions"])
        )
    ownership_compatible = account_relationship.same_account is not None and account_relationship.partitions_match
    if not ownership_compatible:
        uncertainties.extend(describe_account_relationship(account_relationship))
        uncertainties.append(
            f"{role.address} targeting {bucket.address}: S3 ownership or partition compatibility is unresolved"
        )
    if account_relationship.same_account is False and assessment["unknown_actions"]:
        uncertainties.append(
            f"{role.address} targeting {bucket.address}: cross-account S3 access requires compatible "
            "identity and bucket-policy grants for each operation and resource scope"
        )
    modeled_access_state = _modeled_access_state(assessment)
    access_state: AwsS3AccessState = modeled_access_state if identity_policy.complete else "unknown"
    if access_state == "allowed" and not identity_policy.permissions_boundary_compatible:
        access_state = "unknown"
    if not constraints.complete or (access_state == "allowed" and not ownership_compatible):
        access_state = "unknown"
    return S3IdentityAuthorization(
        bucket_address=bucket.address,
        bucket_arn=bucket_arn,
        identity_policy=identity_policy,
        account_relationship=account_relationship,
        statement_records=statement_records,
        assessment=assessment,
        bucket_constraints=constraints,
        modeled_access_state=modeled_access_state,
        access_state=access_state,
        uncertainties=tuple(dedupe(uncertainties)),
    )


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
    allow_records: list[AwsS3BucketPolicyStatementEvidence] = []
    if complete:
        for source in sources.sources:
            for statement in source.policy_statements:
                if statement.effect.strip().lower() != "allow":
                    continue
                principal_match = s3_bucket_principal_match(statement, task_role.arn)
                if principal_match not in {"role", "account"}:
                    continue
                for match in _matching_statement_records((statement,), bucket_arn):
                    allow_records.append(
                        {
                            **match,
                            "source_address": source.address,
                            "principal_match": principal_match,
                            "target_match": "resolved",
                            "applicability_uncertain": False,
                            "principals": [
                                {"kind": principal.kind, "value": principal.value}
                                for principal in statement.principal_entries
                            ],
                        }
                    )
    return _BucketPolicyConstraints(
        tuple(records), tuple(sorted(addresses)), complete, tuple(dedupe(uncertainties)), tuple(allow_records)
    )


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
        bound_resources: set[str] = set()
        for action in _S3_ACTIONS:
            action_patterns = _matching_action_patterns(statement, action.name)
            resources = _matching_resources(statement, bucket_arn, action.resource_kind)
            if not action_patterns or not resources:
                continue
            matched_actions.append(action.name)
            matching_patterns.update(action_patterns)
            matching_resources.update(resources)
            bound_resources.update(
                bound
                for resource in resources
                if (
                    bound := _resource_for_bucket(
                        resource, bucket_arn, action.resource_kind, deny=normalized_effect == "deny"
                    )
                )
                is not None
            )

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
                "resource_scopes": s3_resource_scopes(bound_resources, bucket_arn),
                "access_classes": s3_access_classes(matched_actions),
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
        return s3_resource_for_bucket(resource, bucket_arn, resource_kind)
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
    *,
    cross_account_allows: list[AwsS3BucketPolicyStatementEvidence] | None = None,
    scope_limits: Mapping[str, Sequence[str]] | None = None,
) -> _S3AccessAssessment:
    allowed: list[str] = []
    denied: list[str] = []
    unknown: list[str] = []
    conditional: list[str] = []
    evaluations: list[AwsS3ScopeEvaluation] = []
    for action in _S3_ACTIONS:
        if scope_limits is not None and action.name not in scope_limits:
            continue
        matching = [record for record in records if action.name in record["matched_actions"]]
        if not matching:
            continue
        allow_scopes: dict[str, list[AwsS3PolicyStatementEvidence]] = {}
        deny_scopes: list[_DenyScope] = []
        for record in matching:
            for resource in record["matching_resources"]:
                bound = _resource_for_bucket(
                    resource, bucket_arn, action.resource_kind, deny=record["effect"] == "deny"
                )
                if bound is None:
                    continue
                if record["effect"] == "allow":
                    allow_scopes.setdefault(bound, []).append(record)
                else:
                    deny_scopes.append(
                        _DenyScope(resource, record["conditional"], record.get("applicability_uncertain", False))
                    )
        if scope_limits is not None:
            limited: dict[str, list[AwsS3PolicyStatementEvidence]] = {}
            for resource, allows in allow_scopes.items():
                for limit in scope_limits[action.name]:
                    intersection = _scope_resource_intersection(resource, limit, bucket_arn, action.resource_kind)
                    if intersection is not None:
                        limited.setdefault(intersection, []).extend(allows)
            allow_scopes = limited
        action_evaluations = _evaluate_action_scopes(
            action,
            allow_scopes,
            deny_scopes,
            bucket_arn,
            cross_account_allows,
        )
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


def _scope_resource_intersection(
    left_resource: str,
    right_resource: str,
    bucket_arn: str,
    resource_kind: Literal["bucket_level", "object_level"],
) -> str | None:
    if resource_kind == "bucket_level":
        return bucket_arn if left_resource == right_resource == bucket_arn else None
    left = object_scope_from_resource(left_resource, bucket_arn)
    right = object_scope_from_resource(right_resource, bucket_arn)
    scope = object_scope_intersection(left, right) if left is not None and right is not None else None
    return scope.resource if scope is not None else None


def _evaluate_action_scopes(
    action: _S3Action,
    allow_scopes: dict[str, list[AwsS3PolicyStatementEvidence]],
    deny_scopes: list[_DenyScope],
    bucket_arn: str,
    cross_account_allows: list[AwsS3BucketPolicyStatementEvidence] | None,
) -> list[AwsS3ScopeEvaluation]:
    if cross_account_allows is None:
        return [
            _evaluate_scope(action, resource, allows, deny_scopes, bucket_arn)
            for resource, allows in sorted(allow_scopes.items())
        ]
    intersections: dict[str, list[AwsS3PolicyStatementEvidence]] = {}
    unmatched: list[AwsS3ScopeEvaluation] = []
    for resource, allows in sorted(allow_scopes.items()):
        matched = False
        # Bucket administration remains owner-only in this model, including DeleteBucket.
        grants = cross_account_allows if action.resource_kind == "object_level" or action.access_class == "read" else []
        for grant in grants:
            if action.name not in grant["matched_actions"]:
                continue
            for raw in grant["matching_resources"]:
                bound = _resource_for_bucket(raw, bucket_arn, action.resource_kind, deny=False)
                if bound is None:
                    continue
                intersection = _scope_resource_intersection(resource, bound, bucket_arn, action.resource_kind)
                if intersection is None:
                    continue
                matched = True
                intersections.setdefault(intersection, []).extend(
                    {**allow, "conditional": allow["conditional"] or grant["conditional"]} for allow in allows
                )
        if not matched:
            evaluation = _evaluate_scope(action, resource, allows, deny_scopes, bucket_arn)
            if evaluation["modeled_access_state"] == "allowed":
                evaluation.update(modeled_access_state="unknown", reason="cross_account_not_authorized")
            unmatched.append(evaluation)
    return sorted(
        [
            *unmatched,
            *[
                _evaluate_scope(action, resource, allows, deny_scopes, bucket_arn)
                for resource, allows in sorted(intersections.items())
            ],
        ],
        key=lambda evaluation: evaluation["resource"],
    )


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


def _modeled_access_state(assessment: _S3AccessAssessment) -> AwsS3AccessState:
    if assessment["allowed_actions"]:
        return "allowed"
    if assessment["unknown_actions"]:
        return "unknown"
    if assessment["denied_actions"]:
        return "denied"
    return "not_modeled"


def s3_access_classes(actions: list[str]) -> list[AwsS3AccessClass]:
    classes = {_ACTION_BY_NAME[action].access_class for action in actions}
    return [access_class for access_class in _ACCESS_CLASS_ORDER if access_class in classes]


def s3_resource_scopes(resources: set[str], bucket_arn: str) -> list[AwsS3ResourceScope]:
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
