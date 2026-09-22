from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Literal

from tfstride.models import IAMPolicyStatement, NormalizedResource
from tfstride.providers.aws.object_storage_deletion_evidence import (
    AwsEcsS3BucketObjectNamespaceDeletionPath,
    AwsEcsS3BucketObjectVersionNamespaceDeletionPath,
    AwsEcsS3ExactObjectDeletionPath,
    AwsEcsS3ObjectDeletionPath,
    AwsEcsS3ObjectDeletionPathCommon,
    AwsEcsS3ObjectPrefixDeletionPath,
    AwsEcsS3ObjectPrefixVersionNamespaceDeletionPath,
    AwsEcsS3ObjectVersionNamespaceDeletionPath,
    AwsS3ObjectDeletionAuthorizationBasis,
    AwsS3ObjectDeletionLifecycleCompatibilityState,
    AwsS3ObjectDeletionOperation,
    AwsS3ObjectDeletionPolicyStatementEvidence,
    AwsS3ObjectDeletionRecoveryEvidence,
)
from tfstride.providers.aws.policy_documents import policy_statement_is_fully_representable
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.aws.s3_object_scopes import (
    S3ObjectScope as _ObjectScope,
)
from tfstride.providers.aws.s3_object_scopes import (
    object_scope_contains as _scope_contains,
)
from tfstride.providers.aws.s3_object_scopes import (
    object_scope_from_resource as _scope_from_resource,
)
from tfstride.providers.aws.s3_object_scopes import (
    object_scope_intersection as _scope_intersection,
)
from tfstride.providers.aws.s3_object_scopes import (
    object_scopes_overlap as _scopes_overlap,
)
from tfstride.providers.coercion import STATE_DISABLED, dedupe
from tfstride.resource_helpers import parse_aws_account_id

_ECS_TASK_DEFINITION = "aws_ecs_task_definition"
_ECS_SERVICE = "aws_ecs_service"
_S3_BUCKET = "aws_s3_bucket"
_S3_BUCKET_POLICY = "aws_s3_bucket_policy"
_COMPLETE = "complete"
_BYPASS_GOVERNANCE_RETENTION = "s3:BypassGovernanceRetention"
_ModeledAction = AwsS3ObjectDeletionOperation | Literal["s3:BypassGovernanceRetention"]
_ScopeKind = Literal["exact", "prefix", "all"]
_PrincipalMatch = Literal["role", "account", "wildcard"]

_OPERATION_ORDER: tuple[AwsS3ObjectDeletionOperation, ...] = (
    "s3:DeleteObject",
    "s3:DeleteObjectVersion",
)
_AUTHORIZATION_BASIS_ORDER: tuple[AwsS3ObjectDeletionAuthorizationBasis, ...] = (
    "identity_policy",
    "bucket_policy_direct",
    "cross_account_identity_and_bucket_policy",
)


@dataclass(frozen=True, slots=True)
class _StatementMatch:
    statement: IAMPolicyStatement
    operation: _ModeledAction
    source_address: str
    source_kind: Literal["identity_policy", "bucket_policy"]
    effect: Literal["allow", "deny"]
    matching_action_patterns: tuple[str, ...]
    matching_resource: str
    scope: _ObjectScope
    principal_match: _PrincipalMatch | None = None

    @property
    def conditional(self) -> bool:
        return bool(self.statement.conditions)


@dataclass(frozen=True, slots=True)
class _BucketPolicyPosture:
    sources: tuple[NormalizedResource, ...]
    source_addresses: tuple[str, ...]
    complete: bool
    uncertainties: tuple[str, ...]


@dataclass(slots=True)
class _EffectiveProof:
    scope: _ObjectScope
    bases: list[AwsS3ObjectDeletionAuthorizationBasis] = field(default_factory=list)
    identity_matches: list[_StatementMatch] = field(default_factory=list)
    bucket_matches: list[_StatementMatch] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class _AuthorizationEvaluation:
    proofs: tuple[_EffectiveProof, ...]
    uncertainties: tuple[str, ...]


class ModelEcsS3ObjectDeletionPathsStage:
    """Model deterministic ECS task-role authority over exact S3 object scopes."""

    name = "model_ecs_s3_object_deletion_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AwsDecorationContext,
    ) -> None:
        buckets = tuple(resource for resource in resources if resource.resource_type == _S3_BUCKET)
        primary_account_id = _infer_primary_account_id(resources)
        unresolved_policy_sources = _unresolved_bucket_policy_sources(resources, context)

        for task_definition in resources:
            if task_definition.resource_type != _ECS_TASK_DEFINITION:
                continue
            paths, uncertainties = _task_definition_paths(
                task_definition,
                buckets,
                context,
                primary_account_id=primary_account_id,
                unresolved_policy_sources=unresolved_policy_sources,
            )
            facts = aws_facts(task_definition)
            facts.set_ecs_s3_object_deletion_paths(paths)
            facts.extend_ecs_s3_object_deletion_path_uncertainties(uncertainties)


class ProjectEcsS3ObjectDeletionPathsOntoServicesStage:
    name = "project_ecs_s3_object_deletion_paths_onto_services"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AwsDecorationContext,
    ) -> None:
        for service in resources:
            if service.resource_type != _ECS_SERVICE:
                continue

            service_facts = aws_facts(service)
            paths: list[AwsEcsS3ObjectDeletionPath] = []
            uncertainties = [
                f"{service.address}: task definition reference {reference} is unresolved "
                "for S3 object-deletion path projection"
                for reference in service_facts.unresolved_task_definition_references
            ]
            for task_definition_address in service_facts.resolved_task_definition_addresses:
                task_definition = context.index.ecs_task_definitions.get(task_definition_address, source=service)
                if task_definition is None:
                    uncertainties.append(
                        f"{service.address}: resolved task definition {task_definition_address} "
                        "is unavailable for S3 object-deletion path projection"
                    )
                    continue
                task_facts = aws_facts(task_definition)
                uncertainties.extend(task_facts.ecs_s3_object_deletion_path_uncertainties)
                paths.extend(
                    _service_path(service, task_definition, path) for path in task_facts.ecs_s3_object_deletion_paths
                )

            service_facts.set_ecs_s3_object_deletion_paths(paths)
            service_facts.extend_ecs_s3_object_deletion_path_uncertainties(dedupe(uncertainties))


def _task_definition_paths(
    task_definition: NormalizedResource,
    buckets: Sequence[NormalizedResource],
    context: AwsDecorationContext,
    *,
    primary_account_id: str | None,
    unresolved_policy_sources: tuple[str, ...],
) -> tuple[list[AwsEcsS3ObjectDeletionPath], list[str]]:
    task_facts = aws_facts(task_definition)
    task_role_reference = task_facts.task_role_arn
    if not task_role_reference:
        return (
            [],
            [
                f"{task_definition.address}: ECS task role {reference} is unresolved "
                "for S3 object-deletion path modeling"
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
                f"{task_definition.address}: ECS task role {task_role.address} has no exact IAM role ARN "
                "for S3 object-deletion path matching"
            ],
        )
    assert task_role.arn is not None

    role_policy_complete = _identity_policy_complete(task_role)
    uncertainties: list[str] = []
    if not role_policy_complete:
        role_facts = aws_facts(task_role)
        uncertainties.append(
            f"{task_definition.address}: {task_role.address} S3 object-deletion authorization "
            "is unresolved because identity-policy evidence is incomplete"
        )
        uncertainties.extend(
            f"{task_definition.address}: {task_role.address}: {uncertainty}"
            for uncertainty in role_facts.iam_policy_posture_uncertainties
        )

    paths: list[AwsEcsS3ObjectDeletionPath] = []
    role_has_deletion_action = _has_deletion_action_pattern(task_role.policy_statements)
    for bucket in buckets:
        bucket_arn = bucket.arn
        if not _is_exact_bucket_arn(bucket_arn):
            if role_has_deletion_action or _policy_may_apply_to_role_deletion(
                bucket.policy_statements,
                task_role.arn,
            ):
                uncertainties.append(
                    f"{task_definition.address}: S3 bucket {bucket.address} has no exact ARN "
                    "for object-deletion path matching"
                )
            continue
        assert bucket_arn is not None

        modeled_actions: tuple[_ModeledAction, ...] = (
            *_OPERATION_ORDER,
            _BYPASS_GOVERNANCE_RETENTION,
        )
        unresolved_sources_by_action = {
            action: tuple(
                source_address
                for source_address in unresolved_policy_sources
                if (
                    (source := context.index.resources_by_address.get(source_address)) is not None
                    and _unresolved_policy_may_affect_bucket_role_action(
                        source,
                        bucket,
                        task_role.arn,
                        action,
                        context,
                    )
                )
            )
            for action in modeled_actions
        }
        uncertainties.extend(
            f"{task_definition.address}: {source_address} has an unresolved S3 bucket-policy "
            f"target and may affect {task_role.address} {action} authorization "
            f"for {bucket.address}"
            for action in modeled_actions
            for source_address in unresolved_sources_by_action[action]
        )

        bucket_posture = _bucket_policy_posture(bucket, context)
        identity_matches, identity_scope_uncertainties = _identity_policy_matches(
            task_role,
            bucket_arn,
        )
        bucket_matches, bucket_scope_uncertainties = _bucket_policy_matches(
            bucket_posture.sources,
            bucket_arn=bucket_arn,
            role_arn=task_role.arn,
        )
        scope_uncertainties = (*identity_scope_uncertainties, *bucket_scope_uncertainties)
        deletion_evidence = any(
            match.operation in _OPERATION_ORDER for match in (*identity_matches, *bucket_matches)
        ) or any(operation in uncertainty for operation in _OPERATION_ORDER for uncertainty in scope_uncertainties)
        if not deletion_evidence:
            continue

        uncertainties.extend(f"{task_definition.address}: {message}" for message in scope_uncertainties)
        uncertainties.extend(f"{task_definition.address}: {message}" for message in bucket_posture.uncertainties)
        same_account, partitions_match = _account_relationship(
            task_role.arn,
            bucket_arn,
            primary_account_id,
        )
        bypass_evaluation = _evaluate_authorization(
            bucket,
            task_role,
            _BYPASS_GOVERNANCE_RETENTION,
            identity_matches=identity_matches,
            bucket_matches=bucket_matches,
            identity_policy_complete=role_policy_complete,
            bucket_policy_complete=(
                bucket_posture.complete and not unresolved_sources_by_action[_BYPASS_GOVERNANCE_RETENTION]
            ),
            same_account=same_account,
            partitions_match=partitions_match,
        )
        bypass_policy_unresolved = bool(unresolved_sources_by_action[_BYPASS_GOVERNANCE_RETENTION])

        for operation in _OPERATION_ORDER:
            evaluation = _evaluate_authorization(
                bucket,
                task_role,
                operation,
                identity_matches=identity_matches,
                bucket_matches=bucket_matches,
                identity_policy_complete=role_policy_complete,
                bucket_policy_complete=(bucket_posture.complete and not unresolved_sources_by_action[operation]),
                same_account=same_account,
                partitions_match=partitions_match,
            )
            uncertainties.extend(
                f"{task_definition.address}: {uncertainty}" for uncertainty in evaluation.uncertainties
            )
            for proof in evaluation.proofs:
                bypass_is_relevant = operation == "s3:DeleteObjectVersion"
                bypass_authorized = (
                    None
                    if bypass_is_relevant and bypass_policy_unresolved
                    else (
                        _bypass_authorization_for_scope(
                            proof.scope,
                            bypass_evaluation,
                        )
                        if bypass_is_relevant
                        else False
                    )
                )
                lifecycle_state, recovery_evidence = _recovery_evidence(
                    bucket,
                    operation,
                    bypass_authorized=bypass_authorized,
                    bypass_uncertain=(
                        bypass_is_relevant and (bypass_policy_unresolved or bool(bypass_evaluation.uncertainties))
                    ),
                )
                paths.append(
                    _path_record(
                        task_definition,
                        task_role,
                        bucket,
                        bucket_posture,
                        operation,
                        proof,
                        same_account=same_account is True,
                        lifecycle_state=lifecycle_state,
                        recovery_evidence=recovery_evidence,
                    )
                )

    paths.sort(key=_path_sort_key)
    return paths, dedupe(uncertainties)


def _evaluate_authorization(
    bucket: NormalizedResource,
    role: NormalizedResource,
    operation: _ModeledAction,
    *,
    identity_matches: Sequence[_StatementMatch],
    bucket_matches: Sequence[_StatementMatch],
    identity_policy_complete: bool,
    bucket_policy_complete: bool,
    same_account: bool | None,
    partitions_match: bool,
) -> _AuthorizationEvaluation:
    operation_identity_matches = [match for match in identity_matches if match.operation == operation]
    operation_bucket_matches = [match for match in bucket_matches if match.operation == operation]
    identity_allows = [match for match in operation_identity_matches if match.effect == "allow"]
    identity_denies = [match for match in operation_identity_matches if match.effect == "deny"]
    bucket_allows = [match for match in operation_bucket_matches if match.effect == "allow"]
    bucket_denies = [match for match in operation_bucket_matches if match.effect == "deny"]

    potential_allow = bool(identity_allows or bucket_allows)
    if not potential_allow:
        return _AuthorizationEvaluation((), ())
    if same_account is None:
        return _AuthorizationEvaluation(
            (),
            (
                f"{bucket.address}: {role.address} {operation} authorization is unresolved "
                "because the S3 bucket account is not exact",
            ),
        )
    if not partitions_match:
        return _AuthorizationEvaluation(
            (),
            (
                f"{bucket.address}: {role.address} {operation} authorization uses "
                "cross-partition S3 policy semantics that are not modeled",
            ),
        )

    candidates = _candidate_proofs(
        identity_allows,
        bucket_allows,
        same_account=same_account,
    )
    surviving: list[_EffectiveProof] = []
    conditional_deny_scopes: list[_ObjectScope] = []
    partially_denied_scopes: list[_ObjectScope] = []
    for candidate in candidates:
        overlapping_denies = [
            match for match in (*identity_denies, *bucket_denies) if _scopes_overlap(match.scope, candidate.scope)
        ]
        unconditional_denies = [match for match in overlapping_denies if not match.conditional]
        if any(_scope_contains(match.scope, candidate.scope) for match in unconditional_denies):
            continue
        if unconditional_denies:
            partially_denied_scopes.append(candidate.scope)
            continue
        if overlapping_denies:
            conditional_deny_scopes.append(candidate.scope)
            continue
        surviving.append(candidate)

    uncertainties: list[str] = []
    if conditional_deny_scopes:
        uncertainties.append(
            f"{bucket.address}: {role.address} {operation} has condition-dependent deny evidence "
            "for modeled object scope(s): " + ", ".join(sorted({scope.resource for scope in conditional_deny_scopes}))
        )
    if partially_denied_scopes:
        uncertainties.append(
            f"{bucket.address}: {role.address} {operation} allow scope is narrowed by a more-specific "
            "explicit deny; the residual object scope is not representable: "
            + ", ".join(sorted({scope.resource for scope in partially_denied_scopes}))
        )

    if not identity_policy_complete or not bucket_policy_complete:
        if surviving or _has_unblocked_conditional_candidate(
            identity_allows,
            bucket_allows,
            identity_denies,
            bucket_denies,
            same_account=same_account,
        ):
            incomplete_surfaces: list[str] = []
            if not identity_policy_complete:
                incomplete_surfaces.append("identity policy")
            if not bucket_policy_complete:
                incomplete_surfaces.append("bucket policy")
            uncertainties.append(
                f"{bucket.address}: {role.address} {operation} authorization is unresolved because "
                + " and ".join(incomplete_surfaces)
                + " evidence is incomplete"
            )
        return _AuthorizationEvaluation((), tuple(dedupe(uncertainties)))

    if surviving:
        return _AuthorizationEvaluation(tuple(_merge_proofs(surviving)), tuple(dedupe(uncertainties)))

    if _has_unblocked_conditional_candidate(
        identity_allows,
        bucket_allows,
        identity_denies,
        bucket_denies,
        same_account=same_account,
    ):
        uncertainties.append(
            f"{bucket.address}: {role.address} {operation} authorization depends on runtime policy conditions"
        )
    elif any(match.principal_match == "wildcard" for match in bucket_allows):
        uncertainties.append(
            f"{bucket.address}: {role.address} {operation} has wildcard-principal bucket-policy "
            "allow evidence outside the exact-principal model"
        )

    return _AuthorizationEvaluation((), tuple(dedupe(uncertainties)))


def _candidate_proofs(
    identity_allows: Sequence[_StatementMatch],
    bucket_allows: Sequence[_StatementMatch],
    *,
    same_account: bool,
) -> list[_EffectiveProof]:
    unconditional_identity = [match for match in identity_allows if not match.conditional]
    unconditional_direct_bucket = [
        match for match in bucket_allows if not match.conditional and match.principal_match == "role"
    ]
    unconditional_account_bucket = [
        match for match in bucket_allows if not match.conditional and match.principal_match == "account"
    ]
    proofs: list[_EffectiveProof] = []

    if same_account:
        proofs.extend(
            _EffectiveProof(
                scope=match.scope,
                bases=["identity_policy"],
                identity_matches=[match],
            )
            for match in unconditional_identity
        )
        proofs.extend(
            _EffectiveProof(
                scope=match.scope,
                bases=["bucket_policy_direct"],
                bucket_matches=[match],
            )
            for match in unconditional_direct_bucket
        )
        return proofs

    for identity_match in unconditional_identity:
        for bucket_match in (*unconditional_direct_bucket, *unconditional_account_bucket):
            intersection = _scope_intersection(identity_match.scope, bucket_match.scope)
            if intersection is None:
                continue
            proofs.append(
                _EffectiveProof(
                    scope=intersection,
                    bases=["cross_account_identity_and_bucket_policy"],
                    identity_matches=[identity_match],
                    bucket_matches=[bucket_match],
                )
            )
    return proofs


def _has_unblocked_conditional_candidate(
    identity_allows: Sequence[_StatementMatch],
    bucket_allows: Sequence[_StatementMatch],
    identity_denies: Sequence[_StatementMatch],
    bucket_denies: Sequence[_StatementMatch],
    *,
    same_account: bool,
) -> bool:
    scopes: list[_ObjectScope] = []
    if same_account:
        scopes.extend(match.scope for match in identity_allows if match.conditional)
        scopes.extend(match.scope for match in bucket_allows if match.conditional and match.principal_match == "role")
    else:
        exact_bucket_allows = [match for match in bucket_allows if match.principal_match in {"role", "account"}]
        for identity_match in identity_allows:
            for bucket_match in exact_bucket_allows:
                if not (identity_match.conditional or bucket_match.conditional):
                    continue
                intersection = _scope_intersection(identity_match.scope, bucket_match.scope)
                if intersection is not None:
                    scopes.append(intersection)

    unconditional_denies = [match for match in (*identity_denies, *bucket_denies) if not match.conditional]
    return any(not any(_scope_contains(deny.scope, scope) for deny in unconditional_denies) for scope in scopes)


def _merge_proofs(proofs: Sequence[_EffectiveProof]) -> list[_EffectiveProof]:
    merged: dict[tuple[_ScopeKind, str | None], _EffectiveProof] = {}
    for proof in proofs:
        key = (proof.scope.kind, proof.scope.key)
        existing = merged.get(key)
        if existing is None:
            merged[key] = _EffectiveProof(
                proof.scope,
                list(proof.bases),
                list(proof.identity_matches),
                list(proof.bucket_matches),
            )
            continue
        existing.bases = _ordered_bases((*existing.bases, *proof.bases))
        existing.identity_matches = _dedupe_matches((*existing.identity_matches, *proof.identity_matches))
        existing.bucket_matches = _dedupe_matches((*existing.bucket_matches, *proof.bucket_matches))
    return sorted(
        merged.values(),
        key=lambda proof: (_scope_order(proof.scope.kind), proof.scope.key or ""),
    )


def _identity_policy_matches(
    role: NormalizedResource,
    bucket_arn: str,
) -> tuple[list[_StatementMatch], list[str]]:
    matches: list[_StatementMatch] = []
    uncertainties: list[str] = []
    for statement in role.policy_statements:
        effect = _normalized_effect(statement)
        if effect is None:
            continue
        for operation, action_patterns in _matching_actions(statement.actions):
            for resource in statement.resources:
                scope = _scope_from_resource(resource, bucket_arn)
                if scope is None:
                    if _resource_may_target_bucket(resource, bucket_arn):
                        if effect == "deny":
                            scope = _ObjectScope(bucket_arn, "all", None)
                        else:
                            uncertainties.append(
                                f"{role.address} {operation} policy resource {resource!r} does not "
                                f"identify an exact object scope in {bucket_arn}"
                            )
                            continue
                    else:
                        continue
                matches.append(
                    _StatementMatch(
                        statement,
                        operation,
                        role.address,
                        "identity_policy",
                        effect,
                        action_patterns,
                        resource,
                        scope,
                    )
                )
    return matches, dedupe(uncertainties)


def _bucket_policy_matches(
    sources: Sequence[NormalizedResource],
    *,
    bucket_arn: str,
    role_arn: str,
) -> tuple[list[_StatementMatch], list[str]]:
    role_account_id = parse_aws_account_id(role_arn)
    if role_account_id is None:
        return [], []
    account_root_arn = f"arn:{_arn_partition(role_arn)}:iam::{role_account_id}:root"
    matches: list[_StatementMatch] = []
    uncertainties: list[str] = []

    for source in sources:
        for statement in source.policy_statements:
            effect = _normalized_effect(statement)
            if effect is None:
                continue
            principal_values = _aws_principal_values(statement)
            direct_principal = role_arn in principal_values
            account_principal = bool(principal_values & {role_account_id, account_root_arn})
            wildcard_principal = "*" in principal_values
            if not (direct_principal or account_principal or wildcard_principal):
                continue
            principal_match: _PrincipalMatch = (
                "role" if direct_principal else "account" if account_principal else "wildcard"
            )

            for operation, action_patterns in _matching_actions(statement.actions):
                for resource in statement.resources:
                    scope = _scope_from_resource(resource, bucket_arn)
                    if scope is None:
                        if _resource_may_target_bucket(resource, bucket_arn):
                            if effect == "deny":
                                scope = _ObjectScope(bucket_arn, "all", None)
                            else:
                                uncertainties.append(
                                    f"{source.address} {operation} bucket-policy resource {resource!r} "
                                    f"does not identify an exact object scope in {bucket_arn}"
                                )
                                continue
                        else:
                            continue
                    matches.append(
                        _StatementMatch(
                            statement,
                            operation,
                            source.address,
                            "bucket_policy",
                            effect,
                            action_patterns,
                            resource,
                            scope,
                            principal_match,
                        )
                    )
    return matches, dedupe(uncertainties)


def _has_deletion_action_pattern(
    statements: Sequence[IAMPolicyStatement],
) -> bool:
    return any(
        any(
            fnmatchcase(operation.casefold(), pattern.casefold())
            for operation in _OPERATION_ORDER
            for pattern in statement.actions
        )
        for statement in statements
    )


def _policy_may_apply_to_role_deletion(
    statements: Sequence[IAMPolicyStatement],
    role_arn: str,
) -> bool:
    role_account_id = parse_aws_account_id(role_arn)
    if role_account_id is None:
        return False
    account_root_arn = f"arn:{_arn_partition(role_arn)}:iam::{role_account_id}:root"
    for statement in statements:
        if not any(
            fnmatchcase(operation.casefold(), pattern.casefold())
            for operation in _OPERATION_ORDER
            for pattern in statement.actions
        ):
            continue
        principal_values = _aws_principal_values(statement)
        if principal_values & {role_arn, role_account_id, account_root_arn, "*"}:
            return True
    return False


def _unresolved_policy_may_affect_bucket_role_action(
    source: NormalizedResource,
    bucket: NormalizedResource,
    role_arn: str,
    action: _ModeledAction,
    context: AwsDecorationContext,
) -> bool:
    target = aws_facts(source).bucket_name
    modeled_target = context.index.buckets.get(target, source=source) if target else None
    if modeled_target is None:
        target_address = _symbolic_bucket_target_address(target)
        candidate = context.index.resources_by_address.get(target_address) if target_address is not None else None
        if candidate is not None and candidate.resource_type == _S3_BUCKET:
            modeled_target = candidate
    if modeled_target is not None and modeled_target.address != bucket.address:
        return False

    if not _bucket_policy_is_representable(source):
        return True

    bucket_arn = bucket.arn
    if not _is_exact_bucket_arn(bucket_arn):
        return True
    assert bucket_arn is not None

    role_account_id = parse_aws_account_id(role_arn)
    if role_account_id is None:
        return True
    account_root_arn = f"arn:{_arn_partition(role_arn)}:iam::{role_account_id}:root"
    unresolved_resource = False
    for statement in source.policy_statements:
        if not any(fnmatchcase(action.casefold(), pattern.casefold()) for pattern in statement.actions):
            continue
        principal_values = _aws_principal_values(statement)
        if not principal_values & {role_arn, role_account_id, account_root_arn, "*"}:
            continue
        for resource in statement.resources:
            applicability = _policy_resource_bucket_applicability(resource, bucket_arn)
            if applicability is True:
                return True
            if applicability is None:
                unresolved_resource = True
    return unresolved_resource


def _symbolic_bucket_target_address(target: str | None) -> str | None:
    if not target:
        return None
    normalized = target.strip()
    if normalized.startswith("${") and normalized.endswith("}"):
        normalized = normalized[2:-1].strip()
    for suffix in (".bucket", ".arn", ".id"):
        if normalized.endswith(suffix):
            return normalized[: -len(suffix)]
    return normalized if normalized.startswith("aws_s3_bucket.") else None


def _policy_resource_bucket_applicability(
    resource: str,
    bucket_arn: str,
) -> bool | None:
    if resource == "*":
        return True
    if _scope_from_resource(resource, bucket_arn) is not None:
        return True
    if _resource_may_target_bucket(resource, bucket_arn):
        return True
    if "${" in resource or resource.startswith(("aws_s3_bucket.", "module.")):
        return None

    marker = ":s3:::"
    marker_index = resource.find(marker)
    if resource.startswith("arn:") and marker_index >= 0:
        resource_path = resource[marker_index + len(marker) :]
        if "/" in resource_path:
            return False
        return False
    if "*" in resource or "?" in resource:
        return None
    return False


def _matching_actions(
    action_patterns: Sequence[str],
) -> list[tuple[_ModeledAction, tuple[str, ...]]]:
    actions: tuple[_ModeledAction, ...] = (*_OPERATION_ORDER, _BYPASS_GOVERNANCE_RETENTION)
    matches: list[tuple[_ModeledAction, tuple[str, ...]]] = []
    for action in actions:
        patterns = tuple(pattern for pattern in action_patterns if fnmatchcase(action.casefold(), pattern.casefold()))
        if patterns:
            matches.append((action, patterns))
    return matches


def _resource_may_target_bucket(resource: str, bucket_arn: str) -> bool:
    if resource == "*":
        return True
    marker = ":s3:::"
    marker_index = resource.find(marker)
    if not resource.startswith("arn:") or marker_index < 0:
        return False
    resource_path = resource[marker_index + len(marker) :]
    if "/" not in resource_path:
        return False
    bucket_pattern, _ = resource_path.split("/", 1)
    bucket_name = bucket_arn.split(marker, 1)[1]
    return bool(bucket_pattern and fnmatchcase(bucket_name, bucket_pattern))


def _bypass_authorization_for_scope(
    target_scope: _ObjectScope,
    evaluation: _AuthorizationEvaluation,
) -> bool | None:
    if any(_scope_contains(proof.scope, target_scope) for proof in evaluation.proofs):
        return True
    if evaluation.uncertainties:
        return None
    return False


def _recovery_evidence(
    bucket: NormalizedResource,
    operation: AwsS3ObjectDeletionOperation,
    *,
    bypass_authorized: bool | None,
    bypass_uncertain: bool,
) -> tuple[AwsS3ObjectDeletionLifecycleCompatibilityState, AwsS3ObjectDeletionRecoveryEvidence]:
    facts = aws_facts(bucket)
    uncertainties = list(facts.s3_posture_uncertainties)
    status = facts.s3_versioning_status

    if operation == "s3:DeleteObject":
        normalized_status = status.strip().casefold() if status else None
        if normalized_status == "enabled":
            lifecycle_state: AwsS3ObjectDeletionLifecycleCompatibilityState = "recoverable_delete_marker"
        elif normalized_status == STATE_DISABLED:
            lifecycle_state = "compatible"
        else:
            lifecycle_state = "unknown"
            if normalized_status == "suspended":
                uncertainties.append(
                    f"{bucket.address}: suspended versioning does not establish whether the current "
                    "null version would be permanently removed"
                )
            else:
                uncertainties.append(
                    f"{bucket.address}: S3 versioning state is not exact for logical object-deletion recovery"
                )
    else:
        object_lock_enabled = facts.s3_object_lock_enabled
        if object_lock_enabled is False:
            lifecycle_state = "compatible"
        else:
            lifecycle_state = "unknown"
            if object_lock_enabled is True:
                uncertainties.append(
                    f"{bucket.address}: Object Lock bucket defaults do not establish the effective "
                    "retention or legal-hold state of a targeted object version"
                )
            else:
                uncertainties.append(
                    f"{bucket.address}: Object Lock enablement is not observed for object-version deletion"
                )

    if bypass_uncertain:
        uncertainties.append(
            f"{bucket.address}: s3:BypassGovernanceRetention authority is condition-dependent or unresolved"
        )

    recovery: AwsS3ObjectDeletionRecoveryEvidence = {
        "recovery_evidence_scope": "s3_versioning_and_object_lock",
        "versioning_status": status,
        "versioning_enabled": facts.s3_versioning_enabled,
        "object_lock_enabled": facts.s3_object_lock_enabled,
        "object_lock_default_retention_mode": facts.s3_object_lock_default_retention_mode,
        "object_lock_default_retention_days": facts.s3_object_lock_default_retention_days,
        "object_lock_default_retention_years": facts.s3_object_lock_default_retention_years,
        "bypass_governance_retention_authorized": bypass_authorized,
        "uncertainties": dedupe(uncertainties),
    }
    return lifecycle_state, recovery


def _path_record(
    task_definition: NormalizedResource,
    task_role: NormalizedResource,
    bucket: NormalizedResource,
    bucket_posture: _BucketPolicyPosture,
    operation: AwsS3ObjectDeletionOperation,
    proof: _EffectiveProof,
    *,
    same_account: bool,
    lifecycle_state: AwsS3ObjectDeletionLifecycleCompatibilityState,
    recovery_evidence: AwsS3ObjectDeletionRecoveryEvidence,
) -> AwsEcsS3ObjectDeletionPath:
    bucket_arn = bucket.arn
    role_arn = task_role.arn
    assert bucket_arn is not None
    assert role_arn is not None
    identity_sources = _identity_policy_sources(task_role)
    used_identity_sources = identity_sources if proof.identity_matches else []
    used_bucket_sources = list(bucket_posture.source_addresses) if proof.bucket_matches else []
    all_matches = (*proof.identity_matches, *proof.bucket_matches)
    model_evidence_addresses = dedupe(
        value
        for value in (
            bucket.address,
            aws_facts(bucket).s3_versioning_source_address,
            aws_facts(bucket).s3_object_lock_source_address,
        )
        if value is not None
    )
    common: AwsEcsS3ObjectDeletionPathCommon = {
        "workload_address": task_definition.address,
        "workload_type": task_definition.resource_type,
        "task_definition_address": task_definition.address,
        "task_definition_arn": task_definition.arn,
        "internet_facing_load_balancers": [],
        "role_kind": "ecs_task_role",
        "credential_context": "workload_runtime",
        "role_address": task_role.address,
        "role_arn": role_arn,
        "bucket_address": bucket.address,
        "bucket_arn": bucket_arn,
        "management_effect": "disruption",
        "internal_operation": ("delete_current_object" if operation == "s3:DeleteObject" else "delete_object_version"),
        "target_scope": proof.scope.resource,
        "target_model_evidence_addresses": model_evidence_addresses,
        "authorization_source_addresses": dedupe((*used_identity_sources, *used_bucket_sources)),
        "authorization_state": "allowed",
        "authorization_bases": _ordered_bases(proof.bases),
        "same_account": same_account,
        "matched_actions": [operation],
        "policy_action_patterns": sorted(
            {pattern for match in all_matches for pattern in match.matching_action_patterns},
            key=str.casefold,
        ),
        "policy_resources": sorted({match.matching_resource for match in all_matches}),
        "identity_policy_complete": True,
        "bucket_policy_complete": True,
        "identity_policy_source_addresses": identity_sources,
        "bucket_policy_source_addresses": list(bucket_posture.source_addresses),
        "identity_policy_statements": [_statement_record(match) for match in proof.identity_matches],
        "bucket_policy_statements": [_statement_record(match) for match in proof.bucket_matches],
        "explicit_deny": False,
        "conditional_evaluation_required": False,
        "lifecycle_compatibility_state": lifecycle_state,
        "recovery_evidence": recovery_evidence,
        "posture_uncertainties": list(recovery_evidence["uncertainties"]),
    }

    if operation == "s3:DeleteObject":
        if proof.scope.kind == "exact":
            assert proof.scope.key is not None
            exact_path: AwsEcsS3ExactObjectDeletionPath = {
                **common,
                "operation": "s3:DeleteObject",
                "operation_class": "logical_object_deletion",
                "target_granularity": "object",
                "object_key": proof.scope.key,
                "object_version": None,
            }
            return exact_path
        if proof.scope.kind == "prefix":
            assert proof.scope.key is not None
            prefix_path: AwsEcsS3ObjectPrefixDeletionPath = {
                **common,
                "operation": "s3:DeleteObject",
                "operation_class": "logical_object_deletion",
                "target_granularity": "object_prefix",
                "object_key": proof.scope.key,
                "object_version": None,
            }
            return prefix_path
        namespace_path: AwsEcsS3BucketObjectNamespaceDeletionPath = {
            **common,
            "operation": "s3:DeleteObject",
            "operation_class": "logical_object_deletion",
            "target_granularity": "bucket_object_namespace",
            "object_key": None,
            "object_version": None,
        }
        return namespace_path

    if proof.scope.kind == "exact":
        assert proof.scope.key is not None
        version_namespace_path: AwsEcsS3ObjectVersionNamespaceDeletionPath = {
            **common,
            "operation": "s3:DeleteObjectVersion",
            "operation_class": "object_version_deletion",
            "target_granularity": "object_version_namespace",
            "object_key": proof.scope.key,
            "object_version": None,
        }
        return version_namespace_path
    if proof.scope.kind == "prefix":
        assert proof.scope.key is not None
        prefix_version_path: AwsEcsS3ObjectPrefixVersionNamespaceDeletionPath = {
            **common,
            "operation": "s3:DeleteObjectVersion",
            "operation_class": "object_version_deletion",
            "target_granularity": "object_prefix_version_namespace",
            "object_key": proof.scope.key,
            "object_version": None,
        }
        return prefix_version_path
    bucket_versions_path: AwsEcsS3BucketObjectVersionNamespaceDeletionPath = {
        **common,
        "operation": "s3:DeleteObjectVersion",
        "operation_class": "object_version_deletion",
        "target_granularity": "bucket_object_version_namespace",
        "object_key": None,
        "object_version": None,
    }
    return bucket_versions_path


def _service_path(
    service: NormalizedResource,
    task_definition: NormalizedResource,
    path: AwsEcsS3ObjectDeletionPath,
) -> AwsEcsS3ObjectDeletionPath:
    projected = path.copy()
    projected["workload_address"] = service.address
    projected["workload_type"] = service.resource_type
    projected["task_definition_address"] = task_definition.address
    projected["task_definition_arn"] = task_definition.arn
    projected["internet_facing_load_balancers"] = aws_facts(service).internet_facing_load_balancer_addresses
    return projected


def _bucket_policy_posture(
    bucket: NormalizedResource,
    context: AwsDecorationContext,
) -> _BucketPolicyPosture:
    source_addresses = tuple(dedupe(aws_facts(bucket).resource_policy_source_addresses))
    sources: list[NormalizedResource] = []
    uncertainties: list[str] = []

    if source_addresses:
        for source_address in source_addresses:
            source = context.index.resources_by_address.get(source_address)
            if source is None or source.resource_type != _S3_BUCKET_POLICY:
                uncertainties.append(f"{bucket.address}: bucket-policy source {source_address} is unavailable")
                continue
            sources.append(source)
            if not _bucket_policy_is_representable(source):
                uncertainties.append(
                    f"{bucket.address}: {source.address} bucket policy is incomplete, malformed, or unsupported"
                )
    elif _has_policy_statements(aws_facts(bucket).policy_document):
        sources.append(bucket)
        source_addresses = (bucket.address,)
        if not _bucket_policy_is_representable(bucket):
            uncertainties.append(f"{bucket.address}: inline bucket policy is incomplete, malformed, or unsupported")

    if len(source_addresses) > 1:
        uncertainties.append(
            f"{bucket.address}: multiple S3 bucket-policy resources provide conflicting authoritative evidence"
        )
    complete = (
        len(sources) == len(source_addresses)
        and len(source_addresses) <= 1
        and all(_bucket_policy_is_representable(source) for source in sources)
    )
    return _BucketPolicyPosture(
        tuple(sources),
        source_addresses,
        complete,
        tuple(dedupe(uncertainties)),
    )


def _unresolved_bucket_policy_sources(
    resources: Sequence[NormalizedResource],
    context: AwsDecorationContext,
) -> tuple[str, ...]:
    unresolved: list[str] = []
    for resource in resources:
        if resource.resource_type != _S3_BUCKET_POLICY:
            continue
        target = aws_facts(resource).bucket_name
        if target and context.index.buckets.get(target, source=resource) is not None:
            continue
        if _is_exact_unmodeled_bucket_reference(target):
            continue
        unresolved.append(resource.address)
    return tuple(dedupe(unresolved))


def _bucket_policy_is_representable(source: NormalizedResource) -> bool:
    document = aws_facts(source).policy_document
    raw_statements = document.get("Statement")
    if isinstance(raw_statements, Mapping):
        statement_documents: list[Mapping[str, object]] = [raw_statements]
    elif isinstance(raw_statements, list) and all(isinstance(statement, Mapping) for statement in raw_statements):
        statement_documents = [statement for statement in raw_statements if isinstance(statement, Mapping)]
    else:
        return False
    statements = source.policy_statements
    return (
        bool(statement_documents)
        and len(statements) == len(statement_documents)
        and all(
            policy_statement_is_fully_representable(
                raw_statement,
                statement,
                principal_mode="required",
            )
            for raw_statement, statement in zip(statement_documents, statements, strict=True)
        )
    )


def _has_policy_statements(document: Mapping[str, object]) -> bool:
    statements = document.get("Statement")
    return isinstance(statements, Mapping) or bool(isinstance(statements, list) and statements)


def _identity_policy_complete(role: NormalizedResource) -> bool:
    facts = aws_facts(role)
    return bool(
        facts.iam_policy_completeness_state == _COMPLETE
        and not facts.unresolved_attached_policy_arns
        and all(
            statement.effect.strip().casefold() in {"allow", "deny"}
            and bool(statement.actions)
            and bool(statement.resources)
            and not statement.principal_entries
            for statement in role.policy_statements
        )
    )


def _identity_policy_sources(role: NormalizedResource) -> list[str]:
    facts = aws_facts(role)
    return dedupe(
        [
            role.address,
            *facts.inline_policy_resource_addresses,
            *facts.attached_policy_addresses,
        ]
    )


def _statement_record(match: _StatementMatch) -> AwsS3ObjectDeletionPolicyStatementEvidence:
    return {
        "source_address": match.source_address,
        "source_kind": match.source_kind,
        "effect": match.effect,
        "actions": list(match.statement.actions),
        "matching_action_patterns": list(match.matching_action_patterns),
        "resources": list(match.statement.resources),
        "matching_resources": [match.matching_resource],
        "principal_match": match.principal_match,
        "conditions": [
            {
                "operator": condition.operator,
                "key": condition.key,
                "values": list(condition.values),
            }
            for condition in match.statement.conditions
        ],
        "conditional": match.conditional,
    }


def _normalized_effect(statement: IAMPolicyStatement) -> Literal["allow", "deny"] | None:
    effect = statement.effect.strip().casefold()
    if effect == "allow":
        return "allow"
    if effect == "deny":
        return "deny"
    return None


def _aws_principal_values(statement: IAMPolicyStatement) -> set[str]:
    return {entry.value for entry in statement.principal_entries if entry.kind.casefold() in {"aws", "unknown"}}


def _ordered_bases(
    values: Sequence[AwsS3ObjectDeletionAuthorizationBasis],
) -> list[AwsS3ObjectDeletionAuthorizationBasis]:
    present = set(values)
    return [basis for basis in _AUTHORIZATION_BASIS_ORDER if basis in present]


def _dedupe_matches(matches: Sequence[_StatementMatch]) -> list[_StatementMatch]:
    seen: set[tuple[str, str, str, str, str | None]] = set()
    result: list[_StatementMatch] = []
    for match in matches:
        fingerprint = (
            match.source_address,
            match.operation,
            match.effect,
            match.matching_resource,
            match.principal_match,
        )
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        result.append(match)
    return result


def _account_relationship(
    role_arn: str,
    bucket_arn: str,
    primary_account_id: str | None,
) -> tuple[bool | None, bool]:
    role_account_id = parse_aws_account_id(role_arn)
    if role_account_id is None or primary_account_id is None:
        return None, _arn_partition(role_arn) == _arn_partition(bucket_arn)
    return (
        role_account_id == primary_account_id,
        _arn_partition(role_arn) == _arn_partition(bucket_arn),
    )


def _infer_primary_account_id(resources: Sequence[NormalizedResource]) -> str | None:
    caller_identity_facts = [
        aws_facts(resource) for resource in resources if resource.resource_type == "aws_caller_identity"
    ]
    caller_states = {facts.caller_identity_account_id_state for facts in caller_identity_facts}
    if caller_states & {"ambiguous", "invalid"}:
        return None
    caller_account_ids = {
        facts.caller_identity_account_id
        for facts in caller_identity_facts
        if facts.caller_identity_account_id is not None
    }
    if caller_account_ids:
        if caller_states != {"resolved"} or len(caller_account_ids) != 1:
            return None
        return next(iter(caller_account_ids))

    resource_account_ids: set[str] = set()
    for resource in resources:
        if resource.resource_type == "aws_caller_identity":
            continue
        account_id, invalid_account_segment = _resource_arn_account_evidence(resource.arn)
        if invalid_account_segment:
            return None
        if account_id is not None:
            resource_account_ids.add(account_id)
    if len(resource_account_ids) != 1:
        return None
    return next(iter(resource_account_ids))


def _resource_arn_account_evidence(arn: str | None) -> tuple[str | None, bool]:
    if not arn or not arn.startswith("arn:"):
        return None, False
    parts = arn.split(":")
    if len(parts) < 5 or not parts[4]:
        return None, False
    account_id = parse_aws_account_id(arn)
    return account_id, account_id is None


def _is_exact_unmodeled_bucket_reference(value: str | None) -> bool:
    if not value or _has_wildcard(value) or "${" in value:
        return False
    if value.startswith("aws_s3_bucket."):
        return False
    if value.startswith("arn:"):
        return _is_exact_bucket_arn(value)
    return "." not in value or value.replace(".", "").replace("-", "").isalnum()


def _is_exact_bucket_arn(value: str | None) -> bool:
    if not value or _has_wildcard(value):
        return False
    parts = value.split(":", 5)
    return bool(
        len(parts) == 6
        and parts[0] == "arn"
        and parts[1]
        and parts[2] == "s3"
        and not parts[3]
        and not parts[4]
        and parts[5]
        and "/" not in parts[5]
    )


def _is_exact_iam_role_arn(value: str | None) -> bool:
    if not value or _has_wildcard(value):
        return False
    parts = value.split(":", 5)
    return bool(
        len(parts) == 6
        and parts[0] == "arn"
        and parts[1]
        and parts[2] == "iam"
        and not parts[3]
        and parse_aws_account_id(value) is not None
        and parts[5].startswith("role/")
        and len(parts[5]) > len("role/")
    )


def _arn_partition(value: str) -> str | None:
    parts = value.split(":", 2)
    return parts[1] if len(parts) == 3 and parts[0] == "arn" else None


def _scope_order(scope: _ScopeKind) -> int:
    return {"exact": 0, "prefix": 1, "all": 2}[scope]


def _path_sort_key(path: AwsEcsS3ObjectDeletionPath) -> tuple[str, int, str, str]:
    return (
        path["bucket_address"],
        _OPERATION_ORDER.index(path["operation"]),
        path["target_granularity"],
        path["target_scope"],
    )


def _has_wildcard(value: str) -> bool:
    return "*" in value or "?" in value
