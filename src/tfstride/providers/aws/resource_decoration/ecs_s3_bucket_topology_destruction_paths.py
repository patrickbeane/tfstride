from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Literal, cast

from tfstride.models import (
    IAMPolicyStatement,
    NormalizedResource,
    TerraformReferenceProvenance,
    TerraformReferenceResolutionState,
)
from tfstride.providers.aws.object_storage_topology_destruction_evidence import (
    AwsEcsS3BucketTopologyDestructionPath,
    AwsS3BucketTopologyDestructionAuthorizationBasis,
    AwsS3BucketTopologyIdentityPolicyStatementEvidence,
    AwsS3BucketTopologyPolicyStatementEvidence,
    AwsS3BucketTopologyResourcePolicyStatementEvidence,
)
from tfstride.providers.aws.policy_documents import (
    policy_statement_is_fully_representable,
)
from tfstride.providers.aws.reference_resolution import (
    assess_symbolic_reference,
    symbolic_reference_target,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.coercion import dedupe
from tfstride.resource_helpers import parse_aws_account_id

_ECS_TASK_DEFINITION = "aws_ecs_task_definition"
_ECS_SERVICE = "aws_ecs_service"
_IAM_ROLE = "aws_iam_role"
_S3_BUCKET = "aws_s3_bucket"
_S3_BUCKET_POLICY = "aws_s3_bucket_policy"
_CALLER_IDENTITY = "aws_caller_identity"
_COMPLETE = "complete"
_DELETE_BUCKET = "s3:DeleteBucket"
_PrincipalMatch = Literal["role", "account", "wildcard"]
_PolicySourceKind = Literal["identity_policy", "bucket_policy"]


@dataclass(frozen=True, slots=True)
class _StatementMatch:
    statement: IAMPolicyStatement
    source_address: str
    source_kind: _PolicySourceKind
    effect: Literal["allow", "deny"]
    matching_action_patterns: tuple[str, ...]
    matching_resource: str
    principal_match: _PrincipalMatch | None = None

    @property
    def conditional(self) -> bool:
        return bool(self.statement.conditions)


@dataclass(frozen=True, slots=True)
class _PolicyMatches:
    matches: tuple[_StatementMatch, ...]
    unresolved_allow: bool
    unresolved_deny: bool


@dataclass(frozen=True, slots=True)
class _BucketPolicyPosture:
    sources: tuple[NormalizedResource, ...]
    source_addresses: tuple[str, ...]
    complete: bool
    uncertainties: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _EffectiveProof:
    bases: tuple[AwsS3BucketTopologyDestructionAuthorizationBasis, ...]
    identity_matches: tuple[_StatementMatch, ...]
    bucket_matches: tuple[_StatementMatch, ...]


@dataclass(frozen=True, slots=True)
class _AuthorizationEvaluation:
    proof: _EffectiveProof | None
    uncertainties: tuple[str, ...]


class ModelEcsS3BucketTopologyDestructionPathsStage:
    """Model effective ECS task-role authority to delete exact S3 buckets."""

    name = "model_ecs_s3_bucket_topology_destruction_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AwsDecorationContext,
    ) -> None:
        buckets = tuple(resource for resource in resources if resource.resource_type == _S3_BUCKET)
        unresolved_policy_sources = _unresolved_bucket_policy_sources(
            resources,
            context,
        )
        for task_definition in resources:
            if task_definition.resource_type != _ECS_TASK_DEFINITION:
                continue
            paths, uncertainties = _task_definition_paths(
                task_definition,
                buckets,
                context,
                unresolved_policy_sources=unresolved_policy_sources,
            )
            facts = aws_facts(task_definition)
            facts.set_ecs_s3_bucket_topology_destruction_paths(paths)
            facts.extend_ecs_s3_bucket_topology_destruction_path_uncertainties(
                uncertainties,
            )


class ProjectEcsS3BucketTopologyDestructionPathsOntoServicesStage:
    name = "project_ecs_s3_bucket_topology_destruction_paths_onto_services"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AwsDecorationContext,
    ) -> None:
        for service in resources:
            if service.resource_type != _ECS_SERVICE:
                continue
            service_facts = aws_facts(service)
            paths: list[AwsEcsS3BucketTopologyDestructionPath] = []
            uncertainties = [
                f"{service.address}: task definition reference {reference} is "
                "unresolved for S3 bucket-deletion path projection"
                for reference in service_facts.unresolved_task_definition_references
            ]
            for task_definition_address in service_facts.resolved_task_definition_addresses:
                task_definition = context.index.ecs_task_definitions.get(
                    task_definition_address,
                    source=service,
                )
                if task_definition is None:
                    uncertainties.append(
                        f"{service.address}: resolved task definition "
                        f"{task_definition_address} is unavailable for S3 "
                        "bucket-deletion path projection"
                    )
                    continue
                task_facts = aws_facts(task_definition)
                uncertainties.extend(
                    task_facts.ecs_s3_bucket_topology_destruction_path_uncertainties,
                )
                paths.extend(
                    _service_path(service, task_definition, path)
                    for path in (task_facts.ecs_s3_bucket_topology_destruction_paths)
                )
            paths.sort(key=_path_sort_key)
            service_facts.set_ecs_s3_bucket_topology_destruction_paths(paths)
            service_facts.extend_ecs_s3_bucket_topology_destruction_path_uncertainties(
                dedupe(uncertainties),
            )


def _task_definition_paths(
    task_definition: NormalizedResource,
    buckets: Sequence[NormalizedResource],
    context: AwsDecorationContext,
    *,
    unresolved_policy_sources: Sequence[NormalizedResource],
) -> tuple[list[AwsEcsS3BucketTopologyDestructionPath], list[str]]:
    task_facts = aws_facts(task_definition)
    task_role_reference = task_facts.task_role_arn
    if task_role_reference is None:
        return [], _task_role_resolution_uncertainties(task_definition)

    task_role = context.index.role_index.get(task_role_reference, source=task_definition)
    if task_role is None or task_role.resource_type != _IAM_ROLE:
        if _task_role_configuration_reference_observed(task_definition):
            return (
                [],
                [
                    f"{task_definition.address}: task role relationship is "
                    "ambiguous or unresolved for S3 bucket-deletion paths"
                ],
            )
        return (
            [],
            [
                f"{task_definition.address}: ECS task role {task_role_reference} "
                "is not modeled for S3 bucket-deletion paths"
            ],
        )
    if not _task_role_relationship_is_exact(
        task_definition,
        task_role,
        context,
    ):
        return [], []

    role_reference = _task_role_evidence_reference(task_definition, task_role)
    if role_reference is None:
        return [], []
    if not _is_exact_iam_role_arn(task_role.arn):
        return (
            [],
            [
                f"{task_definition.address}: ECS task role {task_role.address} "
                "has no exact IAM role ARN for S3 bucket ownership compatibility"
            ],
        )
    role_arn = cast(str, task_role.arn)

    identity_policy_complete = _identity_policy_complete(task_role)
    uncertainties: list[str] = []
    if not identity_policy_complete and _role_has_delete_bucket_action(task_role):
        uncertainties.append(
            f"{task_definition.address}: {task_role.address} S3 bucket-deletion "
            "authorization is unresolved because identity-policy evidence is incomplete"
        )
        uncertainties.extend(
            f"{task_definition.address}: {task_role.address}: {uncertainty}"
            for uncertainty in aws_facts(task_role).iam_policy_posture_uncertainties
        )

    paths: list[AwsEcsS3BucketTopologyDestructionPath] = []
    for bucket in buckets:
        bucket_arn = bucket.arn
        if not _is_exact_bucket_arn(bucket_arn):
            if _role_has_delete_bucket_action(task_role) or (
                _bucket_policy_may_apply_to_role(
                    bucket.policy_statements,
                    role_arn,
                )
            ):
                uncertainties.append(
                    f"{task_definition.address}: {bucket.address} has no exact "
                    "S3 bucket ARN for bucket-deletion path matching"
                )
            continue
        assert bucket_arn is not None

        identity_matches = _identity_policy_matches(
            task_role,
            bucket,
            context,
        )
        exact_posture = _bucket_policy_posture(bucket, context)
        relevant_unresolved_sources = tuple(
            source
            for source in unresolved_policy_sources
            if _unresolved_policy_may_affect_bucket_role(
                source,
                bucket,
                role_arn,
                context,
            )
        )
        bucket_matches = _bucket_policy_matches(
            exact_posture.sources,
            bucket,
            role_arn,
            context,
        )
        operation_evidence = bool(
            identity_matches.matches
            or bucket_matches.matches
            or identity_matches.unresolved_allow
            or identity_matches.unresolved_deny
            or bucket_matches.unresolved_allow
            or bucket_matches.unresolved_deny
        )
        if not operation_evidence:
            continue

        same_account, partitions_match = _account_relationship(
            role_arn,
            bucket_arn,
            _provider_account_id_for_bucket_role(
                tuple(context.index.resources_by_address.values()),
                task_role,
                bucket,
            ),
        )
        if same_account is False or not partitions_match:
            continue
        if same_account is None:
            uncertainties.append(
                f"{task_definition.address}: {bucket.address} bucket ownership "
                f"compatibility with {task_role.address} is unresolved"
            )
            continue

        uncertainties.extend(f"{task_definition.address}: {uncertainty}" for uncertainty in exact_posture.uncertainties)
        uncertainties.extend(
            f"{task_definition.address}: {source.address} has an unresolved "
            "S3 bucket-policy target and may affect "
            f"{task_role.address} {_DELETE_BUCKET} authorization for {bucket.address}"
            for source in relevant_unresolved_sources
        )
        evaluation = _evaluate_authorization(
            bucket,
            task_role,
            identity_matches=identity_matches,
            bucket_matches=bucket_matches,
            identity_policy_complete=identity_policy_complete,
            bucket_policy_complete=(exact_posture.complete and not relevant_unresolved_sources),
        )
        uncertainties.extend(f"{task_definition.address}: {uncertainty}" for uncertainty in evaluation.uncertainties)
        if evaluation.proof is None:
            continue
        paths.append(
            _path(
                task_definition,
                task_role,
                role_reference,
                bucket,
                evaluation.proof,
                exact_posture,
            )
        )

    paths.sort(key=_path_sort_key)
    return paths, dedupe(uncertainties)


def _evaluate_authorization(
    bucket: NormalizedResource,
    role: NormalizedResource,
    *,
    identity_matches: _PolicyMatches,
    bucket_matches: _PolicyMatches,
    identity_policy_complete: bool,
    bucket_policy_complete: bool,
) -> _AuthorizationEvaluation:
    matches = (*identity_matches.matches, *bucket_matches.matches)
    denies = [match for match in matches if match.effect == "deny"]
    if any(not match.conditional for match in denies):
        return _AuthorizationEvaluation(None, ())
    if any(match.conditional for match in denies):
        return _AuthorizationEvaluation(
            None,
            (f"{bucket.address}: {role.address} {_DELETE_BUCKET} has condition-dependent explicit-deny evidence",),
        )
    if identity_matches.unresolved_deny or bucket_matches.unresolved_deny:
        return _AuthorizationEvaluation(
            None,
            (f"{bucket.address}: {role.address} {_DELETE_BUCKET} has ambiguous or unresolved explicit-deny scope",),
        )

    identity_allows = tuple(
        match for match in identity_matches.matches if match.effect == "allow" and not match.conditional
    )
    bucket_allows = tuple(
        match
        for match in bucket_matches.matches
        if match.effect == "allow" and not match.conditional and match.principal_match == "role"
    )
    candidate_observed = bool(
        identity_allows
        or bucket_allows
        or identity_matches.unresolved_allow
        or bucket_matches.unresolved_allow
        or any(match.effect == "allow" for match in matches)
    )
    if not candidate_observed:
        return _AuthorizationEvaluation(None, ())

    if not identity_policy_complete or not bucket_policy_complete:
        surfaces: list[str] = []
        if not identity_policy_complete:
            surfaces.append("identity policy")
        if not bucket_policy_complete:
            surfaces.append("bucket policy")
        return _AuthorizationEvaluation(
            None,
            (
                f"{bucket.address}: {role.address} {_DELETE_BUCKET} authorization "
                f"is unresolved because {' and '.join(surfaces)} evidence is incomplete",
            ),
        )

    if identity_allows or bucket_allows:
        bases: list[AwsS3BucketTopologyDestructionAuthorizationBasis] = []
        if identity_allows:
            bases.append("identity_policy")
        if bucket_allows:
            bases.append("bucket_policy_direct")
        return _AuthorizationEvaluation(
            _EffectiveProof(
                tuple(bases),
                identity_allows,
                bucket_allows,
            ),
            (),
        )

    if identity_matches.unresolved_allow or bucket_matches.unresolved_allow:
        return _AuthorizationEvaluation(
            None,
            (
                f"{bucket.address}: {role.address} {_DELETE_BUCKET} allow evidence "
                "does not identify one exact S3 bucket",
            ),
        )
    if any(match.effect == "allow" and match.conditional for match in matches):
        return _AuthorizationEvaluation(
            None,
            (f"{bucket.address}: {role.address} {_DELETE_BUCKET} authorization depends on runtime policy conditions",),
        )
    if any(
        match.effect == "allow" and match.principal_match in {"account", "wildcard"} for match in bucket_matches.matches
    ):
        return _AuthorizationEvaluation(
            None,
            (
                f"{bucket.address}: {role.address} {_DELETE_BUCKET} has bucket-policy "
                "allow evidence outside the exact-role principal model",
            ),
        )
    return _AuthorizationEvaluation(None, ())


def _identity_policy_matches(
    role: NormalizedResource,
    bucket: NormalizedResource,
    context: AwsDecorationContext,
) -> _PolicyMatches:
    sources = _identity_policy_resources(role, context)
    matches: list[_StatementMatch] = []
    unresolved_allow = False
    unresolved_deny = False
    for statement in role.policy_statements:
        effect = _normalized_effect(statement)
        if effect is None:
            continue
        action_patterns = _matching_action_patterns(statement.actions)
        if not action_patterns:
            continue
        for resource in statement.resources:
            applicability = _resource_targets_bucket(
                resource,
                bucket,
                sources,
                context,
                exact_allow_required=effect == "allow",
            )
            if applicability is True:
                matches.append(
                    _StatementMatch(
                        statement,
                        role.address,
                        "identity_policy",
                        effect,
                        action_patterns,
                        resource,
                    )
                )
            elif applicability is None:
                if effect == "allow":
                    unresolved_allow = True
                else:
                    unresolved_deny = True
    return _PolicyMatches(
        tuple(matches),
        unresolved_allow,
        unresolved_deny,
    )


def _bucket_policy_matches(
    sources: Sequence[NormalizedResource],
    bucket: NormalizedResource,
    role_arn: str,
    context: AwsDecorationContext,
) -> _PolicyMatches:
    role_account_id = parse_aws_account_id(role_arn)
    if role_account_id is None:
        return _PolicyMatches((), False, True)
    account_root_arn = f"arn:{_arn_partition(role_arn)}:iam::{role_account_id}:root"
    matches: list[_StatementMatch] = []
    unresolved_allow = False
    unresolved_deny = False
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
            action_patterns = _matching_action_patterns(statement.actions)
            if not action_patterns:
                continue
            for resource in statement.resources:
                applicability = _resource_targets_bucket(
                    resource,
                    bucket,
                    (source,),
                    context,
                    exact_allow_required=effect == "allow",
                )
                if applicability is True:
                    matches.append(
                        _StatementMatch(
                            statement,
                            source.address,
                            "bucket_policy",
                            effect,
                            action_patterns,
                            resource,
                            principal_match,
                        )
                    )
                elif applicability is None:
                    if effect == "allow":
                        unresolved_allow = True
                    else:
                        unresolved_deny = True
    return _PolicyMatches(
        tuple(matches),
        unresolved_allow,
        unresolved_deny,
    )


def _resource_targets_bucket(
    resource: str,
    bucket: NormalizedResource,
    sources: Sequence[NormalizedResource],
    context: AwsDecorationContext,
    *,
    exact_allow_required: bool,
) -> bool | None:
    bucket_arn = bucket.arn
    assert bucket_arn is not None
    normalized = _unwrap_reference(resource)
    if normalized == bucket_arn:
        return True
    if normalized.startswith("arn:"):
        if _has_wildcard(normalized):
            matches = fnmatchcase(bucket_arn, normalized)
            if not matches:
                return False
            return None if exact_allow_required else True
        return False

    candidates: set[str] = set()
    uncertain = False
    for source in sources:
        assessment = assess_symbolic_reference(
            source,
            context.index,
            normalized,
            expected_resource_types={_S3_BUCKET},
            expected_reference_suffixes={".arn"},
        )
        if assessment.state == "resolved" and assessment.target is not None:
            candidates.add(assessment.target.address)
        elif assessment.state == "uncertain":
            uncertain = True
    if uncertain or len(candidates) > 1:
        return None
    if candidates:
        return candidates == {bucket.address}

    if normalized == "*":
        return None if exact_allow_required else True
    if _has_wildcard(normalized):
        return None
    return False


def _bucket_policy_posture(
    bucket: NormalizedResource,
    context: AwsDecorationContext,
) -> _BucketPolicyPosture:
    source_addresses = tuple(
        dedupe(
            [
                *aws_facts(bucket).resource_policy_source_addresses,
                *(
                    resource.address
                    for resource in context.index.resources_by_address.values()
                    if resource.resource_type == _S3_BUCKET_POLICY
                    and (
                        target := _resolved_bucket_policy_target(
                            resource,
                            context,
                        )
                    )
                    is not None
                    and target.address == bucket.address
                ),
            ]
        )
    )
    sources: list[NormalizedResource] = []
    uncertainties: list[str] = []
    if source_addresses:
        for source_address in source_addresses:
            source = context.index.resources_by_address.get(source_address)
            if source is None or source.resource_type != _S3_BUCKET_POLICY:
                uncertainties.append(f"{bucket.address}: bucket-policy source {source_address} is unavailable")
                continue
            sources.append(source)
            if not _bucket_policy_is_complete_for_operation(source):
                uncertainties.append(
                    f"{bucket.address}: {source.address} bucket-policy evidence "
                    f"is incomplete or unsupported for {_DELETE_BUCKET}"
                )
    elif _has_policy_statements(aws_facts(bucket).policy_document):
        sources.append(bucket)
        source_addresses = (bucket.address,)
        if not _bucket_policy_is_complete_for_operation(bucket):
            uncertainties.append(
                f"{bucket.address}: inline bucket-policy evidence is incomplete or unsupported for {_DELETE_BUCKET}"
            )

    if len(source_addresses) > 1:
        uncertainties.append(
            f"{bucket.address}: multiple S3 bucket-policy resources provide conflicting authoritative evidence"
        )
    complete = bool(
        len(sources) == len(source_addresses)
        and len(source_addresses) <= 1
        and all(_bucket_policy_is_complete_for_operation(source) for source in sources)
    )
    return _BucketPolicyPosture(
        tuple(sources),
        source_addresses,
        complete,
        tuple(dedupe(uncertainties)),
    )


def _bucket_policy_is_complete_for_operation(
    source: NormalizedResource,
) -> bool:
    statement_documents = _raw_policy_statements(
        aws_facts(source).policy_document,
    )
    if statement_documents is None:
        return False
    statements = source.policy_statements
    if len(statements) != len(statement_documents):
        return not any(
            _raw_statement_affects_delete_bucket(statement) is not False for statement in statement_documents
        )
    for raw_statement, statement in zip(
        statement_documents,
        statements,
        strict=True,
    ):
        if policy_statement_is_fully_representable(
            raw_statement,
            statement,
            principal_mode="required",
        ):
            continue
        if _raw_statement_affects_delete_bucket(raw_statement) is not False:
            return False
    return True


def _raw_policy_statements(
    document: Mapping[str, object],
) -> list[Mapping[str, object]] | None:
    raw_statements = document.get("Statement")
    if isinstance(raw_statements, Mapping):
        return [raw_statements]
    if isinstance(raw_statements, list) and all(isinstance(statement, Mapping) for statement in raw_statements):
        return [statement for statement in raw_statements if isinstance(statement, Mapping)]
    return None


def _raw_statement_affects_delete_bucket(
    statement: Mapping[str, object],
) -> bool | None:
    if "NotAction" in statement:
        return None
    raw_actions = statement.get("Action")
    if isinstance(raw_actions, str):
        actions = [raw_actions]
    elif isinstance(raw_actions, list) and all(isinstance(action, str) for action in raw_actions):
        actions = [action for action in raw_actions if isinstance(action, str)]
    else:
        return None
    return any(fnmatchcase(_DELETE_BUCKET.casefold(), action.casefold()) for action in actions)


def _unresolved_bucket_policy_sources(
    resources: Sequence[NormalizedResource],
    context: AwsDecorationContext,
) -> tuple[NormalizedResource, ...]:
    unresolved: list[NormalizedResource] = []
    for resource in resources:
        if resource.resource_type != _S3_BUCKET_POLICY:
            continue
        if _resolved_bucket_policy_target(resource, context) is not None:
            continue
        target = aws_facts(resource).bucket_name
        if _is_exact_unmodeled_bucket_reference(target):
            continue
        unresolved.append(resource)
    return tuple(unresolved)


def _unresolved_policy_may_affect_bucket_role(
    source: NormalizedResource,
    bucket: NormalizedResource,
    role_arn: str,
    context: AwsDecorationContext,
) -> bool:
    modeled_target = _resolved_bucket_policy_target(source, context)
    if modeled_target is not None:
        return modeled_target.address == bucket.address
    target = aws_facts(source).bucket_name
    if _is_exact_unmodeled_bucket_reference(target):
        return False

    statement_documents = _raw_policy_statements(
        aws_facts(source).policy_document,
    )
    if statement_documents is None:
        return True
    if not any(_raw_statement_affects_delete_bucket(statement) is not False for statement in statement_documents):
        return False
    if not _bucket_policy_is_fully_representable(source):
        return True

    role_account_id = parse_aws_account_id(role_arn)
    if role_account_id is None:
        return True
    account_root_arn = f"arn:{_arn_partition(role_arn)}:iam::{role_account_id}:root"
    unresolved_resource = False
    for statement in source.policy_statements:
        if not _matching_action_patterns(statement.actions):
            continue
        principals = _aws_principal_values(statement)
        if not principals & {role_arn, role_account_id, account_root_arn, "*"}:
            continue
        for resource in statement.resources:
            applicability = _resource_targets_bucket(
                resource,
                bucket,
                (source,),
                context,
                exact_allow_required=False,
            )
            if applicability is True:
                return True
            if applicability is None:
                unresolved_resource = True
    return unresolved_resource


def _resolved_bucket_policy_target(
    source: NormalizedResource,
    context: AwsDecorationContext,
) -> NormalizedResource | None:
    target = aws_facts(source).bucket_name
    modeled_target = context.index.buckets.get(target, source=source) if target else None
    if modeled_target is not None:
        return modeled_target
    return symbolic_reference_target(
        source,
        context.index,
        "bucket",
        expected_resource_types={_S3_BUCKET},
        expected_reference_suffixes={".id", ".bucket", ".arn"},
    )


def _bucket_policy_is_fully_representable(
    source: NormalizedResource,
) -> bool:
    statement_documents = _raw_policy_statements(
        aws_facts(source).policy_document,
    )
    if not statement_documents:
        return False
    statements = source.policy_statements
    return bool(
        len(statements) == len(statement_documents)
        and all(
            policy_statement_is_fully_representable(
                raw_statement,
                statement,
                principal_mode="required",
            )
            for raw_statement, statement in zip(
                statement_documents,
                statements,
                strict=True,
            )
        )
    )


def _path(
    task_definition: NormalizedResource,
    task_role: NormalizedResource,
    role_reference: str,
    bucket: NormalizedResource,
    proof: _EffectiveProof,
    bucket_posture: _BucketPolicyPosture,
) -> AwsEcsS3BucketTopologyDestructionPath:
    bucket_arn = cast(str, bucket.arn)
    bucket_facts = aws_facts(bucket)
    recovery_uncertainties = dedupe(
        [
            *bucket_facts.s3_posture_uncertainties,
            f"{bucket.address}: plan-local S3 evidence does not establish that "
            "the bucket is empty of current objects, versions, and delete markers",
        ]
    )
    identity_sources = _identity_policy_sources(task_role)
    used_identity_sources = identity_sources if proof.identity_matches else []
    used_bucket_sources = dedupe(match.source_address for match in proof.bucket_matches)
    evidence_addresses = dedupe(
        value
        for value in (
            bucket.address,
            bucket_facts.s3_versioning_source_address,
            bucket_facts.s3_object_lock_source_address,
        )
        if value is not None
    )
    statements = [_statement_record(match) for match in (*proof.identity_matches, *proof.bucket_matches)]
    return {
        "workload_address": task_definition.address,
        "workload_type": task_definition.resource_type,
        "task_definition_address": task_definition.address,
        "task_definition_arn": task_definition.arn,
        "internet_facing_load_balancers": [],
        "role_kind": "ecs_task_role",
        "credential_context": "workload_runtime",
        "role_address": task_role.address,
        "role_reference": role_reference,
        "role_arn": task_role.arn,
        "same_account": True,
        "bucket_address": bucket.address,
        "bucket_name": _bucket_name(bucket, bucket_arn),
        "bucket_arn": bucket_arn,
        "operation": "s3:DeleteBucket",
        "operation_class": "bucket_deletion",
        "internal_operation": "delete_bucket",
        "management_effect": "disruption",
        "target_granularity": "bucket_topology",
        "target_scope": "exact_s3_bucket",
        "target_model_evidence_addresses": evidence_addresses,
        "authorization_source_addresses": dedupe([*used_identity_sources, *used_bucket_sources]),
        "authorization_bases": list(proof.bases),
        "authorization_state": "allowed",
        "evaluation_basis": "modeled_identity_and_bucket_policies",
        "matched_actions": ["s3:DeleteBucket"],
        "identity_policy_complete": True,
        "bucket_policy_complete": True,
        "identity_policy_source_addresses": identity_sources,
        "bucket_policy_source_addresses": list(
            bucket_posture.source_addresses,
        ),
        "authorization_statements": statements,
        "explicit_deny": False,
        "conditional_evaluation_required": False,
        "lifecycle_compatibility_state": "bucket_emptiness_not_established",
        "recovery_evidence": {
            "recovery_evidence_scope": ("s3_bucket_deletion_prerequisites_and_recovery"),
            "bucket_emptiness_required": True,
            "bucket_emptiness_state": "not_established",
            "versioning_status": bucket_facts.s3_versioning_status,
            "versioning_enabled": bucket_facts.s3_versioning_enabled,
            "object_lock_enabled": bucket_facts.s3_object_lock_enabled,
            "object_lock_default_retention_mode": (bucket_facts.s3_object_lock_default_retention_mode),
            "object_lock_default_retention_days": (bucket_facts.s3_object_lock_default_retention_days),
            "object_lock_default_retention_years": (bucket_facts.s3_object_lock_default_retention_years),
            "out_of_plan_object_inventory_evaluated": False,
            "attached_access_point_state": "not_established",
            "bucket_recovery_state": ("not_established_by_modeled_aws_s3_bucket_evidence"),
            "successful_deletion_observed": False,
            "recovery_observed": False,
            "uncertainties": recovery_uncertainties,
        },
        "posture_uncertainties": recovery_uncertainties,
    }


def _statement_record(
    match: _StatementMatch,
) -> AwsS3BucketTopologyPolicyStatementEvidence:
    if match.source_kind == "identity_policy":
        identity_record: AwsS3BucketTopologyIdentityPolicyStatementEvidence = {
            "source_address": match.source_address,
            "source_kind": "identity_policy",
            "effect": "allow",
            "actions": list(match.statement.actions),
            "matching_action_patterns": list(match.matching_action_patterns),
            "matched_actions": ["s3:DeleteBucket"],
            "resources": list(match.statement.resources),
            "matching_resources": [match.matching_resource],
            "resource_scopes": ["exact_bucket"],
            "principals": [],
            "principal_match": None,
            "conditions": [],
            "conditional": False,
        }
        return identity_record
    resource_record: AwsS3BucketTopologyResourcePolicyStatementEvidence = {
        "source_address": match.source_address,
        "source_kind": "bucket_policy",
        "effect": "allow",
        "actions": list(match.statement.actions),
        "matching_action_patterns": list(match.matching_action_patterns),
        "matched_actions": ["s3:DeleteBucket"],
        "resources": list(match.statement.resources),
        "matching_resources": [match.matching_resource],
        "resource_scopes": ["exact_bucket"],
        "principals": sorted(_aws_principal_values(match.statement)),
        "principal_match": cast(_PrincipalMatch, match.principal_match),
        "conditions": [],
        "conditional": False,
    }
    return resource_record


def current_s3_bucket_topology_destruction_path(
    task_definition: NormalizedResource,
    bucket: NormalizedResource,
    context: AwsDecorationContext,
) -> AwsEcsS3BucketTopologyDestructionPath | None:
    """Recompute the current deterministic path for one task and S3 bucket."""

    resources = tuple(context.index.resources_by_address.values())
    paths, _uncertainties = _task_definition_paths(
        task_definition,
        (bucket,),
        context,
        unresolved_policy_sources=_unresolved_bucket_policy_sources(
            resources,
            context,
        ),
    )
    return next(
        (path for path in paths if path["bucket_address"] == bucket.address and path["operation"] == _DELETE_BUCKET),
        None,
    )


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


def _identity_policy_resources(
    role: NormalizedResource,
    context: AwsDecorationContext,
) -> list[NormalizedResource]:
    resources = [role]
    facts = aws_facts(role)
    for address in (
        *facts.inline_policy_resource_addresses,
        *facts.attached_policy_addresses,
    ):
        source = context.index.resources_by_address.get(address)
        if source is not None:
            resources.append(source)
    return resources


def _identity_policy_sources(role: NormalizedResource) -> list[str]:
    facts = aws_facts(role)
    return dedupe(
        [
            role.address,
            *facts.inline_policy_resource_addresses,
            *facts.attached_policy_addresses,
        ]
    )


def _task_role_evidence_reference(
    task_definition: NormalizedResource,
    task_role: NormalizedResource,
) -> str | None:
    current = aws_facts(task_definition).task_role_arn
    if task_role.arn is not None and current == task_role.arn:
        return current
    for resolution in task_definition.reference_resolutions:
        if (
            resolution.path != ("task_role_arn",)
            or resolution.state != TerraformReferenceResolutionState.SYMBOLIC
            or resolution.provenance != TerraformReferenceProvenance.CONFIGURATION_REFERENCE
            or len(resolution.targets) != 1
        ):
            continue
        target = resolution.targets[0]
        if target.address == task_role.address and target.reference.endswith(".arn"):
            return target.reference
    return None


def _task_role_relationship_is_exact(
    task_definition: NormalizedResource,
    task_role: NormalizedResource,
    context: AwsDecorationContext,
) -> bool:
    reference = aws_facts(task_definition).task_role_arn
    if reference is None:
        return False
    if task_role.arn is not None and reference == task_role.arn:
        return True
    symbolic = symbolic_reference_target(
        task_definition,
        context.index,
        "task_role_arn",
        expected_resource_types={_IAM_ROLE},
        expected_reference_suffixes={".arn"},
    )
    return bool(symbolic is not None and symbolic.address == task_role.address and reference == task_role.address)


def _task_role_configuration_reference_observed(
    task_definition: NormalizedResource,
) -> bool:
    return any(
        resolution.path == ("task_role_arn",)
        and resolution.provenance == TerraformReferenceProvenance.CONFIGURATION_REFERENCE
        for resolution in task_definition.reference_resolutions
    )


def _task_role_resolution_uncertainties(
    task_definition: NormalizedResource,
) -> list[str]:
    uncertainties = [
        f"{task_definition.address}: task role reference {reference} is unresolved for S3 bucket-deletion paths"
        for reference in aws_facts(task_definition).unresolved_task_role_arns
    ]
    if any(
        resolution.path == ("task_role_arn",)
        and resolution.provenance == TerraformReferenceProvenance.CONFIGURATION_REFERENCE
        and resolution.state
        in {
            TerraformReferenceResolutionState.AMBIGUOUS,
            TerraformReferenceResolutionState.UNRESOLVED,
            TerraformReferenceResolutionState.UNSUPPORTED,
        }
        for resolution in task_definition.reference_resolutions
    ):
        uncertainties.append(
            f"{task_definition.address}: task role configuration reference is "
            "ambiguous or unresolved for S3 bucket-deletion paths"
        )
    return dedupe(uncertainties)


def _matching_action_patterns(
    patterns: Sequence[str],
) -> tuple[str, ...]:
    return tuple(pattern for pattern in patterns if fnmatchcase(_DELETE_BUCKET.casefold(), pattern.casefold()))


def _role_has_delete_bucket_action(role: NormalizedResource) -> bool:
    return any(_matching_action_patterns(statement.actions) for statement in role.policy_statements)


def _bucket_policy_may_apply_to_role(
    statements: Sequence[IAMPolicyStatement],
    role_arn: str,
) -> bool:
    role_account_id = parse_aws_account_id(role_arn)
    if role_account_id is None:
        return False
    account_root_arn = f"arn:{_arn_partition(role_arn)}:iam::{role_account_id}:root"
    return any(
        bool(_matching_action_patterns(statement.actions))
        and bool(_aws_principal_values(statement) & {role_arn, role_account_id, account_root_arn, "*"})
        for statement in statements
    )


def _normalized_effect(
    statement: IAMPolicyStatement,
) -> Literal["allow", "deny"] | None:
    effect = statement.effect.strip().casefold()
    if effect == "allow":
        return "allow"
    if effect == "deny":
        return "deny"
    return None


def _aws_principal_values(statement: IAMPolicyStatement) -> set[str]:
    return {entry.value for entry in statement.principal_entries if entry.kind.casefold() in {"aws", "unknown"}}


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


def _provider_account_id_for_bucket_role(
    resources: Sequence[NormalizedResource],
    role: NormalizedResource,
    bucket: NormalizedResource,
) -> str | None:
    provider_config_key = bucket.provider_config_key
    if provider_config_key is None or role.provider_config_key != provider_config_key:
        return None

    caller_identity_facts = [
        aws_facts(resource)
        for resource in resources
        if resource.resource_type == _CALLER_IDENTITY and resource.provider_config_key == provider_config_key
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

    # S3 bucket ARNs do not encode ownership. Other resource ARNs can identify
    # the role's account, but cannot prove that it owns the bucket.
    return None


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


def _bucket_name(bucket: NormalizedResource, bucket_arn: str) -> str:
    name = aws_facts(bucket).bucket_name
    if name:
        return name
    if isinstance(bucket.identifier, str) and bucket.identifier:
        return bucket.identifier
    return bucket_arn.rsplit(":::", 1)[-1]


def _has_policy_statements(document: Mapping[str, object]) -> bool:
    statements = document.get("Statement")
    return isinstance(statements, Mapping) or bool(isinstance(statements, list) and statements)


def _unwrap_reference(value: str) -> str:
    normalized = value.strip()
    if normalized.startswith("${") and normalized.endswith("}"):
        return normalized[2:-1].strip()
    return normalized


def _arn_partition(value: str) -> str | None:
    parts = value.split(":", 2)
    return parts[1] if len(parts) == 3 and parts[0] == "arn" else None


def _has_wildcard(value: str) -> bool:
    return "*" in value or "?" in value


def _service_path(
    service: NormalizedResource,
    task_definition: NormalizedResource,
    path: AwsEcsS3BucketTopologyDestructionPath,
) -> AwsEcsS3BucketTopologyDestructionPath:
    projected = path.copy()
    projected["workload_address"] = service.address
    projected["workload_type"] = service.resource_type
    projected["task_definition_address"] = task_definition.address
    projected["task_definition_arn"] = task_definition.arn
    projected["internet_facing_load_balancers"] = aws_facts(service).internet_facing_load_balancer_addresses
    return projected


def _path_sort_key(
    path: AwsEcsS3BucketTopologyDestructionPath,
) -> tuple[str, str]:
    return path["bucket_address"], path["role_address"]
