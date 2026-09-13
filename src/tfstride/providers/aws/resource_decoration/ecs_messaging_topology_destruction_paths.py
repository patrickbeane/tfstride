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
from tfstride.providers.aws.messaging_topology_destruction_evidence import (
    AwsEcsMessagingTopologyDestructionPath,
    AwsEcsMessagingTopologyDestructionPathCommon,
    AwsEcsSnsTopicDeletionPath,
    AwsEcsSqsQueueDeletionPath,
    AwsMessagingTopologyDestructionAuthorizationBasis,
    AwsMessagingTopologyDestructionOperation,
    AwsMessagingTopologyPolicyStatementEvidenceCommon,
    AwsSnsTopicDeletionPolicyStatementEvidence,
    AwsSqsQueueDeletionPolicyStatementEvidence,
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
_SQS_QUEUE = "aws_sqs_queue"
_SNS_TOPIC = "aws_sns_topic"
_COMPLETE = "complete"
_DELETE_QUEUE = "sqs:DeleteQueue"
_DELETE_TOPIC = "sns:DeleteTopic"
_PrincipalMatch = Literal["role", "account", "wildcard"]
_PolicySourceKind = Literal["identity_policy", "queue_policy", "topic_policy"]


@dataclass(frozen=True, slots=True)
class _OperationDefinition:
    service: Literal["sqs", "sns"]
    resource_type: Literal["aws_sqs_queue", "aws_sns_topic"]
    operation: AwsMessagingTopologyDestructionOperation
    policy_source_kind: Literal["queue_policy", "topic_policy"]
    direct_basis: Literal["queue_policy_direct", "topic_policy_direct"]


_OPERATION_DEFINITIONS = (
    _OperationDefinition(
        "sqs",
        _SQS_QUEUE,
        _DELETE_QUEUE,
        "queue_policy",
        "queue_policy_direct",
    ),
    _OperationDefinition(
        "sns",
        _SNS_TOPIC,
        _DELETE_TOPIC,
        "topic_policy",
        "topic_policy_direct",
    ),
)


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
class _ResourcePolicyPosture:
    source_addresses: tuple[str, ...]
    complete: bool
    uncertainties: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _EffectiveProof:
    bases: tuple[AwsMessagingTopologyDestructionAuthorizationBasis, ...]
    identity_matches: tuple[_StatementMatch, ...]
    resource_matches: tuple[_StatementMatch, ...]


@dataclass(frozen=True, slots=True)
class _AuthorizationEvaluation:
    proof: _EffectiveProof | None
    uncertainties: tuple[str, ...]


class ModelEcsMessagingTopologyDestructionPathsStage:
    """Model effective ECS task-role authority to delete SQS/SNS topology."""

    name = "model_ecs_messaging_topology_destruction_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AwsDecorationContext,
    ) -> None:
        targets = tuple(resource for resource in resources if resource.resource_type in {_SQS_QUEUE, _SNS_TOPIC})
        for task_definition in resources:
            if task_definition.resource_type != _ECS_TASK_DEFINITION:
                continue
            paths, uncertainties = _task_definition_paths(
                task_definition,
                targets,
                context,
            )
            facts = aws_facts(task_definition)
            facts.set_ecs_messaging_topology_destruction_paths(paths)
            facts.extend_ecs_messaging_topology_destruction_path_uncertainties(
                uncertainties,
            )


class ProjectEcsMessagingTopologyDestructionPathsOntoServicesStage:
    name = "project_ecs_messaging_topology_destruction_paths_onto_services"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AwsDecorationContext,
    ) -> None:
        for service in resources:
            if service.resource_type != _ECS_SERVICE:
                continue
            service_facts = aws_facts(service)
            paths: list[AwsEcsMessagingTopologyDestructionPath] = []
            uncertainties = [
                f"{service.address}: task definition reference {reference} is "
                "unresolved for messaging topology-deletion path projection"
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
                        f"{task_definition_address} is unavailable for messaging "
                        "topology-deletion path projection"
                    )
                    continue
                task_facts = aws_facts(task_definition)
                uncertainties.extend(
                    task_facts.ecs_messaging_topology_destruction_path_uncertainties,
                )
                paths.extend(
                    _service_path(service, task_definition, path)
                    for path in (task_facts.ecs_messaging_topology_destruction_paths)
                )
            paths.sort(key=_path_sort_key)
            service_facts.set_ecs_messaging_topology_destruction_paths(paths)
            service_facts.extend_ecs_messaging_topology_destruction_path_uncertainties(
                dedupe(uncertainties),
            )


def _task_definition_paths(
    task_definition: NormalizedResource,
    targets: Sequence[NormalizedResource],
    context: AwsDecorationContext,
) -> tuple[list[AwsEcsMessagingTopologyDestructionPath], list[str]]:
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
                    "ambiguous or unresolved for messaging topology-deletion paths"
                ],
            )
        return (
            [],
            [
                f"{task_definition.address}: ECS task role {task_role_reference} "
                "is not modeled for messaging topology-deletion paths"
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
                "has no exact IAM role ARN for messaging topology ownership "
                "compatibility"
            ],
        )
    role_arn = cast(str, task_role.arn)

    identity_policy_complete = _identity_policy_complete(task_role)
    uncertainties: list[str] = []
    if not identity_policy_complete and _role_has_topology_operation(task_role):
        uncertainties.append(
            f"{task_definition.address}: {task_role.address} messaging topology-"
            "deletion authorization is unresolved because identity-policy "
            "evidence is incomplete"
        )
        uncertainties.extend(
            f"{task_definition.address}: {task_role.address}: {uncertainty}"
            for uncertainty in aws_facts(task_role).iam_policy_posture_uncertainties
        )

    paths: list[AwsEcsMessagingTopologyDestructionPath] = []
    for target in targets:
        definition = _definition_for_target(target)
        if definition is None:
            continue
        target_arn = target.arn
        if not _exact_target_arn(target_arn, definition):
            if _role_has_operation(task_role, definition.operation) or (
                _resource_policy_may_apply_to_role(
                    target.policy_statements,
                    role_arn,
                    definition.operation,
                )
            ):
                uncertainties.append(
                    f"{task_definition.address}: {target.address} has no exact "
                    "messaging resource ARN for topology-deletion path matching"
                )
            continue
        assert target_arn is not None

        same_account, partitions_match = _account_relationship(
            role_arn,
            target_arn,
        )
        if same_account is not True or not partitions_match:
            # Queue and topic deletion are owner-account operations. Exact
            # cross-account evidence is incompatible, not uncertain.
            continue

        posture = _resource_policy_posture(target, definition)
        identity_matches = _identity_policy_matches(
            task_role,
            target,
            definition,
            context,
        )
        resource_matches = _resource_policy_matches(
            target,
            role_arn,
            definition,
            context,
        )
        operation_evidence = bool(
            identity_matches.matches
            or resource_matches.matches
            or identity_matches.unresolved_allow
            or identity_matches.unresolved_deny
            or resource_matches.unresolved_allow
            or resource_matches.unresolved_deny
        )
        if not operation_evidence:
            continue

        uncertainties.extend(f"{task_definition.address}: {uncertainty}" for uncertainty in posture.uncertainties)
        evaluation = _evaluate_authorization(
            target,
            task_role,
            definition,
            identity_matches=identity_matches,
            resource_matches=resource_matches,
            identity_policy_complete=identity_policy_complete,
            resource_policy_complete=posture.complete,
        )
        uncertainties.extend(f"{task_definition.address}: {uncertainty}" for uncertainty in evaluation.uncertainties)
        if evaluation.proof is None:
            continue
        paths.append(
            _path(
                task_definition,
                task_role,
                role_reference,
                target,
                definition,
                evaluation.proof,
                posture,
            )
        )

    paths.sort(key=_path_sort_key)
    return paths, dedupe(uncertainties)


def _evaluate_authorization(
    target: NormalizedResource,
    role: NormalizedResource,
    definition: _OperationDefinition,
    *,
    identity_matches: _PolicyMatches,
    resource_matches: _PolicyMatches,
    identity_policy_complete: bool,
    resource_policy_complete: bool,
) -> _AuthorizationEvaluation:
    matches = (*identity_matches.matches, *resource_matches.matches)
    denies = [match for match in matches if match.effect == "deny"]
    if any(not match.conditional for match in denies):
        return _AuthorizationEvaluation(None, ())
    if any(match.conditional for match in denies):
        return _AuthorizationEvaluation(
            None,
            (
                f"{target.address}: {role.address} {definition.operation} has "
                "condition-dependent explicit-deny evidence",
            ),
        )
    if identity_matches.unresolved_deny or resource_matches.unresolved_deny:
        return _AuthorizationEvaluation(
            None,
            (
                f"{target.address}: {role.address} {definition.operation} has "
                "ambiguous or unresolved explicit-deny scope",
            ),
        )

    identity_allows = [match for match in identity_matches.matches if match.effect == "allow" and not match.conditional]
    resource_allows = [
        match
        for match in resource_matches.matches
        if match.effect == "allow" and not match.conditional and match.principal_match in {"role", "wildcard"}
    ]
    candidate_observed = bool(
        identity_allows
        or resource_allows
        or identity_matches.unresolved_allow
        or resource_matches.unresolved_allow
        or any(match.effect == "allow" for match in matches)
    )
    if not candidate_observed:
        return _AuthorizationEvaluation(None, ())

    if not identity_policy_complete or not resource_policy_complete:
        incomplete_surfaces: list[str] = []
        if not identity_policy_complete:
            incomplete_surfaces.append("identity policy")
        if not resource_policy_complete:
            incomplete_surfaces.append("queue policy" if definition.service == "sqs" else "topic policy")
        return _AuthorizationEvaluation(
            None,
            (
                f"{target.address}: {role.address} {definition.operation} "
                "authorization is unresolved because "
                f"{' and '.join(incomplete_surfaces)} evidence is incomplete",
            ),
        )

    if identity_allows or resource_allows:
        bases: list[AwsMessagingTopologyDestructionAuthorizationBasis] = []
        if identity_allows:
            bases.append("identity_policy")
        if resource_allows:
            bases.append(definition.direct_basis)
        return _AuthorizationEvaluation(
            _EffectiveProof(
                tuple(bases),
                tuple(identity_allows),
                tuple(resource_allows),
            ),
            (),
        )

    if identity_matches.unresolved_allow or resource_matches.unresolved_allow:
        return _AuthorizationEvaluation(
            None,
            (
                f"{target.address}: {role.address} {definition.operation} allow "
                "evidence does not identify an exact messaging resource scope",
            ),
        )
    if any(match.effect == "allow" and match.conditional for match in matches):
        return _AuthorizationEvaluation(
            None,
            (
                f"{target.address}: {role.address} {definition.operation} "
                "authorization depends on runtime policy conditions",
            ),
        )
    return _AuthorizationEvaluation(None, ())


def _identity_policy_matches(
    role: NormalizedResource,
    target: NormalizedResource,
    definition: _OperationDefinition,
    context: AwsDecorationContext,
) -> _PolicyMatches:
    matches: list[_StatementMatch] = []
    unresolved_allow = False
    unresolved_deny = False
    sources = _identity_policy_resources(role, context)
    for statement in role.policy_statements:
        effect = _normalized_effect(statement)
        if effect is None:
            continue
        action_patterns = _matching_action_patterns(
            statement.actions,
            definition.operation,
        )
        if not action_patterns:
            continue
        for resource in statement.resources:
            applicability = _resource_targets(
                resource,
                target,
                definition,
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


def _resource_policy_matches(
    target: NormalizedResource,
    role_arn: str,
    definition: _OperationDefinition,
    context: AwsDecorationContext,
) -> _PolicyMatches:
    role_account_id = parse_aws_account_id(role_arn)
    if role_account_id is None:
        return _PolicyMatches((), False, True)
    account_root_arn = f"arn:{_arn_partition(role_arn)}:iam::{role_account_id}:root"
    matches: list[_StatementMatch] = []
    unresolved_allow = False
    unresolved_deny = False
    for statement in target.policy_statements:
        effect = _normalized_effect(statement)
        if effect is None:
            continue
        principals = _aws_principal_values(statement)
        direct_principal = role_arn in principals
        account_principal = bool(principals & {role_account_id, account_root_arn})
        wildcard_principal = "*" in principals
        if not (direct_principal or account_principal or wildcard_principal):
            continue
        principal_match: _PrincipalMatch = (
            "role" if direct_principal else "account" if account_principal else "wildcard"
        )
        action_patterns = _matching_action_patterns(
            statement.actions,
            definition.operation,
        )
        if not action_patterns:
            continue
        for resource in statement.resources:
            applicability = _resource_targets(
                resource,
                target,
                definition,
                (target,),
                context,
                exact_allow_required=effect == "allow",
            )
            if applicability is True:
                matches.append(
                    _StatementMatch(
                        statement,
                        target.address,
                        definition.policy_source_kind,
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


def _resource_targets(
    resource: str,
    target: NormalizedResource,
    definition: _OperationDefinition,
    sources: Sequence[NormalizedResource],
    context: AwsDecorationContext,
    *,
    exact_allow_required: bool,
) -> bool | None:
    target_arn = target.arn
    assert target_arn is not None
    normalized = _unwrap_reference(resource)
    if normalized == target_arn:
        return True
    if normalized.startswith("arn:"):
        if _has_wildcard(normalized):
            if exact_allow_required:
                return None if _arn_pattern_targets_service(normalized, definition.service) else False
            return fnmatchcase(target_arn, normalized)
        return False

    candidates: set[str] = set()
    uncertain = False
    for source in sources:
        assessment = assess_symbolic_reference(
            source,
            context.index,
            normalized,
            expected_resource_types={definition.resource_type},
            expected_reference_suffixes={".arn"},
        )
        if assessment.state == "resolved" and assessment.target is not None:
            candidates.add(assessment.target.address)
        elif assessment.state == "uncertain":
            uncertain = True
    if uncertain or len(candidates) > 1:
        return None
    if candidates:
        return candidates == {target.address}

    if normalized == "*":
        return None if exact_allow_required else True
    if _has_wildcard(normalized):
        return None
    return False


def _resource_policy_posture(
    target: NormalizedResource,
    definition: _OperationDefinition,
) -> _ResourcePolicyPosture:
    facts = aws_facts(target)
    if definition.service == "sqs":
        state = facts.sqs_queue_policy_state
        normalized_uncertainties = facts.sqs_queue_policy_uncertainties
        label = "SQS queue"
    else:
        state = facts.sns_topic_policy_state
        normalized_uncertainties = facts.sns_topic_policy_uncertainties
        label = "SNS topic"

    if state == "not_configured":
        return _ResourcePolicyPosture((), True, ())
    if state != "configured":
        uncertainties = normalized_uncertainties or [f"inline {label} policy is unknown or malformed"]
        return _ResourcePolicyPosture(
            (),
            False,
            tuple(f"{target.address}: {value}" for value in uncertainties),
        )

    complete, uncertainties = _configured_resource_policy_is_complete(
        target,
        definition,
    )
    return _ResourcePolicyPosture(
        (target.address,),
        complete,
        tuple(uncertainties),
    )


def _configured_resource_policy_is_complete(
    target: NormalizedResource,
    definition: _OperationDefinition,
) -> tuple[bool, list[str]]:
    document = aws_facts(target).policy_document
    raw_statements = document.get("Statement")
    if isinstance(raw_statements, Mapping):
        statement_documents: list[Mapping[str, object]] = [raw_statements]
    elif isinstance(raw_statements, list) and all(isinstance(statement, Mapping) for statement in raw_statements):
        statement_documents = [statement for statement in raw_statements if isinstance(statement, Mapping)]
    else:
        return (
            False,
            [f"{target.address}: inline {definition.service.upper()} policy has an unsupported statement shape"],
        )

    incomplete = False
    statements = target.policy_statements
    if len(statements) != len(statement_documents):
        for raw_statement in statement_documents:
            affected = _raw_statement_affects_operation(
                raw_statement,
                definition.operation,
            )
            if affected is not False:
                incomplete = True
                break
    else:
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
            affected = _raw_statement_affects_operation(
                raw_statement,
                definition.operation,
            )
            if affected is not False:
                incomplete = True
                break

    if not incomplete:
        return True, []
    return (
        False,
        [
            f"{target.address}: inline {definition.service.upper()} policy "
            "evidence is incomplete or unsupported for "
            f"{definition.operation}"
        ],
    )


def _raw_statement_affects_operation(
    statement: Mapping[str, object],
    operation: AwsMessagingTopologyDestructionOperation,
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
    return any(fnmatchcase(operation.casefold(), action.casefold()) for action in actions)


def _path(
    task_definition: NormalizedResource,
    role: NormalizedResource,
    role_reference: str,
    target: NormalizedResource,
    definition: _OperationDefinition,
    proof: _EffectiveProof,
    posture: _ResourcePolicyPosture,
) -> AwsEcsMessagingTopologyDestructionPath:
    common = _path_common(
        task_definition,
        role,
        role_reference,
        target,
        posture,
    )
    target_arn = cast(str, target.arn)
    target_name = _target_name(target, target_arn)
    if definition.service == "sqs":
        statements = [_queue_statement_record(match) for match in _proof_matches(proof)]
        queue_path: AwsEcsSqsQueueDeletionPath = {
            **common,
            "messaging_service": "sqs",
            "operation": "sqs:DeleteQueue",
            "operation_class": "queue_deletion",
            "internal_operation": "delete_queue",
            "target_granularity": "queue_topology",
            "target_scope": "exact_sqs_queue",
            "queue_address": target.address,
            "queue_name": target_name,
            "queue_arn": target_arn,
            "queue_url": aws_facts(target).sqs_queue_url,
            "topic_address": None,
            "topic_name": None,
            "topic_arn": None,
            "authorization_bases": cast(
                list[Literal["identity_policy", "queue_policy_direct"]],
                list(proof.bases),
            ),
            "matched_actions": ["sqs:DeleteQueue"],
            "authorization_statements": statements,
        }
        return queue_path

    statements = [_topic_statement_record(match) for match in _proof_matches(proof)]
    topic_path: AwsEcsSnsTopicDeletionPath = {
        **common,
        "messaging_service": "sns",
        "operation": "sns:DeleteTopic",
        "operation_class": "topic_deletion",
        "internal_operation": "delete_topic",
        "target_granularity": "topic_topology",
        "target_scope": "exact_sns_topic",
        "queue_address": None,
        "queue_name": None,
        "queue_arn": None,
        "queue_url": None,
        "topic_address": target.address,
        "topic_name": target_name,
        "topic_arn": target_arn,
        "authorization_bases": cast(
            list[Literal["identity_policy", "topic_policy_direct"]],
            list(proof.bases),
        ),
        "matched_actions": ["sns:DeleteTopic"],
        "authorization_statements": statements,
    }
    return topic_path


def _path_common(
    task_definition: NormalizedResource,
    role: NormalizedResource,
    role_reference: str,
    target: NormalizedResource,
    posture: _ResourcePolicyPosture,
) -> AwsEcsMessagingTopologyDestructionPathCommon:
    role_arn = cast(str, role.arn)
    target_arn = cast(str, target.arn)
    authorization_sources = dedupe(
        [
            *_identity_policy_sources(role),
            *posture.source_addresses,
        ]
    )
    return {
        "workload_address": task_definition.address,
        "workload_type": task_definition.resource_type,
        "task_definition_address": task_definition.address,
        "task_definition_arn": task_definition.arn,
        "internet_facing_load_balancers": [],
        "role_kind": "ecs_task_role",
        "credential_context": "workload_runtime",
        "role_address": role.address,
        "role_reference": role_reference,
        "role_arn": role_arn,
        "same_account": True,
        "messaging_resource_address": target.address,
        "messaging_resource_type": target.resource_type,
        "messaging_resource_name": _target_name(target, target_arn),
        "messaging_resource_arn": target_arn,
        "target_model_evidence_addresses": [target.address],
        "management_effect": "disruption",
        "authorization_source_addresses": authorization_sources,
        "evaluation_basis": "modeled_identity_and_messaging_resource_policies",
        "authorization_state": "allowed",
        "identity_policy_complete": True,
        "resource_policy_complete": True,
        "explicit_deny": False,
        "conditional_evaluation_required": False,
        "lifecycle_compatibility_state": "compatible",
        "outcome_evidence": {
            "outcome_evidence_scope": ("plan_local_messaging_topology_deletion_authority"),
            "successful_deletion_observed": False,
            "recovery_state": ("not_established_by_modeled_aws_messaging_topology_evidence"),
            "descendant_impact_evaluated": False,
            "out_of_plan_topology_evaluated": False,
            "uncertainties": [],
        },
        "posture_uncertainties": [],
    }


def _proof_matches(proof: _EffectiveProof) -> tuple[_StatementMatch, ...]:
    return (*proof.identity_matches, *proof.resource_matches)


def _statement_common(
    match: _StatementMatch,
) -> AwsMessagingTopologyPolicyStatementEvidenceCommon:
    return {
        "source_address": match.source_address,
        "effect": "allow",
        "actions": list(match.statement.actions),
        "matching_action_patterns": list(match.matching_action_patterns),
        "resources": list(match.statement.resources),
        "matching_resources": [match.matching_resource],
        "principals": sorted(_aws_principal_values(match.statement)),
        "principal_match": match.principal_match,
        "conditions": [],
        "conditional": False,
    }


def _queue_statement_record(
    match: _StatementMatch,
) -> AwsSqsQueueDeletionPolicyStatementEvidence:
    common = _statement_common(match)
    return {
        **common,
        "source_kind": cast(
            Literal["identity_policy", "queue_policy"],
            match.source_kind,
        ),
        "matched_actions": ["sqs:DeleteQueue"],
        "resource_scopes": ["exact_queue"],
    }


def _topic_statement_record(
    match: _StatementMatch,
) -> AwsSnsTopicDeletionPolicyStatementEvidence:
    common = _statement_common(match)
    return {
        **common,
        "source_kind": cast(
            Literal["identity_policy", "topic_policy"],
            match.source_kind,
        ),
        "matched_actions": ["sns:DeleteTopic"],
        "resource_scopes": ["exact_topic"],
    }


def _definition_for_target(
    target: NormalizedResource,
) -> _OperationDefinition | None:
    return next(
        (definition for definition in _OPERATION_DEFINITIONS if definition.resource_type == target.resource_type),
        None,
    )


def current_messaging_topology_destruction_path(
    task_definition: NormalizedResource,
    target: NormalizedResource,
    operation: AwsMessagingTopologyDestructionOperation,
    context: AwsDecorationContext,
) -> AwsEcsMessagingTopologyDestructionPath | None:
    """Recompute the current deterministic path for one task and target."""

    definition = _definition_for_target(target)
    if definition is None or definition.operation != operation:
        return None

    paths, _uncertainties = _task_definition_paths(
        task_definition,
        (target,),
        context,
    )
    return next(
        (
            path
            for path in paths
            if path["operation"] == operation and path["messaging_resource_address"] == target.address
        ),
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
        f"{task_definition.address}: task role reference {reference} is "
        "unresolved for messaging topology-deletion paths"
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
            "ambiguous or unresolved for messaging topology-deletion paths"
        )
    return dedupe(uncertainties)


def _matching_action_patterns(
    patterns: Sequence[str],
    operation: AwsMessagingTopologyDestructionOperation,
) -> tuple[str, ...]:
    return tuple(pattern for pattern in patterns if fnmatchcase(operation.casefold(), pattern.casefold()))


def _role_has_topology_operation(role: NormalizedResource) -> bool:
    return any(_role_has_operation(role, definition.operation) for definition in _OPERATION_DEFINITIONS)


def _role_has_operation(
    role: NormalizedResource,
    operation: AwsMessagingTopologyDestructionOperation,
) -> bool:
    return any(_matching_action_patterns(statement.actions, operation) for statement in role.policy_statements)


def _resource_policy_may_apply_to_role(
    statements: Sequence[IAMPolicyStatement],
    role_arn: str,
    operation: AwsMessagingTopologyDestructionOperation,
) -> bool:
    account_id = parse_aws_account_id(role_arn)
    if account_id is None:
        return False
    root_arn = f"arn:{_arn_partition(role_arn)}:iam::{account_id}:root"
    return any(
        bool(_matching_action_patterns(statement.actions, operation))
        and bool(_aws_principal_values(statement) & {role_arn, account_id, root_arn, "*"})
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
    target_arn: str,
) -> tuple[bool | None, bool]:
    role_account = parse_aws_account_id(role_arn)
    target_account = parse_aws_account_id(target_arn)
    if role_account is None or target_account is None:
        return None, _arn_partition(role_arn) == _arn_partition(target_arn)
    return (
        role_account == target_account,
        _arn_partition(role_arn) == _arn_partition(target_arn),
    )


def _arn_pattern_targets_service(
    value: str,
    service: Literal["sqs", "sns"],
) -> bool:
    parts = value.split(":", 5)
    return bool(len(parts) == 6 and parts[0] == "arn" and parts[2].casefold() == service)


def _exact_target_arn(
    value: str | None,
    definition: _OperationDefinition,
) -> bool:
    if not value or _has_wildcard(value):
        return False
    parts = value.split(":", 5)
    if not (
        len(parts) == 6
        and parts[0] == "arn"
        and parts[1]
        and parts[2] == definition.service
        and parts[3]
        and parse_aws_account_id(value) is not None
        and parts[5]
    ):
        return False
    return "/" not in parts[5] and (definition.service != "sns" or ":" not in parts[5])


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


def _target_name(target: NormalizedResource, target_arn: str) -> str:
    if isinstance(target.identifier, str) and target.identifier:
        return target.identifier
    return target_arn.rsplit(":", 1)[-1]


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
    path: AwsEcsMessagingTopologyDestructionPath,
) -> AwsEcsMessagingTopologyDestructionPath:
    projected = path.copy()
    projected["workload_address"] = service.address
    projected["workload_type"] = service.resource_type
    projected["task_definition_address"] = task_definition.address
    projected["task_definition_arn"] = task_definition.arn
    projected["internet_facing_load_balancers"] = aws_facts(service).internet_facing_load_balancer_addresses
    return projected


def _path_sort_key(
    path: AwsEcsMessagingTopologyDestructionPath,
) -> tuple[str, str, str]:
    return (
        path["messaging_resource_address"],
        path["operation"],
        path["role_address"],
    )
