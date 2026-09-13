from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Literal, cast

from tfstride.models import IAMPolicyStatement, NormalizedResource
from tfstride.providers.aws.message_removal_evidence import (
    AwsEcsSqsMessageRemovalPath,
    AwsEcsSqsMessageRemovalPathCommon,
    AwsEcsSqsQueueMessagePurgePath,
    AwsEcsSqsReceivedMessageDeletionPath,
    AwsSqsDeleteMessageAuthorizationProof,
    AwsSqsDeterministicAuthorizationProofCommon,
    AwsSqsMessageRemovalAuthorizationBasis,
    AwsSqsMessageRemovalAuthorizationOperation,
    AwsSqsMessageRemovalAuthorizationProof,
    AwsSqsMessageRemovalDeliveryEvidence,
    AwsSqsMessageRemovalPolicyStatementEvidence,
    AwsSqsPurgeQueueAuthorizationProof,
    AwsSqsReceiveAuthorizationProof,
)
from tfstride.providers.aws.policy_documents import policy_statement_is_fully_representable
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.coercion import dedupe
from tfstride.resource_helpers import parse_aws_account_id

_ECS_TASK_DEFINITION = "aws_ecs_task_definition"
_ECS_SERVICE = "aws_ecs_service"
_SQS_QUEUE = "aws_sqs_queue"
_COMPLETE = "complete"
_RECEIVE = "sqs:ReceiveMessage"
_DELETE = "sqs:DeleteMessage"
_PURGE = "sqs:PurgeQueue"
_OPERATION_ORDER: tuple[AwsSqsMessageRemovalAuthorizationOperation, ...] = (
    _RECEIVE,
    _DELETE,
    _PURGE,
)
_AUTHORIZATION_BASIS_ORDER: tuple[AwsSqsMessageRemovalAuthorizationBasis, ...] = (
    "identity_policy",
    "queue_policy_direct",
    "cross_account_identity_and_queue_policy",
)
_PrincipalMatch = Literal["role", "account", "wildcard"]


@dataclass(frozen=True, slots=True)
class _StatementMatch:
    statement: IAMPolicyStatement
    operation: AwsSqsMessageRemovalAuthorizationOperation
    source_address: str
    source_kind: Literal["identity_policy", "queue_policy"]
    effect: Literal["allow", "deny"]
    matching_action_patterns: tuple[str, ...]
    matching_resource: str
    principal_match: _PrincipalMatch | None = None

    @property
    def conditional(self) -> bool:
        return bool(self.statement.conditions)


@dataclass(frozen=True, slots=True)
class _QueuePolicyPosture:
    source_addresses: tuple[str, ...]
    incomplete_operations: frozenset[AwsSqsMessageRemovalAuthorizationOperation]
    uncertainties: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _EffectiveProof:
    bases: tuple[AwsSqsMessageRemovalAuthorizationBasis, ...]
    identity_matches: tuple[_StatementMatch, ...]
    queue_matches: tuple[_StatementMatch, ...]


@dataclass(frozen=True, slots=True)
class _AuthorizationEvaluation:
    proof: _EffectiveProof | None
    uncertainties: tuple[str, ...]


class ModelEcsSqsMessageRemovalPathsStage:
    """Model effective ECS task-role authority for deterministic SQS removal."""

    name = "model_ecs_sqs_message_removal_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AwsDecorationContext,
    ) -> None:
        queues = tuple(resource for resource in resources if resource.resource_type == _SQS_QUEUE)
        for task_definition in resources:
            if task_definition.resource_type != _ECS_TASK_DEFINITION:
                continue
            paths, uncertainties = _task_definition_paths(
                task_definition,
                queues,
                context,
            )
            facts = aws_facts(task_definition)
            facts.set_ecs_sqs_message_removal_paths(paths)
            facts.extend_ecs_sqs_message_removal_path_uncertainties(uncertainties)


class ProjectEcsSqsMessageRemovalPathsOntoServicesStage:
    name = "project_ecs_sqs_message_removal_paths_onto_services"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AwsDecorationContext,
    ) -> None:
        for service in resources:
            if service.resource_type != _ECS_SERVICE:
                continue
            service_facts = aws_facts(service)
            paths: list[AwsEcsSqsMessageRemovalPath] = []
            uncertainties = [
                f"{service.address}: task definition reference {reference} is unresolved "
                "for SQS message-removal path projection"
                for reference in service_facts.unresolved_task_definition_references
            ]
            for task_definition_address in service_facts.resolved_task_definition_addresses:
                task_definition = context.index.ecs_task_definitions.get(task_definition_address, source=service)
                if task_definition is None:
                    uncertainties.append(
                        f"{service.address}: resolved task definition {task_definition_address} "
                        "is unavailable for SQS message-removal path projection"
                    )
                    continue
                task_facts = aws_facts(task_definition)
                uncertainties.extend(task_facts.ecs_sqs_message_removal_path_uncertainties)
                paths.extend(
                    _service_path(service, task_definition, path) for path in task_facts.ecs_sqs_message_removal_paths
                )
            service_facts.set_ecs_sqs_message_removal_paths(paths)
            service_facts.extend_ecs_sqs_message_removal_path_uncertainties(dedupe(uncertainties))


def _task_definition_paths(
    task_definition: NormalizedResource,
    queues: Sequence[NormalizedResource],
    context: AwsDecorationContext,
) -> tuple[list[AwsEcsSqsMessageRemovalPath], list[str]]:
    task_facts = aws_facts(task_definition)
    task_role_reference = task_facts.task_role_arn
    if not task_role_reference:
        return (
            [],
            [
                f"{task_definition.address}: ECS task role {reference} is unresolved "
                "for SQS message-removal path modeling"
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
                f"{task_definition.address}: ECS task role {task_role.address} has no exact "
                "IAM role ARN for SQS message-removal path matching"
            ],
        )
    assert task_role.arn is not None

    identity_policy_complete = _identity_policy_complete(task_role)
    uncertainties: list[str] = []
    if not identity_policy_complete:
        role_facts = aws_facts(task_role)
        uncertainties.append(
            f"{task_definition.address}: {task_role.address} SQS message-removal "
            "authorization is unresolved because identity-policy evidence is incomplete"
        )
        uncertainties.extend(
            f"{task_definition.address}: {task_role.address}: {uncertainty}"
            for uncertainty in role_facts.iam_policy_posture_uncertainties
        )

    paths: list[AwsEcsSqsMessageRemovalPath] = []
    role_has_modeled_action = _has_modeled_action_pattern(task_role.policy_statements)
    for queue in queues:
        queue_arn = queue.arn
        if not _is_exact_sqs_queue_arn(queue_arn):
            if role_has_modeled_action or _queue_policy_may_apply_to_role(
                queue.policy_statements,
                task_role.arn,
            ):
                uncertainties.append(
                    f"{task_definition.address}: SQS queue {queue.address} has no exact ARN "
                    "for message-removal path matching"
                )
            continue
        assert queue_arn is not None

        queue_posture = _queue_policy_posture(queue)
        identity_matches, identity_unresolved = _identity_policy_matches(
            task_role,
            queue,
            context,
        )
        queue_matches, queue_unresolved = _queue_policy_matches(
            queue,
            task_role.arn,
            context,
        )
        operation_evidence = any(
            match.operation in {_DELETE, _PURGE} for match in (*identity_matches, *queue_matches)
        ) or bool(({_DELETE, _PURGE} & identity_unresolved) or ({_DELETE, _PURGE} & queue_unresolved))
        if not operation_evidence:
            continue

        uncertainties.extend(f"{task_definition.address}: {message}" for message in queue_posture.uncertainties)
        same_account, partitions_match = _account_relationship(task_role.arn, queue_arn)
        evaluations: dict[
            AwsSqsMessageRemovalAuthorizationOperation,
            _AuthorizationEvaluation,
        ] = {}
        for operation in _OPERATION_ORDER:
            evaluation = _evaluate_authorization(
                queue,
                task_role,
                operation,
                identity_matches=identity_matches,
                queue_matches=queue_matches,
                identity_policy_complete=(identity_policy_complete and operation not in identity_unresolved),
                queue_policy_complete=(
                    operation not in queue_posture.incomplete_operations and operation not in queue_unresolved
                ),
                same_account=same_account,
                partitions_match=partitions_match,
            )
            evaluations[operation] = evaluation
            uncertainties.extend(
                f"{task_definition.address}: {uncertainty}" for uncertainty in evaluation.uncertainties
            )

        delete_evaluation = evaluations[_DELETE]
        receive_evaluation = evaluations[_RECEIVE]
        if delete_evaluation.proof is not None:
            if receive_evaluation.proof is None:
                if not receive_evaluation.uncertainties:
                    uncertainties.append(
                        f"{task_definition.address}: {task_role.address} has deterministic "
                        f"{_DELETE} authority for {queue.address}, but {_RECEIVE} authority "
                        "is not established for the receipt-handle prerequisite"
                    )
            else:
                paths.append(
                    _delete_path(
                        task_definition,
                        task_role,
                        queue,
                        receive_evaluation.proof,
                        delete_evaluation.proof,
                        queue_posture,
                        same_account=cast(bool, same_account),
                    )
                )

        purge_evaluation = evaluations[_PURGE]
        if purge_evaluation.proof is not None:
            paths.append(
                _purge_path(
                    task_definition,
                    task_role,
                    queue,
                    purge_evaluation.proof,
                    queue_posture,
                    same_account=cast(bool, same_account),
                )
            )

    paths.sort(key=_path_sort_key)
    return paths, dedupe(uncertainties)


def _evaluate_authorization(
    queue: NormalizedResource,
    role: NormalizedResource,
    operation: AwsSqsMessageRemovalAuthorizationOperation,
    *,
    identity_matches: Sequence[_StatementMatch],
    queue_matches: Sequence[_StatementMatch],
    identity_policy_complete: bool,
    queue_policy_complete: bool,
    same_account: bool | None,
    partitions_match: bool,
) -> _AuthorizationEvaluation:
    operation_identity = [match for match in identity_matches if match.operation == operation]
    operation_queue = [match for match in queue_matches if match.operation == operation]
    identity_allows = [match for match in operation_identity if match.effect == "allow"]
    queue_allows = [match for match in operation_queue if match.effect == "allow"]
    all_denies = [match for match in (*operation_identity, *operation_queue) if match.effect == "deny"]

    if not identity_allows and not queue_allows:
        return _AuthorizationEvaluation(None, ())
    if same_account is None:
        return _AuthorizationEvaluation(
            None,
            (
                f"{queue.address}: {role.address} {operation} authorization is unresolved "
                "because the role or queue account is not exact",
            ),
        )
    if not partitions_match:
        return _AuthorizationEvaluation(
            None,
            (
                f"{queue.address}: {role.address} {operation} authorization uses "
                "cross-partition SQS policy semantics that are not modeled",
            ),
        )

    unconditional_denies = [match for match in all_denies if not match.conditional]
    if unconditional_denies:
        return _AuthorizationEvaluation(None, ())
    conditional_denies = [match for match in all_denies if match.conditional]
    if conditional_denies:
        return _AuthorizationEvaluation(
            None,
            (f"{queue.address}: {role.address} {operation} has condition-dependent explicit-deny evidence",),
        )

    unconditional_identity = [match for match in identity_allows if not match.conditional]
    unconditional_queue = [
        match for match in queue_allows if not match.conditional and match.principal_match in {"role", "wildcard"}
    ]
    account_queue = [match for match in queue_allows if not match.conditional and match.principal_match == "account"]

    proof: _EffectiveProof | None = None
    if same_account and (unconditional_identity or unconditional_queue):
        bases: list[AwsSqsMessageRemovalAuthorizationBasis] = []
        if unconditional_identity:
            bases.append("identity_policy")
        if unconditional_queue:
            bases.append("queue_policy_direct")
        proof = _EffectiveProof(
            tuple(_ordered_bases(bases)),
            tuple(unconditional_identity),
            tuple(unconditional_queue),
        )
    elif not same_account and unconditional_identity and (unconditional_queue or account_queue):
        proof = _EffectiveProof(
            ("cross_account_identity_and_queue_policy",),
            tuple(unconditional_identity),
            tuple((*unconditional_queue, *account_queue)),
        )

    if not identity_policy_complete or not queue_policy_complete:
        incomplete_surfaces: list[str] = []
        if not identity_policy_complete:
            incomplete_surfaces.append("identity policy")
        if not queue_policy_complete:
            incomplete_surfaces.append("queue policy")
        return _AuthorizationEvaluation(
            None,
            (
                f"{queue.address}: {role.address} {operation} authorization is unresolved "
                f"because {' and '.join(incomplete_surfaces)} evidence is incomplete",
            ),
        )

    if proof is not None:
        return _AuthorizationEvaluation(proof, ())

    conditional_candidate = bool(
        any(match.conditional for match in identity_allows) or any(match.conditional for match in queue_allows)
    )
    if conditional_candidate:
        return _AuthorizationEvaluation(
            None,
            (f"{queue.address}: {role.address} {operation} authorization depends on runtime policy conditions",),
        )
    if not same_account and (identity_allows or queue_allows):
        return _AuthorizationEvaluation(
            None,
            (
                f"{queue.address}: {role.address} cross-account {operation} authorization "
                "does not have complete identity-policy and queue-policy allow evidence",
            ),
        )
    return _AuthorizationEvaluation(None, ())


def _identity_policy_matches(
    role: NormalizedResource,
    queue: NormalizedResource,
    context: AwsDecorationContext,
) -> tuple[list[_StatementMatch], set[AwsSqsMessageRemovalAuthorizationOperation]]:
    matches: list[_StatementMatch] = []
    unresolved: set[AwsSqsMessageRemovalAuthorizationOperation] = set()
    for statement in role.policy_statements:
        effect = _normalized_effect(statement)
        if effect is None:
            continue
        for operation, action_patterns in _matching_actions(statement.actions):
            for resource in statement.resources:
                applicability = _resource_targets_queue(resource, queue, context)
                if applicability is True:
                    matches.append(
                        _StatementMatch(
                            statement,
                            operation,
                            role.address,
                            "identity_policy",
                            effect,
                            action_patterns,
                            resource,
                        )
                    )
                elif applicability is None:
                    unresolved.add(operation)
    return matches, unresolved


def _queue_policy_matches(
    queue: NormalizedResource,
    role_arn: str,
    context: AwsDecorationContext,
) -> tuple[list[_StatementMatch], set[AwsSqsMessageRemovalAuthorizationOperation]]:
    role_account_id = parse_aws_account_id(role_arn)
    if role_account_id is None:
        return [], set(_OPERATION_ORDER)
    account_root_arn = f"arn:{_arn_partition(role_arn)}:iam::{role_account_id}:root"
    matches: list[_StatementMatch] = []
    unresolved: set[AwsSqsMessageRemovalAuthorizationOperation] = set()
    for statement in queue.policy_statements:
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
                applicability = _resource_targets_queue(resource, queue, context)
                if applicability is True:
                    matches.append(
                        _StatementMatch(
                            statement,
                            operation,
                            queue.address,
                            "queue_policy",
                            effect,
                            action_patterns,
                            resource,
                            principal_match,
                        )
                    )
                elif applicability is None:
                    unresolved.add(operation)
    return matches, unresolved


def _resource_targets_queue(
    resource: str,
    queue: NormalizedResource,
    context: AwsDecorationContext,
) -> bool | None:
    queue_arn = queue.arn
    assert queue_arn is not None
    normalized = _unwrap_reference(resource)
    if normalized == "*":
        return True
    modeled = context.index.sqs_queues.get(normalized, source=queue)
    if modeled is not None:
        return modeled.address == queue.address
    if normalized.startswith("arn:"):
        return fnmatchcase(queue_arn, normalized)
    if normalized.startswith(("aws_sqs_queue.", "module.")) or "${" in resource:
        return None
    if "*" in normalized or "?" in normalized:
        return None
    return False


def _matching_actions(
    patterns: Sequence[str],
) -> list[tuple[AwsSqsMessageRemovalAuthorizationOperation, tuple[str, ...]]]:
    matches: list[tuple[AwsSqsMessageRemovalAuthorizationOperation, tuple[str, ...]]] = []
    for operation in _OPERATION_ORDER:
        matching = tuple(pattern for pattern in patterns if fnmatchcase(operation.casefold(), pattern.casefold()))
        if matching:
            matches.append((operation, matching))
    return matches


def _queue_policy_posture(queue: NormalizedResource) -> _QueuePolicyPosture:
    facts = aws_facts(queue)
    state = facts.sqs_queue_policy_state
    if state == "not_configured":
        return _QueuePolicyPosture((), frozenset(), ())
    if state != "configured":
        uncertainties = facts.sqs_queue_policy_uncertainties or ["inline SQS queue policy is unknown or malformed"]
        return _QueuePolicyPosture(
            (),
            frozenset(_OPERATION_ORDER),
            tuple(f"{queue.address}: {value}" for value in uncertainties),
        )

    incomplete_operations, uncertainties = _queue_policy_incomplete_operations(queue)
    return _QueuePolicyPosture(
        (queue.address,),
        frozenset(incomplete_operations),
        tuple(uncertainties),
    )


def sqs_queue_policy_operation_is_complete(
    queue: NormalizedResource,
    operation: str,
) -> bool:
    if operation not in _OPERATION_ORDER:
        return False
    state = aws_facts(queue).sqs_queue_policy_state
    if state == "not_configured":
        return True
    if state != "configured":
        return False
    incomplete_operations, _ = _queue_policy_incomplete_operations(queue)
    return operation not in incomplete_operations


def _queue_policy_incomplete_operations(
    queue: NormalizedResource,
) -> tuple[
    set[AwsSqsMessageRemovalAuthorizationOperation],
    list[str],
]:
    document = aws_facts(queue).policy_document
    raw_statements = document.get("Statement")
    if isinstance(raw_statements, Mapping):
        statement_documents: list[Mapping[str, object]] = [raw_statements]
    elif isinstance(raw_statements, list) and all(isinstance(statement, Mapping) for statement in raw_statements):
        statement_documents = [statement for statement in raw_statements if isinstance(statement, Mapping)]
    else:
        return set(_OPERATION_ORDER), [f"{queue.address}: inline SQS queue policy has an unsupported statement shape"]

    statements = queue.policy_statements
    incomplete: set[AwsSqsMessageRemovalAuthorizationOperation] = set()
    if len(statements) != len(statement_documents):
        for raw_statement in statement_documents:
            affected = _raw_statement_operations(raw_statement)
            incomplete.update(_OPERATION_ORDER if affected is None else affected)
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
            affected = _raw_statement_operations(raw_statement)
            incomplete.update(_OPERATION_ORDER if affected is None else affected)

    uncertainties = [
        f"{queue.address}: inline SQS queue policy evidence is incomplete or unsupported for {operation}"
        for operation in _OPERATION_ORDER
        if operation in incomplete
    ]
    return incomplete, uncertainties


def _raw_statement_operations(
    statement: Mapping[str, object],
) -> set[AwsSqsMessageRemovalAuthorizationOperation] | None:
    if "NotAction" in statement:
        return None
    raw_actions = statement.get("Action")
    if isinstance(raw_actions, str):
        actions = [raw_actions]
    elif isinstance(raw_actions, list) and all(isinstance(action, str) for action in raw_actions):
        actions = [action for action in raw_actions if isinstance(action, str)]
    else:
        return None
    return {
        operation
        for operation in _OPERATION_ORDER
        if any(fnmatchcase(operation.casefold(), action.casefold()) for action in actions)
    }


def _authorization_record(
    queue: NormalizedResource,
    role: NormalizedResource,
    operation: AwsSqsMessageRemovalAuthorizationOperation,
    proof: _EffectiveProof,
    queue_posture: _QueuePolicyPosture,
    *,
    same_account: bool,
) -> AwsSqsMessageRemovalAuthorizationProof:
    queue_arn = queue.arn
    role_arn = role.arn
    assert queue_arn is not None
    assert role_arn is not None
    identity_sources = _identity_policy_sources(role)
    common: AwsSqsDeterministicAuthorizationProofCommon = {
        "queue_address": queue.address,
        "queue_resource_type": queue.resource_type,
        "queue_arn": queue_arn,
        "principal_address": role.address,
        "principal_arn": role_arn,
        "principal_kind": "iam_role",
        "authorization_state": "allowed",
        "authorization_bases": list(proof.bases),
        "same_account": same_account,
        "identity_policy_required": (not same_account or bool(proof.identity_matches and not proof.queue_matches)),
        "queue_policy_required": (not same_account or bool(proof.queue_matches and not proof.identity_matches)),
        "identity_policy_complete": True,
        "queue_policy_complete": True,
        "identity_policy_source_addresses": identity_sources,
        "queue_policy_source_addresses": list(queue_posture.source_addresses),
        "identity_policy_statements": [_statement_record(match) for match in proof.identity_matches],
        "queue_policy_statements": [_statement_record(match) for match in proof.queue_matches],
        "explicit_deny": False,
        "conditional_evaluation_required": False,
        "evaluation_scope": "modeled_identity_and_sqs_queue_policies",
    }
    if operation == _RECEIVE:
        receive: AwsSqsReceiveAuthorizationProof = {
            **common,
            "operation": "sqs:ReceiveMessage",
            "matched_actions": ["sqs:ReceiveMessage"],
        }
        return receive
    if operation == _DELETE:
        delete: AwsSqsDeleteMessageAuthorizationProof = {
            **common,
            "operation": "sqs:DeleteMessage",
            "matched_actions": ["sqs:DeleteMessage"],
        }
        return delete
    purge: AwsSqsPurgeQueueAuthorizationProof = {
        **common,
        "operation": "sqs:PurgeQueue",
        "matched_actions": ["sqs:PurgeQueue"],
    }
    return purge


def _delete_path(
    task_definition: NormalizedResource,
    role: NormalizedResource,
    queue: NormalizedResource,
    receive_proof: _EffectiveProof,
    delete_proof: _EffectiveProof,
    queue_posture: _QueuePolicyPosture,
    *,
    same_account: bool,
) -> AwsEcsSqsReceivedMessageDeletionPath:
    receive_authorization = cast(
        AwsSqsReceiveAuthorizationProof,
        _authorization_record(
            queue,
            role,
            _RECEIVE,
            receive_proof,
            queue_posture,
            same_account=same_account,
        ),
    )
    delete_authorization = cast(
        AwsSqsDeleteMessageAuthorizationProof,
        _authorization_record(
            queue,
            role,
            _DELETE,
            delete_proof,
            queue_posture,
            same_account=same_account,
        ),
    )
    common = _path_common(
        task_definition,
        role,
        queue,
        (receive_authorization, delete_authorization),
    )
    return {
        **common,
        "operation": "sqs:DeleteMessage",
        "operation_class": "received_message_deletion",
        "internal_operation": "delete_received_message",
        "target_granularity": "queue_received_message_namespace",
        "target_scope": "exact_queue_received_message_namespace",
        "prerequisite_operation": "sqs:ReceiveMessage",
        "receipt_handle_source": "runtime_receive_response",
        "receipt_handle_value": None,
        "receive_authorization": receive_authorization,
        "removal_authorization": delete_authorization,
    }


def _purge_path(
    task_definition: NormalizedResource,
    role: NormalizedResource,
    queue: NormalizedResource,
    proof: _EffectiveProof,
    queue_posture: _QueuePolicyPosture,
    *,
    same_account: bool,
) -> AwsEcsSqsQueueMessagePurgePath:
    authorization = cast(
        AwsSqsPurgeQueueAuthorizationProof,
        _authorization_record(
            queue,
            role,
            _PURGE,
            proof,
            queue_posture,
            same_account=same_account,
        ),
    )
    common = _path_common(
        task_definition,
        role,
        queue,
        (authorization,),
    )
    return {
        **common,
        "operation": "sqs:PurgeQueue",
        "operation_class": "queue_message_purge",
        "internal_operation": "purge_queue_messages",
        "target_granularity": "queue_message_namespace",
        "target_scope": "exact_queue_message_namespace",
        "prerequisite_operation": None,
        "receipt_handle_source": None,
        "receipt_handle_value": None,
        "removal_authorization": authorization,
    }


def _path_common(
    task_definition: NormalizedResource,
    role: NormalizedResource,
    queue: NormalizedResource,
    authorizations: Sequence[AwsSqsMessageRemovalAuthorizationProof],
) -> AwsEcsSqsMessageRemovalPathCommon:
    queue_arn = queue.arn
    role_arn = role.arn
    assert queue_arn is not None
    assert role_arn is not None
    delivery = _delivery_evidence(queue)
    queue_name = queue.identifier
    if not isinstance(queue_name, str) or not queue_name:
        queue_name = queue_arn.rsplit(":", 1)[-1]
    authorization_sources = dedupe(
        source
        for authorization in authorizations
        for source in (
            *authorization["identity_policy_source_addresses"],
            *authorization["queue_policy_source_addresses"],
        )
    )
    model_sources = dedupe(
        value
        for value in (
            queue.address,
            aws_facts(queue).sqs_redrive_source_address,
        )
        if value is not None
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
        "role_arn": role_arn,
        "queue_address": queue.address,
        "queue_resource_type": queue.resource_type,
        "queue_name": queue_name,
        "queue_arn": queue_arn,
        "queue_url": aws_facts(queue).sqs_queue_url,
        "target_model_evidence_addresses": model_sources,
        "management_effect": "disruption",
        "authorization_source_addresses": authorization_sources,
        "authorization_state": "allowed",
        "explicit_deny": False,
        "conditional_evaluation_required": False,
        "lifecycle_compatibility_state": "not_applicable",
        "delivery_evidence": delivery,
        "posture_uncertainties": list(delivery["uncertainties"]),
    }


def _delivery_evidence(queue: NormalizedResource) -> AwsSqsMessageRemovalDeliveryEvidence:
    facts = aws_facts(queue)
    uncertainties = list(facts.sqs_posture_uncertainties)
    redrive_state = facts.sqs_redrive_state
    if redrive_state not in {"configured", "not_configured", "unknown"}:
        redrive_state = "unknown"
        uncertainties.append(f"{queue.address}: SQS redrive posture is not exact after normalization")
    return {
        "delivery_evidence_scope": "sqs_retention_and_redrive_posture",
        "message_retention_seconds": facts.sqs_message_retention_seconds,
        "redrive_state": cast(
            Literal["configured", "not_configured", "unknown"],
            redrive_state,
        ),
        "redrive_target_arn": facts.sqs_redrive_target_arn,
        "redrive_max_receive_count": facts.sqs_redrive_max_receive_count,
        "removed_message_recovery_state": ("not_established_by_modeled_sqs_delivery_controls"),
        "uncertainties": dedupe(uncertainties),
    }


def _service_path(
    service: NormalizedResource,
    task_definition: NormalizedResource,
    path: AwsEcsSqsMessageRemovalPath,
) -> AwsEcsSqsMessageRemovalPath:
    projected = path.copy()
    projected["workload_address"] = service.address
    projected["workload_type"] = service.resource_type
    projected["task_definition_address"] = task_definition.address
    projected["task_definition_arn"] = task_definition.arn
    projected["internet_facing_load_balancers"] = aws_facts(service).internet_facing_load_balancer_addresses
    return projected


def _statement_record(
    match: _StatementMatch,
) -> AwsSqsMessageRemovalPolicyStatementEvidence:
    return {
        "source_address": match.source_address,
        "source_kind": match.source_kind,
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


def _has_modeled_action_pattern(statements: Sequence[IAMPolicyStatement]) -> bool:
    return any(
        any(
            fnmatchcase(operation.casefold(), pattern.casefold())
            for operation in _OPERATION_ORDER
            for pattern in statement.actions
        )
        for statement in statements
    )


def _queue_policy_may_apply_to_role(
    statements: Sequence[IAMPolicyStatement],
    role_arn: str,
) -> bool:
    account_id = parse_aws_account_id(role_arn)
    if account_id is None:
        return False
    root_arn = f"arn:{_arn_partition(role_arn)}:iam::{account_id}:root"
    return any(
        any(
            fnmatchcase(operation.casefold(), pattern.casefold())
            for operation in _OPERATION_ORDER
            for pattern in statement.actions
        )
        and bool(_aws_principal_values(statement) & {role_arn, account_id, root_arn, "*"})
        for statement in statements
    )


def _account_relationship(role_arn: str, queue_arn: str) -> tuple[bool | None, bool]:
    role_account = parse_aws_account_id(role_arn)
    queue_account = parse_aws_account_id(queue_arn)
    if role_account is None or queue_account is None:
        return None, _arn_partition(role_arn) == _arn_partition(queue_arn)
    return (
        role_account == queue_account,
        _arn_partition(role_arn) == _arn_partition(queue_arn),
    )


def _is_exact_sqs_queue_arn(value: str | None) -> bool:
    if not value or _has_wildcard(value):
        return False
    parts = value.split(":", 5)
    return bool(
        len(parts) == 6
        and parts[0] == "arn"
        and parts[1]
        and parts[2] == "sqs"
        and parts[3]
        and parse_aws_account_id(value) is not None
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


def _ordered_bases(
    values: Sequence[AwsSqsMessageRemovalAuthorizationBasis],
) -> list[AwsSqsMessageRemovalAuthorizationBasis]:
    present = set(values)
    return [basis for basis in _AUTHORIZATION_BASIS_ORDER if basis in present]


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


def _path_sort_key(path: AwsEcsSqsMessageRemovalPath) -> tuple[str, int]:
    return (
        path["queue_address"],
        (_DELETE, _PURGE).index(path["operation"]),
    )
