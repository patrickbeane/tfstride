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
from tfstride.providers.aws.policy_documents import (
    policy_statement_is_fully_representable,
)
from tfstride.providers.aws.reference_resolution import (
    assess_symbolic_reference,
    symbolic_reference_target,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.aws.structured_data_topology_destruction_evidence import (
    AwsDynamoDbTableTopologyIdentityPolicyStatementEvidence,
    AwsDynamoDbTableTopologyPolicyStatementEvidence,
    AwsDynamoDbTableTopologyResourcePolicyStatementEvidence,
    AwsEcsDynamoDbCrossAccountTableDeletionPath,
    AwsEcsDynamoDbSameAccountCombinedTableDeletionPath,
    AwsEcsDynamoDbSameAccountIdentityTableDeletionPath,
    AwsEcsDynamoDbSameAccountTablePolicyDeletionPath,
    AwsEcsDynamoDbTableTopologyDestructionPath,
)
from tfstride.providers.coercion import (
    STATE_DISABLED,
    STATE_ENABLED,
    STATE_NOT_CONFIGURED,
    dedupe,
)
from tfstride.resource_helpers import parse_aws_account_id

_ECS_TASK_DEFINITION = "aws_ecs_task_definition"
_ECS_SERVICE = "aws_ecs_service"
_IAM_ROLE = "aws_iam_role"
_DYNAMODB_TABLE = "aws_dynamodb_table"
_DYNAMODB_RESOURCE_POLICY = "aws_dynamodb_resource_policy"
_CALLER_IDENTITY = "aws_caller_identity"
_DELETE_TABLE = "dynamodb:DeleteTable"
_COMPLETE = "complete"
_PrincipalMatch = Literal["role", "account", "wildcard"]
_PolicySourceKind = Literal["identity_policy", "table_policy"]


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
class _TablePolicyPosture:
    sources: tuple[NormalizedResource, ...]
    source_addresses: tuple[str, ...]
    complete: bool
    uncertainties: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _EffectiveProof:
    grant_basis: Literal[
        "same_account_identity_policy",
        "same_account_table_policy_direct",
        "same_account_combined",
        "cross_account_identity_and_table_policy",
    ]
    identity_matches: tuple[_StatementMatch, ...]
    table_matches: tuple[_StatementMatch, ...]
    principal_match: _PrincipalMatch | None


@dataclass(frozen=True, slots=True)
class _AuthorizationEvaluation:
    proof: _EffectiveProof | None
    uncertainties: tuple[str, ...]


class ModelEcsDynamoDbTableTopologyDestructionPathsStage:
    """Model effective ECS task-role authority to delete exact DynamoDB tables."""

    name = "model_ecs_dynamodb_table_topology_destruction_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AwsDecorationContext,
    ) -> None:
        tables = tuple(resource for resource in resources if resource.resource_type == _DYNAMODB_TABLE)
        unresolved_policy_sources = _unresolved_table_policy_sources(
            resources,
            context,
        )
        for task_definition in resources:
            if task_definition.resource_type != _ECS_TASK_DEFINITION:
                continue
            paths, uncertainties = _task_definition_paths(
                task_definition,
                tables,
                context,
                resources=resources,
                unresolved_policy_sources=unresolved_policy_sources,
            )
            facts = aws_facts(task_definition)
            facts.set_ecs_dynamodb_table_topology_destruction_paths(paths)
            facts.extend_ecs_dynamodb_table_topology_destruction_path_uncertainties(
                uncertainties,
            )


class ProjectEcsDynamoDbTableTopologyDestructionPathsOntoServicesStage:
    name = "project_ecs_dynamodb_table_topology_destruction_paths_onto_services"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AwsDecorationContext,
    ) -> None:
        for service in resources:
            if service.resource_type != _ECS_SERVICE:
                continue
            service_facts = aws_facts(service)
            paths: list[AwsEcsDynamoDbTableTopologyDestructionPath] = []
            uncertainties = [
                f"{service.address}: task definition reference {reference} is "
                "unresolved for DynamoDB table-deletion path projection"
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
                        f"{task_definition_address} is unavailable for DynamoDB "
                        "table-deletion path projection"
                    )
                    continue
                task_facts = aws_facts(task_definition)
                uncertainties.extend(
                    task_facts.ecs_dynamodb_table_topology_destruction_path_uncertainties,
                )
                paths.extend(
                    _service_path(service, task_definition, path)
                    for path in (task_facts.ecs_dynamodb_table_topology_destruction_paths)
                )
            paths.sort(key=_path_sort_key)
            service_facts.set_ecs_dynamodb_table_topology_destruction_paths(
                paths,
            )
            service_facts.extend_ecs_dynamodb_table_topology_destruction_path_uncertainties(
                dedupe(uncertainties),
            )


def _task_definition_paths(
    task_definition: NormalizedResource,
    tables: Sequence[NormalizedResource],
    context: AwsDecorationContext,
    *,
    resources: Sequence[NormalizedResource],
    unresolved_policy_sources: Sequence[NormalizedResource],
) -> tuple[list[AwsEcsDynamoDbTableTopologyDestructionPath], list[str]]:
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
                    "ambiguous or unresolved for DynamoDB table-deletion paths"
                ],
            )
        return (
            [],
            [
                f"{task_definition.address}: ECS task role "
                f"{task_role_reference} is not modeled for DynamoDB "
                "table-deletion paths"
            ],
        )
    if not _task_role_relationship_is_exact(
        task_definition,
        task_role,
        context,
    ):
        return [], []
    if task_definition.provider_config_key != task_role.provider_config_key:
        return (
            [],
            [
                f"{task_definition.address}: task role {task_role.address} does "
                "not share the ECS task definition provider configuration"
            ],
        )

    role_reference = _task_role_evidence_reference(
        task_definition,
        task_role,
    )
    if role_reference is None:
        return [], []
    role_account_id = _resource_account_id(
        task_role,
        task_role.arn,
        resources,
    )
    if role_account_id is None:
        return (
            [],
            [
                f"{task_definition.address}: ECS task role {task_role.address} "
                "account ownership is unresolved for DynamoDB table deletion"
            ],
        )

    identity_policy_complete = _identity_policy_complete(task_role)
    uncertainties: list[str] = []
    if not identity_policy_complete and _role_has_delete_table_action(task_role):
        uncertainties.append(
            f"{task_definition.address}: {task_role.address} DynamoDB "
            "table-deletion authorization is unresolved because identity-policy "
            "evidence is incomplete"
        )
        uncertainties.extend(
            f"{task_definition.address}: {task_role.address}: {uncertainty}"
            for uncertainty in (aws_facts(task_role).iam_policy_posture_uncertainties)
        )

    paths: list[AwsEcsDynamoDbTableTopologyDestructionPath] = []
    for table in tables:
        table_account_id = _resource_account_id(
            table,
            aws_facts(table).dynamodb_table_arn or table.arn,
            resources,
        )
        table_name = _table_name(table)
        if table_account_id is None or table_name is None:
            if _role_has_delete_table_action(task_role):
                uncertainties.append(
                    f"{task_definition.address}: {table.address} has unresolved "
                    "provider-native identity or account ownership for DynamoDB "
                    "table deletion"
                )
            continue

        identity_matches = _identity_policy_matches(
            task_role,
            table,
            context,
        )
        exact_posture = _table_policy_posture(table, context)
        relevant_unresolved_sources = tuple(
            source
            for source in unresolved_policy_sources
            if _unresolved_policy_may_affect_table_role(
                source,
                table,
                task_role,
                context,
            )
        )
        table_matches = _table_policy_matches(
            exact_posture.sources,
            table,
            task_role,
            context,
        )
        operation_evidence = bool(
            identity_matches.matches
            or table_matches.matches
            or identity_matches.unresolved_allow
            or identity_matches.unresolved_deny
            or table_matches.unresolved_allow
            or table_matches.unresolved_deny
        )
        if not operation_evidence:
            continue

        same_account = role_account_id == table_account_id
        role_partition = _resource_partition(
            task_role,
            task_role.arn,
            resources,
        )
        table_partition = _resource_partition(
            table,
            aws_facts(table).dynamodb_table_arn or table.arn,
            resources,
        )
        if role_partition is None or table_partition is None or role_partition != table_partition:
            uncertainties.append(
                f"{task_definition.address}: {table.address} AWS partition "
                f"compatibility with {task_role.address} is unresolved"
            )
            continue

        uncertainties.extend(f"{task_definition.address}: {uncertainty}" for uncertainty in exact_posture.uncertainties)
        uncertainties.extend(
            f"{task_definition.address}: {source.address} has an unresolved "
            "DynamoDB resource-policy target and may affect "
            f"{task_role.address} {_DELETE_TABLE} authorization for "
            f"{table.address}"
            for source in relevant_unresolved_sources
        )
        evaluation = _evaluate_authorization(
            table,
            task_role,
            same_account=same_account,
            identity_matches=identity_matches,
            table_matches=table_matches,
            identity_policy_complete=identity_policy_complete,
            table_policy_complete=(exact_posture.complete and not relevant_unresolved_sources),
        )
        uncertainties.extend(f"{task_definition.address}: {uncertainty}" for uncertainty in evaluation.uncertainties)
        if evaluation.proof is None:
            continue

        constraint, constraint_uncertainties = _deletion_constraint(table)
        uncertainties.extend(
            f"{task_definition.address}: {table.address}: {uncertainty}" for uncertainty in constraint_uncertainties
        )
        if constraint is None:
            continue

        path = _path(
            task_definition,
            task_role,
            role_reference,
            role_account_id,
            table,
            table_name,
            table_account_id,
            evaluation.proof,
            exact_posture,
            constraint,
        )
        paths.append(path)
        uncertainties.extend(
            f"{task_definition.address}: {table.address} {_DELETE_TABLE} recovery evidence is uncertain: {uncertainty}"
            for uncertainty in path["posture_uncertainties"]
        )

    paths.sort(key=_path_sort_key)
    return paths, dedupe(uncertainties)


def _evaluate_authorization(
    table: NormalizedResource,
    role: NormalizedResource,
    *,
    same_account: bool,
    identity_matches: _PolicyMatches,
    table_matches: _PolicyMatches,
    identity_policy_complete: bool,
    table_policy_complete: bool,
) -> _AuthorizationEvaluation:
    matches = (*identity_matches.matches, *table_matches.matches)
    denies = [match for match in matches if match.effect == "deny"]
    if any(not match.conditional for match in denies):
        return _AuthorizationEvaluation(None, ())
    if any(match.conditional for match in denies):
        return _AuthorizationEvaluation(
            None,
            (f"{table.address}: {role.address} {_DELETE_TABLE} has condition-dependent explicit-deny evidence",),
        )
    if identity_matches.unresolved_deny or table_matches.unresolved_deny:
        return _AuthorizationEvaluation(
            None,
            (f"{table.address}: {role.address} {_DELETE_TABLE} has ambiguous or unresolved explicit-deny scope",),
        )

    identity_allows = tuple(
        match for match in identity_matches.matches if match.effect == "allow" and not match.conditional
    )
    table_allows = tuple(
        match
        for match in table_matches.matches
        if match.effect == "allow" and not match.conditional and match.principal_match is not None
    )
    candidate_observed = bool(
        identity_allows
        or table_allows
        or identity_matches.unresolved_allow
        or table_matches.unresolved_allow
        or any(match.effect == "allow" for match in matches)
    )
    if not candidate_observed:
        return _AuthorizationEvaluation(None, ())

    if not identity_policy_complete or not table_policy_complete:
        surfaces: list[str] = []
        if not identity_policy_complete:
            surfaces.append("identity policy")
        if not table_policy_complete:
            surfaces.append("table resource policy")
        return _AuthorizationEvaluation(
            None,
            (
                f"{table.address}: {role.address} {_DELETE_TABLE} authorization "
                f"is unresolved because {' and '.join(surfaces)} evidence is "
                "incomplete",
            ),
        )

    if same_account:
        if identity_allows and table_allows:
            return _AuthorizationEvaluation(
                _EffectiveProof(
                    "same_account_combined",
                    identity_allows,
                    table_allows,
                    _broadest_principal_match(table_allows),
                ),
                (),
            )
        if identity_allows:
            return _AuthorizationEvaluation(
                _EffectiveProof(
                    "same_account_identity_policy",
                    identity_allows,
                    (),
                    None,
                ),
                (),
            )
        direct_table_allows = tuple(match for match in table_allows if match.principal_match == "role")
        if direct_table_allows:
            return _AuthorizationEvaluation(
                _EffectiveProof(
                    "same_account_table_policy_direct",
                    (),
                    direct_table_allows,
                    "role",
                ),
                (),
            )
    elif identity_allows and table_allows:
        return _AuthorizationEvaluation(
            _EffectiveProof(
                "cross_account_identity_and_table_policy",
                identity_allows,
                table_allows,
                _broadest_principal_match(table_allows),
            ),
            (),
        )

    if identity_matches.unresolved_allow or table_matches.unresolved_allow:
        return _AuthorizationEvaluation(
            None,
            (
                f"{table.address}: {role.address} {_DELETE_TABLE} allow evidence "
                "does not identify one exact DynamoDB table",
            ),
        )
    if any(match.effect == "allow" and match.conditional for match in matches):
        return _AuthorizationEvaluation(
            None,
            (f"{table.address}: {role.address} {_DELETE_TABLE} authorization depends on runtime policy conditions",),
        )
    if not same_account and (identity_allows or table_allows):
        return _AuthorizationEvaluation(
            None,
            (
                f"{table.address}: cross-account {_DELETE_TABLE} authorization "
                "requires both identity and table resource-policy allows",
            ),
        )
    if same_account and table_allows:
        return _AuthorizationEvaluation(
            None,
            (f"{table.address}: same-account table-policy allow does not identify the exact ECS task role principal",),
        )
    return _AuthorizationEvaluation(None, ())


def _identity_policy_matches(
    role: NormalizedResource,
    table: NormalizedResource,
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
            applicability = _resource_targets_table(
                resource,
                table,
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


def _table_policy_matches(
    sources: Sequence[NormalizedResource],
    table: NormalizedResource,
    role: NormalizedResource,
    context: AwsDecorationContext,
) -> _PolicyMatches:
    role_arn = role.arn
    role_account_id = parse_aws_account_id(role_arn)
    if role_arn is None or role_account_id is None:
        return _PolicyMatches((), False, bool(sources))
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
                applicability = _resource_targets_table(
                    resource,
                    table,
                    (source,),
                    context,
                    exact_allow_required=effect == "allow",
                )
                if applicability is True:
                    matches.append(
                        _StatementMatch(
                            statement,
                            source.address,
                            "table_policy",
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


def _resource_targets_table(
    resource: str,
    table: NormalizedResource,
    sources: Sequence[NormalizedResource],
    context: AwsDecorationContext,
    *,
    exact_allow_required: bool,
) -> bool | None:
    table_arn = aws_facts(table).dynamodb_table_arn or table.arn
    normalized = _unwrap_reference(resource)
    if table_arn is not None and normalized == table_arn:
        return True
    if normalized.startswith("arn:"):
        if table_arn is None:
            return None
        if _has_wildcard(normalized):
            matches = fnmatchcase(table_arn, normalized)
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
            expected_resource_types={_DYNAMODB_TABLE},
            expected_reference_suffixes={".arn"},
        )
        if assessment.state == "resolved" and assessment.target is not None:
            candidates.add(assessment.target.address)
        elif assessment.state == "uncertain":
            uncertain = True
    if uncertain or len(candidates) > 1:
        return None
    if candidates:
        return candidates == {table.address}

    if normalized == "*":
        return None if exact_allow_required else True
    if _has_wildcard(normalized):
        return None
    return False


def _table_policy_posture(
    table: NormalizedResource,
    context: AwsDecorationContext,
) -> _TablePolicyPosture:
    sources = [
        resource
        for resource in context.index.resources_by_address.values()
        if resource.resource_type == _DYNAMODB_RESOURCE_POLICY
        and (target := _resolved_table_policy_target(resource, context)) is not None
        and target.address == table.address
    ]
    sources.sort(key=lambda source: source.address)
    uncertainties: list[str] = []
    for source in sources:
        if source.provider_config_key != table.provider_config_key:
            uncertainties.append(
                f"{table.address}: {source.address} uses a different provider "
                "configuration from its DynamoDB table target"
            )
        if not _table_policy_is_complete_for_operation(source):
            uncertainties.append(
                f"{table.address}: {source.address} table resource-policy "
                f"evidence is incomplete or unsupported for {_DELETE_TABLE}"
            )
    if len(sources) > 1:
        uncertainties.append(
            f"{table.address}: multiple DynamoDB resource-policy resources provide conflicting authoritative evidence"
        )
    complete = bool(
        len(sources) <= 1
        and all(
            source.provider_config_key == table.provider_config_key and _table_policy_is_complete_for_operation(source)
            for source in sources
        )
    )
    return _TablePolicyPosture(
        tuple(sources),
        tuple(source.address for source in sources),
        complete,
        tuple(dedupe(uncertainties)),
    )


def _table_policy_is_complete_for_operation(
    source: NormalizedResource,
) -> bool:
    statement_documents = _raw_policy_statements(
        aws_facts(source).policy_document,
    )
    if statement_documents is None:
        return False
    statements = source.policy_statements
    if len(statements) != len(statement_documents):
        return not any(_raw_statement_affects_delete_table(statement) is not False for statement in statement_documents)
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
        if _raw_statement_affects_delete_table(raw_statement) is not False:
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


def _raw_statement_affects_delete_table(
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
    return any(fnmatchcase(_DELETE_TABLE.casefold(), action.casefold()) for action in actions)


def _unresolved_table_policy_sources(
    resources: Sequence[NormalizedResource],
    context: AwsDecorationContext,
) -> tuple[NormalizedResource, ...]:
    unresolved: list[NormalizedResource] = []
    for resource in resources:
        if resource.resource_type != _DYNAMODB_RESOURCE_POLICY:
            continue
        if _resolved_table_policy_target(resource, context) is not None:
            continue
        target = aws_facts(resource).dynamodb_resource_policy_target_reference
        if _is_exact_unmodeled_table_reference(target):
            continue
        unresolved.append(resource)
    return tuple(unresolved)


def _unresolved_policy_may_affect_table_role(
    source: NormalizedResource,
    table: NormalizedResource,
    role: NormalizedResource,
    context: AwsDecorationContext,
) -> bool:
    if source.provider_config_key != table.provider_config_key:
        return False
    modeled_target = _resolved_table_policy_target(source, context)
    if modeled_target is not None:
        return modeled_target.address == table.address
    target = aws_facts(source).dynamodb_resource_policy_target_reference
    if _is_exact_unmodeled_table_reference(target):
        return False

    statement_documents = _raw_policy_statements(
        aws_facts(source).policy_document,
    )
    if statement_documents is None:
        return True
    if not any(_raw_statement_affects_delete_table(statement) is not False for statement in statement_documents):
        return False
    if not _table_policy_is_fully_representable(source):
        return True

    role_arn = role.arn
    role_account_id = parse_aws_account_id(role_arn)
    if role_arn is None or role_account_id is None:
        return True
    account_root_arn = f"arn:{_arn_partition(role_arn)}:iam::{role_account_id}:root"
    unresolved_resource = False
    for statement in source.policy_statements:
        if not _matching_action_patterns(statement.actions):
            continue
        principals = _aws_principal_values(statement)
        if not principals & {
            role_arn,
            role_account_id,
            account_root_arn,
            "*",
        }:
            continue
        for resource in statement.resources:
            applicability = _resource_targets_table(
                resource,
                table,
                (source,),
                context,
                exact_allow_required=False,
            )
            if applicability is True:
                return True
            if applicability is None:
                unresolved_resource = True
    return unresolved_resource


def _resolved_table_policy_target(
    source: NormalizedResource,
    context: AwsDecorationContext,
) -> NormalizedResource | None:
    target = aws_facts(source).dynamodb_resource_policy_target_reference
    if _is_exact_dynamodb_table_arn(target):
        modeled_target = context.index.dynamodb_tables.get(cast(str, target), source=source)
        if modeled_target is not None:
            return modeled_target
    return symbolic_reference_target(
        source,
        context.index,
        "resource_arn",
        expected_resource_types={_DYNAMODB_TABLE},
        expected_reference_suffixes={".arn"},
    )


def _table_policy_is_fully_representable(
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


def _deletion_constraint(
    table: NormalizedResource,
) -> tuple[dict[str, object] | None, list[str]]:
    facts = aws_facts(table)
    state = facts.dynamodb_deletion_protection_state
    uncertainties = [
        uncertainty
        for uncertainty in facts.dynamodb_posture_uncertainties
        if "deletion_protection_enabled" in uncertainty
    ]
    if state == STATE_ENABLED:
        return None, []
    if state == STATE_DISABLED:
        return (
            {
                "constraint_evidence_scope": ("dynamodb_table_deletion_protection"),
                "deletion_protection_state": "disabled",
                "deletion_protection_enabled": False,
                "provider_default_applied": False,
                "deletion_compatibility_state": "compatible",
                "uncertainties": [],
            },
            [],
        )
    if state == STATE_NOT_CONFIGURED:
        return (
            {
                "constraint_evidence_scope": ("dynamodb_table_deletion_protection"),
                "deletion_protection_state": "not_configured",
                "deletion_protection_enabled": False,
                "provider_default_applied": True,
                "deletion_compatibility_state": "compatible",
                "uncertainties": [],
            },
            [],
        )
    if not uncertainties:
        uncertainties.append("deletion protection posture is unresolved for table deletion")
    return None, dedupe(uncertainties)


def _recovery_evidence(table: NormalizedResource) -> dict[str, object]:
    facts = aws_facts(table)
    uncertainties = [
        uncertainty for uncertainty in facts.dynamodb_posture_uncertainties if "point_in_time_recovery" in uncertainty
    ]
    common: dict[str, object] = {
        "recovery_evidence_scope": ("dynamodb_table_deletion_and_point_in_time_recovery"),
        "successful_deletion_observed": False,
        "restoration_observed": False,
        "runtime_table_state_evaluated": False,
        "descendant_impact_evaluated": False,
        "out_of_plan_table_topology_evaluated": False,
        "uncertainties": dedupe(uncertainties),
    }
    state = facts.dynamodb_pitr_state
    days = facts.dynamodb_pitr_recovery_period_days
    if state == STATE_ENABLED:
        if days is not None and days <= 0:
            uncertainties.append("point_in_time_recovery.recovery_period_in_days is not positive")
            days = None
        return {
            **common,
            "pitr_state": "enabled",
            "pitr_enabled": True,
            "pitr_recovery_period_days": days,
            "restore_target_kind": "new_table",
            "table_recovery_state": ("pitr_restore_to_new_table_configured"),
            "uncertainties": dedupe(uncertainties),
        }
    if state == STATE_DISABLED:
        return {
            **common,
            "pitr_state": "disabled",
            "pitr_enabled": False,
            "pitr_recovery_period_days": None,
            "restore_target_kind": None,
            "table_recovery_state": ("not_established_by_modeled_aws_dynamodb_table_evidence"),
        }
    if state == STATE_NOT_CONFIGURED:
        return {
            **common,
            "pitr_state": "not_configured",
            "pitr_enabled": False,
            "pitr_recovery_period_days": None,
            "restore_target_kind": None,
            "table_recovery_state": ("not_established_by_modeled_aws_dynamodb_table_evidence"),
        }
    if not uncertainties:
        uncertainties.append("point-in-time recovery posture is unresolved for table-deletion recovery evidence")
    return {
        **common,
        "pitr_state": "unknown",
        "pitr_enabled": None,
        "pitr_recovery_period_days": None,
        "restore_target_kind": None,
        "table_recovery_state": "unknown",
        "uncertainties": dedupe(uncertainties),
    }


def _path(
    task_definition: NormalizedResource,
    task_role: NormalizedResource,
    role_reference: str,
    role_account_id: str,
    table: NormalizedResource,
    table_name: str,
    table_account_id: str,
    proof: _EffectiveProof,
    table_posture: _TablePolicyPosture,
    constraint: dict[str, object],
) -> AwsEcsDynamoDbTableTopologyDestructionPath:
    table_arn = aws_facts(table).dynamodb_table_arn or table.arn
    recovery = _recovery_evidence(table)
    posture_uncertainties = dedupe(
        cast(list[str], recovery["uncertainties"]),
    )
    identity_sources = _identity_policy_sources(task_role)
    used_identity_sources = identity_sources if proof.identity_matches else []
    used_table_sources = dedupe(match.source_address for match in proof.table_matches)
    statement_records = [_statement_record(match) for match in (*proof.identity_matches, *proof.table_matches)]
    table_references = sorted(
        {match.matching_resource for match in (*proof.identity_matches, *proof.table_matches)},
        key=str.casefold,
    )
    table_reference = table_arn if table_arn is not None and table_arn in table_references else table_references[0]
    common: dict[str, object] = {
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
        "role_account_id": role_account_id,
        "role_provider_config_key": task_role.provider_config_key,
        "table_address": table.address,
        "table_resource_type": table.resource_type,
        "table_name": table_name,
        "table_reference": table_reference,
        "table_arn": table_arn,
        "table_account_id": table_account_id,
        "table_provider_config_key": table.provider_config_key,
        "operation": "dynamodb:DeleteTable",
        "operation_class": "table_deletion",
        "internal_operation": "delete_table",
        "management_effect": "disruption",
        "target_granularity": "table_topology",
        "target_scope": "exact_dynamodb_table",
        "target_model_evidence_addresses": [table.address],
        "authorization_source_addresses": dedupe([*used_identity_sources, *used_table_sources]),
        "authorization_state": "allowed",
        "evaluation_basis": ("modeled_identity_and_table_resource_policies"),
        "matched_actions": ["dynamodb:DeleteTable"],
        "identity_policy_complete": True,
        "table_policy_complete": True,
        "identity_policy_source_addresses": identity_sources,
        "table_policy_source_addresses": list(table_posture.source_addresses),
        "authorization_statements": statement_records,
        "explicit_deny": False,
        "conditional_evaluation_required": False,
        "lifecycle_compatibility_state": "compatible",
        "deletion_constraint_evidence": constraint,
        "recovery_evidence": recovery,
        "posture_uncertainties": posture_uncertainties,
    }
    if proof.grant_basis == "same_account_identity_policy":
        return cast(
            AwsEcsDynamoDbSameAccountIdentityTableDeletionPath,
            {
                **common,
                "account_relationship": "same_account",
                "same_account": True,
                "grant_basis": proof.grant_basis,
                "identity_policy_allow_required": True,
                "table_policy_allow_required": False,
                "resource_policy_principal_match": None,
            },
        )
    if proof.grant_basis == "same_account_table_policy_direct":
        return cast(
            AwsEcsDynamoDbSameAccountTablePolicyDeletionPath,
            {
                **common,
                "account_relationship": "same_account",
                "same_account": True,
                "grant_basis": proof.grant_basis,
                "identity_policy_allow_required": False,
                "table_policy_allow_required": True,
                "resource_policy_principal_match": "role",
            },
        )
    if proof.grant_basis == "same_account_combined":
        return cast(
            AwsEcsDynamoDbSameAccountCombinedTableDeletionPath,
            {
                **common,
                "account_relationship": "same_account",
                "same_account": True,
                "grant_basis": proof.grant_basis,
                "identity_policy_allow_required": True,
                "table_policy_allow_required": True,
                "resource_policy_principal_match": proof.principal_match,
            },
        )
    return cast(
        AwsEcsDynamoDbCrossAccountTableDeletionPath,
        {
            **common,
            "account_relationship": "cross_account",
            "same_account": False,
            "grant_basis": proof.grant_basis,
            "identity_policy_allow_required": True,
            "table_policy_allow_required": True,
            "resource_policy_principal_match": proof.principal_match,
        },
    )


def _statement_record(
    match: _StatementMatch,
) -> AwsDynamoDbTableTopologyPolicyStatementEvidence:
    if match.source_kind == "identity_policy":
        identity_record: AwsDynamoDbTableTopologyIdentityPolicyStatementEvidence = {
            "source_address": match.source_address,
            "source_kind": "identity_policy",
            "effect": "allow",
            "actions": list(match.statement.actions),
            "matching_action_patterns": list(match.matching_action_patterns),
            "matched_actions": ["dynamodb:DeleteTable"],
            "resources": list(match.statement.resources),
            "matching_resources": [match.matching_resource],
            "resource_scopes": ["exact_table"],
            "principals": [],
            "principal_match": None,
            "conditions": [],
            "conditional": False,
        }
        return identity_record
    resource_record: AwsDynamoDbTableTopologyResourcePolicyStatementEvidence = {
        "source_address": match.source_address,
        "source_kind": "table_policy",
        "effect": "allow",
        "actions": list(match.statement.actions),
        "matching_action_patterns": list(match.matching_action_patterns),
        "matched_actions": ["dynamodb:DeleteTable"],
        "resources": list(match.statement.resources),
        "matching_resources": [match.matching_resource],
        "resource_scopes": ["exact_table"],
        "principals": sorted(_aws_principal_values(match.statement)),
        "principal_match": cast(_PrincipalMatch, match.principal_match),
        "conditions": [],
        "conditional": False,
    }
    return resource_record


def current_ecs_dynamodb_table_topology_destruction_path(
    task_definition: NormalizedResource,
    table: NormalizedResource,
    context: AwsDecorationContext,
) -> AwsEcsDynamoDbTableTopologyDestructionPath | None:
    """Recompute the current deterministic path for one task and table."""

    resources = tuple(context.index.resources_by_address.values())
    paths, _uncertainties = _task_definition_paths(
        task_definition,
        (table,),
        context,
        resources=resources,
        unresolved_policy_sources=_unresolved_table_policy_sources(
            resources,
            context,
        ),
    )
    return next(
        (path for path in paths if path["table_address"] == table.address and path["operation"] == _DELETE_TABLE),
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
        f"{task_definition.address}: task role reference {reference} is unresolved for DynamoDB table-deletion paths"
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
            "ambiguous or unresolved for DynamoDB table-deletion paths"
        )
    return dedupe(uncertainties)


def _resource_account_id(
    resource: NormalizedResource,
    arn: str | None,
    resources: Sequence[NormalizedResource],
) -> str | None:
    arn_account_id = parse_aws_account_id(arn)
    provider_account_id = _provider_account_id(
        resources,
        resource.provider_config_key,
    )
    if arn_account_id is not None and provider_account_id is not None and arn_account_id != provider_account_id:
        return None
    return arn_account_id or provider_account_id


def _resource_partition(
    resource: NormalizedResource,
    arn: str | None,
    resources: Sequence[NormalizedResource],
) -> str | None:
    arn_partition = _arn_partition(arn) if arn is not None else None
    provider_partitions = {
        partition
        for candidate in resources
        if candidate.resource_type == _CALLER_IDENTITY
        and candidate.provider_config_key == resource.provider_config_key
        and (partition := _arn_partition(candidate.arn)) is not None
    }
    if len(provider_partitions) > 1:
        return None
    provider_partition = next(iter(provider_partitions), None)
    if arn_partition is not None and provider_partition is not None and arn_partition != provider_partition:
        return None
    return arn_partition or provider_partition


def _provider_account_id(
    resources: Sequence[NormalizedResource],
    provider_config_key: str | None,
) -> str | None:
    caller_facts = [
        aws_facts(resource)
        for resource in resources
        if resource.resource_type == _CALLER_IDENTITY and resource.provider_config_key == provider_config_key
    ]
    states = {facts.caller_identity_account_id_state for facts in caller_facts}
    if states & {"ambiguous", "invalid", "unknown"}:
        return None
    account_ids = {
        facts.caller_identity_account_id for facts in caller_facts if facts.caller_identity_account_id is not None
    }
    if not account_ids:
        return None
    if states != {"resolved"} or len(account_ids) != 1:
        return None
    return next(iter(account_ids))


def _matching_action_patterns(
    patterns: Sequence[str],
) -> tuple[str, ...]:
    return tuple(pattern for pattern in patterns if fnmatchcase(_DELETE_TABLE.casefold(), pattern.casefold()))


def _role_has_delete_table_action(role: NormalizedResource) -> bool:
    return any(_matching_action_patterns(statement.actions) for statement in role.policy_statements)


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


def _broadest_principal_match(
    matches: Sequence[_StatementMatch],
) -> _PrincipalMatch:
    principal_matches = {match.principal_match for match in matches if match.principal_match is not None}
    if "wildcard" in principal_matches:
        return "wildcard"
    if "account" in principal_matches:
        return "account"
    return "role"


def _table_name(table: NormalizedResource) -> str | None:
    table_arn = aws_facts(table).dynamodb_table_arn or table.arn
    if _is_exact_dynamodb_table_arn(table_arn):
        return cast(str, table_arn).split(":", 5)[5][len("table/") :]
    if isinstance(table.identifier, str) and table.identifier and table.identifier != table.address:
        return table.identifier
    return None


def _is_exact_unmodeled_table_reference(value: str | None) -> bool:
    return bool(value is not None and _is_exact_dynamodb_table_arn(value))


def _is_exact_dynamodb_table_arn(value: str | None) -> bool:
    if value is None or _has_wildcard(value):
        return False
    parts = value.split(":", 5)
    return bool(
        len(parts) == 6
        and parts[0] == "arn"
        and parts[1]
        and parts[2] == "dynamodb"
        and parts[3]
        and parse_aws_account_id(value) is not None
        and parts[5].startswith("table/")
        and len(parts[5]) > len("table/")
        and "/" not in parts[5][len("table/") :]
    )


def _unwrap_reference(value: str) -> str:
    normalized = value.strip()
    if normalized.startswith("${") and normalized.endswith("}"):
        return normalized[2:-1].strip()
    return normalized


def _arn_partition(value: str | None) -> str | None:
    if value is None:
        return None
    parts = value.split(":", 2)
    return parts[1] if len(parts) == 3 and parts[0] == "arn" else None


def _has_wildcard(value: str) -> bool:
    return "*" in value or "?" in value


def _service_path(
    service: NormalizedResource,
    task_definition: NormalizedResource,
    path: AwsEcsDynamoDbTableTopologyDestructionPath,
) -> AwsEcsDynamoDbTableTopologyDestructionPath:
    projected = path.copy()
    projected["workload_address"] = service.address
    projected["workload_type"] = service.resource_type
    projected["task_definition_address"] = task_definition.address
    projected["task_definition_arn"] = task_definition.arn
    projected["internet_facing_load_balancers"] = aws_facts(service).internet_facing_load_balancer_addresses
    return projected


def _path_sort_key(
    path: AwsEcsDynamoDbTableTopologyDestructionPath,
) -> tuple[str, str]:
    return path["table_address"], path["role_address"]
