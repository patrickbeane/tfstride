from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Literal

from tfstride.models import IAMPolicyStatement, NormalizedResource
from tfstride.providers.aws.policy_documents import (
    policy_statement_is_fully_representable,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.aws.secret_management_evidence import (
    AwsSecretsManagerAuthorizationBasis,
    AwsSecretsManagerCandidateAuthorizationBasis,
    AwsSecretsManagerManagementEffect,
    AwsSecretsManagerOperation,
    AwsSecretsManagerOperationAuthorization,
    AwsSecretsManagerOperationClass,
    AwsSecretsManagerPolicyStatementEvidence,
)
from tfstride.providers.coercion import dedupe
from tfstride.resource_helpers import parse_aws_account_id

_SECRETS_MANAGER_SECRET = "aws_secretsmanager_secret"
_SECRETS_MANAGER_SECRET_POLICY = "aws_secretsmanager_secret_policy"
_IAM_ROLE = "aws_iam_role"
_COMPLETE = "complete"


@dataclass(frozen=True, slots=True)
class _OperationDefinition:
    action: AwsSecretsManagerOperation
    operation_class: AwsSecretsManagerOperationClass
    management_effect: AwsSecretsManagerManagementEffect


_OPERATION_CATALOG = (
    _OperationDefinition(
        "secretsmanager:PutSecretValue",
        "value_mutation",
        "tampering",
    ),
    _OperationDefinition(
        "secretsmanager:UpdateSecret",
        "value_mutation",
        "tampering",
    ),
    _OperationDefinition(
        "secretsmanager:UpdateSecretVersionStage",
        "version_stage_mutation",
        "tampering",
    ),
    _OperationDefinition(
        "secretsmanager:DeleteSecret",
        "destructive_administration",
        "disruption",
    ),
)
_OPERATION_BY_NAME = {definition.action: definition for definition in _OPERATION_CATALOG}
_OPERATION_ORDER = {definition.action.casefold(): index for index, definition in enumerate(_OPERATION_CATALOG)}
_SUPPORTED_AUTHORIZATION_BASES: tuple[AwsSecretsManagerAuthorizationBasis, ...] = (
    "identity_policy",
    "resource_policy_direct",
    "cross_account_identity_and_resource_policy",
)


@dataclass(frozen=True, slots=True)
class _StatementMatch:
    statement: IAMPolicyStatement
    operation: AwsSecretsManagerOperation
    source_address: str
    source_kind: Literal["identity_policy", "resource_policy"]
    matching_action_patterns: tuple[str, ...]
    matching_resources: tuple[str, ...]
    principal_match: str | None = None

    @property
    def effect(self) -> str:
        return self.statement.effect.strip().casefold()

    @property
    def conditional(self) -> bool:
        return bool(self.statement.conditions)


@dataclass(frozen=True, slots=True)
class _ResourcePolicyPosture:
    sources: tuple[NormalizedResource, ...]
    source_addresses: tuple[str, ...]
    complete: bool
    uncertainties: tuple[str, ...]


class ModelSecretsManagerOperationAuthorizationStage:
    """Model effective role authority over exact Secrets Manager secrets."""

    name = "model_secrets_manager_operation_authorization"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AwsDecorationContext,
    ) -> None:
        roles = tuple(resource for resource in resources if resource.resource_type == _IAM_ROLE)
        unresolved_policy_sources = _unresolved_resource_policy_sources(
            resources,
            context,
        )
        for secret in resources:
            if secret.resource_type != _SECRETS_MANAGER_SECRET:
                continue
            authorizations, uncertainties = _operation_authorization_posture(
                secret,
                roles,
                context,
                unresolved_policy_sources=unresolved_policy_sources,
            )
            aws_facts(secret).set_secrets_manager_operation_authorization_posture(
                authorizations=authorizations,
                uncertainties=uncertainties,
            )


def _operation_authorization_posture(
    secret: NormalizedResource,
    roles: Sequence[NormalizedResource],
    context: AwsDecorationContext,
    *,
    unresolved_policy_sources: tuple[str, ...],
) -> tuple[list[AwsSecretsManagerOperationAuthorization], list[str]]:
    secret_arn = secret.arn
    if not _is_exact_secret_arn(secret_arn):
        return [], [f"{secret.address}: exact Secrets Manager ARN is unresolved"]
    assert secret_arn is not None

    secret_account_id = parse_aws_account_id(secret_arn)
    if secret_account_id is None:
        return [], [f"{secret.address}: Secrets Manager ARN does not contain an exact AWS account ID"]

    resource_posture = _resource_policy_posture(
        secret,
        context,
        unresolved_policy_sources=unresolved_policy_sources,
    )
    uncertainties = list(resource_posture.uncertainties)
    authorizations: list[AwsSecretsManagerOperationAuthorization] = []

    for role in roles:
        role_arn = role.arn
        if not _is_exact_iam_role_arn(role_arn):
            continue
        assert role_arn is not None
        role_account_id = parse_aws_account_id(role_arn)
        if role_account_id is None:
            continue

        identity_matches = _identity_policy_matches(
            role,
            secret_arn,
        )
        (
            direct_resource_matches,
            account_resource_matches,
            resource_deny_matches,
            wildcard_resource_matches,
        ) = _resource_policy_matches(
            resource_posture.sources,
            secret_arn=secret_arn,
            role_arn=role_arn,
            role_account_id=role_account_id,
        )

        role_facts = aws_facts(role)
        identity_policy_complete = (
            role_facts.iam_policy_completeness_state == _COMPLETE
            and not role_facts.unresolved_attached_policy_arns
            and _identity_policy_is_representable(role.policy_statements)
        )
        candidate_operations: set[AwsSecretsManagerOperation] = {
            match.operation
            for match in (
                *identity_matches,
                *direct_resource_matches,
                *account_resource_matches,
                *resource_deny_matches,
                *wildcard_resource_matches,
            )
        }
        if not identity_policy_complete or not resource_posture.complete:
            candidate_operations.update(definition.action for definition in _OPERATION_CATALOG)

        same_account = role_account_id == secret_account_id and _arn_partition(role_arn) == _arn_partition(secret_arn)
        partitions_match = _arn_partition(role_arn) == _arn_partition(secret_arn)

        for operation in sorted(candidate_operations, key=_operation_sort_key):
            authorization, operation_uncertainties = _authorization_record(
                secret,
                role,
                operation,
                identity_matches=_for_operation(identity_matches, operation),
                direct_resource_matches=_for_operation(
                    direct_resource_matches,
                    operation,
                ),
                account_resource_matches=_for_operation(
                    account_resource_matches,
                    operation,
                ),
                resource_deny_matches=_for_operation(
                    resource_deny_matches,
                    operation,
                ),
                wildcard_resource_matches=_for_operation(
                    wildcard_resource_matches,
                    operation,
                ),
                identity_policy_complete=identity_policy_complete,
                resource_policy_complete=resource_posture.complete,
                secrets_manager_resource_policy_source_addresses=resource_posture.source_addresses,
                resource_policy_uncertainties=resource_posture.uncertainties,
                same_account=same_account,
                partitions_match=partitions_match,
            )
            authorizations.append(authorization)
            uncertainties.extend(operation_uncertainties)

    authorizations.sort(
        key=lambda record: (
            record["principal_address"],
            _operation_sort_key(record["operation"]),
            record["secret_address"],
        )
    )
    return authorizations, dedupe(uncertainties)


def _authorization_record(
    secret: NormalizedResource,
    role: NormalizedResource,
    operation: AwsSecretsManagerOperation,
    *,
    identity_matches: list[_StatementMatch],
    direct_resource_matches: list[_StatementMatch],
    account_resource_matches: list[_StatementMatch],
    resource_deny_matches: list[_StatementMatch],
    wildcard_resource_matches: list[_StatementMatch],
    identity_policy_complete: bool,
    resource_policy_complete: bool,
    secrets_manager_resource_policy_source_addresses: tuple[str, ...],
    resource_policy_uncertainties: tuple[str, ...],
    same_account: bool,
    partitions_match: bool,
) -> tuple[AwsSecretsManagerOperationAuthorization, list[str]]:
    identity_denies = [match for match in identity_matches if match.effect == "deny"]
    identity_allows = [match for match in identity_matches if match.effect == "allow"]
    direct_resource_allows = [match for match in direct_resource_matches if match.effect == "allow"]
    account_resource_allows = [match for match in account_resource_matches if match.effect == "allow"]
    wildcard_resource_allows = [match for match in wildcard_resource_matches if match.effect == "allow"]

    unconditional_identity_deny = _has_unconditional(identity_denies)
    unconditional_resource_deny = _has_unconditional(resource_deny_matches)
    conditional_deny = _has_conditional(identity_denies) or _has_conditional(resource_deny_matches)
    unconditional_identity_allow = _has_unconditional(identity_allows)
    unconditional_direct_resource_allow = _has_unconditional(direct_resource_allows)
    unconditional_account_resource_allow = _has_unconditional(account_resource_allows)
    conditional_allow = any(
        _has_conditional(matches)
        for matches in (
            identity_allows,
            direct_resource_allows,
            account_resource_allows,
            wildcard_resource_allows,
        )
    )

    candidate_bases: list[AwsSecretsManagerCandidateAuthorizationBasis] = []
    if same_account:
        if identity_allows:
            candidate_bases.append("identity_policy")
        if direct_resource_allows:
            candidate_bases.append("resource_policy_direct")
    elif identity_allows or direct_resource_allows or account_resource_allows:
        candidate_bases.append("cross_account_identity_and_resource_policy")
    if wildcard_resource_allows:
        candidate_bases.append("wildcard_resource_policy")

    authorization_bases: list[AwsSecretsManagerAuthorizationBasis] = []
    if same_account:
        if unconditional_identity_allow:
            authorization_bases.append("identity_policy")
        if unconditional_direct_resource_allow:
            authorization_bases.append("resource_policy_direct")
    elif (
        partitions_match
        and unconditional_identity_allow
        and (unconditional_direct_resource_allow or unconditional_account_resource_allow)
    ):
        authorization_bases.append("cross_account_identity_and_resource_policy")

    explicit_deny = unconditional_identity_deny or unconditional_resource_deny
    incomplete_evidence = not identity_policy_complete or not resource_policy_complete
    cross_account_candidate = not same_account and bool(
        identity_allows or direct_resource_allows or account_resource_allows or wildcard_resource_allows
    )
    if explicit_deny:
        authorization_state = "denied"
        authorization_bases = []
    elif incomplete_evidence or conditional_deny:
        authorization_state = "unknown"
        authorization_bases = []
    elif cross_account_candidate and not partitions_match:
        authorization_state = "unknown"
        authorization_bases = []
    elif authorization_bases:
        authorization_state = "allowed"
    elif wildcard_resource_allows or conditional_allow:
        authorization_state = "unknown"
        authorization_bases = []
    else:
        authorization_state = "not_allowed"

    uncertainties: list[str] = []
    if not identity_policy_complete:
        uncertainties.append(
            f"{secret.address}: {role.address} {operation} authorization is unknown "
            "because identity-policy evidence is incomplete"
        )
    if not resource_policy_complete:
        uncertainties.append(
            f"{secret.address}: {role.address} {operation} authorization is unknown "
            "because effective Secrets Manager resource-policy evidence is incomplete"
        )
    if cross_account_candidate and not partitions_match:
        uncertainties.append(
            f"{secret.address}: {role.address} {operation} uses cross-partition "
            "resource-policy semantics that are not modeled"
        )
    if conditional_deny or conditional_allow:
        uncertainties.append(
            f"{secret.address}: {role.address} {operation} has conditional policy "
            "evidence whose applicability depends on runtime context"
        )
    if wildcard_resource_allows:
        uncertainties.append(
            f"{secret.address}: {role.address} {operation} has wildcard-principal "
            "resource-policy allow evidence outside the exact-principal model"
        )

    role_facts = aws_facts(role)
    identity_policy_sources = dedupe(
        [
            role.address,
            *role_facts.inline_policy_resource_addresses,
            *role_facts.attached_policy_addresses,
        ]
    )
    conditional_evidence_present = conditional_deny or conditional_allow
    definition = _OPERATION_BY_NAME[operation]
    record: AwsSecretsManagerOperationAuthorization = {
        "secret_address": secret.address,
        "secret_resource_type": secret.resource_type,
        "secret_arn": secret.arn or "",
        "secret_name": aws_facts(secret).name,
        "principal_address": role.address,
        "principal_arn": role.arn or "",
        "principal_kind": "iam_role",
        "operation": operation,
        "operation_class": definition.operation_class,
        "management_effect": definition.management_effect,
        "supported_authorization_bases": list(_SUPPORTED_AUTHORIZATION_BASES),
        "authorization_state": authorization_state,
        "authorization_bases": authorization_bases,
        "candidate_authorization_bases": candidate_bases,
        "same_account": same_account,
        "identity_policy_required": not same_account,
        "resource_policy_required": not same_account,
        "identity_policy_complete": identity_policy_complete,
        "resource_policy_complete": resource_policy_complete,
        "identity_policy_source_addresses": identity_policy_sources,
        "secrets_manager_resource_policy_source_addresses": list(secrets_manager_resource_policy_source_addresses),
        "unresolved_attached_policy_arns": list(role_facts.unresolved_attached_policy_arns),
        "identity_policy_uncertainties": list(role_facts.iam_policy_posture_uncertainties),
        "resource_policy_uncertainties": list(resource_policy_uncertainties),
        "explicit_deny": explicit_deny,
        "conditional_policy_evidence_present": conditional_evidence_present,
        "authorization_requires_condition_evaluation": (
            authorization_state == "unknown" and conditional_evidence_present
        ),
        "identity_policy_statements": [_statement_record(match) for match in identity_matches],
        "resource_policy_statements": [
            _statement_record(match)
            for match in (
                *direct_resource_matches,
                *account_resource_matches,
                *resource_deny_matches,
                *wildcard_resource_matches,
            )
        ],
        "evaluation_scope": ("modeled_identity_and_secrets_manager_resource_policies"),
    }
    return record, uncertainties


def _identity_policy_matches(
    role: NormalizedResource,
    secret_arn: str,
) -> list[_StatementMatch]:
    matches: list[_StatementMatch] = []
    for statement in role.policy_statements:
        if statement.effect.strip().casefold() not in {"allow", "deny"}:
            continue
        matching_resources = tuple(
            resource for resource in statement.resources if _policy_resource_matches(resource, secret_arn)
        )
        if not matching_resources:
            continue
        for definition, patterns in _matching_operations(statement.actions):
            matches.append(
                _StatementMatch(
                    statement,
                    definition.action,
                    role.address,
                    "identity_policy",
                    patterns,
                    matching_resources,
                )
            )
    return matches


def _resource_policy_matches(
    sources: Sequence[NormalizedResource],
    *,
    secret_arn: str,
    role_arn: str,
    role_account_id: str,
) -> tuple[
    list[_StatementMatch],
    list[_StatementMatch],
    list[_StatementMatch],
    list[_StatementMatch],
]:
    direct: list[_StatementMatch] = []
    account: list[_StatementMatch] = []
    denies: list[_StatementMatch] = []
    wildcard: list[_StatementMatch] = []
    account_root_arn = f"arn:{role_arn.split(':', 2)[1]}:iam::{role_account_id}:root"

    for source in sources:
        for statement in source.policy_statements:
            effect = statement.effect.strip().casefold()
            if effect not in {"allow", "deny"}:
                continue
            matching_resources = tuple(
                resource for resource in statement.resources if _policy_resource_matches(resource, secret_arn)
            )
            if not matching_resources:
                continue

            principal_values = _aws_principal_values(statement)
            direct_principal = role_arn in principal_values
            account_principal = bool(principal_values & {role_account_id, account_root_arn})
            wildcard_principal = "*" in principal_values
            if not (direct_principal or account_principal or wildcard_principal):
                continue

            for definition, patterns in _matching_operations(statement.actions):
                principal_match = "role" if direct_principal else "account" if account_principal else "wildcard"
                match = _StatementMatch(
                    statement,
                    definition.action,
                    source.address,
                    "resource_policy",
                    patterns,
                    matching_resources,
                    principal_match,
                )
                if effect == "deny":
                    denies.append(match)
                elif direct_principal:
                    direct.append(match)
                elif account_principal:
                    account.append(match)
                else:
                    wildcard.append(match)

    return direct, account, denies, wildcard


def _resource_policy_posture(
    secret: NormalizedResource,
    context: AwsDecorationContext,
    *,
    unresolved_policy_sources: tuple[str, ...],
) -> _ResourcePolicyPosture:
    source_addresses = tuple(dedupe(aws_facts(secret).resource_policy_source_addresses))
    sources: list[NormalizedResource] = []
    uncertainties: list[str] = []

    for source_address in source_addresses:
        source = context.index.resources_by_address.get(source_address)
        if source is None or source.resource_type != _SECRETS_MANAGER_SECRET_POLICY:
            uncertainties.append(f"{secret.address}: resource-policy source {source_address} is unavailable")
            continue
        sources.append(source)
        if not _resource_policy_is_representable(source):
            uncertainties.append(
                f"{secret.address}: {source.address} resource policy is incomplete, malformed, or unsupported"
            )

    if len(source_addresses) > 1:
        uncertainties.append(
            f"{secret.address}: multiple Secrets Manager resource-policy resources "
            "provide conflicting authoritative evidence"
        )
    if unresolved_policy_sources:
        uncertainties.extend(
            f"{secret.address}: {source_address} has an unresolved Secrets Manager resource-policy target"
            for source_address in unresolved_policy_sources
        )

    complete = (
        len(sources) == len(source_addresses)
        and len(source_addresses) <= 1
        and all(_resource_policy_is_representable(source) for source in sources)
        and not unresolved_policy_sources
    )
    return _ResourcePolicyPosture(
        tuple(sources),
        source_addresses,
        complete,
        tuple(dedupe(uncertainties)),
    )


def _unresolved_resource_policy_sources(
    resources: Sequence[NormalizedResource],
    context: AwsDecorationContext,
) -> tuple[str, ...]:
    unresolved: list[str] = []
    for resource in resources:
        if resource.resource_type != _SECRETS_MANAGER_SECRET_POLICY:
            continue
        target = aws_facts(resource).secret_arn
        if target and context.index.secrets.get(target, source=resource) is not None:
            continue
        if _is_exact_secret_arn(target):
            continue
        unresolved.append(resource.address)
    return tuple(dedupe(unresolved))


def _resource_policy_is_representable(source: NormalizedResource) -> bool:
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
            for raw_statement, statement in zip(
                statement_documents,
                statements,
                strict=True,
            )
        )
    )


def _identity_policy_is_representable(
    statements: tuple[IAMPolicyStatement, ...],
) -> bool:
    return all(
        statement.effect.strip().casefold() in {"allow", "deny"}
        and bool(statement.actions)
        and bool(statement.resources)
        and not statement.principal_entries
        for statement in statements
    )


def _matching_operations(
    action_patterns: list[str],
) -> list[tuple[_OperationDefinition, tuple[str, ...]]]:
    matches: list[tuple[_OperationDefinition, tuple[str, ...]]] = []
    for definition in _OPERATION_CATALOG:
        patterns = tuple(
            pattern for pattern in action_patterns if fnmatchcase(definition.action.casefold(), pattern.casefold())
        )
        if patterns:
            matches.append((definition, patterns))
    return matches


def _policy_resource_matches(resource: str, secret_arn: str) -> bool:
    if resource == "*":
        return True
    return _is_secret_arn_pattern(resource) and fnmatchcase(secret_arn, resource)


def _is_secret_arn_pattern(value: str) -> bool:
    parts = value.split(":", 5)
    return bool(
        len(parts) == 6
        and parts[0] == "arn"
        and parts[1]
        and parts[2] == "secretsmanager"
        and parts[3]
        and parts[4]
        and parts[5].startswith("secret:")
        and len(parts[5]) > len("secret:")
    )


def _is_exact_secret_arn(value: str | None) -> bool:
    return bool(
        value and not _has_wildcard(value) and _is_secret_arn_pattern(value) and parse_aws_account_id(value) is not None
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


def _aws_principal_values(statement: IAMPolicyStatement) -> set[str]:
    return {entry.value for entry in statement.principal_entries if entry.kind.casefold() in {"aws", "unknown"}}


def _statement_record(
    match: _StatementMatch,
) -> AwsSecretsManagerPolicyStatementEvidence:
    statement = match.statement
    return {
        "source_address": match.source_address,
        "source_kind": match.source_kind,
        "effect": match.effect,
        "actions": list(statement.actions),
        "matching_action_patterns": list(match.matching_action_patterns),
        "resources": list(statement.resources),
        "matching_resources": list(match.matching_resources),
        "principals": list(statement.principals),
        "principal_match": match.principal_match,
        "conditions": [
            {
                "operator": condition.operator,
                "key": condition.key,
                "values": list(condition.values),
            }
            for condition in statement.conditions
        ],
        "conditional": match.conditional,
    }


def _for_operation(
    matches: Sequence[_StatementMatch],
    operation: AwsSecretsManagerOperation,
) -> list[_StatementMatch]:
    return [match for match in matches if match.operation == operation]


def _has_unconditional(matches: Sequence[_StatementMatch]) -> bool:
    return any(not match.conditional for match in matches)


def _has_conditional(matches: Sequence[_StatementMatch]) -> bool:
    return any(match.conditional for match in matches)


def _operation_sort_key(operation: str) -> tuple[int, str]:
    return (
        _OPERATION_ORDER.get(operation.casefold(), len(_OPERATION_ORDER)),
        operation.casefold(),
    )


def _arn_partition(value: str) -> str | None:
    parts = value.split(":", 2)
    return parts[1] if len(parts) == 3 and parts[0] == "arn" else None


def _has_wildcard(value: str) -> bool:
    return "*" in value or "?" in value
