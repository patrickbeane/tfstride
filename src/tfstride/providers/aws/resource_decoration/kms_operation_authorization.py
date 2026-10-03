from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any, TypeVar

from tfstride.models import IAMPolicyCondition, IAMPolicyStatement, NormalizedResource
from tfstride.providers.aws.kms_evidence import (
    AwsKmsAuthorizationBasis,
    AwsKmsCandidateAuthorizationBasis,
    AwsKmsGrantAuthorizationEvidence,
    AwsKmsKeyOriginCompatibilityState,
    AwsKmsOperationAuthorization,
    AwsKmsOperationClass,
    AwsKmsPolicyConditionEvidence,
    AwsKmsPolicyStatementEvidence,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.coercion import dedupe
from tfstride.resource_helpers import parse_aws_account_id

_KMS_KEY = "aws_kms_key"
_IAM_ROLE = "aws_iam_role"
_KMS_GRANT = "aws_kms_grant"
_COMPLETE = "complete"


@dataclass(frozen=True, slots=True)
class _KmsOperationDefinition:
    action: str
    operation_class: AwsKmsOperationClass
    supported_authorization_bases: tuple[AwsKmsAuthorizationBasis, ...]
    required_key_origins: tuple[str, ...] = ()


_POLICY_AUTHORIZATION_BASES: tuple[AwsKmsAuthorizationBasis, ...] = (
    "direct_key_policy",
    "iam_via_account_principal",
)
_POLICY_AND_GRANT_AUTHORIZATION_BASES: tuple[AwsKmsAuthorizationBasis, ...] = (
    *_POLICY_AUTHORIZATION_BASES,
    "kms_grant",
)

KMS_CRYPTOGRAPHIC_OPERATIONS = (
    "kms:Decrypt",
    "kms:Encrypt",
    "kms:ReEncryptFrom",
    "kms:ReEncryptTo",
    "kms:GenerateDataKey",
    "kms:GenerateDataKeyWithoutPlaintext",
    "kms:GenerateDataKeyPair",
    "kms:GenerateDataKeyPairWithoutPlaintext",
    "kms:Sign",
    "kms:Verify",
    "kms:GenerateMac",
    "kms:VerifyMac",
    "kms:GetPublicKey",
    "kms:DeriveSharedSecret",
)
_KMS_OPERATION_CATALOG = (
    *(
        _KmsOperationDefinition(
            operation,
            "cryptographic_use",
            _POLICY_AND_GRANT_AUTHORIZATION_BASES,
        )
        for operation in KMS_CRYPTOGRAPHIC_OPERATIONS
    ),
    _KmsOperationDefinition(
        "kms:CreateGrant",
        "authorization_administration",
        _POLICY_AND_GRANT_AUTHORIZATION_BASES,
    ),
    _KmsOperationDefinition(
        "kms:PutKeyPolicy",
        "authorization_administration",
        _POLICY_AUTHORIZATION_BASES,
    ),
    _KmsOperationDefinition(
        "kms:DisableKey",
        "disruptive_administration",
        _POLICY_AUTHORIZATION_BASES,
    ),
    _KmsOperationDefinition(
        "kms:ScheduleKeyDeletion",
        "destructive_administration",
        _POLICY_AUTHORIZATION_BASES,
    ),
    _KmsOperationDefinition(
        "kms:DeleteImportedKeyMaterial",
        "destructive_administration",
        _POLICY_AUTHORIZATION_BASES,
        ("EXTERNAL",),
    ),
    _KmsOperationDefinition(
        "kms:CancelKeyDeletion",
        "recovery",
        _POLICY_AUTHORIZATION_BASES,
    ),
    _KmsOperationDefinition(
        "kms:EnableKey",
        "recovery",
        _POLICY_AUTHORIZATION_BASES,
    ),
    _KmsOperationDefinition(
        "kms:RotateKeyOnDemand",
        "lifecycle_administration",
        _POLICY_AUTHORIZATION_BASES,
        ("AWS_KMS", "EXTERNAL"),
    ),
    _KmsOperationDefinition(
        "kms:GetKeyPolicy",
        "metadata_read",
        _POLICY_AUTHORIZATION_BASES,
    ),
)
_OPERATION_DEFINITIONS_BY_NAME = {definition.action: definition for definition in _KMS_OPERATION_CATALOG}
_OPERATION_ORDER = {definition.action.casefold(): index for index, definition in enumerate(_KMS_OPERATION_CATALOG)}
_GRANT_OPERATION_NAMES = {
    definition.action.removeprefix("kms:").casefold(): definition.action
    for definition in _KMS_OPERATION_CATALOG
    if "kms_grant" in definition.supported_authorization_bases
}


@dataclass(frozen=True, slots=True)
class _StatementMatch:
    statement: IAMPolicyStatement
    operation: str
    source_kind: str
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
class _GrantMatch:
    source: str
    operation: str
    constraints: Mapping[str, Any]
    constraint_state: str
    posture_uncertainties: tuple[str, ...]

    @property
    def deterministic(self) -> bool:
        return not self.posture_uncertainties and self.constraint_state in {
            "not_configured",
            "encryption_context",
        }


_OperationMatch = TypeVar("_OperationMatch", _StatementMatch, _GrantMatch)


class ModelKmsOperationAuthorizationStage:
    """Model role-to-key operation authority across KMS authorization sources."""

    name = "model_kms_operation_authorization"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AwsDecorationContext,
    ) -> None:
        roles = tuple(resource for resource in resources if resource.resource_type == _IAM_ROLE)
        for key in resources:
            if key.resource_type != _KMS_KEY:
                continue
            authorizations, uncertainties = current_kms_operation_authorizations(
                key,
                roles,
                context,
            )
            aws_facts(key).set_kms_operation_authorization_posture(
                authorizations=authorizations,
                uncertainties=uncertainties,
            )


def current_kms_operation_authorizations(
    key: NormalizedResource,
    roles: tuple[NormalizedResource, ...],
    context: AwsDecorationContext,
) -> tuple[list[AwsKmsOperationAuthorization], list[str]]:
    key_facts = aws_facts(key)
    key_arn = key_facts.kms_key_arn or key.arn
    if not _is_exact_kms_key_arn(key_arn):
        return [], [f"{key.address}: exact KMS key ARN is unresolved"]
    assert key_arn is not None

    key_account_id = parse_aws_account_id(key_arn)
    if key_account_id is None:
        return [], [f"{key.address}: KMS key ARN does not contain an exact AWS account ID"]

    key_policy_complete = key_facts.kms_policy_completeness_state == _COMPLETE and _key_policy_is_representable(
        key.policy_statements
    )
    uncertainties = _attached_grant_uncertainties(key, context)
    if not key_policy_complete:
        uncertainties.append(
            f"{key.address}: effective KMS key policy is incomplete, conflicting, malformed, or unknown"
        )

    authorizations: list[AwsKmsOperationAuthorization] = []
    for role in roles:
        role_arn = role.arn
        if not _is_exact_iam_role_arn(role_arn):
            continue
        assert role_arn is not None
        role_account_id = parse_aws_account_id(role_arn)
        if role_account_id is None:
            continue

        identity_matches = _identity_policy_matches(role.policy_statements, key_arn)
        direct_matches, delegation_matches, key_deny_matches, wildcard_allow_matches = _key_policy_matches(
            key.policy_statements,
            key_arn=key_arn,
            role_arn=role_arn,
            account_root_arn=f"arn:{key_arn.split(':', 2)[1]}:iam::{key_account_id}:root",
        )
        grant_matches, grant_uncertainties = _grant_matches(
            key,
            role_arn,
            context,
        )
        uncertainties.extend(grant_uncertainties)

        role_facts = aws_facts(role)
        role_policy_complete = (
            role_facts.iam_policy_completeness_state == _COMPLETE
            and not role_facts.unresolved_attached_policy_arns
            and _identity_policy_is_representable(role.policy_statements)
        )

        candidate_operations = sorted(
            {
                match.operation
                for match in (
                    *identity_matches,
                    *direct_matches,
                    *key_deny_matches,
                    *wildcard_allow_matches,
                    *grant_matches,
                    *(delegation_matches if not role_policy_complete else ()),
                )
            },
            key=_operation_sort_key,
        )
        if not candidate_operations:
            continue

        same_account = role_account_id == key_account_id and _arn_partition(role_arn) == _arn_partition(key_arn)

        for operation in candidate_operations:
            operation_identity = _for_operation(identity_matches, operation)
            operation_direct = _for_operation(direct_matches, operation)
            operation_delegation = _for_operation(delegation_matches, operation)
            operation_key_denies = _for_operation(key_deny_matches, operation)
            operation_wildcard_allows = _for_operation(wildcard_allow_matches, operation)
            operation_grants = _for_operation(grant_matches, operation)
            record, operation_uncertainties = _authorization_record(
                key,
                role,
                operation,
                identity_matches=operation_identity,
                direct_matches=operation_direct,
                delegation_matches=operation_delegation,
                key_deny_matches=operation_key_denies,
                wildcard_allow_matches=operation_wildcard_allows,
                grant_matches=operation_grants,
                key_policy_complete=key_policy_complete,
                role_policy_complete=role_policy_complete,
                same_account=same_account,
            )
            authorizations.append(record)
            uncertainties.extend(operation_uncertainties)

    authorizations.sort(
        key=lambda record: (
            str(record["principal_address"]),
            _operation_sort_key(str(record["operation"])),
            str(record["key_address"]),
        )
    )
    return authorizations, dedupe(uncertainties)


def _authorization_record(
    key: NormalizedResource,
    role: NormalizedResource,
    operation: str,
    *,
    identity_matches: list[_StatementMatch],
    direct_matches: list[_StatementMatch],
    delegation_matches: list[_StatementMatch],
    key_deny_matches: list[_StatementMatch],
    wildcard_allow_matches: list[_StatementMatch],
    grant_matches: list[_GrantMatch],
    key_policy_complete: bool,
    role_policy_complete: bool,
    same_account: bool,
) -> tuple[AwsKmsOperationAuthorization, list[str]]:
    identity_denies = [match for match in identity_matches if match.effect == "deny"]
    identity_allows = [match for match in identity_matches if match.effect == "allow"]
    unconditional_identity_deny = _has_unconditional(identity_denies)
    unconditional_key_deny = key_policy_complete and _has_unconditional(key_deny_matches)
    conditional_deny = _has_conditional(identity_denies) or (key_policy_complete and _has_conditional(key_deny_matches))

    unconditional_identity_allow = _has_unconditional(identity_allows)
    unconditional_direct_allow = key_policy_complete and same_account and _has_unconditional(direct_matches)
    unconditional_delegation = key_policy_complete and same_account and _has_unconditional(delegation_matches)
    deterministic_grants = [match for match in grant_matches if match.deterministic]
    uncertain_grants = [match for match in grant_matches if not match.deterministic]

    candidate_bases: list[AwsKmsCandidateAuthorizationBasis] = []
    if direct_matches:
        candidate_bases.append("direct_key_policy")
    if identity_allows or (delegation_matches and not role_policy_complete):
        candidate_bases.append("iam_via_account_principal")
    if grant_matches:
        candidate_bases.append("kms_grant")
    if wildcard_allow_matches:
        candidate_bases.append("wildcard_key_policy")

    allowed_bases: list[AwsKmsAuthorizationBasis] = []
    if unconditional_direct_allow:
        allowed_bases.append("direct_key_policy")
    if unconditional_delegation and unconditional_identity_allow:
        allowed_bases.append("iam_via_account_principal")
    if deterministic_grants and same_account:
        allowed_bases.append("kms_grant")

    conditional_allow = (
        _has_conditional(identity_allows)
        or _has_conditional(direct_matches)
        or _has_conditional(delegation_matches)
        or _has_conditional(wildcard_allow_matches)
    )
    incomplete_evidence = not key_policy_complete or not role_policy_complete

    if unconditional_identity_deny or unconditional_key_deny:
        state = "denied"
        allowed_bases = []
    elif incomplete_evidence or not same_account or conditional_deny:
        state = "unknown"
        allowed_bases = []
    elif allowed_bases:
        state = "allowed"
    elif wildcard_allow_matches or uncertain_grants or conditional_allow:
        state = "unknown"
        allowed_bases = []
    else:
        state = "not_allowed"

    uncertainties: list[str] = []
    if not key_policy_complete:
        uncertainties.append(
            f"{key.address}: {role.address} {operation} authorization is unknown because the effective key policy is unresolved"
        )
    if not role_policy_complete:
        uncertainties.append(
            f"{key.address}: {role.address} {operation} authorization is unknown because identity-policy evidence is incomplete"
        )
    if not same_account:
        uncertainties.append(
            f"{key.address}: {role.address} {operation} uses cross-account authorization semantics that are not modeled"
        )
    if conditional_deny or conditional_allow:
        uncertainties.append(
            f"{key.address}: {role.address} {operation} has conditional policy evidence whose applicability depends on runtime context"
        )
    if wildcard_allow_matches:
        uncertainties.append(
            f"{key.address}: {role.address} {operation} has wildcard-principal key-policy allow evidence outside the exact-principal authorization model"
        )
    if uncertain_grants:
        uncertainties.append(
            f"{key.address}: {role.address} {operation} has grant evidence that is not direct deterministic role authority"
        )

    key_facts = aws_facts(key)
    role_facts = aws_facts(role)
    operation_definition = _OPERATION_DEFINITIONS_BY_NAME[operation]
    key_origin = key_facts.kms_key_origin
    identity_policy_sources = [
        role.address,
        *role_facts.inline_policy_resource_addresses,
        *role_facts.attached_policy_addresses,
    ]
    conditional_evidence_present = conditional_deny or conditional_allow
    authorization_requires_condition_evaluation = state == "unknown" and conditional_evidence_present
    record: AwsKmsOperationAuthorization = {
        "key_address": key.address,
        "key_arn": key_facts.kms_key_arn or key.arn,
        "key_id": key_facts.kms_key_id or key.identifier,
        "key_usage": key_facts.kms_key_usage,
        "key_spec": key_facts.kms_key_spec,
        "principal_address": role.address,
        "principal_arn": role.arn,
        "principal_kind": "iam_role",
        "operation": operation,
        "operation_class": operation_definition.operation_class,
        "supported_authorization_bases": list(operation_definition.supported_authorization_bases),
        "authorization_state": state,
        "authorization_bases": list(allowed_bases),
        "candidate_authorization_bases": list(candidate_bases),
        "key_policy_complete": key_policy_complete,
        "identity_policy_complete": role_policy_complete,
        "key_policy_source_addresses": list(key_facts.kms_policy_source_addresses),
        "identity_policy_source_addresses": dedupe(identity_policy_sources),
        "unresolved_attached_policy_arns": list(role_facts.unresolved_attached_policy_arns),
        "key_policy_uncertainties": list(key_facts.kms_policy_posture_uncertainties),
        "identity_policy_uncertainties": list(role_facts.iam_policy_posture_uncertainties),
        "same_account": same_account,
        "key_origin": key_origin,
        "required_key_origins": list(operation_definition.required_key_origins),
        "key_origin_compatibility_state": _key_origin_compatibility_state(
            operation_definition,
            key_origin,
        ),
        "explicit_deny": unconditional_identity_deny or unconditional_key_deny,
        "conditional_policy_evidence_present": conditional_evidence_present,
        "authorization_requires_condition_evaluation": authorization_requires_condition_evaluation,
        "conditional_evaluation_required": authorization_requires_condition_evaluation,
        "constraint_state": _combined_constraint_state(grant_matches),
        "identity_policy_statements": [_statement_record(match) for match in identity_matches],
        "key_policy_statements": [
            _statement_record(match)
            for match in (*direct_matches, *delegation_matches, *key_deny_matches, *wildcard_allow_matches)
        ],
        "kms_grants": [_grant_record(match) for match in grant_matches],
        "evaluation_scope": "modeled_key_policy_identity_policies_and_grants",
    }
    return record, uncertainties


def _identity_policy_matches(
    statements: tuple[IAMPolicyStatement, ...],
    key_arn: str,
) -> list[_StatementMatch]:
    matches: list[_StatementMatch] = []
    for statement in statements:
        if statement.effect.strip().casefold() not in {"allow", "deny"}:
            continue
        matching_resources = tuple(
            resource for resource in statement.resources if _identity_policy_resource_matches(resource, key_arn)
        )
        if not matching_resources:
            continue
        for definition, patterns in _matching_operations(
            statement.actions,
            required_basis="iam_via_account_principal",
        ):
            matches.append(
                _StatementMatch(
                    statement,
                    definition.action,
                    "identity_policy",
                    patterns,
                    matching_resources,
                )
            )
    return matches


def _key_policy_matches(
    statements: tuple[IAMPolicyStatement, ...],
    *,
    key_arn: str,
    role_arn: str,
    account_root_arn: str,
) -> tuple[
    list[_StatementMatch],
    list[_StatementMatch],
    list[_StatementMatch],
    list[_StatementMatch],
]:
    direct: list[_StatementMatch] = []
    delegation: list[_StatementMatch] = []
    denies: list[_StatementMatch] = []
    wildcard_allows: list[_StatementMatch] = []
    for statement in statements:
        effect = statement.effect.strip().casefold()
        if effect not in {"allow", "deny"}:
            continue
        matching_resources = tuple(
            resource for resource in statement.resources if _key_policy_resource_matches(resource, key_arn)
        )
        if not matching_resources:
            continue

        principal_values = _aws_principal_values(statement)
        direct_principal = role_arn in principal_values
        account_principal = account_root_arn in principal_values
        wildcard_principal = "*" in principal_values
        if not (direct_principal or account_principal or wildcard_principal):
            continue

        for definition, patterns in _matching_operations(statement.actions):
            operation = definition.action
            if effect == "deny" and (direct_principal or account_principal or wildcard_principal):
                denies.append(
                    _StatementMatch(
                        statement,
                        operation,
                        "key_policy_deny",
                        patterns,
                        matching_resources,
                        "role" if direct_principal else "account" if account_principal else "wildcard",
                    )
                )
                continue
            if direct_principal and "direct_key_policy" in definition.supported_authorization_bases:
                direct.append(
                    _StatementMatch(
                        statement,
                        operation,
                        "direct_key_policy",
                        patterns,
                        matching_resources,
                        "role",
                    )
                )
            if account_principal and "iam_via_account_principal" in definition.supported_authorization_bases:
                delegation.append(
                    _StatementMatch(
                        statement,
                        operation,
                        "account_principal_delegation",
                        patterns,
                        matching_resources,
                        "account",
                    )
                )
            if wildcard_principal and "direct_key_policy" in definition.supported_authorization_bases:
                wildcard_allows.append(
                    _StatementMatch(
                        statement,
                        operation,
                        "wildcard_key_policy",
                        patterns,
                        matching_resources,
                        "wildcard",
                    )
                )
    return direct, delegation, denies, wildcard_allows


def _attached_grant_uncertainties(
    key: NormalizedResource,
    context: AwsDecorationContext,
) -> list[str]:
    uncertainties: list[str] = []
    for raw_grant in aws_facts(key).kms_grants:
        if not isinstance(raw_grant, Mapping):
            continue
        source = _known_string(raw_grant.get("source"))
        if source is None or raw_grant.get("resolved_key_address") != key.address:
            continue
        grant = context.index.resources_by_address.get(source)
        if grant is None or grant.resource_type != _KMS_GRANT:
            continue
        for uncertainty in aws_facts(grant).kms_grant_posture_uncertainties:
            if any(field in uncertainty for field in ("grantee_principal", "operations", "constraints", "key_id")):
                uncertainties.append(f"{key.address}: {source} authorization evidence is unresolved: {uncertainty}")
    return uncertainties


def _grant_matches(
    key: NormalizedResource,
    role_arn: str,
    context: AwsDecorationContext,
) -> tuple[list[_GrantMatch], list[str]]:
    matches: list[_GrantMatch] = []
    uncertainties: list[str] = []
    for raw_grant in aws_facts(key).kms_grants:
        if not isinstance(raw_grant, Mapping):
            continue
        source = _known_string(raw_grant.get("source"))
        if source is None or raw_grant.get("resolved_key_address") != key.address:
            continue
        grant = context.index.resources_by_address.get(source)
        if grant is None or grant.resource_type != _KMS_GRANT:
            continue
        grant_facts = aws_facts(grant)
        if grant_facts.kms_grant_resolved_key_address != key.address:
            continue
        if grant_facts.kms_grant_grantee_principal != role_arn:
            continue

        posture_uncertainties = tuple(
            uncertainty
            for uncertainty in grant_facts.kms_grant_posture_uncertainties
            if any(field in uncertainty for field in ("grantee_principal", "operations", "constraints", "key_id"))
        )
        constraints = grant_facts.kms_grant_constraints
        constraint_state = _grant_constraint_state(
            constraints,
            posture_uncertainties,
        )
        operations = [
            operation
            for raw_operation in grant_facts.kms_grant_operations
            if (operation := _GRANT_OPERATION_NAMES.get(raw_operation.removeprefix("kms:").casefold())) is not None
        ]
        if not operations and posture_uncertainties:
            uncertainties.append(f"{key.address}: {source} has unresolved KMS grant operations for {role_arn}")
        for operation in sorted(set(operations), key=_operation_sort_key):
            matches.append(
                _GrantMatch(
                    source,
                    operation,
                    constraints,
                    constraint_state,
                    posture_uncertainties,
                )
            )
    return matches, uncertainties


def _grant_constraint_state(
    constraints: Mapping[str, Any],
    posture_uncertainties: tuple[str, ...],
) -> str:
    if posture_uncertainties:
        return "unknown"
    if not constraints:
        return "not_configured"
    normalized_keys = {str(key).replace("_", "").replace(":", "").casefold() for key in constraints}
    if "sourcearn" in normalized_keys or "awssourcearn" in normalized_keys:
        return "service_source_arn"
    if set(constraints) <= {
        "encryption_context_equals",
        "encryption_context_subset",
    } and all(isinstance(value, Mapping) and bool(value) for value in constraints.values()):
        return "encryption_context"
    return "unknown"


def _matching_operations(
    action_patterns: list[str],
    *,
    required_basis: AwsKmsAuthorizationBasis | None = None,
) -> list[tuple[_KmsOperationDefinition, tuple[str, ...]]]:
    matches: list[tuple[_KmsOperationDefinition, tuple[str, ...]]] = []
    for definition in _KMS_OPERATION_CATALOG:
        if required_basis is not None and required_basis not in definition.supported_authorization_bases:
            continue
        patterns = tuple(
            pattern for pattern in action_patterns if fnmatchcase(definition.action.casefold(), pattern.casefold())
        )
        if patterns:
            matches.append((definition, patterns))
    return matches


def _identity_policy_resource_matches(resource: str, key_arn: str) -> bool:
    if resource == "*":
        return True
    if not _is_kms_key_arn_pattern(resource):
        return False
    return fnmatchcase(key_arn, resource)


def _key_policy_resource_matches(resource: str, key_arn: str) -> bool:
    return resource == "*" or (_is_kms_key_arn_pattern(resource) and fnmatchcase(key_arn, resource))


def _is_exact_kms_key_arn(value: str | None) -> bool:
    return bool(
        value
        and not _has_wildcard(value)
        and _is_kms_key_arn_pattern(value)
        and parse_aws_account_id(value) is not None
    )


def _is_kms_key_arn_pattern(value: str) -> bool:
    parts = value.split(":", 5)
    return bool(
        len(parts) == 6
        and parts[0] == "arn"
        and parts[1]
        and parts[2] == "kms"
        and parts[3]
        and parts[4]
        and parts[5].startswith("key/")
        and len(parts[5]) > len("key/")
    )


def _arn_partition(value: str) -> str | None:
    parts = value.split(":", 2)
    return parts[1] if len(parts) == 3 and parts[0] == "arn" else None


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


def _key_policy_is_representable(
    statements: tuple[IAMPolicyStatement, ...],
) -> bool:
    return bool(statements) and all(
        statement.effect.strip().casefold() in {"allow", "deny"}
        and bool(statement.actions)
        and bool(statement.resources)
        and bool(statement.principal_entries)
        for statement in statements
    )


def _identity_policy_is_representable(
    statements: tuple[IAMPolicyStatement, ...],
) -> bool:
    return all(
        statement.effect.strip().casefold() in {"allow", "deny"}
        and bool(statement.actions)
        and bool(statement.resources)
        for statement in statements
    )


def _aws_principal_values(statement: IAMPolicyStatement) -> set[str]:
    return {entry.value for entry in statement.principal_entries if entry.kind.casefold() in {"aws", "unknown"}}


def _statement_record(match: _StatementMatch) -> AwsKmsPolicyStatementEvidence:
    statement = match.statement
    return {
        "source_kind": match.source_kind,
        "effect": match.effect,
        "actions": list(statement.actions),
        "matching_action_patterns": list(match.matching_action_patterns),
        "resources": list(statement.resources),
        "matching_resources": list(match.matching_resources),
        "principals": list(statement.principals),
        "principal_match": match.principal_match,
        "conditions": [_condition_record(condition) for condition in statement.conditions],
        "conditional": match.conditional,
    }


def _grant_record(match: _GrantMatch) -> AwsKmsGrantAuthorizationEvidence:
    return {
        "source": match.source,
        "operation": match.operation,
        "constraints": dict(match.constraints),
        "constraint_state": match.constraint_state,
        "posture_uncertainties": list(match.posture_uncertainties),
        "direct_role_authority": match.deterministic,
    }


def _condition_record(condition: IAMPolicyCondition) -> AwsKmsPolicyConditionEvidence:
    return {
        "operator": condition.operator,
        "key": condition.key,
        "values": list(condition.values),
    }


def _combined_constraint_state(matches: list[_GrantMatch]) -> str:
    states = {match.constraint_state for match in matches}
    if not states:
        return "not_applicable"
    if "unknown" in states or "service_source_arn" in states:
        return "unknown"
    if "not_configured" in states:
        return "unconstrained"
    return "encryption_context"


def _has_unconditional(matches: list[_StatementMatch]) -> bool:
    return any(not match.conditional for match in matches)


def _has_conditional(matches: list[_StatementMatch]) -> bool:
    return any(match.conditional for match in matches)


def _for_operation(
    matches: list[_OperationMatch],
    operation: str,
) -> list[_OperationMatch]:
    return [match for match in matches if match.operation == operation]


def _key_origin_compatibility_state(
    definition: _KmsOperationDefinition,
    key_origin: str | None,
) -> AwsKmsKeyOriginCompatibilityState:
    if not definition.required_key_origins:
        return "not_applicable"
    if key_origin is None:
        return "unknown"
    normalized_origin = key_origin.strip().upper()
    return "compatible" if normalized_origin in definition.required_key_origins else "incompatible"


def _operation_sort_key(operation: str) -> tuple[int, str]:
    return (_OPERATION_ORDER.get(operation.casefold(), len(_OPERATION_ORDER)), operation.casefold())


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _has_wildcard(value: str) -> bool:
    return "*" in value or "?" in value
