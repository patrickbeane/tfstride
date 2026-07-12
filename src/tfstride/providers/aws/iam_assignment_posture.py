from __future__ import annotations

from collections.abc import Iterable

from tfstride.identity import (
    AssignmentScopeKind,
    PrincipalType,
    PrivilegeCategory,
    PrivilegeConfidence,
    PrivilegedAccessGrant,
    PrivilegedAccessPosture,
    PrivilegedAssignmentScope,
    PrivilegedPrincipal,
)
from tfstride.models import IAMPolicyStatement, NormalizedResource
from tfstride.providers.coercion import append_unique

_AWS_PROVIDER = "aws"
_FULL_ADMIN_ACTIONS = frozenset({"*", "*:*"})
_IAM_ADMIN_PATTERNS = (
    "iam:*",
    "iam:Create*",
    "iam:Delete*",
    "iam:Update*",
    "iam:Put*",
    "iam:Attach*",
    "iam:Detach*",
    "iam:Set*",
    "organizations:*",
    "organizations:Create*",
    "organizations:Delete*",
    "organizations:Update*",
    "organizations:Attach*",
    "organizations:Detach*",
    "account:*",
)
_POLICY_ADMIN_PREFIXES = ("iam:CreatePolicy", "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion")
_ROLE_ASSIGNMENT_ACTIONS = frozenset(
    {
        "iam:AttachRolePolicy",
        "iam:AttachUserPolicy",
        "iam:AttachGroupPolicy",
        "iam:PutRolePolicy",
        "iam:PutUserPolicy",
        "iam:PutGroupPolicy",
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
    }
)
_PRIVILEGE_ESCALATION_ACTIONS = frozenset(
    {
        "iam:PassRole",
        "sts:AssumeRole",
        "sts:AssumeRoleWithWebIdentity",
        "sts:AssumeRoleWithSAML",
    }
)
_DATA_ADMIN_PATTERNS = ("s3:*", "rds:*", "dynamodb:*", "redshift:*")
_SECRETS_ADMIN_PATTERNS = ("secretsmanager:*", "secretsmanager:GetSecretValue", "ssm:GetParameter*")
_KEY_ADMIN_PATTERNS = ("kms:*", "kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey*")
_COMPUTE_ADMIN_PATTERNS = ("ec2:*", "ecs:*", "eks:*", "lambda:*")
_NETWORK_ADMIN_PREFIXES = ("ec2:AuthorizeSecurityGroup*", "ec2:CreateRoute", "ec2:CreateVpc")
_AUDIT_ADMIN_PREFIXES = ("cloudtrail:", "guardduty:", "securityhub:", "config:")


def build_aws_privileged_access_posture(
    role: NormalizedResource,
    *,
    unresolved_assignments: Iterable[str | None] = (),
) -> PrivilegedAccessPosture:
    """Build provider-neutral privileged access posture from an AWS IAM role."""

    if role.provider != _AWS_PROVIDER or role.resource_type != "aws_iam_role":
        return PrivilegedAccessPosture(provider=_AWS_PROVIDER)

    grants: list[PrivilegedAccessGrant] = []
    for statement in role.policy_statements:
        categories = _statement_privilege_categories(statement)
        if not categories:
            continue
        grants.append(_grant_for_statement(role, statement, categories))

    return PrivilegedAccessPosture(
        provider=_AWS_PROVIDER,
        grants=tuple(grants),
        unresolved_assignments=tuple(unresolved_assignments),
    )


def serialize_privileged_access_posture(posture: PrivilegedAccessPosture) -> list[dict[str, object]]:
    return [_serialize_grant(grant) for grant in posture.grants]


def deserialize_privileged_access_grants(records: Iterable[dict[str, object]]) -> tuple[PrivilegedAccessGrant, ...]:
    grants: list[PrivilegedAccessGrant] = []
    for record in records:
        grants.append(
            PrivilegedAccessGrant(
                provider=_record_string(record, "provider") or _AWS_PROVIDER,
                principal=PrivilegedPrincipal(
                    principal_type=_record_string(record, "principal_type") or PrincipalType.UNKNOWN,
                    identifier=_record_string(record, "principal_identifier"),
                    display_name=_record_string(record, "principal_display_name"),
                    source_address=_record_string(record, "principal_source_address"),
                ),
                assignment_scope=PrivilegedAssignmentScope(
                    scope_kind=_record_string(record, "scope_kind") or AssignmentScopeKind.UNKNOWN,
                    value=_record_string(record, "scope_value"),
                    source_address=_record_string(record, "scope_source_address"),
                ),
                privilege_categories=tuple(_record_string_list(record, "privilege_categories")),
                confidence=_record_string(record, "confidence") or PrivilegeConfidence.HIGH,
                assignment_source_address=_record_string(record, "assignment_source_address"),
                role_name=_record_string(record, "role_name"),
                role_id=_record_string(record, "role_id"),
                permission_patterns=tuple(_record_string_list(record, "permission_patterns")),
                evidence=tuple(_record_string_list(record, "evidence")),
                uncertainties=tuple(_record_string_list(record, "uncertainties")),
            )
        )
    return tuple(grants)


def _grant_for_statement(
    role: NormalizedResource,
    statement: IAMPolicyStatement,
    categories: tuple[PrivilegeCategory, ...],
) -> PrivilegedAccessGrant:
    scope = _scope_for_statement(statement)
    return PrivilegedAccessGrant(
        provider=_AWS_PROVIDER,
        principal=PrivilegedPrincipal(
            principal_type=PrincipalType.ROLE,
            identifier=role.arn or role.identifier or role.address,
            display_name=role.display_name,
            source_address=role.address,
        ),
        assignment_scope=scope,
        privilege_categories=categories,
        confidence=_statement_confidence(statement),
        assignment_source_address=role.address,
        role_name=role.identifier or role.name,
        role_id=role.arn,
        permission_patterns=tuple(_privileged_action_patterns(statement.actions)),
        evidence=tuple(_statement_evidence(statement)),
    )


def _statement_privilege_categories(statement: IAMPolicyStatement) -> tuple[PrivilegeCategory, ...]:
    if statement.effect != "Allow":
        return ()
    categories: list[PrivilegeCategory] = []
    for action in statement.actions:
        normalized = action.strip()
        lower = normalized.lower()
        if normalized in _FULL_ADMIN_ACTIONS:
            append_unique(categories, PrivilegeCategory.FULL_ADMIN)
            continue
        if _action_matches_any(lower, _IAM_ADMIN_PATTERNS):
            append_unique(categories, PrivilegeCategory.IAM_ADMIN)
        if _action_matches_any(lower, _POLICY_ADMIN_PREFIXES):
            append_unique(categories, PrivilegeCategory.POLICY_ADMIN)
        if _action_matches_any(lower, _ROLE_ASSIGNMENT_ACTIONS):
            append_unique(categories, PrivilegeCategory.ROLE_ASSIGNMENT)
        if _action_matches_any(lower, _PRIVILEGE_ESCALATION_ACTIONS):
            append_unique(categories, PrivilegeCategory.PRIVILEGE_ESCALATION)
        if _action_matches_any(lower, _DATA_ADMIN_PATTERNS):
            append_unique(categories, PrivilegeCategory.DATA_ADMIN)
        if _action_matches_any(lower, _SECRETS_ADMIN_PATTERNS):
            append_unique(categories, PrivilegeCategory.SECRETS_ADMIN)
        if _action_matches_any(lower, _KEY_ADMIN_PATTERNS):
            append_unique(categories, PrivilegeCategory.KEY_ADMIN)
        if _action_matches_any(lower, _COMPUTE_ADMIN_PATTERNS):
            append_unique(categories, PrivilegeCategory.COMPUTE_ADMIN)
        if _action_matches_any(lower, _NETWORK_ADMIN_PREFIXES):
            append_unique(categories, PrivilegeCategory.NETWORK_ADMIN)
        if _action_matches_prefixes(lower, _AUDIT_ADMIN_PREFIXES):
            append_unique(categories, PrivilegeCategory.AUDIT_ADMIN)
    return tuple(categories)


def _scope_for_statement(statement: IAMPolicyStatement) -> PrivilegedAssignmentScope:
    if not statement.resources:
        return PrivilegedAssignmentScope(AssignmentScopeKind.UNKNOWN)
    if "*" in statement.resources:
        return PrivilegedAssignmentScope(AssignmentScopeKind.ACCOUNT, value="*")
    if len(statement.resources) == 1:
        return PrivilegedAssignmentScope(AssignmentScopeKind.RESOURCE, value=statement.resources[0])
    return PrivilegedAssignmentScope(AssignmentScopeKind.RESOURCE, value=",".join(sorted(statement.resources)))


def _statement_confidence(statement: IAMPolicyStatement) -> PrivilegeConfidence:
    if statement.resources and "*" not in statement.resources:
        return PrivilegeConfidence.MEDIUM
    return PrivilegeConfidence.HIGH


def _privileged_action_patterns(actions: Iterable[str]) -> list[str]:
    patterns: list[str] = []
    for action in actions:
        normalized = action.strip()
        if not normalized:
            continue
        if normalized in _FULL_ADMIN_ACTIONS or normalized.endswith(":*"):
            append_unique(patterns, normalized)
            continue
        lower = normalized.lower()
        if (
            _action_matches_any(lower, _ROLE_ASSIGNMENT_ACTIONS)
            or _action_matches_any(lower, _PRIVILEGE_ESCALATION_ACTIONS)
            or _action_matches_any(lower, _POLICY_ADMIN_PREFIXES)
        ):
            append_unique(patterns, normalized)
    return patterns


def _statement_evidence(statement: IAMPolicyStatement) -> list[str]:
    evidence: list[str] = []
    for action in statement.actions:
        append_unique(evidence, f"action={action}")
    for resource in statement.resources:
        append_unique(evidence, f"resource={resource}")
    return evidence


def _serialize_grant(grant: PrivilegedAccessGrant) -> dict[str, object]:
    return {
        "provider": grant.provider,
        "principal_type": grant.principal.principal_type.value,
        "principal_identifier": grant.principal.identifier,
        "principal_display_name": grant.principal.display_name,
        "principal_source_address": grant.principal.source_address,
        "scope_kind": grant.assignment_scope.scope_kind.value,
        "scope_value": grant.assignment_scope.value,
        "scope_source_address": grant.assignment_scope.source_address,
        "privilege_categories": [category.value for category in grant.privilege_categories],
        "confidence": grant.confidence.value,
        "assignment_source_address": grant.assignment_source_address,
        "role_name": grant.role_name,
        "role_id": grant.role_id,
        "permission_patterns": list(grant.permission_patterns),
        "evidence": list(grant.evidence),
        "uncertainties": list(grant.uncertainties),
    }


def _record_string(record: dict[str, object], key: str) -> str | None:
    value = record.get(key)
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _record_string_list(record: dict[str, object], key: str) -> list[str]:
    value = record.get(key)
    if not isinstance(value, list | tuple):
        return []
    return [normalized for item in value if (normalized := _known_string(item))]


def _known_string(value: object) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _action_matches_any(action: str, patterns: Iterable[str]) -> bool:
    for pattern in patterns:
        lower_pattern = pattern.lower()
        if action == lower_pattern:
            return True
        if lower_pattern.endswith("*") and not lower_pattern.endswith(":*") and action.startswith(lower_pattern[:-1]):
            return True
    return False


def _action_matches_prefixes(action: str, prefixes: Iterable[str]) -> bool:
    return any(action.startswith(prefix.lower()) for prefix in prefixes)
