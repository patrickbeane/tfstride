from __future__ import annotations

import json
from collections.abc import Mapping
from fnmatch import fnmatchcase
from typing import Any, Literal

from tfstride.models import IAMPolicyCondition, IAMPolicyStatement, IAMPrincipal
from tfstride.providers.aws.coercion import as_list, compact

_ASSUME_ROLE_ACTIONS = (
    "sts:assumerole",
    "sts:assumerolewithsaml",
    "sts:assumerolewithwebidentity",
)

SUPPORTED_TRUST_NARROWING_CONDITIONS = {
    "sts:ExternalId": {
        "StringEquals",
        "StringLike",
        "ForAnyValue:StringEquals",
        "ForAnyValue:StringLike",
    },
    "aws:SourceArn": {
        "ArnEquals",
        "ArnLike",
        "StringEquals",
        "StringLike",
        "ForAnyValue:ArnEquals",
        "ForAnyValue:ArnLike",
    },
    "aws:SourceAccount": {
        "StringEquals",
        "StringLike",
        "ForAnyValue:StringEquals",
        "ForAnyValue:StringLike",
    },
    "SAML:aud": {
        "StringEquals",
        "StringLike",
        "ForAnyValue:StringEquals",
        "ForAnyValue:StringLike",
    },
}
SUPPORTED_WEB_IDENTITY_TRUST_NARROWING_CLAIMS = frozenset({"aud", "sub"})
SUPPORTED_WEB_IDENTITY_TRUST_NARROWING_OPERATORS = frozenset(
    {
        "StringEquals",
        "StringLike",
        "ForAnyValue:StringEquals",
        "ForAnyValue:StringLike",
    }
)


def parse_policy_statements(policy_document: dict[str, Any]) -> list[IAMPolicyStatement]:
    statements: list[IAMPolicyStatement] = []
    for statement in as_list(policy_document.get("Statement")):
        statements.append(parse_policy_statement(statement))
    return statements


def parse_policy_statement(statement: Any) -> IAMPolicyStatement:
    statement_dict = statement if isinstance(statement, dict) else {}
    principal_entries = extract_principal_entries(statement_dict.get("Principal"))
    return IAMPolicyStatement(
        effect=str(statement_dict.get("Effect", "Allow")),
        actions=as_list(statement_dict.get("Action")),
        resources=as_list(statement_dict.get("Resource")),
        principals=[entry.value for entry in principal_entries],
        principal_entries=principal_entries,
        conditions=parse_condition_entries(statement_dict.get("Condition")),
    )


def policy_statement_is_fully_representable(
    raw_statement: Mapping[str, Any],
    statement: IAMPolicyStatement,
    *,
    principal_mode: Literal["required", "forbidden", "optional"],
) -> bool:
    if any(key in raw_statement for key in ("NotAction", "NotResource", "NotPrincipal")):
        return False
    if raw_statement.get("Effect") not in {"Allow", "Deny"}:
        return False

    actions = _policy_string_values(raw_statement.get("Action"))
    resources = _policy_string_values(raw_statement.get("Resource"))
    if actions is None or resources is None:
        return False
    if statement.actions != actions or statement.resources != resources:
        return False

    has_principal = "Principal" in raw_statement
    if principal_mode == "forbidden" and has_principal:
        return False
    if principal_mode == "required" and not has_principal:
        return False
    if has_principal and not _policy_principal_is_representable(raw_statement.get("Principal")):
        return False
    if principal_mode == "required" and not statement.principal_entries:
        return False

    return _policy_conditions_are_representable(
        raw_statement.get("Condition"),
        statement.conditions,
    )


def _policy_string_values(value: object) -> list[str] | None:
    if isinstance(value, str) and value:
        return [value]
    if isinstance(value, list) and value and all(isinstance(item, str) and bool(item) for item in value):
        return list(value)
    return None


def _policy_principal_is_representable(value: object) -> bool:
    if isinstance(value, str):
        return bool(value)
    if not isinstance(value, Mapping) or not value:
        return False
    return all(
        isinstance(kind, str) and bool(kind) and _policy_string_values(principals) is not None
        for kind, principals in value.items()
    )


def _policy_conditions_are_representable(
    raw_condition: object,
    conditions: list[IAMPolicyCondition],
) -> bool:
    if raw_condition is None:
        return not conditions
    if not isinstance(raw_condition, Mapping) or not raw_condition:
        return False

    expected: list[tuple[str, str, list[str]]] = []
    for operator in sorted(raw_condition):
        keyed_values = raw_condition.get(operator)
        if not isinstance(operator, str) or not operator:
            return False
        if not isinstance(keyed_values, Mapping) or not keyed_values:
            return False
        for key in sorted(keyed_values):
            if not isinstance(key, str) or not key:
                return False
            raw_values = keyed_values.get(key)
            values = _policy_condition_values(raw_values)
            if values is None:
                return False
            expected.append((operator, key, values))

    actual = [(condition.operator, condition.key, list(condition.values)) for condition in conditions]
    return actual == expected


def _policy_condition_values(value: object) -> list[str] | None:
    raw_values = value if isinstance(value, list) else [value]
    if not raw_values or any(item in (None, "", []) or isinstance(item, Mapping) for item in raw_values):
        return None
    normalized: list[str] = []
    for item in raw_values:
        text = str(item)
        if text not in normalized:
            normalized.append(text)
    return normalized


def extract_principals(policy_document: dict[str, Any]) -> list[str]:
    principals: list[str] = []
    for statement in parse_policy_statements(policy_document):
        principals.extend(statement.principals)
    return sorted(set(principals))


def extract_trust_statements(policy_document: dict[str, Any]) -> list[dict[str, Any]]:
    trust_statements: list[dict[str, Any]] = []
    for raw_statement in as_list(policy_document.get("Statement")):
        statement = parse_policy_statement(raw_statement)
        if statement.effect != "Allow" or not any(
            fnmatchcase(operation, action.lower()) for action in statement.actions for operation in _ASSUME_ROLE_ACTIONS
        ):
            continue
        principals = sorted(set(statement.principals))
        if not principals:
            continue
        principal_entries = sorted(
            ({"kind": entry.kind, "value": entry.value} for entry in statement.principal_entries),
            key=lambda entry: (entry["kind"], entry["value"]),
        )
        narrowing_conditions = extract_supported_trust_narrowing_conditions(statement.conditions)
        trust_statement = {
            "principals": principals,
            "principal_entries": principal_entries,
            "narrowing_condition_keys": sorted({condition.key for condition in narrowing_conditions}),
            "narrowing_conditions": [
                {
                    "operator": condition.operator,
                    "key": condition.key,
                    "values": list(condition.values),
                }
                for condition in narrowing_conditions
            ],
            "has_narrowing_conditions": bool(narrowing_conditions),
        }
        if any(action.lower() == "sts:assumerolewithwebidentity" for action in statement.actions):
            trust_statement["actions"] = sorted(set(statement.actions))
        trust_statements.append(trust_statement)
    return trust_statements


def extract_supported_trust_narrowing_conditions(
    conditions: list[IAMPolicyCondition],
) -> list[IAMPolicyCondition]:
    supported: list[IAMPolicyCondition] = []
    for condition in conditions:
        supported_operators = supported_trust_narrowing_operators(condition.key)
        if supported_operators is None or condition.operator not in supported_operators:
            continue
        supported.append(
            IAMPolicyCondition(
                operator=condition.operator,
                key=condition.key,
                values=list(condition.values),
            )
        )
    return supported


def supported_trust_narrowing_operators(key: str) -> frozenset[str] | set[str] | None:
    supported_operators = SUPPORTED_TRUST_NARROWING_CONDITIONS.get(key)
    if supported_operators is not None:
        return supported_operators
    if is_supported_web_identity_trust_narrowing_key(key):
        return SUPPORTED_WEB_IDENTITY_TRUST_NARROWING_OPERATORS
    return None


def is_supported_web_identity_trust_narrowing_key(key: str) -> bool:
    provider_prefix, separator, claim = key.rpartition(":")
    if not separator:
        return False
    if provider_prefix in {"aws", "sts", "SAML"}:
        return False
    if claim not in SUPPORTED_WEB_IDENTITY_TRUST_NARROWING_CLAIMS:
        return False
    return "." in provider_prefix or "/" in provider_prefix


def extract_principal_entries(raw_principal: Any) -> list[IAMPrincipal]:
    if raw_principal is None:
        return []
    if isinstance(raw_principal, str):
        return [IAMPrincipal(kind="unknown", value=raw_principal)]
    if isinstance(raw_principal, dict):
        entries: list[IAMPrincipal] = []
        for principal_kind, principal_value in raw_principal.items():
            entries.extend(
                IAMPrincipal(kind=str(principal_kind), value=str(value))
                for value in as_list(principal_value)
                if value not in (None, "")
            )
        return entries
    if isinstance(raw_principal, list):
        return [IAMPrincipal(kind="unknown", value=str(item)) for item in raw_principal]
    return []


def lambda_permission_principal_entries(raw_principal: Any) -> list[IAMPrincipal]:
    principals = compact([raw_principal])
    entries: list[IAMPrincipal] = []
    for principal in principals:
        kind = "Service" if principal.endswith(".amazonaws.com") else "AWS"
        entries.append(IAMPrincipal(kind=kind, value=principal))
    return entries


def parse_condition_entries(raw_condition: Any) -> list[IAMPolicyCondition]:
    if not isinstance(raw_condition, dict):
        return []

    entries: list[IAMPolicyCondition] = []
    for operator in sorted(raw_condition):
        keyed_values = raw_condition.get(operator)
        if not isinstance(keyed_values, dict):
            continue
        for key in sorted(keyed_values):
            entry = condition_entry(
                operator=str(operator),
                key=str(key),
                values=normalize_condition_values(keyed_values.get(key)),
            )
            if entry is not None:
                entries.append(entry)
    return entries


def condition_entry(*, operator: str, key: str, values: list[str]) -> IAMPolicyCondition | None:
    if not operator or not key or not values:
        return None
    return IAMPolicyCondition(operator=operator, key=key, values=values)


def compact_condition_entries(
    entries: list[IAMPolicyCondition | None],
) -> list[IAMPolicyCondition]:
    return [entry for entry in entries if entry is not None]


def normalize_condition_values(value: Any) -> list[str]:
    raw_values = as_list(value)
    normalized: list[str] = []
    seen_values: set[str] = set()
    for raw_value in raw_values:
        if raw_value in (None, "", []):
            continue
        if isinstance(raw_value, dict):
            text = json.dumps(raw_value, sort_keys=True)
        else:
            text = str(raw_value)
        if text in seen_values:
            continue
        seen_values.add(text)
        normalized.append(text)
    return normalized
