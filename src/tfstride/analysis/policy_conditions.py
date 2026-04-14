from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from tfstride.models import IAMPolicyCondition

EFFECTIVE_TRUST_NARROWING_KEYS = frozenset({"sts:ExternalId", "aws:SourceArn", "aws:SourceAccount"})
EFFECTIVE_RESOURCE_POLICY_NARROWING_KEYS = frozenset({"aws:SourceArn", "aws:SourceAccount"})


@dataclass(frozen=True, slots=True)
class PrincipalAssessment:
    principal: str
    account_id: str | None
    is_service: bool
    is_wildcard: bool
    is_root_like: bool
    is_foreign_account: bool
    scope_description: str | None
    trust_path_description: str


def assess_principal(principal: str, primary_account_id: str | None) -> PrincipalAssessment:
    is_service = principal.endswith(".amazonaws.com")
    is_wildcard = principal == "*"
    account_id = _parse_account_id(principal)
    is_root_like = _is_root_like_principal(principal)
    is_foreign_account = bool(account_id and primary_account_id and account_id != primary_account_id)

    scope_description = None
    if is_wildcard:
        scope_description = "principal is wildcard"
    elif is_foreign_account:
        if is_root_like:
            scope_description = f"principal is foreign account root {account_id}"
        else:
            scope_description = f"principal belongs to foreign account {account_id}"
    elif is_root_like:
        if account_id:
            scope_description = f"principal is account root {account_id}"
        else:
            scope_description = "principal is account root"

    if is_wildcard:
        trust_path_description = "trust policy allows any AWS principal"
    elif is_foreign_account:
        trust_path_description = f"trust principal belongs to foreign account {account_id}"
    elif account_id:
        trust_path_description = f"trust principal belongs to account {account_id}"
    else:
        trust_path_description = f"trust policy includes principal {principal}"

    return PrincipalAssessment(
        principal=principal,
        account_id=account_id,
        is_service=is_service,
        is_wildcard=is_wildcard,
        is_root_like=is_root_like,
        is_foreign_account=is_foreign_account,
        scope_description=scope_description,
        trust_path_description=trust_path_description,
    )


def trust_statement_narrowing_conditions(trust_statement: Mapping[str, Any]) -> list[IAMPolicyCondition]:
    raw_conditions = trust_statement.get("narrowing_conditions")
    if isinstance(raw_conditions, list):
        parsed: list[IAMPolicyCondition] = []
        for raw_condition in raw_conditions:
            if not isinstance(raw_condition, Mapping):
                continue
            operator = str(raw_condition.get("operator") or "").strip()
            key = str(raw_condition.get("key") or "").strip()
            values = _coerce_string_list(raw_condition.get("values"))
            if not key:
                continue
            parsed.append(
                IAMPolicyCondition(
                    operator=operator,
                    key=key,
                    values=values,
                )
            )
        if parsed:
            return parsed

    return [
        IAMPolicyCondition(operator="", key=key, values=[])
        for key in trust_statement_narrowing_keys(trust_statement)
    ]


def trust_statement_narrowing_keys(trust_statement: Mapping[str, Any]) -> list[str]:
    raw_keys = trust_statement.get("narrowing_condition_keys")
    if not isinstance(raw_keys, list):
        return []
    parsed_keys: list[str] = []
    for raw_key in raw_keys:
        key = str(raw_key).strip()
        if key and key not in parsed_keys:
            parsed_keys.append(key)
    return parsed_keys


def trust_statement_has_supported_narrowing(trust_statement: Mapping[str, Any]) -> bool:
    if isinstance(trust_statement.get("has_narrowing_conditions"), bool):
        return bool(trust_statement["has_narrowing_conditions"])
    return bool(trust_statement_narrowing_keys(trust_statement))


def trust_statement_has_effective_narrowing(trust_statement: Mapping[str, Any]) -> bool:
    return _has_effective_narrowing(
        trust_statement_narrowing_conditions(trust_statement),
        EFFECTIVE_TRUST_NARROWING_KEYS,
    )


def describe_trust_narrowing(trust_statement: Mapping[str, Any]) -> list[str]:
    keys = trust_statement_narrowing_keys(trust_statement)
    if keys:
        return [
            "supported narrowing conditions present: true",
            "supported narrowing condition keys: " + ", ".join(keys),
        ]
    return [
        "supported narrowing conditions present: false",
        "supported narrowing condition keys: none",
    ]


def resource_policy_statement_narrowing_conditions(statement: Any) -> list[IAMPolicyCondition]:
    raw_conditions = getattr(statement, "conditions", [])
    if not isinstance(raw_conditions, list):
        return []

    narrowed: list[IAMPolicyCondition] = []
    for raw_condition in raw_conditions:
        if not isinstance(raw_condition, IAMPolicyCondition):
            continue
        if raw_condition.key not in EFFECTIVE_RESOURCE_POLICY_NARROWING_KEYS:
            continue
        narrowed.append(
            IAMPolicyCondition(
                operator=raw_condition.operator,
                key=raw_condition.key,
                values=list(raw_condition.values),
            )
        )
    return narrowed


def resource_policy_statement_has_effective_narrowing(statement: Any) -> bool:
    return _has_effective_narrowing(
        resource_policy_statement_narrowing_conditions(statement),
        EFFECTIVE_RESOURCE_POLICY_NARROWING_KEYS,
    )


def _parse_account_id(principal: str) -> str | None:
    if principal.isdigit() and len(principal) == 12:
        return principal
    if not principal.startswith("arn:"):
        return None
    parts = principal.split(":")
    if len(parts) < 5:
        return None
    return parts[4] or None


def _is_root_like_principal(principal: str) -> bool:
    return (principal.startswith("arn:") and principal.endswith(":root")) or (
        principal.isdigit() and len(principal) == 12
    )


def _coerce_string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        raw_values = value
    elif value in (None, ""):
        raw_values = []
    else:
        raw_values = [value]

    parsed_values: list[str] = []
    for raw_value in raw_values:
        text = str(raw_value).strip()
        if text and text not in parsed_values:
            parsed_values.append(text)
    return parsed_values


def _has_effective_narrowing(
    conditions: list[IAMPolicyCondition],
    effective_keys: frozenset[str],
) -> bool:
    keys = {condition.key for condition in conditions if condition.key in effective_keys}
    return "sts:ExternalId" in keys or "aws:SourceArn" in keys
