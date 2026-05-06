from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from tfstride.models import IAMPolicyCondition

EFFECTIVE_TRUST_NARROWING_KEYS = frozenset({"sts:ExternalId", "aws:SourceArn", "aws:SourceAccount"})
EFFECTIVE_RESOURCE_POLICY_NARROWING_KEYS = frozenset({"aws:SourceArn", "aws:SourceAccount"})
SAML_TRUST_NARROWING_KEYS = frozenset({"SAML:aud"})
COGNITO_TRUST_NARROWING_KEYS = frozenset({"cognito-identity.amazonaws.com:aud"})


@dataclass(frozen=True, slots=True)
class PrincipalAssessment:
    principal: str
    principal_kind: str
    account_id: str | None
    is_service: bool
    is_federated: bool
    federated_provider_type: str | None
    is_wildcard: bool
    is_root_like: bool
    is_foreign_account: bool
    scope_description: str | None
    trust_path_description: str


def assess_principal(
    principal: str,
    primary_account_id: str | None,
    *,
    principal_kind: str | None = None,
) -> PrincipalAssessment:
    principal_kind = _classify_principal_kind(principal, principal_kind)
    is_service = principal_kind == "Service"
    is_federated = principal_kind == "Federated"
    federated_provider_type = _federated_provider_type(principal) if is_federated else None
    is_wildcard = principal == "*"
    account_id = _parse_account_id(principal)
    is_root_like = _is_root_like_principal(principal)
    is_foreign_account = bool(account_id and primary_account_id and account_id != primary_account_id)

    scope_description = None
    if is_wildcard:
        scope_description = "principal is wildcard"
    elif is_federated and is_foreign_account:
        scope_description = (
            f"{_federated_provider_description(federated_provider_type)} belongs to foreign account {account_id}"
        )
    elif is_federated:
        provider_description = _federated_provider_description(federated_provider_type)
        if account_id:
            scope_description = f"{provider_description} belongs to account {account_id}"
        else:
            scope_description = f"principal is {provider_description}"
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
    elif is_federated:
        provider_description = _federated_provider_description(federated_provider_type)
        if is_foreign_account:
            trust_path_description = f"trust principal is {provider_description} in foreign account {account_id}"
        elif account_id:
            trust_path_description = f"trust principal is {provider_description} in account {account_id}"
        else:
            trust_path_description = f"trust principal is {provider_description}"
    elif is_foreign_account:
        trust_path_description = f"trust principal belongs to foreign account {account_id}"
    elif account_id:
        trust_path_description = f"trust principal belongs to account {account_id}"
    else:
        trust_path_description = f"trust policy includes principal {principal}"

    return PrincipalAssessment(
        principal=principal,
        principal_kind=principal_kind,
        account_id=account_id,
        is_service=is_service,
        is_federated=is_federated,
        federated_provider_type=federated_provider_type,
        is_wildcard=is_wildcard,
        is_root_like=is_root_like,
        is_foreign_account=is_foreign_account,
        scope_description=scope_description,
        trust_path_description=trust_path_description,
    )


def trust_statement_principal_assessments(
    trust_statement: Mapping[str, Any],
    primary_account_id: str | None,
) -> list[PrincipalAssessment]:
    entries = _trust_statement_principal_entries(trust_statement)
    return [
        assess_principal(value, primary_account_id, principal_kind=kind)
        for kind, value in entries
    ]


def policy_statement_principal_assessments(
    statement: Any,
    primary_account_id: str | None,
) -> list[PrincipalAssessment]:
    entries = _policy_statement_principal_entries(statement)
    return [
        assess_principal(value, primary_account_id, principal_kind=kind)
        for kind, value in entries
    ]


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


def trust_statement_has_supported_narrowing_for_principal(
    trust_statement: Mapping[str, Any],
    assessment: PrincipalAssessment,
) -> bool:
    if not assessment.is_federated:
        return trust_statement_has_supported_narrowing(trust_statement)
    return bool(_federated_narrowing_keys(trust_statement, assessment))


def trust_statement_has_effective_narrowing(trust_statement: Mapping[str, Any]) -> bool:
    return _has_effective_narrowing(
        trust_statement_narrowing_conditions(trust_statement),
        EFFECTIVE_TRUST_NARROWING_KEYS,
    )


def trust_statement_has_effective_narrowing_for_principal(
    trust_statement: Mapping[str, Any],
    assessment: PrincipalAssessment,
) -> bool:
    if not assessment.is_federated:
        return trust_statement_has_effective_narrowing(trust_statement)
    narrowing_keys = set(_federated_narrowing_keys(trust_statement, assessment))
    if assessment.federated_provider_type == "saml":
        return bool(narrowing_keys.intersection(SAML_TRUST_NARROWING_KEYS))
    if assessment.federated_provider_type == "oidc":
        provider_prefix = _oidc_provider_condition_key_prefix(assessment.principal)
        if provider_prefix is None:
            return False
        return {
            f"{provider_prefix}:aud",
            f"{provider_prefix}:sub",
        }.issubset(narrowing_keys)
    if assessment.federated_provider_type == "cognito":
        return bool(narrowing_keys.intersection(COGNITO_TRUST_NARROWING_KEYS))
    return False


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


def describe_trust_narrowing_for_principal(
    trust_statement: Mapping[str, Any],
    assessment: PrincipalAssessment,
) -> list[str]:
    if not assessment.is_federated:
        return describe_trust_narrowing(trust_statement)

    keys = _federated_narrowing_keys(trust_statement, assessment)
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


def _classify_principal_kind(principal: str, explicit_kind: str | None) -> str:
    normalized_explicit_kind = _normalize_principal_kind(explicit_kind)
    if normalized_explicit_kind is not None:
        return normalized_explicit_kind
    if principal == "*":
        return "Wildcard"
    if _is_federated_provider_arn(principal):
        return "Federated"
    if principal.endswith(".amazonaws.com"):
        return "Service"
    if principal.isdigit() and len(principal) == 12:
        return "AWS"
    if principal.startswith("arn:aws:iam::"):
        return "AWS"
    return "Unknown"


def _normalize_principal_kind(kind: str | None) -> str | None:
    if kind is None:
        return None
    normalized = str(kind).strip().lower()
    if not normalized:
        return None
    known_kinds = {
        "aws": "AWS",
        "service": "Service",
        "federated": "Federated",
        "canonicaluser": "CanonicalUser",
        "wildcard": "Wildcard",
        "unknown": "Unknown",
    }
    return known_kinds.get(normalized, str(kind).strip())


def _is_federated_provider_arn(principal: str) -> bool:
    return ":saml-provider/" in principal or ":oidc-provider/" in principal


def _federated_provider_type(principal: str) -> str:
    if ":saml-provider/" in principal:
        return "saml"
    if ":oidc-provider/" in principal:
        return "oidc"
    if principal == "cognito-identity.amazonaws.com":
        return "cognito"
    return "unknown"


def _federated_provider_description(provider_type: str | None) -> str:
    if provider_type == "saml":
        return "SAML identity provider"
    if provider_type == "oidc":
        return "OIDC identity provider"
    if provider_type == "cognito":
        return "Cognito identity provider"
    return "federated identity provider"


def _federated_narrowing_keys(
    trust_statement: Mapping[str, Any],
    assessment: PrincipalAssessment,
) -> list[str]:
    relevant_keys = _federated_condition_keys(assessment)
    if not relevant_keys:
        return []

    narrowing_keys: list[str] = []
    for condition in trust_statement_narrowing_conditions(trust_statement):
        if condition.key not in relevant_keys:
            continue
        if condition.key in narrowing_keys:
            continue
        narrowing_keys.append(condition.key)
    return narrowing_keys


def _federated_condition_keys(assessment: PrincipalAssessment) -> frozenset[str]:
    if assessment.federated_provider_type == "saml":
        return SAML_TRUST_NARROWING_KEYS
    if assessment.federated_provider_type == "oidc":
        provider_prefix = _oidc_provider_condition_key_prefix(assessment.principal)
        if provider_prefix is None:
            return frozenset()
        return frozenset(
            {
                f"{provider_prefix}:aud",
                f"{provider_prefix}:sub",
            }
        )
    if assessment.federated_provider_type == "cognito":
        return COGNITO_TRUST_NARROWING_KEYS
    return frozenset()


def _oidc_provider_condition_key_prefix(principal: str) -> str | None:
    marker = ":oidc-provider/"
    if marker not in principal:
        return None
    provider = principal.split(marker, 1)[1].strip("/")
    return provider or None


def _is_root_like_principal(principal: str) -> bool:
    return (principal.startswith("arn:") and principal.endswith(":root")) or (
        principal.isdigit() and len(principal) == 12
    )


def _trust_statement_principal_entries(trust_statement: Mapping[str, Any]) -> list[tuple[str | None, str]]:
    raw_entries = trust_statement.get("principal_entries")
    if isinstance(raw_entries, list):
        parsed_entries: list[tuple[str | None, str]] = []
        for raw_entry in raw_entries:
            if not isinstance(raw_entry, Mapping):
                continue
            value = str(raw_entry.get("value") or "").strip()
            if not value:
                continue
            kind = str(raw_entry.get("kind") or "").strip() or None
            parsed_entries.append((kind, value))
        if parsed_entries:
            return _dedupe_principal_entries(parsed_entries)

    return _dedupe_principal_entries(
        (None, principal)
        for principal in _coerce_string_list(trust_statement.get("principals"))
    )


def _policy_statement_principal_entries(statement: Any) -> list[tuple[str | None, str]]:
    raw_entries = getattr(statement, "principal_entries", [])
    if isinstance(raw_entries, list):
        parsed_entries: list[tuple[str | None, str]] = []
        for raw_entry in raw_entries:
            kind = getattr(raw_entry, "kind", None)
            value = getattr(raw_entry, "value", None)
            if value in (None, ""):
                continue
            parsed_entries.append((str(kind).strip() if kind else None, str(value)))
        if parsed_entries:
            return _dedupe_principal_entries(parsed_entries)

    return _dedupe_principal_entries(
        (None, principal)
        for principal in _coerce_string_list(getattr(statement, "principals", []))
    )


def _dedupe_principal_entries(entries: Any) -> list[tuple[str | None, str]]:
    deduped: list[tuple[str | None, str]] = []
    seen: set[tuple[str | None, str]] = set()
    for kind, value in entries:
        key = (kind, value)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(key)
    return deduped


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
