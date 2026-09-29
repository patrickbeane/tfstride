from __future__ import annotations

import json
from typing import Any

from tfstride.providers.coercion import STATE_CONFIGURED, STATE_NOT_CONFIGURED, STATE_UNKNOWN
from tfstride.providers.gcp.attributes import GcpAttribute, GcpValues
from tfstride.providers.gcp.coercion import as_list, compact
from tfstride.providers.gcp.resource_utils import first_non_empty


def _target_reference(values: GcpValues, keys: tuple[GcpAttribute[Any], ...]) -> str | None:
    return first_non_empty(*(values.get(key) for key in keys))


def _policy_bindings(policy_document: dict[str, Any]) -> list[dict[str, Any]]:
    bindings: list[dict[str, Any]] = []
    for binding in as_list(policy_document.get("bindings")):
        if not isinstance(binding, dict):
            continue
        role = first_non_empty(binding.get("role"))
        members = compact(as_list(binding.get("members")))
        bindings.extend(_iam_bindings(role, members, condition=binding.get("condition")))
    return bindings


def _iam_bindings(
    role: str | None,
    members: list[str],
    *,
    condition: Any = None,
    condition_unknown: bool = False,
    role_unknown: bool = False,
    members_unknown: bool = False,
) -> list[dict[str, Any]]:
    if not role and not role_unknown:
        return []
    if not members and not members_unknown:
        return []

    binding: dict[str, Any] = {"role": role, "members": list(members)}
    if role_unknown:
        binding["role_state"] = "unknown"
    if members_unknown:
        binding["members_state"] = "unknown"
    normalized_condition = _condition(condition)
    condition_shape_unknown = (
        condition not in (None, {}, [])
        and not isinstance(condition, dict)
        and not (isinstance(condition, list) and len(condition) == 1 and isinstance(condition[0], dict))
    )
    if condition_unknown or condition_shape_unknown:
        binding["condition_state"] = "unknown"
    elif normalized_condition:
        binding["condition"] = normalized_condition
    return [binding]


def _condition(value: Any) -> dict[str, Any]:
    if isinstance(value, list):
        value = value[0] if value and isinstance(value[0], dict) else {}
    if not isinstance(value, dict):
        return {}
    return {str(key): raw_value for key, raw_value in value.items() if raw_value not in (None, "", [])}


def _policy_data_state(raw_policy_data: Any, *, unknown: bool) -> str:
    if unknown:
        return STATE_UNKNOWN
    if raw_policy_data in (None, ""):
        return STATE_NOT_CONFIGURED
    if isinstance(raw_policy_data, dict):
        return STATE_CONFIGURED
    if isinstance(raw_policy_data, str) and raw_policy_data.strip():
        try:
            parsed = json.loads(raw_policy_data)
        except json.JSONDecodeError:
            return "invalid"
        return STATE_CONFIGURED if isinstance(parsed, dict) else "invalid"
    return "invalid"


def _binding_identifier(target: str | None, role: str | None, members: list[str | None]) -> str | None:
    normalized_members = compact(list(members))
    if not target or not role or not normalized_members:
        return None
    return f"{target}:{role}:{','.join(normalized_members)}"
