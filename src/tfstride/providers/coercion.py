from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

STATE_ENABLED = "enabled"
STATE_DISABLED = "disabled"
STATE_UNKNOWN = "unknown"
STATE_CONFIGURED = "configured"
STATE_NOT_CONFIGURED = "not_configured"


def compact(values: Iterable[Any] | None) -> list[str]:
    if values is None:
        return []
    return [str(value) for value in values if value not in (None, "", [])]


def compact_strings(values: Iterable[Any]) -> list[str]:
    compacted: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if not text or text in seen:
            continue
        compacted.append(text)
        seen.add(text)
    return compacted


def first_non_empty(*values: Any) -> str | None:
    compacted = compact_strings(values)
    return compacted[0] if compacted else None


def as_bool(value: Any, *, allow_on_off: bool = True) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        truthy = {"true", "enabled", "yes"}
        falsey = {"false", "disabled", "no"}
        if allow_on_off:
            truthy.add("on")
            falsey.add("off")
        if normalized in truthy:
            return True
        if normalized in falsey:
            return False
    return bool(value)


def as_list(value: Any, *, expand_tuples: bool = True) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if expand_tuples and isinstance(value, tuple):
        return list(value)
    return [value]


def as_optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def first_item(value: Any, *, expand_tuples: bool = True) -> dict[str, Any] | None:
    items = as_list(value, expand_tuples=expand_tuples)
    if not items:
        return None
    first = items[0]
    if isinstance(first, dict):
        return first
    return None


def first_mapping(
    value: Any,
    *,
    expand_tuples: bool = False,
    scan_all: bool = False,
) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    items = as_list(value, expand_tuples=expand_tuples)
    if scan_all:
        for item in items:
            if isinstance(item, Mapping):
                return item
        return None
    first = items[0] if items else None
    return first if isinstance(first, Mapping) else None


def value_is_unknown(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, Mapping):
        return any(value_is_unknown(item) for item in value.values())
    if isinstance(value, list):
        return any(value_is_unknown(item) for item in value)
    return False


def attribute_unknown(unknown_values: Mapping[str, Any] | None, key: str) -> bool:
    return isinstance(unknown_values, Mapping) and value_is_unknown(unknown_values.get(key))


def unknown_block_at(value: Any, index: int) -> Any:
    if value is True:
        return True
    if isinstance(value, list) and index < len(value):
        return value[index]
    return None


def block_attribute_unknown(unknown_block: Any, key: str) -> bool:
    if unknown_block is True:
        return True
    if isinstance(unknown_block, Mapping):
        return value_is_unknown(unknown_block.get(key))
    if isinstance(unknown_block, list) and unknown_block:
        first = unknown_block[0]
        return first is True or (isinstance(first, Mapping) and value_is_unknown(first.get(key)))
    return False


def first_block_attribute_unknown(
    unknown_values: Mapping[str, Any] | None,
    block: str,
    key: str,
) -> bool:
    if not isinstance(unknown_values, Mapping):
        return False
    return block_attribute_unknown(unknown_values.get(block), key)


def known_string(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    key: str,
    uncertainties: list[str],
    *,
    path: str | None = None,
    require_string: bool = False,
) -> str | None:
    display_path = path or key
    if attribute_unknown(unknown_values, key):
        uncertainties.append(f"{display_path} is unknown after planning")
        return None
    raw = values.get(key)
    if raw is None:
        return None
    if require_string and not isinstance(raw, str):
        uncertainties.append(f"{display_path} has an unrecognized value shape")
        return None
    return first_non_empty(raw)


def known_string_list(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    key: str,
    uncertainties: list[str],
    *,
    path: str | None = None,
) -> list[str]:
    display_path = path or key
    if attribute_unknown(unknown_values, key):
        uncertainties.append(f"{display_path} is unknown after planning")
        return []
    return compact_strings(as_list(values.get(key)))


def known_bool(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    key: str,
    uncertainties: list[str],
    *,
    path: str | None = None,
    allow_string: bool = True,
) -> bool | None:
    display_path = path or key
    if attribute_unknown(unknown_values, key):
        uncertainties.append(f"{display_path} is unknown after planning")
        return None
    if key not in values or values[key] is None:
        return None
    value = values[key]
    if isinstance(value, bool):
        return value
    if allow_string and isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "enabled", "yes", "on"}:
            return True
        if normalized in {"false", "disabled", "no", "off"}:
            return False
    uncertainties.append(f"{display_path} has an unrecognized value shape")
    return None


def known_block_string(
    values: Mapping[str, Any] | None,
    unknown_block: Any,
    key: str,
    uncertainties: list[str],
    *,
    path: str,
    unknown_fields: list[str] | None = None,
) -> str | None:
    if block_attribute_unknown(unknown_block, key):
        uncertainties.append(f"{path}.{key} is unknown after planning")
        if unknown_fields is not None:
            unknown_fields.append(key)
        return None
    return first_non_empty(values.get(key)) if values is not None else None


def known_block_strings(
    values: Mapping[str, Any] | None,
    unknown_block: Any,
    key: str,
    uncertainties: list[str],
    *,
    path: str,
    unknown_fields: list[str] | None = None,
) -> list[str]:
    if block_attribute_unknown(unknown_block, key):
        uncertainties.append(f"{path}.{key} is unknown after planning")
        if unknown_fields is not None:
            unknown_fields.append(key)
        return []
    return compact_strings(as_list(values.get(key))) if values is not None else []


def known_block_bool(
    values: Mapping[str, Any] | None,
    unknown_block: Any,
    key: str,
    uncertainties: list[str],
    *,
    path: str,
    unknown_fields: list[str] | None = None,
) -> bool | None:
    if block_attribute_unknown(unknown_block, key):
        uncertainties.append(f"{path}.{key} is unknown after planning")
        if unknown_fields is not None:
            unknown_fields.append(key)
        return None
    value = values.get(key) if values is not None else None
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    uncertainties.append(f"{path}.{key} has an unrecognized value shape")
    return None


def known_block_bool_state(
    values: Mapping[str, Any] | None,
    unknown_block: Any,
    key: str,
    uncertainties: list[str],
    *,
    path: str,
) -> str | None:
    if block_attribute_unknown(unknown_block, key):
        uncertainties.append(f"{path}.{key} is unknown after planning")
        return None
    value = values.get(key) if values is not None else None
    if isinstance(value, bool):
        return "enabled" if value else "disabled"
    return None


def known_block_int(
    values: Mapping[str, Any] | None,
    unknown_block: Any,
    key: str,
    uncertainties: list[str],
    *,
    path: str,
    unknown_fields: list[str] | None = None,
) -> int | None:
    if block_attribute_unknown(unknown_block, key):
        uncertainties.append(f"{path}.{key} is unknown after planning")
        if unknown_fields is not None:
            unknown_fields.append(key)
        return None
    value = values.get(key) if values is not None else None
    if value is None:
        return None
    if isinstance(value, bool):
        uncertainties.append(f"{path}.{key} has an unrecognized value shape")
        return None
    parsed = as_optional_int(value)
    if parsed is None:
        uncertainties.append(f"{path}.{key} has an unrecognized value shape")
    return parsed


def dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


def dedupe_strings(values: Iterable[str | None]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if value is None:
            continue
        normalized = str(value).strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(normalized)
    return deduped


def bool_state(value: bool | None) -> str:
    if value is True:
        return STATE_ENABLED
    if value is False:
        return STATE_DISABLED
    return STATE_UNKNOWN


def block_bool_state(
    block: Mapping[str, Any] | None,
    unknown_block: Any,
    key: str,
    uncertainties: list[str],
    *,
    path: str,
) -> str:
    value = known_block_bool(block, unknown_block, key, uncertainties, path=path)
    if value is None:
        return STATE_UNKNOWN
    return STATE_ENABLED if value else STATE_DISABLED


def block_config_state(block: Mapping[str, Any] | None, unknown_block: Any) -> str:
    if unknown_block is True and block is None:
        return STATE_UNKNOWN
    return STATE_CONFIGURED if block else STATE_NOT_CONFIGURED


def tls_version_below_1_2(value: str | None) -> bool:
    if value is None:
        return False
    normalized = value.strip().lower().replace(".", "_").replace("-", "_")
    return normalized in {"tls1_0", "tls1_1", "tlsv1", "tlsv1_0", "tlsv1_1", "1_0", "1_1"}


def append_unique(values: list[Any], value: Any) -> None:
    if value not in values:
        values.append(value)
