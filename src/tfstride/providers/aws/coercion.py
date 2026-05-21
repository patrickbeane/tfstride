from __future__ import annotations

from typing import Any


def compact(values: list[Any]) -> list[str]:
    return [str(value) for value in values if value not in (None, "", [])]


def as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "enabled", "yes"}:
            return True
        if normalized in {"false", "disabled", "no"}:
            return False
    return bool(value)


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def first_item(value: Any) -> dict[str, Any] | None:
    items = as_list(value)
    if not items:
        return None
    first = items[0]
    if isinstance(first, dict):
        return first
    return None


def as_optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
