from __future__ import annotations

from typing import Any

from tfstride.providers.coercion import as_bool as _as_bool
from tfstride.providers.coercion import as_list as _as_list
from tfstride.providers.coercion import as_optional_int as as_optional_int
from tfstride.providers.coercion import compact as compact
from tfstride.providers.coercion import first_item as _first_item

__all__ = ["as_bool", "as_list", "as_optional_int", "compact", "first_item"]


def as_bool(value: Any) -> bool:
    return _as_bool(value, allow_on_off=False)


def as_list(value: Any) -> list[Any]:
    return _as_list(value, expand_tuples=False)


def first_item(value: Any) -> dict[str, Any] | None:
    return _first_item(value, expand_tuples=False)
