from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping
from typing import Any

from tfstride.providers.coercion import unknown_block_at

_BROAD_PUBLIC_ALIASES = frozenset({"*", "internet", "any"})


def first_unknown_block(value: Any) -> Any:
    if value is True or isinstance(value, Mapping):
        return value
    return unknown_block_at(value, 0)


def unknown_block_at_index(value: Any, index: int, *, mapping_applies_to_any_index: bool = False) -> Any:
    if value is True:
        return value
    if isinstance(value, Mapping):
        return value if mapping_applies_to_any_index or index == 0 else None
    return unknown_block_at(value, index)


def block_value(block: Any, key: str) -> Any:
    if isinstance(block, Mapping):
        return block.get(key)
    if block is True:
        return True
    return None


def dedupe(values: Iterable[Any]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if not text or text in seen:
            continue
        deduped.append(text)
        seen.add(text)
    return deduped


def is_broad_public_range(value: object) -> bool:
    normalized = str(value or "").strip().lower()
    if not normalized:
        return False
    if normalized in _BROAD_PUBLIC_ALIASES:
        return True
    try:
        network = ipaddress.ip_network(normalized, strict=False)
    except ValueError:
        return False
    return network.prefixlen == 0


def uncertainty_evidence(uncertainties: Iterable[str], field_markers: tuple[str, ...]) -> list[str]:
    return [uncertainty for uncertainty in uncertainties if any(marker in uncertainty for marker in field_markers)]
