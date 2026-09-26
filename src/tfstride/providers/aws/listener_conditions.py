"""Conservative request witnesses for modeled ALB rule precedence.

A witness proves that at least one host/path/method reaches the action after
earlier rules. Failure to find a witness is uncertainty, not proof of a block.
The bounded search deliberately makes no claim about arbitrary regexes, headers,
query strings, or source-IP conditions.
"""

from __future__ import annotations

import re
from itertools import islice, product
from typing import Any

_DEFAULTS = {
    "host_header": ("tfstride.invalid", "other.invalid", "a.example"),
    "path_pattern": ("/", "/tfstride", "/other"),
    "http_request_method": ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"),
}


def _matches(field: str, pattern: str, value: str) -> bool:
    if field == "http_request_method":
        return pattern == value
    if field == "host_header":
        pattern, value = pattern.lower(), value.lower()
    # Only ALB's '*' and '?' are special. Avoid regex backtracking on plan input.
    positions = {0}
    for char in pattern:
        if char == "*":
            positions = set(range(min(positions), len(value) + 1)) if positions else set()
        else:
            positions = {
                position + 1
                for position in positions
                if position < len(value) and (char == "?" or char == value[position])
            }
        if not positions:
            return False
    return len(value) in positions


def _matches_conditions(conditions: list[dict[str, Any]], request: dict[str, str]) -> bool:
    return all(
        any(_matches(condition["field"], pattern, request[condition["field"]]) for pattern in condition["values"])
        for condition in conditions
    )


def listener_request_witness(
    conditions: list[dict[str, Any]],
    predecessors: list[list[dict[str, Any]] | None],
) -> dict[str, str] | None:
    if any(predecessor is None for predecessor in predecessors):
        return None
    choices: list[list[str]] = []
    for field, defaults in _DEFAULTS.items():
        candidates: set[str] = set(defaults)
        for condition in conditions:
            if condition["field"] != field:
                continue
            for pattern in condition["values"]:
                for replacement in ("", "a", "tfstride", "other"):
                    candidates.add(pattern.replace("*", replacement).replace("?", "a"))
        candidates = {value for value in candidates if _valid_value(field, value)}
        matching = [condition for condition in conditions if condition["field"] == field]
        choices.append(
            sorted(
                value
                for value in candidates
                if all(
                    any(_matches(field, pattern, value) for pattern in condition["values"]) for condition in matching
                )
            )
        )
    for values in islice(product(*choices), 256):
        request = dict(zip(_DEFAULTS, values, strict=True))
        if not any(
            _matches_conditions(predecessor, request) for predecessor in predecessors if predecessor is not None
        ):
            return request
    return None


def _valid_value(field: str, value: str) -> bool:
    if field == "host_header":
        return re.fullmatch(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", value) is not None
    if field == "http_request_method":
        return re.fullmatch(r"[A-Z_-]+", value) is not None
    return value.startswith("/") and all(32 < ord(char) < 127 and char not in "?#" for char in value)
