from __future__ import annotations

import ipaddress


def consume_intervals(
    intervals: list[tuple[int, int]],
    rule_start: int,
    rule_end: int,
) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    """Split inclusive intervals into their intersection and remaining pieces."""
    matched: list[tuple[int, int]] = []
    remaining: list[tuple[int, int]] = []
    for start, end in intervals:
        overlap_start = max(start, rule_start)
        overlap_end = min(end, rule_end)
        if overlap_start > overlap_end:
            remaining.append((start, end))
            continue
        matched.append((overlap_start, overlap_end))
        if start < overlap_start:
            remaining.append((start, overlap_start - 1))
        if overlap_end < end:
            remaining.append((overlap_end + 1, end))
    return matched, remaining


_BROAD_PUBLIC_ALIASES = frozenset({"*", "internet", "any"})


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
