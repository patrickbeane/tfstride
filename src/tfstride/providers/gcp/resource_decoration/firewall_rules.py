from __future__ import annotations


def priority_value(value: object, *, default: int = 1000) -> int:
    if value is None:
        return default
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except ValueError:
        return default
