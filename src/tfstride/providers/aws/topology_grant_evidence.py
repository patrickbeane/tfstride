"""Read grant breadth from projected topology-disruption path statements.

Topology-disruption paths record, per authorization statement, whether the
allow named the exact target or a resource pattern covering it. Public-workload
rules use these helpers to report that breadth in finding evidence and to note
when a grant may extend beyond the modeled plan.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import cast


def path_statements(path: Mapping[str, object]) -> list[Mapping[str, object]]:
    statements = path.get("authorization_statements")
    if not isinstance(statements, list):
        return []
    return [
        cast(Mapping[str, object], statement)
        for statement in cast(list[object], statements)
        if isinstance(statement, Mapping)
    ]


def path_grant_resource_scopes(path: Mapping[str, object]) -> list[str]:
    return sorted(
        {scope for statement in path_statements(path) for scope in _string_values(statement.get("resource_scopes"))}
    )


def path_grant_resources(path: Mapping[str, object]) -> list[str]:
    return sorted(
        {
            resource
            for statement in path_statements(path)
            for resource in _string_values(statement.get("matching_resources"))
        },
        key=str.casefold,
    )


def has_pattern_grant(paths: Sequence[Mapping[str, object]]) -> bool:
    return any(scope.endswith("_pattern") for path in paths for scope in path_grant_resource_scopes(path))


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in cast(list[object], value) if isinstance(item, str) and item]
