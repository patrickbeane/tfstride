from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType


def path_string_values(paths: Iterable[Mapping[str, Any]], key: str) -> list[str]:
    values: set[str] = set()
    for path in paths:
        value = path.get(key)
        if isinstance(value, str) and value:
            values.add(value)
        elif isinstance(value, list):
            values.update(item for item in value if isinstance(item, str) and item)
    return sorted(values)


def resolved_public_load_balancers(
    paths: Iterable[Mapping[str, Any]],
    context: RuleEvaluationContext,
) -> list[str]:
    addresses = path_string_values(paths, "internet_facing_load_balancers")
    return [
        address
        for address in addresses
        if (resource := context.inventory.get_by_address(address)) is not None
        and resource.resource_type == "aws_lb"
        and resource.public_exposure
    ]


def internet_boundary_id(
    load_balancer_addresses: list[str],
    context: RuleEvaluationContext,
) -> str | None:
    return next(
        (
            boundary.identifier
            for address in load_balancer_addresses
            if (boundary := context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", address)))
            is not None
        ),
        None,
    )


def public_service_network_path(load_balancer_addresses: list[str], service_address: str) -> list[str]:
    return [
        item
        for address in load_balancer_addresses
        for item in (
            f"internet reaches {address}",
            f"{address} fronts {service_address}",
        )
    ]
