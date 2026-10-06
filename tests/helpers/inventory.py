from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from typing import Any

from tfstride.models import NormalizedResource, ResourceInventory


def inventory_with_resources(
    inventory: ResourceInventory,
    resources: Iterable[NormalizedResource],
) -> ResourceInventory:
    """Build a new indexed snapshot while retaining the inventory's cached metadata."""
    return ResourceInventory(
        provider=inventory.provider,
        resources=tuple(resources),
        unsupported_resources=list(inventory.unsupported_resources),
        plan_time_unknown_resources=inventory.plan_time_unknown_resources,
        metadata=inventory.metadata_snapshot(),
    )


def inventory_with_updated_identity(
    inventory: ResourceInventory,
    resource: NormalizedResource,
    **changes: Any,
) -> ResourceInventory:
    replacement = replace(resource, metadata=resource.metadata_snapshot(), **changes)
    return inventory_with_resources(
        inventory,
        (replacement if current is resource else current for current in inventory.resources),
    )
