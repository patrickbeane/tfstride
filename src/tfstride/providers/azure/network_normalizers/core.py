from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.azure.resource_utils import value_is_unknown

AZURE_PROVIDER = "azure"


def _network_resource(
    resource: TerraformResource,
    *,
    identifier: str | None,
    vpc_id: str | None = None,
    subnet_ids: tuple[str, ...] = (),
    security_group_ids: tuple[str, ...] = (),
    network_rules=None,
    public_access_configured: bool = False,
    metadata=None,
) -> NormalizedResource:
    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=identifier,
        vpc_id=vpc_id,
        subnet_ids=subnet_ids,
        security_group_ids=security_group_ids,
        network_rules=network_rules or [],
        public_access_configured=public_access_configured,
        metadata=metadata,
    )


def _bool_with_default(value, default: bool) -> bool:
    return default if value is None else bool(value)


def _known_int(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    key: str,
    uncertainties: list[str],
) -> int | None:
    if isinstance(unknown_values, Mapping) and value_is_unknown(unknown_values.get(key)):
        uncertainties.append(f"{key} is unknown after planning")
        return None
    value = values.get(key)
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        uncertainties.append(f"{key} has an unrecognized value shape")
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        uncertainties.append(f"{key} has an unrecognized value shape")
        return None
