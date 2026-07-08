from __future__ import annotations

from typing import Any

from tfstride.providers.coercion import attribute_unknown
from tfstride.providers.gcp.attributes import GcpValues
from tfstride.providers.gcp.coercion import as_list, compact


def _known_optional_int(
    values: dict[str, Any],
    unknown_values: dict[str, Any] | None,
    key: str,
    uncertainties: list[str],
) -> int | None:
    if attribute_unknown(unknown_values, key):
        uncertainties.append(f"{key} is unknown after planning")
        return None
    value = values.get(key)
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        uncertainties.append(f"{key} has an unrecognized value shape")
        return None


def _known_dict_list(
    values: dict[str, Any],
    unknown_values: dict[str, Any] | None,
    key: str,
    uncertainties: list[str],
) -> list[dict[str, Any]]:
    if attribute_unknown(unknown_values, key):
        uncertainties.append(f"{key} is unknown after planning")
        return []
    return [dict(item) for item in as_list(values.get(key)) if isinstance(item, dict)]


def _known_first_dict(
    values: dict[str, Any],
    unknown_values: dict[str, Any] | None,
    key: str,
    uncertainties: list[str],
) -> dict[str, Any]:
    records = _known_dict_list(values, unknown_values, key, uncertainties)
    return records[0] if records else {}


def _psc_config_subnetworks(psc_config: dict[str, Any]) -> list[str]:
    return compact(as_list(psc_config.get("subnetworks")))


def _string_from_raw(value: Any) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    return text or None


def _dict_list(value: Any) -> list[dict[str, Any]]:
    return [item for item in as_list(value) if isinstance(item, dict)]


def _gcp_values(values: dict[str, Any] | GcpValues) -> GcpValues:
    if isinstance(values, GcpValues):
        return values
    return GcpValues(values)
