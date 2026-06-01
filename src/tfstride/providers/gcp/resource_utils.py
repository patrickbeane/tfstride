from __future__ import annotations

import json
from typing import Any

from tfstride.models import TerraformResource
from tfstride.providers.gcp.coercion import as_list, compact


def first_non_empty(*values: Any) -> str | None:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def load_json_document(raw_document: Any) -> dict[str, Any]:
    if isinstance(raw_document, dict):
        return raw_document
    if isinstance(raw_document, str) and raw_document.strip():
        try:
            loaded = json.loads(raw_document)
        except json.JSONDecodeError:
            return {}
        if isinstance(loaded, dict):
            return loaded
    return {}


def resource_identifier(resource: TerraformResource) -> str:
    values = resource.values
    return first_non_empty(values.get("self_link"), values.get("id"), values.get("name"), resource.address) or resource.address


def resource_name(resource: TerraformResource) -> str:
    return first_non_empty(resource.values.get("name"), resource.name, resource.address) or resource.address


def last_path_segment(value: Any) -> str | None:
    text = first_non_empty(value)
    if text is None:
        return None
    return text.rstrip("/").rsplit("/", 1)[-1] or None


def network_interface_subnetworks(values: dict[str, Any]) -> list[str]:
    return compact(
        [interface.get("subnetwork") for interface in as_list(values.get("network_interface")) if isinstance(interface, dict)]
    )


def has_external_access_config(values: dict[str, Any]) -> bool:
    for interface in as_list(values.get("network_interface")):
        if not isinstance(interface, dict):
            continue
        if as_list(interface.get("access_config")) or as_list(interface.get("ipv6_access_config")):
            return True
    return False