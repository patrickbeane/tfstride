from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from tfstride.models import TerraformResource
from tfstride.providers.coercion import first_non_empty
from tfstride.providers.gcp.coercion import as_list, compact

GCP_REFERENCE_SUFFIXES = (
    ".id",
    ".name",
    ".email",
    ".member",
    ".self_link",
    ".secret_id",
    ".crypto_key_id",
    ".dataset_id",
    ".table_id",
)
GCP_ROLE_REFERENCE_SUFFIXES = (".id", ".name", ".role_id", ".self_link")
GCP_NETWORK_REFERENCE_SUFFIXES = (
    ".id",
    ".name",
    ".secret_id",
    ".crypto_key_id",
    ".dataset_id",
    ".table_id",
    ".self_link",
)


def resource_identifier(resource: TerraformResource) -> str:
    values = resource.values
    return (
        first_non_empty(values.get("self_link"), values.get("id"), values.get("name"), resource.address)
        or resource.address
    )


def resource_name(resource: TerraformResource) -> str:
    return first_non_empty(resource.values.get("name"), resource.name, resource.address) or resource.address


def last_path_segment(value: Any) -> str | None:
    text = first_non_empty(value)
    if text is None:
        return None
    return text.rstrip("/").rsplit("/", 1)[-1] or None


def network_interface_subnetworks(values: dict[str, Any]) -> list[str]:
    return compact(
        [
            interface.get("subnetwork")
            for interface in as_list(values.get("network_interface"))
            if isinstance(interface, dict)
        ]
    )


def has_external_access_config(values: dict[str, Any]) -> bool:
    for interface in as_list(values.get("network_interface")):
        if not isinstance(interface, dict):
            continue
        if as_list(interface.get("access_config")) or as_list(interface.get("ipv6_access_config")):
            return True
    return False


def binding_members(binding: Mapping[str, Any]) -> list[str]:
    members = binding.get("members")
    if isinstance(members, list):
        return [str(member) for member in members if member not in (None, "")]
    if members in (None, ""):
        return []
    return [str(members)]


def service_account_member(email: str | None) -> str | None:
    if not email:
        return None
    if email.startswith("serviceAccount:"):
        return email
    return f"serviceAccount:{email}"


def strip_reference_suffix(value: str, suffixes: Iterable[str]) -> str:
    text = str(value).strip()
    for suffix in suffixes:
        if text.endswith(suffix):
            return text[: -len(suffix)]
    return text


def gcp_reference_key(
    value: str,
    suffixes: Iterable[str] = GCP_REFERENCE_SUFFIXES,
) -> str:
    return strip_reference_suffix(value, suffixes)
