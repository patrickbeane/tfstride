from __future__ import annotations

import re
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
GCP_BASIC_IAM_ROLES = frozenset({"roles/owner", "roles/editor", "roles/viewer"})

_TERRAFORM_IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_-]*"
_TERRAFORM_INSTANCE_KEY = r'(?:\[(?:\d+|"(?:[^"\\]|\\.)*")\])?'
_TERRAFORM_MODULE_INSTANCE = rf"module\.{_TERRAFORM_IDENTIFIER}{_TERRAFORM_INSTANCE_KEY}\."
_TERRAFORM_GCP_RESOURCE_ADDRESS_PATTERN = re.compile(
    rf"^(?:{_TERRAFORM_MODULE_INSTANCE})*"
    rf"(?:data\.)?google_{_TERRAFORM_IDENTIFIER}\."
    rf"{_TERRAFORM_IDENTIFIER}{_TERRAFORM_INSTANCE_KEY}$"
)
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
    """Strip a Terraform result attribute without changing provider-native identities."""

    text = str(value).strip()
    traversal = text
    if traversal.startswith("${") and traversal.endswith("}"):
        traversal = traversal[2:-1].strip()
    for suffix in suffixes:
        if not traversal.endswith(suffix):
            continue
        resource_address = traversal[: -len(suffix)]
        if _TERRAFORM_GCP_RESOURCE_ADDRESS_PATTERN.fullmatch(resource_address):
            return resource_address
    return text


def gcp_reference_key(
    value: str,
    suffixes: Iterable[str] = GCP_REFERENCE_SUFFIXES,
) -> str:
    return strip_reference_suffix(value, suffixes)


def is_gcp_terraform_resource_address(value: str) -> bool:
    text = str(value).strip()
    if text.startswith("${") and text.endswith("}"):
        text = text[2:-1].strip()
    return _TERRAFORM_GCP_RESOURCE_ADDRESS_PATTERN.fullmatch(text) is not None


def normalize_gcp_project(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    parts = [part for part in text.split("/") if part]
    if len(parts) == 2 and parts[0] == "projects":
        return parts[1]
    if len(parts) == 1 and "${" not in text and not text.startswith("google_"):
        return parts[0]
    return None
