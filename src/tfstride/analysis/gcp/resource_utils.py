from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

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


def binding_members(binding: Mapping[str, Any]) -> list[str]:
    members = binding.get("members")
    if isinstance(members, list):
        return [str(member) for member in members if member not in (None, "")]
    if members in (None, ""):
        return []
    return [str(members)]


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
