from __future__ import annotations

from tfstride.providers.gcp.custom_role_index import custom_role_reference_keys
from tfstride.providers.gcp.resource_utils import normalize_gcp_project

__all__ = [
    "custom_role_reference_keys",
    "gcs_bucket_scope_name",
    "gcs_bucket_target_matches",
    "normalize_gcp_project",
]


def gcs_bucket_scope_name(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.startswith("${") and text.endswith("}"):
        text = text[2:-1].strip()
    prefix = "projects/_/buckets/"
    if not text.startswith(prefix):
        return None
    name = text[len(prefix) :].rstrip("/")
    return name if name and "/" not in name else None


def gcs_bucket_target_matches(
    value: object,
    bucket_address: str,
    bucket_name: str,
) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip()
    if text.startswith("${") and text.endswith("}"):
        text = text[2:-1].strip()
    return (
        text
        in {
            bucket_name,
            f"{bucket_address}.name",
        }
        or gcs_bucket_scope_name(text) == bucket_name
    )
