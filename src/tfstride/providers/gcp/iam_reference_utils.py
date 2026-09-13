from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_utils import (
    GCP_ROLE_REFERENCE_SUFFIXES,
    gcp_reference_key,
    normalize_gcp_project,
)

__all__ = [
    "custom_role_reference_keys",
    "gcs_bucket_scope_name",
    "gcs_bucket_target_matches",
    "normalize_gcp_project",
]


def custom_role_reference_keys(resource: NormalizedResource) -> set[str]:
    facts = gcp_facts(resource)
    references: set[str | None] = {
        resource.address,
        f"{resource.address}.id",
        f"{resource.address}.name",
        f"{resource.address}.role_id",
        resource.identifier,
        facts.resource_name,
        facts.custom_role_id,
    }
    if facts.project and facts.custom_role_id:
        references.add(f"projects/{facts.project}/roles/{facts.custom_role_id}")
    if facts.organization_id and facts.custom_role_id:
        references.add(f"organizations/{facts.organization_id}/roles/{facts.custom_role_id}")
    return {gcp_reference_key(reference.strip(), GCP_ROLE_REFERENCE_SUFFIXES) for reference in references if reference}


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
