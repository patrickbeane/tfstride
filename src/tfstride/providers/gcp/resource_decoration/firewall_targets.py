from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata


def instance_service_account_keys(instance: NormalizedResource) -> set[str]:
    keys: set[str] = set()
    for account in instance.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNTS):
        if not isinstance(account, dict):
            continue
        keys.update(service_account_reference_keys([account.get("email")]))
    return keys


def service_account_reference_keys(values: list[object]) -> set[str]:
    keys: set[str] = set()
    for value in values:
        if value in (None, "", "default"):
            continue
        text = str(value).strip()
        if not text or text == "default":
            continue
        keys.add(text)
        if text.startswith("serviceAccount:"):
            keys.add(text.removeprefix("serviceAccount:"))
        else:
            keys.add(f"serviceAccount:{text}")
    return keys
