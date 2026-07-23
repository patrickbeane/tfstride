from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_utils import known_string

AZURE_PROVIDER = "azure"


def normalize_servicebus_queue(resource: TerraformResource) -> NormalizedResource:
    return _normalize_entity(resource, "queue")


def normalize_servicebus_topic(resource: TerraformResource) -> NormalizedResource:
    return _normalize_entity(resource, "topic")


def normalize_servicebus_subscription(resource: TerraformResource) -> NormalizedResource:
    return _normalize_entity(
        resource,
        "subscription",
        namespace_reference_key=None,
        topic_reference_key="topic_id",
    )


def _normalize_entity(
    resource: TerraformResource,
    entity_kind: str,
    *,
    namespace_reference_key: str | None = "namespace_id",
    topic_reference_key: str | None = None,
) -> NormalizedResource:
    values = resource.values
    uncertainties: list[str] = []
    entity_id = _required_string(resource, "id", uncertainties)
    entity_name = known_string(
        values,
        resource.unknown_values,
        "name",
        uncertainties,
        require_string=True,
    )
    namespace_reference = (
        _required_string(resource, namespace_reference_key, uncertainties)
        if namespace_reference_key is not None
        else None
    )
    topic_reference = (
        _required_string(resource, topic_reference_key, uncertainties) if topic_reference_key is not None else None
    )

    metadata: dict[Any, Any] = {
        AzureResourceMetadata.NAME: entity_name or resource.name,
        AzureResourceMetadata.SERVICE_BUS_ENTITY_ID: entity_id,
        AzureResourceMetadata.SERVICE_BUS_ENTITY_NAME: entity_name,
        AzureResourceMetadata.SERVICE_BUS_ENTITY_KIND: entity_kind,
        AzureResourceMetadata.SERVICE_BUS_NAMESPACE_REFERENCE: namespace_reference,
        AzureResourceMetadata.SERVICE_BUS_TOPIC_REFERENCE: topic_reference,
    }
    if uncertainties:
        metadata[AzureResourceMetadata.SERVICE_BUS_POSTURE_UNCERTAINTIES] = uncertainties

    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=entity_id or resource.address,
        data_sensitivity="sensitive",
        metadata=metadata,
    )


def _required_string(resource: TerraformResource, key: str, uncertainties: list[str]) -> str | None:
    before = len(uncertainties)
    value = known_string(
        resource.values,
        resource.unknown_values,
        key,
        uncertainties,
        require_string=True,
    )
    if value is None and len(uncertainties) == before:
        uncertainties.append(f"{key} is not represented in planned values")
    return value
