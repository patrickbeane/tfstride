from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.azure.identity_normalizers import managed_identity_metadata
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.public_network import public_network_fallback_state
from tfstride.providers.azure.resource_utils import first_non_empty

AZURE_PROVIDER = "azure"


def normalize_linux_web_app(resource: TerraformResource) -> NormalizedResource:
    return _normalize_app_service(resource, os_type="linux")


def normalize_windows_web_app(resource: TerraformResource) -> NormalizedResource:
    return _normalize_app_service(resource, os_type="windows")


def normalize_function_app(resource: TerraformResource) -> NormalizedResource:
    return _normalize_app_service(resource, os_type=None)


def normalize_linux_function_app(resource: TerraformResource) -> NormalizedResource:
    return _normalize_app_service(resource, os_type="linux")


def normalize_windows_function_app(resource: TerraformResource) -> NormalizedResource:
    return _normalize_app_service(resource, os_type="windows")


def _normalize_app_service(resource: TerraformResource, *, os_type: str | None) -> NormalizedResource:
    values = resource.values
    uncertainties: list[str] = []
    site_config = _first_mapping(values.get("site_config"))
    app_service_id = _known_string(resource, values, "id", uncertainties)
    service_plan_reference = _known_service_plan_reference(resource, values, uncertainties)
    public_network_access_enabled = _known_bool(resource, values, "public_network_access_enabled", uncertainties)
    min_tls_version = _known_site_config_string(
        resource,
        site_config,
        ("minimum_tls_version", "min_tls_version"),
        uncertainties,
        display_key="minimum_tls_version",
    )
    ftps_state = _known_site_config_string(
        resource,
        site_config,
        ("ftps_state",),
        uncertainties,
        display_key="ftps_state",
    )

    metadata: dict[Any, Any] = {
        AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
        AzureResourceMetadata.LOCATION: first_non_empty(values.get("location")),
        AzureResourceMetadata.APP_SERVICE_ID: app_service_id,
        AzureResourceMetadata.APP_SERVICE_PLAN_REFERENCE: service_plan_reference,
        AzureResourceMetadata.OS_TYPE: os_type or first_non_empty(values.get("os_type")),
        AzureResourceMetadata.PUBLIC_NETWORK_FALLBACK_STATE: public_network_fallback_state(
            public_network_access_enabled
        ),
    }
    if public_network_access_enabled is not None:
        metadata[AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED] = public_network_access_enabled
    if min_tls_version is not None:
        metadata[AzureResourceMetadata.MIN_TLS_VERSION] = min_tls_version
    if ftps_state is not None:
        metadata[AzureResourceMetadata.FTPS_STATE] = ftps_state
    if uncertainties:
        metadata[AzureResourceMetadata.APP_SERVICE_POSTURE_UNCERTAINTIES] = uncertainties
    metadata.update(managed_identity_metadata(resource))

    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.COMPUTE,
        identifier=app_service_id or first_non_empty(values.get("name"), resource.name, resource.address),
        public_access_configured=public_network_access_enabled is True,
        metadata=metadata,
    )


def _known_service_plan_reference(
    resource: TerraformResource,
    values: Mapping[str, Any],
    uncertainties: list[str],
) -> str | None:
    for key in ("service_plan_id", "app_service_plan_id", "server_farm_id"):
        reference = _known_string(resource, values, key, uncertainties)
        if reference:
            return reference
    return None


def _known_bool(
    resource: TerraformResource,
    values: Mapping[str, Any],
    key: str,
    uncertainties: list[str],
) -> bool | None:
    if _value_is_unknown(resource.unknown_values.get(key)):
        uncertainties.append(f"{key} is unknown after planning")
        return None
    if key not in values or values[key] is None:
        return None
    value = values[key]
    if isinstance(value, bool):
        return value
    uncertainties.append(f"{key} has an unrecognized value shape")
    return None


def _known_string(
    resource: TerraformResource,
    values: Mapping[str, Any],
    key: str,
    uncertainties: list[str],
) -> str | None:
    if _value_is_unknown(resource.unknown_values.get(key)):
        uncertainties.append(f"{key} is unknown after planning")
        return None
    return first_non_empty(values.get(key))


def _known_site_config_string(
    resource: TerraformResource,
    site_config: Mapping[str, Any] | None,
    keys: tuple[str, ...],
    uncertainties: list[str],
    *,
    display_key: str,
) -> str | None:
    raw_unknown = resource.unknown_values.get("site_config")
    if raw_unknown is True and site_config is None:
        uncertainty = "site_config is unknown after planning"
        if uncertainty not in uncertainties:
            uncertainties.append(uncertainty)
        return None
    unknown_block = _first_mapping(raw_unknown)
    for key in keys:
        if _value_is_unknown(unknown_block.get(key) if unknown_block else None):
            uncertainties.append(f"site_config.{display_key} is unknown after planning")
            return None
    if site_config is None:
        return None
    for key in keys:
        value = first_non_empty(site_config.get(key))
        if value:
            return value
    return None


def _first_mapping(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, list) and value and isinstance(value[0], Mapping):
        return value[0]
    return None


def _value_is_unknown(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, Mapping):
        return any(_value_is_unknown(item) for item in value.values())
    if isinstance(value, list):
        return any(_value_is_unknown(item) for item in value)
    return False
