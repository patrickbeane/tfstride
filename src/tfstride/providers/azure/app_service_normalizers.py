from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.azure.identity_normalizers import managed_identity_metadata
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.public_network import public_network_fallback_state
from tfstride.providers.azure.resource_utils import (
    as_list,
    compact_strings,
    first_mapping,
    first_non_empty,
    known_block_int,
    known_block_string,
    known_bool,
    known_string,
    unknown_block_at,
    value_is_unknown,
)

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
    site_config = first_mapping(values.get("site_config"))
    app_service_id = known_string(values, resource.unknown_values, "id", uncertainties)
    service_plan_reference = _known_service_plan_reference(resource, values, uncertainties)
    vnet_integration_subnet_id = known_string(
        values, resource.unknown_values, "virtual_network_subnet_id", uncertainties
    )
    public_network_access_enabled = known_bool(
        values, resource.unknown_values, "public_network_access_enabled", uncertainties, allow_string=False
    )
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
    ip_restriction_default_action = _known_site_config_string(
        resource,
        site_config,
        ("ip_restriction_default_action",),
        uncertainties,
        display_key="ip_restriction_default_action",
    )
    scm_ip_restriction_default_action = _known_site_config_string(
        resource,
        site_config,
        ("scm_ip_restriction_default_action",),
        uncertainties,
        display_key="scm_ip_restriction_default_action",
    )
    scm_use_main_ip_restriction = _known_site_config_bool(
        resource,
        site_config,
        "scm_use_main_ip_restriction",
        uncertainties,
    )
    access_restrictions = _access_restriction_records(
        resource,
        site_config,
        "ip_restriction",
        uncertainties,
    )
    scm_access_restrictions = _access_restriction_records(
        resource,
        site_config,
        "scm_ip_restriction",
        uncertainties,
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
    if vnet_integration_subnet_id is not None:
        metadata[AzureResourceMetadata.APP_SERVICE_VNET_INTEGRATION_SUBNET_ID] = vnet_integration_subnet_id
    if public_network_access_enabled is not None:
        metadata[AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED] = public_network_access_enabled
    if min_tls_version is not None:
        metadata[AzureResourceMetadata.MIN_TLS_VERSION] = min_tls_version
    if ftps_state is not None:
        metadata[AzureResourceMetadata.FTPS_STATE] = ftps_state
    if ip_restriction_default_action is not None:
        metadata[AzureResourceMetadata.APP_SERVICE_IP_RESTRICTION_DEFAULT_ACTION] = ip_restriction_default_action
    if scm_ip_restriction_default_action is not None:
        metadata[AzureResourceMetadata.APP_SERVICE_SCM_IP_RESTRICTION_DEFAULT_ACTION] = (
            scm_ip_restriction_default_action
        )
    if scm_use_main_ip_restriction is not None:
        metadata[AzureResourceMetadata.APP_SERVICE_SCM_USE_MAIN_IP_RESTRICTION] = scm_use_main_ip_restriction
    if access_restrictions:
        metadata[AzureResourceMetadata.APP_SERVICE_ACCESS_RESTRICTIONS] = access_restrictions
    if scm_access_restrictions:
        metadata[AzureResourceMetadata.APP_SERVICE_SCM_ACCESS_RESTRICTIONS] = scm_access_restrictions
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
        reference = known_string(values, resource.unknown_values, key, uncertainties)
        if reference:
            return reference
    return None


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
    unknown_block = first_mapping(raw_unknown)
    for key in keys:
        if value_is_unknown(unknown_block.get(key) if unknown_block else None):
            uncertainties.append(f"site_config.{display_key} is unknown after planning")
            return None
    if site_config is None:
        return None
    for key in keys:
        value = first_non_empty(site_config.get(key))
        if value:
            return value
    return None


def _known_site_config_bool(
    resource: TerraformResource,
    site_config: Mapping[str, Any] | None,
    key: str,
    uncertainties: list[str],
) -> bool | None:
    raw_unknown = resource.unknown_values.get("site_config")
    if raw_unknown is True and site_config is None:
        uncertainty = "site_config is unknown after planning"
        if uncertainty not in uncertainties:
            uncertainties.append(uncertainty)
        return None
    unknown_block = first_mapping(raw_unknown)
    if value_is_unknown(unknown_block.get(key) if unknown_block else None):
        uncertainties.append(f"site_config.{key} is unknown after planning")
        return None
    if site_config is None or key not in site_config or site_config[key] is None:
        return None
    value = site_config[key]
    if isinstance(value, bool):
        return value
    uncertainties.append(f"site_config.{key} has an unrecognized value shape")
    return None


def _access_restriction_records(
    resource: TerraformResource,
    site_config: Mapping[str, Any] | None,
    block_key: str,
    uncertainties: list[str],
) -> list[dict[str, Any]]:
    raw_unknown = resource.unknown_values.get("site_config")
    if raw_unknown is True and site_config is None:
        uncertainty = "site_config is unknown after planning"
        if uncertainty not in uncertainties:
            uncertainties.append(uncertainty)
        return []

    unknown_site_config = first_mapping(raw_unknown)
    unknown_blocks = unknown_site_config.get(block_key) if unknown_site_config else None
    blocks = as_list(site_config.get(block_key)) if site_config is not None else []
    if value_is_unknown(unknown_blocks) and not blocks:
        uncertainties.append(f"site_config.{block_key} is unknown after planning")
        return []

    records: list[dict[str, Any]] = []
    for index, raw_block in enumerate(blocks):
        path = f"site_config.{block_key}[{index}]"
        unknown_block = unknown_block_at(unknown_blocks, index)
        if unknown_block is True:
            uncertainties.append(f"{path} is unknown after planning")
            records.append(
                {
                    "unknown_fields": [
                        "name",
                        "priority",
                        "action",
                        "ip_address",
                        "service_tag",
                        "virtual_network_subnet_id",
                        "description",
                        "headers",
                    ]
                }
            )
            continue
        if not isinstance(raw_block, Mapping):
            uncertainties.append(f"{path} has an unrecognized value shape")
            continue
        records.append(_access_restriction_record(raw_block, unknown_block, path, uncertainties))
    return records


def _access_restriction_record(
    values: Mapping[str, Any],
    unknown_values: Any,
    path: str,
    uncertainties: list[str],
) -> dict[str, Any]:
    unknown_fields: list[str] = []
    record: dict[str, Any] = {}
    for key in ("name", "action", "ip_address", "service_tag", "virtual_network_subnet_id", "description"):
        value = known_block_string(values, unknown_values, key, uncertainties, path=path, unknown_fields=unknown_fields)
        if value is not None:
            record[key] = value
    priority = known_block_int(
        values, unknown_values, "priority", uncertainties, path=path, unknown_fields=unknown_fields
    )
    if priority is not None:
        record["priority"] = priority
    headers = _access_restriction_headers(values.get("headers"))
    if headers:
        record["headers"] = headers
    if isinstance(unknown_values, Mapping) and value_is_unknown(unknown_values.get("headers")):
        uncertainties.append(f"{path}.headers is unknown after planning")
        unknown_fields.append("headers")
    if unknown_fields:
        record["unknown_fields"] = sorted(set(unknown_fields))
    return record


def _access_restriction_headers(raw_headers: Any) -> list[dict[str, list[str]]]:
    headers: list[dict[str, list[str]]] = []
    for raw_header in as_list(raw_headers):
        if not isinstance(raw_header, Mapping):
            continue
        normalized = {
            str(key): compact_strings(as_list(value))
            for key, value in sorted(raw_header.items(), key=lambda item: str(item[0]))
        }
        normalized = {key: values for key, values in normalized.items() if values}
        if normalized:
            headers.append(normalized)
    return headers
