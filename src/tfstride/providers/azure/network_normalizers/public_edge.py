from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.network_normalizers.core import AZURE_PROVIDER, _network_resource
from tfstride.providers.azure.resource_utils import (
    as_list,
    bool_state,
    compact_strings,
    first_non_empty,
    known_block_bool,
    known_block_string,
    known_block_strings,
    known_string,
    unknown_block_at,
    value_is_unknown,
)
from tfstride.providers.coercion import (
    STATE_CONFIGURED,
    STATE_DISABLED,
    STATE_ENABLED,
    STATE_NOT_CONFIGURED,
    STATE_UNKNOWN,
)

_EXPOSURE_PUBLIC = "public"
_EXPOSURE_PRIVATE = "private"
_EXPOSURE_UNKNOWN = "unknown"


def normalize_public_ip(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=first_non_empty(values.get("id"), values.get("name"), resource.address),
        public_access_configured=True,
        metadata={
            AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
            AzureResourceMetadata.LOCATION: first_non_empty(values.get("location")),
            AzureResourceMetadata.PUBLIC_IP_ADDRESS: first_non_empty(values.get("ip_address")),
        },
    )


def normalize_load_balancer(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    uncertainties: list[str] = []
    load_balancer_id = known_string(values, resource.unknown_values, "id", uncertainties, path="id")
    (
        frontends,
        public_ip_references,
        public_ip_prefix_references,
        subnet_references,
        private_ip_addresses,
        frontend_unknown,
    ) = _load_balancer_frontends(resource, uncertainties)
    exposure_state = _frontend_exposure_state(
        [*public_ip_references, *public_ip_prefix_references],
        [*subnet_references, *private_ip_addresses],
        frontends,
        frontend_unknown,
    )
    metadata: dict[Any, Any] = {
        AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
        AzureResourceMetadata.LOCATION: first_non_empty(values.get("location")),
        AzureResourceMetadata.LOAD_BALANCER_ID: load_balancer_id,
        AzureResourceMetadata.LOAD_BALANCER_SKU: _sku_name(values.get("sku")),
        AzureResourceMetadata.LOAD_BALANCER_EXPOSURE_STATE: exposure_state,
        AzureResourceMetadata.LOAD_BALANCER_FRONTENDS: frontends,
        AzureResourceMetadata.LOAD_BALANCER_PUBLIC_IP_REFERENCES: public_ip_references,
        AzureResourceMetadata.LOAD_BALANCER_PUBLIC_IP_PREFIX_REFERENCES: public_ip_prefix_references,
        AzureResourceMetadata.LOAD_BALANCER_SUBNET_REFERENCES: subnet_references,
        AzureResourceMetadata.LOAD_BALANCER_PRIVATE_IP_ADDRESSES: private_ip_addresses,
    }
    if uncertainties:
        metadata[AzureResourceMetadata.LOAD_BALANCER_POSTURE_UNCERTAINTIES] = uncertainties

    return _network_resource(
        resource,
        identifier=first_non_empty(load_balancer_id, values.get("name"), resource.address),
        subnet_ids=tuple(subnet_references),
        public_access_configured=exposure_state == _EXPOSURE_PUBLIC,
        metadata=metadata,
    )


def normalize_application_gateway(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    uncertainties: list[str] = []
    gateway_id = known_string(values, resource.unknown_values, "id", uncertainties, path="id")
    edge_protection_metadata, edge_protection_uncertainties = _application_gateway_edge_protection_metadata(resource)
    uncertainties.extend(edge_protection_uncertainties)
    (
        frontends,
        public_ip_references,
        subnet_references,
        private_ip_addresses,
        frontend_unknown,
    ) = _application_gateway_frontends(resource, uncertainties)
    exposure_state = _frontend_exposure_state(
        public_ip_references,
        [*subnet_references, *private_ip_addresses],
        frontends,
        frontend_unknown,
    )
    metadata: dict[Any, Any] = {
        AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
        AzureResourceMetadata.LOCATION: first_non_empty(values.get("location")),
        AzureResourceMetadata.APPLICATION_GATEWAY_ID: gateway_id,
        AzureResourceMetadata.APPLICATION_GATEWAY_SKU: _sku_name(values.get("sku")),
        AzureResourceMetadata.APPLICATION_GATEWAY_EXPOSURE_STATE: exposure_state,
        AzureResourceMetadata.APPLICATION_GATEWAY_FRONTENDS: frontends,
        AzureResourceMetadata.APPLICATION_GATEWAY_HTTP_LISTENERS: _application_gateway_http_listeners(
            resource,
            uncertainties,
        ),
        AzureResourceMetadata.APPLICATION_GATEWAY_ROUTING_RULES: _application_gateway_routing_rules(
            resource,
            uncertainties,
        ),
        AzureResourceMetadata.APPLICATION_GATEWAY_PUBLIC_IP_REFERENCES: public_ip_references,
        AzureResourceMetadata.APPLICATION_GATEWAY_SUBNET_REFERENCES: subnet_references,
        AzureResourceMetadata.APPLICATION_GATEWAY_PRIVATE_IP_ADDRESSES: private_ip_addresses,
    }
    metadata.update(edge_protection_metadata)
    if uncertainties:
        metadata[AzureResourceMetadata.APPLICATION_GATEWAY_POSTURE_UNCERTAINTIES] = uncertainties

    return _network_resource(
        resource,
        identifier=first_non_empty(gateway_id, values.get("name"), resource.address),
        subnet_ids=tuple(subnet_references),
        public_access_configured=exposure_state == _EXPOSURE_PUBLIC,
        metadata=metadata,
    )


def _load_balancer_frontends(
    resource: TerraformResource,
    uncertainties: list[str],
) -> tuple[list[dict[str, Any]], list[str], list[str], list[str], list[str], bool]:
    records: list[dict[str, Any]] = []
    public_ip_references: list[str] = []
    public_ip_prefix_references: list[str] = []
    subnet_references: list[str] = []
    private_ip_addresses: list[str] = []
    frontend_unknown = False
    values = resource.values
    raw_unknown = resource.unknown_values.get("frontend_ip_configuration")
    if raw_unknown is True and not values.get("frontend_ip_configuration"):
        uncertainties.append("frontend_ip_configuration is unknown after planning")
        return [], [], [], [], [], True

    for index, item in enumerate(as_list(values.get("frontend_ip_configuration"))):
        path = f"frontend_ip_configuration[{index}]"
        if not isinstance(item, Mapping):
            uncertainties.append(f"{path} has an unrecognized value shape")
            frontend_unknown = True
            continue
        unknown_item = unknown_block_at(raw_unknown, index)
        record, unknown_fields = _frontend_record(
            item,
            unknown_item,
            uncertainties,
            path=path,
            include_public_ip_prefix=True,
        )
        if unknown_fields:
            frontend_unknown = True
            record["unknown_fields"] = unknown_fields
        if public_ip_reference := record.get("public_ip_address_id"):
            public_ip_references.append(str(public_ip_reference))
        if public_ip_prefix_reference := record.get("public_ip_prefix_id"):
            public_ip_prefix_references.append(str(public_ip_prefix_reference))
        if subnet_reference := record.get("subnet_id"):
            subnet_references.append(str(subnet_reference))
        if private_ip_address := record.get("private_ip_address"):
            private_ip_addresses.append(str(private_ip_address))
        records.append(record)

    return (
        records,
        compact_strings(public_ip_references),
        compact_strings(public_ip_prefix_references),
        compact_strings(subnet_references),
        compact_strings(private_ip_addresses),
        frontend_unknown,
    )


def _application_gateway_frontends(
    resource: TerraformResource,
    uncertainties: list[str],
) -> tuple[list[dict[str, Any]], list[str], list[str], list[str], bool]:
    records: list[dict[str, Any]] = []
    public_ip_references: list[str] = []
    subnet_references: list[str] = []
    private_ip_addresses: list[str] = []
    frontend_unknown = False
    values = resource.values
    raw_unknown = resource.unknown_values.get("frontend_ip_configuration")
    if raw_unknown is True and not values.get("frontend_ip_configuration"):
        uncertainties.append("frontend_ip_configuration is unknown after planning")
        return [], [], [], [], True

    for index, item in enumerate(as_list(values.get("frontend_ip_configuration"))):
        path = f"frontend_ip_configuration[{index}]"
        if not isinstance(item, Mapping):
            uncertainties.append(f"{path} has an unrecognized value shape")
            frontend_unknown = True
            continue
        unknown_item = unknown_block_at(raw_unknown, index)
        record, unknown_fields = _frontend_record(
            item,
            unknown_item,
            uncertainties,
            path=path,
            include_public_ip_prefix=False,
        )
        if unknown_fields:
            frontend_unknown = True
            record["unknown_fields"] = unknown_fields
        if public_ip_reference := record.get("public_ip_address_id"):
            public_ip_references.append(str(public_ip_reference))
        if subnet_reference := record.get("subnet_id"):
            subnet_references.append(str(subnet_reference))
        if private_ip_address := record.get("private_ip_address"):
            private_ip_addresses.append(str(private_ip_address))
        records.append(record)

    return (
        records,
        compact_strings(public_ip_references),
        compact_strings(subnet_references),
        compact_strings(private_ip_addresses),
        frontend_unknown,
    )


def _frontend_record(
    item: Mapping[str, Any],
    unknown_item: Any,
    uncertainties: list[str],
    *,
    path: str,
    include_public_ip_prefix: bool,
) -> tuple[dict[str, Any], list[str]]:
    record: dict[str, Any] = {}
    unknown_fields: list[str] = []
    for field in (
        "name",
        "public_ip_address_id",
        "subnet_id",
        "private_ip_address",
        "private_ip_address_allocation",
    ):
        value = known_block_string(
            item,
            unknown_item,
            field,
            uncertainties,
            path=path,
            unknown_fields=unknown_fields,
        )
        if value:
            record[field] = value
    if include_public_ip_prefix:
        public_ip_prefix_id = known_block_string(
            item,
            unknown_item,
            "public_ip_prefix_id",
            uncertainties,
            path=path,
            unknown_fields=unknown_fields,
        )
        if public_ip_prefix_id:
            record["public_ip_prefix_id"] = public_ip_prefix_id
    return record, unknown_fields


def _application_gateway_http_listeners(
    resource: TerraformResource,
    uncertainties: list[str],
) -> list[dict[str, Any]]:
    return _block_records(
        resource,
        "http_listener",
        (
            "name",
            "frontend_ip_configuration_name",
            "frontend_port_name",
            "protocol",
            "host_name",
            "ssl_certificate_name",
        ),
        uncertainties,
        list_fields=("host_names",),
    )


def _application_gateway_routing_rules(
    resource: TerraformResource,
    uncertainties: list[str],
) -> list[dict[str, Any]]:
    return _block_records(
        resource,
        "request_routing_rule",
        (
            "name",
            "rule_type",
            "http_listener_name",
            "backend_address_pool_name",
            "backend_http_settings_name",
            "redirect_configuration_name",
            "priority",
        ),
        uncertainties,
    )


def _application_gateway_edge_protection_metadata(
    resource: TerraformResource,
) -> tuple[dict[Any, Any], list[str]]:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    firewall_policy_id = known_string(
        values,
        unknown_values,
        "firewall_policy_id",
        uncertainties,
        path="firewall_policy_id",
    )
    firewall_policy_unknown = isinstance(unknown_values, Mapping) and value_is_unknown(
        unknown_values.get("firewall_policy_id")
    )
    waf_configurations, waf_enabled_state = _application_gateway_waf_configurations(resource, uncertainties)
    metadata: dict[Any, Any] = {
        AzureResourceMetadata.APPLICATION_GATEWAY_EDGE_PROTECTION_STATE: _application_gateway_edge_protection_state(
            firewall_policy_id,
            firewall_policy_unknown=firewall_policy_unknown,
            waf_enabled_state=waf_enabled_state,
        ),
        AzureResourceMetadata.APPLICATION_GATEWAY_FIREWALL_POLICY_ID: firewall_policy_id,
        AzureResourceMetadata.APPLICATION_GATEWAY_WAF_ENABLED_STATE: waf_enabled_state,
        AzureResourceMetadata.APPLICATION_GATEWAY_WAF_MODE: _first_record_value(waf_configurations, "firewall_mode"),
        AzureResourceMetadata.APPLICATION_GATEWAY_WAF_RULE_SET_TYPE: _first_record_value(
            waf_configurations,
            "rule_set_type",
        ),
        AzureResourceMetadata.APPLICATION_GATEWAY_WAF_RULE_SET_VERSION: _first_record_value(
            waf_configurations,
            "rule_set_version",
        ),
        AzureResourceMetadata.APPLICATION_GATEWAY_WAF_CONFIGURATIONS: waf_configurations,
    }
    if uncertainties:
        metadata[AzureResourceMetadata.APPLICATION_GATEWAY_EDGE_PROTECTION_UNCERTAINTIES] = uncertainties
    return metadata, uncertainties


def _application_gateway_edge_protection_state(
    firewall_policy_id: str | None,
    *,
    firewall_policy_unknown: bool,
    waf_enabled_state: str,
) -> str:
    if firewall_policy_id:
        return STATE_CONFIGURED
    if firewall_policy_unknown:
        return STATE_UNKNOWN
    if waf_enabled_state == STATE_ENABLED:
        return STATE_CONFIGURED
    if waf_enabled_state == STATE_DISABLED:
        return STATE_DISABLED
    if waf_enabled_state == STATE_UNKNOWN:
        return STATE_UNKNOWN
    return STATE_NOT_CONFIGURED


def _application_gateway_waf_configurations(
    resource: TerraformResource,
    uncertainties: list[str],
) -> tuple[list[dict[str, Any]], str]:
    values = resource.values
    raw_unknown = resource.unknown_values.get("waf_configuration")
    if raw_unknown is True and not values.get("waf_configuration"):
        uncertainties.append("waf_configuration is unknown after planning")
        return [], STATE_UNKNOWN

    records: list[dict[str, Any]] = []
    enabled_unknown = raw_unknown is True
    for index, item in enumerate(as_list(values.get("waf_configuration"))):
        path = f"waf_configuration[{index}]"
        if not isinstance(item, Mapping):
            uncertainties.append(f"{path} has an unrecognized value shape")
            enabled_unknown = True
            continue
        unknown_item = unknown_block_at(raw_unknown, index)
        record: dict[str, Any] = {}
        unknown_fields: list[str] = []
        enabled = known_block_bool(
            item,
            unknown_item,
            "enabled",
            uncertainties,
            path=path,
            unknown_fields=unknown_fields,
        )
        if enabled is not None:
            record["enabled"] = enabled
            record["enabled_state"] = bool_state(enabled)
        for field in ("firewall_mode", "rule_set_type", "rule_set_version"):
            value = known_block_string(
                item,
                unknown_item,
                field,
                uncertainties,
                path=path,
                unknown_fields=unknown_fields,
            )
            if value:
                record[field] = value
        for field in ("disabled_rule_group", "exclusion"):
            nested_records = _nested_block_records(
                item,
                unknown_item,
                field,
                uncertainties,
                path=path,
                unknown_fields=unknown_fields,
            )
            if nested_records:
                record[field] = nested_records
        if "enabled" in unknown_fields:
            enabled_unknown = True
        if unknown_fields:
            record["unknown_fields"] = unknown_fields
        records.append(record)

    return records, _application_gateway_waf_enabled_state(records, enabled_unknown)


def _application_gateway_waf_enabled_state(records: list[dict[str, Any]], unknown: bool) -> str:
    if any(record.get("enabled") is True for record in records):
        return STATE_ENABLED
    if unknown or any("enabled" in record.get("unknown_fields", []) for record in records):
        return STATE_UNKNOWN
    if any(record.get("enabled") is False for record in records):
        return STATE_DISABLED
    if records:
        return STATE_UNKNOWN
    return STATE_NOT_CONFIGURED


def _nested_block_records(
    item: Mapping[str, Any],
    unknown_item: Any,
    field: str,
    uncertainties: list[str],
    *,
    path: str,
    unknown_fields: list[str],
) -> list[dict[str, Any]]:
    if unknown_item is True or (isinstance(unknown_item, Mapping) and value_is_unknown(unknown_item.get(field))):
        uncertainties.append(f"{path}.{field} is unknown after planning")
        unknown_fields.append(field)
        return []
    records: list[dict[str, Any]] = []
    for index, raw_record in enumerate(as_list(item.get(field))):
        nested_path = f"{path}.{field}[{index}]"
        if not isinstance(raw_record, Mapping):
            uncertainties.append(f"{nested_path} has an unrecognized value shape")
            continue
        record = _normalized_record(raw_record)
        if record:
            records.append(record)
    return records


def _normalized_record(values: Mapping[str, Any]) -> dict[str, Any]:
    record: dict[str, Any] = {}
    for key, value in values.items():
        normalized = _normalized_evidence_value(value)
        if normalized not in (None, [], {}):
            record[str(key)] = normalized
    return record


def _normalized_evidence_value(value: Any) -> Any:
    if value in (None, "", [], {}):
        return None
    if isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, Mapping):
        return _normalized_record(value)
    if isinstance(value, list | tuple):
        normalized = [_normalized_evidence_value(item) for item in value]
        return [item for item in normalized if item not in (None, [], {})]
    return str(value)


def _first_record_value(records: list[dict[str, Any]], field: str) -> str | None:
    return first_non_empty(*(record.get(field) for record in records))


def _block_records(
    resource: TerraformResource,
    block_name: str,
    scalar_fields: tuple[str, ...],
    uncertainties: list[str],
    *,
    list_fields: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    values = resource.values
    raw_unknown = resource.unknown_values.get(block_name)
    if raw_unknown is True and not values.get(block_name):
        uncertainties.append(f"{block_name} is unknown after planning")
        return []

    for index, item in enumerate(as_list(values.get(block_name))):
        path = f"{block_name}[{index}]"
        if not isinstance(item, Mapping):
            uncertainties.append(f"{path} has an unrecognized value shape")
            continue
        unknown_item = unknown_block_at(raw_unknown, index)
        record: dict[str, Any] = {}
        unknown_fields: list[str] = []
        for field in scalar_fields:
            value = known_block_string(
                item,
                unknown_item,
                field,
                uncertainties,
                path=path,
                unknown_fields=unknown_fields,
            )
            if value:
                record[field] = value
        for field in list_fields:
            values_list = known_block_strings(
                item,
                unknown_item,
                field,
                uncertainties,
                path=path,
                unknown_fields=unknown_fields,
            )
            if values_list:
                record[field] = values_list
        if unknown_fields:
            record["unknown_fields"] = unknown_fields
        records.append(record)
    return records


def _frontend_exposure_state(
    public_references: list[str],
    private_references: list[str],
    frontends: list[dict[str, Any]],
    frontend_unknown: bool,
) -> str:
    if public_references:
        return _EXPOSURE_PUBLIC
    if frontend_unknown:
        return _EXPOSURE_UNKNOWN
    if private_references:
        return _EXPOSURE_PRIVATE
    if frontends:
        return _EXPOSURE_UNKNOWN
    return _EXPOSURE_UNKNOWN


def _sku_name(value: Any) -> str | None:
    if isinstance(value, Mapping):
        return first_non_empty(value.get("name"), value.get("tier"))
    for item in as_list(value):
        if isinstance(item, Mapping):
            return first_non_empty(item.get("name"), item.get("tier"))
    return first_non_empty(value)
