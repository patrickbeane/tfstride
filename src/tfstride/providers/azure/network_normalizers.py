from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_utils import (
    as_list,
    bool_state,
    compact_strings,
    first_mapping,
    first_non_empty,
    known_block_bool,
    known_block_int,
    known_block_string,
    known_block_strings,
    known_bool,
    known_string,
    parse_network_security_rules,
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

AZURE_PROVIDER = "azure"


def normalize_virtual_network(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return _network_resource(
        resource,
        identifier=first_non_empty(values.get("id"), values.get("name"), resource.address),
        metadata={
            AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
            AzureResourceMetadata.LOCATION: first_non_empty(values.get("location")),
            AzureResourceMetadata.ADDRESS_SPACE: compact_strings(as_list(values.get("address_space"))),
        },
    )


def normalize_subnet(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    virtual_network_reference = first_non_empty(values.get("virtual_network_name"))
    return _network_resource(
        resource,
        identifier=first_non_empty(values.get("id"), values.get("name"), resource.address),
        vpc_id=virtual_network_reference,
        metadata={
            AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
            AzureResourceMetadata.VIRTUAL_NETWORK_REFERENCE: virtual_network_reference,
            AzureResourceMetadata.ADDRESS_PREFIXES: compact_strings(
                [values.get("address_prefix"), *as_list(values.get("address_prefixes"))]
            ),
            AzureResourceMetadata.DEFAULT_OUTBOUND_ACCESS_ENABLED: _bool_with_default(
                values.get("default_outbound_access_enabled"), True
            ),
        },
    )


def normalize_network_security_group(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    rules, records = parse_network_security_rules(values, resource.unknown_values)
    return _network_resource(
        resource,
        identifier=first_non_empty(values.get("id"), values.get("name"), resource.address),
        network_rules=rules,
        metadata={
            AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
            AzureResourceMetadata.LOCATION: first_non_empty(values.get("location")),
            AzureResourceMetadata.NETWORK_SECURITY_RULES: records,
        },
    )


def normalize_network_security_rule(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    rules, records = parse_network_security_rules(values, resource.unknown_values)
    return _network_resource(
        resource,
        identifier=first_non_empty(values.get("id"), values.get("name"), resource.address),
        network_rules=rules,
        metadata={
            AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
            AzureResourceMetadata.NETWORK_SECURITY_GROUP_REFERENCE: first_non_empty(
                values.get("network_security_group_name")
            ),
            AzureResourceMetadata.NETWORK_SECURITY_RULES: records,
        },
    )


def normalize_network_watcher_flow_log(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    flow_log_id = known_string(values, unknown_values, "id", uncertainties, path="id")
    name = known_string(values, unknown_values, "name", uncertainties, path="name") or resource.name
    network_security_group_id = known_string(
        values,
        unknown_values,
        "network_security_group_id",
        uncertainties,
        path="network_security_group_id",
    )
    target_resource_id = known_string(
        values,
        unknown_values,
        "target_resource_id",
        uncertainties,
        path="target_resource_id",
    )
    target_id = first_non_empty(network_security_group_id, target_resource_id)
    location = known_string(values, unknown_values, "location", uncertainties)
    enabled = known_bool(values, unknown_values, "enabled", uncertainties, path="enabled")
    storage_account_id = known_string(
        values,
        unknown_values,
        "storage_account_id",
        uncertainties,
        path="storage_account_id",
    )
    network_watcher_name = known_string(
        values,
        unknown_values,
        "network_watcher_name",
        uncertainties,
        path="network_watcher_name",
    )
    resource_group_name = known_string(
        values,
        unknown_values,
        "resource_group_name",
        uncertainties,
        path="resource_group_name",
    )
    version = _known_int(values, unknown_values, "version", uncertainties)
    retention_policy, retention_state, retention_days = _flow_log_retention_policy(resource, uncertainties)
    traffic_analytics, traffic_analytics_state = _flow_log_traffic_analytics(resource, uncertainties)

    return _network_resource(
        resource,
        identifier=first_non_empty(flow_log_id, name, target_id, resource.address),
        security_group_ids=tuple([target_id] if target_id else []),
        metadata={
            AzureResourceMetadata.NAME: name,
            AzureResourceMetadata.LOCATION: location,
            AzureResourceMetadata.NETWORK_FLOW_LOG_ID: flow_log_id,
            AzureResourceMetadata.NETWORK_FLOW_LOG_NAME: name,
            AzureResourceMetadata.NETWORK_FLOW_LOG_STATE: bool_state(enabled),
            AzureResourceMetadata.NETWORK_FLOW_LOG_TARGET_RESOURCE_ID: target_id,
            AzureResourceMetadata.NETWORK_FLOW_LOG_NETWORK_SECURITY_GROUP_ID: network_security_group_id,
            AzureResourceMetadata.NETWORK_FLOW_LOG_STORAGE_ACCOUNT_ID: storage_account_id,
            AzureResourceMetadata.NETWORK_FLOW_LOG_NETWORK_WATCHER_NAME: network_watcher_name,
            AzureResourceMetadata.NETWORK_FLOW_LOG_RESOURCE_GROUP_NAME: resource_group_name,
            AzureResourceMetadata.NETWORK_FLOW_LOG_VERSION: version,
            AzureResourceMetadata.NETWORK_FLOW_LOG_RETENTION_STATE: retention_state,
            AzureResourceMetadata.NETWORK_FLOW_LOG_RETENTION_DAYS: retention_days,
            AzureResourceMetadata.NETWORK_FLOW_LOG_RETENTION_POLICY: retention_policy,
            AzureResourceMetadata.NETWORK_FLOW_LOG_TRAFFIC_ANALYTICS_STATE: traffic_analytics_state,
            AzureResourceMetadata.NETWORK_FLOW_LOG_TRAFFIC_ANALYTICS_WORKSPACE_ID: traffic_analytics.get(
                "workspace_id"
            ),
            AzureResourceMetadata.NETWORK_FLOW_LOG_TRAFFIC_ANALYTICS_WORKSPACE_REGION: traffic_analytics.get(
                "workspace_region"
            ),
            AzureResourceMetadata.NETWORK_FLOW_LOG_TRAFFIC_ANALYTICS_WORKSPACE_RESOURCE_ID: traffic_analytics.get(
                "workspace_resource_id"
            ),
            AzureResourceMetadata.NETWORK_FLOW_LOG_TRAFFIC_ANALYTICS_INTERVAL_MINUTES: traffic_analytics.get(
                "interval_in_minutes"
            ),
            AzureResourceMetadata.NETWORK_FLOW_LOG_TRAFFIC_ANALYTICS: traffic_analytics,
            AzureResourceMetadata.NETWORK_TELEMETRY_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_subnet_network_security_group_association(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return _network_resource(
        resource,
        identifier=first_non_empty(values.get("id"), resource.address),
        metadata={
            AzureResourceMetadata.SUBNET_REFERENCE: first_non_empty(values.get("subnet_id")),
            AzureResourceMetadata.NETWORK_SECURITY_GROUP_REFERENCE: first_non_empty(
                values.get("network_security_group_id")
            ),
        },
    )


def normalize_network_interface(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    ip_configurations = [dict(item) for item in as_list(values.get("ip_configuration")) if isinstance(item, Mapping)]
    subnet_references = compact_strings(item.get("subnet_id") for item in ip_configurations)
    public_ip_references = compact_strings(item.get("public_ip_address_id") for item in ip_configurations)
    return _network_resource(
        resource,
        identifier=first_non_empty(values.get("id"), values.get("name"), resource.address),
        subnet_ids=tuple(subnet_references),
        public_access_configured=bool(public_ip_references),
        metadata={
            AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
            AzureResourceMetadata.LOCATION: first_non_empty(values.get("location")),
            AzureResourceMetadata.IP_CONFIGURATIONS: ip_configurations,
            AzureResourceMetadata.PUBLIC_IP_REFERENCES: public_ip_references,
            AzureResourceMetadata.IP_FORWARDING_ENABLED: bool(values.get("ip_forwarding_enabled", False)),
        },
    )


def normalize_network_interface_security_group_association(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return _network_resource(
        resource,
        identifier=first_non_empty(values.get("id"), resource.address),
        metadata={
            AzureResourceMetadata.NETWORK_INTERFACE_REFERENCE: first_non_empty(values.get("network_interface_id")),
            AzureResourceMetadata.NETWORK_SECURITY_GROUP_REFERENCE: first_non_empty(
                values.get("network_security_group_id")
            ),
        },
    )


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


def normalize_private_endpoint(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    uncertainties: list[str] = []
    endpoint_id = known_string(values, resource.unknown_values, "id", uncertainties, path="id")
    subnet_reference = known_string(values, resource.unknown_values, "subnet_id", uncertainties, path="subnet_id")
    service_connections, connection_resource_ids, subresource_names = _private_service_connections(
        resource,
        uncertainties,
    )
    (
        private_dns_zone_groups,
        private_dns_zone_ids,
        private_dns_zone_group_names,
        private_dns_zone_group_state,
        private_dns_zone_ids_state,
    ) = _private_dns_zone_groups(resource, uncertainties)

    metadata: dict[Any, Any] = {
        AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
        AzureResourceMetadata.LOCATION: first_non_empty(values.get("location")),
        AzureResourceMetadata.PRIVATE_ENDPOINT_ID: endpoint_id,
        AzureResourceMetadata.SUBNET_REFERENCE: subnet_reference,
        AzureResourceMetadata.PRIVATE_SERVICE_CONNECTIONS: service_connections,
        AzureResourceMetadata.PRIVATE_CONNECTION_RESOURCE_IDS: connection_resource_ids,
        AzureResourceMetadata.PRIVATE_ENDPOINT_SUBRESOURCE_NAMES: subresource_names,
        AzureResourceMetadata.PRIVATE_DNS_ZONE_GROUP_NAMES: private_dns_zone_group_names,
        AzureResourceMetadata.PRIVATE_DNS_ZONE_IDS: private_dns_zone_ids,
        AzureResourceMetadata.PRIVATE_DNS_ZONE_GROUPS: private_dns_zone_groups,
        AzureResourceMetadata.PRIVATE_DNS_ZONE_GROUP_STATE: private_dns_zone_group_state,
        AzureResourceMetadata.PRIVATE_DNS_ZONE_IDS_STATE: private_dns_zone_ids_state,
    }
    if uncertainties:
        metadata[AzureResourceMetadata.PRIVATE_ENDPOINT_UNCERTAINTIES] = uncertainties

    return _network_resource(
        resource,
        identifier=first_non_empty(endpoint_id, values.get("name"), resource.address),
        subnet_ids=tuple([subnet_reference] if subnet_reference else []),
        metadata=metadata,
    )


def normalize_private_dns_zone(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    uncertainties: list[str] = []
    zone_id = known_string(values, resource.unknown_values, "id", uncertainties, path="id")
    metadata: dict[Any, Any] = {
        AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
        AzureResourceMetadata.PRIVATE_DNS_ZONE_ID: zone_id,
    }
    if uncertainties:
        metadata[AzureResourceMetadata.PRIVATE_DNS_ZONE_UNCERTAINTIES] = uncertainties
    return _network_resource(
        resource,
        identifier=first_non_empty(zone_id, values.get("name"), resource.address),
        metadata=metadata,
    )


def normalize_private_dns_zone_virtual_network_link(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    uncertainties: list[str] = []
    link_id = known_string(values, resource.unknown_values, "id", uncertainties, path="id")
    zone_reference = known_string(
        values,
        resource.unknown_values,
        "private_dns_zone_name",
        uncertainties,
        path="private_dns_zone_name",
    )
    virtual_network_reference = known_string(
        values,
        resource.unknown_values,
        "virtual_network_id",
        uncertainties,
        path="virtual_network_id",
    )
    registration_enabled = known_bool(
        values,
        resource.unknown_values,
        "registration_enabled",
        uncertainties,
        path="registration_enabled",
    )
    metadata: dict[Any, Any] = {
        AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
        AzureResourceMetadata.PRIVATE_DNS_ZONE_VIRTUAL_NETWORK_LINK_ID: link_id,
        AzureResourceMetadata.PRIVATE_DNS_ZONE_REFERENCE: zone_reference,
        AzureResourceMetadata.PRIVATE_DNS_ZONE_VIRTUAL_NETWORK_REFERENCE: virtual_network_reference,
        AzureResourceMetadata.PRIVATE_DNS_ZONE_REGISTRATION_STATE: bool_state(registration_enabled),
    }
    if uncertainties:
        metadata[AzureResourceMetadata.PRIVATE_DNS_ZONE_UNCERTAINTIES] = uncertainties
    return _network_resource(
        resource,
        identifier=first_non_empty(link_id, values.get("name"), resource.address),
        vpc_id=virtual_network_reference,
        metadata=metadata,
    )


_EXPOSURE_PUBLIC = "public"
_EXPOSURE_PRIVATE = "private"
_EXPOSURE_UNKNOWN = "unknown"


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


def _private_service_connections(
    resource: TerraformResource,
    uncertainties: list[str],
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    values = resource.values
    raw_unknown = resource.unknown_values.get("private_service_connection")
    if raw_unknown is True and not values.get("private_service_connection"):
        uncertainties.append("private_service_connection is unknown after planning")
        return [], [], []

    records: list[dict[str, Any]] = []
    connection_resource_ids: list[str] = []
    subresource_names: list[str] = []
    for index, item in enumerate(as_list(values.get("private_service_connection"))):
        path = f"private_service_connection[{index}]"
        if not isinstance(item, Mapping):
            uncertainties.append(f"{path} has an unrecognized value shape")
            continue
        unknown_item = unknown_block_at(raw_unknown, index)
        record: dict[str, Any] = {}
        unknown_fields: list[str] = []

        connection_name = known_block_string(item, unknown_item, "name", uncertainties, path=path)
        if connection_name:
            record["name"] = connection_name

        target_id = known_block_string(
            item,
            unknown_item,
            "private_connection_resource_id",
            uncertainties,
            path=path,
            unknown_fields=unknown_fields,
        )
        if target_id:
            record["private_connection_resource_id"] = target_id
            connection_resource_ids.append(target_id)

        names = known_block_strings(
            item,
            unknown_item,
            "subresource_names",
            uncertainties,
            path=path,
            unknown_fields=unknown_fields,
        )
        record["subresource_names"] = names
        subresource_names.extend(names)

        manual_connection = known_block_bool(
            item,
            unknown_item,
            "is_manual_connection",
            uncertainties,
            path=path,
            unknown_fields=unknown_fields,
        )
        if manual_connection is not None:
            record["is_manual_connection"] = manual_connection

        if unknown_fields:
            record["unknown_fields"] = unknown_fields
        records.append(record)

    return records, compact_strings(connection_resource_ids), compact_strings(subresource_names)


def _private_dns_zone_groups(
    resource: TerraformResource,
    uncertainties: list[str],
) -> tuple[list[dict[str, Any]], list[str], list[str], str, str]:
    values = resource.values
    raw_unknown = resource.unknown_values.get("private_dns_zone_group")
    if raw_unknown is True and not values.get("private_dns_zone_group"):
        uncertainties.append("private_dns_zone_group is unknown after planning")
        return [], [], [], STATE_UNKNOWN, STATE_UNKNOWN

    records: list[dict[str, Any]] = []
    all_zone_ids: list[str] = []
    group_names: list[str] = []
    group_state_unknown = raw_unknown is True
    for index, item in enumerate(as_list(values.get("private_dns_zone_group"))):
        path = f"private_dns_zone_group[{index}]"
        if not isinstance(item, Mapping):
            uncertainties.append(f"{path} has an unrecognized value shape")
            group_state_unknown = True
            continue
        unknown_item = unknown_block_at(raw_unknown, index)
        record: dict[str, Any] = {}
        unknown_fields: list[str] = []

        group_name = known_block_string(item, unknown_item, "name", uncertainties, path=path)
        if group_name:
            record["name"] = group_name
            group_names.append(group_name)
        record_zone_ids = known_block_strings(
            item,
            unknown_item,
            "private_dns_zone_ids",
            uncertainties,
            path=path,
            unknown_fields=unknown_fields,
        )
        record["private_dns_zone_ids"] = record_zone_ids
        all_zone_ids.extend(record_zone_ids)
        if unknown_fields:
            record["unknown_fields"] = unknown_fields
        records.append(record)

    compact_zone_ids = compact_strings(all_zone_ids)
    group_state = _private_dns_zone_group_state(records, group_state_unknown)
    zone_ids_state = _private_dns_zone_ids_state(records, compact_zone_ids, group_state_unknown)
    return records, compact_zone_ids, compact_strings(group_names), group_state, zone_ids_state


def _private_dns_zone_group_state(records: list[dict[str, Any]], unknown: bool) -> str:
    if unknown:
        return STATE_UNKNOWN
    if records:
        return STATE_CONFIGURED
    return STATE_NOT_CONFIGURED


def _private_dns_zone_ids_state(records: list[dict[str, Any]], zone_ids: list[str], unknown: bool) -> str:
    if unknown or any("private_dns_zone_ids" in record.get("unknown_fields", []) for record in records):
        return STATE_UNKNOWN
    if zone_ids:
        return STATE_CONFIGURED
    return STATE_NOT_CONFIGURED


def _flow_log_retention_policy(
    resource: TerraformResource,
    uncertainties: list[str],
) -> tuple[dict[str, Any], str, int | None]:
    values = resource.values
    raw_unknown = resource.unknown_values.get("retention_policy")
    if raw_unknown is True and not values.get("retention_policy"):
        uncertainties.append("retention_policy is unknown after planning")
        return {}, STATE_UNKNOWN, None
    retention_policy = first_mapping(values.get("retention_policy"), expand_tuples=True)
    if retention_policy is None:
        if raw_unknown:
            uncertainties.append("retention_policy is unknown after planning")
            return {}, STATE_UNKNOWN, None
        return {}, STATE_NOT_CONFIGURED, None
    unknown_block = unknown_block_at(raw_unknown, 0)
    unknown_fields: list[str] = []
    enabled = known_block_bool(
        retention_policy,
        unknown_block,
        "enabled",
        uncertainties,
        path="retention_policy",
        unknown_fields=unknown_fields,
    )
    days = known_block_int(
        retention_policy,
        unknown_block,
        "days",
        uncertainties,
        path="retention_policy",
        unknown_fields=unknown_fields,
    )
    record: dict[str, Any] = {}
    if enabled is not None:
        record["enabled"] = enabled
    if days is not None:
        record["days"] = days
    if unknown_fields:
        record["unknown_fields"] = unknown_fields
    return record, bool_state(enabled), days


def _flow_log_traffic_analytics(
    resource: TerraformResource,
    uncertainties: list[str],
) -> tuple[dict[str, Any], str]:
    values = resource.values
    raw_unknown = resource.unknown_values.get("traffic_analytics")
    if raw_unknown is True and not values.get("traffic_analytics"):
        uncertainties.append("traffic_analytics is unknown after planning")
        return {}, STATE_UNKNOWN
    traffic_analytics = first_mapping(values.get("traffic_analytics"), expand_tuples=True)
    if traffic_analytics is None:
        if raw_unknown:
            uncertainties.append("traffic_analytics is unknown after planning")
            return {}, STATE_UNKNOWN
        return {}, STATE_NOT_CONFIGURED
    unknown_block = unknown_block_at(raw_unknown, 0)
    unknown_fields: list[str] = []
    enabled = known_block_bool(
        traffic_analytics,
        unknown_block,
        "enabled",
        uncertainties,
        path="traffic_analytics",
        unknown_fields=unknown_fields,
    )
    record: dict[str, Any] = {}
    if enabled is not None:
        record["enabled"] = enabled
    for field in ("workspace_id", "workspace_region", "workspace_resource_id"):
        value = known_block_string(
            traffic_analytics,
            unknown_block,
            field,
            uncertainties,
            path="traffic_analytics",
            unknown_fields=unknown_fields,
        )
        if value:
            record[field] = value
    interval = known_block_int(
        traffic_analytics,
        unknown_block,
        "interval_in_minutes",
        uncertainties,
        path="traffic_analytics",
        unknown_fields=unknown_fields,
    )
    if interval is not None:
        record["interval_in_minutes"] = interval
    if unknown_fields:
        record["unknown_fields"] = unknown_fields
    return record, bool_state(enabled)


def _network_resource(
    resource: TerraformResource,
    *,
    identifier: str | None,
    vpc_id: str | None = None,
    subnet_ids: tuple[str, ...] = (),
    security_group_ids: tuple[str, ...] = (),
    network_rules=None,
    public_access_configured: bool = False,
    metadata=None,
) -> NormalizedResource:
    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=identifier,
        vpc_id=vpc_id,
        subnet_ids=subnet_ids,
        security_group_ids=security_group_ids,
        network_rules=network_rules or [],
        public_access_configured=public_access_configured,
        metadata=metadata,
    )


def _bool_with_default(value, default: bool) -> bool:
    return default if value is None else bool(value)


def _known_int(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    key: str,
    uncertainties: list[str],
) -> int | None:
    if isinstance(unknown_values, Mapping) and value_is_unknown(unknown_values.get(key)):
        uncertainties.append(f"{key} is unknown after planning")
        return None
    value = values.get(key)
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        uncertainties.append(f"{key} has an unrecognized value shape")
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        uncertainties.append(f"{key} has an unrecognized value shape")
        return None
