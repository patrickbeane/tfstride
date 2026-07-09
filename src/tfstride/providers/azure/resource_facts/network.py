from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from tfstride.models import NormalizedResource, SecurityGroupRule
from tfstride.providers.azure.metadata import AzureResourceMetadata


class AzureNetworkFacts:
    __slots__ = ()

    @property
    def virtual_network_reference(self) -> str | None:
        return self.get(AzureResourceMetadata.VIRTUAL_NETWORK_REFERENCE)

    @property
    def network_security_group_reference(self) -> str | None:
        return self.get(AzureResourceMetadata.NETWORK_SECURITY_GROUP_REFERENCE)

    @property
    def subnet_reference(self) -> str | None:
        return self.get(AzureResourceMetadata.SUBNET_REFERENCE)

    @property
    def network_interface_reference(self) -> str | None:
        return self.get(AzureResourceMetadata.NETWORK_INTERFACE_REFERENCE)

    @property
    def network_interface_references(self) -> list[str]:
        return self.get(AzureResourceMetadata.NETWORK_INTERFACE_REFERENCES)

    @property
    def public_ip_references(self) -> list[str]:
        return self.get(AzureResourceMetadata.PUBLIC_IP_REFERENCES)

    @property
    def ip_configurations(self) -> list[dict]:
        return self.get(AzureResourceMetadata.IP_CONFIGURATIONS)

    @property
    def network_security_rules(self) -> list[dict]:
        return self.get(AzureResourceMetadata.NETWORK_SECURITY_RULES)

    @property
    def network_flow_log_id(self) -> str | None:
        return self.get(AzureResourceMetadata.NETWORK_FLOW_LOG_ID)

    @property
    def network_flow_log_name(self) -> str | None:
        return self.get(AzureResourceMetadata.NETWORK_FLOW_LOG_NAME)

    @property
    def network_flow_log_state(self) -> str | None:
        return self.get(AzureResourceMetadata.NETWORK_FLOW_LOG_STATE)

    @property
    def network_flow_log_target_resource_id(self) -> str | None:
        return self.get(AzureResourceMetadata.NETWORK_FLOW_LOG_TARGET_RESOURCE_ID)

    @property
    def network_flow_log_network_security_group_id(self) -> str | None:
        return self.get(AzureResourceMetadata.NETWORK_FLOW_LOG_NETWORK_SECURITY_GROUP_ID)

    @property
    def network_flow_log_storage_account_id(self) -> str | None:
        return self.get(AzureResourceMetadata.NETWORK_FLOW_LOG_STORAGE_ACCOUNT_ID)

    @property
    def network_flow_log_network_watcher_name(self) -> str | None:
        return self.get(AzureResourceMetadata.NETWORK_FLOW_LOG_NETWORK_WATCHER_NAME)

    @property
    def network_flow_log_resource_group_name(self) -> str | None:
        return self.get(AzureResourceMetadata.NETWORK_FLOW_LOG_RESOURCE_GROUP_NAME)

    @property
    def network_flow_log_version(self) -> int | None:
        return self.get(AzureResourceMetadata.NETWORK_FLOW_LOG_VERSION)

    @property
    def network_flow_log_retention_state(self) -> str | None:
        return self.get(AzureResourceMetadata.NETWORK_FLOW_LOG_RETENTION_STATE)

    @property
    def network_flow_log_retention_days(self) -> int | None:
        return self.get(AzureResourceMetadata.NETWORK_FLOW_LOG_RETENTION_DAYS)

    @property
    def network_flow_log_retention_policy(self) -> dict[str, Any]:
        return self.get(AzureResourceMetadata.NETWORK_FLOW_LOG_RETENTION_POLICY)

    @property
    def network_flow_log_traffic_analytics_state(self) -> str | None:
        return self.get(AzureResourceMetadata.NETWORK_FLOW_LOG_TRAFFIC_ANALYTICS_STATE)

    @property
    def network_flow_log_traffic_analytics_workspace_id(self) -> str | None:
        return self.get(AzureResourceMetadata.NETWORK_FLOW_LOG_TRAFFIC_ANALYTICS_WORKSPACE_ID)

    @property
    def network_flow_log_traffic_analytics_workspace_region(self) -> str | None:
        return self.get(AzureResourceMetadata.NETWORK_FLOW_LOG_TRAFFIC_ANALYTICS_WORKSPACE_REGION)

    @property
    def network_flow_log_traffic_analytics_workspace_resource_id(self) -> str | None:
        return self.get(AzureResourceMetadata.NETWORK_FLOW_LOG_TRAFFIC_ANALYTICS_WORKSPACE_RESOURCE_ID)

    @property
    def network_flow_log_traffic_analytics_interval_minutes(self) -> int | None:
        return self.get(AzureResourceMetadata.NETWORK_FLOW_LOG_TRAFFIC_ANALYTICS_INTERVAL_MINUTES)

    @property
    def network_flow_log_traffic_analytics(self) -> dict[str, Any]:
        return self.get(AzureResourceMetadata.NETWORK_FLOW_LOG_TRAFFIC_ANALYTICS)

    @property
    def network_telemetry_posture_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.NETWORK_TELEMETRY_POSTURE_UNCERTAINTIES)

    @property
    def resolved_subnet_addresses(self) -> list[str]:
        return self.get(AzureResourceMetadata.RESOLVED_SUBNET_ADDRESSES)

    @property
    def resolved_network_security_group_addresses(self) -> list[str]:
        return self.get(AzureResourceMetadata.RESOLVED_NETWORK_SECURITY_GROUP_ADDRESSES)

    @property
    def resolved_network_interface_addresses(self) -> list[str]:
        return self.get(AzureResourceMetadata.RESOLVED_NETWORK_INTERFACE_ADDRESSES)

    @property
    def resolved_public_ip_addresses(self) -> list[str]:
        return self.get(AzureResourceMetadata.RESOLVED_PUBLIC_IP_ADDRESSES)

    @property
    def public_ip_address(self) -> str | None:
        return self.get(AzureResourceMetadata.PUBLIC_IP_ADDRESS)

    @property
    def load_balancer_id(self) -> str | None:
        return self.get(AzureResourceMetadata.LOAD_BALANCER_ID)

    @property
    def load_balancer_sku(self) -> str | None:
        return self.get(AzureResourceMetadata.LOAD_BALANCER_SKU)

    @property
    def load_balancer_exposure_state(self) -> str | None:
        return self.get(AzureResourceMetadata.LOAD_BALANCER_EXPOSURE_STATE)

    @property
    def load_balancer_public_ip_references(self) -> list[str]:
        return self.get(AzureResourceMetadata.LOAD_BALANCER_PUBLIC_IP_REFERENCES)

    @property
    def load_balancer_public_ip_prefix_references(self) -> list[str]:
        return self.get(AzureResourceMetadata.LOAD_BALANCER_PUBLIC_IP_PREFIX_REFERENCES)

    @property
    def load_balancer_subnet_references(self) -> list[str]:
        return self.get(AzureResourceMetadata.LOAD_BALANCER_SUBNET_REFERENCES)

    @property
    def load_balancer_private_ip_addresses(self) -> list[str]:
        return self.get(AzureResourceMetadata.LOAD_BALANCER_PRIVATE_IP_ADDRESSES)

    @property
    def load_balancer_frontends(self) -> list[dict]:
        return self.get(AzureResourceMetadata.LOAD_BALANCER_FRONTENDS)

    @property
    def load_balancer_posture_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.LOAD_BALANCER_POSTURE_UNCERTAINTIES)

    @property
    def application_gateway_id(self) -> str | None:
        return self.get(AzureResourceMetadata.APPLICATION_GATEWAY_ID)

    @property
    def application_gateway_sku(self) -> str | None:
        return self.get(AzureResourceMetadata.APPLICATION_GATEWAY_SKU)

    @property
    def application_gateway_exposure_state(self) -> str | None:
        return self.get(AzureResourceMetadata.APPLICATION_GATEWAY_EXPOSURE_STATE)

    @property
    def application_gateway_public_ip_references(self) -> list[str]:
        return self.get(AzureResourceMetadata.APPLICATION_GATEWAY_PUBLIC_IP_REFERENCES)

    @property
    def application_gateway_subnet_references(self) -> list[str]:
        return self.get(AzureResourceMetadata.APPLICATION_GATEWAY_SUBNET_REFERENCES)

    @property
    def application_gateway_private_ip_addresses(self) -> list[str]:
        return self.get(AzureResourceMetadata.APPLICATION_GATEWAY_PRIVATE_IP_ADDRESSES)

    @property
    def application_gateway_frontends(self) -> list[dict]:
        return self.get(AzureResourceMetadata.APPLICATION_GATEWAY_FRONTENDS)

    @property
    def application_gateway_http_listeners(self) -> list[dict]:
        return self.get(AzureResourceMetadata.APPLICATION_GATEWAY_HTTP_LISTENERS)

    @property
    def application_gateway_routing_rules(self) -> list[dict]:
        return self.get(AzureResourceMetadata.APPLICATION_GATEWAY_ROUTING_RULES)

    @property
    def application_gateway_posture_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.APPLICATION_GATEWAY_POSTURE_UNCERTAINTIES)

    @property
    def private_dns_zone_id(self) -> str | None:
        return self.get(AzureResourceMetadata.PRIVATE_DNS_ZONE_ID)

    @property
    def private_dns_zone_reference(self) -> str | None:
        return self.get(AzureResourceMetadata.PRIVATE_DNS_ZONE_REFERENCE)

    @property
    def private_dns_zone_virtual_network_link_id(self) -> str | None:
        return self.get(AzureResourceMetadata.PRIVATE_DNS_ZONE_VIRTUAL_NETWORK_LINK_ID)

    @property
    def private_dns_zone_virtual_network_reference(self) -> str | None:
        return self.get(AzureResourceMetadata.PRIVATE_DNS_ZONE_VIRTUAL_NETWORK_REFERENCE)

    @property
    def private_dns_zone_registration_state(self) -> str | None:
        return self.get(AzureResourceMetadata.PRIVATE_DNS_ZONE_REGISTRATION_STATE)

    @property
    def private_dns_zone_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.PRIVATE_DNS_ZONE_UNCERTAINTIES)

    def set_resolved_virtual_network_address(self, address: str) -> None:
        self.set(AzureResourceMetadata.RESOLVED_VIRTUAL_NETWORK_ADDRESS, address)
        self.resource.vpc_id = address

    def add_resolved_subnet_address(self, address: str) -> None:
        self.append(AzureResourceMetadata.RESOLVED_SUBNET_ADDRESSES, address)

    def add_resolved_network_security_group_address(self, address: str) -> None:
        self.append(AzureResourceMetadata.RESOLVED_NETWORK_SECURITY_GROUP_ADDRESSES, address)

    def add_resolved_network_interface_address(self, address: str) -> None:
        self.append(AzureResourceMetadata.RESOLVED_NETWORK_INTERFACE_ADDRESSES, address)

    def add_resolved_public_ip_address(self, address: str) -> None:
        self.append(AzureResourceMetadata.RESOLVED_PUBLIC_IP_ADDRESSES, address)

    def add_associated_resource_address(self, address: str) -> None:
        self.append(AzureResourceMetadata.ASSOCIATED_RESOURCE_ADDRESSES, address)

    def add_standalone_rule_address(self, address: str) -> None:
        self.append(AzureResourceMetadata.STANDALONE_RULE_ADDRESSES, address)

    def merge_network_security_rules(
        self,
        rules: Sequence[SecurityGroupRule],
        records: Sequence[dict],
    ) -> None:
        self.resource.extend_network_rules(rules)
        self.set(
            AzureResourceMetadata.NETWORK_SECURITY_RULES,
            [*self.network_security_rules, *records],
        )

    def add_security_group_reference(self, reference: str) -> None:
        if reference not in self.resource.security_group_ids:
            self.resource.security_group_ids = (*self.resource.security_group_ids, reference)

    def add_subnet_reference(self, reference: str) -> None:
        if reference not in self.resource.subnet_ids:
            self.resource.subnet_ids = (*self.resource.subnet_ids, reference)

    def set_subnet_references(self, references: Sequence[str]) -> None:
        self.resource.subnet_ids = tuple(dict.fromkeys(reference for reference in references if reference))

    def inherit_network_relationships(self, resource: NormalizedResource) -> None:
        for subnet_id in resource.subnet_ids:
            self.add_subnet_reference(subnet_id)
        for security_group_id in resource.security_group_ids:
            self.add_security_group_reference(security_group_id)
        if not self.resource.vpc_id and resource.vpc_id:
            self.resource.vpc_id = resource.vpc_id

    def set_public_ip_attachment(self, *, configured: bool, reasons: Sequence[str]) -> None:
        self.resource.public_access_configured = configured
        self.resource.public_access_reasons = list(reasons)
