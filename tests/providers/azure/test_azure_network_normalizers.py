from __future__ import annotations

import unittest

from tests.helpers.paths import SOURCE_ROOT
from tfstride.models import ResourceCategory, TerraformResource
from tfstride.providers.azure.network_normalizers import (
    normalize_application_gateway,
    normalize_load_balancer,
    normalize_network_interface,
    normalize_network_interface_security_group_association,
    normalize_network_security_group,
    normalize_network_security_rule,
    normalize_network_watcher_flow_log,
    normalize_private_dns_zone,
    normalize_private_dns_zone_virtual_network_link,
    normalize_public_ip,
    normalize_subnet,
    normalize_subnet_network_security_group_association,
    normalize_virtual_network,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType


def _resource(
    resource_type: str,
    values: dict[str, object],
    *,
    name: str = "example",
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values=values,
        unknown_values=unknown_values or {},
    )


class AzureNetworkNormalizerTests(unittest.TestCase):
    def test_network_normalizers_are_grouped_by_domain(self) -> None:
        azure_provider_root = SOURCE_ROOT / "providers" / "azure"
        normalizers_package = azure_provider_root / "network_normalizers"
        required_modules = {
            "core",
            "vnet_nsg",
            "public_edge",
            "private_endpoint_dns",
            "flow_logs",
        }

        self.assertFalse((azure_provider_root / "network_normalizers.py").exists())
        self.assertTrue(normalizers_package.is_dir())
        self.assertTrue(
            required_modules <= {path.stem for path in normalizers_package.glob("*.py")},
        )

    def test_virtual_network_and_subnet_normalize_graph_references(self) -> None:
        virtual_network = normalize_virtual_network(
            _resource(
                AzureResourceType.VIRTUAL_NETWORK,
                {"id": "/subscriptions/example/virtualNetworks/main", "name": "main", "address_space": ["10.0.0.0/16"]},
                name="main",
            )
        )
        subnet = normalize_subnet(
            _resource(
                AzureResourceType.SUBNET,
                {
                    "id": "/subscriptions/example/subnets/app",
                    "name": "app",
                    "virtual_network_name": "azurerm_virtual_network.main.name",
                    "address_prefixes": ["10.0.1.0/24"],
                },
                name="app",
            )
        )

        self.assertEqual(virtual_network.category, ResourceCategory.NETWORK)
        self.assertEqual(azure_facts(virtual_network).name, "main")
        self.assertEqual(azure_facts(subnet).virtual_network_reference, "azurerm_virtual_network.main.name")
        self.assertEqual(subnet.vpc_id, "azurerm_virtual_network.main.name")

    def test_network_security_group_preserves_allow_and_deny_records(self) -> None:
        network_security_group = normalize_network_security_group(
            _resource(
                AzureResourceType.NETWORK_SECURITY_GROUP,
                {
                    "name": "web",
                    "security_rule": [
                        {
                            "name": "allow-web",
                            "priority": 200,
                            "direction": "Inbound",
                            "access": "Allow",
                            "protocol": "Tcp",
                            "source_address_prefix": "*",
                            "destination_port_range": "443",
                        },
                        {
                            "name": "deny-ssh",
                            "priority": 100,
                            "direction": "Inbound",
                            "access": "Deny",
                            "protocol": "Tcp",
                            "source_address_prefix": "*",
                            "destination_port_range": "22",
                        },
                    ],
                },
                name="web",
            )
        )

        self.assertEqual(len(network_security_group.network_rules), 1)
        self.assertTrue(network_security_group.network_rules[0].allows_internet())
        self.assertEqual(
            [record["access"] for record in azure_facts(network_security_group).network_security_rules],
            ["allow", "deny"],
        )

    def test_standalone_rule_and_associations_normalize_references(self) -> None:
        rule = normalize_network_security_rule(
            _resource(
                AzureResourceType.NETWORK_SECURITY_RULE,
                {
                    "name": "allow-web",
                    "network_security_group_name": "azurerm_network_security_group.web.name",
                    "priority": 200,
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "source_address_prefix": "Internet",
                    "destination_port_range": "80",
                },
                name="allow_web",
            )
        )
        subnet_association = normalize_subnet_network_security_group_association(
            _resource(
                AzureResourceType.SUBNET_NETWORK_SECURITY_GROUP_ASSOCIATION,
                {
                    "subnet_id": "azurerm_subnet.app.id",
                    "network_security_group_id": "azurerm_network_security_group.web.id",
                },
            )
        )
        nic_association = normalize_network_interface_security_group_association(
            _resource(
                AzureResourceType.NETWORK_INTERFACE_SECURITY_GROUP_ASSOCIATION,
                {
                    "network_interface_id": "azurerm_network_interface.web.id",
                    "network_security_group_id": "azurerm_network_security_group.web.id",
                },
            )
        )

        self.assertEqual(azure_facts(rule).network_security_group_reference, "azurerm_network_security_group.web.name")
        self.assertEqual(azure_facts(subnet_association).subnet_reference, "azurerm_subnet.app.id")
        self.assertEqual(azure_facts(nic_association).network_interface_reference, "azurerm_network_interface.web.id")

    def test_network_watcher_flow_log_normalizes_enabled_telemetry_posture(self) -> None:
        flow_log = normalize_network_watcher_flow_log(
            _resource(
                AzureResourceType.NETWORK_WATCHER_FLOW_LOG,
                {
                    "id": "/subscriptions/example/networkWatchers/watcher/flowLogs/app-nsg",
                    "name": "app-nsg",
                    "location": "eastus",
                    "network_watcher_name": "watcher",
                    "resource_group_name": "rg-network",
                    "network_security_group_id": "azurerm_network_security_group.app.id",
                    "storage_account_id": "azurerm_storage_account.flow_logs.id",
                    "enabled": True,
                    "version": 2,
                    "retention_policy": [{"enabled": True, "days": 30}],
                    "traffic_analytics": [
                        {
                            "enabled": True,
                            "workspace_id": "workspace-guid",
                            "workspace_region": "eastus",
                            "workspace_resource_id": "azurerm_log_analytics_workspace.security.id",
                            "interval_in_minutes": 10,
                        }
                    ],
                },
                name="app",
            )
        )
        facts = azure_facts(flow_log)

        self.assertEqual(flow_log.category, ResourceCategory.NETWORK)
        self.assertEqual(flow_log.identifier, "/subscriptions/example/networkWatchers/watcher/flowLogs/app-nsg")
        self.assertEqual(flow_log.security_group_ids, ("azurerm_network_security_group.app.id",))
        self.assertEqual(facts.network_flow_log_id, "/subscriptions/example/networkWatchers/watcher/flowLogs/app-nsg")
        self.assertEqual(facts.network_flow_log_name, "app-nsg")
        self.assertEqual(facts.network_flow_log_state, "enabled")
        self.assertEqual(facts.network_flow_log_target_resource_id, "azurerm_network_security_group.app.id")
        self.assertEqual(
            facts.network_flow_log_network_security_group_id,
            "azurerm_network_security_group.app.id",
        )
        self.assertEqual(facts.network_flow_log_storage_account_id, "azurerm_storage_account.flow_logs.id")
        self.assertEqual(facts.network_flow_log_network_watcher_name, "watcher")
        self.assertEqual(facts.network_flow_log_resource_group_name, "rg-network")
        self.assertEqual(facts.network_flow_log_version, 2)
        self.assertEqual(facts.network_flow_log_retention_state, "enabled")
        self.assertEqual(facts.network_flow_log_retention_days, 30)
        self.assertEqual(facts.network_flow_log_retention_policy, {"enabled": True, "days": 30})
        self.assertEqual(facts.network_flow_log_traffic_analytics_state, "enabled")
        self.assertEqual(facts.network_flow_log_traffic_analytics_workspace_id, "workspace-guid")
        self.assertEqual(facts.network_flow_log_traffic_analytics_workspace_region, "eastus")
        self.assertEqual(
            facts.network_flow_log_traffic_analytics_workspace_resource_id,
            "azurerm_log_analytics_workspace.security.id",
        )
        self.assertEqual(facts.network_flow_log_traffic_analytics_interval_minutes, 10)
        self.assertEqual(
            facts.network_flow_log_traffic_analytics,
            {
                "enabled": True,
                "workspace_id": "workspace-guid",
                "workspace_region": "eastus",
                "workspace_resource_id": "azurerm_log_analytics_workspace.security.id",
                "interval_in_minutes": 10,
            },
        )
        self.assertEqual(facts.network_telemetry_posture_uncertainties, [])

    def test_network_watcher_flow_log_preserves_disabled_and_missing_blocks(self) -> None:
        flow_log = normalize_network_watcher_flow_log(
            _resource(
                AzureResourceType.NETWORK_WATCHER_FLOW_LOG,
                {
                    "name": "disabled",
                    "target_resource_id": "/subscriptions/example/networkSecurityGroups/app",
                    "enabled": False,
                },
                name="disabled",
            )
        )
        facts = azure_facts(flow_log)

        self.assertEqual(flow_log.identifier, "disabled")
        self.assertEqual(flow_log.security_group_ids, ("/subscriptions/example/networkSecurityGroups/app",))
        self.assertEqual(facts.network_flow_log_state, "disabled")
        self.assertEqual(facts.network_flow_log_target_resource_id, "/subscriptions/example/networkSecurityGroups/app")
        self.assertEqual(facts.network_flow_log_network_security_group_id, None)
        self.assertEqual(facts.network_flow_log_retention_state, "not_configured")
        self.assertEqual(facts.network_flow_log_traffic_analytics_state, "not_configured")
        self.assertEqual(facts.network_telemetry_posture_uncertainties, [])

    def test_network_watcher_flow_log_preserves_unknown_values_as_uncertainty(self) -> None:
        flow_log = normalize_network_watcher_flow_log(
            _resource(
                AzureResourceType.NETWORK_WATCHER_FLOW_LOG,
                {
                    "name": "pending",
                    "retention_policy": [{}],
                    "traffic_analytics": [{}],
                },
                name="pending",
                unknown_values={
                    "id": True,
                    "enabled": True,
                    "network_security_group_id": True,
                    "storage_account_id": True,
                    "version": True,
                    "retention_policy": [{"enabled": True, "days": True}],
                    "traffic_analytics": [
                        {
                            "enabled": True,
                            "workspace_id": True,
                            "workspace_region": True,
                            "workspace_resource_id": True,
                            "interval_in_minutes": True,
                        }
                    ],
                },
            )
        )
        facts = azure_facts(flow_log)

        self.assertEqual(flow_log.identifier, "pending")
        self.assertEqual(flow_log.security_group_ids, ())
        self.assertEqual(facts.network_flow_log_state, "unknown")
        self.assertIsNone(facts.network_flow_log_target_resource_id)
        self.assertEqual(facts.network_flow_log_retention_state, "unknown")
        self.assertEqual(
            facts.network_flow_log_retention_policy,
            {"unknown_fields": ["enabled", "days"]},
        )
        self.assertEqual(facts.network_flow_log_traffic_analytics_state, "unknown")
        self.assertEqual(
            facts.network_flow_log_traffic_analytics,
            {
                "unknown_fields": [
                    "enabled",
                    "workspace_id",
                    "workspace_region",
                    "workspace_resource_id",
                    "interval_in_minutes",
                ]
            },
        )
        self.assertEqual(
            facts.network_telemetry_posture_uncertainties,
            [
                "id is unknown after planning",
                "network_security_group_id is unknown after planning",
                "enabled is unknown after planning",
                "storage_account_id is unknown after planning",
                "version is unknown after planning",
                "retention_policy.enabled is unknown after planning",
                "retention_policy.days is unknown after planning",
                "traffic_analytics.enabled is unknown after planning",
                "traffic_analytics.workspace_id is unknown after planning",
                "traffic_analytics.workspace_region is unknown after planning",
                "traffic_analytics.workspace_resource_id is unknown after planning",
                "traffic_analytics.interval_in_minutes is unknown after planning",
            ],
        )

    def test_network_interface_and_public_ip_normalize_public_ip_relationship(self) -> None:
        network_interface = normalize_network_interface(
            _resource(
                AzureResourceType.NETWORK_INTERFACE,
                {
                    "name": "web",
                    "ip_configuration": [
                        {
                            "name": "primary",
                            "subnet_id": "azurerm_subnet.app.id",
                            "public_ip_address_id": "azurerm_public_ip.web.id",
                        }
                    ],
                },
                name="web",
            )
        )
        public_ip = normalize_public_ip(
            _resource(AzureResourceType.PUBLIC_IP, {"name": "web", "ip_address": "203.0.113.10"}, name="web")
        )

        self.assertEqual(network_interface.subnet_ids, ("azurerm_subnet.app.id",))
        self.assertEqual(azure_facts(network_interface).public_ip_references, ["azurerm_public_ip.web.id"])
        self.assertTrue(network_interface.public_access_configured)
        self.assertEqual(public_ip.category, ResourceCategory.EDGE)
        self.assertEqual(azure_facts(public_ip).public_ip_address, "203.0.113.10")

    def test_load_balancer_normalizes_public_frontend_exposure(self) -> None:
        load_balancer = normalize_load_balancer(
            _resource(
                AzureResourceType.LOAD_BALANCER,
                {
                    "id": "/subscriptions/example/loadBalancers/public-web",
                    "name": "public-web",
                    "location": "eastus",
                    "sku": "Standard",
                    "frontend_ip_configuration": [
                        {
                            "name": "public",
                            "public_ip_address_id": "azurerm_public_ip.web.id",
                        }
                    ],
                },
                name="public_web",
            )
        )
        facts = azure_facts(load_balancer)

        self.assertEqual(load_balancer.category, ResourceCategory.NETWORK)
        self.assertTrue(load_balancer.public_access_configured)
        self.assertEqual(facts.load_balancer_id, "/subscriptions/example/loadBalancers/public-web")
        self.assertEqual(facts.load_balancer_sku, "Standard")
        self.assertEqual(facts.load_balancer_exposure_state, "public")
        self.assertEqual(facts.load_balancer_public_ip_references, ["azurerm_public_ip.web.id"])
        self.assertEqual(
            facts.load_balancer_frontends,
            [{"name": "public", "public_ip_address_id": "azurerm_public_ip.web.id"}],
        )

    def test_load_balancer_normalizes_private_frontend_exposure(self) -> None:
        load_balancer = normalize_load_balancer(
            _resource(
                AzureResourceType.LOAD_BALANCER,
                {
                    "name": "internal-web",
                    "sku": [{"name": "Standard"}],
                    "frontend_ip_configuration": [
                        {
                            "name": "private",
                            "subnet_id": "azurerm_subnet.app.id",
                            "private_ip_address": "10.0.1.20",
                        }
                    ],
                },
                name="internal_web",
            )
        )
        facts = azure_facts(load_balancer)

        self.assertFalse(load_balancer.public_access_configured)
        self.assertEqual(load_balancer.subnet_ids, ("azurerm_subnet.app.id",))
        self.assertEqual(facts.load_balancer_exposure_state, "private")
        self.assertEqual(facts.load_balancer_subnet_references, ["azurerm_subnet.app.id"])
        self.assertEqual(facts.load_balancer_private_ip_addresses, ["10.0.1.20"])

    def test_load_balancer_preserves_unknown_frontend_values(self) -> None:
        load_balancer = normalize_load_balancer(
            _resource(
                AzureResourceType.LOAD_BALANCER,
                {
                    "name": "pending",
                    "frontend_ip_configuration": [{"name": "pending"}],
                },
                name="pending",
                unknown_values={
                    "id": True,
                    "frontend_ip_configuration": [{"public_ip_address_id": True}],
                },
            )
        )
        facts = azure_facts(load_balancer)

        self.assertFalse(load_balancer.public_access_configured)
        self.assertEqual(facts.load_balancer_exposure_state, "unknown")
        self.assertEqual(
            facts.load_balancer_posture_uncertainties,
            [
                "id is unknown after planning",
                "frontend_ip_configuration[0].public_ip_address_id is unknown after planning",
            ],
        )
        self.assertEqual(
            facts.load_balancer_frontends, [{"name": "pending", "unknown_fields": ["public_ip_address_id"]}]
        )

    def test_application_gateway_normalizes_public_frontend_and_listener_evidence(self) -> None:
        gateway = normalize_application_gateway(
            _resource(
                AzureResourceType.APPLICATION_GATEWAY,
                {
                    "id": "/subscriptions/example/applicationGateways/web",
                    "name": "web",
                    "sku": [{"name": "WAF_v2", "tier": "WAF_v2"}],
                    "frontend_ip_configuration": [
                        {
                            "name": "public",
                            "public_ip_address_id": "azurerm_public_ip.gateway.id",
                        }
                    ],
                    "http_listener": [
                        {
                            "name": "https",
                            "frontend_ip_configuration_name": "public",
                            "frontend_port_name": "https",
                            "protocol": "Https",
                            "host_names": ["app.example.com"],
                        }
                    ],
                    "request_routing_rule": [
                        {
                            "name": "default",
                            "rule_type": "Basic",
                            "http_listener_name": "https",
                            "backend_address_pool_name": "app",
                            "backend_http_settings_name": "https",
                            "priority": 100,
                        }
                    ],
                },
                name="web",
            )
        )
        facts = azure_facts(gateway)

        self.assertTrue(gateway.public_access_configured)
        self.assertEqual(facts.application_gateway_id, "/subscriptions/example/applicationGateways/web")
        self.assertEqual(facts.application_gateway_sku, "WAF_v2")
        self.assertEqual(facts.application_gateway_exposure_state, "public")
        self.assertEqual(facts.application_gateway_public_ip_references, ["azurerm_public_ip.gateway.id"])
        self.assertEqual(
            facts.application_gateway_http_listeners,
            [
                {
                    "name": "https",
                    "frontend_ip_configuration_name": "public",
                    "frontend_port_name": "https",
                    "protocol": "Https",
                    "host_names": ["app.example.com"],
                }
            ],
        )
        self.assertEqual(facts.application_gateway_routing_rules[0]["priority"], "100")
        self.assertEqual(facts.application_gateway_edge_protection_state, "not_configured")
        self.assertEqual(facts.application_gateway_waf_enabled_state, "not_configured")
        self.assertEqual(facts.application_gateway_waf_configurations, [])

    def test_application_gateway_normalizes_waf_policy_and_configuration(self) -> None:
        gateway = normalize_application_gateway(
            _resource(
                AzureResourceType.APPLICATION_GATEWAY,
                {
                    "id": "/subscriptions/example/applicationGateways/web",
                    "name": "web",
                    "sku": [{"name": "WAF_v2", "tier": "WAF_v2"}],
                    "firewall_policy_id": "/subscriptions/example/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/web",
                    "waf_configuration": [
                        {
                            "enabled": True,
                            "firewall_mode": "Prevention",
                            "rule_set_type": "OWASP",
                            "rule_set_version": "3.2",
                            "disabled_rule_group": [
                                {
                                    "rule_group_name": "REQUEST-920-PROTOCOL-ENFORCEMENT",
                                    "rules": [920300],
                                }
                            ],
                            "exclusion": [
                                {
                                    "match_variable": "RequestHeaderNames",
                                    "selector": "x-test",
                                    "selector_match_operator": "Equals",
                                }
                            ],
                        }
                    ],
                },
                name="web",
            )
        )
        facts = azure_facts(gateway)

        self.assertEqual(facts.application_gateway_edge_protection_state, "configured")
        self.assertEqual(
            facts.application_gateway_firewall_policy_id,
            "/subscriptions/example/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/web",
        )
        self.assertEqual(facts.application_gateway_waf_enabled_state, "enabled")
        self.assertEqual(facts.application_gateway_waf_mode, "Prevention")
        self.assertEqual(facts.application_gateway_waf_rule_set_type, "OWASP")
        self.assertEqual(facts.application_gateway_waf_rule_set_version, "3.2")
        self.assertEqual(
            facts.application_gateway_waf_configurations,
            [
                {
                    "enabled": True,
                    "enabled_state": "enabled",
                    "firewall_mode": "Prevention",
                    "rule_set_type": "OWASP",
                    "rule_set_version": "3.2",
                    "disabled_rule_group": [{"rule_group_name": "REQUEST-920-PROTOCOL-ENFORCEMENT", "rules": [920300]}],
                    "exclusion": [
                        {
                            "match_variable": "RequestHeaderNames",
                            "selector": "x-test",
                            "selector_match_operator": "Equals",
                        }
                    ],
                }
            ],
        )

    def test_application_gateway_normalizes_disabled_waf_configuration(self) -> None:
        gateway = normalize_application_gateway(
            _resource(
                AzureResourceType.APPLICATION_GATEWAY,
                {
                    "name": "web",
                    "waf_configuration": [
                        {
                            "enabled": False,
                            "firewall_mode": "Detection",
                            "rule_set_type": "OWASP",
                            "rule_set_version": "3.1",
                        }
                    ],
                },
                name="web",
            )
        )
        facts = azure_facts(gateway)

        self.assertEqual(facts.application_gateway_edge_protection_state, "disabled")
        self.assertEqual(facts.application_gateway_waf_enabled_state, "disabled")
        self.assertEqual(facts.application_gateway_waf_mode, "Detection")
        self.assertEqual(facts.application_gateway_edge_protection_uncertainties, [])

    def test_application_gateway_preserves_unknown_edge_protection_values(self) -> None:
        gateway = normalize_application_gateway(
            _resource(
                AzureResourceType.APPLICATION_GATEWAY,
                {"name": "pending"},
                name="pending",
                unknown_values={"firewall_policy_id": True, "waf_configuration": True},
            )
        )
        facts = azure_facts(gateway)

        self.assertEqual(facts.application_gateway_edge_protection_state, "unknown")
        self.assertEqual(facts.application_gateway_waf_enabled_state, "unknown")
        self.assertEqual(facts.application_gateway_waf_configurations, [])
        self.assertEqual(
            facts.application_gateway_edge_protection_uncertainties,
            [
                "firewall_policy_id is unknown after planning",
                "waf_configuration is unknown after planning",
            ],
        )
        self.assertEqual(
            facts.application_gateway_posture_uncertainties,
            [
                "firewall_policy_id is unknown after planning",
                "waf_configuration is unknown after planning",
            ],
        )

    def test_application_gateway_normalizes_private_frontend_exposure(self) -> None:
        gateway = normalize_application_gateway(
            _resource(
                AzureResourceType.APPLICATION_GATEWAY,
                {
                    "name": "internal",
                    "frontend_ip_configuration": [
                        {
                            "name": "private",
                            "subnet_id": "azurerm_subnet.gateway.id",
                            "private_ip_address": "10.0.2.10",
                        }
                    ],
                },
                name="internal",
            )
        )
        facts = azure_facts(gateway)

        self.assertFalse(gateway.public_access_configured)
        self.assertEqual(gateway.subnet_ids, ("azurerm_subnet.gateway.id",))
        self.assertEqual(facts.application_gateway_exposure_state, "private")
        self.assertEqual(facts.application_gateway_subnet_references, ["azurerm_subnet.gateway.id"])
        self.assertEqual(facts.application_gateway_private_ip_addresses, ["10.0.2.10"])

    def test_private_dns_zone_normalizes_zone_identity(self) -> None:
        zone = normalize_private_dns_zone(
            _resource(
                AzureResourceType.PRIVATE_DNS_ZONE,
                {
                    "id": "/subscriptions/example/resourceGroups/dns/providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net",
                    "name": "privatelink.blob.core.windows.net",
                },
                name="blob",
            )
        )
        facts = azure_facts(zone)

        self.assertEqual(zone.category, ResourceCategory.NETWORK)
        self.assertEqual(zone.identifier, facts.private_dns_zone_id)
        self.assertEqual(facts.name, "privatelink.blob.core.windows.net")
        self.assertEqual(
            facts.private_dns_zone_id,
            "/subscriptions/example/resourceGroups/dns/providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net",
        )

    def test_private_dns_zone_virtual_network_link_normalizes_references_and_unknowns(self) -> None:
        link = normalize_private_dns_zone_virtual_network_link(
            _resource(
                AzureResourceType.PRIVATE_DNS_ZONE_VIRTUAL_NETWORK_LINK,
                {
                    "id": "/subscriptions/example/privateDnsZoneLinks/blob-main",
                    "name": "blob-main",
                    "private_dns_zone_name": "azurerm_private_dns_zone.blob.name",
                    "virtual_network_id": "azurerm_virtual_network.main.id",
                    "registration_enabled": True,
                },
                name="blob_main",
            )
        )
        unknown_link = normalize_private_dns_zone_virtual_network_link(
            _resource(
                AzureResourceType.PRIVATE_DNS_ZONE_VIRTUAL_NETWORK_LINK,
                {
                    "name": "pending",
                    "registration_enabled": None,
                },
                name="pending",
                unknown_values={
                    "id": True,
                    "private_dns_zone_name": True,
                    "virtual_network_id": True,
                    "registration_enabled": True,
                },
            )
        )
        facts = azure_facts(link)
        unknown_facts = azure_facts(unknown_link)

        self.assertEqual(link.vpc_id, "azurerm_virtual_network.main.id")
        self.assertEqual(
            facts.private_dns_zone_virtual_network_link_id, "/subscriptions/example/privateDnsZoneLinks/blob-main"
        )
        self.assertEqual(facts.private_dns_zone_reference, "azurerm_private_dns_zone.blob.name")
        self.assertEqual(facts.private_dns_zone_virtual_network_reference, "azurerm_virtual_network.main.id")
        self.assertEqual(facts.private_dns_zone_registration_state, "enabled")
        self.assertEqual(unknown_facts.private_dns_zone_registration_state, "unknown")
        self.assertEqual(
            unknown_facts.private_dns_zone_uncertainties,
            [
                "id is unknown after planning",
                "private_dns_zone_name is unknown after planning",
                "virtual_network_id is unknown after planning",
                "registration_enabled is unknown after planning",
            ],
        )


if __name__ == "__main__":
    unittest.main()
