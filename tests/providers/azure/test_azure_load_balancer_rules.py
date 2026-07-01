from __future__ import annotations

import unittest

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS

_LOAD_BALANCER_RULE_IDS = (
    "azure-load-balancer-public-frontend",
    "azure-application-gateway-public-listener",
)


def _resource(
    resource_type: str,
    name: str,
    values: dict[str, object],
    *,
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


def _load_balancer(
    *,
    name: str = "web",
    frontend: dict[str, object] | None = None,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "id": f"/subscriptions/example/resourceGroups/app/providers/Microsoft.Network/loadBalancers/{name}",
        "name": name,
        "location": "eastus",
        "sku": "Standard",
    }
    if frontend is not None:
        values["frontend_ip_configuration"] = [frontend]
    return _resource(AzureResourceType.LOAD_BALANCER, name, values, unknown_values=unknown_values)


def _application_gateway(
    *,
    name: str = "web",
    frontend: dict[str, object] | None = None,
    listeners: list[dict[str, object]] | None = None,
    routing_rules: list[dict[str, object]] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "id": f"/subscriptions/example/resourceGroups/app/providers/Microsoft.Network/applicationGateways/{name}",
        "name": name,
        "location": "eastus",
        "sku": [{"name": "WAF_v2", "tier": "WAF_v2"}],
    }
    if frontend is not None:
        values["frontend_ip_configuration"] = [frontend]
    if listeners is not None:
        values["http_listener"] = listeners
    if routing_rules is not None:
        values["request_routing_rule"] = routing_rules
    return _resource(AzureResourceType.APPLICATION_GATEWAY, name, values)


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = AzureNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AzureLoadBalancerRuleTests(unittest.TestCase):
    def test_public_load_balancer_frontend_emits_finding(self) -> None:
        findings = _evaluate(
            [
                _load_balancer(
                    frontend={
                        "name": "public",
                        "public_ip_address_id": "azurerm_public_ip.web.id",
                    }
                )
            ],
            "azure-load-balancer-public-frontend",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-load-balancer-public-frontend"])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["azurerm_lb.web"])
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["frontend_exposure"],
            [
                "load_balancer_exposure_state=public",
                "public_ip_address_id=azurerm_public_ip.web.id",
                "frontend public uses public_ip_address_id=azurerm_public_ip.web.id",
            ],
        )
        self.assertIn("backend reachability still depends", finding.rationale)

    def test_public_load_balancer_prefix_frontend_emits_finding(self) -> None:
        findings = _evaluate(
            [
                _load_balancer(
                    frontend={
                        "name": "public-prefix",
                        "public_ip_prefix_id": "azurerm_public_ip_prefix.edge.id",
                    }
                )
            ],
            "azure-load-balancer-public-frontend",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-load-balancer-public-frontend"])
        self.assertIn(
            "public_ip_prefix_id=azurerm_public_ip_prefix.edge.id",
            _evidence_by_key(findings[0])["frontend_exposure"],
        )

    def test_private_or_unknown_load_balancer_frontend_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _load_balancer(
                    name="internal",
                    frontend={
                        "name": "private",
                        "subnet_id": "azurerm_subnet.app.id",
                        "private_ip_address": "10.0.1.20",
                    },
                ),
                _load_balancer(
                    name="pending",
                    frontend={"name": "pending"},
                    unknown_values={"frontend_ip_configuration": [{"public_ip_address_id": True}]},
                ),
            ],
            "azure-load-balancer-public-frontend",
        )

        self.assertEqual(findings, [])

    def test_public_application_gateway_listener_emits_finding(self) -> None:
        findings = _evaluate(
            [
                _application_gateway(
                    frontend={
                        "name": "public",
                        "public_ip_address_id": "azurerm_public_ip.gateway.id",
                    },
                    listeners=[
                        {
                            "name": "https",
                            "frontend_ip_configuration_name": "public",
                            "frontend_port_name": "https",
                            "protocol": "Https",
                            "host_names": ["app.example.com"],
                        }
                    ],
                    routing_rules=[
                        {
                            "name": "default",
                            "rule_type": "Basic",
                            "http_listener_name": "https",
                            "backend_address_pool_name": "app",
                            "backend_http_settings_name": "https",
                            "priority": 100,
                        }
                    ],
                )
            ],
            "azure-application-gateway-public-listener",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-application-gateway-public-listener"])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["azurerm_application_gateway.web"])
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["frontend_exposure"],
            [
                "application_gateway_exposure_state=public",
                "public_ip_address_id=azurerm_public_ip.gateway.id",
                "frontend public uses public_ip_address_id=azurerm_public_ip.gateway.id",
            ],
        )
        self.assertEqual(
            evidence["public_listeners"],
            ["listener https uses frontend=public protocol=Https host_names=app.example.com"],
        )
        self.assertEqual(
            evidence["routing_rules"],
            ["routing_rule default type=Basic listener=https backend_pool=app"],
        )

    def test_application_gateway_requires_listener_on_public_frontend(self) -> None:
        findings = _evaluate(
            [
                _application_gateway(
                    name="public_no_listener",
                    frontend={
                        "name": "public",
                        "public_ip_address_id": "azurerm_public_ip.gateway.id",
                    },
                    listeners=[],
                ),
                _application_gateway(
                    name="private",
                    frontend={
                        "name": "private",
                        "subnet_id": "azurerm_subnet.gateway.id",
                        "private_ip_address": "10.0.2.10",
                    },
                    listeners=[
                        {
                            "name": "https",
                            "frontend_ip_configuration_name": "private",
                            "protocol": "Https",
                        }
                    ],
                ),
            ],
            "azure-application-gateway-public-listener",
        )

        self.assertEqual(findings, [])

    def test_application_gateway_listener_on_private_frontend_does_not_use_unrelated_public_frontend(self) -> None:
        findings = _evaluate(
            [
                _application_gateway(
                    frontend={
                        "name": "public",
                        "public_ip_address_id": "azurerm_public_ip.gateway.id",
                    },
                    listeners=[
                        {
                            "name": "internal",
                            "frontend_ip_configuration_name": "private",
                            "protocol": "Https",
                        }
                    ],
                )
            ],
            "azure-application-gateway-public-listener",
        )

        self.assertEqual(findings, [])

    def test_load_balancer_rule_ids_are_registered_with_azure_rule_group(self) -> None:
        registered = tuple(rule_id for group in AZURE_RULE_GROUP_IDS for rule_id in group)

        for rule_id in _LOAD_BALANCER_RULE_IDS:
            with self.subTest(rule_id=rule_id):
                self.assertIn(rule_id, registered)


if __name__ == "__main__":
    unittest.main()
