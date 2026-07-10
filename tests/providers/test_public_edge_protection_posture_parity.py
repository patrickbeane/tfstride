from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_edge_protection_rules import _MISSING as AWS_MISSING
from tests.providers.aws.test_aws_edge_protection_rules import _RULE_ID as AWS_EDGE_PROTECTION_RULE
from tests.providers.aws.test_aws_edge_protection_rules import _findings as _aws_findings
from tests.providers.aws.test_aws_edge_protection_rules import _load_balancer as _aws_load_balancer
from tests.providers.aws.test_aws_edge_protection_rules import _web_acl_association as _aws_web_acl_association
from tests.providers.azure.test_azure_load_balancer_rules import _application_gateway as _azure_application_gateway
from tests.providers.azure.test_azure_load_balancer_rules import _evaluate as _azure_findings
from tests.providers.gcp.test_gcp_compute_rules import _GCP_EDGE_PROTECTION_RULE as GCP_EDGE_PROTECTION_RULE
from tests.providers.gcp.test_gcp_compute_rules import _backend_service as _gcp_backend_service
from tests.providers.gcp.test_gcp_compute_rules import _findings as _gcp_findings
from tests.providers.gcp.test_gcp_compute_rules import _public_forwarding_rule as _gcp_forwarding_rule
from tests.providers.gcp.test_gcp_compute_rules import _target_https_proxy as _gcp_target_https_proxy
from tests.providers.gcp.test_gcp_compute_rules import _url_map as _gcp_url_map
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

AZURE_EDGE_PROTECTION_RULE = "azure-public-application-gateway-waf-missing"


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for rule_group in rule_groups for rule_id in rule_group)


def _rule_ids(findings) -> frozenset[str]:
    return frozenset(finding.rule_id for finding in findings)


def _public_application_gateway(**overrides) -> object:
    values = {
        "frontend": {
            "name": "public",
            "public_ip_address_id": "azurerm_public_ip.gateway.id",
        },
        "listeners": [
            {
                "name": "https",
                "frontend_ip_configuration_name": "public",
                "frontend_port_name": "https",
                "protocol": "Https",
                "host_names": ["app.example.com"],
            }
        ],
        "routing_rules": [
            {
                "name": "default",
                "rule_type": "Basic",
                "http_listener_name": "https",
                "backend_address_pool_name": "app",
                "backend_http_settings_name": "https",
                "priority": 100,
            }
        ],
    }
    values.update(overrides)
    return _azure_application_gateway(**values)


class PublicEdgeProtectionPostureParityTests(unittest.TestCase):
    def test_public_edge_protection_rule_families_are_registered(self) -> None:
        self.assertIn(AWS_EDGE_PROTECTION_RULE, _flatten(AWS_RULE_GROUP_IDS))
        self.assertIn(GCP_EDGE_PROTECTION_RULE, _flatten(GCP_RULE_GROUP_IDS))
        self.assertIn(AZURE_EDGE_PROTECTION_RULE, _flatten(AZURE_RULE_GROUP_IDS))

    def test_missing_public_edge_protection_findings_are_pinned(self) -> None:
        aws_findings = _aws_findings([_aws_load_balancer()])
        gcp_findings = _gcp_findings(
            [_gcp_forwarding_rule(), _gcp_target_https_proxy(), _gcp_url_map(), _gcp_backend_service()],
            GCP_EDGE_PROTECTION_RULE,
        )
        azure_findings = _azure_findings(
            [_public_application_gateway()],
            AZURE_EDGE_PROTECTION_RULE,
        )

        self.assertEqual(_rule_ids(aws_findings), frozenset({AWS_EDGE_PROTECTION_RULE}))
        self.assertEqual(_rule_ids(gcp_findings), frozenset({GCP_EDGE_PROTECTION_RULE}))
        self.assertEqual(_rule_ids(azure_findings), frozenset({AZURE_EDGE_PROTECTION_RULE}))

    def test_configured_public_edge_protection_is_quiet_across_providers(self) -> None:
        aws_findings = _aws_findings([_aws_load_balancer(), _aws_web_acl_association()])
        gcp_findings = _gcp_findings(
            [
                _gcp_forwarding_rule(),
                _gcp_target_https_proxy(),
                _gcp_url_map(),
                _gcp_backend_service(security_policy="google_compute_security_policy.edge.id"),
            ],
            GCP_EDGE_PROTECTION_RULE,
        )
        azure_policy_findings = _azure_findings(
            [
                _public_application_gateway(
                    firewall_policy_id=(
                        "/subscriptions/example/providers/Microsoft.Network/"
                        "ApplicationGatewayWebApplicationFirewallPolicies/web"
                    )
                )
            ],
            AZURE_EDGE_PROTECTION_RULE,
        )
        azure_waf_config_findings = _azure_findings(
            [
                _public_application_gateway(
                    waf_configuration=[
                        {
                            "enabled": True,
                            "firewall_mode": "Prevention",
                            "rule_set_type": "OWASP",
                            "rule_set_version": "3.2",
                        }
                    ]
                )
            ],
            AZURE_EDGE_PROTECTION_RULE,
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_findings, [])
        self.assertEqual(azure_policy_findings, [])
        self.assertEqual(azure_waf_config_findings, [])

    def test_unknown_public_edge_protection_state_is_not_reported_as_missing(self) -> None:
        aws_findings = _aws_findings(
            [
                _aws_load_balancer(),
                _aws_web_acl_association(
                    resource_arn=AWS_MISSING,
                    unknown_values={"resource_arn": True},
                ),
            ]
        )
        gcp_findings = _gcp_findings(
            [
                _gcp_forwarding_rule(),
                _gcp_target_https_proxy(),
                _gcp_url_map(),
                _gcp_backend_service(unknown_values={"security_policy": True}),
            ],
            GCP_EDGE_PROTECTION_RULE,
        )
        azure_findings = _azure_findings(
            [_public_application_gateway(unknown_values={"firewall_policy_id": True, "waf_configuration": True})],
            AZURE_EDGE_PROTECTION_RULE,
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_findings, [])
        self.assertEqual(azure_findings, [])


if __name__ == "__main__":
    unittest.main()
