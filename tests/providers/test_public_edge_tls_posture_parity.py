from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_load_balancer_rules import (
    _ALL_RULE_IDS as AWS_LOAD_BALANCER_TLS_RULE_IDS,
)
from tests.providers.aws.test_aws_load_balancer_rules import (
    _CERTIFICATE_RULE as AWS_CERTIFICATE_RULE,
)
from tests.providers.aws.test_aws_load_balancer_rules import (
    _HTTP_RULE as AWS_HTTP_RULE,
)
from tests.providers.aws.test_aws_load_balancer_rules import (
    _MISSING as AWS_MISSING,
)
from tests.providers.aws.test_aws_load_balancer_rules import (
    _SSL_POLICY_RULE as AWS_SSL_POLICY_RULE,
)
from tests.providers.aws.test_aws_load_balancer_rules import (
    _findings as _aws_findings,
)
from tests.providers.aws.test_aws_load_balancer_rules import (
    _listener as _aws_listener,
)
from tests.providers.aws.test_aws_load_balancer_rules import (
    _load_balancer as _aws_load_balancer,
)
from tests.providers.azure.test_azure_app_service_rules import (
    _app as _azure_app,
)
from tests.providers.azure.test_azure_app_service_rules import (
    _evaluate as _azure_app_findings,
)
from tests.providers.azure.test_azure_app_service_rules import (
    _system_identity as _azure_system_identity,
)
from tests.providers.azure.test_azure_load_balancer_rules import (
    _application_gateway as _azure_application_gateway,
)
from tests.providers.azure.test_azure_load_balancer_rules import (
    _evaluate as _azure_network_findings,
)
from tests.providers.gcp.test_gcp_compute_rules import (
    _GCP_HTTP_LB_RULE as GCP_HTTP_RULE,
)
from tests.providers.gcp.test_gcp_compute_rules import (
    _GCP_SSL_POLICY_RULE as GCP_SSL_POLICY_RULE,
)
from tests.providers.gcp.test_gcp_compute_rules import (
    _findings as _gcp_findings,
)
from tests.providers.gcp.test_gcp_compute_rules import (
    _public_forwarding_rule as _gcp_forwarding_rule,
)
from tests.providers.gcp.test_gcp_compute_rules import (
    _ssl_policy as _gcp_ssl_policy,
)
from tests.providers.gcp.test_gcp_compute_rules import (
    _target_http_proxy as _gcp_target_http_proxy,
)
from tests.providers.gcp.test_gcp_compute_rules import (
    _target_https_proxy as _gcp_target_https_proxy,
)
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

AZURE_APP_SERVICE_TLS_RULE_IDS = (
    "azure-app-service-minimum-tls-below-1-2",
    "azure-app-service-minimum-tls-unknown",
)
AZURE_APPLICATION_GATEWAY_RULE = "azure-application-gateway-public-listener"
AZURE_PUBLIC_EDGE_TLS_RULE_IDS = (*AZURE_APP_SERVICE_TLS_RULE_IDS, AZURE_APPLICATION_GATEWAY_RULE)
GCP_LOAD_BALANCER_TLS_RULE_IDS = (GCP_HTTP_RULE, GCP_SSL_POLICY_RULE)


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for rule_group in rule_groups for rule_id in rule_group)


def _rule_ids(findings) -> frozenset[str]:
    return frozenset(finding.rule_id for finding in findings)


def _public_application_gateway() -> object:
    return _azure_application_gateway(
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


def _private_application_gateway() -> object:
    return _azure_application_gateway(
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
                "frontend_port_name": "https",
                "protocol": "Https",
                "host_names": ["app.internal.example.com"],
            }
        ],
    )


class PublicEdgeTlsPostureParityTests(unittest.TestCase):
    def test_public_edge_tls_rule_families_are_registered(self) -> None:
        self.assertLessEqual(frozenset(AWS_LOAD_BALANCER_TLS_RULE_IDS), _flatten(AWS_RULE_GROUP_IDS))
        self.assertLessEqual(frozenset(GCP_LOAD_BALANCER_TLS_RULE_IDS), _flatten(GCP_RULE_GROUP_IDS))
        self.assertLessEqual(frozenset(AZURE_PUBLIC_EDGE_TLS_RULE_IDS), _flatten(AZURE_RULE_GROUP_IDS))

    def test_public_plaintext_or_public_edge_findings_are_pinned(self) -> None:
        aws_findings = _aws_findings(
            [_aws_load_balancer(), _aws_listener(protocol="HTTP", certificate_arn=AWS_MISSING, ssl_policy=AWS_MISSING)],
            AWS_HTTP_RULE,
        )
        gcp_findings = _gcp_findings(
            [
                _gcp_forwarding_rule(target="google_compute_target_http_proxy.web.id", ports=["80"]),
                _gcp_target_http_proxy(),
            ],
            GCP_HTTP_RULE,
        )
        azure_findings = _azure_network_findings(
            [_public_application_gateway()],
            AZURE_APPLICATION_GATEWAY_RULE,
        )

        self.assertEqual(_rule_ids(aws_findings), frozenset({AWS_HTTP_RULE}))
        self.assertEqual(_rule_ids(gcp_findings), frozenset({GCP_HTTP_RULE}))
        self.assertEqual(_rule_ids(azure_findings), frozenset({AZURE_APPLICATION_GATEWAY_RULE}))

    def test_public_edge_tls_control_findings_are_pinned(self) -> None:
        aws_findings = _aws_findings(
            [
                _aws_load_balancer(),
                _aws_listener(
                    protocol="HTTPS",
                    certificate_arn=AWS_MISSING,
                    ssl_policy="ELBSecurityPolicy-2016-08",
                ),
            ],
            AWS_CERTIFICATE_RULE,
            AWS_SSL_POLICY_RULE,
        )
        gcp_missing_policy_findings = _gcp_findings(
            [_gcp_forwarding_rule(), _gcp_target_https_proxy(ssl_policy=None)],
            GCP_SSL_POLICY_RULE,
        )
        gcp_weak_policy_findings = _gcp_findings(
            [_gcp_forwarding_rule(), _gcp_target_https_proxy(), _gcp_ssl_policy(min_tls_version="TLS_1_0")],
            GCP_SSL_POLICY_RULE,
        )
        azure_findings = _azure_app_findings(
            [_azure_app(public_network=True, tls_version="1.0", identity=_azure_system_identity())],
            *AZURE_APP_SERVICE_TLS_RULE_IDS,
        )

        self.assertEqual(_rule_ids(aws_findings), frozenset({AWS_CERTIFICATE_RULE, AWS_SSL_POLICY_RULE}))
        self.assertEqual(_rule_ids(gcp_missing_policy_findings), frozenset({GCP_SSL_POLICY_RULE}))
        self.assertEqual(_rule_ids(gcp_weak_policy_findings), frozenset({GCP_SSL_POLICY_RULE}))
        self.assertEqual(_rule_ids(azure_findings), frozenset({"azure-app-service-minimum-tls-below-1-2"}))

    def test_public_edge_tls_safe_posture_is_quiet(self) -> None:
        aws_findings = _aws_findings([_aws_load_balancer(), _aws_listener()], *AWS_LOAD_BALANCER_TLS_RULE_IDS)
        gcp_findings = _gcp_findings(
            [_gcp_forwarding_rule(), _gcp_target_https_proxy(), _gcp_ssl_policy(min_tls_version="TLS_1_2")],
            *GCP_LOAD_BALANCER_TLS_RULE_IDS,
        )
        azure_app_findings = _azure_app_findings(
            [_azure_app(public_network=True, tls_version="1.2", identity=_azure_system_identity())],
            *AZURE_APP_SERVICE_TLS_RULE_IDS,
        )
        azure_gateway_findings = _azure_network_findings(
            [_private_application_gateway()],
            AZURE_APPLICATION_GATEWAY_RULE,
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_findings, [])
        self.assertEqual(azure_app_findings, [])
        self.assertEqual(azure_gateway_findings, [])


if __name__ == "__main__":
    unittest.main()
