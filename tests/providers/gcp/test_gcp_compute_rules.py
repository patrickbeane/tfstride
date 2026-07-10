from __future__ import annotations

import unittest

from tests.providers.gcp.rule_support.common import (
    _load_balancer_fronted_metadata,
    _normalized_gcp_resource,
    _org_policy_policy,
)
from tests.providers.gcp.rule_support.compute import (
    _compute_instance,
    _compute_network,
    _compute_subnetwork,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import (
    ResourceCategory,
    ResourceInventory,
    SecurityGroupRule,
    TerraformResource,
)
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_decorator import GcpResourceDecorator

_GCP_HTTP_LB_RULE = "gcp-load-balancer-http-public-proxy"
_GCP_SSL_POLICY_RULE = "gcp-load-balancer-ssl-policy-missing-or-weak"
_GCP_EDGE_PROTECTION_RULE = "gcp-public-load-balancer-cloud-armor-missing"


def _gcp_resource(address: str, resource_type: str, values: dict[str, object]) -> TerraformResource:
    return TerraformResource(
        address=address,
        mode="managed",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        provider_name="registry.terraform.io/hashicorp/google",
        values=values,
    )


def _public_forwarding_rule(
    *,
    target: str = "google_compute_target_https_proxy.web.id",
    ports: list[str] | None = None,
    scheme: str = "EXTERNAL_MANAGED",
) -> TerraformResource:
    return _gcp_resource(
        "google_compute_global_forwarding_rule.web",
        "google_compute_global_forwarding_rule",
        {
            "name": "web-forwarding",
            "load_balancing_scheme": scheme,
            "ip_address": "35.1.2.3",
            "target": target,
            "ports": ports or ["443"],
        },
    )


def _target_http_proxy() -> TerraformResource:
    return _gcp_resource(
        "google_compute_target_http_proxy.web",
        "google_compute_target_http_proxy",
        {"name": "web-http-proxy", "url_map": "google_compute_url_map.web.id"},
    )


def _target_https_proxy(*, ssl_policy: str | None = "google_compute_ssl_policy.modern.id") -> TerraformResource:
    values: dict[str, object] = {
        "name": "web-https-proxy",
        "url_map": "google_compute_url_map.web.id",
        "ssl_certificates": ["google_compute_managed_ssl_certificate.web.id"],
    }
    if ssl_policy is not None:
        values["ssl_policy"] = ssl_policy
    return _gcp_resource("google_compute_target_https_proxy.web", "google_compute_target_https_proxy", values)


def _ssl_policy(*, min_tls_version: str = "TLS_1_2") -> TerraformResource:
    return _gcp_resource(
        "google_compute_ssl_policy.modern",
        "google_compute_ssl_policy",
        {"name": "modern-tls", "min_tls_version": min_tls_version, "profile": "MODERN"},
    )


def _url_map(*, default_service: str = "google_compute_backend_service.web.id") -> TerraformResource:
    return _gcp_resource(
        "google_compute_url_map.web",
        "google_compute_url_map",
        {"name": "web-url-map", "default_service": default_service},
    )


def _backend_service(
    *,
    security_policy: str | None = None,
    edge_security_policy: str | None = None,
    unknown_values: dict[str, object] | None = None,
    resource_type: str = "google_compute_backend_service",
) -> TerraformResource:
    address = f"{resource_type}.web"
    values: dict[str, object] = {
        "name": "web-backend",
        "protocol": "HTTP",
        "load_balancing_scheme": "EXTERNAL_MANAGED",
    }
    if security_policy is not None:
        values["security_policy"] = security_policy
    if edge_security_policy is not None:
        values["edge_security_policy"] = edge_security_policy
    return TerraformResource(
        address=address,
        mode="managed",
        resource_type=resource_type,
        name="web",
        provider_name="registry.terraform.io/hashicorp/google",
        values=values,
        unknown_values=unknown_values or {},
    )


def _findings(resources: list[TerraformResource], *rule_ids: str):
    inventory = GcpNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class GcpComputeRuleTests(unittest.TestCase):
    def test_public_load_balanced_workload_reports_distinct_exposure(self) -> None:
        forwarding_rule = _normalized_gcp_resource(
            "google_compute_global_forwarding_rule.web",
            "google_compute_global_forwarding_rule",
            ResourceCategory.EDGE,
            metadata={
                GcpResourceMetadata.FORWARDING_RULE_LOAD_BALANCING_SCHEME: "EXTERNAL_MANAGED",
            },
        )
        forwarding_rule.public_exposure = True
        forwarding_rule.direct_internet_reachable = True
        service = _normalized_gcp_resource(
            "google_cloud_run_v2_service.api",
            "google_cloud_run_v2_service",
            ResourceCategory.COMPUTE,
            metadata=_load_balancer_fronted_metadata(
                [
                    "google_compute_global_forwarding_rule.web",
                    "google_compute_target_https_proxy.web",
                    "google_compute_url_map.web",
                    "google_compute_backend_service.run",
                    "google_compute_region_network_endpoint_group.run",
                    "google_cloud_run_v2_service.api",
                ]
            ),
        )
        bucket = _normalized_gcp_resource(
            "google_storage_bucket.assets",
            "google_storage_bucket",
            ResourceCategory.DATA,
            data_sensitivity="sensitive",
            metadata=_load_balancer_fronted_metadata(
                [
                    "google_compute_global_forwarding_rule.web",
                    "google_compute_target_https_proxy.web",
                    "google_compute_url_map.web",
                    "google_compute_backend_bucket.assets",
                    "google_storage_bucket.assets",
                ]
            ),
        )
        inventory = ResourceInventory(provider="gcp", resources=[forwarding_rule, service, bucket])
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-load-balanced-workload"})),
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [
                "gcp-public-load-balanced-workload",
                "gcp-public-load-balanced-workload",
            ],
        )
        self.assertEqual(
            [finding.affected_resources for finding in findings],
            [
                ["google_cloud_run_v2_service.api", "google_compute_global_forwarding_rule.web"],
                ["google_storage_bucket.assets", "google_compute_global_forwarding_rule.web"],
            ],
        )
        self.assertEqual(
            findings[0].trust_boundary_id,
            "internet-to-service:internet->google_compute_global_forwarding_rule.web",
        )
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(evidence["frontend_load_balancers"], ["google_compute_global_forwarding_rule.web"])
        self.assertEqual(evidence["direct_public_exposure"], ["false"])
        self.assertIn("scheme=EXTERNAL_MANAGED", evidence["load_balancer_paths"][0])
        self.assertIn("path=google_compute_global_forwarding_rule.web ->", evidence["load_balancer_paths"][0])

    def test_public_load_balanced_workload_rule_ignores_direct_exposure_without_lb_marker(self) -> None:
        service = _normalized_gcp_resource(
            "google_cloud_run_v2_service.api",
            "google_cloud_run_v2_service",
            ResourceCategory.COMPUTE,
        )
        service.public_exposure = True
        service.direct_internet_reachable = True
        inventory = ResourceInventory(provider="gcp", resources=[service])

        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-load-balanced-workload"})),
        )

        self.assertEqual(findings, [])

    def test_public_http_load_balancer_proxy_is_detected(self) -> None:
        findings = _findings(
            [
                _public_forwarding_rule(target="google_compute_target_http_proxy.web.id", ports=["80"]),
                _target_http_proxy(),
            ],
            _GCP_HTTP_LB_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_GCP_HTTP_LB_RULE])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(
            finding.affected_resources,
            ["google_compute_global_forwarding_rule.web", "google_compute_target_http_proxy.web"],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            "internet-to-service:internet->google_compute_global_forwarding_rule.web",
        )
        evidence = _evidence_by_key(finding)
        self.assertIn("ports=80", evidence["frontend_forwarding_rule"])
        self.assertIn("target=google_compute_target_http_proxy.web.id", evidence["frontend_forwarding_rule"])
        self.assertEqual(
            evidence["proxy_transport"],
            ["target_proxy_type=google_compute_target_http_proxy", "HTTP target proxy does not terminate TLS"],
        )

    def test_internal_http_load_balancer_proxy_is_quiet(self) -> None:
        self.assertEqual(
            _findings(
                [
                    _public_forwarding_rule(
                        target="google_compute_target_http_proxy.web.id",
                        ports=["80"],
                        scheme="INTERNAL_MANAGED",
                    ),
                    _target_http_proxy(),
                ],
                _GCP_HTTP_LB_RULE,
                _GCP_SSL_POLICY_RULE,
            ),
            [],
        )

    def test_public_https_proxy_without_ssl_policy_is_detected(self) -> None:
        findings = _findings(
            [_public_forwarding_rule(), _target_https_proxy(ssl_policy=None)],
            _GCP_SSL_POLICY_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_GCP_SSL_POLICY_RULE])
        self.assertEqual(
            findings[0].affected_resources,
            ["google_compute_global_forwarding_rule.web", "google_compute_target_https_proxy.web"],
        )
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["ssl_policy_posture"], ["ssl_policy_state=missing", "ssl_policy is unset"])

    def test_public_https_proxy_with_weak_ssl_policy_is_detected(self) -> None:
        findings = _findings(
            [_public_forwarding_rule(), _target_https_proxy(), _ssl_policy(min_tls_version="TLS_1_0")],
            _GCP_SSL_POLICY_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_GCP_SSL_POLICY_RULE])
        self.assertEqual(
            findings[0].affected_resources,
            [
                "google_compute_global_forwarding_rule.web",
                "google_compute_target_https_proxy.web",
                "google_compute_ssl_policy.modern",
            ],
        )
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["ssl_policy_posture"],
            [
                "ssl_policy_state=weak",
                "ssl_policy_reference=google_compute_ssl_policy.modern.id",
                "ssl_policy_resource=google_compute_ssl_policy.modern",
                "min_tls_version=TLS_1_0",
                "profile=MODERN",
            ],
        )

    def test_public_https_proxy_with_modern_or_unresolved_ssl_policy_is_quiet(self) -> None:
        self.assertEqual(
            _findings([_public_forwarding_rule(), _target_https_proxy(), _ssl_policy()], _GCP_SSL_POLICY_RULE),
            [],
        )
        self.assertEqual(
            _findings(
                [_public_forwarding_rule(), _target_https_proxy(ssl_policy="google_compute_ssl_policy.missing.id")],
                _GCP_SSL_POLICY_RULE,
            ),
            [],
        )

    def test_public_backend_service_without_cloud_armor_policy_is_detected(self) -> None:
        findings = _findings(
            [_public_forwarding_rule(), _target_https_proxy(), _url_map(), _backend_service()],
            _GCP_EDGE_PROTECTION_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_GCP_EDGE_PROTECTION_RULE])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(
            finding.affected_resources,
            ["google_compute_backend_service.web", "google_compute_global_forwarding_rule.web"],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            "internet-to-service:internet->google_compute_global_forwarding_rule.web",
        )
        evidence = _evidence_by_key(finding)
        self.assertEqual(evidence["frontend_load_balancers"], ["google_compute_global_forwarding_rule.web"])
        self.assertIn("protocol=HTTP", evidence["target_backend_service"])
        self.assertIn(
            "fronted_by_internet_facing_load_balancer=true",
            evidence["target_backend_service"],
        )
        self.assertEqual(
            evidence["edge_protection_policy"],
            [
                "edge_protection_state=missing",
                "security_policy is unset",
                "edge_security_policy is unset",
            ],
        )
        self.assertIn(
            "path=google_compute_global_forwarding_rule.web -> google_compute_target_https_proxy.web -> "
            "google_compute_url_map.web -> google_compute_backend_service.web",
            evidence["load_balancer_paths"][0],
        )

    def test_public_backend_service_with_cloud_armor_policy_is_quiet(self) -> None:
        self.assertEqual(
            _findings(
                [
                    _public_forwarding_rule(),
                    _target_https_proxy(),
                    _url_map(),
                    _backend_service(security_policy="google_compute_security_policy.edge.id"),
                ],
                _GCP_EDGE_PROTECTION_RULE,
            ),
            [],
        )

    def test_public_backend_service_with_edge_security_policy_is_quiet(self) -> None:
        self.assertEqual(
            _findings(
                [
                    _public_forwarding_rule(),
                    _target_https_proxy(),
                    _url_map(),
                    _backend_service(edge_security_policy="google_compute_security_policy.edge.self_link"),
                ],
                _GCP_EDGE_PROTECTION_RULE,
            ),
            [],
        )

    def test_unknown_cloud_armor_policy_reference_does_not_create_missing_policy_finding(self) -> None:
        self.assertEqual(
            _findings(
                [
                    _public_forwarding_rule(),
                    _target_https_proxy(),
                    _url_map(),
                    _backend_service(unknown_values={"security_policy": True}),
                ],
                _GCP_EDGE_PROTECTION_RULE,
            ),
            [],
        )

    def test_internal_backend_service_without_cloud_armor_policy_is_quiet(self) -> None:
        self.assertEqual(
            _findings(
                [
                    _public_forwarding_rule(scheme="INTERNAL_MANAGED"),
                    _target_https_proxy(),
                    _url_map(),
                    _backend_service(),
                ],
                _GCP_EDGE_PROTECTION_RULE,
            ),
            [],
        )

    def test_public_compute_ssh_and_rdp_broad_ingress_is_detected_for_each_target(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _compute_network(),
                _compute_subnetwork(),
                TerraformResource(
                    address="google_compute_firewall.admin",
                    mode="managed",
                    resource_type="google_compute_firewall",
                    name="admin",
                    provider_name="registry.terraform.io/hashicorp/google",
                    values={
                        "name": "tfstride-admin",
                        "network": "google_compute_network.main.name",
                        "direction": "INGRESS",
                        "source_ranges": ["0.0.0.0/0"],
                        "allow": [{"protocol": "tcp", "ports": ["22", "3389"]}],
                    },
                ),
                _compute_instance(),
                TerraformResource(
                    address="google_compute_instance.worker",
                    mode="managed",
                    resource_type="google_compute_instance",
                    name="worker",
                    provider_name="registry.terraform.io/hashicorp/google",
                    values={
                        "name": "tfstride-worker",
                        "machine_type": "e2-medium",
                        "zone": "us-central1-a",
                        "network_interface": [
                            {
                                "subnetwork": "google_compute_subnetwork.app.id",
                                "access_config": [{}],
                            }
                        ],
                    },
                ),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-compute-broad-ingress"})),
        )

        self.assertEqual(
            [finding.affected_resources for finding in findings],
            [
                ["google_compute_instance.web", "google_compute_firewall.admin"],
                ["google_compute_instance.worker", "google_compute_firewall.admin"],
            ],
        )
        for finding in findings:
            evidence = {item.key: item.values for item in finding.evidence}
            self.assertEqual(
                evidence["firewall_rules"],
                [
                    "google_compute_firewall.admin ingress tcp 22 from 0.0.0.0/0",
                    "google_compute_firewall.admin ingress tcp 3389 from 0.0.0.0/0",
                ],
            )

    def test_direct_network_compute_firewall_produces_public_compute_finding(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _compute_network(),
                TerraformResource(
                    address="google_compute_firewall.admin",
                    mode="managed",
                    resource_type="google_compute_firewall",
                    name="admin",
                    provider_name="registry.terraform.io/hashicorp/google",
                    values={
                        "name": "tfstride-admin",
                        "network": "google_compute_network.main.name",
                        "direction": "INGRESS",
                        "source_ranges": ["0.0.0.0/0"],
                        "target_tags": ["web"],
                        "allow": [{"protocol": "tcp", "ports": ["22"]}],
                    },
                ),
                TerraformResource(
                    address="google_compute_instance.web",
                    mode="managed",
                    resource_type="google_compute_instance",
                    name="web",
                    provider_name="registry.terraform.io/hashicorp/google",
                    values={
                        "name": "tfstride-web",
                        "tags": ["web"],
                        "network_interface": [
                            {
                                "network": "google_compute_network.main.id",
                                "access_config": [{}],
                            }
                        ],
                    },
                ),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-compute-broad-ingress"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(
            finding.affected_resources,
            ["google_compute_instance.web", "google_compute_firewall.admin"],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            "internet-to-service:internet->google_compute_instance.web",
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["internet_ingress_reasons"],
            ["google_compute_firewall.admin ingress tcp 22 from 0.0.0.0/0"],
        )
        self.assertEqual(
            evidence["public_exposure_reasons"],
            ["compute instance has an external access config and matching firewall rules allow internet ingress"],
        )

    def test_firewall_policy_project_association_produces_public_compute_finding(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _compute_network(),
                _compute_subnetwork(),
                TerraformResource(
                    address="google_compute_firewall_policy_association.project",
                    mode="managed",
                    resource_type="google_compute_firewall_policy_association",
                    name="project",
                    provider_name="registry.terraform.io/hashicorp/google",
                    values={
                        "name": "tfstride-project-policy",
                        "firewall_policy": "google_compute_firewall_policy.org.name",
                        "attachment_target": "projects/tfstride-demo",
                    },
                ),
                TerraformResource(
                    address="google_compute_firewall_policy_rule.public_admin",
                    mode="managed",
                    resource_type="google_compute_firewall_policy_rule",
                    name="public_admin",
                    provider_name="registry.terraform.io/hashicorp/google",
                    values={
                        "firewall_policy": "google_compute_firewall_policy.org.name",
                        "priority": 1000,
                        "action": "ALLOW",
                        "direction": "INGRESS",
                        "match": [
                            {
                                "src_ip_ranges": ["0.0.0.0/0"],
                                "layer4_configs": [{"ip_protocol": "tcp", "ports": ["22"]}],
                            }
                        ],
                    },
                ),
                _compute_instance(),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-compute-broad-ingress"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(
            finding.affected_resources,
            ["google_compute_instance.web", "google_compute_firewall_policy_rule.public_admin"],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            "internet-to-service:internet->google_compute_instance.web",
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["firewall_rules"],
            ["google_compute_firewall_policy_rule.public_admin ingress tcp 22 from 0.0.0.0/0"],
        )
        self.assertEqual(
            evidence["internet_ingress_reasons"],
            ["google_compute_firewall_policy_rule.public_admin ingress tcp 22 from 0.0.0.0/0"],
        )

    def test_hierarchical_firewall_policy_org_and_folder_admin_ingress_produce_findings(self) -> None:
        org_rule = _normalized_gcp_resource(
            "google_compute_firewall_policy_rule.org_admin",
            "google_compute_firewall_policy_rule",
            ResourceCategory.NETWORK,
            network_rules=[
                SecurityGroupRule(
                    direction="ingress",
                    protocol="tcp",
                    from_port=22,
                    to_port=22,
                    cidr_blocks=["0.0.0.0/0"],
                )
            ],
            metadata={
                GcpResourceMetadata.FIREWALL_POLICY_REFERENCE: "org-policy",
                GcpResourceMetadata.FIREWALL_POLICY_ACTION: "allow",
                GcpResourceMetadata.FIREWALL_POLICY_DIRECTION: "ingress",
            },
        )
        org_association = _normalized_gcp_resource(
            "google_compute_firewall_policy_association.organization",
            "google_compute_firewall_policy_association",
            ResourceCategory.NETWORK,
            metadata={
                GcpResourceMetadata.FIREWALL_POLICY_REFERENCE: "org-policy",
                GcpResourceMetadata.FIREWALL_POLICY_ATTACHMENT_TARGET: "organizations/1234567890",
            },
        )
        org_instance = _normalized_gcp_resource(
            "google_compute_instance.org_web",
            "google_compute_instance",
            ResourceCategory.COMPUTE,
            public_access_configured=True,
            metadata={GcpResourceMetadata.ORGANIZATION_ID: "1234567890"},
        )
        folder_rule = _normalized_gcp_resource(
            "google_compute_firewall_policy_rule.folder_admin",
            "google_compute_firewall_policy_rule",
            ResourceCategory.NETWORK,
            network_rules=[
                SecurityGroupRule(
                    direction="ingress",
                    protocol="tcp",
                    from_port=3389,
                    to_port=3389,
                    cidr_blocks=["0.0.0.0/0"],
                )
            ],
            metadata={
                GcpResourceMetadata.FIREWALL_POLICY_REFERENCE: "folder-policy",
                GcpResourceMetadata.FIREWALL_POLICY_ACTION: "allow",
                GcpResourceMetadata.FIREWALL_POLICY_DIRECTION: "ingress",
            },
        )
        folder_association = _normalized_gcp_resource(
            "google_compute_firewall_policy_association.folder",
            "google_compute_firewall_policy_association",
            ResourceCategory.NETWORK,
            metadata={
                GcpResourceMetadata.FIREWALL_POLICY_REFERENCE: "folder-policy",
                GcpResourceMetadata.FIREWALL_POLICY_ATTACHMENT_TARGET: "folders/12345",
            },
        )
        folder_instance = _normalized_gcp_resource(
            "google_compute_instance.folder_web",
            "google_compute_instance",
            ResourceCategory.COMPUTE,
            public_access_configured=True,
            metadata={GcpResourceMetadata.FOLDER_ID: "folders/12345"},
        )
        resources = [
            org_rule,
            org_association,
            org_instance,
            folder_rule,
            folder_association,
            folder_instance,
        ]
        GcpResourceDecorator().decorate(resources)
        inventory = ResourceInventory(provider="gcp", resources=resources)

        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-compute-broad-ingress"})),
        )

        self.assertEqual(
            [finding.affected_resources for finding in findings],
            [
                ["google_compute_instance.org_web", "google_compute_firewall_policy_rule.org_admin"],
                ["google_compute_instance.folder_web", "google_compute_firewall_policy_rule.folder_admin"],
            ],
        )
        evidence_by_instance = {finding.affected_resources[0]: finding.evidence for finding in findings}
        org_evidence = {item.key: item.values for item in evidence_by_instance["google_compute_instance.org_web"]}
        folder_evidence = {item.key: item.values for item in evidence_by_instance["google_compute_instance.folder_web"]}
        self.assertEqual(
            org_evidence["firewall_rules"],
            ["google_compute_firewall_policy_rule.org_admin ingress tcp 22 from 0.0.0.0/0"],
        )
        self.assertEqual(
            folder_evidence["firewall_rules"],
            ["google_compute_firewall_policy_rule.folder_admin ingress tcp 3389 from 0.0.0.0/0"],
        )

    def test_private_compute_broad_admin_firewall_is_still_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _compute_network(),
                _compute_subnetwork(),
                TerraformResource(
                    address="google_compute_firewall.admin",
                    mode="managed",
                    resource_type="google_compute_firewall",
                    name="admin",
                    provider_name="registry.terraform.io/hashicorp/google",
                    values={
                        "name": "tfstride-admin",
                        "network": "projects/tfstride-demo/global/networks/tfstride-main",
                        "direction": "INGRESS",
                        "source_ranges": ["0.0.0.0/0"],
                        "allow": [{"protocol": "tcp", "ports": ["22"]}],
                    },
                ),
                _compute_instance(public=False),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-compute-broad-ingress"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(
            finding.affected_resources,
            ["google_compute_instance.web", "google_compute_firewall.admin"],
        )
        self.assertIsNone(finding.trust_boundary_id)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["internet_ingress_reasons"],
            ["google_compute_firewall.admin ingress tcp 22 from 0.0.0.0/0"],
        )
        self.assertNotIn("public_exposure_reasons", evidence)

    def test_compute_os_login_disabled_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                TerraformResource(
                    address="google_compute_instance.app",
                    mode="managed",
                    resource_type="google_compute_instance",
                    name="app",
                    provider_name="registry.terraform.io/hashicorp/google",
                    values={
                        "name": "tfstride-app",
                        "metadata": {"enable-oslogin": "false"},
                    },
                )
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-compute-os-login-disabled"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-compute-os-login-disabled")
        self.assertEqual(finding.severity.value, "low")
        self.assertEqual(finding.affected_resources, ["google_compute_instance.app"])
        self.assertIsNone(finding.trust_boundary_id)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["os_login_posture"], ["metadata.enable-oslogin is false"])

    def test_compute_os_login_disabled_includes_organization_guardrail_evidence(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _org_policy_policy(
                    "google_org_policy_policy.require_os_login",
                    constraint="constraints/compute.requireOsLogin",
                    enforced=True,
                ),
                TerraformResource(
                    address="google_compute_instance.app",
                    mode="managed",
                    resource_type="google_compute_instance",
                    name="app",
                    provider_name="registry.terraform.io/hashicorp/google",
                    values={
                        "name": "tfstride-app",
                        "project": "tfstride-demo",
                        "metadata": {"enable-oslogin": "false"},
                    },
                ),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-compute-os-login-disabled"})),
        )

        finding = findings[0]
        self.assertEqual(finding.severity.value, "low")
        self.assertIsNotNone(finding.severity_reasoning)
        assert finding.severity_reasoning is not None
        self.assertEqual(finding.severity_reasoning.final_score, 0)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["organization_guardrails"],
            [
                "constraint=constraints/compute.requireOsLogin; "
                "scope=project:tfstride-demo; "
                "source=google_org_policy_policy.require_os_login; "
                "enforced=true"
            ],
        )

    def test_compute_os_login_enabled_or_unset_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                TerraformResource(
                    address="google_compute_instance.enabled",
                    mode="managed",
                    resource_type="google_compute_instance",
                    name="enabled",
                    provider_name="registry.terraform.io/hashicorp/google",
                    values={"name": "enabled", "metadata": {"enable-oslogin": "true"}},
                ),
                TerraformResource(
                    address="google_compute_instance.unset",
                    mode="managed",
                    resource_type="google_compute_instance",
                    name="unset",
                    provider_name="registry.terraform.io/hashicorp/google",
                    values={"name": "unset"},
                ),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-compute-os-login-disabled"})),
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
