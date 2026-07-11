from __future__ import annotations

import unittest
from typing import Any

from tfstride.models import ResourceCategory, TerraformResource
from tfstride.providers.aws.network_normalizers import (
    normalize_cloudfront_distribution,
    normalize_flow_log,
    normalize_load_balancer_listener,
    normalize_vpc_endpoint,
    normalize_wafv2_web_acl,
    normalize_wafv2_web_acl_association,
)
from tfstride.providers.aws.resource_facts import aws_facts


def _terraform_resource(
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address="aws_lb_listener.https",
        mode="managed",
        resource_type="aws_lb_listener",
        name="https",
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _vpc_endpoint_resource(
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address="aws_vpc_endpoint.service",
        mode="managed",
        resource_type="aws_vpc_endpoint",
        name="service",
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _flow_log_resource(
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address="aws_flow_log.vpc",
        mode="managed",
        resource_type="aws_flow_log",
        name="vpc",
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _cloudfront_distribution_resource(
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address="aws_cloudfront_distribution.cdn",
        mode="managed",
        resource_type="aws_cloudfront_distribution",
        name="cdn",
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _wafv2_web_acl_resource(
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address="aws_wafv2_web_acl.edge",
        mode="managed",
        resource_type="aws_wafv2_web_acl",
        name="edge",
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _wafv2_web_acl_association_resource(
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address="aws_wafv2_web_acl_association.alb",
        mode="managed",
        resource_type="aws_wafv2_web_acl_association",
        name="alb",
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


class AwsNetworkNormalizerTests(unittest.TestCase):
    def test_load_balancer_listener_normalizes_tls_posture(self) -> None:
        listener_arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/web/abc/listener/443"
        target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/app/def"

        normalized = normalize_load_balancer_listener(
            _terraform_resource(
                {
                    "id": listener_arn,
                    "arn": listener_arn,
                    "load_balancer_arn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/web/abc",
                    "port": 443,
                    "protocol": "HTTPS",
                    "certificate_arn": "arn:aws:acm:us-east-1:111122223333:certificate/listener",
                    "ssl_policy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
                    "default_action": [{"type": "forward", "target_group_arn": target_group_arn}],
                }
            )
        )
        facts = aws_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.EDGE)
        self.assertEqual(normalized.identifier, listener_arn)
        self.assertEqual(normalized.arn, listener_arn)
        self.assertEqual(normalized.metadata["protocol"], "HTTPS")
        self.assertEqual(normalized.metadata["target_group_arns"], [target_group_arn])
        self.assertEqual(facts.load_balancer_listener_protocol, "HTTPS")
        self.assertEqual(
            facts.load_balancer_listener_certificate_arn,
            "arn:aws:acm:us-east-1:111122223333:certificate/listener",
        )
        self.assertEqual(facts.load_balancer_listener_ssl_policy, "ELBSecurityPolicy-TLS13-1-2-2021-06")
        self.assertEqual(facts.load_balancer_listener_tls_uncertainties, [])

    def test_load_balancer_listener_without_tls_keeps_tls_fields_absent(self) -> None:
        normalized = normalize_load_balancer_listener(
            _terraform_resource(
                {
                    "id": "listener-http",
                    "port": 80,
                    "protocol": "HTTP",
                }
            )
        )
        facts = aws_facts(normalized)

        self.assertEqual(normalized.metadata["protocol"], "HTTP")
        self.assertEqual(facts.load_balancer_listener_protocol, "HTTP")
        self.assertIsNone(facts.load_balancer_listener_certificate_arn)
        self.assertIsNone(facts.load_balancer_listener_ssl_policy)
        self.assertEqual(facts.load_balancer_listener_tls_uncertainties, [])

    def test_load_balancer_listener_preserves_unknown_tls_values(self) -> None:
        normalized = normalize_load_balancer_listener(
            _terraform_resource(
                {
                    "id": "listener-computed",
                    "port": 443,
                },
                unknown_values={
                    "protocol": True,
                    "certificate_arn": True,
                    "ssl_policy": True,
                },
            )
        )
        facts = aws_facts(normalized)

        self.assertIsNone(normalized.metadata.get("protocol"))
        self.assertIsNone(facts.load_balancer_listener_protocol)
        self.assertIsNone(facts.load_balancer_listener_certificate_arn)
        self.assertIsNone(facts.load_balancer_listener_ssl_policy)
        self.assertEqual(
            facts.load_balancer_listener_tls_uncertainties,
            [
                "protocol is unknown after planning",
                "certificate_arn is unknown after planning",
                "ssl_policy is unknown after planning",
            ],
        )

    def test_cloudfront_distribution_normalizes_edge_posture(self) -> None:
        distribution_arn = "arn:aws:cloudfront::111122223333:distribution/E123"
        certificate_arn = "arn:aws:acm:us-east-1:111122223333:certificate/cdn"
        web_acl_arn = "arn:aws:wafv2:us-east-1:111122223333:global/webacl/cdn/abc"

        normalized = normalize_cloudfront_distribution(
            _cloudfront_distribution_resource(
                {
                    "id": "E123",
                    "arn": distribution_arn,
                    "comment": "production CDN",
                    "domain_name": "d111111abcdef8.cloudfront.net",
                    "enabled": True,
                    "is_ipv6_enabled": True,
                    "http_version": "http2and3",
                    "default_root_object": "index.html",
                    "aliases": ["www.example.com"],
                    "web_acl_id": web_acl_arn,
                    "origin": [
                        {
                            "origin_id": "app",
                            "domain_name": "app.example.com",
                            "origin_path": "/prod",
                            "custom_origin_config": [{"origin_protocol_policy": "https-only"}],
                        }
                    ],
                    "default_cache_behavior": [
                        {
                            "target_origin_id": "app",
                            "viewer_protocol_policy": "redirect-to-https",
                            "cache_policy_id": "managed-cache",
                            "origin_request_policy_id": "origin-policy",
                            "response_headers_policy_id": "headers-policy",
                            "allowed_methods": ["GET", "HEAD", "OPTIONS"],
                            "cached_methods": ["GET", "HEAD"],
                        }
                    ],
                    "ordered_cache_behavior": [
                        {
                            "path_pattern": "/api/*",
                            "target_origin_id": "api",
                            "viewer_protocol_policy": "https-only",
                            "allowed_methods": ["GET", "HEAD"],
                            "cached_methods": ["GET", "HEAD"],
                        }
                    ],
                    "viewer_certificate": [
                        {
                            "cloudfront_default_certificate": False,
                            "acm_certificate_arn": certificate_arn,
                            "minimum_protocol_version": "TLSv1.2_2021",
                            "ssl_support_method": "sni-only",
                        }
                    ],
                    "logging_config": [
                        {
                            "bucket": "logs.s3.amazonaws.com",
                            "prefix": "cloudfront/",
                            "include_cookies": False,
                        }
                    ],
                    "tags": {"Environment": "prod"},
                }
            )
        )
        facts = aws_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.EDGE)
        self.assertEqual(normalized.identifier, "E123")
        self.assertEqual(normalized.arn, distribution_arn)
        self.assertTrue(normalized.public_access_configured)
        self.assertTrue(normalized.public_exposure)
        self.assertEqual(normalized.public_access_reasons, ["CloudFront distribution is enabled"])
        self.assertEqual(normalized.public_exposure_reasons, ["CloudFront distribution is enabled"])
        self.assertEqual(normalized.metadata["tags"], {"Environment": "prod"})
        self.assertEqual(facts.name, "production CDN")
        self.assertEqual(facts.cloudfront_distribution_id, "E123")
        self.assertEqual(facts.cloudfront_distribution_arn, distribution_arn)
        self.assertEqual(facts.cloudfront_domain_name, "d111111abcdef8.cloudfront.net")
        self.assertEqual(facts.cloudfront_enabled_state, "enabled")
        self.assertTrue(facts.cloudfront_enabled)
        self.assertEqual(facts.cloudfront_ipv6_enabled_state, "enabled")
        self.assertTrue(facts.cloudfront_ipv6_enabled)
        self.assertEqual(facts.cloudfront_http_version, "http2and3")
        self.assertEqual(facts.cloudfront_default_root_object, "index.html")
        self.assertEqual(facts.cloudfront_aliases, ["www.example.com"])
        self.assertEqual(facts.cloudfront_web_acl_id, web_acl_arn)
        self.assertEqual(facts.cloudfront_origin_ids, ["app"])
        self.assertEqual(facts.cloudfront_origin_domain_names, ["app.example.com"])
        self.assertEqual(facts.cloudfront_origins[0]["custom_origin_config"], {"origin_protocol_policy": "https-only"})
        self.assertEqual(facts.cloudfront_default_viewer_protocol_policy, "redirect-to-https")
        self.assertEqual(facts.cloudfront_default_allowed_methods, ["GET", "HEAD", "OPTIONS"])
        self.assertEqual(facts.cloudfront_default_cached_methods, ["GET", "HEAD"])
        self.assertEqual(facts.cloudfront_ordered_viewer_protocol_policies, ["https-only"])
        self.assertEqual(facts.cloudfront_viewer_certificate_source, "acm")
        self.assertEqual(facts.cloudfront_default_certificate_state, "disabled")
        self.assertFalse(facts.cloudfront_default_certificate)
        self.assertEqual(facts.cloudfront_minimum_protocol_version, "TLSv1.2_2021")
        self.assertEqual(facts.cloudfront_ssl_support_method, "sni-only")
        self.assertEqual(facts.cloudfront_acm_certificate_arn, certificate_arn)
        self.assertEqual(facts.cloudfront_logging_state, "configured")
        self.assertEqual(facts.cloudfront_logging_bucket, "logs.s3.amazonaws.com")
        self.assertEqual(facts.cloudfront_logging_prefix, "cloudfront/")
        self.assertEqual(
            facts.cloudfront_logging_config,
            {"bucket_name": "logs.s3.amazonaws.com", "prefix": "cloudfront/", "include_cookies": False},
        )
        self.assertEqual(facts.cloudfront_posture_uncertainties, [])

    def test_cloudfront_distribution_disabled_is_not_marked_public(self) -> None:
        normalized = normalize_cloudfront_distribution(
            _cloudfront_distribution_resource(
                {
                    "id": "Edisabled",
                    "domain_name": "d222222abcdef8.cloudfront.net",
                    "enabled": False,
                }
            )
        )
        facts = aws_facts(normalized)

        self.assertFalse(normalized.public_access_configured)
        self.assertFalse(normalized.public_exposure)
        self.assertEqual(normalized.public_access_reasons, [])
        self.assertEqual(normalized.public_exposure_reasons, [])
        self.assertEqual(facts.cloudfront_enabled_state, "disabled")
        self.assertFalse(facts.cloudfront_enabled)
        self.assertEqual(facts.cloudfront_logging_state, "not_configured")
        self.assertEqual(facts.cloudfront_posture_uncertainties, [])

    def test_cloudfront_distribution_preserves_unknown_edge_values(self) -> None:
        normalized = normalize_cloudfront_distribution(
            _cloudfront_distribution_resource(
                {},
                unknown_values={
                    "id": True,
                    "domain_name": True,
                    "enabled": True,
                    "is_ipv6_enabled": True,
                    "aliases": True,
                    "web_acl_id": True,
                    "origin": True,
                    "default_cache_behavior": [{"viewer_protocol_policy": True}],
                    "viewer_certificate": [
                        {
                            "cloudfront_default_certificate": True,
                            "minimum_protocol_version": True,
                        }
                    ],
                    "logging_config": [{"bucket": True}],
                },
            )
        )
        facts = aws_facts(normalized)

        self.assertEqual(normalized.identifier, "aws_cloudfront_distribution.cdn")
        self.assertFalse(normalized.public_access_configured)
        self.assertFalse(normalized.public_exposure)
        self.assertEqual(facts.cloudfront_enabled_state, "unknown")
        self.assertIsNone(facts.cloudfront_enabled)
        self.assertEqual(facts.cloudfront_ipv6_enabled_state, "unknown")
        self.assertIsNone(facts.cloudfront_ipv6_enabled)
        self.assertEqual(facts.cloudfront_aliases, [])
        self.assertEqual(facts.cloudfront_origin_ids, [])
        self.assertIsNone(facts.cloudfront_default_viewer_protocol_policy)
        self.assertEqual(facts.cloudfront_viewer_certificate_source, "unknown")
        self.assertEqual(facts.cloudfront_default_certificate_state, "unknown")
        self.assertIsNone(facts.cloudfront_default_certificate)
        self.assertEqual(facts.cloudfront_logging_state, "unknown")
        self.assertEqual(
            facts.cloudfront_posture_uncertainties,
            [
                "id is unknown after planning",
                "domain_name is unknown after planning",
                "enabled is unknown after planning",
                "is_ipv6_enabled is unknown after planning",
                "aliases is unknown after planning",
                "default_cache_behavior.viewer_protocol_policy is unknown after planning",
                "origin is unknown after planning",
                "viewer_certificate.cloudfront_default_certificate is unknown after planning",
                "viewer_certificate.minimum_protocol_version is unknown after planning",
                "logging_config.bucket is unknown after planning",
                "web_acl_id is unknown after planning",
            ],
        )

    def test_flow_log_normalizes_cloudwatch_vpc_telemetry_posture(self) -> None:
        normalized = normalize_flow_log(
            _flow_log_resource(
                {
                    "id": "fl-123",
                    "vpc_id": "vpc-app",
                    "traffic_type": "ALL",
                    "log_destination_type": "cloud-watch-logs",
                    "log_group_name": "/aws/vpc-flow-logs/app",
                    "iam_role_arn": "arn:aws:iam::111122223333:role/vpc-flow-logs",
                    "max_aggregation_interval": 60,
                    "destination_options": [
                        {
                            "file_format": "plain-text",
                            "hive_compatible_partitions": False,
                            "per_hour_partition": False,
                        }
                    ],
                    "tags": {"Environment": "prod"},
                }
            )
        )
        facts = aws_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.NETWORK)
        self.assertEqual(normalized.identifier, "fl-123")
        self.assertEqual(normalized.vpc_id, "vpc-app")
        self.assertEqual(normalized.metadata["tags"], {"Environment": "prod"})
        self.assertEqual(facts.name, "vpc")
        self.assertEqual(facts.flow_log_id, "fl-123")
        self.assertEqual(facts.flow_log_target_type, "vpc")
        self.assertEqual(facts.flow_log_target_id, "vpc-app")
        self.assertEqual(facts.flow_log_traffic_type, "ALL")
        self.assertEqual(facts.flow_log_destination_type, "cloud-watch-logs")
        self.assertIsNone(facts.flow_log_destination)
        self.assertEqual(facts.flow_log_log_group_name, "/aws/vpc-flow-logs/app")
        self.assertEqual(facts.flow_log_iam_role_arn, "arn:aws:iam::111122223333:role/vpc-flow-logs")
        self.assertEqual(facts.flow_log_max_aggregation_interval, 60)
        self.assertEqual(
            facts.flow_log_destination_options,
            {
                "file_format": "plain-text",
                "hive_compatible_partitions": False,
                "per_hour_partition": False,
            },
        )
        self.assertEqual(facts.flow_log_posture_uncertainties, [])

    def test_flow_log_normalizes_s3_subnet_telemetry_posture(self) -> None:
        normalized = normalize_flow_log(
            _flow_log_resource(
                {
                    "id": "fl-subnet",
                    "subnet_id": "subnet-private",
                    "traffic_type": "REJECT",
                    "log_destination_type": "s3",
                    "log_destination": "arn:aws:s3:::central-flow-logs/prefix/",
                    "max_aggregation_interval": "600",
                    "destination_options": [{"file_format": "parquet", "per_hour_partition": True}],
                }
            )
        )
        facts = aws_facts(normalized)

        self.assertIsNone(normalized.vpc_id)
        self.assertEqual(facts.flow_log_id, "fl-subnet")
        self.assertEqual(facts.flow_log_target_type, "subnet")
        self.assertEqual(facts.flow_log_target_id, "subnet-private")
        self.assertEqual(facts.flow_log_traffic_type, "REJECT")
        self.assertEqual(facts.flow_log_destination_type, "s3")
        self.assertEqual(facts.flow_log_destination, "arn:aws:s3:::central-flow-logs/prefix/")
        self.assertIsNone(facts.flow_log_log_group_name)
        self.assertIsNone(facts.flow_log_iam_role_arn)
        self.assertEqual(facts.flow_log_max_aggregation_interval, 600)
        self.assertEqual(
            facts.flow_log_destination_options,
            {"file_format": "parquet", "per_hour_partition": True},
        )
        self.assertEqual(facts.flow_log_posture_uncertainties, [])

    def test_flow_log_preserves_unknown_values_as_uncertainty(self) -> None:
        normalized = normalize_flow_log(
            _flow_log_resource(
                {},
                unknown_values={
                    "id": True,
                    "vpc_id": True,
                    "traffic_type": True,
                    "log_destination_type": True,
                    "log_destination": True,
                    "log_group_name": True,
                    "iam_role_arn": True,
                    "max_aggregation_interval": True,
                    "destination_options": True,
                },
            )
        )
        facts = aws_facts(normalized)

        self.assertEqual(normalized.identifier, "aws_flow_log.vpc")
        self.assertIsNone(normalized.vpc_id)
        self.assertIsNone(facts.flow_log_id)
        self.assertIsNone(facts.flow_log_target_type)
        self.assertIsNone(facts.flow_log_target_id)
        self.assertEqual(facts.flow_log_destination_options, {})
        self.assertEqual(
            facts.flow_log_posture_uncertainties,
            [
                "id is unknown after planning",
                "vpc_id is unknown after planning",
                "traffic_type is unknown after planning",
                "log_destination_type is unknown after planning",
                "log_destination is unknown after planning",
                "log_group_name is unknown after planning",
                "iam_role_arn is unknown after planning",
                "max_aggregation_interval is unknown after planning",
                "destination_options is unknown after planning",
            ],
        )

    def test_wafv2_web_acl_normalizes_edge_protection_posture(self) -> None:
        web_acl_arn = "arn:aws:wafv2:us-east-1:111122223333:regional/webacl/app/abc"
        normalized = normalize_wafv2_web_acl(
            _wafv2_web_acl_resource(
                {
                    "id": "app/abc",
                    "name": "app-edge",
                    "arn": web_acl_arn,
                    "scope": "REGIONAL",
                    "default_action": [{"allow": [{}]}],
                    "rule": [
                        {
                            "name": "aws-managed-common",
                            "priority": 1,
                            "override_action": [{"none": [{}]}],
                        }
                    ],
                    "tags": {"Environment": "prod"},
                }
            )
        )
        facts = aws_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.EDGE)
        self.assertEqual(normalized.identifier, web_acl_arn)
        self.assertEqual(normalized.arn, web_acl_arn)
        self.assertEqual(normalized.metadata["tags"], {"Environment": "prod"})
        self.assertEqual(facts.web_acl_id, "app/abc")
        self.assertEqual(facts.web_acl_name, "app-edge")
        self.assertEqual(facts.web_acl_arn, web_acl_arn)
        self.assertEqual(facts.web_acl_scope, "REGIONAL")
        self.assertEqual(facts.web_acl_default_action, "allow")
        self.assertEqual(facts.web_acl_default_action_evidence, {"allow": [{}]})
        self.assertEqual(facts.web_acl_rule_names, ["aws-managed-common"])
        self.assertEqual(facts.web_acl_rules[0]["name"], "aws-managed-common")
        self.assertEqual(facts.edge_protection_posture_uncertainties, [])

    def test_wafv2_web_acl_association_normalizes_target_and_web_acl_arns(self) -> None:
        load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/web/abc"
        web_acl_arn = "arn:aws:wafv2:us-east-1:111122223333:regional/webacl/app/abc"

        normalized = normalize_wafv2_web_acl_association(
            _wafv2_web_acl_association_resource(
                {
                    "id": f"{web_acl_arn},{load_balancer_arn}",
                    "resource_arn": load_balancer_arn,
                    "web_acl_arn": web_acl_arn,
                }
            )
        )
        facts = aws_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.EDGE)
        self.assertEqual(normalized.identifier, f"{web_acl_arn},{load_balancer_arn}")
        self.assertEqual(facts.web_acl_association_resource_arn, load_balancer_arn)
        self.assertEqual(facts.web_acl_association_web_acl_arn, web_acl_arn)
        self.assertEqual(facts.edge_protection_posture_uncertainties, [])

    def test_wafv2_web_acl_association_preserves_unknown_targets_as_uncertainty(self) -> None:
        normalized = normalize_wafv2_web_acl_association(
            _wafv2_web_acl_association_resource(
                {},
                unknown_values={
                    "id": True,
                    "resource_arn": True,
                    "web_acl_arn": True,
                },
            )
        )
        facts = aws_facts(normalized)

        self.assertEqual(normalized.identifier, "aws_wafv2_web_acl_association.alb")
        self.assertIsNone(facts.web_acl_association_resource_arn)
        self.assertIsNone(facts.web_acl_association_web_acl_arn)
        self.assertEqual(
            facts.edge_protection_posture_uncertainties,
            [
                "resource_arn is unknown after planning",
                "web_acl_arn is unknown after planning",
                "id is unknown after planning",
            ],
        )

    def test_vpc_endpoint_normalizes_gateway_service_posture(self) -> None:
        normalized = normalize_vpc_endpoint(
            _vpc_endpoint_resource(
                {
                    "id": "vpce-s3",
                    "service_name": "com.amazonaws.us-east-1.s3",
                    "vpc_endpoint_type": "Gateway",
                    "vpc_id": "vpc-123",
                    "route_table_ids": ["rtb-private", "rtb-private"],
                    "policy": '{"Statement":[{"Effect":"Allow"}]}',
                }
            )
        )
        facts = aws_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.NETWORK)
        self.assertEqual(normalized.identifier, "vpce-s3")
        self.assertEqual(normalized.vpc_id, "vpc-123")
        self.assertEqual(normalized.subnet_ids, ())
        self.assertEqual(normalized.security_group_ids, ())
        self.assertEqual(facts.vpc_endpoint_id, "vpce-s3")
        self.assertEqual(facts.vpc_endpoint_service_name, "com.amazonaws.us-east-1.s3")
        self.assertEqual(facts.vpc_endpoint_service_family, "s3")
        self.assertEqual(facts.vpc_endpoint_type, "Gateway")
        self.assertEqual(facts.vpc_endpoint_vpc_id, "vpc-123")
        self.assertEqual(facts.vpc_endpoint_route_table_ids, ["rtb-private"])
        self.assertEqual(facts.vpc_endpoint_private_dns_enabled_state, "unknown")
        self.assertIsNone(facts.vpc_endpoint_private_dns_enabled)
        self.assertEqual(facts.vpc_endpoint_policy_document, {"Statement": [{"Effect": "Allow"}]})
        self.assertEqual(facts.vpc_endpoint_dns_entries, [])
        self.assertEqual(facts.vpc_endpoint_dns_names, [])
        self.assertEqual(facts.vpc_endpoint_posture_uncertainties, [])

    def test_vpc_endpoint_normalizes_interface_service_posture(self) -> None:
        normalized = normalize_vpc_endpoint(
            _vpc_endpoint_resource(
                {
                    "id": "vpce-secrets",
                    "service_name": "com.amazonaws.us-east-1.secretsmanager",
                    "vpc_endpoint_type": "Interface",
                    "vpc_id": "vpc-123",
                    "subnet_ids": ["subnet-a", "subnet-b"],
                    "security_group_ids": ["sg-endpoint"],
                    "private_dns_enabled": True,
                    "dns_entry": [
                        {
                            "dns_name": "vpce-secrets-abc.secretsmanager.us-east-1.vpce.amazonaws.com",
                            "hosted_zone_id": "Z1HUB23UULQXV",
                        }
                    ],
                }
            )
        )
        facts = aws_facts(normalized)

        self.assertEqual(normalized.subnet_ids, ("subnet-a", "subnet-b"))
        self.assertEqual(normalized.security_group_ids, ("sg-endpoint",))
        self.assertEqual(facts.vpc_endpoint_service_family, "secretsmanager")
        self.assertEqual(facts.vpc_endpoint_subnet_ids, ["subnet-a", "subnet-b"])
        self.assertEqual(facts.vpc_endpoint_security_group_ids, ["sg-endpoint"])
        self.assertEqual(facts.vpc_endpoint_private_dns_enabled_state, "enabled")
        self.assertTrue(facts.vpc_endpoint_private_dns_enabled)
        self.assertEqual(
            facts.vpc_endpoint_dns_entries,
            [
                {
                    "dns_name": "vpce-secrets-abc.secretsmanager.us-east-1.vpce.amazonaws.com",
                    "hosted_zone_id": "Z1HUB23UULQXV",
                }
            ],
        )
        self.assertEqual(
            facts.vpc_endpoint_dns_names,
            ["vpce-secrets-abc.secretsmanager.us-east-1.vpce.amazonaws.com"],
        )

    def test_vpc_endpoint_classifies_supported_service_families_only(self) -> None:
        cases = {
            "com.amazonaws.us-east-1.kms": "kms",
            "com.amazonaws.us-east-1.ecr.api": "ecr",
            "com.amazonaws.us-east-1.ecr.dkr": "ecr",
            "com.amazonaws.us-east-1.sts": "sts",
            "com.amazonaws.us-east-1.logs": "cloudwatch",
            "com.amazonaws.us-east-1.monitoring": "cloudwatch",
            "com.amazonaws.vpce.us-east-1.vpce-svc-1234567890abcdef": None,
            "com.amazonaws.us-east-1.rds": None,
        }

        for service_name, expected_family in cases.items():
            with self.subTest(service_name=service_name):
                facts = aws_facts(normalize_vpc_endpoint(_vpc_endpoint_resource({"service_name": service_name})))

                self.assertEqual(facts.vpc_endpoint_service_family, expected_family)

    def test_vpc_endpoint_preserves_unknown_values_as_uncertainty(self) -> None:
        normalized = normalize_vpc_endpoint(
            _vpc_endpoint_resource(
                {},
                unknown_values={
                    "id": True,
                    "service_name": True,
                    "vpc_endpoint_type": True,
                    "vpc_id": True,
                    "private_dns_enabled": True,
                    "route_table_ids": True,
                    "subnet_ids": True,
                    "security_group_ids": True,
                    "policy": True,
                    "dns_entry": True,
                },
            )
        )
        facts = aws_facts(normalized)

        self.assertEqual(normalized.identifier, "aws_vpc_endpoint.service")
        self.assertIsNone(normalized.vpc_id)
        self.assertEqual(facts.vpc_endpoint_private_dns_enabled_state, "unknown")
        self.assertEqual(facts.vpc_endpoint_route_table_ids, [])
        self.assertEqual(facts.vpc_endpoint_subnet_ids, [])
        self.assertEqual(facts.vpc_endpoint_security_group_ids, [])
        self.assertEqual(facts.vpc_endpoint_dns_entries, [])
        self.assertEqual(
            facts.vpc_endpoint_posture_uncertainties,
            [
                "id is unknown after planning",
                "service_name is unknown after planning",
                "vpc_endpoint_type is unknown after planning",
                "vpc_id is unknown after planning",
                "private_dns_enabled is unknown after planning",
                "route_table_ids is unknown after planning",
                "subnet_ids is unknown after planning",
                "security_group_ids is unknown after planning",
                "policy is unknown after planning",
                "dns_entry is unknown after planning",
            ],
        )


if __name__ == "__main__":
    unittest.main()
