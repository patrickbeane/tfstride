from __future__ import annotations

import unittest
from typing import Any

from tfstride.models import ResourceCategory, TerraformResource
from tfstride.providers.aws.network_normalizers import normalize_load_balancer_listener, normalize_vpc_endpoint
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
