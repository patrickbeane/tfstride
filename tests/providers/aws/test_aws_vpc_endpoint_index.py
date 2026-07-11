from __future__ import annotations

import unittest
from typing import Any

from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.vpc_endpoint_index import build_aws_vpc_endpoint_index


def _vpc_endpoint(
    name: str,
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"aws_vpc_endpoint.{name}",
        mode="managed",
        resource_type="aws_vpc_endpoint",
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _normalized(*resources: TerraformResource):
    return AwsNormalizer().normalize(list(resources))


class AwsVpcEndpointIndexTests(unittest.TestCase):
    def test_s3_gateway_endpoint_coverage_is_indexed_by_vpc(self) -> None:
        inventory = _normalized(
            _vpc_endpoint(
                "s3_gateway",
                {
                    "id": "vpce-s3-gateway",
                    "service_name": "com.amazonaws.us-east-1.s3",
                    "vpc_endpoint_type": "Gateway",
                    "vpc_id": "vpc-app",
                    "route_table_ids": ["rtb-private", "rtb-private"],
                    "policy": '{"Statement":[{"Effect":"Allow","Action":"s3:GetObject"}]}',
                },
            )
        )

        index = build_aws_vpc_endpoint_index(inventory)
        coverage = index.coverage_for("vpc-app", "s3", endpoint_type="gateway")

        self.assertTrue(index.has_s3_endpoint("vpc-app"))
        self.assertFalse(index.coverage_for("vpc-app", "s3", endpoint_type="interface").has_endpoint)
        self.assertFalse(index.has_s3_endpoint("vpc-other"))
        self.assertTrue(coverage.has_endpoint)
        self.assertEqual(coverage.endpoint_addresses, ("aws_vpc_endpoint.s3_gateway",))
        self.assertEqual(coverage.endpoint_ids, ("vpce-s3-gateway",))
        self.assertEqual(coverage.route_table_ids, ("rtb-private",))
        self.assertEqual(coverage.endpoints[0].service_name, "com.amazonaws.us-east-1.s3")
        self.assertEqual(coverage.endpoints[0].service_family, "s3")
        self.assertEqual(coverage.endpoints[0].endpoint_type, "Gateway")
        self.assertEqual(
            dict(coverage.endpoints[0].policy_document),
            {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject"}]},
        )

    def test_s3_interface_endpoint_coverage_preserves_private_dns_evidence(self) -> None:
        inventory = _normalized(
            _vpc_endpoint(
                "s3_interface",
                {
                    "id": "vpce-s3-interface",
                    "service_name": "com.amazonaws.us-east-1.s3",
                    "vpc_endpoint_type": "Interface",
                    "vpc_id": "vpc-app",
                    "subnet_ids": ["subnet-a", "subnet-b"],
                    "security_group_ids": ["sg-endpoint"],
                    "private_dns_enabled": True,
                    "dns_entry": [
                        {
                            "dns_name": "vpce-s3-abc.s3.us-east-1.vpce.amazonaws.com",
                            "hosted_zone_id": "Z1HUB23UULQXV",
                        }
                    ],
                },
            )
        )

        index = build_aws_vpc_endpoint_index(inventory)
        coverage = index.coverage_for("vpc-app", "s3", endpoint_type="interface")

        self.assertTrue(index.has_s3_endpoint("vpc-app"))
        self.assertFalse(index.coverage_for("vpc-app", "s3", endpoint_type="gateway").has_endpoint)
        self.assertEqual(coverage.subnet_ids, ("subnet-a", "subnet-b"))
        self.assertEqual(coverage.security_group_ids, ("sg-endpoint",))
        self.assertEqual(coverage.dns_names, ("vpce-s3-abc.s3.us-east-1.vpce.amazonaws.com",))
        self.assertTrue(coverage.endpoints[0].private_dns_enabled)
        self.assertEqual(coverage.endpoints[0].private_dns_enabled_state, "enabled")
        self.assertEqual(
            tuple(dict(entry) for entry in coverage.endpoints[0].dns_entries),
            (
                {
                    "dns_name": "vpce-s3-abc.s3.us-east-1.vpce.amazonaws.com",
                    "hosted_zone_id": "Z1HUB23UULQXV",
                },
            ),
        )

    def test_sensitive_interface_endpoint_coverage_is_service_specific(self) -> None:
        inventory = _normalized(
            _vpc_endpoint(
                "secrets",
                {
                    "id": "vpce-secrets",
                    "service_name": "com.amazonaws.us-east-1.secretsmanager",
                    "vpc_endpoint_type": "Interface",
                    "vpc_id": "vpc-app",
                    "subnet_ids": ["subnet-a"],
                    "private_dns_enabled": True,
                },
            ),
            _vpc_endpoint(
                "kms",
                {
                    "id": "vpce-kms",
                    "service_name": "com.amazonaws.us-east-1.kms",
                    "vpc_endpoint_type": "Interface",
                    "vpc_id": "vpc-app",
                    "subnet_ids": ["subnet-b"],
                    "private_dns_enabled": False,
                },
            ),
            _vpc_endpoint(
                "rds",
                {
                    "id": "vpce-rds",
                    "service_name": "com.amazonaws.us-east-1.rds",
                    "vpc_endpoint_type": "Interface",
                    "vpc_id": "vpc-app",
                    "subnet_ids": ["subnet-c"],
                },
            ),
        )

        index = build_aws_vpc_endpoint_index(inventory)

        self.assertTrue(index.has_secrets_manager_interface_endpoint("vpc-app"))
        self.assertTrue(index.has_kms_endpoint("vpc-app"))
        self.assertFalse(index.has_secrets_manager_interface_endpoint("vpc-other"))
        self.assertEqual(
            index.coverage_for("vpc-app", "secretsmanager").endpoint_addresses,
            ("aws_vpc_endpoint.secrets",),
        )
        self.assertEqual(index.coverage_for("vpc-app", "kms").endpoint_addresses, ("aws_vpc_endpoint.kms",))
        self.assertEqual(index.coverage_for("vpc-app", "rds").endpoints, ())
        self.assertEqual(len(index.unclassified_service_endpoints), 1)
        self.assertEqual(index.unclassified_service_endpoints[0].endpoint_address, "aws_vpc_endpoint.rds")
        self.assertEqual(index.unclassified_service_endpoints[0].service_name, "com.amazonaws.us-east-1.rds")

    def test_unresolved_service_name_is_retained_without_service_coverage(self) -> None:
        inventory = _normalized(
            _vpc_endpoint(
                "computed",
                {
                    "id": "vpce-computed",
                    "vpc_endpoint_type": "Interface",
                    "vpc_id": "vpc-app",
                    "subnet_ids": ["subnet-a"],
                },
                unknown_values={"service_name": True},
            )
        )

        index = build_aws_vpc_endpoint_index(inventory)

        self.assertFalse(index.has_s3_endpoint("vpc-app"))
        self.assertFalse(index.has_secrets_manager_interface_endpoint("vpc-app"))
        self.assertFalse(index.has_kms_endpoint("vpc-app"))
        self.assertEqual(index.endpoints_for_vpc("vpc-app")[0].endpoint_address, "aws_vpc_endpoint.computed")
        self.assertEqual(len(index.unresolved_service_name_endpoints), 1)
        self.assertEqual(index.unresolved_service_name_endpoints[0].endpoint_address, "aws_vpc_endpoint.computed")
        self.assertEqual(
            index.unresolved_service_name_endpoints[0].uncertainties,
            ("service_name is unknown after planning",),
        )

    def test_multiple_endpoints_for_same_vpc_and_service_are_preserved_in_order(self) -> None:
        inventory = _normalized(
            _vpc_endpoint(
                "s3_gateway",
                {
                    "id": "vpce-s3-gateway",
                    "service_name": "com.amazonaws.us-east-1.s3",
                    "vpc_endpoint_type": "Gateway",
                    "vpc_id": "vpc-app",
                    "route_table_ids": ["rtb-private"],
                },
            ),
            _vpc_endpoint(
                "s3_interface",
                {
                    "id": "vpce-s3-interface",
                    "service_name": "com.amazonaws.us-east-1.s3",
                    "vpc_endpoint_type": "Interface",
                    "vpc_id": "vpc-app",
                    "subnet_ids": ["subnet-a"],
                },
            ),
        )

        coverage = build_aws_vpc_endpoint_index(inventory).coverage_for("vpc-app", "s3")

        self.assertEqual(
            coverage.endpoint_addresses,
            ("aws_vpc_endpoint.s3_gateway", "aws_vpc_endpoint.s3_interface"),
        )
        self.assertEqual(coverage.endpoint_ids, ("vpce-s3-gateway", "vpce-s3-interface"))
        self.assertEqual(coverage.endpoint_types, ("Gateway", "Interface"))


if __name__ == "__main__":
    unittest.main()
