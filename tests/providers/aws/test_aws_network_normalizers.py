from __future__ import annotations

import unittest
from typing import Any

from tfstride.models import ResourceCategory, TerraformResource
from tfstride.providers.aws.network_normalizers import normalize_load_balancer_listener
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


if __name__ == "__main__":
    unittest.main()
