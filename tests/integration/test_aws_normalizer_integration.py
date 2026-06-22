from __future__ import annotations

import unittest

from tfstride.models import (
    TerraformResource,
)
from tfstride.providers.aws.normalizer import SUPPORTED_AWS_TYPES, AwsNormalizer


class AwsNormalizerRegistrationTests(unittest.TestCase):
    def test_supported_resource_types_match_dispatch_registry(self) -> None:
        normalizer = AwsNormalizer()

        self.assertEqual(set(normalizer._resource_normalizers), set(SUPPORTED_AWS_TYPES))
        self.assertTrue(all(callable(handler) for handler in normalizer._resource_normalizers.values()))

    def test_normalizer_models_ecs_service_behind_listener_target_group_path(self) -> None:
        load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/web/abc"
        listener_arn = f"{load_balancer_arn}/listener/443"
        target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/app/def"
        inventory = AwsNormalizer().normalize(
            [
                TerraformResource(
                    address="aws_lb.web",
                    mode="managed",
                    resource_type="aws_lb",
                    name="web",
                    provider_name="registry.terraform.io/hashicorp/aws",
                    values={
                        "id": "app/web/abc",
                        "arn": load_balancer_arn,
                        "internal": False,
                        "load_balancer_type": "application",
                    },
                ),
                TerraformResource(
                    address="aws_lb_target_group.app",
                    mode="managed",
                    resource_type="aws_lb_target_group",
                    name="app",
                    provider_name="registry.terraform.io/hashicorp/aws",
                    values={
                        "id": target_group_arn,
                        "arn": target_group_arn,
                        "name": "app",
                        "port": 8080,
                        "protocol": "HTTP",
                        "target_type": "ip",
                        "vpc_id": "vpc-app",
                    },
                ),
                TerraformResource(
                    address="aws_lb_listener.https",
                    mode="managed",
                    resource_type="aws_lb_listener",
                    name="https",
                    provider_name="registry.terraform.io/hashicorp/aws",
                    values={
                        "id": listener_arn,
                        "arn": listener_arn,
                        "load_balancer_arn": load_balancer_arn,
                        "port": 443,
                        "protocol": "HTTPS",
                        "default_action": [
                            {
                                "type": "forward",
                                "target_group_arn": target_group_arn,
                            }
                        ],
                    },
                ),
                TerraformResource(
                    address="aws_ecs_service.app",
                    mode="managed",
                    resource_type="aws_ecs_service",
                    name="app",
                    provider_name="registry.terraform.io/hashicorp/aws",
                    values={
                        "id": "app",
                        "name": "app",
                        "load_balancer": [
                            {
                                "target_group_arn": target_group_arn,
                                "container_name": "app",
                                "container_port": 8080,
                            }
                        ],
                    },
                ),
            ]
        )

        service = inventory.get_by_address("aws_ecs_service.app")

        self.assertEqual(inventory.unsupported_resources, [])
        self.assertIsNotNone(service)
        self.assertTrue(service.metadata["fronted_by_internet_facing_load_balancer"])
        self.assertEqual(
            service.metadata["internet_facing_load_balancer_addresses"],
            ["aws_lb.web"],
        )


if __name__ == "__main__":
    unittest.main()
