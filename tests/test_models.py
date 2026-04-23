from __future__ import annotations

import unittest

from tfstride.models import NormalizedResource, ResourceCategory, ResourceInventory


def _resource(
    *,
    address: str,
    resource_type: str,
    category: ResourceCategory = ResourceCategory.COMPUTE,
    identifier: str | None = None,
    arn: str | None = None,
) -> NormalizedResource:
    return NormalizedResource(
        address=address,
        provider="aws",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        category=category,
        identifier=identifier,
        arn=arn,
    )


class ResourceInventoryTests(unittest.TestCase):
    def test_by_type_preserves_original_resource_order_for_multiple_types(self) -> None:
        resources = [
            _resource(address="aws_instance.web", resource_type="aws_instance"),
            _resource(address="aws_db_instance.app", resource_type="aws_db_instance", category=ResourceCategory.DATA),
            _resource(address="aws_lambda_function.worker", resource_type="aws_lambda_function"),
            _resource(address="aws_instance.jobs", resource_type="aws_instance"),
        ]
        inventory = ResourceInventory(provider="aws", resources=resources)

        selected = inventory.by_type("aws_lambda_function", "aws_instance")

        self.assertEqual(
            [resource.address for resource in selected],
            [
                "aws_instance.web",
                "aws_lambda_function.worker",
                "aws_instance.jobs",
            ],
        )

    def test_get_by_identifier_preserves_first_match_across_identifier_arn_and_address_aliases(self) -> None:
        first = _resource(
            address="alias",
            resource_type="aws_instance",
            identifier="instance-1",
            arn="arn:aws:ec2:us-east-1:111122223333:instance/i-1234567890",
        )
        second = _resource(
            address="aws_s3_bucket.logs",
            resource_type="aws_s3_bucket",
            category=ResourceCategory.DATA,
            identifier="alias",
            arn="arn:aws:s3:::logs",
        )
        third = _resource(
            address="aws_iam_role.app",
            resource_type="aws_iam_role",
            category=ResourceCategory.IAM,
            identifier="role-app",
            arn="alias",
        )
        inventory = ResourceInventory(provider="aws", resources=[first, second, third])

        self.assertIs(inventory.get_by_identifier("alias"), first)

    def test_get_by_address_uses_address_index(self) -> None:
        target = _resource(address="aws_instance.web", resource_type="aws_instance")
        inventory = ResourceInventory(
            provider="aws",
            resources=[
                target,
                _resource(address="aws_lambda_function.worker", resource_type="aws_lambda_function"),
            ],
        )

        self.assertIs(inventory.get_by_address("aws_instance.web"), target)
        self.assertIsNone(inventory.get_by_address("aws_instance.missing"))


class NormalizedResourcePropertyTests(unittest.TestCase):
    def test_posture_property_defaults_do_not_require_metadata_keys(self) -> None:
        resource = _resource(address="aws_instance.web", resource_type="aws_instance")

        self.assertFalse(resource.direct_internet_reachable)
        self.assertFalse(resource.in_public_subnet)
        self.assertFalse(resource.has_nat_gateway_egress)
        self.assertFalse(resource.internet_ingress_capable)
        self.assertFalse(resource.publicly_accessible)
        self.assertFalse(resource.storage_encrypted)
        self.assertTrue(resource.vpc_enabled)
        self.assertEqual(resource.public_access_reasons, [])
        self.assertEqual(resource.public_exposure_reasons, [])
        self.assertEqual(resource.internet_ingress_reasons, [])
        self.assertEqual(resource.metadata, {})

    def test_posture_property_setters_update_metadata(self) -> None:
        resource = _resource(address="aws_db_instance.app", resource_type="aws_db_instance")

        resource.direct_internet_reachable = True
        resource.internet_ingress_capable = True
        resource.in_public_subnet = True
        resource.has_nat_gateway_egress = True
        resource.is_public_subnet = True
        resource.has_public_route = True
        resource.publicly_accessible = True
        resource.storage_encrypted = True
        resource.vpc_enabled = False
        resource.public_access_reasons = ["instance requests a public IP", ""]
        resource.public_exposure_reasons = ["attached security groups allow internet ingress"]
        resource.internet_ingress_reasons = ["aws_security_group.web ingress tcp 443 from 0.0.0.0/0"]

        self.assertTrue(resource.metadata["direct_internet_reachable"])
        self.assertTrue(resource.metadata["internet_ingress_capable"])
        self.assertTrue(resource.metadata["in_public_subnet"])
        self.assertTrue(resource.metadata["has_nat_gateway_egress"])
        self.assertTrue(resource.metadata["is_public_subnet"])
        self.assertTrue(resource.metadata["has_public_route"])
        self.assertTrue(resource.metadata["publicly_accessible"])
        self.assertTrue(resource.metadata["storage_encrypted"])
        self.assertFalse(resource.metadata["vpc_enabled"])
        self.assertEqual(resource.metadata["public_access_reasons"], ["instance requests a public IP"])
        self.assertEqual(
            resource.metadata["public_exposure_reasons"],
            ["attached security groups allow internet ingress"],
        )
        self.assertEqual(
            resource.metadata["internet_ingress_reasons"],
            ["aws_security_group.web ingress tcp 443 from 0.0.0.0/0"],
        )
        

if __name__ == "__main__":
    unittest.main()
