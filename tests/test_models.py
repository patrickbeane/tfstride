from __future__ import annotations

import unittest

from tfstride.models import (
    IAMPolicyStatement,
    NormalizedResource,
    ResourceCategory,
    ResourceInventory,
    SecurityGroupRule,
    Severity,
)
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.resource_metadata import ResourceMetadata


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


class SeverityTests(unittest.TestCase):
    def test_rank_orders_severities_for_threshold_comparison(self) -> None:
        self.assertLess(Severity.LOW.rank, Severity.MEDIUM.rank)
        self.assertLess(Severity.MEDIUM.rank, Severity.HIGH.rank)
        self.assertFalse(hasattr(Severity, "RANK_ORDER"))

    def test_sort_key_orders_highest_severity_first(self) -> None:
        severities = [Severity.LOW, Severity.HIGH, Severity.MEDIUM]

        self.assertEqual(
            sorted(severities, key=Severity.sort_key),
            [Severity.HIGH, Severity.MEDIUM, Severity.LOW],
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

    def test_resources_are_tuple_backed_after_index_construction(self) -> None:
        first = _resource(address="aws_instance.web", resource_type="aws_instance")
        second = _resource(address="aws_lambda_function.worker", resource_type="aws_lambda_function")
        resources = [first]

        inventory = ResourceInventory(provider="aws", resources=resources)
        resources.append(second)

        self.assertEqual(inventory.resources, (first,))
        self.assertEqual(inventory.by_type("aws_lambda_function"), [])
        with self.assertRaises(AttributeError):
            inventory.resources.append(second)

    def test_primary_account_id_property_defaults_and_setter_use_metadata(self) -> None:
        inventory = ResourceInventory(provider="aws", resources=[])

        self.assertIsNone(inventory.primary_account_id)

        inventory.primary_account_id = "111122223333"
        self.assertEqual(inventory.primary_account_id, "111122223333")
        self.assertEqual(inventory.metadata["primary_account_id"], "111122223333")

        inventory.primary_account_id = None
        self.assertIsNone(inventory.primary_account_id)
        self.assertNotIn("primary_account_id", inventory.metadata)

    def test_metadata_snapshot_returns_detached_copy(self) -> None:
        inventory = ResourceInventory(
            provider="aws",
            resources=[],
            metadata={"unsupported_resource_types": {"aws_cloudwatch_log_group": 1}},
        )

        snapshot = inventory.metadata_snapshot()
        snapshot["unsupported_resource_types"]["aws_cloudwatch_log_group"] = 2
        snapshot["new_key"] = "new-value"

        self.assertEqual(
            inventory.metadata,
            {"unsupported_resource_types": {"aws_cloudwatch_log_group": 1}},
        )

    def test_metadata_view_is_read_only_and_detached(self) -> None:
        source_metadata = {"unsupported_resource_types": {"aws_cloudwatch_log_group": 1}}
        inventory = ResourceInventory(provider="aws", resources=[], metadata=source_metadata)

        source_metadata["unsupported_resource_types"]["aws_cloudwatch_log_group"] = 2
        with self.assertRaises(TypeError):
            inventory.metadata["unsupported_resource_types"] = {"aws_cloudwatch_log_group": 3}

        self.assertEqual(
            inventory.metadata,
            {"unsupported_resource_types": {"aws_cloudwatch_log_group": 1}},
        )


class NormalizedResourcePropertyTests(unittest.TestCase):
    def test_resource_placement_ids_are_tuple_backed(self) -> None:
        subnet_ids = ["subnet-1"]
        security_group_ids = ["sg-1"]
        resource = NormalizedResource(
            address="aws_instance.web",
            provider="aws",
            resource_type="aws_instance",
            name="web",
            category=ResourceCategory.COMPUTE,
            subnet_ids=subnet_ids,
            security_group_ids=security_group_ids,
        )

        subnet_ids.append("subnet-2")
        security_group_ids.append("sg-2")

        self.assertEqual(resource.subnet_ids, ("subnet-1",))
        self.assertEqual(resource.security_group_ids, ("sg-1",))
        with self.assertRaises(AttributeError):
            resource.subnet_ids.append("subnet-3")
        with self.assertRaises(AttributeError):
            resource.security_group_ids.append("sg-3")

    def test_resource_mutation_helpers_update_explicit_mutable_fields(self) -> None:
        resource = _resource(address="aws_instance.web", resource_type="aws_instance")
        network_rule = SecurityGroupRule(
            direction="ingress",
            protocol="tcp",
            from_port=443,
            to_port=443,
            cidr_blocks=["0.0.0.0/0"],
        )
        policy_statement = IAMPolicyStatement(effect="Allow", actions=["s3:GetObject"])

        resource.add_attached_role_arn("arn:aws:iam::111122223333:role/web")
        resource.add_attached_role_arn("arn:aws:iam::111122223333:role/web")
        resource.add_attached_role_arn(None)
        resource.extend_network_rules([network_rule])
        resource.extend_policy_statements([policy_statement])

        self.assertEqual(resource.attached_role_arns, ["arn:aws:iam::111122223333:role/web"])
        self.assertEqual(resource.network_rules, [network_rule])
        self.assertEqual(resource.policy_statements, [policy_statement])

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

    def test_metadata_snapshot_returns_detached_copy(self) -> None:
        resource = NormalizedResource(
            address="aws_s3_bucket.logs",
            provider="aws",
            resource_type="aws_s3_bucket",
            name="logs",
            category=ResourceCategory.DATA,
            metadata={
                "policy_document": {"Statement": [{"Effect": "Allow"}]},
                "tags": {"env": "prod"},
            },
        )

        snapshot = resource.metadata_snapshot()
        snapshot["policy_document"]["Statement"][0]["Effect"] = "Deny"
        snapshot["tags"]["env"] = "dev"
        snapshot["new_key"] = "new-value"

        self.assertEqual(
            resource.metadata,
            {
                "policy_document": {"Statement": [{"Effect": "Allow"}]},
                "tags": {"env": "prod"},
            },
        )

    def test_metadata_view_is_read_only_and_detached(self) -> None:
        source_metadata = {"tags": {"env": "prod"}}
        resource = NormalizedResource(
            address="aws_s3_bucket.logs",
            provider="aws",
            resource_type="aws_s3_bucket",
            name="logs",
            category=ResourceCategory.DATA,
            metadata=source_metadata,
        )

        source_metadata["tags"]["env"] = "dev"
        with self.assertRaises(TypeError):
            resource.metadata["tags"] = {"env": "test"}

        self.assertEqual(resource.metadata["tags"], {"env": "prod"})

    def test_metadata_schema_helpers_update_private_metadata(self) -> None:
        resource = _resource(address="aws_iam_role.app", resource_type="aws_iam_role")

        self.assertFalse(resource.has_metadata_field(ResourceMetadata.PUBLIC_ACCESS_CONFIGURED))
        self.assertFalse(resource.get_metadata_field(ResourceMetadata.PUBLIC_ACCESS_CONFIGURED))
        resource.set_metadata_field(ResourceMetadata.PUBLIC_ACCESS_CONFIGURED, True)
        resource.append_metadata_field(
            AwsResourceMetadata.UNRESOLVED_ROLE_REFERENCES,
            "missing-role",
        )
        resource.append_metadata_field(
            AwsResourceMetadata.UNRESOLVED_ROLE_REFERENCES,
            "missing-role",
        )
        resource.append_metadata_field(
            AwsResourceMetadata.UNRESOLVED_ROLE_REFERENCES,
            None,
        )
        resource.extend_metadata_field(
            AwsResourceMetadata.UNRESOLVED_ROLE_REFERENCES,
            ["missing-role", "another-missing-role", "another-missing-role", None],
        )

        self.assertTrue(resource.has_metadata_field(ResourceMetadata.PUBLIC_ACCESS_CONFIGURED))
        self.assertTrue(resource.get_metadata_field(ResourceMetadata.PUBLIC_ACCESS_CONFIGURED))
        self.assertTrue(resource.metadata["public_access_configured"])
        self.assertEqual(
            resource.get_metadata_field(AwsResourceMetadata.UNRESOLVED_ROLE_REFERENCES),
            ["missing-role", "another-missing-role"],
        )
        self.assertEqual(
            resource.metadata["unresolved_role_references"],
            ["missing-role", "another-missing-role"],
        )

    def test_metadata_field_getter_uses_field_copy_semantics(self) -> None:
        resource = _resource(address="aws_s3_bucket.logs", resource_type="aws_s3_bucket")
        resource.set_metadata_field(
            AwsResourceMetadata.POLICY_DOCUMENT,
            {"Statement": [{"Effect": "Allow"}]},
        )

        policy_document = resource.get_metadata_field(AwsResourceMetadata.POLICY_DOCUMENT)
        policy_document["Statement"][0]["Effect"] = "Deny"

        self.assertEqual(
            resource.get_metadata_field(AwsResourceMetadata.POLICY_DOCUMENT),
            {"Statement": [{"Effect": "Allow"}]},
        )

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