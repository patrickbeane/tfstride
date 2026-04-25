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

    def test_primary_account_id_property_defaults_and_setter_use_metadata(self) -> None:
	    inventory = ResourceInventory(provider="aws", resources=[])
	
	    self.assertIsNone(inventory.primary_account_id)
	
	    inventory.primary_account_id = "111122223333"
	    self.assertEqual(inventory.primary_account_id, "111122223333")
	    self.assertEqual(inventory.metadata["primary_account_id"], "111122223333")
	
	    inventory.primary_account_id = None
	    self.assertIsNone(inventory.primary_account_id)
	    self.assertNotIn("primary_account_id", inventory.metadata)


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
        
    def test_policy_and_trust_property_defaults_do_not_require_metadata_keys(self) -> None:
	    resource = _resource(address="aws_iam_role.app", resource_type="aws_iam_role")
	
	    self.assertEqual(resource.trust_principals, [])
	    self.assertEqual(resource.trust_statements, [])
	    self.assertEqual(resource.resource_policy_source_addresses, [])
	    self.assertEqual(resource.policy_document, {})
	    self.assertIsNone(resource.public_access_block)
	    self.assertEqual(resource.bucket_acl, "")
	    self.assertIsNone(resource.bucket_name)
	    self.assertIsNone(resource.engine)
	    self.assertEqual(resource.metadata, {})
	
    def test_policy_and_trust_property_setters_update_metadata(self) -> None:
	    resource = _resource(address="aws_s3_bucket.logs", resource_type="aws_s3_bucket")
	
	    resource.trust_principals = ["arn:aws:iam::111122223333:root"]
	    resource.trust_statements = [
	        {
	            "principals": ["arn:aws:iam::111122223333:root"],
	            "has_narrowing_conditions": True,
	        }
	    ]
	    resource.resource_policy_source_addresses = ["aws_s3_bucket_policy.logs"]
	    resource.policy_document = {"Version": "2012-10-17", "Statement": []}
	    resource.public_access_block = {"block_public_policy": True, "restrict_public_buckets": False}
	    resource.bucket_acl = "public-read"
	    resource.bucket_name = "logs"
	    resource.engine = "postgres"
	
	    self.assertEqual(resource.metadata["trust_principals"], ["arn:aws:iam::111122223333:root"])
	    self.assertEqual(
	        resource.metadata["trust_statements"],
	        [{"principals": ["arn:aws:iam::111122223333:root"], "has_narrowing_conditions": True}],
	    )
	    self.assertEqual(resource.metadata["resource_policy_source_addresses"], ["aws_s3_bucket_policy.logs"])
	    self.assertEqual(resource.metadata["policy_document"], {"Version": "2012-10-17", "Statement": []})
	    self.assertEqual(
	        resource.metadata["public_access_block"],
	        {"block_public_policy": True, "restrict_public_buckets": False},
	    )
	    self.assertEqual(resource.metadata["acl"], "public-read")
	    self.assertEqual(resource.metadata["bucket"], "logs")
	    self.assertEqual(resource.metadata["engine"], "postgres")

    def test_decoration_property_defaults_do_not_require_metadata_keys(self) -> None:
        resource = _resource(address="aws_ecs_service.app", resource_type="aws_ecs_service")

        self.assertIsNone(resource.security_group_id)
        self.assertIsNone(resource.role_reference)
        self.assertEqual(resource.role_references, [])
        self.assertEqual(resource.resolved_role_references, [])
        self.assertIsNone(resource.iam_instance_profile)
        self.assertIsNone(resource.policy_arn)
        self.assertIsNone(resource.policy_name)
        self.assertIsNone(resource.cluster_reference)
        self.assertIsNone(resource.cluster_name)
        self.assertIsNone(resource.task_definition_reference)
        self.assertIsNone(resource.task_definition_family)
        self.assertIsNone(resource.task_definition_revision)
        self.assertIsNone(resource.network_mode)
        self.assertEqual(resource.requires_compatibilities, [])
        self.assertIsNone(resource.task_role_arn)
        self.assertIsNone(resource.execution_role_arn)
        self.assertIsNone(resource.secret_arn)
        self.assertIsNone(resource.secret_name)
        self.assertIsNone(resource.function_name)
        self.assertIsNone(resource.route_table_id)
        self.assertIsNone(resource.subnet_id)
        self.assertEqual(resource.routes, [])
        self.assertFalse(resource.map_public_ip_on_launch)
        self.assertFalse(resource.block_public_acls)
        self.assertFalse(resource.block_public_policy)
        self.assertFalse(resource.ignore_public_acls)
        self.assertFalse(resource.restrict_public_buckets)
        self.assertEqual(resource.metadata, {})

    def test_decoration_property_setters_update_metadata(self) -> None:
        resource = _resource(address="aws_ecs_service.app", resource_type="aws_ecs_service")
        cluster_resource = _resource(address="aws_ecs_cluster.app", resource_type="aws_ecs_cluster")
        secret_resource = _resource(
            address="aws_secretsmanager_secret.app",
            resource_type="aws_secretsmanager_secret",
        )

        resource.security_group_id = "sg-123"
        resource.role_reference = "app-role"
        resource.role_references = ["app-role", ""]
        resource.resolved_role_references = ["arn:aws:iam::111122223333:role/app"]
        resource.iam_instance_profile = "app-profile"
        resource.policy_arn = "arn:aws:iam::111122223333:policy/app"
        resource.policy_name = "app-inline"
        resource.cluster_reference = "arn:aws:ecs:us-east-1:111122223333:cluster/app"
        resource.task_definition_reference = "app:12"
        resource.task_definition_family = "app"
        resource.task_definition_revision = 12
        resource.network_mode = "awsvpc"
        resource.requires_compatibilities = ["FARGATE", ""]
        resource.task_role_arn = "arn:aws:iam::111122223333:role/task"
        resource.execution_role_arn = "arn:aws:iam::111122223333:role/execution"
        resource.secret_arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:app"
        resource.function_name = "app-worker"
        resource.route_table_id = "rtb-123"
        resource.subnet_id = "subnet-123"
        resource.routes = [{"gateway_id": "igw-123"}]
        resource.map_public_ip_on_launch = True
        resource.block_public_acls = True
        resource.block_public_policy = True
        resource.ignore_public_acls = True
        resource.restrict_public_buckets = True
        cluster_resource.cluster_name = "app-cluster"
        secret_resource.secret_name = "app/secret"

        self.assertEqual(resource.metadata["security_group_id"], "sg-123")
        self.assertEqual(resource.metadata["role"], "app-role")
        self.assertEqual(resource.metadata["role_references"], ["app-role"])
        self.assertEqual(
            resource.metadata["resolved_role_references"],
            ["arn:aws:iam::111122223333:role/app"],
        )
        self.assertEqual(resource.metadata["iam_instance_profile"], "app-profile")
        self.assertEqual(resource.metadata["policy_arn"], "arn:aws:iam::111122223333:policy/app")
        self.assertEqual(resource.metadata["policy_name"], "app-inline")
        self.assertEqual(
            resource.metadata["cluster"],
            "arn:aws:ecs:us-east-1:111122223333:cluster/app",
        )
        self.assertEqual(resource.metadata["task_definition"], "app:12")
        self.assertEqual(resource.metadata["family"], "app")
        self.assertEqual(resource.metadata["revision"], 12)
        self.assertEqual(resource.metadata["network_mode"], "awsvpc")
        self.assertEqual(resource.metadata["requires_compatibilities"], ["FARGATE"])
        self.assertEqual(resource.metadata["task_role_arn"], "arn:aws:iam::111122223333:role/task")
        self.assertEqual(
            resource.metadata["execution_role_arn"],
            "arn:aws:iam::111122223333:role/execution",
        )
        self.assertEqual(
            resource.metadata["secret_arn"],
            "arn:aws:secretsmanager:us-east-1:111122223333:secret:app",
        )
        self.assertEqual(resource.metadata["function_name"], "app-worker")
        self.assertEqual(resource.metadata["route_table_id"], "rtb-123")
        self.assertEqual(resource.metadata["subnet_id"], "subnet-123")
        self.assertEqual(resource.metadata["routes"], [{"gateway_id": "igw-123"}])
        self.assertTrue(resource.metadata["map_public_ip_on_launch"])
        self.assertTrue(resource.metadata["block_public_acls"])
        self.assertTrue(resource.metadata["block_public_policy"])
        self.assertTrue(resource.metadata["ignore_public_acls"])
        self.assertTrue(resource.metadata["restrict_public_buckets"])
        self.assertEqual(cluster_resource.metadata["name"], "app-cluster")
        self.assertEqual(secret_resource.metadata["name"], "app/secret")
        

if __name__ == "__main__":
    unittest.main()
