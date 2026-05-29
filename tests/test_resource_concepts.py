from __future__ import annotations

import unittest

from tfstride.analysis.resource_concepts import (
    CONTROL_PLANE_SENSITIVE_DATA_STORE_TYPES,
    DATA_STORE_RESOURCE_TYPES,
    IDENTITY_ROLE_RESOURCE_TYPES,
    NETWORK_SECURITY_GROUP_RESOURCE_TYPES,
    PUBLIC_EDGE_RESOURCE_TYPES,
    WORKLOAD_RESOURCE_TYPES,
    is_control_plane_sensitive_data_store,
    is_data_store_resource,
    is_database_resource,
    is_identity_role_resource,
    is_network_security_group_resource,
    is_object_storage_resource,
    is_public_edge_resource,
    is_secret_store_resource,
    is_workload_resource,
)
from tfstride.models import NormalizedResource, ResourceCategory


def _resource(resource_type: str) -> NormalizedResource:
    return NormalizedResource(
        address=f"{resource_type}.example",
        provider="aws",
        resource_type=resource_type,
        name="example",
        category=ResourceCategory.COMPUTE,
    )


class ResourceConceptTests(unittest.TestCase):
    def test_concept_sets_match_current_aws_analysis_categories(self) -> None:
        self.assertEqual(
            WORKLOAD_RESOURCE_TYPES,
            frozenset({"aws_instance", "aws_lambda_function", "aws_ecs_service"}),
        )
        self.assertEqual(
            DATA_STORE_RESOURCE_TYPES,
            frozenset({"aws_db_instance", "aws_s3_bucket", "aws_secretsmanager_secret"}),
        )
        self.assertEqual(
            PUBLIC_EDGE_RESOURCE_TYPES,
            frozenset({"aws_instance", "aws_lb", "aws_db_instance", "aws_s3_bucket"}),
        )
        self.assertEqual(IDENTITY_ROLE_RESOURCE_TYPES, frozenset({"aws_iam_role"}))
        self.assertEqual(NETWORK_SECURITY_GROUP_RESOURCE_TYPES, frozenset({"aws_security_group"}))
        self.assertEqual(
            CONTROL_PLANE_SENSITIVE_DATA_STORE_TYPES,
            frozenset({"aws_db_instance", "aws_secretsmanager_secret"}),
        )

    def test_resource_concept_predicates_classify_known_resources(self) -> None:
        self.assertTrue(is_workload_resource(_resource("aws_instance")))
        self.assertTrue(is_workload_resource(_resource("aws_lambda_function")))
        self.assertTrue(is_workload_resource(_resource("aws_ecs_service")))
        self.assertTrue(is_data_store_resource(_resource("aws_db_instance")))
        self.assertTrue(is_data_store_resource(_resource("aws_s3_bucket")))
        self.assertTrue(is_data_store_resource(_resource("aws_secretsmanager_secret")))
        self.assertTrue(is_public_edge_resource(_resource("aws_lb")))
        self.assertTrue(is_identity_role_resource(_resource("aws_iam_role")))
        self.assertTrue(is_network_security_group_resource(_resource("aws_security_group")))
        self.assertTrue(is_database_resource(_resource("aws_db_instance")))
        self.assertTrue(is_object_storage_resource(_resource("aws_s3_bucket")))
        self.assertTrue(is_secret_store_resource(_resource("aws_secretsmanager_secret")))
        self.assertTrue(is_control_plane_sensitive_data_store(_resource("aws_db_instance")))
        self.assertTrue(
            is_control_plane_sensitive_data_store(_resource("aws_secretsmanager_secret"))
        )

    def test_resource_concept_predicates_reject_unrelated_resources(self) -> None:
        subnet = _resource("aws_subnet")

        self.assertFalse(is_workload_resource(subnet))
        self.assertFalse(is_data_store_resource(subnet))
        self.assertFalse(is_public_edge_resource(subnet))
        self.assertFalse(is_identity_role_resource(subnet))
        self.assertFalse(is_network_security_group_resource(subnet))
        self.assertFalse(is_database_resource(subnet))
        self.assertFalse(is_object_storage_resource(subnet))
        self.assertFalse(is_secret_store_resource(subnet))
        self.assertFalse(is_control_plane_sensitive_data_store(_resource("aws_s3_bucket")))


if __name__ == "__main__":
    unittest.main()