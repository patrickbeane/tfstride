from __future__ import annotations

import re
import unittest

from tests.helpers.paths import SOURCE_ROOT
from tfstride.analysis.resource_concepts import (
    CONTROL_PLANE_SENSITIVE_DATA_STORE_TYPES,
    DATA_STORE_RESOURCE_TYPES,
    DATABASE_RESOURCE_TYPES,
    IAM_POLICY_RESOURCE_TYPES,
    IDENTITY_ROLE_RESOURCE_TYPES,
    KEY_MANAGEMENT_RESOURCE_TYPES,
    NETWORK_SECURITY_GROUP_RESOURCE_TYPES,
    OBJECT_STORAGE_PUBLIC_ACCESS_CONTROL_RESOURCE_TYPES,
    PROVIDER_MANAGED_EGRESS_WITHOUT_VPC_RESOURCE_TYPES,
    PUBLIC_COMPUTE_RESOURCE_TYPES,
    PUBLIC_EDGE_RESOURCE_TYPES,
    SECURITY_GROUP_BACKED_WORKLOAD_RESOURCE_TYPES,
    SENSITIVE_RESOURCE_POLICY_RESOURCE_TYPES,
    SERVICE_RESOURCE_POLICY_RESOURCE_TYPES,
    SUBNET_RESOURCE_TYPES,
    WORKLOAD_RESOURCE_TYPES,
    has_provider_managed_egress_without_vpc,
    is_control_plane_sensitive_data_store,
    is_data_store_resource,
    is_database_resource,
    is_iam_policy_resource,
    is_identity_role_resource,
    is_key_management_resource,
    is_network_security_group_resource,
    is_object_storage_public_access_control_resource,
    is_object_storage_resource,
    is_public_compute_resource,
    is_public_edge_resource,
    is_secret_store_resource,
    is_security_group_backed_workload_resource,
    is_subnet_resource,
    is_workload_resource,
)
from tfstride.models import NormalizedResource, ResourceCategory


def _resource(
    resource_type: str,
    *,
    provider: str = "aws",
    metadata: dict[str, object] | None = None,
) -> NormalizedResource:
    return NormalizedResource(
        address=f"{resource_type}.example",
        provider=provider,
        resource_type=resource_type,
        name="example",
        category=ResourceCategory.COMPUTE,
        metadata=metadata,
    )


class ResourceConceptTests(unittest.TestCase):
    def test_concept_sets_match_registered_provider_analysis_categories(self) -> None:
        self.assertEqual(
            WORKLOAD_RESOURCE_TYPES,
            frozenset(
                {
                    "aws_instance",
                    "aws_lambda_function",
                    "aws_ecs_service",
                    "google_cloud_run_service",
                    "google_cloud_run_v2_service",
                    "google_cloudfunctions_function",
                    "google_cloudfunctions2_function",
                    "google_compute_instance",
                    "azurerm_linux_virtual_machine",
                    "azurerm_windows_virtual_machine",
                }
            ),
        )
        self.assertEqual(
            SECURITY_GROUP_BACKED_WORKLOAD_RESOURCE_TYPES,
            frozenset(
                {
                    "aws_instance",
                    "aws_ecs_service",
                    "azurerm_linux_virtual_machine",
                    "azurerm_windows_virtual_machine",
                }
            ),
        )
        self.assertEqual(
            PUBLIC_COMPUTE_RESOURCE_TYPES,
            frozenset(
                {
                    "aws_instance",
                    "google_cloud_run_service",
                    "google_cloud_run_v2_service",
                    "google_cloudfunctions_function",
                    "google_cloudfunctions2_function",
                    "google_compute_instance",
                    "azurerm_linux_virtual_machine",
                    "azurerm_windows_virtual_machine",
                }
            ),
        )
        self.assertEqual(
            DATA_STORE_RESOURCE_TYPES,
            frozenset(
                {
                    "aws_db_instance",
                    "aws_s3_bucket",
                    "aws_secretsmanager_secret",
                    "google_bigquery_dataset",
                    "google_bigquery_table",
                    "google_pubsub_subscription",
                    "google_pubsub_topic",
                    "google_secret_manager_secret",
                    "google_sql_database_instance",
                    "google_storage_bucket",
                    "azurerm_storage_account",
                }
            ),
        )
        self.assertEqual(
            PUBLIC_EDGE_RESOURCE_TYPES,
            frozenset(
                {
                    "aws_instance",
                    "aws_lb",
                    "aws_db_instance",
                    "aws_s3_bucket",
                    "google_cloud_run_service",
                    "google_cloud_run_v2_service",
                    "google_cloudfunctions_function",
                    "google_cloudfunctions2_function",
                    "google_compute_forwarding_rule",
                    "google_compute_global_forwarding_rule",
                    "google_compute_instance",
                    "google_container_cluster",
                    "google_sql_database_instance",
                    "google_storage_bucket",
                    "azurerm_storage_account",
                    "azurerm_linux_virtual_machine",
                    "azurerm_windows_virtual_machine",
                }
            ),
        )
        self.assertEqual(IDENTITY_ROLE_RESOURCE_TYPES, frozenset({"aws_iam_role", "google_service_account"}))
        self.assertEqual(
            IAM_POLICY_RESOURCE_TYPES,
            frozenset(
                {
                    "aws_iam_policy",
                    "aws_iam_role",
                    "google_bigquery_dataset_iam_binding",
                    "google_bigquery_dataset_iam_member",
                    "google_bigquery_dataset_iam_policy",
                    "google_bigquery_table_iam_binding",
                    "google_bigquery_table_iam_member",
                    "google_bigquery_table_iam_policy",
                    "google_cloud_run_service_iam_binding",
                    "google_cloud_run_service_iam_member",
                    "google_cloud_run_service_iam_policy",
                    "google_cloud_run_v2_service_iam_binding",
                    "google_cloud_run_v2_service_iam_member",
                    "google_cloud_run_v2_service_iam_policy",
                    "google_cloudfunctions_function_iam_binding",
                    "google_cloudfunctions_function_iam_member",
                    "google_cloudfunctions_function_iam_policy",
                    "google_cloudfunctions2_function_iam_binding",
                    "google_cloudfunctions2_function_iam_member",
                    "google_cloudfunctions2_function_iam_policy",
                    "google_kms_crypto_key_iam_binding",
                    "google_kms_crypto_key_iam_member",
                    "google_kms_crypto_key_iam_policy",
                    "google_kms_key_ring_iam_binding",
                    "google_kms_key_ring_iam_member",
                    "google_kms_key_ring_iam_policy",
                    "google_folder_iam_binding",
                    "google_folder_iam_member",
                    "google_folder_iam_policy",
                    "google_organization_iam_binding",
                    "google_organization_iam_custom_role",
                    "google_organization_iam_member",
                    "google_organization_iam_policy",
                    "google_project_iam_binding",
                    "google_project_iam_custom_role",
                    "google_project_iam_member",
                    "google_project_iam_policy",
                    "google_pubsub_subscription_iam_binding",
                    "google_pubsub_subscription_iam_member",
                    "google_pubsub_subscription_iam_policy",
                    "google_pubsub_topic_iam_binding",
                    "google_pubsub_topic_iam_member",
                    "google_pubsub_topic_iam_policy",
                    "google_secret_manager_secret_iam_binding",
                    "google_secret_manager_secret_iam_member",
                    "google_secret_manager_secret_iam_policy",
                    "google_service_account_iam_binding",
                    "google_service_account_iam_member",
                    "google_service_account_iam_policy",
                    "google_storage_bucket_iam_binding",
                    "google_storage_bucket_iam_member",
                    "google_storage_bucket_iam_policy",
                }
            ),
        )
        self.assertEqual(
            NETWORK_SECURITY_GROUP_RESOURCE_TYPES,
            frozenset(
                {
                    "aws_security_group",
                    "google_compute_firewall",
                    "google_compute_firewall_policy",
                    "google_compute_firewall_policy_rule",
                    "azurerm_network_security_group",
                }
            ),
        )
        self.assertEqual(
            SUBNET_RESOURCE_TYPES,
            frozenset({"aws_subnet", "google_compute_subnetwork", "azurerm_subnet"}),
        )
        self.assertEqual(DATABASE_RESOURCE_TYPES, frozenset({"aws_db_instance", "google_sql_database_instance"}))
        self.assertEqual(
            CONTROL_PLANE_SENSITIVE_DATA_STORE_TYPES,
            frozenset({"aws_db_instance", "aws_secretsmanager_secret", "google_secret_manager_secret"}),
        )
        self.assertEqual(
            OBJECT_STORAGE_PUBLIC_ACCESS_CONTROL_RESOURCE_TYPES,
            frozenset({"aws_s3_bucket_public_access_block"}),
        )
        self.assertEqual(KEY_MANAGEMENT_RESOURCE_TYPES, frozenset({"aws_kms_key", "google_kms_crypto_key"}))
        self.assertEqual(
            SENSITIVE_RESOURCE_POLICY_RESOURCE_TYPES,
            frozenset(
                {
                    "aws_s3_bucket",
                    "aws_kms_key",
                    "aws_secretsmanager_secret",
                    "google_bigquery_dataset",
                    "google_bigquery_table",
                    "google_kms_crypto_key",
                    "google_pubsub_subscription",
                    "google_pubsub_topic",
                    "google_secret_manager_secret",
                    "google_storage_bucket",
                }
            ),
        )
        self.assertEqual(
            SERVICE_RESOURCE_POLICY_RESOURCE_TYPES,
            frozenset({"aws_lambda_function", "aws_sqs_queue", "aws_sns_topic"}),
        )
        self.assertEqual(
            PROVIDER_MANAGED_EGRESS_WITHOUT_VPC_RESOURCE_TYPES,
            frozenset(
                {
                    "aws_lambda_function",
                    "google_cloud_run_service",
                    "google_cloud_run_v2_service",
                    "google_cloudfunctions_function",
                    "google_cloudfunctions2_function",
                }
            ),
        )

    def test_resource_concept_predicates_classify_known_resources(self) -> None:
        self.assertTrue(is_workload_resource(_resource("aws_instance")))
        self.assertTrue(is_workload_resource(_resource("aws_lambda_function")))
        self.assertTrue(is_workload_resource(_resource("aws_ecs_service")))
        self.assertTrue(is_workload_resource(_resource("google_cloud_run_v2_service", provider="gcp")))
        self.assertTrue(is_workload_resource(_resource("google_cloudfunctions_function", provider="gcp")))
        self.assertTrue(is_workload_resource(_resource("google_compute_instance", provider="gcp")))
        self.assertTrue(is_workload_resource(_resource("azurerm_linux_virtual_machine", provider="azure")))
        self.assertTrue(is_security_group_backed_workload_resource(_resource("aws_instance")))
        self.assertTrue(is_security_group_backed_workload_resource(_resource("aws_ecs_service")))
        self.assertTrue(
            is_security_group_backed_workload_resource(_resource("azurerm_linux_virtual_machine", provider="azure"))
        )
        self.assertTrue(is_public_compute_resource(_resource("aws_instance")))
        self.assertTrue(is_public_compute_resource(_resource("google_cloud_run_v2_service", provider="gcp")))
        self.assertTrue(is_public_compute_resource(_resource("google_cloudfunctions_function", provider="gcp")))
        self.assertTrue(is_public_compute_resource(_resource("google_compute_instance", provider="gcp")))
        self.assertTrue(is_public_compute_resource(_resource("azurerm_linux_virtual_machine", provider="azure")))
        self.assertTrue(is_data_store_resource(_resource("aws_db_instance")))
        self.assertTrue(is_data_store_resource(_resource("aws_s3_bucket")))
        self.assertTrue(is_data_store_resource(_resource("aws_secretsmanager_secret")))
        self.assertTrue(is_data_store_resource(_resource("google_bigquery_dataset", provider="gcp")))
        self.assertTrue(is_data_store_resource(_resource("google_bigquery_table", provider="gcp")))
        self.assertTrue(is_data_store_resource(_resource("google_pubsub_topic", provider="gcp")))
        self.assertTrue(is_data_store_resource(_resource("google_pubsub_subscription", provider="gcp")))
        self.assertTrue(is_data_store_resource(_resource("google_secret_manager_secret", provider="gcp")))
        self.assertTrue(is_data_store_resource(_resource("google_sql_database_instance", provider="gcp")))
        self.assertTrue(is_data_store_resource(_resource("google_storage_bucket", provider="gcp")))
        self.assertTrue(is_data_store_resource(_resource("azurerm_storage_account", provider="azure")))
        self.assertTrue(is_public_edge_resource(_resource("aws_lb")))
        self.assertTrue(is_public_edge_resource(_resource("google_cloud_run_v2_service", provider="gcp")))
        self.assertTrue(is_public_edge_resource(_resource("google_cloudfunctions_function", provider="gcp")))
        self.assertTrue(is_public_edge_resource(_resource("google_compute_forwarding_rule", provider="gcp")))
        self.assertTrue(is_public_edge_resource(_resource("google_compute_global_forwarding_rule", provider="gcp")))
        self.assertTrue(is_public_edge_resource(_resource("google_compute_instance", provider="gcp")))
        self.assertTrue(is_public_edge_resource(_resource("google_container_cluster", provider="gcp")))
        self.assertTrue(is_public_edge_resource(_resource("google_sql_database_instance", provider="gcp")))
        self.assertTrue(is_public_edge_resource(_resource("azurerm_storage_account", provider="azure")))
        self.assertTrue(is_public_edge_resource(_resource("azurerm_linux_virtual_machine", provider="azure")))
        self.assertTrue(is_identity_role_resource(_resource("aws_iam_role")))
        self.assertTrue(is_identity_role_resource(_resource("google_service_account", provider="gcp")))
        self.assertTrue(is_iam_policy_resource(_resource("aws_iam_policy")))
        self.assertTrue(is_iam_policy_resource(_resource("aws_iam_role")))
        self.assertTrue(is_iam_policy_resource(_resource("google_bigquery_dataset_iam_member", provider="gcp")))
        self.assertTrue(is_iam_policy_resource(_resource("google_bigquery_table_iam_binding", provider="gcp")))
        self.assertTrue(is_iam_policy_resource(_resource("google_pubsub_topic_iam_member", provider="gcp")))
        self.assertTrue(is_iam_policy_resource(_resource("google_pubsub_subscription_iam_binding", provider="gcp")))
        self.assertTrue(is_iam_policy_resource(_resource("google_cloud_run_v2_service_iam_member", provider="gcp")))
        self.assertTrue(is_iam_policy_resource(_resource("google_cloudfunctions_function_iam_member", provider="gcp")))
        self.assertTrue(is_iam_policy_resource(_resource("google_kms_crypto_key_iam_member", provider="gcp")))
        self.assertTrue(is_iam_policy_resource(_resource("google_kms_key_ring_iam_member", provider="gcp")))
        self.assertTrue(is_iam_policy_resource(_resource("google_folder_iam_member", provider="gcp")))
        self.assertTrue(is_iam_policy_resource(_resource("google_organization_iam_binding", provider="gcp")))
        self.assertTrue(is_iam_policy_resource(_resource("google_organization_iam_custom_role", provider="gcp")))
        self.assertTrue(is_iam_policy_resource(_resource("google_project_iam_binding", provider="gcp")))
        self.assertTrue(is_iam_policy_resource(_resource("google_project_iam_custom_role", provider="gcp")))
        self.assertTrue(is_iam_policy_resource(_resource("google_project_iam_member", provider="gcp")))
        self.assertTrue(is_iam_policy_resource(_resource("google_project_iam_policy", provider="gcp")))
        self.assertTrue(is_iam_policy_resource(_resource("google_secret_manager_secret_iam_member", provider="gcp")))
        self.assertTrue(is_iam_policy_resource(_resource("google_service_account_iam_member", provider="gcp")))
        self.assertTrue(is_iam_policy_resource(_resource("google_storage_bucket_iam_member", provider="gcp")))
        self.assertTrue(is_network_security_group_resource(_resource("aws_security_group")))
        self.assertTrue(is_network_security_group_resource(_resource("google_compute_firewall", provider="gcp")))
        self.assertTrue(is_network_security_group_resource(_resource("google_compute_firewall_policy", provider="gcp")))
        self.assertTrue(
            is_network_security_group_resource(_resource("google_compute_firewall_policy_rule", provider="gcp"))
        )
        self.assertTrue(
            is_network_security_group_resource(_resource("azurerm_network_security_group", provider="azure"))
        )
        self.assertTrue(is_subnet_resource(_resource("aws_subnet")))
        self.assertTrue(is_subnet_resource(_resource("google_compute_subnetwork", provider="gcp")))
        self.assertTrue(is_subnet_resource(_resource("azurerm_subnet", provider="azure")))
        self.assertTrue(is_database_resource(_resource("aws_db_instance")))
        self.assertTrue(is_database_resource(_resource("google_sql_database_instance", provider="gcp")))
        self.assertTrue(is_object_storage_resource(_resource("aws_s3_bucket")))
        self.assertTrue(is_object_storage_resource(_resource("google_storage_bucket", provider="gcp")))
        self.assertTrue(is_object_storage_resource(_resource("azurerm_storage_account", provider="azure")))
        self.assertTrue(is_secret_store_resource(_resource("aws_secretsmanager_secret")))
        self.assertTrue(is_secret_store_resource(_resource("google_secret_manager_secret", provider="gcp")))
        self.assertTrue(is_control_plane_sensitive_data_store(_resource("aws_db_instance")))
        self.assertTrue(is_control_plane_sensitive_data_store(_resource("aws_secretsmanager_secret")))
        self.assertTrue(
            is_control_plane_sensitive_data_store(_resource("google_secret_manager_secret", provider="gcp"))
        )
        self.assertTrue(
            is_object_storage_public_access_control_resource(_resource("aws_s3_bucket_public_access_block"))
        )
        self.assertTrue(is_key_management_resource(_resource("aws_kms_key")))
        self.assertTrue(is_key_management_resource(_resource("google_kms_crypto_key", provider="gcp")))
        self.assertTrue(
            has_provider_managed_egress_without_vpc(_resource("aws_lambda_function", metadata={"vpc_enabled": False}))
        )
        self.assertTrue(
            has_provider_managed_egress_without_vpc(
                _resource("google_cloud_run_v2_service", provider="gcp", metadata={"vpc_enabled": False})
            )
        )

    def test_resource_concept_predicates_reject_unrelated_resources(self) -> None:
        subnet = _resource("aws_subnet")

        self.assertFalse(is_workload_resource(subnet))
        self.assertFalse(is_workload_resource(_resource("google_compute_instance")))
        self.assertFalse(is_security_group_backed_workload_resource(_resource("aws_lambda_function")))
        self.assertFalse(is_public_compute_resource(_resource("aws_ecs_service")))
        self.assertFalse(is_data_store_resource(subnet))
        self.assertFalse(is_public_edge_resource(subnet))
        self.assertFalse(is_identity_role_resource(subnet))
        self.assertFalse(is_iam_policy_resource(subnet))
        self.assertFalse(is_network_security_group_resource(subnet))
        self.assertFalse(is_subnet_resource(_resource("aws_instance")))
        self.assertFalse(is_database_resource(subnet))
        self.assertFalse(is_object_storage_resource(subnet))
        self.assertFalse(is_secret_store_resource(subnet))
        self.assertFalse(is_control_plane_sensitive_data_store(_resource("aws_s3_bucket")))
        self.assertFalse(is_object_storage_public_access_control_resource(subnet))
        self.assertFalse(is_key_management_resource(subnet))
        self.assertFalse(
            has_provider_managed_egress_without_vpc(_resource("aws_lambda_function", metadata={"vpc_enabled": True}))
        )

    def test_analysis_resource_type_selection_is_centralized(self) -> None:
        analysis_root = SOURCE_ROOT / "analysis"
        direct_type_patterns = (
            re.compile(r"by_type\([^\n)]*['\"]aws_"),
            re.compile(r"resource_type\s*(?:==|!=)\s*['\"]aws_"),
        )
        offenders: list[str] = []

        for path in sorted(analysis_root.glob("*.py")):
            if path.name == "resource_concepts.py":
                continue
            text = path.read_text(encoding="utf-8")
            for pattern in direct_type_patterns:
                if pattern.search(text):
                    offenders.append(path.name)
                    break

        self.assertEqual(offenders, [])

    def test_analysis_resource_concepts_do_not_embed_provider_type_literals(self) -> None:
        path = SOURCE_ROOT / "analysis" / "resource_concepts.py"
        text = path.read_text(encoding="utf-8")

        self.assertNotIn("aws_", text)
        self.assertNotIn("google_", text)
        self.assertNotIn("azurerm_", text)


if __name__ == "__main__":
    unittest.main()
