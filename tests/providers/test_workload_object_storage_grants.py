from __future__ import annotations

import json
import unittest
from typing import Any

from tfstride.models import TerraformResource
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_AWS_ACCOUNT_ID = "111122223333"
_AWS_TASK_ROLE_ARN = f"arn:aws:iam::{_AWS_ACCOUNT_ID}:role/orders-task"
_AWS_BUCKET_ARN = "arn:aws:s3:::orders-data"
_GCP_SERVICE_ACCOUNT_EMAIL = "orders@tfstride-demo.iam.gserviceaccount.com"
_GCP_SERVICE_ACCOUNT_MEMBER = f"serviceAccount:{_GCP_SERVICE_ACCOUNT_EMAIL}"
_AZURE_PRINCIPAL_ID = "orders-app-principal-id"
_AZURE_STORAGE_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/ordersdata"


def _resource(
    provider: str,
    resource_type: str,
    name: str,
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name=f"registry.terraform.io/hashicorp/{provider}",
        values=values,
        unknown_values=unknown_values or {},
    )


def _aws_role(statements: list[dict[str, Any]]) -> TerraformResource:
    return _resource(
        "aws",
        "aws_iam_role",
        "orders_task",
        {
            "name": "orders-task",
            "arn": _AWS_TASK_ROLE_ARN,
            "inline_policy": [
                {
                    "name": "orders-storage",
                    "policy": json.dumps({"Version": "2012-10-17", "Statement": statements}),
                }
            ],
        },
    )


def _aws_task_definition(*, task_role_arn: str = _AWS_TASK_ROLE_ARN) -> TerraformResource:
    return _resource(
        "aws",
        "aws_ecs_task_definition",
        "orders",
        {
            "family": "orders",
            "revision": 1,
            "task_role_arn": task_role_arn,
            "container_definitions": "[]",
        },
    )


def _aws_service() -> TerraformResource:
    return _resource(
        "aws",
        "aws_ecs_service",
        "orders",
        {"name": "orders", "task_definition": "orders:1"},
    )


def _aws_bucket() -> TerraformResource:
    return _resource(
        "aws",
        "aws_s3_bucket",
        "orders",
        {"id": "orders-data", "bucket": "orders-data", "arn": _AWS_BUCKET_ARN},
    )


def _gcp_cloud_run() -> TerraformResource:
    return _resource(
        "google",
        GcpResourceType.CLOUD_RUN_V2_SERVICE,
        "orders",
        {
            "name": "orders",
            "project": "tfstride-demo",
            "location": "us-central1",
            "template": [{"service_account": _GCP_SERVICE_ACCOUNT_EMAIL}],
        },
    )


def _gcp_bucket() -> TerraformResource:
    return _resource(
        "google",
        GcpResourceType.STORAGE_BUCKET,
        "orders",
        {"name": "tfstride-orders-data", "project": "tfstride-demo", "location": "US"},
    )


def _gcp_bucket_iam_member(
    *,
    bucket: str = "google_storage_bucket.orders.name",
    condition: dict[str, object] | None = None,
) -> TerraformResource:
    return _resource(
        "google",
        GcpResourceType.STORAGE_BUCKET_IAM_MEMBER,
        "orders_writer",
        {
            "bucket": bucket,
            "role": "roles/storage.objectAdmin",
            "member": _GCP_SERVICE_ACCOUNT_MEMBER,
            **({"condition": [condition]} if condition else {}),
        },
    )


def _azure_web_app() -> TerraformResource:
    return _resource(
        "azurerm",
        AzureResourceType.LINUX_WEB_APP,
        "orders",
        {
            "id": "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Web/sites/orders",
            "name": "orders",
            "identity": [
                {
                    "type": "SystemAssigned",
                    "principal_id": _AZURE_PRINCIPAL_ID,
                    "tenant_id": "tenant-id",
                    "identity_ids": [],
                }
            ],
        },
    )


def _azure_storage_account() -> TerraformResource:
    return _resource(
        "azurerm",
        AzureResourceType.STORAGE_ACCOUNT,
        "orders",
        {
            "id": _AZURE_STORAGE_ID,
            "name": "ordersdata",
            "public_network_access_enabled": False,
            "network_rules": [{"default_action": "Deny"}],
        },
    )


def _azure_role_assignment(
    *,
    scope: object = "azurerm_storage_account.orders.id",
    role_definition_name: object = "Storage Blob Data Owner",
    role_definition_id: object = (
        "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/storage-blob-data-owner"
    ),
    condition: object | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "scope": scope,
        "role_definition_name": role_definition_name,
        "role_definition_id": role_definition_id,
        "principal_id": _AZURE_PRINCIPAL_ID,
        "principal_type": "ServicePrincipal",
    }
    if condition is not None:
        values["condition"] = condition
    return _resource(
        "azurerm",
        AzureResourceType.ROLE_ASSIGNMENT,
        "orders_storage",
        values,
    )


def _azure_custom_storage_role() -> TerraformResource:
    return _resource(
        "azurerm",
        AzureResourceType.ROLE_DEFINITION,
        "storage_writer",
        {
            "id": ("/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/custom-storage-writer"),
            "name": "Custom Storage Writer",
            "scope": "/subscriptions/sub-0001",
            "assignable_scopes": ["/subscriptions/sub-0001"],
            "permissions": [
                {
                    "actions": [],
                    "not_actions": [],
                    "data_actions": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*"],
                    "not_data_actions": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"],
                }
            ],
        },
    )


class WorkloadObjectStorageGrantCharacterizationTests(unittest.TestCase):
    def test_aws_task_role_preserves_exact_s3_scope_conditions_and_denies(self) -> None:
        condition = {"StringLike": {"s3:prefix": ["orders/*"]}}
        inventory = AwsNormalizer().normalize(
            [
                _aws_bucket(),
                _aws_role(
                    [
                        {
                            "Effect": "Allow",
                            "Action": ["s3:GetObject", "s3:PutObject"],
                            "Resource": f"{_AWS_BUCKET_ARN}/*",
                            "Condition": condition,
                        },
                        {
                            "Effect": "Deny",
                            "Action": "s3:DeleteObject",
                            "Resource": f"{_AWS_BUCKET_ARN}/*",
                        },
                    ]
                ),
                _aws_task_definition(),
                _aws_service(),
            ]
        )
        service = inventory.get_by_address("aws_ecs_service.orders")
        role = inventory.get_by_address("aws_iam_role.orders_task")
        assert service is not None
        assert role is not None

        self.assertEqual(aws_facts(service).task_role_arn, _AWS_TASK_ROLE_ARN)
        self.assertEqual(service.attached_role_arns, (_AWS_TASK_ROLE_ARN,))
        self.assertEqual(
            service.get_metadata_field(AwsResourceMetadata.RESOLVED_TASK_ROLE_ADDRESSES),
            ["aws_iam_role.orders_task"],
        )
        self.assertEqual(len(role.policy_statements), 2)
        allow, deny = role.policy_statements
        self.assertEqual(allow.effect, "Allow")
        self.assertEqual(allow.actions, ["s3:GetObject", "s3:PutObject"])
        self.assertEqual(allow.resources, [f"{_AWS_BUCKET_ARN}/*"])
        self.assertEqual(
            [(item.operator, item.key, item.values) for item in allow.conditions],
            [("StringLike", "s3:prefix", ["orders/*"])],
        )
        self.assertEqual(deny.effect, "Deny")
        self.assertEqual(deny.actions, ["s3:DeleteObject"])
        self.assertEqual(deny.resources, [f"{_AWS_BUCKET_ARN}/*"])

    def test_aws_unresolved_task_role_is_preserved_without_relationship(self) -> None:
        missing_role_arn = f"arn:aws:iam::{_AWS_ACCOUNT_ID}:role/missing-task"
        inventory = AwsNormalizer().normalize(
            [_aws_bucket(), _aws_task_definition(task_role_arn=missing_role_arn), _aws_service()]
        )
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert service is not None

        self.assertEqual(aws_facts(service).task_role_arn, missing_role_arn)
        self.assertEqual(service.attached_role_arns, (missing_role_arn,))
        self.assertEqual(
            service.get_metadata_field(AwsResourceMetadata.RESOLVED_TASK_ROLE_ADDRESSES),
            [],
        )
        self.assertEqual(
            service.get_metadata_field(AwsResourceMetadata.UNRESOLVED_TASK_ROLE_ARNS),
            [missing_role_arn],
        )

    def test_gcp_service_account_bucket_grant_preserves_exact_scope_and_condition(self) -> None:
        condition = {
            "title": "orders-prefix",
            "description": "Limit the grant to the orders object prefix",
            "expression": "resource.name.startsWith('projects/_/buckets/tfstride-orders-data/objects/orders/')",
        }
        inventory = GcpNormalizer().normalize(
            [_gcp_cloud_run(), _gcp_bucket(), _gcp_bucket_iam_member(condition=condition)]
        )
        workload = inventory.get_by_address("google_cloud_run_v2_service.orders")
        bucket = inventory.get_by_address("google_storage_bucket.orders")
        iam_member = inventory.get_by_address("google_storage_bucket_iam_member.orders_writer")
        assert workload is not None
        assert bucket is not None
        assert iam_member is not None

        self.assertEqual(gcp_facts(workload).identity_members, [_GCP_SERVICE_ACCOUNT_MEMBER])
        self.assertEqual(gcp_facts(iam_member).bucket_name, "google_storage_bucket.orders.name")
        self.assertEqual(
            gcp_facts(bucket).bindings,
            [
                {
                    "role": "roles/storage.objectAdmin",
                    "members": [_GCP_SERVICE_ACCOUNT_MEMBER],
                    "source": "google_storage_bucket_iam_member.orders_writer",
                    "condition": condition,
                }
            ],
        )

    def test_gcp_unresolved_bucket_reference_does_not_attach_by_name(self) -> None:
        unresolved_reference = "google_storage_bucket.orders_archive.name"
        inventory = GcpNormalizer().normalize(
            [_gcp_cloud_run(), _gcp_bucket(), _gcp_bucket_iam_member(bucket=unresolved_reference)]
        )
        bucket = inventory.get_by_address("google_storage_bucket.orders")
        iam_member = inventory.get_by_address("google_storage_bucket_iam_member.orders_writer")
        assert bucket is not None
        assert iam_member is not None

        self.assertEqual(gcp_facts(iam_member).bucket_name, unresolved_reference)
        self.assertEqual(gcp_facts(bucket).bindings, [])
        self.assertEqual(gcp_facts(bucket).resource_policy_source_addresses, [])

    def test_azure_managed_identity_assignment_resolves_storage_scope_and_condition(self) -> None:
        condition = "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringEquals 'orders'"
        inventory = AzureNormalizer().normalize(
            [
                _azure_storage_account(),
                _azure_web_app(),
                _azure_role_assignment(condition=condition),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        assignment = inventory.get_by_address("azurerm_role_assignment.orders_storage")
        assert workload is not None
        assert assignment is not None

        assignment_facts = azure_facts(assignment)
        self.assertEqual(assignment_facts.resolved_managed_identity_address, workload.address)
        self.assertEqual(assignment_facts.role_assignment_scope, "azurerm_storage_account.orders.id")
        self.assertEqual(assignment_facts.role_assignment_scope_kind, "resource")
        self.assertEqual(
            assignment_facts.role_assignment_target_resource_address,
            "azurerm_storage_account.orders",
        )
        self.assertEqual(
            assignment_facts.role_assignment_target_resource_type,
            AzureResourceType.STORAGE_ACCOUNT,
        )
        self.assertEqual(assignment_facts.role_assignment_condition, condition)
        self.assertEqual(
            azure_facts(workload).managed_identity_role_assignments[0]["target_resource_address"],
            "azurerm_storage_account.orders",
        )

    def test_azure_custom_role_not_data_action_is_preserved(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _azure_storage_account(),
                _azure_web_app(),
                _azure_custom_storage_role(),
                _azure_role_assignment(
                    role_definition_name=None,
                    role_definition_id=("azurerm_role_definition.storage_writer.role_definition_resource_id"),
                ),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        role = inventory.get_by_address("azurerm_role_definition.storage_writer")
        assignment = inventory.get_by_address("azurerm_role_assignment.orders_storage")
        assert workload is not None
        assert role is not None
        assert assignment is not None

        role_facts = azure_facts(role)
        assignment_facts = azure_facts(assignment)
        self.assertEqual(
            role_facts.role_definition_data_actions,
            ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*"],
        )
        self.assertEqual(
            role_facts.role_definition_not_data_actions,
            ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"],
        )
        self.assertEqual(
            assignment_facts.resolved_role_definition_address,
            "azurerm_role_definition.storage_writer",
        )
        self.assertIn(
            "not_data_action=Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete",
            assignment_facts.role_assignment_breadth_mitigations,
        )
        self.assertEqual(
            azure_facts(workload).managed_identity_role_assignments[0]["target_resource_address"],
            "azurerm_storage_account.orders",
        )

    def test_azure_unresolved_storage_scope_does_not_invent_target(self) -> None:
        unresolved_scope = "azurerm_storage_account.orders_archive.id"
        inventory = AzureNormalizer().normalize(
            [
                _azure_storage_account(),
                _azure_web_app(),
                _azure_role_assignment(scope=unresolved_scope),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        assignment = inventory.get_by_address("azurerm_role_assignment.orders_storage")
        assert workload is not None
        assert assignment is not None

        assignment_facts = azure_facts(assignment)
        self.assertEqual(assignment_facts.resolved_managed_identity_address, workload.address)
        self.assertEqual(assignment_facts.role_assignment_scope, unresolved_scope)
        self.assertIsNone(assignment_facts.role_assignment_target_resource_address)
        self.assertIsNone(assignment_facts.role_assignment_target_resource_type)
        projected = azure_facts(workload).managed_identity_role_assignments[0]
        self.assertEqual(projected["scope"], unresolved_scope)
        self.assertIsNone(projected["target_resource_address"])


if __name__ == "__main__":
    unittest.main()
