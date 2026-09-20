from __future__ import annotations

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
_AWS_EXECUTION_ROLE_ARN = f"arn:aws:iam::{_AWS_ACCOUNT_ID}:role/orders-execution"
_AWS_TABLE_ARN = f"arn:aws:dynamodb:us-east-1:{_AWS_ACCOUNT_ID}:table/orders"
_AWS_LOAD_BALANCER_ARN = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/public/abc"
_AWS_LISTENER_ARN = "arn:aws:elasticloadbalancing:us-east-1:111122223333:listener/app/public/abc/ghi"
_AWS_TARGET_GROUP_ARN = "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/orders/def"

_GCP_PROJECT = "tfstride-demo"
_GCP_SERVICE_ACCOUNT_EMAIL = f"orders@{_GCP_PROJECT}.iam.gserviceaccount.com"
_GCP_SERVICE_ACCOUNT_MEMBER = f"serviceAccount:{_GCP_SERVICE_ACCOUNT_EMAIL}"
_GCP_DATABASE_ID = f"projects/{_GCP_PROJECT}/databases/orders"

_AZURE_APP_PRINCIPAL_ID = "orders-app-principal-id"
_AZURE_FUNCTION_PRINCIPAL_ID = "orders-function-principal-id"
_AZURE_USER_IDENTITY_ID = (
    "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.ManagedIdentity/"
    "userAssignedIdentities/orders-function"
)
_AZURE_COSMOSDB_ACCOUNT_ID = (
    "/subscriptions/sub-0001/resourceGroups/data/providers/Microsoft.DocumentDB/databaseAccounts/orders"
)


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


def _aws_role(name: str, arn: str) -> TerraformResource:
    return _resource(
        "aws",
        "aws_iam_role",
        name,
        {
            "name": name.replace("_", "-"),
            "arn": arn,
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
            "execution_role_arn": _AWS_EXECUTION_ROLE_ARN,
            "container_definitions": "[]",
        },
    )


def _aws_load_balancer() -> TerraformResource:
    return _resource(
        "aws",
        "aws_lb",
        "public",
        {
            "name": "public",
            "arn": _AWS_LOAD_BALANCER_ARN,
            "internal": False,
            "load_balancer_type": "application",
        },
    )


def _aws_load_balancer_target_group() -> TerraformResource:
    return _resource(
        "aws",
        "aws_lb_target_group",
        "orders",
        {
            "id": _AWS_TARGET_GROUP_ARN,
            "arn": _AWS_TARGET_GROUP_ARN,
            "name": "orders",
            "port": 8080,
            "protocol": "HTTP",
            "target_type": "ip",
        },
    )


def _aws_load_balancer_listener() -> TerraformResource:
    return _resource(
        "aws",
        "aws_lb_listener",
        "https",
        {
            "id": _AWS_LISTENER_ARN,
            "arn": _AWS_LISTENER_ARN,
            "load_balancer_arn": _AWS_LOAD_BALANCER_ARN,
            "port": 443,
            "protocol": "HTTPS",
            "default_action": [
                {
                    "type": "forward",
                    "target_group_arn": _AWS_TARGET_GROUP_ARN,
                }
            ],
        },
    )


def _aws_ecs_service() -> TerraformResource:
    return _resource(
        "aws",
        "aws_ecs_service",
        "orders",
        {
            "name": "orders",
            "task_definition": "orders:1",
            "load_balancer": [
                {
                    "target_group_arn": _AWS_TARGET_GROUP_ARN,
                    "container_name": "orders",
                    "container_port": 8080,
                }
            ],
        },
    )


def _aws_dynamodb_table() -> TerraformResource:
    return _resource(
        "aws",
        "aws_dynamodb_table",
        "orders",
        {
            "id": "orders",
            "name": "orders",
            "arn": _AWS_TABLE_ARN,
        },
    )


def _gcp_cloud_run(*, public_ingress: bool = True) -> TerraformResource:
    return _resource(
        "google",
        GcpResourceType.CLOUD_RUN_V2_SERVICE,
        "orders",
        {
            "name": "orders",
            "project": _GCP_PROJECT,
            "location": "us-central1",
            "ingress": ("INGRESS_TRAFFIC_ALL" if public_ingress else "INGRESS_TRAFFIC_INTERNAL_ONLY"),
            "template": [{"service_account": _GCP_SERVICE_ACCOUNT_EMAIL}],
        },
    )


def _gcp_public_invoker() -> TerraformResource:
    return _resource(
        "google",
        GcpResourceType.CLOUD_RUN_V2_SERVICE_IAM_MEMBER,
        "public_invoker",
        {
            "name": "orders",
            "project": _GCP_PROJECT,
            "location": "us-central1",
            "role": "roles/run.invoker",
            "member": "allUsers",
        },
    )


def _gcp_firestore_database() -> TerraformResource:
    return _resource(
        "google",
        GcpResourceType.FIRESTORE_DATABASE,
        "orders",
        {
            "id": _GCP_DATABASE_ID,
            "name": "orders",
            "project": _GCP_PROJECT,
            "location_id": "nam5",
            "type": "FIRESTORE_NATIVE",
        },
    )


def _azure_web_app(
    *,
    principal_id: object = _AZURE_APP_PRINCIPAL_ID,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return _resource(
        "azurerm",
        AzureResourceType.LINUX_WEB_APP,
        "orders",
        {
            "id": ("/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Web/sites/orders"),
            "name": "orders",
            "public_network_access_enabled": True,
            "identity": [
                {
                    "type": "SystemAssigned",
                    "principal_id": principal_id,
                    "tenant_id": "tenant-id",
                    "identity_ids": [],
                }
            ],
        },
        unknown_values=unknown_values,
    )


def _azure_function_app() -> TerraformResource:
    return _resource(
        "azurerm",
        AzureResourceType.LINUX_FUNCTION_APP,
        "orders_worker",
        {
            "id": ("/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Web/sites/orders-worker"),
            "name": "orders-worker",
            "public_network_access_enabled": True,
            "identity": [
                {
                    "type": "UserAssigned",
                    "identity_ids": ["azurerm_user_assigned_identity.orders_function.id"],
                }
            ],
        },
    )


def _azure_user_assigned_identity() -> TerraformResource:
    return _resource(
        "azurerm",
        AzureResourceType.USER_ASSIGNED_IDENTITY,
        "orders_function",
        {
            "id": _AZURE_USER_IDENTITY_ID,
            "name": "orders-function",
            "principal_id": _AZURE_FUNCTION_PRINCIPAL_ID,
            "client_id": "orders-function-client-id",
            "tenant_id": "tenant-id",
        },
    )


def _azure_cosmosdb_account() -> TerraformResource:
    return _resource(
        "azurerm",
        AzureResourceType.COSMOSDB_ACCOUNT,
        "orders",
        {
            "id": _AZURE_COSMOSDB_ACCOUNT_ID,
            "name": "orders",
            "resource_group_name": "data",
            "location": "eastus",
            "offer_type": "Standard",
        },
    )


class ManagedNosqlWorkloadIdentityBoundaryTests(unittest.TestCase):
    """Pin normalization/decorator prerequisites, not NoSQL authorization paths."""

    def test_aws_public_ecs_boundary_uses_task_role_and_exact_table_identity(
        self,
    ) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _aws_load_balancer(),
                _aws_load_balancer_target_group(),
                _aws_load_balancer_listener(),
                _aws_role("orders_task", _AWS_TASK_ROLE_ARN),
                _aws_role("orders_execution", _AWS_EXECUTION_ROLE_ARN),
                _aws_task_definition(),
                _aws_ecs_service(),
                _aws_dynamodb_table(),
            ]
        )
        load_balancer = inventory.get_by_address("aws_lb.public")
        service = inventory.get_by_address("aws_ecs_service.orders")
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        table = inventory.get_by_address("aws_dynamodb_table.orders")
        assert load_balancer is not None
        assert service is not None
        assert task_definition is not None
        assert table is not None

        self.assertTrue(load_balancer.public_exposure)
        self.assertEqual(
            aws_facts(service).internet_facing_load_balancer_addresses,
            ["aws_lb.public"],
        )
        self.assertEqual(
            aws_facts(service).ecs_load_balancers,
            [
                {
                    "target_group_arn": _AWS_TARGET_GROUP_ARN,
                    "container_name": "orders",
                    "container_port": 8080,
                }
            ],
        )
        self.assertTrue(service.get_metadata_field(AwsResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER))
        self.assertEqual(
            aws_facts(service).resolved_task_definition_addresses,
            ["aws_ecs_task_definition.orders"],
        )
        self.assertEqual(aws_facts(task_definition).task_role_arn, _AWS_TASK_ROLE_ARN)
        self.assertEqual(aws_facts(service).task_role_arn, _AWS_TASK_ROLE_ARN)
        self.assertEqual(service.attached_role_arns, (_AWS_TASK_ROLE_ARN,))
        self.assertEqual(
            service.get_metadata_field(AwsResourceMetadata.RESOLVED_TASK_ROLE_ADDRESSES),
            ["aws_iam_role.orders_task"],
        )
        self.assertNotIn(_AWS_EXECUTION_ROLE_ARN, service.attached_role_arns)
        self.assertEqual(table.identifier, "orders")
        self.assertEqual(table.arn, _AWS_TABLE_ARN)
        self.assertEqual(aws_facts(table).dynamodb_table_arn, _AWS_TABLE_ARN)

    def test_aws_unresolved_task_role_does_not_invent_identity_boundary(
        self,
    ) -> None:
        missing_role_arn = f"arn:aws:iam::{_AWS_ACCOUNT_ID}:role/missing-orders-task"
        inventory = AwsNormalizer().normalize(
            [
                _aws_load_balancer(),
                _aws_load_balancer_target_group(),
                _aws_load_balancer_listener(),
                _aws_task_definition(task_role_arn=missing_role_arn),
                _aws_ecs_service(),
                _aws_dynamodb_table(),
            ]
        )
        service = inventory.get_by_address("aws_ecs_service.orders")
        table = inventory.get_by_address("aws_dynamodb_table.orders")
        assert service is not None
        assert table is not None

        self.assertEqual(aws_facts(service).task_role_arn, missing_role_arn)
        self.assertEqual(
            service.get_metadata_field(AwsResourceMetadata.RESOLVED_TASK_ROLE_ADDRESSES),
            [],
        )
        self.assertEqual(
            service.get_metadata_field(AwsResourceMetadata.UNRESOLVED_TASK_ROLE_ARNS),
            [missing_role_arn],
        )
        self.assertEqual(aws_facts(table).dynamodb_table_arn, _AWS_TABLE_ARN)

    def test_gcp_public_cloud_run_boundary_preserves_runtime_identity_and_database(
        self,
    ) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _gcp_cloud_run(),
                _gcp_public_invoker(),
                _gcp_firestore_database(),
            ]
        )
        workload = inventory.get_by_address("google_cloud_run_v2_service.orders")
        database = inventory.get_by_address("google_firestore_database.orders")
        assert workload is not None
        assert database is not None

        self.assertTrue(workload.public_access_configured)
        self.assertTrue(workload.public_exposure)
        self.assertEqual(
            workload.public_exposure_reasons,
            ["google_cloud_run_v2_service_iam_member.public_invoker grants roles/run.invoker to allUsers"],
        )
        self.assertEqual(
            gcp_facts(workload).service_account_email,
            _GCP_SERVICE_ACCOUNT_EMAIL,
        )
        self.assertEqual(
            gcp_facts(workload).service_account_member,
            _GCP_SERVICE_ACCOUNT_MEMBER,
        )
        self.assertEqual(
            gcp_facts(workload).identity_members,
            [_GCP_SERVICE_ACCOUNT_MEMBER],
        )
        self.assertEqual(database.identifier, _GCP_DATABASE_ID)
        self.assertEqual(gcp_facts(database).firestore_database_type, "FIRESTORE_NATIVE")

    def test_gcp_private_ingress_does_not_become_public_from_invoker_alone(
        self,
    ) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _gcp_cloud_run(public_ingress=False),
                _gcp_public_invoker(),
                _gcp_firestore_database(),
            ]
        )
        workload = inventory.get_by_address("google_cloud_run_v2_service.orders")
        database = inventory.get_by_address("google_firestore_database.orders")
        assert workload is not None
        assert database is not None

        self.assertFalse(workload.public_access_configured)
        self.assertFalse(workload.public_exposure)
        self.assertEqual(
            gcp_facts(workload).service_account_member,
            _GCP_SERVICE_ACCOUNT_MEMBER,
        )
        self.assertEqual(database.identifier, _GCP_DATABASE_ID)

    def test_azure_public_app_boundary_preserves_system_identity_and_account(
        self,
    ) -> None:
        inventory = AzureNormalizer().normalize([_azure_web_app(), _azure_cosmosdb_account()])
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        account = inventory.get_by_address("azurerm_cosmosdb_account.orders")
        assert workload is not None
        assert account is not None

        workload_facts = azure_facts(workload)
        self.assertTrue(workload.public_access_configured)
        self.assertTrue(workload_facts.public_network_access_enabled)
        self.assertTrue(workload_facts.has_system_assigned_identity)
        self.assertFalse(workload_facts.has_user_assigned_identity)
        self.assertEqual(workload_facts.principal_id, _AZURE_APP_PRINCIPAL_ID)
        self.assertEqual(account.identifier, _AZURE_COSMOSDB_ACCOUNT_ID)
        self.assertEqual(
            azure_facts(account).cosmosdb_account_id,
            _AZURE_COSMOSDB_ACCOUNT_ID,
        )

    def test_azure_function_boundary_preserves_exact_user_identity_reference(
        self,
    ) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _azure_function_app(),
                _azure_user_assigned_identity(),
                _azure_cosmosdb_account(),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_function_app.orders_worker")
        identity = inventory.get_by_address("azurerm_user_assigned_identity.orders_function")
        account = inventory.get_by_address("azurerm_cosmosdb_account.orders")
        assert workload is not None
        assert identity is not None
        assert account is not None

        workload_facts = azure_facts(workload)
        self.assertTrue(workload.public_access_configured)
        self.assertFalse(workload_facts.has_system_assigned_identity)
        self.assertTrue(workload_facts.has_user_assigned_identity)
        self.assertEqual(
            workload_facts.attached_identity_references,
            ["azurerm_user_assigned_identity.orders_function.id"],
        )
        self.assertEqual(identity.identifier, _AZURE_USER_IDENTITY_ID)
        self.assertEqual(
            azure_facts(identity).principal_id,
            _AZURE_FUNCTION_PRINCIPAL_ID,
        )
        self.assertEqual(
            azure_facts(account).cosmosdb_account_id,
            _AZURE_COSMOSDB_ACCOUNT_ID,
        )

    def test_azure_unknown_principal_does_not_become_exact_identity(
        self,
    ) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _azure_web_app(
                    principal_id=None,
                    unknown_values={
                        "identity": [
                            {
                                "principal_id": True,
                            }
                        ]
                    },
                ),
                _azure_cosmosdb_account(),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        account = inventory.get_by_address("azurerm_cosmosdb_account.orders")
        assert workload is not None
        assert account is not None

        workload_facts = azure_facts(workload)
        self.assertTrue(workload.public_access_configured)
        self.assertTrue(workload_facts.has_system_assigned_identity)
        self.assertIsNone(workload_facts.principal_id)
        self.assertIn(
            "identity.principal_id is unknown after planning",
            workload_facts.managed_identity_uncertainties,
        )
        self.assertEqual(
            azure_facts(account).cosmosdb_account_id,
            _AZURE_COSMOSDB_ACCOUNT_ID,
        )


if __name__ == "__main__":
    unittest.main()
