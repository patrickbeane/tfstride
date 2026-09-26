from __future__ import annotations

import json
import unittest
from typing import Any

from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _BUCKET_ARN as AWS_BUCKET_ARN,
)
from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _EXECUTION_ROLE_ARN as AWS_EXECUTION_ROLE_ARN,
)
from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _TASK_ROLE_ARN as AWS_TASK_ROLE_ARN,
)
from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _bucket as aws_bucket,
)
from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _role as aws_role,
)
from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _role_policy_attachment as aws_role_policy_attachment,
)
from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _statement as aws_statement,
)
from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _task_definition as aws_task_definition,
)
from tests.providers.aws.test_aws_public_ecs_s3_mutation_rules import (
    _load_balancer_path as aws_load_balancer_path,
)
from tests.providers.aws.test_aws_public_ecs_s3_mutation_rules import (
    _service as aws_service,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _STORAGE_ACCOUNT_ID as AZURE_STORAGE_ACCOUNT_ID,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _STORAGE_CONTAINER_ID as AZURE_STORAGE_CONTAINER_ID,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _SYSTEM_PRINCIPAL_ID as AZURE_SYSTEM_PRINCIPAL_ID,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _USER_IDENTITY_ID as AZURE_USER_IDENTITY_ID,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _USER_PRINCIPAL_ID as AZURE_USER_PRINCIPAL_ID,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _resource as azure_resource,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _storage_container as azure_storage_container,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _symbolic_resolution as azure_symbolic_resolution,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _user_assigned_identity as azure_user_assigned_identity,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _web_app as azure_web_app,
)
from tests.providers.gcp.normalizer_support import _terraform_resource
from tests.providers.gcp.test_gcp_cloud_run_gcs_access_paths import (
    _BUCKET_ADDRESS as GCP_BUCKET_ADDRESS,
)
from tests.providers.gcp.test_gcp_cloud_run_gcs_access_paths import (
    _BUCKET_NAME as GCP_BUCKET_NAME,
)
from tests.providers.gcp.test_gcp_cloud_run_gcs_access_paths import (
    _PROJECT as GCP_PROJECT,
)
from tests.providers.gcp.test_gcp_cloud_run_gcs_access_paths import (
    _SERVICE_ACCOUNT_EMAIL as GCP_SERVICE_ACCOUNT_EMAIL,
)
from tests.providers.gcp.test_gcp_cloud_run_gcs_access_paths import (
    _SERVICE_ACCOUNT_MEMBER as GCP_SERVICE_ACCOUNT_MEMBER,
)
from tests.providers.gcp.test_gcp_public_cloud_run_gcs_mutation_rules import (
    _cloud_run as gcp_cloud_run,
)
from tests.providers.gcp.test_gcp_public_cloud_run_gcs_mutation_rules import (
    _public_invoker as gcp_public_invoker,
)
from tests.providers.test_public_workload_object_storage_deletion_boundaries import (
    _aws_bucket_policy,
    _aws_object_lock,
    _aws_versioning,
    _azure_public_app,
    _azure_storage_account,
    _gcp_bucket,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import Finding, ResourceInventory, TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.azure.arm_control_plane_authorization import (
    AzureArmControlPlaneAuthorityResult,
    model_arm_control_plane_action_authority,
)
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_decoration.workload_identities import (
    workload_managed_identities,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import (
    AzureDecorationContext,
    AzureResourceIndexBuilder,
)
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType
from tfstride.resource_helpers import parse_aws_account_id

_AWS_ACCOUNT_ID = "111122223333"
_AWS_FOREIGN_ACCOUNT_ID = "444455556666"
_AWS_FOREIGN_TASK_ROLE_ARN = f"arn:aws:iam::{_AWS_FOREIGN_ACCOUNT_ID}:role/orders-task"
_AWS_DELETE_BUCKET = "s3:DeleteBucket"
_GCP_DELETE_BUCKET = "storage.buckets.delete"
_GCP_DELETE_OBJECT = "storage.objects.delete"
_GCP_ROLE_ID = "storageTopologyDeletion"
_GCP_ROLE_ADDRESS = f"google_project_iam_custom_role.{_GCP_ROLE_ID}"
_GCP_OTHER_PROJECT = "tfstride-archive"

_AZURE_DELETE_CONTAINER = "Microsoft.Storage/storageAccounts/blobServices/containers/delete"
_AZURE_DELETE_ACCOUNT = "Microsoft.Storage/storageAccounts/delete"
_AZURE_DELETE_BLOB = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"
_AZURE_CONTROL_ROLE_ID = (
    "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/storage-topology-operator"
)

_AWS_MUTATION_RULE = "aws-public-ecs-s3-mutation-access"
_AWS_OBJECT_DISRUPTION_RULE = "aws-public-ecs-s3-object-disruption"
_GCP_MUTATION_RULE = "gcp-public-cloud-run-gcs-mutation-access"
_GCP_OBJECT_DISRUPTION_RULE = "gcp-public-cloud-run-gcs-object-disruption"
_AZURE_MUTATION_RULE = "azure-public-app-service-storage-mutation-access"
_AZURE_OBJECT_DISRUPTION_RULE = "azure-public-app-service-storage-blob-disruption"


def _evaluate(
    normalizer: ProviderNormalizer,
    resources: list[TerraformResource],
    rule_ids: frozenset[str],
) -> list[Finding]:
    inventory = normalizer.normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=rule_ids),
    )


def _aws_caller_identity(
    account_id: str | None = _AWS_ACCOUNT_ID,
    *,
    unknown: bool = False,
) -> TerraformResource:
    values: dict[str, object] = {}
    if account_id is not None:
        values.update(
            {
                "account_id": account_id,
                "id": account_id,
                "arn": f"arn:aws:iam::{account_id}:root",
            }
        )
    return TerraformResource(
        address="data.aws_caller_identity.current",
        mode="data",
        resource_type="aws_caller_identity",
        name="current",
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values={"account_id": True} if unknown else {},
    )


def _aws_resources(
    statements: list[dict[str, Any]],
    *,
    internal: bool = False,
    task_role_arn: str = AWS_TASK_ROLE_ARN,
    execution_statements: list[dict[str, Any]] | None = None,
    incomplete: bool = False,
    bucket_policy: TerraformResource | None = None,
    caller_identity: TerraformResource | None = None,
) -> list[TerraformResource]:
    resources = [
        caller_identity or _aws_caller_identity(),
        *aws_load_balancer_path(internal=internal),
        aws_bucket(),
        aws_role("orders_task", task_role_arn, statements),
    ]
    if execution_statements is not None:
        resources.append(
            aws_role(
                "orders_execution",
                AWS_EXECUTION_ROLE_ARN,
                execution_statements,
            )
        )
    if incomplete:
        resources.append(
            aws_role_policy_attachment(
                task_role_arn,
                "arn:aws:iam::aws:policy/ExternalS3Administration",
            )
        )
    if bucket_policy is not None:
        resources.append(bucket_policy)
    resources.extend(
        [
            aws_task_definition(
                task_role_arn=task_role_arn,
                execution_role_arn=(AWS_EXECUTION_ROLE_ARN if execution_statements is not None else None),
            ),
            aws_service(),
        ]
    )
    return resources


def _aws_service_facts(
    resources: list[TerraformResource],
):
    inventory = AwsNormalizer().normalize(resources)
    service = inventory.get_by_address("aws_ecs_service.orders")
    assert service is not None
    return inventory, aws_facts(service)


def _gcp_workload(*, public: bool = True) -> TerraformResource:
    workload = gcp_cloud_run(public_ingress=public)
    assert isinstance(workload, TerraformResource)
    return workload


def _gcp_custom_role(
    permissions: list[str],
    *,
    stage: str | None = "GA",
    deleted: bool | None = False,
    unknown_permissions: bool = False,
    unknown_stage: bool = False,
    unknown_deleted: bool = False,
) -> TerraformResource:
    values: dict[str, object] = {
        "project": GCP_PROJECT,
        "role_id": _GCP_ROLE_ID,
        "name": f"projects/{GCP_PROJECT}/roles/{_GCP_ROLE_ID}",
        "permissions": permissions,
    }
    if stage is not None:
        values["stage"] = stage
    if deleted is not None:
        values["deleted"] = deleted
    unknown_values: dict[str, object] = {}
    if unknown_permissions:
        unknown_values["permissions"] = True
    if unknown_stage:
        unknown_values["stage"] = True
    if unknown_deleted:
        unknown_values["deleted"] = True
    return _terraform_resource(
        _GCP_ROLE_ADDRESS,
        GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
        values,
        unknown_values=unknown_values or None,
    )


def _gcp_role_name() -> str:
    return f"projects/{GCP_PROJECT}/roles/{_GCP_ROLE_ID}"


def _gcp_bucket_member(
    *,
    role: str | None = None,
    member: str = GCP_SERVICE_ACCOUNT_MEMBER,
    bucket: str = f"{GCP_BUCKET_ADDRESS}.name",
    condition: dict[str, str] | None = None,
    name: str = "topology",
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "bucket": bucket,
        "role": role or _gcp_role_name(),
        "member": member,
    }
    if condition is not None:
        values["condition"] = [condition]
    return _terraform_resource(
        f"google_storage_bucket_iam_member.{name}",
        GcpResourceType.STORAGE_BUCKET_IAM_MEMBER,
        values,
        unknown_values=unknown_values,
    )


def _gcp_bucket_binding(
    *,
    role: str | None = None,
    members: list[str] | None = None,
    name: str = "topology",
) -> TerraformResource:
    return _terraform_resource(
        f"google_storage_bucket_iam_binding.{name}",
        GcpResourceType.STORAGE_BUCKET_IAM_BINDING,
        {
            "bucket": f"{GCP_BUCKET_ADDRESS}.name",
            "role": role or _gcp_role_name(),
            "members": members or [GCP_SERVICE_ACCOUNT_MEMBER],
        },
    )


def _gcp_project_member(
    *,
    role: str = "roles/storage.admin",
    project: str = GCP_PROJECT,
    member: str = GCP_SERVICE_ACCOUNT_MEMBER,
    name: str = "topology",
) -> TerraformResource:
    return _terraform_resource(
        f"google_project_iam_member.{name}",
        GcpResourceType.PROJECT_IAM_MEMBER,
        {
            "project": project,
            "role": role,
            "member": member,
        },
    )


def _gcp_project_binding(
    *,
    role: str | None = None,
    members: list[str] | None = None,
    name: str = "topology",
) -> TerraformResource:
    return _terraform_resource(
        f"google_project_iam_binding.{name}",
        GcpResourceType.PROJECT_IAM_BINDING,
        {
            "project": GCP_PROJECT,
            "role": role or _gcp_role_name(),
            "members": members or [GCP_SERVICE_ACCOUNT_MEMBER],
        },
    )


def _gcp_other_bucket() -> TerraformResource:
    return _terraform_resource(
        "google_storage_bucket.archive",
        GcpResourceType.STORAGE_BUCKET,
        {
            "name": "tfstride-archive-data",
            "project": _GCP_OTHER_PROJECT,
            "location": "US",
        },
    )


def _azure_workload(*, public: bool = True) -> TerraformResource:
    return _azure_public_app(public=public)


def _azure_container(
    *,
    name: str = "orders",
    configured_name: str = "orders",
    account_address: str = "azurerm_storage_account.orders",
    account_id: str = AZURE_STORAGE_ACCOUNT_ID,
    has_immutability_policy: bool | None = False,
    has_legal_hold: bool | None = False,
    unknown_immutability: bool = False,
) -> TerraformResource:
    container_id = f"{account_id}/blobServices/default/containers/{configured_name}"
    values: dict[str, object] = {
        "id": container_id,
        "resource_manager_id": container_id,
        "name": configured_name,
        "storage_account_id": f"{account_address}.id",
        "container_access_type": "private",
    }
    if has_immutability_policy is not None:
        values["has_immutability_policy"] = has_immutability_policy
    if has_legal_hold is not None:
        values["has_legal_hold"] = has_legal_hold
    unknown_values: dict[str, object] = {}
    if unknown_immutability:
        unknown_values.update(
            {
                "has_immutability_policy": True,
                "has_legal_hold": True,
            }
        )
    return azure_resource(
        AzureResourceType.STORAGE_CONTAINER,
        values,
        name=name,
        unknown_values=unknown_values,
    )


def _azure_control_role(
    *,
    actions: list[str],
    not_actions: list[str] | None = None,
    data_actions: list[str] | None = None,
    assignable_scopes: list[str] | None = None,
) -> TerraformResource:
    return azure_resource(
        AzureResourceType.ROLE_DEFINITION,
        {
            "id": _AZURE_CONTROL_ROLE_ID,
            "role_definition_id": _AZURE_CONTROL_ROLE_ID,
            "name": "Storage Topology Operator",
            "scope": "/subscriptions/sub-0001",
            "assignable_scopes": (assignable_scopes if assignable_scopes is not None else ["/subscriptions/sub-0001"]),
            "permissions": [
                {
                    "actions": actions,
                    "not_actions": not_actions or [],
                    "data_actions": data_actions or [],
                    "not_data_actions": [],
                }
            ],
        },
        name="storage_topology",
    )


def _azure_control_assignment(
    *,
    scope: object = "azurerm_storage_account.orders.id",
    principal_id: object = AZURE_SYSTEM_PRINCIPAL_ID,
    condition: object | None = None,
    name: str = "storage_topology",
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    scope_reference = scope if isinstance(scope, str) and scope.startswith("azurerm_") else None
    values: dict[str, object] = {
        "scope": None if scope_reference is not None else scope,
        "role_definition_id": _AZURE_CONTROL_ROLE_ID,
        "principal_id": principal_id,
        "principal_type": "ServicePrincipal",
    }
    if condition is not None:
        values["condition"] = condition
        values["condition_version"] = "2.0"
    resolved_unknown_values = dict(unknown_values or {})
    reference_resolutions = ()
    if scope_reference is not None:
        resolved_unknown_values["scope"] = True
        reference_resolutions = (azure_symbolic_resolution(("scope",), scope_reference),)
    return azure_resource(
        AzureResourceType.ROLE_ASSIGNMENT,
        values,
        name=name,
        unknown_values=resolved_unknown_values,
        reference_resolutions=reference_resolutions,
    )


def _azure_inventory_and_context(
    resources: list[TerraformResource],
) -> tuple[ResourceInventory, AzureDecorationContext]:
    inventory = AzureNormalizer().normalize(resources)
    return (
        inventory,
        AzureDecorationContext(index=AzureResourceIndexBuilder().build(list(inventory.resources))),
    )


def _azure_authority(
    inventory: ResourceInventory,
    context: AzureDecorationContext,
    *,
    target_arm_id: str = AZURE_STORAGE_CONTAINER_ID,
    action: str = _AZURE_DELETE_CONTAINER,
    principal_id: str = AZURE_SYSTEM_PRINCIPAL_ID,
    assignment_address: str = "azurerm_role_assignment.storage_topology",
) -> AzureArmControlPlaneAuthorityResult:
    assignment = inventory.get_by_address(assignment_address)
    assert assignment is not None
    return model_arm_control_plane_action_authority(
        assignment,
        context,
        principal_id=principal_id,
        target_arm_id=target_arm_id,
        requested_actions=(action,),
    )


class PublicWorkloadObjectStorageTopologyDestructionBoundaryTests(unittest.TestCase):
    """Pin storage-topology deletion inputs without constructing new paths."""

    def test_topology_deletion_is_distinct_from_object_deletion(
        self,
    ) -> None:
        aws_resources = _aws_resources(
            [
                aws_statement(
                    "Allow",
                    _AWS_DELETE_BUCKET,
                    AWS_BUCKET_ARN,
                )
            ]
        )
        aws_inventory, aws_workload_facts = _aws_service_facts(aws_resources)
        self.assertEqual(
            aws_workload_facts.ecs_s3_access_paths[0]["matched_actions"],
            [_AWS_DELETE_BUCKET],
        )
        self.assertEqual(
            aws_workload_facts.ecs_s3_object_deletion_paths,
            [],
        )
        self.assertIsNotNone(aws_inventory.get_by_address("aws_s3_bucket.orders"))

        gcp_resources = [
            _gcp_workload(),
            gcp_public_invoker(),
            _gcp_bucket(),
            _gcp_custom_role([_GCP_DELETE_BUCKET]),
            _gcp_bucket_member(),
        ]
        gcp_inventory = GcpNormalizer().normalize(gcp_resources)
        gcp_workload = gcp_inventory.get_by_address("google_cloud_run_v2_service.orders")
        gcp_role = gcp_inventory.get_by_address(_GCP_ROLE_ADDRESS)
        assert gcp_workload is not None
        assert gcp_role is not None
        self.assertTrue(gcp_workload.public_exposure)
        self.assertEqual(
            gcp_facts(gcp_role).custom_role_permissions,
            [_GCP_DELETE_BUCKET],
        )
        self.assertEqual(
            gcp_facts(gcp_workload).cloud_run_gcs_access_paths,
            [],
        )
        self.assertEqual(
            gcp_facts(gcp_workload).cloud_run_gcs_object_deletion_paths,
            [],
        )

        azure_resources = [
            _azure_storage_account(),
            _azure_container(),
            _azure_workload(),
            _azure_control_role(actions=[_AZURE_DELETE_CONTAINER]),
            _azure_control_assignment(scope=("azurerm_storage_container.orders.resource_manager_id")),
        ]
        azure_inventory, azure_context = _azure_inventory_and_context(azure_resources)
        azure_workload = azure_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert azure_workload is not None
        self.assertTrue(azure_workload.public_access_configured)
        self.assertEqual(
            azure_facts(azure_workload).app_service_storage_access_paths,
            [],
        )
        self.assertEqual(
            azure_facts(azure_workload).app_service_blob_deletion_paths,
            [],
        )
        self.assertEqual(
            _azure_authority(azure_inventory, azure_context).state,
            "granted",
        )

    def test_aws_task_role_preserves_exact_bucket_delete_authority(
        self,
    ) -> None:
        inventory, facts = _aws_service_facts(
            _aws_resources(
                [
                    aws_statement(
                        "Allow",
                        _AWS_DELETE_BUCKET,
                        AWS_BUCKET_ARN,
                    )
                ],
                execution_statements=[
                    aws_statement(
                        "Allow",
                        _AWS_DELETE_BUCKET,
                        AWS_BUCKET_ARN,
                    )
                ],
            )
        )

        self.assertEqual(inventory.primary_account_id, _AWS_ACCOUNT_ID)
        self.assertEqual(len(facts.ecs_s3_access_paths), 1)
        path = facts.ecs_s3_access_paths[0]
        self.assertEqual(path["role_kind"], "ecs_task_role")
        self.assertEqual(path["credential_context"], "workload_runtime")
        self.assertEqual(path["role_arn"], AWS_TASK_ROLE_ARN)
        self.assertEqual(path["bucket_address"], "aws_s3_bucket.orders")
        self.assertEqual(path["bucket_arn"], AWS_BUCKET_ARN)
        self.assertEqual(path["matched_actions"], [_AWS_DELETE_BUCKET])
        self.assertEqual(path["access_classes"], ["administrative"])
        self.assertEqual(path["resource_scopes"], ["exact_bucket"])
        self.assertEqual(path["access_state"], "allowed")
        self.assertTrue(path["role_policy_complete"])
        self.assertFalse(path["explicit_deny"])
        self.assertFalse(path["conditional_evaluation_required"])

    def test_aws_execution_role_cannot_substitute_for_task_role(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _aws_caller_identity(),
                aws_bucket(),
                aws_role("orders_task", AWS_TASK_ROLE_ARN, []),
                aws_role(
                    "orders_execution",
                    AWS_EXECUTION_ROLE_ARN,
                    [
                        aws_statement(
                            "Allow",
                            _AWS_DELETE_BUCKET,
                            AWS_BUCKET_ARN,
                        )
                    ],
                ),
                aws_task_definition(),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None
        self.assertEqual(
            aws_facts(task_definition).ecs_s3_access_paths,
            [],
        )

    def test_aws_denied_conditional_incomplete_and_non_exact_authority_fails_closed(
        self,
    ) -> None:
        cases = {
            "explicit deny": _aws_resources(
                [
                    aws_statement(
                        "Allow",
                        _AWS_DELETE_BUCKET,
                        AWS_BUCKET_ARN,
                    ),
                    aws_statement(
                        "Deny",
                        _AWS_DELETE_BUCKET,
                        AWS_BUCKET_ARN,
                    ),
                ]
            ),
            "conditional": _aws_resources(
                [
                    aws_statement(
                        "Allow",
                        _AWS_DELETE_BUCKET,
                        AWS_BUCKET_ARN,
                        condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
                    )
                ]
            ),
            "incomplete": _aws_resources(
                [
                    aws_statement(
                        "Allow",
                        _AWS_DELETE_BUCKET,
                        AWS_BUCKET_ARN,
                    )
                ],
                incomplete=True,
            ),
            "non exact": _aws_resources(
                [
                    aws_statement(
                        "Allow",
                        _AWS_DELETE_BUCKET,
                        "arn:aws:s3:::orders-*",
                    )
                ]
            ),
        }

        for case, resources in cases.items():
            with self.subTest(case=case):
                _inventory, facts = _aws_service_facts(resources)
                deterministic = [
                    path
                    for path in facts.ecs_s3_access_paths
                    if path["access_state"] == "allowed"
                    and path["matched_actions"] == [_AWS_DELETE_BUCKET]
                    and path["resource_scopes"] == ["exact_bucket"]
                    and path["role_policy_complete"]
                    and not path["explicit_deny"]
                    and not path["conditional_evaluation_required"]
                ]
                self.assertEqual(deterministic, [])
                if case == "non exact":
                    self.assertTrue(
                        any(
                            "does not identify an exact bucket" in value
                            for value in facts.ecs_s3_access_path_uncertainties
                        )
                    )
                else:
                    self.assertEqual(len(facts.ecs_s3_access_paths), 1)

    def test_aws_bucket_policy_constraints_preserve_separate_account_evidence(
        self,
    ) -> None:
        bucket_policy = _aws_bucket_policy(
            [
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": AWS_TASK_ROLE_ARN},
                    "Action": _AWS_DELETE_BUCKET,
                    "Resource": AWS_BUCKET_ARN,
                },
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": AWS_TASK_ROLE_ARN},
                    "Action": _AWS_DELETE_BUCKET,
                    "Resource": AWS_BUCKET_ARN,
                    "Condition": {"StringEquals": {"aws:PrincipalTag/environment": "production"}},
                },
            ]
        )
        inventory, facts = _aws_service_facts(
            _aws_resources(
                [
                    aws_statement(
                        "Allow",
                        _AWS_DELETE_BUCKET,
                        AWS_BUCKET_ARN,
                    )
                ],
                bucket_policy=bucket_policy,
            )
        )
        bucket = inventory.get_by_address("aws_s3_bucket.orders")
        assert bucket is not None

        self.assertEqual(
            facts.ecs_s3_access_paths[0]["evaluation_basis"],
            "modeled_identity_policy_with_bucket_policy_constraints",
        )
        self.assertEqual(facts.ecs_s3_access_paths[0]["access_state"], "denied")
        self.assertEqual(
            facts.ecs_s3_access_paths[0]["denied_actions"],
            [_AWS_DELETE_BUCKET],
        )
        self.assertEqual(
            aws_facts(bucket).resource_policy_source_addresses,
            ["aws_s3_bucket_policy.orders"],
        )
        self.assertEqual(len(bucket.policy_statements), 2)
        self.assertEqual(bucket.policy_statements[0].effect, "Deny")
        self.assertEqual(
            bucket.policy_statements[0].actions,
            [_AWS_DELETE_BUCKET],
        )
        self.assertFalse(bucket.policy_statements[0].conditions)
        self.assertEqual(bucket.policy_statements[1].effect, "Allow")
        self.assertTrue(bucket.policy_statements[1].conditions)

        foreign_inventory, foreign_facts = _aws_service_facts(
            _aws_resources(
                [
                    aws_statement(
                        "Allow",
                        _AWS_DELETE_BUCKET,
                        AWS_BUCKET_ARN,
                    )
                ],
                task_role_arn=_AWS_FOREIGN_TASK_ROLE_ARN,
            )
        )
        self.assertEqual(foreign_inventory.primary_account_id, _AWS_ACCOUNT_ID)
        self.assertEqual(
            foreign_facts.ecs_s3_access_paths[0]["access_state"],
            "allowed",
        )
        self.assertNotEqual(
            parse_aws_account_id(foreign_facts.ecs_s3_access_paths[0]["role_arn"]),
            foreign_inventory.primary_account_id,
        )

    def test_aws_empty_bucket_prerequisite_is_not_inferred_from_lifecycle_posture(
        self,
    ) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _aws_caller_identity(),
                aws_bucket(),
                _aws_versioning("Enabled"),
                _aws_object_lock("GOVERNANCE"),
                aws_role(
                    "orders_task",
                    AWS_TASK_ROLE_ARN,
                    [
                        aws_statement(
                            "Allow",
                            _AWS_DELETE_BUCKET,
                            AWS_BUCKET_ARN,
                        )
                    ],
                ),
                aws_task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        bucket = inventory.get_by_address("aws_s3_bucket.orders")
        assert task_definition is not None
        assert bucket is not None

        self.assertEqual(
            aws_facts(task_definition).ecs_s3_access_paths[0]["matched_actions"],
            [_AWS_DELETE_BUCKET],
        )
        bucket_facts = aws_facts(bucket)
        self.assertTrue(bucket_facts.s3_versioning_enabled)
        self.assertTrue(bucket_facts.s3_object_lock_enabled)
        self.assertEqual(
            bucket_facts.s3_object_lock_default_retention_mode,
            "GOVERNANCE",
        )
        self.assertEqual(
            aws_facts(task_definition).ecs_s3_object_deletion_paths,
            [],
        )
        evidence = json.dumps(bucket.metadata_snapshot(), sort_keys=True, default=str)
        self.assertNotIn("bucket_empty", evidence)
        self.assertNotIn("successful_deletion", evidence)
        self.assertNotIn("recovered", evidence)

    def test_aws_private_topology_authority_survives_without_existing_findings(
        self,
    ) -> None:
        resources = _aws_resources(
            [
                aws_statement(
                    "Allow",
                    _AWS_DELETE_BUCKET,
                    AWS_BUCKET_ARN,
                )
            ],
            internal=True,
        )
        inventory, facts = _aws_service_facts(resources)
        load_balancer = inventory.get_by_address("aws_lb.public")
        assert load_balancer is not None
        self.assertFalse(load_balancer.public_exposure)
        self.assertEqual(
            facts.ecs_s3_access_paths[0]["matched_actions"],
            [_AWS_DELETE_BUCKET],
        )
        self.assertEqual(
            _evaluate(
                AwsNormalizer(),
                resources,
                frozenset(
                    {
                        _AWS_MUTATION_RULE,
                        _AWS_OBJECT_DISRUPTION_RULE,
                    }
                ),
            ),
            [],
        )

    def test_gcp_exact_bucket_permission_identity_and_scope_are_preserved(
        self,
    ) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _gcp_workload(),
                _gcp_bucket(),
                _gcp_custom_role([_GCP_DELETE_BUCKET]),
                _gcp_bucket_member(),
            ]
        )
        workload = inventory.get_by_address("google_cloud_run_v2_service.orders")
        bucket = inventory.get_by_address(GCP_BUCKET_ADDRESS)
        role = inventory.get_by_address(_GCP_ROLE_ADDRESS)
        member = inventory.get_by_address("google_storage_bucket_iam_member.topology")
        assert workload is not None
        assert bucket is not None
        assert role is not None
        assert member is not None

        workload_facts = gcp_facts(workload)
        self.assertEqual(
            workload_facts.service_account_email,
            GCP_SERVICE_ACCOUNT_EMAIL,
        )
        self.assertEqual(
            workload_facts.service_account_member,
            GCP_SERVICE_ACCOUNT_MEMBER,
        )
        self.assertEqual(gcp_facts(bucket).bucket_name, GCP_BUCKET_NAME)
        self.assertEqual(gcp_facts(bucket).project, GCP_PROJECT)
        role_facts = gcp_facts(role)
        self.assertEqual(
            role_facts.custom_role_permissions,
            [_GCP_DELETE_BUCKET],
        )
        self.assertEqual(role_facts.custom_role_permissions_state, "configured")
        self.assertEqual(role_facts.custom_role_stage, "GA")
        self.assertFalse(role_facts.custom_role_deleted)
        member_facts = gcp_facts(member)
        self.assertEqual(member_facts.bucket_name, f"{GCP_BUCKET_ADDRESS}.name")
        self.assertEqual(member_facts.role, _gcp_role_name())
        self.assertEqual(member_facts.member, GCP_SERVICE_ACCOUNT_MEMBER)
        self.assertEqual(
            member_facts.bindings[0]["members"],
            [GCP_SERVICE_ACCOUNT_MEMBER],
        )
        self.assertEqual(workload_facts.cloud_run_gcs_access_paths, [])
        self.assertEqual(
            workload_facts.cloud_run_gcs_object_deletion_paths,
            [],
        )

    def test_gcp_bucket_and_project_iam_scopes_remain_distinct(
        self,
    ) -> None:
        project_member = _gcp_project_member()
        bucket_member = _gcp_bucket_member(
            role="roles/storage.admin",
            name="bucket_admin",
        )
        inventory = GcpNormalizer().normalize(
            [
                _gcp_workload(),
                _gcp_bucket(),
                _gcp_other_bucket(),
                project_member,
                bucket_member,
            ]
        )
        normalized_project_member = inventory.get_by_address(project_member.address)
        normalized_bucket_member = inventory.get_by_address(bucket_member.address)
        local_bucket = inventory.get_by_address(GCP_BUCKET_ADDRESS)
        foreign_bucket = inventory.get_by_address("google_storage_bucket.archive")
        assert normalized_project_member is not None
        assert normalized_bucket_member is not None
        assert local_bucket is not None
        assert foreign_bucket is not None

        project_facts = gcp_facts(normalized_project_member)
        self.assertEqual(project_facts.project, GCP_PROJECT)
        self.assertEqual(
            project_facts.iam_scope_reference_state,
            "configured",
        )
        self.assertEqual(project_facts.role, "roles/storage.admin")
        bucket_facts = gcp_facts(normalized_bucket_member)
        self.assertEqual(
            bucket_facts.bucket_name,
            f"{GCP_BUCKET_ADDRESS}.name",
        )
        self.assertEqual(bucket_facts.role, "roles/storage.admin")
        self.assertEqual(gcp_facts(local_bucket).project, GCP_PROJECT)
        self.assertEqual(
            gcp_facts(foreign_bucket).project,
            _GCP_OTHER_PROJECT,
        )

    def test_gcp_bucket_delete_roles_retain_provider_native_scope(self) -> None:
        cases = (
            ("roles/storage.admin", "bucket"),
            ("roles/storage.editor", "bucket"),
            ("roles/storage.admin", "project"),
            ("roles/storage.editor", "project"),
            ("roles/editor", "project"),
            ("roles/owner", "project"),
        )
        for role, scope_type in cases:
            with self.subTest(role=role, scope_type=scope_type):
                iam_resource = (
                    _gcp_bucket_member(role=role) if scope_type == "bucket" else _gcp_project_member(role=role)
                )
                inventory = GcpNormalizer().normalize([iam_resource])
                source = inventory.get_by_address(iam_resource.address)
                assert source is not None
                facts = gcp_facts(source)
                self.assertEqual(facts.role, role)
                self.assertEqual(
                    facts.member,
                    GCP_SERVICE_ACCOUNT_MEMBER,
                )
                if scope_type == "project":
                    self.assertEqual(facts.project, GCP_PROJECT)
                    self.assertEqual(
                        facts.iam_scope_reference_state,
                        "configured",
                    )
                else:
                    self.assertEqual(
                        facts.bucket_name,
                        f"{GCP_BUCKET_ADDRESS}.name",
                    )

    def test_gcp_conditions_custom_role_lifecycle_and_manager_overlap_fail_closed(
        self,
    ) -> None:
        condition = {
            "title": "runtime-window",
            "expression": "request.time < timestamp('2030-01-01T00:00:00Z')",
        }
        conditional_inventory = GcpNormalizer().normalize(
            [
                _gcp_workload(),
                _gcp_bucket(),
                _gcp_custom_role([_GCP_DELETE_BUCKET, _GCP_DELETE_OBJECT]),
                _gcp_bucket_member(condition=condition),
            ]
        )
        conditional_workload = conditional_inventory.get_by_address("google_cloud_run_v2_service.orders")
        conditional_member = conditional_inventory.get_by_address("google_storage_bucket_iam_member.topology")
        assert conditional_workload is not None
        assert conditional_member is not None
        self.assertEqual(
            gcp_facts(conditional_member).bindings[0]["condition"],
            condition,
        )
        self.assertEqual(
            gcp_facts(conditional_workload).cloud_run_gcs_object_deletion_paths,
            [],
        )

        lifecycle_cases = {
            "disabled": _gcp_custom_role(
                [_GCP_DELETE_BUCKET, _GCP_DELETE_OBJECT],
                stage="DISABLED",
            ),
            "deleted": _gcp_custom_role(
                [_GCP_DELETE_BUCKET, _GCP_DELETE_OBJECT],
                deleted=True,
            ),
            "unknown deleted": _gcp_custom_role(
                [_GCP_DELETE_BUCKET, _GCP_DELETE_OBJECT],
                deleted=None,
                unknown_deleted=True,
            ),
            "unknown permissions": _gcp_custom_role(
                [_GCP_DELETE_BUCKET, _GCP_DELETE_OBJECT],
                unknown_permissions=True,
            ),
        }
        for case, role in lifecycle_cases.items():
            with self.subTest(case=case):
                inventory = GcpNormalizer().normalize(
                    [
                        _gcp_workload(),
                        _gcp_bucket(),
                        role,
                        _gcp_bucket_member(),
                    ]
                )
                workload = inventory.get_by_address("google_cloud_run_v2_service.orders")
                normalized_role = inventory.get_by_address(_GCP_ROLE_ADDRESS)
                assert workload is not None
                assert normalized_role is not None
                self.assertEqual(
                    gcp_facts(workload).cloud_run_gcs_object_deletion_paths,
                    [],
                )
                role_facts = gcp_facts(normalized_role)
                if case == "disabled":
                    self.assertEqual(role_facts.custom_role_stage, "DISABLED")
                elif case == "deleted":
                    self.assertTrue(role_facts.custom_role_deleted)
                elif case == "unknown deleted":
                    self.assertIsNone(role_facts.custom_role_deleted)
                    self.assertTrue(role_facts.custom_role_deleted_uncertainties)
                else:
                    self.assertEqual(
                        role_facts.custom_role_permissions_state,
                        "unknown",
                    )

        manager_cases = (
            (
                _gcp_bucket_member(),
                _gcp_bucket_binding(members=["serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"]),
            ),
            (
                _gcp_project_member(role=_gcp_role_name()),
                _gcp_project_binding(members=["serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"]),
            ),
        )
        for member, binding in manager_cases:
            with self.subTest(scope=member.resource_type):
                inventory = GcpNormalizer().normalize(
                    [
                        _gcp_workload(),
                        _gcp_bucket(),
                        _gcp_custom_role([_GCP_DELETE_BUCKET, _GCP_DELETE_OBJECT]),
                        member,
                        binding,
                    ]
                )
                workload = inventory.get_by_address("google_cloud_run_v2_service.orders")
                assert workload is not None
                facts = gcp_facts(workload)
                self.assertEqual(
                    facts.cloud_run_gcs_object_deletion_paths,
                    [],
                )
                self.assertTrue(
                    any(
                        "ambiguous" in value or "overlap" in value
                        for value in facts.cloud_run_gcs_object_deletion_path_uncertainties
                    )
                )

    def test_gcp_soft_delete_and_empty_bucket_prerequisite_remain_distinct(
        self,
    ) -> None:
        cases = (
            (
                "enabled",
                _gcp_bucket(soft_delete_seconds=604_800),
                "enabled",
                604_800,
            ),
            (
                "disabled",
                _gcp_bucket(soft_delete_seconds=0),
                "disabled",
                0,
            ),
            (
                "unknown",
                _gcp_bucket(
                    soft_delete_seconds=None,
                    unknown_soft_delete=True,
                ),
                "unknown",
                None,
            ),
            (
                "not observed",
                _gcp_bucket(soft_delete_seconds=None),
                "not_observed",
                None,
            ),
        )
        for case, source, expected_state, expected_duration in cases:
            with self.subTest(case=case):
                inventory = GcpNormalizer().normalize([source])
                bucket = inventory.get_by_address(GCP_BUCKET_ADDRESS)
                assert bucket is not None
                facts = gcp_facts(bucket)
                self.assertEqual(
                    facts.gcs_soft_delete_state,
                    expected_state,
                )
                self.assertEqual(
                    facts.gcs_soft_delete_retention_duration_seconds,
                    expected_duration,
                )
                evidence = json.dumps(
                    bucket.metadata_snapshot(),
                    sort_keys=True,
                    default=str,
                )
                self.assertNotIn("bucket_empty", evidence)
                self.assertNotIn("successful_deletion", evidence)
                self.assertNotIn("restored", evidence)

    def test_gcp_private_topology_authority_survives_without_existing_findings(
        self,
    ) -> None:
        resources = [
            _gcp_workload(public=False),
            gcp_public_invoker(),
            _gcp_bucket(),
            _gcp_custom_role([_GCP_DELETE_BUCKET]),
            _gcp_bucket_member(),
        ]
        inventory = GcpNormalizer().normalize(resources)
        workload = inventory.get_by_address("google_cloud_run_v2_service.orders")
        role = inventory.get_by_address(_GCP_ROLE_ADDRESS)
        assert workload is not None
        assert role is not None
        self.assertFalse(workload.public_exposure)
        self.assertEqual(
            gcp_facts(role).custom_role_permissions,
            [_GCP_DELETE_BUCKET],
        )
        self.assertEqual(
            _evaluate(
                GcpNormalizer(),
                resources,
                frozenset(
                    {
                        _GCP_MUTATION_RULE,
                        _GCP_OBJECT_DISRUPTION_RULE,
                    }
                ),
            ),
            [],
        )

    def test_azure_arm_actions_and_blob_data_actions_remain_distinct(
        self,
    ) -> None:
        resources = [
            _azure_storage_account(),
            _azure_container(),
            _azure_workload(),
            _azure_control_role(
                actions=[_AZURE_DELETE_CONTAINER],
                data_actions=[_AZURE_DELETE_BLOB],
            ),
            _azure_control_assignment(scope=("azurerm_storage_container.orders.resource_manager_id")),
        ]
        inventory, context = _azure_inventory_and_context(resources)
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert workload is not None

        data_paths = azure_facts(workload).app_service_storage_access_paths
        self.assertEqual(len(data_paths), 1)
        self.assertEqual(
            data_paths[0]["matched_data_actions"],
            [_AZURE_DELETE_BLOB.casefold()],
        )
        authority = _azure_authority(inventory, context)
        self.assertEqual(authority.state, "granted")
        assert authority.grant is not None
        self.assertEqual(
            authority.grant["matched_actions"],
            [_AZURE_DELETE_CONTAINER],
        )
        self.assertEqual(
            authority.grant["role_actions"],
            [_AZURE_DELETE_CONTAINER],
        )

        data_only_inventory, data_only_context = _azure_inventory_and_context(
            [
                _azure_storage_account(),
                _azure_container(),
                _azure_workload(),
                _azure_control_role(
                    actions=[],
                    data_actions=[_AZURE_DELETE_CONTAINER],
                ),
                _azure_control_assignment(scope=("azurerm_storage_container.orders.resource_manager_id")),
            ]
        )
        self.assertEqual(
            _azure_authority(
                data_only_inventory,
                data_only_context,
            ).state,
            "not_granted",
        )

    def test_azure_account_scope_preserves_exact_modeled_container_targets(
        self,
    ) -> None:
        archive_id = f"{AZURE_STORAGE_ACCOUNT_ID}/blobServices/default/containers/archive"
        foreign_account_id = (
            "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/foreign"
        )
        foreign_id = f"{foreign_account_id}/blobServices/default/containers/foreign"
        resources = [
            _azure_storage_account(),
            _azure_container(),
            _azure_container(name="archive", configured_name="archive"),
            _azure_container(
                name="foreign",
                configured_name="foreign",
                account_address="azurerm_storage_account.foreign",
                account_id=foreign_account_id,
            ),
            _azure_workload(),
            _azure_control_role(actions=[_AZURE_DELETE_CONTAINER]),
            _azure_control_assignment(),
        ]
        inventory, context = _azure_inventory_and_context(resources)
        expected_targets = (
            ("azurerm_storage_container.orders", AZURE_STORAGE_CONTAINER_ID),
            ("azurerm_storage_container.archive", archive_id),
        )
        for address, target_id in expected_targets:
            with self.subTest(address=address):
                container = inventory.get_by_address(address)
                assert container is not None
                self.assertEqual(
                    azure_facts(container).resolved_storage_account_address,
                    "azurerm_storage_account.orders",
                )
                result = _azure_authority(
                    inventory,
                    context,
                    target_arm_id=target_id,
                )
                self.assertEqual(result.state, "granted")
                assert result.grant is not None
                self.assertEqual(result.grant["target_arm_id"], target_id)
                self.assertEqual(
                    result.grant["assignment_scope_arm_id"],
                    AZURE_STORAGE_ACCOUNT_ID,
                )

        self.assertEqual(
            _azure_authority(
                inventory,
                context,
                target_arm_id=foreign_id,
            ).state,
            "unrelated",
        )
        self.assertIsNone(inventory.get_by_address("azurerm_storage_account.foreign"))

    def test_azure_conditions_exclusions_assignable_scope_and_identity_fail_closed(
        self,
    ) -> None:
        scope = "azurerm_storage_container.orders.resource_manager_id"
        cases = {
            "condition": (
                _azure_control_role(actions=[_AZURE_DELETE_CONTAINER]),
                _azure_control_assignment(
                    scope=scope,
                    condition=(
                        "@Resource[Microsoft.Storage/storageAccounts/"
                        "blobServices/containers:Name] StringEquals 'orders'"
                    ),
                ),
                AZURE_SYSTEM_PRINCIPAL_ID,
                "unknown",
            ),
            "unknown condition": (
                _azure_control_role(actions=[_AZURE_DELETE_CONTAINER]),
                _azure_control_assignment(
                    scope=scope,
                    unknown_values={"condition": True},
                ),
                AZURE_SYSTEM_PRINCIPAL_ID,
                "unknown",
            ),
            "unknown condition version": (
                _azure_control_role(actions=[_AZURE_DELETE_CONTAINER]),
                _azure_control_assignment(
                    scope=scope,
                    unknown_values={"condition_version": True},
                ),
                AZURE_SYSTEM_PRINCIPAL_ID,
                "unknown",
            ),
            "not action": (
                _azure_control_role(
                    actions=["Microsoft.Storage/storageAccounts/*"],
                    not_actions=[_AZURE_DELETE_CONTAINER],
                ),
                _azure_control_assignment(scope=scope),
                AZURE_SYSTEM_PRINCIPAL_ID,
                "not_granted",
            ),
            "outside assignable scope": (
                _azure_control_role(
                    actions=[_AZURE_DELETE_CONTAINER],
                    assignable_scopes=["/subscriptions/other-subscription"],
                ),
                _azure_control_assignment(scope=scope),
                AZURE_SYSTEM_PRINCIPAL_ID,
                "unknown",
            ),
            "unknown identity": (
                _azure_control_role(actions=[_AZURE_DELETE_CONTAINER]),
                _azure_control_assignment(
                    scope=scope,
                    principal_id=None,
                    unknown_values={"principal_id": True},
                ),
                AZURE_SYSTEM_PRINCIPAL_ID,
                "unknown",
            ),
            "other identity": (
                _azure_control_role(actions=[_AZURE_DELETE_CONTAINER]),
                _azure_control_assignment(
                    scope=scope,
                    principal_id="other-principal",
                ),
                AZURE_SYSTEM_PRINCIPAL_ID,
                "unrelated",
            ),
        }

        for case, (role, assignment, principal_id, expected) in cases.items():
            with self.subTest(case=case):
                inventory, context = _azure_inventory_and_context(
                    [
                        _azure_storage_account(),
                        _azure_container(),
                        _azure_workload(),
                        role,
                        assignment,
                    ]
                )
                self.assertEqual(
                    _azure_authority(
                        inventory,
                        context,
                        principal_id=principal_id,
                    ).state,
                    expected,
                )

    def test_azure_container_recovery_and_immutability_inputs_remain_distinct(
        self,
    ) -> None:
        container = _azure_container(
            has_immutability_policy=True,
            has_legal_hold=True,
        )
        resources = [
            _azure_storage_account(container_delete_days=14),
            container,
            _azure_workload(),
            _azure_control_role(actions=[_AZURE_DELETE_CONTAINER]),
            _azure_control_assignment(scope=("azurerm_storage_container.orders.resource_manager_id")),
        ]
        inventory, context = _azure_inventory_and_context(resources)
        account = inventory.get_by_address("azurerm_storage_account.orders")
        normalized_container = inventory.get_by_address("azurerm_storage_container.orders")
        assert account is not None
        assert normalized_container is not None

        self.assertEqual(
            azure_facts(account).storage_container_delete_retention_days,
            14,
        )
        self.assertTrue(container.values["has_immutability_policy"])
        self.assertTrue(container.values["has_legal_hold"])
        self.assertEqual(
            azure_facts(normalized_container).storage_container_resource_manager_id,
            AZURE_STORAGE_CONTAINER_ID,
        )
        self.assertEqual(
            _azure_authority(inventory, context).state,
            "granted",
        )
        evidence = json.dumps(
            normalized_container.metadata_snapshot(),
            sort_keys=True,
            default=str,
        )
        self.assertNotIn("successful_deletion", evidence)
        self.assertNotIn("restored", evidence)

        unknown_container = _azure_container(
            has_immutability_policy=None,
            has_legal_hold=None,
            unknown_immutability=True,
        )
        self.assertEqual(
            unknown_container.unknown_values,
            {
                "has_immutability_policy": True,
                "has_legal_hold": True,
            },
        )

    def test_azure_arm_lock_and_storage_account_deletion_stay_outside_container_compatibility(
        self,
    ) -> None:
        management_lock = azure_resource(
            AzureResourceType.MANAGEMENT_LOCK,
            {
                "name": "protect-storage-account",
                "scope": "azurerm_storage_account.orders.id",
                "lock_level": "CanNotDelete",
                "notes": "Protect the account control plane",
            },
            name="orders",
        )
        resources = [
            _azure_storage_account(),
            azure_storage_container(),
            _azure_workload(),
            _azure_control_role(
                actions=[
                    _AZURE_DELETE_CONTAINER,
                    _AZURE_DELETE_ACCOUNT,
                ]
            ),
            _azure_control_assignment(),
            management_lock,
        ]
        inventory, context = _azure_inventory_and_context(resources)

        container_authority = _azure_authority(inventory, context)
        account_authority = _azure_authority(
            inventory,
            context,
            target_arm_id=AZURE_STORAGE_ACCOUNT_ID,
            action=_AZURE_DELETE_ACCOUNT,
        )
        self.assertEqual(container_authority.state, "granted")
        self.assertEqual(account_authority.state, "granted")
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert workload is not None
        self.assertEqual(
            azure_facts(workload).app_service_blob_deletion_paths,
            [],
        )
        self.assertIsNotNone(inventory.get_by_address("azurerm_management_lock.orders"))

    def test_azure_system_and_user_assigned_identities_remain_distinct(
        self,
    ) -> None:
        app = azure_web_app(
            identity_type="SystemAssigned, UserAssigned",
            identity_ids=[AZURE_USER_IDENTITY_ID],
        )
        app.values["public_network_access_enabled"] = True
        resources = [
            _azure_storage_account(),
            _azure_container(),
            azure_user_assigned_identity(),
            app,
            _azure_control_role(actions=[_AZURE_DELETE_CONTAINER]),
            _azure_control_assignment(
                scope=("azurerm_storage_container.orders.resource_manager_id"),
                name="system_topology",
            ),
            _azure_control_assignment(
                scope=("azurerm_storage_container.orders.resource_manager_id"),
                principal_id=AZURE_USER_PRINCIPAL_ID,
                name="user_topology",
            ),
        ]
        inventory, context = _azure_inventory_and_context(resources)
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert workload is not None
        identities, uncertainties = workload_managed_identities(
            workload,
            context,
        )
        self.assertEqual(uncertainties, [])
        self.assertEqual(
            {(identity.address, identity_kind) for identity, identity_kind in identities},
            {
                ("azurerm_linux_web_app.orders", "system_assigned"),
                (
                    "azurerm_user_assigned_identity.orders_runtime",
                    "user_assigned",
                ),
            },
        )
        system = _azure_authority(
            inventory,
            context,
            assignment_address=("azurerm_role_assignment.system_topology"),
        )
        user = _azure_authority(
            inventory,
            context,
            principal_id=AZURE_USER_PRINCIPAL_ID,
            assignment_address="azurerm_role_assignment.user_topology",
        )
        self.assertEqual(system.state, "granted")
        self.assertEqual(user.state, "granted")
        assert system.grant is not None
        assert user.grant is not None
        self.assertNotEqual(
            system.grant["principal_id"],
            user.grant["principal_id"],
        )

    def test_azure_private_topology_authority_is_independent_from_exposure(
        self,
    ) -> None:
        resources = [
            _azure_storage_account(),
            _azure_container(),
            _azure_workload(public=False),
            _azure_control_role(actions=[_AZURE_DELETE_CONTAINER]),
            _azure_control_assignment(scope=("azurerm_storage_container.orders.resource_manager_id")),
        ]
        inventory, context = _azure_inventory_and_context(resources)
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert workload is not None
        self.assertFalse(azure_facts(workload).public_network_access_enabled)
        self.assertEqual(
            _azure_authority(inventory, context).state,
            "granted",
        )
        self.assertEqual(
            _evaluate(
                AzureNormalizer(),
                resources,
                frozenset(
                    {
                        _AZURE_MUTATION_RULE,
                        _AZURE_OBJECT_DISRUPTION_RULE,
                    }
                ),
            ),
            [],
        )

    def test_provider_local_evidence_does_not_cross_storage_boundaries(
        self,
    ) -> None:
        _aws_inventory, aws_workload_facts = _aws_service_facts(
            _aws_resources(
                [
                    aws_statement(
                        "Allow",
                        _AWS_DELETE_BUCKET,
                        AWS_BUCKET_ARN,
                    )
                ]
            )
        )
        aws_payload = json.dumps(
            aws_workload_facts.ecs_s3_access_paths,
            sort_keys=True,
        )

        gcp_inventory = GcpNormalizer().normalize(
            [
                _gcp_workload(),
                _gcp_bucket(),
                _gcp_custom_role([_GCP_DELETE_BUCKET]),
                _gcp_bucket_member(),
            ]
        )
        gcp_role = gcp_inventory.get_by_address(_GCP_ROLE_ADDRESS)
        gcp_member = gcp_inventory.get_by_address("google_storage_bucket_iam_member.topology")
        assert gcp_role is not None
        assert gcp_member is not None
        gcp_payload = json.dumps(
            {
                "permissions": gcp_facts(gcp_role).custom_role_permissions,
                "bindings": gcp_facts(gcp_member).bindings,
            },
            sort_keys=True,
        )

        azure_inventory, azure_context = _azure_inventory_and_context(
            [
                _azure_storage_account(),
                _azure_container(),
                _azure_workload(),
                _azure_control_role(actions=[_AZURE_DELETE_CONTAINER]),
                _azure_control_assignment(scope=("azurerm_storage_container.orders.resource_manager_id")),
            ]
        )
        azure_result = _azure_authority(
            azure_inventory,
            azure_context,
        )
        assert azure_result.grant is not None
        azure_payload = json.dumps(azure_result.grant, sort_keys=True)

        for payload, foreign_prefixes in (
            (
                aws_payload,
                ("google_", "azurerm_", "storage.buckets.delete"),
            ),
            (
                gcp_payload,
                ("aws_", "azurerm_", "s3:DeleteBucket"),
            ),
            (
                azure_payload,
                ("aws_", "google_", "storage.buckets.delete"),
            ),
        ):
            for prefix in foreign_prefixes:
                self.assertNotIn(prefix, payload)


if __name__ == "__main__":
    unittest.main()
