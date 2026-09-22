from __future__ import annotations

import json
import unittest
from typing import Any

from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _BUCKET_ARN as AWS_BUCKET_ARN,
)
from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _TASK_ROLE_ARN as AWS_TASK_ROLE_ARN,
)
from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _bucket as aws_bucket,
)
from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _resource as aws_resource,
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
    _load_balancer as aws_load_balancer,
)
from tests.providers.aws.test_aws_public_ecs_s3_mutation_rules import (
    _service as aws_service,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _SYSTEM_PRINCIPAL_ID as AZURE_SYSTEM_PRINCIPAL_ID,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _custom_role as azure_custom_role,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _custom_role_assignment as azure_custom_role_assignment,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _role_assignment as azure_role_assignment,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _storage_account as azure_storage_account,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _storage_container as azure_storage_container,
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
    _SERVICE_ACCOUNT_MEMBER as GCP_SERVICE_ACCOUNT_MEMBER,
)
from tests.providers.gcp.test_gcp_cloud_run_gcs_access_paths import (
    _bucket_iam_member as gcp_bucket_iam_member,
)
from tests.providers.gcp.test_gcp_public_cloud_run_gcs_mutation_rules import (
    _cloud_run as gcp_cloud_run,
)
from tests.providers.gcp.test_gcp_public_cloud_run_gcs_mutation_rules import (
    _public_invoker as gcp_public_invoker,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import Finding, StrideCategory, TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_AWS_MUTATION_RULE = "aws-public-ecs-s3-mutation-access"
_GCP_MUTATION_RULE = "gcp-public-cloud-run-gcs-mutation-access"
_AZURE_MUTATION_RULE = "azure-public-app-service-storage-mutation-access"

_AWS_TAMPERING_ACTIONS = frozenset(
    {
        "s3:PutObject",
        "s3:PutObjectTagging",
        "s3:DeleteObjectTagging",
        "s3:DeleteObjectVersionTagging",
    }
)
_AWS_DELETION_ACTIONS = frozenset(
    {
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
    }
)
_AWS_OUT_OF_SCOPE_ACTIONS = frozenset(
    {
        "s3:DeleteBucket",
        "s3:PutBucketPolicy",
        "s3:PutBucketVersioning",
        "s3:PutBucketObjectLockConfiguration",
    }
)
_GCP_TAMPERING_PERMISSIONS = frozenset(
    {
        "storage.objects.create",
        "storage.objects.update",
    }
)
_GCP_DELETION_PERMISSIONS = frozenset({"storage.objects.delete"})
_GCP_OUT_OF_SCOPE_PERMISSIONS = frozenset(
    {
        "storage.buckets.delete",
        "storage.buckets.update",
        "storage.objects.setIamPolicy",
    }
)
_AZURE_WRITE_ACTION = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"
_AZURE_TAG_ACTION = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags/write"
_AZURE_DELETE_ACTION = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"
_AZURE_DELETE_VERSION_ACTION = (
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/deleteBlobVersion/action"
)
_AZURE_PERMANENT_DELETE_ACTION = (
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/permanentDelete/action"
)
_AZURE_MODIFY_PERMISSIONS_ACTION = (
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/modifyPermissions/action"
)


def _aws_versioning(
    status: str | None,
    *,
    unknown: bool = False,
) -> TerraformResource:
    values = {
        "bucket": "orders-data",
        "versioning_configuration": [{} if status is None else {"status": status}],
    }
    return TerraformResource(
        address="aws_s3_bucket_versioning.orders",
        mode="managed",
        resource_type="aws_s3_bucket_versioning",
        name="orders",
        provider_name="registry.terraform.io/hashicorp/aws",
        provider_config_key="aws",
        values=values,
        unknown_values=({"versioning_configuration": [{"status": True}]} if unknown else {}),
    )


def _aws_object_lock(
    mode: str,
    *,
    days: int = 30,
) -> TerraformResource:
    return TerraformResource(
        address="aws_s3_bucket_object_lock_configuration.orders",
        mode="managed",
        resource_type="aws_s3_bucket_object_lock_configuration",
        name="orders",
        provider_name="registry.terraform.io/hashicorp/aws",
        provider_config_key="aws",
        values={
            "bucket": "orders-data",
            "object_lock_enabled": "Enabled",
            "rule": [
                {
                    "default_retention": [
                        {
                            "mode": mode,
                            "days": days,
                        }
                    ]
                }
            ],
        },
    )


def _aws_bucket_policy(
    statements: list[dict[str, Any]],
) -> TerraformResource:
    return aws_resource(
        "aws_s3_bucket_policy",
        "orders",
        {
            "bucket": "orders-data",
            "policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": statements,
                }
            ),
        },
    )


def _aws_resources(
    actions: str | list[str],
    *,
    internal: bool = False,
    condition: dict[str, object] | None = None,
) -> list[TerraformResource]:
    return [
        aws_load_balancer(internal=internal),
        aws_bucket(),
        aws_role(
            "orders_task",
            AWS_TASK_ROLE_ARN,
            [
                aws_statement(
                    "Allow",
                    actions,
                    f"{AWS_BUCKET_ARN}/*",
                    condition=condition,
                )
            ],
        ),
        aws_task_definition(execution_role_arn=None),
        aws_service(),
    ]


def _gcp_bucket(
    *,
    versioning_enabled: bool | None = True,
    retention_period: str | None = "2592000",
    retention_locked: bool | None = True,
    soft_delete_seconds: int | None = 604_800,
    unknown_soft_delete: bool = False,
    unknown_retention: bool = False,
) -> TerraformResource:
    values: dict[str, object] = {
        "name": GCP_BUCKET_NAME,
        "project": GCP_PROJECT,
        "location": "US",
        "versioning": [{"enabled": versioning_enabled}],
    }
    if retention_period is not None or retention_locked is not None:
        values["retention_policy"] = [
            {
                "retention_period": retention_period,
                "is_locked": retention_locked,
            }
        ]
    if soft_delete_seconds is not None or unknown_soft_delete:
        values["soft_delete_policy"] = [
            {
                "retention_duration_seconds": soft_delete_seconds,
            }
        ]

    unknown_values: dict[str, object] = {}
    if unknown_soft_delete:
        unknown_values["soft_delete_policy"] = [
            {
                "retention_duration_seconds": True,
            }
        ]
    if unknown_retention:
        unknown_values["retention_policy"] = [
            {
                "retention_period": True,
                "is_locked": True,
            }
        ]
    return _terraform_resource(
        GCP_BUCKET_ADDRESS,
        GcpResourceType.STORAGE_BUCKET,
        values,
        unknown_values=unknown_values,
    )


def _gcp_storage_role(
    permissions: list[str],
    *,
    role_id: str = "objectDeletionBoundary",
    unknown_permissions: bool = False,
) -> TerraformResource:
    return _terraform_resource(
        f"google_project_iam_custom_role.{role_id}",
        GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
        {
            "project": GCP_PROJECT,
            "role_id": role_id,
            "name": f"projects/{GCP_PROJECT}/roles/{role_id}",
            "permissions": permissions,
        },
        unknown_values={"permissions": True} if unknown_permissions else None,
    )


def _gcp_storage_member(
    role_id: str = "objectDeletionBoundary",
    *,
    condition: dict[str, str] | None = None,
) -> TerraformResource:
    return gcp_bucket_iam_member(
        role=f"projects/{GCP_PROJECT}/roles/{role_id}",
        condition=condition,
    )


def _gcp_bucket_binding(
    *,
    role: str = "roles/storage.objectAdmin",
) -> TerraformResource:
    return _terraform_resource(
        "google_storage_bucket_iam_binding.object_admins",
        GcpResourceType.STORAGE_BUCKET_IAM_BINDING,
        {
            "bucket": GCP_BUCKET_NAME,
            "role": role,
            "members": [
                GCP_SERVICE_ACCOUNT_MEMBER,
                "group:storage-operators@example.com",
            ],
        },
    )


def _gcp_bucket_policy(
    *,
    role: str = "roles/storage.objectAdmin",
) -> TerraformResource:
    return _terraform_resource(
        "google_storage_bucket_iam_policy.authoritative",
        GcpResourceType.STORAGE_BUCKET_IAM_POLICY,
        {
            "bucket": GCP_BUCKET_NAME,
            "policy_data": json.dumps(
                {
                    "bindings": [
                        {
                            "role": role,
                            "members": [GCP_SERVICE_ACCOUNT_MEMBER],
                        }
                    ]
                }
            ),
        },
    )


def _azure_storage_account(
    *,
    versioning_enabled: bool | None = True,
    blob_delete_days: int | None = 30,
    container_delete_days: int | None = 14,
    permanent_delete_enabled: bool | None = False,
    is_hns_enabled: bool | None = False,
    unknown_recovery: bool = False,
) -> TerraformResource:
    account = azure_storage_account()
    account.values["is_hns_enabled"] = is_hns_enabled
    account.values["blob_properties"] = [
        {
            "versioning_enabled": versioning_enabled,
            "delete_retention_policy": [
                {
                    "days": blob_delete_days,
                    "permanent_delete_enabled": permanent_delete_enabled,
                }
            ],
            "container_delete_retention_policy": [
                {
                    "days": container_delete_days,
                }
            ],
        }
    ]
    if unknown_recovery:
        account.unknown_values.update(
            {
                "is_hns_enabled": True,
                "blob_properties": [
                    {
                        "versioning_enabled": True,
                        "delete_retention_policy": [
                            {
                                "days": True,
                                "permanent_delete_enabled": True,
                            }
                        ],
                        "container_delete_retention_policy": [
                            {
                                "days": True,
                            }
                        ],
                    }
                ],
            }
        )
    return account


def _azure_public_app(*, public: bool = True) -> TerraformResource:
    app = azure_web_app()
    app.values["public_network_access_enabled"] = public
    return app


def _azure_control_plane_role() -> TerraformResource:
    return TerraformResource(
        address="azurerm_role_definition.storage_control_plane",
        mode="managed",
        resource_type=AzureResourceType.ROLE_DEFINITION,
        name="storage_control_plane",
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values={
            "id": ("/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/storage-control-plane"),
            "name": "Storage Control Plane",
            "scope": "/subscriptions/sub-0001",
            "assignable_scopes": ["/subscriptions/sub-0001"],
            "permissions": [
                {
                    "actions": [
                        "Microsoft.Storage/storageAccounts/delete",
                        "Microsoft.Storage/storageAccounts/blobServices/containers/delete",
                        "Microsoft.Storage/storageAccounts/blobServices/write",
                    ],
                    "not_actions": [],
                    "data_actions": [],
                    "not_data_actions": [],
                }
            ],
        },
    )


def _azure_control_plane_assignment() -> TerraformResource:
    return azure_role_assignment(
        role_name=None,
        role_definition_id=("azurerm_role_definition.storage_control_plane.role_definition_resource_id"),
    )


def _evaluate(
    normalizer: ProviderNormalizer,
    resources: list[Any],
    rule_id: str,
) -> list[Finding]:
    inventory = normalizer.normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({rule_id})),
    )


class PublicWorkloadObjectStorageDeletionBoundaryTests(unittest.TestCase):
    """Pin deletion prerequisites without constructing disruption paths."""

    def test_write_overwrite_metadata_and_tag_mutation_remain_tampering(
        self,
    ) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(
                    [
                        "s3:PutObject",
                        "s3:PutObjectTagging",
                        "s3:DeleteObjectTagging",
                    ]
                ),
                _AWS_MUTATION_RULE,
            ),
            (
                "gcp",
                GcpNormalizer(),
                [
                    gcp_cloud_run(),
                    gcp_public_invoker(),
                    _gcp_bucket(),
                    _gcp_storage_role(
                        [
                            "storage.objects.create",
                            "storage.objects.update",
                        ]
                    ),
                    _gcp_storage_member(),
                ],
                _GCP_MUTATION_RULE,
            ),
            (
                "azure",
                AzureNormalizer(),
                [
                    _azure_storage_account(),
                    _azure_public_app(),
                    azure_custom_role(
                        data_actions=[
                            _AZURE_WRITE_ACTION,
                            _AZURE_TAG_ACTION,
                        ]
                    ),
                    azure_custom_role_assignment(),
                ],
                _AZURE_MUTATION_RULE,
            ),
        )

        for provider, normalizer, resources, rule_id in cases:
            with self.subTest(provider=provider):
                findings = _evaluate(normalizer, resources, rule_id)
                self.assertEqual(
                    [finding.rule_id for finding in findings],
                    [rule_id],
                )
                self.assertEqual(
                    findings[0].category,
                    StrideCategory.TAMPERING,
                )

    def test_aws_preserves_operation_scope_and_recovery_boundaries(self) -> None:
        actions = [
            *_AWS_TAMPERING_ACTIONS,
            *_AWS_DELETION_ACTIONS,
            "s3:BypassGovernanceRetention",
        ]
        inventory = AwsNormalizer().normalize(
            [
                aws_load_balancer(),
                aws_bucket(),
                _aws_versioning("Enabled"),
                _aws_object_lock("GOVERNANCE"),
                aws_role(
                    "orders_task",
                    AWS_TASK_ROLE_ARN,
                    [
                        aws_statement(
                            "Allow",
                            actions,
                            f"{AWS_BUCKET_ARN}/*",
                        ),
                        aws_statement(
                            "Allow",
                            list(_AWS_OUT_OF_SCOPE_ACTIONS),
                            AWS_BUCKET_ARN,
                        ),
                    ],
                ),
                aws_task_definition(execution_role_arn=None),
                aws_service(),
            ]
        )
        workload = inventory.get_by_address("aws_ecs_service.orders")
        bucket = inventory.get_by_address("aws_s3_bucket.orders")
        load_balancer = inventory.get_by_address("aws_lb.public")
        assert workload is not None
        assert bucket is not None
        assert load_balancer is not None

        self.assertTrue(load_balancer.public_exposure)
        path = aws_facts(workload).ecs_s3_access_paths[0]
        matched_actions = set(path["matched_actions"])
        self.assertEqual(path["role_kind"], "ecs_task_role")
        self.assertEqual(path["credential_context"], "workload_runtime")
        self.assertEqual(path["role_arn"], AWS_TASK_ROLE_ARN)
        self.assertEqual(path["bucket_address"], bucket.address)
        self.assertEqual(path["bucket_arn"], AWS_BUCKET_ARN)
        self.assertEqual(
            path["resource_scopes"],
            ["all_bucket_objects", "exact_bucket"],
        )
        self.assertTrue(_AWS_TAMPERING_ACTIONS <= matched_actions)
        self.assertTrue(_AWS_DELETION_ACTIONS <= matched_actions)
        self.assertTrue(_AWS_OUT_OF_SCOPE_ACTIONS <= matched_actions)
        self.assertIn("s3:BypassGovernanceRetention", matched_actions)

        # The generic access class groups tag deletion with object deletion.
        # Exact actions remain available for the operation-specific split.
        self.assertIn("delete", path["access_classes"])
        self.assertIn("s3:DeleteObjectTagging", path["matched_actions"])
        self.assertIn("s3:DeleteObject", path["matched_actions"])

        bucket_facts = aws_facts(bucket)
        self.assertEqual(bucket_facts.s3_versioning_status, "Enabled")
        self.assertTrue(bucket_facts.s3_versioning_enabled)
        self.assertEqual(
            bucket_facts.s3_versioning_source_address,
            "aws_s3_bucket_versioning.orders",
        )
        self.assertTrue(bucket_facts.s3_object_lock_enabled)
        self.assertEqual(
            bucket_facts.s3_object_lock_default_retention_mode,
            "GOVERNANCE",
        )
        self.assertEqual(
            bucket_facts.s3_object_lock_default_retention_days,
            30,
        )

    def test_aws_exact_object_and_bounded_prefix_scopes_remain_distinct(
        self,
    ) -> None:
        exact_object = f"{AWS_BUCKET_ARN}/export.json"
        bounded_prefix = f"{AWS_BUCKET_ARN}/private/*"
        inventory = AwsNormalizer().normalize(
            [
                aws_bucket(),
                aws_role(
                    "orders_task",
                    AWS_TASK_ROLE_ARN,
                    [
                        aws_statement(
                            "Allow",
                            "s3:DeleteObject",
                            exact_object,
                        ),
                        aws_statement(
                            "Allow",
                            "s3:DeleteObject",
                            bounded_prefix,
                        ),
                    ],
                ),
                aws_task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        path = aws_facts(task_definition).ecs_s3_access_paths[0]
        self.assertEqual(path["bucket_address"], "aws_s3_bucket.orders")
        self.assertEqual(
            path["resource_scopes"],
            ["exact_object", "object_prefix"],
        )
        self.assertEqual(
            set(path["policy_resources"]),
            {exact_object, bounded_prefix},
        )
        scopes_by_resource = {
            statement["matching_resources"][0]: statement["resource_scopes"] for statement in path["policy_statements"]
        }
        self.assertEqual(
            scopes_by_resource,
            {
                exact_object: ["exact_object"],
                bounded_prefix: ["object_prefix"],
            },
        )
        self.assertNotIn("object_address", path)
        self.assertNotIn("object_version_address", path)

    def test_aws_versioning_and_object_lock_states_remain_provider_native(
        self,
    ) -> None:
        versioning_cases = (
            ("not-configured", [], None, None),
            ("enabled", [_aws_versioning("Enabled")], "Enabled", True),
            ("suspended", [_aws_versioning("Suspended")], "Suspended", False),
        )
        for case, posture_resources, expected_status, expected_enabled in versioning_cases:
            with self.subTest(case=case):
                inventory = AwsNormalizer().normalize(
                    [
                        aws_bucket(),
                        *posture_resources,
                    ]
                )
                bucket = inventory.get_by_address("aws_s3_bucket.orders")
                assert bucket is not None
                facts = aws_facts(bucket)
                self.assertEqual(facts.s3_versioning_status, expected_status)
                self.assertIs(
                    facts.s3_versioning_enabled,
                    expected_enabled,
                )

        for mode in ("GOVERNANCE", "COMPLIANCE"):
            with self.subTest(mode=mode):
                inventory = AwsNormalizer().normalize(
                    [
                        aws_bucket(),
                        _aws_object_lock(mode),
                    ]
                )
                bucket = inventory.get_by_address("aws_s3_bucket.orders")
                assert bucket is not None
                facts = aws_facts(bucket)
                self.assertTrue(facts.s3_object_lock_enabled)
                self.assertEqual(
                    facts.s3_object_lock_default_retention_mode,
                    mode,
                )

    def test_aws_bucket_policy_denies_and_conditions_constrain_access_paths(
        self,
    ) -> None:
        bucket_policy = _aws_bucket_policy(
            [
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": AWS_TASK_ROLE_ARN},
                    "Action": "s3:DeleteObjectVersion",
                    "Resource": f"{AWS_BUCKET_ARN}/*",
                },
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": AWS_TASK_ROLE_ARN},
                    "Action": "s3:DeleteObject",
                    "Resource": f"{AWS_BUCKET_ARN}/*",
                    "Condition": {
                        "StringNotEquals": {
                            "aws:PrincipalTag/break-glass": "approved",
                        }
                    },
                },
            ]
        )
        inventory = AwsNormalizer().normalize(
            [
                aws_bucket(),
                aws_role(
                    "orders_task",
                    AWS_TASK_ROLE_ARN,
                    [
                        aws_statement(
                            "Allow",
                            list(_AWS_DELETION_ACTIONS),
                            f"{AWS_BUCKET_ARN}/*",
                        )
                    ],
                ),
                bucket_policy,
                aws_task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        bucket = inventory.get_by_address("aws_s3_bucket.orders")
        assert task_definition is not None
        assert bucket is not None

        identity_path = aws_facts(task_definition).ecs_s3_access_paths[0]
        self.assertEqual(
            identity_path["evaluation_basis"],
            "modeled_identity_policy_with_bucket_policy_constraints",
        )
        self.assertEqual(identity_path["access_state"], "unknown")
        self.assertEqual(identity_path["matched_actions"], [])
        self.assertEqual(identity_path["denied_actions"], ["s3:DeleteObjectVersion"])
        self.assertEqual(identity_path["unknown_actions"], ["s3:DeleteObject"])
        self.assertEqual(len(identity_path["bucket_policy_statements"]), 2)
        self.assertTrue(identity_path["role_policy_complete"])

        self.assertEqual(
            aws_facts(bucket).resource_policy_source_addresses,
            ["aws_s3_bucket_policy.orders"],
        )
        self.assertEqual(len(bucket.policy_statements), 2)
        unconditional_deny, conditional_deny = bucket.policy_statements
        self.assertEqual(unconditional_deny.effect, "Deny")
        self.assertEqual(
            unconditional_deny.actions,
            ["s3:DeleteObjectVersion"],
        )
        self.assertFalse(unconditional_deny.conditions)
        self.assertEqual(conditional_deny.actions, ["s3:DeleteObject"])
        self.assertTrue(conditional_deny.conditions)

    def test_aws_incomplete_identity_policy_remains_independently_unknown(
        self,
    ) -> None:
        policy_arn = "arn:aws:iam::aws:policy/ExternalS3Deletion"
        inventory = AwsNormalizer().normalize(
            [
                aws_bucket(),
                aws_role(
                    "orders_task",
                    AWS_TASK_ROLE_ARN,
                    [
                        aws_statement(
                            "Allow",
                            list(_AWS_DELETION_ACTIONS),
                            f"{AWS_BUCKET_ARN}/*",
                        )
                    ],
                ),
                aws_role_policy_attachment(
                    AWS_TASK_ROLE_ARN,
                    policy_arn,
                ),
                aws_task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        bucket = inventory.get_by_address("aws_s3_bucket.orders")
        role = inventory.get_by_address("aws_iam_role.orders_task")
        assert task_definition is not None
        assert bucket is not None
        assert role is not None

        path = aws_facts(task_definition).ecs_s3_access_paths[0]
        self.assertEqual(path["modeled_access_state"], "allowed")
        self.assertEqual(path["access_state"], "unknown")
        self.assertFalse(path["role_policy_complete"])
        self.assertEqual(
            aws_facts(role).unresolved_attached_policy_arns,
            [policy_arn],
        )
        self.assertEqual(
            aws_facts(bucket).resource_policy_source_addresses,
            [],
        )

    def test_aws_tag_mutation_remains_tampering_and_private_delete_authority_survives(
        self,
    ) -> None:
        tag_findings = _evaluate(
            AwsNormalizer(),
            _aws_resources("s3:DeleteObjectTagging"),
            _AWS_MUTATION_RULE,
        )
        self.assertEqual(
            [finding.rule_id for finding in tag_findings],
            [_AWS_MUTATION_RULE],
        )

        private_resources = _aws_resources(
            "s3:DeleteObject",
            internal=True,
        )
        private_inventory = AwsNormalizer().normalize(private_resources)
        private_workload = private_inventory.get_by_address("aws_ecs_service.orders")
        private_edge = private_inventory.get_by_address("aws_lb.public")
        assert private_workload is not None
        assert private_edge is not None
        self.assertFalse(private_edge.public_exposure)
        self.assertEqual(
            aws_facts(private_workload).ecs_s3_access_paths[0]["matched_actions"],
            ["s3:DeleteObject"],
        )
        self.assertEqual(
            _evaluate(
                AwsNormalizer(),
                private_resources,
                _AWS_MUTATION_RULE,
            ),
            [],
        )

    def test_aws_non_deterministic_and_non_exact_delete_evidence_does_not_establish_access(
        self,
    ) -> None:
        condition = {
            "StringEquals": {
                "aws:PrincipalTag/environment": "production",
            }
        }
        conditional_inventory = AwsNormalizer().normalize(
            _aws_resources(
                "s3:DeleteObject",
                condition=condition,
            )
        )
        conditional_workload = conditional_inventory.get_by_address("aws_ecs_service.orders")
        assert conditional_workload is not None
        conditional_path = aws_facts(conditional_workload).ecs_s3_access_paths[0]
        self.assertEqual(conditional_path["access_state"], "unknown")
        self.assertEqual(
            conditional_path["unknown_actions"],
            ["s3:DeleteObject"],
        )

        denied_inventory = AwsNormalizer().normalize(
            [
                aws_bucket(),
                aws_role(
                    "orders_task",
                    AWS_TASK_ROLE_ARN,
                    [
                        aws_statement(
                            "Allow",
                            "s3:DeleteObject",
                            f"{AWS_BUCKET_ARN}/*",
                        ),
                        aws_statement(
                            "Deny",
                            "s3:DeleteObject",
                            f"{AWS_BUCKET_ARN}/*",
                        ),
                    ],
                ),
                aws_task_definition(execution_role_arn=None),
            ]
        )
        denied_task = denied_inventory.get_by_address("aws_ecs_task_definition.orders")
        assert denied_task is not None
        denied_path = aws_facts(denied_task).ecs_s3_access_paths[0]
        self.assertEqual(denied_path["access_state"], "denied")
        self.assertEqual(denied_path["matched_actions"], [])
        self.assertEqual(
            denied_path["denied_actions"],
            ["s3:DeleteObject"],
        )

        wildcard_inventory = AwsNormalizer().normalize(
            [
                aws_bucket(),
                aws_role(
                    "orders_task",
                    AWS_TASK_ROLE_ARN,
                    [
                        aws_statement(
                            "Allow",
                            "s3:DeleteObject",
                            "arn:aws:s3:::orders-*/*",
                        )
                    ],
                ),
                aws_task_definition(execution_role_arn=None),
            ]
        )
        wildcard_task = wildcard_inventory.get_by_address("aws_ecs_task_definition.orders")
        assert wildcard_task is not None
        wildcard_facts = aws_facts(wildcard_task)
        self.assertEqual(wildcard_facts.ecs_s3_access_paths, [])
        self.assertTrue(
            any(
                "does not identify an exact bucket" in uncertainty
                for uncertainty in wildcard_facts.ecs_s3_access_path_uncertainties
            )
        )

    def test_gcp_preserves_exact_permission_bucket_scope_and_recovery_boundaries(
        self,
    ) -> None:
        permissions = [
            *_GCP_TAMPERING_PERMISSIONS,
            *_GCP_DELETION_PERMISSIONS,
            *_GCP_OUT_OF_SCOPE_PERMISSIONS,
        ]
        bucket_source = _gcp_bucket()
        inventory = GcpNormalizer().normalize(
            [
                gcp_cloud_run(),
                gcp_public_invoker(),
                bucket_source,
                _gcp_storage_role(permissions),
                _gcp_storage_member(),
            ]
        )
        workload = inventory.get_by_address("google_cloud_run_v2_service.orders")
        bucket = inventory.get_by_address(GCP_BUCKET_ADDRESS)
        assert workload is not None
        assert bucket is not None

        self.assertTrue(workload.public_exposure)
        path = gcp_facts(workload).cloud_run_gcs_access_paths[0]
        self.assertEqual(
            path["service_account_member"],
            GCP_SERVICE_ACCOUNT_MEMBER,
        )
        self.assertEqual(path["bucket_address"], GCP_BUCKET_ADDRESS)
        self.assertEqual(path["bucket_name"], GCP_BUCKET_NAME)
        self.assertEqual(path["resource_scope"], "exact_bucket")
        self.assertEqual(path["access_state"], "granted")
        self.assertTrue(_GCP_TAMPERING_PERMISSIONS <= set(path["matched_permissions"]))
        self.assertTrue(_GCP_DELETION_PERMISSIONS <= set(path["matched_permissions"]))
        self.assertIn(
            "storage.objects.setIamPolicy",
            path["matched_permissions"],
        )
        self.assertNotIn(
            "storage.buckets.delete",
            path["matched_permissions"],
        )
        self.assertNotIn(
            "storage.buckets.update",
            path["matched_permissions"],
        )

        # Bucket IAM does not identify a concrete object or generation.
        self.assertNotIn("object_name", path)
        self.assertNotIn("object_generation", path)

        bucket_facts = gcp_facts(bucket)
        self.assertTrue(bucket_facts.versioning_enabled)
        self.assertEqual(
            bucket_facts.gcs_retention_period_seconds,
            2_592_000,
        )
        self.assertTrue(bucket_facts.gcs_retention_policy_locked)
        retention_policy = bucket_source.values["retention_policy"]
        assert isinstance(retention_policy, list)
        retention_block = retention_policy[0]
        assert isinstance(retention_block, dict)
        self.assertEqual(
            retention_block["retention_period"],
            "2592000",
        )
        self.assertEqual(
            bucket_source.values["soft_delete_policy"],
            [{"retention_duration_seconds": 604_800}],
        )

    def test_gcp_soft_delete_plan_shapes_and_retention_uncertainty_remain_distinct(
        self,
    ) -> None:
        cases = (
            (
                "configured",
                _gcp_bucket(soft_delete_seconds=604_800),
                604_800,
                False,
            ),
            (
                "disabled",
                _gcp_bucket(soft_delete_seconds=0),
                0,
                False,
            ),
            (
                "unknown",
                _gcp_bucket(
                    soft_delete_seconds=None,
                    unknown_soft_delete=True,
                ),
                None,
                True,
            ),
        )
        for case, source, expected_seconds, expected_unknown in cases:
            with self.subTest(case=case):
                soft_delete = source.values["soft_delete_policy"]
                assert isinstance(soft_delete, list)
                block = soft_delete[0]
                assert isinstance(block, dict)
                self.assertEqual(
                    block["retention_duration_seconds"],
                    expected_seconds,
                )
                self.assertIs(
                    bool(source.unknown_values.get("soft_delete_policy")),
                    expected_unknown,
                )

        unknown_retention = _gcp_bucket(
            retention_period=None,
            retention_locked=None,
            unknown_retention=True,
        )
        inventory = GcpNormalizer().normalize([unknown_retention])
        bucket = inventory.get_by_address(GCP_BUCKET_ADDRESS)
        assert bucket is not None
        facts = gcp_facts(bucket)
        self.assertIsNone(facts.gcs_retention_period_seconds)
        self.assertIsNone(facts.gcs_retention_policy_locked)
        self.assertEqual(
            facts.gcs_retention_policy_uncertainties,
            [
                "retention_policy.retention_period is unknown after planning",
                "retention_policy.is_locked is unknown after planning",
            ],
        )

    def test_gcp_conditional_incomplete_and_overlapping_managers_remain_distinct(
        self,
    ) -> None:
        condition = {
            "title": "deletion-window",
            "expression": ("request.time < timestamp('2027-01-01T00:00:00Z')"),
        }
        conditional_inventory = GcpNormalizer().normalize(
            [
                gcp_cloud_run(),
                _gcp_bucket(),
                _gcp_storage_role(["storage.objects.delete"]),
                _gcp_storage_member(condition=condition),
            ]
        )
        workload = conditional_inventory.get_by_address("google_cloud_run_v2_service.orders")
        assert workload is not None
        conditional_path = gcp_facts(workload).cloud_run_gcs_access_paths[0]
        self.assertEqual(conditional_path["condition"], condition)
        self.assertEqual(
            conditional_path["access_state"],
            "conditional",
        )

        incomplete_inventory = GcpNormalizer().normalize(
            [
                gcp_cloud_run(),
                _gcp_bucket(),
                _gcp_storage_role(
                    [],
                    unknown_permissions=True,
                ),
                _gcp_storage_member(),
            ]
        )
        incomplete_workload = incomplete_inventory.get_by_address("google_cloud_run_v2_service.orders")
        assert incomplete_workload is not None
        incomplete_facts = gcp_facts(incomplete_workload)
        self.assertEqual(incomplete_facts.cloud_run_gcs_access_paths, [])
        self.assertTrue(
            any(
                "does not resolve to deterministic permissions" in uncertainty
                for uncertainty in incomplete_facts.cloud_run_gcs_access_path_uncertainties
            )
        )

        overlapping_inventory = GcpNormalizer().normalize(
            [
                gcp_cloud_run(),
                _gcp_bucket(),
                gcp_bucket_iam_member(role="roles/storage.objectAdmin"),
                _gcp_bucket_binding(),
                _gcp_bucket_policy(),
            ]
        )
        bucket = overlapping_inventory.get_by_address(GCP_BUCKET_ADDRESS)
        assert bucket is not None
        sources = {binding["source"] for binding in gcp_facts(bucket).bindings}
        self.assertEqual(
            sources,
            {
                "google_storage_bucket_iam_member.orders_access",
                "google_storage_bucket_iam_binding.object_admins",
                "google_storage_bucket_iam_policy.authoritative",
            },
        )

    def test_gcp_private_delete_authority_survives_without_public_finding(
        self,
    ) -> None:
        resources = [
            gcp_cloud_run(public_ingress=False),
            gcp_public_invoker(),
            _gcp_bucket(),
            _gcp_storage_role(["storage.objects.delete"]),
            _gcp_storage_member(),
        ]
        inventory = GcpNormalizer().normalize(resources)
        workload = inventory.get_by_address("google_cloud_run_v2_service.orders")
        assert workload is not None
        self.assertFalse(workload.public_exposure)
        self.assertEqual(
            gcp_facts(workload).cloud_run_gcs_access_paths[0]["matched_permissions"],
            ["storage.objects.delete"],
        )
        self.assertEqual(
            _evaluate(
                GcpNormalizer(),
                resources,
                _GCP_MUTATION_RULE,
            ),
            [],
        )

    def test_azure_preserves_exact_blob_operations_scope_and_recovery_inputs(
        self,
    ) -> None:
        data_actions = [
            _AZURE_WRITE_ACTION,
            _AZURE_TAG_ACTION,
            _AZURE_DELETE_ACTION,
            _AZURE_DELETE_VERSION_ACTION,
            _AZURE_PERMANENT_DELETE_ACTION,
            _AZURE_MODIFY_PERMISSIONS_ACTION,
        ]
        account_source = _azure_storage_account()
        inventory = AzureNormalizer().normalize(
            [
                account_source,
                azure_storage_container(),
                _azure_public_app(),
                azure_custom_role(data_actions=data_actions),
                azure_custom_role_assignment(scope=("azurerm_storage_container.orders.resource_manager_id")),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        account = inventory.get_by_address("azurerm_storage_account.orders")
        container = inventory.get_by_address("azurerm_storage_container.orders")
        assert workload is not None
        assert account is not None
        assert container is not None

        self.assertTrue(workload.public_access_configured)
        path = azure_facts(workload).app_service_storage_access_paths[0]
        self.assertEqual(path["identity_kind"], "system_assigned")
        self.assertEqual(
            path["principal_id"],
            AZURE_SYSTEM_PRINCIPAL_ID,
        )
        self.assertEqual(
            path["storage_resource_address"],
            container.address,
        )
        self.assertEqual(
            path["storage_account_address"],
            account.address,
        )
        self.assertEqual(path["container_address"], container.address)
        self.assertEqual(
            path["resource_scope"],
            "exact_storage_container",
        )
        self.assertEqual(path["access_state"], "granted")
        self.assertEqual(
            set(path["matched_data_actions"]),
            {action.casefold() for action in data_actions},
        )

        account_facts = azure_facts(account)
        self.assertTrue(account_facts.storage_blob_versioning_enabled)
        self.assertEqual(
            account_facts.storage_blob_delete_retention_days,
            30,
        )
        self.assertEqual(
            account_facts.storage_container_delete_retention_days,
            14,
        )

        blob_properties = account_source.values["blob_properties"]
        assert isinstance(blob_properties, list)
        recovery = blob_properties[0]
        assert isinstance(recovery, dict)
        self.assertEqual(
            recovery["delete_retention_policy"],
            [
                {
                    "days": 30,
                    "permanent_delete_enabled": False,
                }
            ],
        )
        self.assertFalse(account_source.values["is_hns_enabled"])

    def test_azure_flat_hns_and_permanent_delete_plan_shapes_remain_distinct(
        self,
    ) -> None:
        cases = (
            (
                "flat-recoverable",
                _azure_storage_account(
                    versioning_enabled=True,
                    permanent_delete_enabled=False,
                    is_hns_enabled=False,
                ),
                True,
                False,
                False,
            ),
            (
                "flat-permanent-delete",
                _azure_storage_account(
                    versioning_enabled=True,
                    permanent_delete_enabled=True,
                    is_hns_enabled=False,
                ),
                True,
                True,
                False,
            ),
            (
                "hns-soft-delete",
                _azure_storage_account(
                    versioning_enabled=False,
                    permanent_delete_enabled=False,
                    is_hns_enabled=True,
                ),
                False,
                False,
                True,
            ),
            (
                "unknown",
                _azure_storage_account(
                    versioning_enabled=None,
                    blob_delete_days=None,
                    container_delete_days=None,
                    permanent_delete_enabled=None,
                    is_hns_enabled=None,
                    unknown_recovery=True,
                ),
                None,
                None,
                None,
            ),
        )
        for (
            case,
            source,
            expected_versioning,
            expected_permanent_delete,
            expected_hns,
        ) in cases:
            with self.subTest(case=case):
                blob_properties = source.values["blob_properties"]
                assert isinstance(blob_properties, list)
                block = blob_properties[0]
                assert isinstance(block, dict)
                retention = block["delete_retention_policy"]
                assert isinstance(retention, list)
                retention_block = retention[0]
                assert isinstance(retention_block, dict)
                self.assertIs(
                    block["versioning_enabled"],
                    expected_versioning,
                )
                self.assertIs(
                    retention_block["permanent_delete_enabled"],
                    expected_permanent_delete,
                )
                self.assertIs(
                    source.values["is_hns_enabled"],
                    expected_hns,
                )

    def test_azure_conditional_denied_incomplete_and_unresolved_delete_evidence_fails_closed(
        self,
    ) -> None:
        condition = "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringEquals 'orders'"
        conditional_inventory = AzureNormalizer().normalize(
            [
                _azure_storage_account(),
                _azure_public_app(),
                azure_custom_role(data_actions=[_AZURE_DELETE_ACTION]),
                azure_role_assignment(
                    role_name=None,
                    role_definition_id=("azurerm_role_definition.blob_writer.role_definition_resource_id"),
                    condition=condition,
                ),
            ]
        )
        conditional_workload = conditional_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert conditional_workload is not None
        conditional_path = azure_facts(conditional_workload).app_service_storage_access_paths[0]
        self.assertEqual(
            conditional_path["access_state"],
            "conditional",
        )

        denied_inventory = AzureNormalizer().normalize(
            [
                _azure_storage_account(),
                _azure_public_app(),
                azure_custom_role(
                    data_actions=[_AZURE_DELETE_ACTION],
                    not_data_actions=[_AZURE_DELETE_ACTION],
                ),
                azure_custom_role_assignment(),
            ]
        )
        denied_workload = denied_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert denied_workload is not None
        self.assertEqual(
            azure_facts(denied_workload).app_service_storage_access_paths,
            [],
        )

        unresolved_role = azure_custom_role(
            data_actions=[],
            unknown_values={
                "permissions": [
                    {
                        "data_actions": True,
                    }
                ]
            },
        )
        incomplete_inventory = AzureNormalizer().normalize(
            [
                _azure_storage_account(),
                _azure_public_app(),
                unresolved_role,
                azure_custom_role_assignment(),
            ]
        )
        incomplete_workload = incomplete_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert incomplete_workload is not None
        incomplete_facts = azure_facts(incomplete_workload)
        self.assertEqual(
            incomplete_facts.app_service_storage_access_paths,
            [],
        )
        self.assertTrue(
            any(
                "data actions are unresolved" in uncertainty
                for uncertainty in incomplete_facts.app_service_storage_access_path_uncertainties
            )
        )

        unresolved_inventory = AzureNormalizer().normalize(
            [
                _azure_storage_account(),
                _azure_public_app(),
                azure_custom_role(data_actions=[_AZURE_DELETE_ACTION]),
                azure_custom_role_assignment(scope="azurerm_storage_container.missing.id"),
            ]
        )
        unresolved_workload = unresolved_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert unresolved_workload is not None
        unresolved_facts = azure_facts(unresolved_workload)
        self.assertEqual(
            unresolved_facts.app_service_storage_access_paths,
            [],
        )
        self.assertTrue(
            any(
                "does not resolve to an exact Storage Account or container" in uncertainty
                for uncertainty in unresolved_facts.app_service_storage_access_path_uncertainties
            )
        )

    def test_azure_private_delete_authority_survives_without_public_finding(
        self,
    ) -> None:
        resources = [
            _azure_storage_account(),
            _azure_public_app(public=False),
            azure_custom_role(data_actions=[_AZURE_DELETE_ACTION]),
            azure_custom_role_assignment(),
        ]
        inventory = AzureNormalizer().normalize(resources)
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert workload is not None
        self.assertFalse(workload.public_access_configured)
        self.assertEqual(
            azure_facts(workload).app_service_storage_access_paths[0]["matched_data_actions"],
            [_AZURE_DELETE_ACTION.casefold()],
        )
        self.assertEqual(
            _evaluate(
                AzureNormalizer(),
                resources,
                _AZURE_MUTATION_RULE,
            ),
            [],
        )

    def test_out_of_scope_destruction_delegation_and_recovery_control_stay_separate(
        self,
    ) -> None:
        aws_inventory = AwsNormalizer().normalize(
            [
                aws_bucket(),
                aws_role(
                    "orders_task",
                    AWS_TASK_ROLE_ARN,
                    [
                        aws_statement(
                            "Allow",
                            list(_AWS_OUT_OF_SCOPE_ACTIONS),
                            AWS_BUCKET_ARN,
                        )
                    ],
                ),
                aws_task_definition(execution_role_arn=None),
            ]
        )
        aws_task = aws_inventory.get_by_address("aws_ecs_task_definition.orders")
        assert aws_task is not None
        aws_path = aws_facts(aws_task).ecs_s3_access_paths[0]
        self.assertEqual(
            set(aws_path["matched_actions"]),
            _AWS_OUT_OF_SCOPE_ACTIONS,
        )
        self.assertEqual(
            aws_path["access_classes"],
            ["administrative"],
        )
        self.assertFalse(_AWS_DELETION_ACTIONS & set(aws_path["matched_actions"]))

        gcp_inventory = GcpNormalizer().normalize(
            [
                gcp_cloud_run(),
                _gcp_bucket(),
                _gcp_storage_role(
                    list(_GCP_OUT_OF_SCOPE_PERMISSIONS),
                ),
                _gcp_storage_member(),
            ]
        )
        gcp_workload = gcp_inventory.get_by_address("google_cloud_run_v2_service.orders")
        assert gcp_workload is not None
        gcp_path = gcp_facts(gcp_workload).cloud_run_gcs_access_paths[0]
        self.assertEqual(
            gcp_path["matched_permissions"],
            ["storage.objects.setIamPolicy"],
        )
        self.assertEqual(
            gcp_path["access_classes"],
            ["administrative"],
        )

        azure_inventory = AzureNormalizer().normalize(
            [
                _azure_storage_account(),
                _azure_public_app(),
                _azure_control_plane_role(),
                _azure_control_plane_assignment(),
            ]
        )
        azure_workload = azure_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert azure_workload is not None
        self.assertEqual(
            azure_facts(azure_workload).app_service_storage_access_paths,
            [],
        )

        delegated_inventory = AzureNormalizer().normalize(
            [
                _azure_storage_account(),
                _azure_public_app(),
                azure_custom_role(data_actions=[_AZURE_MODIFY_PERMISSIONS_ACTION]),
                azure_custom_role_assignment(),
            ]
        )
        delegated_workload = delegated_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert delegated_workload is not None
        delegated_path = azure_facts(delegated_workload).app_service_storage_access_paths[0]
        self.assertEqual(
            delegated_path["access_classes"],
            ["administrative"],
        )
        self.assertEqual(
            delegated_path["matched_data_actions"],
            [_AZURE_MODIFY_PERMISSIONS_ACTION.casefold()],
        )

    def test_provider_local_evidence_does_not_cross_storage_boundaries(
        self,
    ) -> None:
        aws_inventory = AwsNormalizer().normalize(
            _aws_resources(
                ["s3:PutObject", "s3:DeleteObject"],
            )
        )
        gcp_inventory = GcpNormalizer().normalize(
            [
                gcp_cloud_run(),
                _gcp_bucket(),
                _gcp_storage_role(
                    [
                        "storage.objects.create",
                        "storage.objects.delete",
                    ]
                ),
                _gcp_storage_member(),
            ]
        )
        azure_inventory = AzureNormalizer().normalize(
            [
                _azure_storage_account(),
                _azure_public_app(),
                azure_custom_role(
                    data_actions=[
                        _AZURE_WRITE_ACTION,
                        _AZURE_DELETE_ACTION,
                    ]
                ),
                azure_custom_role_assignment(),
            ]
        )
        payloads = {
            "aws": json.dumps(
                [
                    {
                        "address": resource.address,
                        "metadata": resource.metadata,
                    }
                    for resource in aws_inventory.resources
                ],
                sort_keys=True,
                default=str,
            ),
            "gcp": json.dumps(
                [
                    {
                        "address": resource.address,
                        "metadata": resource.metadata,
                    }
                    for resource in gcp_inventory.resources
                ],
                sort_keys=True,
                default=str,
            ),
            "azure": json.dumps(
                [
                    {
                        "address": resource.address,
                        "metadata": resource.metadata,
                    }
                    for resource in azure_inventory.resources
                ],
                sort_keys=True,
                default=str,
            ),
        }
        foreign_prefixes = {
            "aws": ("google_", "azurerm_"),
            "gcp": ("aws_", "azurerm_"),
            "azure": ("aws_", "google_"),
        }
        for provider, payload in payloads.items():
            with self.subTest(provider=provider):
                for prefix in foreign_prefixes[provider]:
                    self.assertNotIn(prefix, payload)


if __name__ == "__main__":
    unittest.main()
