from __future__ import annotations

import json
import unittest
from typing import Any

from tests.providers.aws.test_aws_ecs_kms_operation_paths import (
    _KEY_ARNS as AWS_KEY_ARNS,
)
from tests.providers.aws.test_aws_ecs_kms_operation_paths import (
    _ROOT_ARN as AWS_ROOT_ARN,
)
from tests.providers.aws.test_aws_ecs_kms_operation_paths import (
    _TASK_ROLE_ARN as AWS_TASK_ROLE_ARN,
)
from tests.providers.aws.test_aws_ecs_kms_operation_paths import (
    _key as aws_key,
)
from tests.providers.aws.test_aws_ecs_kms_operation_paths import (
    _policy as aws_policy,
)
from tests.providers.aws.test_aws_ecs_kms_operation_paths import (
    _resource as aws_resource,
)
from tests.providers.aws.test_aws_ecs_kms_operation_paths import (
    _role as aws_role,
)
from tests.providers.aws.test_aws_ecs_kms_operation_paths import (
    _statement as aws_statement,
)
from tests.providers.aws.test_aws_ecs_s3_access_paths import _caller_identity
from tests.providers.aws.test_aws_kms_encryption_dependencies import (
    _ALIAS_ARN as AWS_ALIAS_ARN,
)
from tests.providers.aws.test_aws_kms_encryption_dependencies import (
    _alias as aws_alias,
)
from tests.providers.aws.test_aws_kms_encryption_dependencies import (
    _resource as aws_dependency_resource,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _STORAGE_ACCOUNT_ID as AZURE_STORAGE_ACCOUNT_ID,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _STORAGE_CONTAINER_ID as AZURE_STORAGE_CONTAINER_ID,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _USER_PRINCIPAL_ID as AZURE_USER_PRINCIPAL_ID,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _role_assignment as azure_storage_role_assignment,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _storage_container as azure_storage_container,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _user_assigned_identity as azure_user_assigned_identity,
)
from tests.providers.azure.test_azure_key_vault_encryption_dependencies import (
    _resource as azure_dependency_resource,
)
from tests.providers.gcp.test_gcp_cloud_run_gcs_access_paths import (
    _BUCKET_ADDRESS as GCP_BUCKET_ADDRESS,
)
from tests.providers.gcp.test_gcp_cloud_run_gcs_access_paths import (
    _BUCKET_NAME as GCP_BUCKET_NAME,
)
from tests.providers.gcp.test_gcp_cloud_run_gcs_access_paths import (
    _bucket_iam_member as gcp_bucket_iam_member,
)
from tests.providers.gcp.test_gcp_cloud_run_kms_operation_paths import (
    _EMAIL as GCP_SERVICE_ACCOUNT_EMAIL,
)
from tests.providers.gcp.test_gcp_cloud_run_kms_operation_paths import (
    _MEMBER as GCP_SERVICE_ACCOUNT_MEMBER,
)
from tests.providers.gcp.test_gcp_cloud_run_kms_operation_paths import (
    _RING as GCP_KEY_RING,
)
from tests.providers.gcp.test_gcp_cloud_run_kms_operation_paths import (
    _cloud_run as gcp_cloud_run,
)
from tests.providers.gcp.test_gcp_cloud_run_kms_operation_paths import (
    _key as gcp_key,
)
from tests.providers.gcp.test_gcp_cloud_run_kms_operation_paths import (
    _key_member as gcp_key_member,
)
from tests.providers.gcp.test_gcp_cloud_run_kms_operation_paths import (
    _version as gcp_version,
)
from tests.providers.gcp.test_gcp_kms_encryption_dependencies import (
    _resource as gcp_dependency_resource,
)
from tests.providers.test_public_workload_managed_key_operation_boundaries import (
    _AZURE_CRYPTO_USER_ROLE_ID,
    _AZURE_RUNTIME_PRINCIPAL_ID,
    _AZURE_VAULT_ID,
    _AZURE_VAULT_URI,
    _aws_ecs_service,
    _aws_public_edge,
    _aws_task_definition,
    _azure_key,
    _azure_role_assignment,
    _azure_vault,
    _azure_web_app,
    _gcp_public_invoker,
)
from tfstride.models import (
    TerraformReferenceProvenance,
    TerraformReferenceResolution,
    TerraformReferenceResolutionState,
    TerraformReferenceTarget,
    TerraformResource,
)
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_AWS_BUCKET_ARN = "arn:aws:s3:::orders"
_GCP_KEY_PATH = f"{GCP_KEY_RING}/cryptoKeys/data"
_GCP_VERSION_PATH = f"{_GCP_KEY_PATH}/cryptoKeyVersions/1"
_AZURE_KEY_VERSION = "v-001"
_AZURE_KEY_VERSIONLESS_URI = f"{_AZURE_VAULT_URI}/keys/data"
_AZURE_KEY_URI = f"{_AZURE_KEY_VERSIONLESS_URI}/{_AZURE_KEY_VERSION}"
_AZURE_KEY_VERSIONLESS_RESOURCE_ID = f"{_AZURE_VAULT_ID}/keys/data"
_AZURE_KEY_RESOURCE_ID = f"{_AZURE_KEY_VERSIONLESS_RESOURCE_ID}/{_AZURE_KEY_VERSION}"


def _reference_resolution(
    path: tuple[str | int, ...],
    targets: tuple[tuple[str, str], ...],
    *,
    state: TerraformReferenceResolutionState,
) -> TerraformReferenceResolution:
    references = tuple(f"{address}{suffix}" for address, suffix in targets)
    return TerraformReferenceResolution(
        path=path,
        state=state,
        provenance=TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
        references=references,
        targets=tuple(
            TerraformReferenceTarget(address=address, reference=reference)
            for (address, _), reference in zip(targets, references, strict=True)
        ),
    )


def _aws_identity_statement(
    effect: str,
    actions: str | list[str],
    resources: str | list[str],
    *,
    condition: dict[str, Any] | None = None,
) -> dict[str, Any]:
    statement: dict[str, Any] = {
        "Effect": effect,
        "Action": actions,
        "Resource": resources,
    }
    if condition is not None:
        statement["Condition"] = condition
    return statement


def _aws_key_policy(*, direct_runtime_allow: bool) -> str:
    principal = AWS_TASK_ROLE_ARN if direct_runtime_allow else AWS_ROOT_ARN
    actions: str | list[str] = "kms:Decrypt" if direct_runtime_allow else "kms:*"
    return aws_policy(
        aws_statement(
            "Allow",
            actions,
            "*",
            principal=principal,
        )
    )


def _aws_role_resource(
    *,
    kms_condition: dict[str, Any] | None = None,
    s3_condition: dict[str, Any] | None = None,
    deny_decrypt: bool = False,
) -> TerraformResource:
    statements = [
        _aws_identity_statement(
            "Allow",
            "kms:Decrypt",
            AWS_KEY_ARNS["data"],
            condition=kms_condition,
        ),
        _aws_identity_statement(
            "Allow",
            "s3:GetObject",
            f"{_AWS_BUCKET_ARN}/*",
            condition=s3_condition,
        ),
    ]
    if deny_decrypt:
        statements.append(
            _aws_identity_statement(
                "Deny",
                "kms:Decrypt",
                AWS_KEY_ARNS["data"],
            )
        )
    return aws_role(
        "orders_task",
        AWS_TASK_ROLE_ARN,
        statements,
    )


def _aws_bucket() -> TerraformResource:
    return aws_resource(
        "aws_s3_bucket",
        "orders",
        {
            "id": "orders",
            "bucket": "orders",
            "arn": _AWS_BUCKET_ARN,
        },
    )


def _aws_bucket_encryption(
    *,
    key_reference: str | None = AWS_ALIAS_ARN,
    resolution: TerraformReferenceResolution | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": "orders",
        "bucket": "orders",
        "rule": [
            {
                "apply_server_side_encryption_by_default": [
                    {
                        "sse_algorithm": ("aws:kms" if key_reference is not None else None),
                        "kms_master_key_id": key_reference,
                    }
                ]
            }
        ],
    }
    unknown_values: dict[str, Any] | None = None
    if key_reference is None:
        unknown_values = {
            "rule": [
                {
                    "apply_server_side_encryption_by_default": [
                        {
                            "sse_algorithm": True,
                            "kms_master_key_id": True,
                        }
                    ]
                }
            ]
        }
    resource = aws_dependency_resource(
        "aws_s3_bucket_server_side_encryption_configuration",
        "orders",
        values,
        unknown_values=unknown_values,
        reference_resolutions=(resolution,) if resolution is not None else (),
    )
    resource.provider_config_key = "aws"
    return resource


def _aws_resources(
    *,
    kms_condition: dict[str, Any] | None = None,
    s3_condition: dict[str, Any] | None = None,
    deny_decrypt: bool = False,
    unresolved_policy: bool = False,
    ambiguous_dependency: bool = False,
) -> list[TerraformResource]:
    direct_runtime_allow = kms_condition is None
    resources = [
        *_aws_public_edge(),
        _caller_identity(),
        _aws_bucket(),
        aws_key(
            "data",
            "ENCRYPT_DECRYPT",
            _aws_key_policy(direct_runtime_allow=direct_runtime_allow),
        ),
        aws_alias(),
        _aws_role_resource(
            kms_condition=kms_condition,
            s3_condition=s3_condition,
            deny_decrypt=deny_decrypt,
        ),
        _aws_task_definition(),
        _aws_ecs_service(),
    ]
    if ambiguous_dependency:
        resources.extend(
            [
                aws_key(
                    "signing",
                    "SIGN_VERIFY",
                    _aws_key_policy(direct_runtime_allow=True),
                ),
                _aws_bucket_encryption(
                    key_reference=None,
                    resolution=_reference_resolution(
                        (
                            "rule",
                            0,
                            "apply_server_side_encryption_by_default",
                            0,
                            "kms_master_key_id",
                        ),
                        (
                            ("aws_kms_key.data", ".arn"),
                            ("aws_kms_key.signing", ".arn"),
                        ),
                        state=TerraformReferenceResolutionState.AMBIGUOUS,
                    ),
                ),
            ]
        )
    else:
        resources.append(_aws_bucket_encryption())
    if unresolved_policy:
        resources.append(
            aws_resource(
                "aws_iam_role_policy_attachment",
                "external",
                {
                    "role": AWS_TASK_ROLE_ARN,
                    "policy_arn": "arn:aws:iam::aws:policy/ExternalKmsAccess",
                },
            )
        )
    for resource in resources:
        resource.provider_config_key = "aws"
    return resources


def _gcp_bucket(
    *,
    key_reference: str | None = _GCP_KEY_PATH,
    resolution: TerraformReferenceResolution | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": GCP_BUCKET_NAME,
        "name": GCP_BUCKET_NAME,
        "project": "tfstride-demo",
        "location": "US",
        "encryption": [{"default_kms_key_name": key_reference}],
    }
    unknown_values: dict[str, Any] | None = None
    if key_reference is None:
        unknown_values = {"encryption": [{"default_kms_key_name": True}]}
    return gcp_dependency_resource(
        GcpResourceType.STORAGE_BUCKET,
        "orders",
        values,
        unknown_values=unknown_values,
        reference_resolutions=(resolution,) if resolution is not None else (),
    )


def _gcp_resources(
    *,
    kms_condition: dict[str, str] | None = None,
    bucket_condition: dict[str, str] | None = None,
    kms_member: str = GCP_SERVICE_ACCOUNT_MEMBER,
    ambiguous_dependency: bool = False,
) -> list[TerraformResource]:
    resources = [
        gcp_cloud_run(public=True),
        _gcp_public_invoker(),
        gcp_key("data", "ENCRYPT_DECRYPT"),
        gcp_version("data", "GOOGLE_SYMMETRIC_ENCRYPTION"),
        gcp_key_member(
            "runtime_decrypter",
            "data",
            "roles/cloudkms.cryptoKeyDecrypter",
            member=kms_member,
            condition=kms_condition,
        ),
        gcp_bucket_iam_member(condition=bucket_condition),
    ]
    if ambiguous_dependency:
        resources.extend(
            [
                gcp_key("audit", "ENCRYPT_DECRYPT"),
                _gcp_bucket(
                    key_reference=None,
                    resolution=_reference_resolution(
                        ("encryption", 0, "default_kms_key_name"),
                        (
                            ("google_kms_crypto_key.data", ".id"),
                            ("google_kms_crypto_key.audit", ".id"),
                        ),
                        state=TerraformReferenceResolutionState.AMBIGUOUS,
                    ),
                ),
            ]
        )
    else:
        resources.append(_gcp_bucket())
    return resources


def _azure_storage_account(
    *,
    key_reference: str | None = _AZURE_KEY_URI,
    resolution: TerraformReferenceResolution | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": AZURE_STORAGE_ACCOUNT_ID,
        "name": "ordersdata",
        "public_network_access_enabled": False,
        "network_rules": [{"default_action": "Deny"}],
        "customer_managed_key": [
            {
                "key_vault_key_id": key_reference,
                "user_assigned_identity_id": "identity-id",
            }
        ],
    }
    unknown_values: dict[str, Any] | None = None
    if key_reference is None:
        unknown_values = {
            "customer_managed_key": [
                {
                    "key_vault_key_id": True,
                }
            ]
        }
    return azure_dependency_resource(
        AzureResourceType.STORAGE_ACCOUNT,
        "orders",
        values,
        unknown_values=unknown_values,
        reference_resolutions=(resolution,) if resolution is not None else (),
    )


def _azure_resources(
    *,
    key_condition: str | None = None,
    storage_condition: str | None = None,
    key_principal_id: str = _AZURE_RUNTIME_PRINCIPAL_ID,
    ambiguous_dependency: bool = False,
) -> list[TerraformResource]:
    key_role = _azure_role_assignment(
        "key_access",
        role_id=_AZURE_CRYPTO_USER_ROLE_ID,
        role_name="Key Vault Crypto User",
        condition=key_condition,
    )
    key_role.values["principal_id"] = key_principal_id
    storage_role = azure_storage_role_assignment(
        principal_id=_AZURE_RUNTIME_PRINCIPAL_ID,
        scope="azurerm_storage_container.orders.resource_manager_id",
        role_name="Storage Blob Data Reader",
        role_definition_id=(
            "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/"
            "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"
        ),
        condition=storage_condition,
    )
    resources = [
        _azure_vault(rbac_enabled=True),
        _azure_key(
            "data",
            key_type="RSA-HSM",
            key_opts=["decrypt", "unwrapKey"],
        ),
        _azure_web_app(public=True),
        key_role,
        azure_storage_container(),
        storage_role,
    ]
    if ambiguous_dependency:
        resources.extend(
            [
                _azure_key(
                    "audit",
                    key_type="RSA",
                    key_opts=["decrypt"],
                ),
                _azure_storage_account(
                    key_reference=None,
                    resolution=_reference_resolution(
                        ("customer_managed_key", 0, "key_vault_key_id"),
                        (
                            ("azurerm_key_vault_key.data", ".id"),
                            ("azurerm_key_vault_key.audit", ".id"),
                        ),
                        state=TerraformReferenceResolutionState.AMBIGUOUS,
                    ),
                ),
            ]
        )
    else:
        resources.append(_azure_storage_account())
    return resources


def _aws_exact_key_mismatch_resources() -> list[TerraformResource]:
    resources = _aws_resources()
    role = next(resource for resource in resources if resource.address == "aws_iam_role.orders_task")
    data_key = next(resource for resource in resources if resource.address == "aws_kms_key.data")

    inline_policies = role.values["inline_policy"]
    assert isinstance(inline_policies, list)
    policy = inline_policies[0]["policy"]
    assert isinstance(policy, str)
    policy_document = json.loads(policy)
    for statement in policy_document["Statement"]:
        if statement.get("Action") == "kms:Decrypt":
            statement["Resource"] = AWS_KEY_ARNS["signing"]
    inline_policies[0]["policy"] = json.dumps(policy_document)

    data_key.values["policy"] = _aws_key_policy(direct_runtime_allow=False)
    resources.append(
        aws_key(
            "signing",
            "ENCRYPT_DECRYPT",
            _aws_key_policy(direct_runtime_allow=True),
        )
    )
    return resources


def _gcp_exact_key_mismatch_resources() -> list[TerraformResource]:
    resources = _gcp_resources()
    key_member = next(
        resource for resource in resources if resource.address == "google_kms_crypto_key_iam_member.runtime_decrypter"
    )
    key_member.values["crypto_key_id"] = None
    key_member.unknown_values["crypto_key_id"] = True
    key_member.reference_resolutions = (
        _reference_resolution(
            ("crypto_key_id",),
            (("google_kms_crypto_key.audit", ".id"),),
            state=TerraformReferenceResolutionState.SYMBOLIC,
        ),
    )
    resources.extend(
        [
            gcp_key("audit", "ENCRYPT_DECRYPT"),
            gcp_version("audit", "GOOGLE_SYMMETRIC_ENCRYPTION"),
        ]
    )
    return resources


def _azure_exact_key_mismatch_resources() -> list[TerraformResource]:
    resources = _azure_resources()
    key_role = next(resource for resource in resources if resource.address == "azurerm_role_assignment.key_access")
    key_role.values["scope"] = "azurerm_key_vault_key.audit.resource_versionless_id"
    resources.append(
        _azure_key(
            "audit",
            key_type="RSA-HSM",
            key_opts=["decrypt", "unwrapKey"],
        )
    )
    return resources


def _azure_dual_identity_resources() -> list[TerraformResource]:
    resources = _azure_resources(key_principal_id=AZURE_USER_PRINCIPAL_ID)
    web_app = next(resource for resource in resources if resource.address == "azurerm_linux_web_app.orders")
    identities = web_app.values["identity"]
    assert isinstance(identities, list)
    identity = identities[0]
    assert isinstance(identity, dict)
    identity["type"] = "SystemAssigned, UserAssigned"
    identity["identity_ids"] = [
        "azurerm_user_assigned_identity.orders_runtime.id",
    ]
    resources.append(azure_user_assigned_identity())
    return resources


def _resource(inventory: Any, address: str):
    resource = inventory.get_by_address(address)
    assert resource is not None
    return resource


class ProtectedDataKeyAuthorityConvergenceCharacterizationTests(unittest.TestCase):
    """Pin the independent evidence needed by a later convergence stage."""

    def test_exact_evidence_preserves_runtime_identity_and_key_equality(self) -> None:
        aws_inventory = AwsNormalizer().normalize(_aws_resources())
        aws_service = _resource(aws_inventory, "aws_ecs_service.orders")
        aws_bucket = _resource(aws_inventory, "aws_s3_bucket.orders")
        aws_read = aws_facts(aws_service).ecs_s3_access_paths[0]
        aws_operation = aws_facts(aws_service).ecs_kms_operation_paths[0]
        aws_dependency = aws_facts(aws_bucket).kms_encryption_dependencies[0]

        self.assertEqual(
            aws_facts(aws_service).internet_facing_load_balancer_addresses,
            ["aws_lb.public"],
        )
        self.assertEqual(aws_read["access_state"], "allowed")
        self.assertIn("read", aws_read["access_classes"])
        self.assertEqual(aws_read["role_address"], aws_operation["role_address"])
        self.assertEqual(aws_read["role_arn"], aws_operation["role_arn"])
        self.assertEqual(aws_dependency["resolution_state"], "resolved")
        self.assertEqual(aws_dependency["key_address"], aws_operation["key_address"])
        self.assertEqual(aws_dependency["key_arn"], aws_operation["key_arn"])
        self.assertEqual(
            aws_read["bucket_address"],
            aws_dependency["dependent_address"],
        )
        self.assertEqual(aws_read["bucket_arn"], _AWS_BUCKET_ARN)

        gcp_inventory = GcpNormalizer().normalize(_gcp_resources())
        gcp_workload = _resource(gcp_inventory, "google_cloud_run_v2_service.orders")
        gcp_bucket = _resource(gcp_inventory, GCP_BUCKET_ADDRESS)
        gcp_read = gcp_facts(gcp_workload).cloud_run_gcs_access_paths[0]
        gcp_operation = gcp_facts(gcp_workload).cloud_run_kms_operation_paths[0]
        gcp_dependency = gcp_facts(gcp_bucket).kms_encryption_dependencies[0]

        self.assertTrue(gcp_workload.public_exposure)
        self.assertEqual(gcp_read["access_state"], "granted")
        self.assertIn("read", gcp_read["access_classes"])
        self.assertEqual(
            gcp_read["service_account_member"],
            gcp_operation["service_account_member"],
        )
        self.assertEqual(
            gcp_read["service_account_email"],
            gcp_operation["service_account_email"],
        )
        self.assertEqual(gcp_dependency["resolution_state"], "resolved")
        self.assertEqual(gcp_dependency["key_address"], gcp_operation["key_address"])
        self.assertEqual(
            gcp_dependency["key_resource_name"],
            gcp_operation["key_resource_name"],
        )
        self.assertEqual(
            gcp_read["bucket_address"],
            gcp_dependency["dependent_address"],
        )

        azure_inventory = AzureNormalizer().normalize(_azure_resources())
        azure_workload = _resource(azure_inventory, "azurerm_linux_web_app.orders")
        azure_account = _resource(azure_inventory, "azurerm_storage_account.orders")
        azure_read = azure_facts(azure_workload).app_service_storage_access_paths[0]
        azure_operation = azure_facts(azure_workload).app_service_key_vault_operation_paths[0]
        azure_dependency = azure_facts(azure_account).key_vault_encryption_dependencies[0]

        self.assertIs(
            azure_facts(azure_workload).public_network_access_enabled,
            True,
        )
        self.assertEqual(azure_read["access_state"], "granted")
        self.assertIn("read", azure_read["access_classes"])
        self.assertEqual(azure_read["principal_id"], azure_operation["principal_id"])
        self.assertEqual(
            azure_read["identity_address"],
            azure_operation["identity_address"],
        )
        self.assertEqual(azure_dependency["resolution_state"], "resolved")
        self.assertEqual(azure_dependency["key_address"], azure_operation["key_address"])
        self.assertEqual(azure_dependency["key_uri"], azure_operation["key_uri"])

    def test_alias_version_and_parent_child_ancestry_remain_provider_native(
        self,
    ) -> None:
        aws_inventory = AwsNormalizer().normalize(_aws_resources())
        aws_bucket = _resource(aws_inventory, "aws_s3_bucket.orders")
        aws_dependency = aws_facts(aws_bucket).kms_encryption_dependencies[0]
        self.assertEqual(aws_dependency["reference_kind"], "alias_arn")
        self.assertEqual(aws_dependency["alias_address"], "aws_kms_alias.data")
        self.assertEqual(aws_dependency["alias_arn"], AWS_ALIAS_ARN)
        self.assertEqual(aws_dependency["key_address"], "aws_kms_key.data")

        gcp_inventory = GcpNormalizer().normalize(_gcp_resources())
        gcp_workload = _resource(gcp_inventory, "google_cloud_run_v2_service.orders")
        gcp_bucket = _resource(gcp_inventory, GCP_BUCKET_ADDRESS)
        gcp_operation = gcp_facts(gcp_workload).cloud_run_kms_operation_paths[0]
        gcp_dependency = gcp_facts(gcp_bucket).kms_encryption_dependencies[0]
        self.assertEqual(gcp_dependency["key_address"], "google_kms_crypto_key.data")
        self.assertIsNone(gcp_dependency["key_version_address"])
        self.assertFalse(gcp_dependency["version_reference_is_explicit"])
        self.assertEqual(
            [version["version_resource_name"] for version in gcp_operation["key_versions"]],
            [_GCP_VERSION_PATH],
        )
        self.assertFalse(gcp_operation["iam_scope_is_key_version"])

        azure_inventory = AzureNormalizer().normalize(_azure_resources())
        azure_workload = _resource(azure_inventory, "azurerm_linux_web_app.orders")
        azure_account = _resource(azure_inventory, "azurerm_storage_account.orders")
        azure_read = azure_facts(azure_workload).app_service_storage_access_paths[0]
        azure_operation = azure_facts(azure_workload).app_service_key_vault_operation_paths[0]
        azure_dependency = azure_facts(azure_account).key_vault_encryption_dependencies[0]
        self.assertEqual(
            azure_read["storage_resource_address"],
            "azurerm_storage_container.orders",
        )
        self.assertEqual(
            azure_read["storage_resource_id"],
            AZURE_STORAGE_CONTAINER_ID,
        )
        self.assertEqual(
            azure_read["storage_account_address"],
            azure_dependency["dependent_address"],
        )
        self.assertEqual(azure_dependency["target_kind"], "key_version")
        self.assertEqual(azure_dependency["key_uri"], _AZURE_KEY_URI)
        self.assertEqual(
            azure_dependency["key_versionless_uri"],
            _AZURE_KEY_VERSIONLESS_URI,
        )
        self.assertEqual(azure_dependency["key_resource_id"], _AZURE_KEY_RESOURCE_ID)
        self.assertEqual(
            azure_dependency["key_versionless_resource_id"],
            _AZURE_KEY_VERSIONLESS_RESOURCE_ID,
        )
        self.assertEqual(azure_operation["scope_type"], "vault")

    def test_exact_but_unequal_keys_preserve_all_three_evidence_legs(self) -> None:
        aws_inventory = AwsNormalizer().normalize(_aws_exact_key_mismatch_resources())
        aws_service = _resource(aws_inventory, "aws_ecs_service.orders")
        aws_bucket = _resource(aws_inventory, "aws_s3_bucket.orders")
        aws_read = aws_facts(aws_service).ecs_s3_access_paths[0]
        aws_operations = aws_facts(aws_service).ecs_kms_operation_paths
        aws_dependency = aws_facts(aws_bucket).kms_encryption_dependencies[0]
        self.assertEqual(aws_read["access_state"], "allowed")
        self.assertEqual(
            [path["operation"] for path in aws_operations],
            ["kms:Decrypt"],
        )
        self.assertEqual(aws_operations[0]["authorization_state"], "allowed")
        self.assertEqual(aws_dependency["resolution_state"], "resolved")
        self.assertEqual(
            aws_read["role_arn"],
            aws_operations[0]["role_arn"],
        )
        self.assertEqual(
            aws_read["bucket_address"],
            aws_dependency["dependent_address"],
        )
        self.assertEqual(aws_dependency["key_address"], "aws_kms_key.data")
        self.assertEqual(aws_operations[0]["key_address"], "aws_kms_key.signing")
        self.assertNotEqual(
            aws_dependency["key_address"],
            aws_operations[0]["key_address"],
        )

        gcp_inventory = GcpNormalizer().normalize(_gcp_exact_key_mismatch_resources())
        gcp_workload = _resource(
            gcp_inventory,
            "google_cloud_run_v2_service.orders",
        )
        gcp_bucket = _resource(gcp_inventory, GCP_BUCKET_ADDRESS)
        gcp_read = gcp_facts(gcp_workload).cloud_run_gcs_access_paths[0]
        gcp_operations = gcp_facts(gcp_workload).cloud_run_kms_operation_paths
        gcp_dependency = gcp_facts(gcp_bucket).kms_encryption_dependencies[0]
        self.assertEqual(gcp_read["access_state"], "granted")
        self.assertEqual(
            [path["operation"] for path in gcp_operations],
            ["cloudkms.cryptoKeyVersions.useToDecrypt"],
        )
        self.assertEqual(gcp_operations[0]["authorization_state"], "granted")
        self.assertEqual(gcp_dependency["resolution_state"], "resolved")
        self.assertEqual(
            gcp_read["service_account_email"],
            gcp_operations[0]["service_account_email"],
        )
        self.assertEqual(
            gcp_read["bucket_address"],
            gcp_dependency["dependent_address"],
        )
        self.assertEqual(
            gcp_dependency["key_address"],
            "google_kms_crypto_key.data",
        )
        self.assertEqual(
            gcp_operations[0]["key_address"],
            "google_kms_crypto_key.audit",
        )
        self.assertNotEqual(
            gcp_dependency["key_address"],
            gcp_operations[0]["key_address"],
        )

        azure_inventory = AzureNormalizer().normalize(_azure_exact_key_mismatch_resources())
        azure_workload = _resource(
            azure_inventory,
            "azurerm_linux_web_app.orders",
        )
        azure_account = _resource(
            azure_inventory,
            "azurerm_storage_account.orders",
        )
        azure_read = azure_facts(azure_workload).app_service_storage_access_paths[0]
        azure_operations = azure_facts(azure_workload).app_service_key_vault_operation_paths
        azure_dependency = azure_facts(azure_account).key_vault_encryption_dependencies[0]
        self.assertEqual(azure_read["access_state"], "granted")
        self.assertEqual(
            {path["operation"] for path in azure_operations},
            {"decrypt", "unwrap"},
        )
        self.assertEqual(
            {path["authorization_state"] for path in azure_operations},
            {"granted"},
        )
        self.assertEqual(azure_dependency["resolution_state"], "resolved")
        self.assertEqual(
            azure_read["principal_id"],
            azure_operations[0]["principal_id"],
        )
        self.assertEqual(
            azure_read["storage_account_address"],
            azure_dependency["dependent_address"],
        )
        self.assertEqual(
            azure_dependency["key_address"],
            "azurerm_key_vault_key.data",
        )
        self.assertEqual(
            {path["key_address"] for path in azure_operations},
            {"azurerm_key_vault_key.audit"},
        )
        self.assertNotIn(
            azure_dependency["key_address"],
            {path["key_address"] for path in azure_operations},
        )

    def test_conditions_denies_and_incomplete_evidence_do_not_become_deterministic_authority(
        self,
    ) -> None:
        aws_cases = {
            "condition": _aws_resources(
                kms_condition={
                    "StringEquals": {
                        "kms:EncryptionContext:service": "orders",
                    }
                }
            ),
            "deny": _aws_resources(deny_decrypt=True),
            "incomplete": _aws_resources(unresolved_policy=True),
        }
        for case, resources in aws_cases.items():
            with self.subTest(provider="aws", case=case):
                inventory = AwsNormalizer().normalize(resources)
                service = _resource(inventory, "aws_ecs_service.orders")
                bucket = _resource(inventory, "aws_s3_bucket.orders")
                self.assertEqual(
                    aws_facts(service).ecs_kms_operation_paths,
                    [],
                )
                self.assertEqual(
                    aws_facts(bucket).kms_encryption_dependencies[0]["resolution_state"],
                    "resolved",
                )
                expected_access_state = "unknown" if case == "incomplete" else "allowed"
                self.assertEqual(
                    aws_facts(service).ecs_s3_access_paths[0]["access_state"],
                    expected_access_state,
                )

        gcp_inventory = GcpNormalizer().normalize(
            _gcp_resources(
                kms_condition={
                    "title": "restricted",
                    "expression": 'resource.name.startsWith("projects/tfstride-demo")',
                }
            )
        )
        gcp_workload = _resource(
            gcp_inventory,
            "google_cloud_run_v2_service.orders",
        )
        gcp_bucket = _resource(gcp_inventory, GCP_BUCKET_ADDRESS)
        self.assertEqual(gcp_facts(gcp_workload).cloud_run_kms_operation_paths, [])
        self.assertTrue(
            any(
                "conditional" in uncertainty
                for uncertainty in gcp_facts(gcp_workload).cloud_run_kms_operation_path_uncertainties
            )
        )
        self.assertEqual(
            gcp_facts(gcp_bucket).kms_encryption_dependencies[0]["resolution_state"],
            "resolved",
        )

        azure_inventory = AzureNormalizer().normalize(
            _azure_resources(
                key_condition="@Resource[Microsoft.KeyVault/vaults/keys:name] StringEquals 'data'",
            )
        )
        azure_workload = _resource(
            azure_inventory,
            "azurerm_linux_web_app.orders",
        )
        azure_account = _resource(
            azure_inventory,
            "azurerm_storage_account.orders",
        )
        self.assertEqual(
            azure_facts(azure_workload).app_service_key_vault_operation_paths,
            [],
        )
        self.assertTrue(azure_facts(azure_workload).app_service_key_vault_operation_path_uncertainties)
        self.assertEqual(
            azure_facts(azure_account).key_vault_encryption_dependencies[0]["resolution_state"],
            "resolved",
        )

    def test_non_deterministic_data_access_remains_separate_from_key_authority(
        self,
    ) -> None:
        aws_inventory = AwsNormalizer().normalize(
            _aws_resources(
                s3_condition={
                    "StringLike": {
                        "s3:prefix": ["customer/*"],
                    }
                }
            )
        )
        aws_service = _resource(aws_inventory, "aws_ecs_service.orders")
        aws_bucket = _resource(aws_inventory, "aws_s3_bucket.orders")
        self.assertEqual(
            aws_facts(aws_service).ecs_s3_access_paths[0]["access_state"],
            "unknown",
        )
        self.assertEqual(
            [path["operation"] for path in aws_facts(aws_service).ecs_kms_operation_paths],
            ["kms:Decrypt"],
        )
        self.assertEqual(
            aws_facts(aws_bucket).kms_encryption_dependencies[0]["resolution_state"],
            "resolved",
        )

        gcp_inventory = GcpNormalizer().normalize(
            _gcp_resources(
                bucket_condition={
                    "title": "restricted",
                    "expression": "resource.name.startsWith('projects/_/buckets/tfstride-orders-data')",
                }
            )
        )
        gcp_workload = _resource(
            gcp_inventory,
            "google_cloud_run_v2_service.orders",
        )
        gcp_bucket = _resource(gcp_inventory, GCP_BUCKET_ADDRESS)
        self.assertEqual(
            gcp_facts(gcp_workload).cloud_run_gcs_access_paths[0]["access_state"],
            "conditional",
        )
        self.assertEqual(
            [path["operation"] for path in gcp_facts(gcp_workload).cloud_run_kms_operation_paths],
            ["cloudkms.cryptoKeyVersions.useToDecrypt"],
        )
        self.assertEqual(
            gcp_facts(gcp_bucket).kms_encryption_dependencies[0]["resolution_state"],
            "resolved",
        )

        azure_inventory = AzureNormalizer().normalize(
            _azure_resources(
                storage_condition=(
                    "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringEquals 'orders'"
                )
            )
        )
        azure_workload = _resource(
            azure_inventory,
            "azurerm_linux_web_app.orders",
        )
        azure_account = _resource(
            azure_inventory,
            "azurerm_storage_account.orders",
        )
        self.assertEqual(
            azure_facts(azure_workload).app_service_storage_access_paths[0]["access_state"],
            "conditional",
        )
        self.assertEqual(
            {path["operation"] for path in azure_facts(azure_workload).app_service_key_vault_operation_paths},
            {"decrypt", "unwrap"},
        )
        self.assertEqual(
            azure_facts(azure_account).key_vault_encryption_dependencies[0]["resolution_state"],
            "resolved",
        )

    def test_runtime_identity_mismatch_does_not_establish_key_authority(self) -> None:
        other_gcp_member = "serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"
        gcp_inventory = GcpNormalizer().normalize(_gcp_resources(kms_member=other_gcp_member))
        gcp_workload = _resource(
            gcp_inventory,
            "google_cloud_run_v2_service.orders",
        )
        self.assertEqual(
            gcp_facts(gcp_workload).cloud_run_kms_operation_paths,
            [],
        )
        self.assertEqual(
            gcp_facts(gcp_workload).cloud_run_gcs_access_paths[0]["service_account_email"],
            GCP_SERVICE_ACCOUNT_EMAIL,
        )

        azure_inventory = AzureNormalizer().normalize(_azure_resources(key_principal_id="other-runtime-principal-id"))
        azure_workload = _resource(
            azure_inventory,
            "azurerm_linux_web_app.orders",
        )
        self.assertEqual(
            azure_facts(azure_workload).app_service_key_vault_operation_paths,
            [],
        )
        self.assertEqual(
            azure_facts(azure_workload).app_service_storage_access_paths[0]["principal_id"],
            _AZURE_RUNTIME_PRINCIPAL_ID,
        )

    def test_two_valid_azure_runtime_identities_do_not_converge(self) -> None:
        inventory = AzureNormalizer().normalize(_azure_dual_identity_resources())
        workload = _resource(inventory, "azurerm_linux_web_app.orders")
        account = _resource(inventory, "azurerm_storage_account.orders")
        read_paths = azure_facts(workload).app_service_storage_access_paths
        operation_paths = azure_facts(workload).app_service_key_vault_operation_paths
        dependency = azure_facts(account).key_vault_encryption_dependencies[0]

        self.assertEqual(len(read_paths), 1)
        self.assertEqual(read_paths[0]["access_state"], "granted")
        self.assertEqual(read_paths[0]["identity_kind"], "system_assigned")
        self.assertEqual(
            read_paths[0]["identity_address"],
            workload.address,
        )
        self.assertEqual(
            read_paths[0]["principal_id"],
            _AZURE_RUNTIME_PRINCIPAL_ID,
        )
        self.assertEqual(
            {path["operation"] for path in operation_paths},
            {"decrypt", "unwrap"},
        )
        self.assertEqual(
            {path["identity_kind"] for path in operation_paths},
            {"user_assigned"},
        )
        self.assertEqual(
            {path["identity_address"] for path in operation_paths},
            {"azurerm_user_assigned_identity.orders_runtime"},
        )
        self.assertEqual(
            {path["principal_id"] for path in operation_paths},
            {AZURE_USER_PRINCIPAL_ID},
        )
        self.assertEqual(
            {path["workload_address"] for path in operation_paths},
            {workload.address},
        )
        self.assertEqual(dependency["resolution_state"], "resolved")
        self.assertEqual(
            dependency["key_address"],
            operation_paths[0]["key_address"],
        )
        self.assertNotEqual(
            read_paths[0]["principal_id"],
            operation_paths[0]["principal_id"],
        )

    def test_ambiguous_key_dependencies_preserve_candidates_without_selecting_a_key(
        self,
    ) -> None:
        aws_inventory = AwsNormalizer().normalize(_aws_resources(ambiguous_dependency=True))
        aws_workload = _resource(aws_inventory, "aws_ecs_service.orders")
        self.assertEqual(
            aws_facts(aws_workload).ecs_s3_access_paths[0]["access_state"],
            "allowed",
        )
        self.assertEqual(
            [path["operation"] for path in aws_facts(aws_workload).ecs_kms_operation_paths],
            ["kms:Decrypt"],
        )

        gcp_inventory = GcpNormalizer().normalize(_gcp_resources(ambiguous_dependency=True))
        gcp_workload = _resource(
            gcp_inventory,
            "google_cloud_run_v2_service.orders",
        )
        self.assertEqual(
            gcp_facts(gcp_workload).cloud_run_gcs_access_paths[0]["access_state"],
            "granted",
        )
        self.assertEqual(
            [path["operation"] for path in gcp_facts(gcp_workload).cloud_run_kms_operation_paths],
            ["cloudkms.cryptoKeyVersions.useToDecrypt"],
        )

        azure_inventory = AzureNormalizer().normalize(_azure_resources(ambiguous_dependency=True))
        azure_workload = _resource(
            azure_inventory,
            "azurerm_linux_web_app.orders",
        )
        self.assertEqual(
            azure_facts(azure_workload).app_service_storage_access_paths[0]["access_state"],
            "granted",
        )
        self.assertEqual(
            {path["operation"] for path in azure_facts(azure_workload).app_service_key_vault_operation_paths},
            {"decrypt", "unwrap"},
        )

        cases = (
            (
                aws_inventory,
                "aws_s3_bucket.orders",
                lambda resource: aws_facts(resource).kms_encryption_dependencies,
                {"aws_kms_key.data", "aws_kms_key.signing"},
            ),
            (
                gcp_inventory,
                GCP_BUCKET_ADDRESS,
                lambda resource: gcp_facts(resource).kms_encryption_dependencies,
                {
                    "google_kms_crypto_key.audit",
                    "google_kms_crypto_key.data",
                },
            ),
            (
                azure_inventory,
                "azurerm_storage_account.orders",
                lambda resource: azure_facts(resource).key_vault_encryption_dependencies,
                {
                    "azurerm_key_vault_key.audit",
                    "azurerm_key_vault_key.data",
                },
            ),
        )

        for inventory, address, dependencies_for, expected_candidates in cases:
            with self.subTest(address=address):
                dependent = _resource(inventory, address)
                dependencies = dependencies_for(dependent)
                self.assertEqual(len(dependencies), 1)
                dependency = dependencies[0]
                self.assertEqual(dependency["resolution_state"], "ambiguous")
                self.assertIsNone(dependency["key_address"])
                raw_candidates = dependency.get(
                    "candidate_targets",
                    dependency.get("candidate_key_addresses", []),
                )
                candidate_addresses = {
                    candidate["address"] if isinstance(candidate, dict) else candidate for candidate in raw_candidates
                }
                self.assertEqual(candidate_addresses, expected_candidates)

    def test_provider_local_evidence_never_contains_foreign_addresses(self) -> None:
        inventories = (
            (
                AwsNormalizer().normalize(_aws_resources()),
                "aws_ecs_service.orders",
                "aws_s3_bucket.orders",
                lambda resource: (
                    aws_facts(resource).ecs_s3_access_paths,
                    aws_facts(resource).ecs_kms_operation_paths,
                ),
                lambda resource: aws_facts(resource).kms_encryption_dependencies,
                ("google_", "azurerm_"),
            ),
            (
                GcpNormalizer().normalize(_gcp_resources()),
                "google_cloud_run_v2_service.orders",
                GCP_BUCKET_ADDRESS,
                lambda resource: (
                    gcp_facts(resource).cloud_run_gcs_access_paths,
                    gcp_facts(resource).cloud_run_kms_operation_paths,
                ),
                lambda resource: gcp_facts(resource).kms_encryption_dependencies,
                ("aws_", "azurerm_"),
            ),
            (
                AzureNormalizer().normalize(_azure_resources()),
                "azurerm_linux_web_app.orders",
                "azurerm_storage_account.orders",
                lambda resource: (
                    azure_facts(resource).app_service_storage_access_paths,
                    azure_facts(resource).app_service_key_vault_operation_paths,
                ),
                lambda resource: azure_facts(resource).key_vault_encryption_dependencies,
                ("aws_", "google_"),
            ),
        )

        for (
            inventory,
            workload_address,
            dependent_address,
            evidence_for,
            dependencies_for,
            foreign_prefixes,
        ) in inventories:
            with self.subTest(address=workload_address):
                workload = _resource(inventory, workload_address)
                dependent = _resource(inventory, dependent_address)
                access_paths, key_paths = evidence_for(workload)
                dependencies = dependencies_for(dependent)
                serialized = json.dumps(
                    {
                        "access_paths": access_paths,
                        "key_paths": key_paths,
                        "dependencies": dependencies,
                    },
                    sort_keys=True,
                )
                for prefix in foreign_prefixes:
                    self.assertNotIn(prefix, serialized)


if __name__ == "__main__":
    unittest.main()
