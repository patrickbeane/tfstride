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
_AWS_EXECUTION_ROLE_ARN = f"arn:aws:iam::{_AWS_ACCOUNT_ID}:role/orders-execution"
_AWS_EXTERNAL_POLICY_ARN = "arn:aws:iam::aws:policy/ExternalKmsAccess"
_AWS_LOAD_BALANCER_ARN = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/public/abc"
_AWS_LISTENER_ARN = "arn:aws:elasticloadbalancing:us-east-1:111122223333:listener/app/public/abc/ghi"
_AWS_TARGET_GROUP_ARN = "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/orders/def"
_AWS_KEY_IDS = {
    "data": "11111111-1111-1111-1111-111111111111",
    "signing": "22222222-2222-2222-2222-222222222222",
    "mac": "33333333-3333-3333-3333-333333333333",
}
_AWS_KEY_ARNS = {name: f"arn:aws:kms:us-east-1:{_AWS_ACCOUNT_ID}:key/{key_id}" for name, key_id in _AWS_KEY_IDS.items()}

_GCP_PROJECT = "tfstride-demo"
_GCP_SERVICE_ACCOUNT_EMAIL = f"orders@{_GCP_PROJECT}.iam.gserviceaccount.com"
_GCP_SERVICE_ACCOUNT_MEMBER = f"serviceAccount:{_GCP_SERVICE_ACCOUNT_EMAIL}"
_GCP_KEY_RING = f"projects/{_GCP_PROJECT}/locations/global/keyRings/application"

_AZURE_SUBSCRIPTION_ID = "sub-0001"
_AZURE_VAULT_ID = (
    f"/subscriptions/{_AZURE_SUBSCRIPTION_ID}/resourceGroups/app/providers/Microsoft.KeyVault/vaults/orders"
)
_AZURE_VAULT_URI = "https://orders.vault.azure.net"
_AZURE_RUNTIME_PRINCIPAL_ID = "orders-runtime-principal-id"
_AZURE_CRYPTO_USER_ROLE_ID = "/providers/Microsoft.Authorization/roleDefinitions/12338af0-0e69-4776-bea7-57ae8d297424"
_AZURE_SERVICE_ENCRYPTION_ROLE_ID = (
    "/providers/Microsoft.Authorization/roleDefinitions/e147488a-f6f5-4113-8e2d-b22465e65bf6"
)
_AZURE_CUSTOM_ROLE_ID = (
    f"/subscriptions/{_AZURE_SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleDefinitions/custom-signing-role"
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


def _aws_policy_statement(
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


def _aws_runtime_role() -> TerraformResource:
    statements = [
        _aws_policy_statement(
            "Allow",
            ["kms:Decrypt", "kms:Encrypt"],
            _AWS_KEY_ARNS["data"],
            condition={
                "StringEquals": {
                    "kms:EncryptionContext:service": "orders",
                }
            },
        ),
        _aws_policy_statement(
            "Allow",
            ["kms:Sign", "kms:Verify", "kms:GetPublicKey"],
            _AWS_KEY_ARNS["signing"],
        ),
        _aws_policy_statement(
            "Allow",
            ["kms:GenerateMac", "kms:VerifyMac"],
            _AWS_KEY_ARNS["mac"],
        ),
        _aws_policy_statement(
            "Deny",
            "kms:Decrypt",
            _AWS_KEY_ARNS["data"],
            condition={
                "StringNotEquals": {
                    "kms:EncryptionContext:tenant": "orders",
                }
            },
        ),
    ]
    return _resource(
        "aws",
        "aws_iam_role",
        "orders_task",
        {
            "name": "orders-task",
            "arn": _AWS_TASK_ROLE_ARN,
            "inline_policy": [
                {
                    "name": "kms-use",
                    "policy": json.dumps(
                        {
                            "Version": "2012-10-17",
                            "Statement": statements,
                        }
                    ),
                }
            ],
        },
    )


def _aws_execution_role() -> TerraformResource:
    return _resource(
        "aws",
        "aws_iam_role",
        "orders_execution",
        {
            "name": "orders-execution",
            "arn": _AWS_EXECUTION_ROLE_ARN,
        },
    )


def _aws_unresolved_policy_attachment() -> TerraformResource:
    return _resource(
        "aws",
        "aws_iam_role_policy_attachment",
        "external",
        {
            "role": _AWS_TASK_ROLE_ARN,
            "policy_arn": _AWS_EXTERNAL_POLICY_ARN,
        },
    )


def _aws_key_policy(actions: list[str]) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DelegateAccountIam",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{_AWS_ACCOUNT_ID}:root",
                    },
                    "Action": "kms:*",
                    "Resource": "*",
                },
                {
                    "Sid": "AllowRuntimeUse",
                    "Effect": "Allow",
                    "Principal": {"AWS": _AWS_TASK_ROLE_ARN},
                    "Action": actions,
                    "Resource": "*",
                },
            ],
        }
    )


def _aws_key(
    name: str,
    *,
    key_usage: str,
    key_spec: str,
    policy_actions: list[str],
) -> TerraformResource:
    return _resource(
        "aws",
        "aws_kms_key",
        name,
        {
            "id": _AWS_KEY_IDS[name],
            "key_id": _AWS_KEY_IDS[name],
            "arn": _AWS_KEY_ARNS[name],
            "key_usage": key_usage,
            "key_spec": key_spec,
            "origin": "AWS_KMS",
            "policy": _aws_key_policy(policy_actions),
        },
    )


def _aws_grant() -> TerraformResource:
    return _resource(
        "aws",
        "aws_kms_grant",
        "orders_runtime",
        {
            "id": "grant-orders-runtime",
            "grant_id": "grant-orders-runtime",
            "name": "orders-runtime",
            "key_id": "aws_kms_key.data.key_id",
            "grantee_principal": _AWS_TASK_ROLE_ARN,
            "operations": ["Decrypt", "Encrypt"],
            "constraints": [
                {
                    "encryption_context_equals": {
                        "service": "orders",
                    }
                }
            ],
        },
    )


def _aws_public_edge(*, internal: bool = False) -> list[TerraformResource]:
    return [
        _resource(
            "aws",
            "aws_lb",
            "public",
            {
                "name": "public",
                "arn": _AWS_LOAD_BALANCER_ARN,
                "internal": internal,
                "load_balancer_type": "application",
            },
        ),
        _resource(
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
        ),
        _resource(
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
        ),
    ]


def _aws_task_definition() -> TerraformResource:
    return _resource(
        "aws",
        "aws_ecs_task_definition",
        "orders",
        {
            "family": "orders",
            "revision": 1,
            "task_role_arn": _AWS_TASK_ROLE_ARN,
            "execution_role_arn": _AWS_EXECUTION_ROLE_ARN,
            "container_definitions": "[]",
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
            "template": [
                {
                    "service_account": _GCP_SERVICE_ACCOUNT_EMAIL,
                }
            ],
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


def _gcp_key(name: str, purpose: str) -> TerraformResource:
    return _resource(
        "google",
        GcpResourceType.KMS_CRYPTO_KEY,
        name,
        {
            "id": f"{_GCP_KEY_RING}/cryptoKeys/{name}",
            "name": name,
            "key_ring": _GCP_KEY_RING,
            "purpose": purpose,
        },
    )


def _gcp_version(
    name: str,
    *,
    algorithm: str,
) -> TerraformResource:
    key_path = f"{_GCP_KEY_RING}/cryptoKeys/{name}"
    version_path = f"{key_path}/cryptoKeyVersions/1"
    return _resource(
        "google",
        GcpResourceType.KMS_CRYPTO_KEY_VERSION,
        name,
        {
            "crypto_key": f"google_kms_crypto_key.{name}.id",
            "id": version_path,
            "name": version_path,
            "state": "ENABLED",
            "algorithm": algorithm,
            "protection_level": "SOFTWARE",
            "generate_time": "2026-07-19T00:00:00Z",
        },
    )


def _gcp_project_member(
    name: str,
    role: str,
    *,
    member: str = _GCP_SERVICE_ACCOUNT_MEMBER,
) -> TerraformResource:
    return _resource(
        "google",
        GcpResourceType.PROJECT_IAM_MEMBER,
        name,
        {
            "project": _GCP_PROJECT,
            "role": role,
            "member": member,
        },
    )


def _gcp_key_member(
    name: str,
    key_name: str,
    role: str,
    *,
    condition: dict[str, str] | None = None,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "crypto_key_id": f"google_kms_crypto_key.{key_name}.id",
        "role": role,
        "member": _GCP_SERVICE_ACCOUNT_MEMBER,
    }
    if condition is not None:
        values["condition"] = [condition]
    return _resource(
        "google",
        GcpResourceType.KMS_CRYPTO_KEY_IAM_MEMBER,
        name,
        values,
        unknown_values=unknown_values,
    )


def _azure_vault(*, rbac_enabled: bool = True) -> TerraformResource:
    return _resource(
        "azurerm",
        AzureResourceType.KEY_VAULT,
        "orders",
        {
            "id": _AZURE_VAULT_ID,
            "name": "orders",
            "vault_uri": _AZURE_VAULT_URI,
            "enable_rbac_authorization": rbac_enabled,
        },
    )


def _azure_key(
    name: str,
    *,
    key_type: str,
    key_opts: list[str],
) -> TerraformResource:
    version = "v-001"
    versionless_uri = f"{_AZURE_VAULT_URI}/keys/{name}"
    versionless_resource_id = f"{_AZURE_VAULT_ID}/keys/{name}"
    return _resource(
        "azurerm",
        AzureResourceType.KEY_VAULT_KEY,
        name,
        {
            "id": f"{versionless_uri}/{version}",
            "versionless_id": versionless_uri,
            "resource_id": f"{versionless_resource_id}/{version}",
            "resource_versionless_id": versionless_resource_id,
            "name": name,
            "version": version,
            "key_vault_id": "azurerm_key_vault.orders.id",
            "key_type": key_type,
            "key_opts": key_opts,
        },
    )


def _azure_web_app(*, public: bool = True) -> TerraformResource:
    return _resource(
        "azurerm",
        AzureResourceType.LINUX_WEB_APP,
        "orders",
        {
            "id": (f"/subscriptions/{_AZURE_SUBSCRIPTION_ID}/resourceGroups/app/providers/Microsoft.Web/sites/orders"),
            "name": "orders",
            "public_network_access_enabled": public,
            "identity": [
                {
                    "type": "SystemAssigned",
                    "principal_id": _AZURE_RUNTIME_PRINCIPAL_ID,
                    "tenant_id": "tenant-id",
                    "identity_ids": [],
                }
            ],
        },
    )


def _azure_role_assignment(
    name: str,
    *,
    role_id: str,
    role_name: str,
    scope: str = "azurerm_key_vault.orders.id",
    condition: str | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "scope": scope,
        "role_definition_id": role_id,
        "role_definition_name": role_name,
        "principal_id": _AZURE_RUNTIME_PRINCIPAL_ID,
        "principal_type": "ServicePrincipal",
    }
    if condition is not None:
        values["condition"] = condition
        values["condition_version"] = "2.0"
    return _resource(
        "azurerm",
        AzureResourceType.ROLE_ASSIGNMENT,
        name,
        values,
    )


def _azure_custom_role(
    *,
    unknown_permissions: bool = False,
) -> TerraformResource:
    return _resource(
        "azurerm",
        AzureResourceType.ROLE_DEFINITION,
        "signing",
        {
            "id": _AZURE_CUSTOM_ROLE_ID,
            "name": "Orders Key Signer",
            "scope": f"/subscriptions/{_AZURE_SUBSCRIPTION_ID}",
            "assignable_scopes": [f"/subscriptions/{_AZURE_SUBSCRIPTION_ID}"],
            "permissions": [
                {
                    "actions": [],
                    "not_actions": [],
                    "data_actions": [
                        "Microsoft.KeyVault/vaults/keys/sign/action",
                        "Microsoft.KeyVault/vaults/keys/verify/action",
                    ],
                    "not_data_actions": [
                        "Microsoft.KeyVault/vaults/keys/verify/action",
                    ],
                }
            ],
        },
        unknown_values=({"permissions": [{"data_actions": True}]} if unknown_permissions else None),
    )


def _azure_access_policy() -> TerraformResource:
    return _resource(
        "azurerm",
        AzureResourceType.KEY_VAULT_ACCESS_POLICY,
        "runtime",
        {
            "key_vault_id": "azurerm_key_vault.orders.id",
            "tenant_id": "tenant-id",
            "object_id": _AZURE_RUNTIME_PRINCIPAL_ID,
            "key_permissions": [
                "Decrypt",
                "Encrypt",
                "UnwrapKey",
                "WrapKey",
                "Sign",
                "Verify",
            ],
        },
    )


class PublicWorkloadManagedKeyOperationBoundaryTests(unittest.TestCase):
    """Pin operation-path prerequisites without constructing workload-to-key paths."""

    def test_aws_public_ecs_preserves_runtime_key_capabilities_and_authorization_sources(
        self,
    ) -> None:
        inventory = AwsNormalizer().normalize(
            [
                *_aws_public_edge(),
                _aws_runtime_role(),
                _aws_execution_role(),
                _aws_unresolved_policy_attachment(),
                _aws_task_definition(),
                _aws_ecs_service(),
                _aws_key(
                    "data",
                    key_usage="ENCRYPT_DECRYPT",
                    key_spec="SYMMETRIC_DEFAULT",
                    policy_actions=["kms:Decrypt", "kms:Encrypt"],
                ),
                _aws_key(
                    "signing",
                    key_usage="SIGN_VERIFY",
                    key_spec="RSA_2048",
                    policy_actions=["kms:Sign", "kms:Verify", "kms:GetPublicKey"],
                ),
                _aws_key(
                    "mac",
                    key_usage="GENERATE_VERIFY_MAC",
                    key_spec="HMAC_256",
                    policy_actions=["kms:GenerateMac", "kms:VerifyMac"],
                ),
                _aws_grant(),
            ]
        )
        service = inventory.get_by_address("aws_ecs_service.orders")
        role = inventory.get_by_address("aws_iam_role.orders_task")
        load_balancer = inventory.get_by_address("aws_lb.public")
        assert service is not None
        assert role is not None
        assert load_balancer is not None

        service_facts = aws_facts(service)
        role_facts = aws_facts(role)
        self.assertTrue(load_balancer.public_exposure)
        self.assertTrue(service.get_metadata_field(AwsResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER))
        self.assertEqual(
            service_facts.internet_facing_load_balancer_addresses,
            ["aws_lb.public"],
        )
        self.assertEqual(service_facts.task_role_arn, _AWS_TASK_ROLE_ARN)
        self.assertEqual(service.attached_role_arns, (_AWS_TASK_ROLE_ARN,))
        self.assertNotIn(_AWS_EXECUTION_ROLE_ARN, service.attached_role_arns)
        self.assertEqual(
            service.get_metadata_field(AwsResourceMetadata.RESOLVED_TASK_ROLE_ADDRESSES),
            ["aws_iam_role.orders_task"],
        )
        self.assertEqual(
            role_facts.unresolved_attached_policy_arns,
            [_AWS_EXTERNAL_POLICY_ARN],
        )

        self.assertEqual(len(role.policy_statements), 4)
        decrypt_allow, signing_allow, mac_allow, decrypt_deny = role.policy_statements
        self.assertEqual(decrypt_allow.effect, "Allow")
        self.assertEqual(decrypt_allow.actions, ["kms:Decrypt", "kms:Encrypt"])
        self.assertEqual(decrypt_allow.resources, [_AWS_KEY_ARNS["data"]])
        self.assertEqual(
            [(condition.operator, condition.key, condition.values) for condition in decrypt_allow.conditions],
            [
                (
                    "StringEquals",
                    "kms:EncryptionContext:service",
                    ["orders"],
                )
            ],
        )
        self.assertEqual(
            signing_allow.actions,
            ["kms:Sign", "kms:Verify", "kms:GetPublicKey"],
        )
        self.assertEqual(mac_allow.actions, ["kms:GenerateMac", "kms:VerifyMac"])
        self.assertEqual(decrypt_deny.effect, "Deny")
        self.assertEqual(decrypt_deny.actions, ["kms:Decrypt"])
        self.assertTrue(decrypt_deny.conditions)

        expected_capabilities = {
            "data": ("ENCRYPT_DECRYPT", "SYMMETRIC_DEFAULT"),
            "signing": ("SIGN_VERIFY", "RSA_2048"),
            "mac": ("GENERATE_VERIFY_MAC", "HMAC_256"),
        }
        for name, (usage, spec) in expected_capabilities.items():
            with self.subTest(key=name):
                key = inventory.get_by_address(f"aws_kms_key.{name}")
                assert key is not None
                facts = aws_facts(key)
                self.assertEqual(key.identifier, _AWS_KEY_IDS[name])
                self.assertEqual(key.arn, _AWS_KEY_ARNS[name])
                self.assertEqual(facts.kms_key_usage, usage)
                self.assertEqual(facts.kms_key_spec, spec)
                self.assertEqual(facts.kms_policy_configuration_state, "configured")
                self.assertEqual(facts.kms_policy_completeness_state, "complete")
                self.assertEqual(facts.kms_policy_source_addresses, [key.address])

        data_key = inventory.get_by_address("aws_kms_key.data")
        grant = inventory.get_by_address("aws_kms_grant.orders_runtime")
        assert data_key is not None
        assert grant is not None
        account_delegation, direct_runtime_allow = data_key.policy_statements
        self.assertEqual(
            account_delegation.principals,
            [f"arn:aws:iam::{_AWS_ACCOUNT_ID}:root"],
        )
        self.assertEqual(account_delegation.actions, ["kms:*"])
        self.assertEqual(direct_runtime_allow.principals, [_AWS_TASK_ROLE_ARN])
        self.assertEqual(
            direct_runtime_allow.actions,
            ["kms:Decrypt", "kms:Encrypt"],
        )
        grant_facts = aws_facts(grant)
        self.assertEqual(grant_facts.kms_grant_resolved_key_address, data_key.address)
        self.assertEqual(grant_facts.kms_grant_grantee_principal, _AWS_TASK_ROLE_ARN)
        self.assertEqual(grant_facts.kms_grant_operations, ["Decrypt", "Encrypt"])
        self.assertEqual(
            grant_facts.kms_grant_constraints,
            {"encryption_context_equals": {"service": "orders"}},
        )
        self.assertEqual(len(aws_facts(data_key).kms_grants), 1)

        # These authorities remain distinct inputs; later analyzers intentionally
        # keep encrypt, verify, and public-key retrieval quiet on their own.
        self.assertEqual(
            [action for action in signing_allow.actions if action != "kms:Sign"],
            ["kms:Verify", "kms:GetPublicKey"],
        )
        self.assertIn("kms:Encrypt", decrypt_allow.actions)
        self.assertIn("kms:VerifyMac", mac_allow.actions)

    def test_aws_unknown_policy_and_grant_operations_remain_incomplete(self) -> None:
        key = _aws_key(
            "data",
            key_usage="ENCRYPT_DECRYPT",
            key_spec="SYMMETRIC_DEFAULT",
            policy_actions=["kms:Decrypt"],
        )
        key.unknown_values["policy"] = True
        grant = _aws_grant()
        grant.unknown_values["operations"] = True
        inventory = AwsNormalizer().normalize([key, grant])
        normalized_key = inventory.get_by_address("aws_kms_key.data")
        normalized_grant = inventory.get_by_address("aws_kms_grant.orders_runtime")
        assert normalized_key is not None
        assert normalized_grant is not None

        key_facts = aws_facts(normalized_key)
        grant_facts = aws_facts(normalized_grant)
        self.assertEqual(key_facts.kms_policy_configuration_state, "unknown")
        self.assertEqual(key_facts.kms_policy_completeness_state, "unknown")
        self.assertEqual(normalized_key.policy_statements, ())
        self.assertIn("policy is unknown after planning", key_facts.kms_posture_uncertainties)
        self.assertEqual(grant_facts.kms_grant_operations, [])
        self.assertIn(
            "operations is unknown after planning",
            grant_facts.kms_grant_posture_uncertainties,
        )

    def test_gcp_public_cloud_run_preserves_key_versions_scopes_and_operation_permissions(
        self,
    ) -> None:
        signing_condition = {
            "title": "temporary-signing",
            "expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
        }
        inventory = GcpNormalizer().normalize(
            [
                _gcp_cloud_run(),
                _gcp_public_invoker(),
                _gcp_key("data", "ENCRYPT_DECRYPT"),
                _gcp_key("signing", "ASYMMETRIC_SIGN"),
                _gcp_key("mac", "MAC"),
                _gcp_version(
                    "data",
                    algorithm="GOOGLE_SYMMETRIC_ENCRYPTION",
                ),
                _gcp_version(
                    "signing",
                    algorithm="EC_SIGN_P256_SHA256",
                ),
                _gcp_version("mac", algorithm="HMAC_SHA256"),
                _gcp_project_member(
                    "runtime_decrypter",
                    "roles/cloudkms.cryptoKeyDecrypter",
                ),
                _gcp_key_member(
                    "runtime_encrypter",
                    "data",
                    "roles/cloudkms.cryptoKeyEncrypter",
                ),
                _gcp_key_member(
                    "runtime_delegated_decrypter",
                    "data",
                    "roles/cloudkms.cryptoKeyDecrypterViaDelegation",
                ),
                _gcp_key_member(
                    "runtime_signer",
                    "signing",
                    "roles/cloudkms.signer",
                    condition=signing_condition,
                ),
                _gcp_key_member(
                    "runtime_verifier",
                    "signing",
                    "roles/cloudkms.verifier",
                ),
                _gcp_key_member(
                    "runtime_mac_signer",
                    "mac",
                    "roles/cloudkms.signer",
                ),
            ]
        )
        workload = inventory.get_by_address("google_cloud_run_v2_service.orders")
        assert workload is not None
        workload_facts = gcp_facts(workload)
        self.assertTrue(workload.public_access_configured)
        self.assertTrue(workload.public_exposure)
        self.assertEqual(
            workload_facts.service_account_email,
            _GCP_SERVICE_ACCOUNT_EMAIL,
        )
        self.assertEqual(
            workload_facts.service_account_member,
            _GCP_SERVICE_ACCOUNT_MEMBER,
        )

        version_expectations = {
            "data": ("ENCRYPT_DECRYPT", "GOOGLE_SYMMETRIC_ENCRYPTION"),
            "signing": ("ASYMMETRIC_SIGN", "EC_SIGN_P256_SHA256"),
            "mac": ("MAC", "HMAC_SHA256"),
        }
        for name, (purpose, algorithm) in version_expectations.items():
            with self.subTest(version=name):
                key = inventory.get_by_address(f"google_kms_crypto_key.{name}")
                version = inventory.get_by_address(f"google_kms_crypto_key_version.{name}")
                assert key is not None
                assert version is not None
                key_path = f"{_GCP_KEY_RING}/cryptoKeys/{name}"
                version_facts = gcp_facts(version)
                self.assertEqual(key.identifier, key_path)
                self.assertEqual(gcp_facts(key).kms_purpose, purpose)
                self.assertEqual(
                    version.identifier,
                    f"{key_path}/cryptoKeyVersions/1",
                )
                self.assertEqual(
                    version_facts.kms_crypto_key_version_resolved_key_address,
                    key.address,
                )
                self.assertEqual(
                    version_facts.kms_crypto_key_version_purpose,
                    purpose,
                )
                self.assertEqual(
                    version_facts.kms_crypto_key_version_algorithm,
                    algorithm,
                )
                self.assertEqual(
                    version_facts.kms_crypto_key_version_state,
                    "ENABLED",
                )

        data_key = inventory.get_by_address("google_kms_crypto_key.data")
        signing_key = inventory.get_by_address("google_kms_crypto_key.signing")
        mac_key = inventory.get_by_address("google_kms_crypto_key.mac")
        assert data_key is not None
        assert signing_key is not None
        assert mac_key is not None
        data_grants = {grant["source"]: grant for grant in gcp_facts(data_key).kms_iam_grants}
        self.assertEqual(
            data_grants["google_project_iam_member.runtime_decrypter"]["scope_type"],
            "project",
        )
        self.assertEqual(
            data_grants["google_project_iam_member.runtime_decrypter"]["scope_effective_permissions"],
            ["cloudkms.cryptoKeyVersions.useToDecrypt"],
        )
        self.assertEqual(
            data_grants["google_project_iam_member.runtime_decrypter"]["members"],
            [_GCP_SERVICE_ACCOUNT_MEMBER],
        )
        self.assertEqual(
            data_grants["google_kms_crypto_key_iam_member.runtime_encrypter"]["scope_type"],
            "crypto_key",
        )
        self.assertEqual(
            data_grants["google_kms_crypto_key_iam_member.runtime_encrypter"]["authorization_state"],
            "granted",
        )
        self.assertEqual(
            data_grants["google_kms_crypto_key_iam_member.runtime_delegated_decrypter"]["scope_effective_permissions"],
            ["cloudkms.cryptoKeyVersions.useToDecryptViaDelegation"],
        )

        signing_grants = {grant["source"]: grant for grant in gcp_facts(signing_key).kms_iam_grants}
        signer = signing_grants["google_kms_crypto_key_iam_member.runtime_signer"]
        self.assertEqual(signer["condition_state"], "configured")
        self.assertEqual(signer["condition"], signing_condition)
        self.assertEqual(signer["authorization_state"], "conditional")
        verifier = signing_grants["google_kms_crypto_key_iam_member.runtime_verifier"]
        self.assertEqual(
            verifier["scope_effective_permissions"],
            [
                "cloudkms.cryptoKeyVersions.useToVerify",
                "cloudkms.cryptoKeyVersions.viewPublicKey",
            ],
        )
        self.assertEqual(verifier["authorization_state"], "granted")

        mac_grants = {grant["source"]: grant for grant in gcp_facts(mac_key).kms_iam_grants}
        self.assertEqual(
            mac_grants["google_kms_crypto_key_iam_member.runtime_mac_signer"]["scope_effective_permissions"],
            ["cloudkms.cryptoKeyVersions.useToSign"],
        )

        # Encrypt, delegated decrypt, verify, and public-key retrieval remain
        # distinguishable inputs for the later analyzer's quiet/deferred set.
        self.assertEqual(
            data_grants["google_kms_crypto_key_iam_member.runtime_encrypter"]["scope_effective_permissions"],
            ["cloudkms.cryptoKeyVersions.useToEncrypt"],
        )

    def test_gcp_unknown_inherited_policy_and_custom_permissions_remain_uncertain(
        self,
    ) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _gcp_cloud_run(),
                _gcp_public_invoker(),
                _gcp_key("data", "ENCRYPT_DECRYPT"),
                _resource(
                    "google",
                    GcpResourceType.PROJECT_IAM_POLICY,
                    "unknown",
                    {"project": _GCP_PROJECT},
                    unknown_values={"policy_data": True},
                ),
                _resource(
                    "google",
                    GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
                    "runtime_crypto",
                    {
                        "project": _GCP_PROJECT,
                        "role_id": "runtimeCrypto",
                        "name": f"projects/{_GCP_PROJECT}/roles/runtimeCrypto",
                        "permissions": [
                            "cloudkms.cryptoKeyVersions.useToDecrypt",
                        ],
                    },
                    unknown_values={"permissions": True},
                ),
                _gcp_project_member(
                    "runtime_custom",
                    "google_project_iam_custom_role.runtime_crypto.id",
                ),
            ]
        )
        workload = inventory.get_by_address("google_cloud_run_v2_service.orders")
        key = inventory.get_by_address("google_kms_crypto_key.data")
        assert workload is not None
        assert key is not None

        self.assertTrue(workload.public_exposure)
        grant = gcp_facts(key).kms_iam_grants[0]
        self.assertEqual(grant["role_kind"], "custom")
        self.assertEqual(grant["role_resolution_state"], "unknown")
        self.assertEqual(grant["scope_effective_permissions"], [])
        self.assertEqual(grant["authorization_state"], "unknown")
        self.assertTrue(
            any(
                "IAM policy_data is unknown" in uncertainty
                for uncertainty in gcp_facts(key).kms_iam_posture_uncertainties
            )
        )

    def test_azure_public_app_preserves_identity_exact_keys_capabilities_and_rbac_sources(
        self,
    ) -> None:
        condition = "@Resource[Microsoft.KeyVault/vaults/keys:Name] StringEqualsIgnoreCase 'data'"
        inventory = AzureNormalizer().normalize(
            [
                _azure_vault(),
                _azure_key(
                    "data",
                    key_type="RSA-HSM",
                    key_opts=["decrypt", "encrypt", "unwrapKey", "wrapKey"],
                ),
                _azure_key(
                    "signing",
                    key_type="EC-HSM",
                    key_opts=["sign", "verify"],
                ),
                _azure_web_app(),
                _azure_role_assignment(
                    "runtime_crypto",
                    role_id=_AZURE_CRYPTO_USER_ROLE_ID,
                    role_name="Key Vault Crypto User",
                ),
                _azure_role_assignment(
                    "conditioned_unwrap",
                    role_id=_AZURE_SERVICE_ENCRYPTION_ROLE_ID,
                    role_name="Key Vault Crypto Service Encryption User",
                    scope="azurerm_key_vault_key.data.resource_versionless_id",
                    condition=condition,
                ),
                _azure_custom_role(),
                _azure_role_assignment(
                    "runtime_signer",
                    role_id=("azurerm_role_definition.signing.role_definition_resource_id"),
                    role_name="Orders Key Signer",
                    scope=("azurerm_key_vault_key.signing.resource_versionless_id"),
                ),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        data_key = inventory.get_by_address("azurerm_key_vault_key.data")
        signing_key = inventory.get_by_address("azurerm_key_vault_key.signing")
        assert workload is not None
        assert data_key is not None
        assert signing_key is not None

        workload_facts = azure_facts(workload)
        self.assertTrue(workload.public_access_configured)
        self.assertTrue(workload_facts.public_network_access_enabled)
        self.assertTrue(workload_facts.has_system_assigned_identity)
        self.assertEqual(
            workload_facts.principal_id,
            _AZURE_RUNTIME_PRINCIPAL_ID,
        )

        key_expectations = {
            "data": (
                "RSA-HSM",
                ["decrypt", "encrypt", "unwrapKey", "wrapKey"],
            ),
            "signing": ("EC-HSM", ["sign", "verify"]),
        }
        for name, (key_type, key_ops) in key_expectations.items():
            with self.subTest(key=name):
                key = inventory.get_by_address(f"azurerm_key_vault_key.{name}")
                assert key is not None
                facts = azure_facts(key)
                self.assertEqual(
                    key.identifier,
                    f"{_AZURE_VAULT_URI}/keys/{name}/v-001",
                )
                self.assertEqual(facts.key_vault_key_identity_state, "resolved")
                self.assertEqual(
                    facts.key_vault_key_versionless_uri,
                    f"{_AZURE_VAULT_URI}/keys/{name}",
                )
                self.assertEqual(
                    facts.key_vault_key_versionless_resource_id,
                    f"{_AZURE_VAULT_ID}/keys/{name}",
                )
                self.assertEqual(facts.key_vault_key_type, key_type)
                self.assertEqual(facts.key_vault_key_ops, key_ops)

        data_grants = {
            grant["grant_source_address"]: grant for grant in azure_facts(data_key).key_vault_key_authorization_grants
        }
        broad_grant = data_grants["azurerm_role_assignment.runtime_crypto"]
        self.assertEqual(broad_grant["grant_kind"], "rbac")
        self.assertEqual(broad_grant["principal_id"], _AZURE_RUNTIME_PRINCIPAL_ID)
        self.assertEqual(broad_grant["grant_scope_type"], "vault")
        self.assertEqual(broad_grant["authorization_state"], "granted")
        self.assertTrue(
            {
                "decrypt",
                "unwrap",
                "sign",
                "encrypt",
                "wrap",
                "verify",
                "read",
            }.issubset(set(broad_grant["matched_operations"]))
        )
        conditioned = data_grants["azurerm_role_assignment.conditioned_unwrap"]
        self.assertEqual(conditioned["grant_scope_type"], "key")
        self.assertEqual(conditioned["condition_state"], "configured")
        self.assertEqual(conditioned["condition"], condition)
        self.assertEqual(
            conditioned["condition_applicability_state"],
            "unsupported",
        )
        self.assertEqual(conditioned["authorization_state"], "unknown")

        signing_grants = {
            grant["grant_source_address"]: grant
            for grant in azure_facts(signing_key).key_vault_key_authorization_grants
        }
        signing_grant = signing_grants["azurerm_role_assignment.runtime_signer"]
        self.assertEqual(signing_grant["grant_scope_type"], "key")
        self.assertEqual(signing_grant["role_kind"], "custom")
        self.assertEqual(signing_grant["matched_operations"], ["sign"])
        self.assertEqual(
            signing_grant["excluded_data_actions"],
            ["Microsoft.KeyVault/vaults/keys/verify/action"],
        )
        self.assertEqual(signing_grant["authorization_state"], "granted")

        # The key and grant retain operations that are intentionally quiet when
        # they are not connected to a stronger threat path.
        self.assertEqual(
            sorted(
                operation
                for operation in broad_grant["matched_operations"]
                if operation in {"encrypt", "wrap", "verify", "read"}
            ),
            ["encrypt", "read", "verify", "wrap"],
        )

    def test_azure_access_policy_and_unknown_custom_role_remain_distinct_sources(
        self,
    ) -> None:
        legacy_inventory = AzureNormalizer().normalize(
            [
                _azure_vault(rbac_enabled=False),
                _azure_key(
                    "data",
                    key_type="RSA-HSM",
                    key_opts=["decrypt", "encrypt", "unwrapKey", "wrapKey"],
                ),
                _azure_web_app(),
                _azure_access_policy(),
            ]
        )
        legacy_key = legacy_inventory.get_by_address("azurerm_key_vault_key.data")
        assert legacy_key is not None
        legacy_grant = azure_facts(legacy_key).key_vault_key_authorization_grants[0]
        self.assertEqual(legacy_grant["grant_kind"], "access_policy")
        self.assertEqual(
            legacy_grant["grant_source_address"],
            "azurerm_key_vault_access_policy.runtime",
        )
        self.assertEqual(legacy_grant["principal_id"], _AZURE_RUNTIME_PRINCIPAL_ID)
        self.assertEqual(
            legacy_grant["matched_operations"],
            ["encrypt", "decrypt", "wrap", "unwrap", "sign", "verify"],
        )
        self.assertEqual(legacy_grant["authorization_state"], "granted")

        unknown_inventory = AzureNormalizer().normalize(
            [
                _azure_vault(),
                _azure_key(
                    "signing",
                    key_type="EC-HSM",
                    key_opts=["sign", "verify"],
                ),
                _azure_web_app(),
                _azure_custom_role(unknown_permissions=True),
                _azure_role_assignment(
                    "runtime_signer",
                    role_id=("azurerm_role_definition.signing.role_definition_resource_id"),
                    role_name="Orders Key Signer",
                    scope=("azurerm_key_vault_key.signing.resource_versionless_id"),
                ),
            ]
        )
        workload = unknown_inventory.get_by_address("azurerm_linux_web_app.orders")
        signing_key = unknown_inventory.get_by_address("azurerm_key_vault_key.signing")
        assert workload is not None
        assert signing_key is not None
        self.assertTrue(workload.public_access_configured)
        unknown_grant = azure_facts(signing_key).key_vault_key_authorization_grants[0]
        self.assertEqual(unknown_grant["role_kind"], "custom")
        self.assertEqual(unknown_grant["role_resolution_state"], "unknown")
        self.assertEqual(unknown_grant["matched_operations"], [])
        self.assertEqual(unknown_grant["authorization_state"], "unknown")

    def test_private_workloads_retain_identity_without_public_exposure(self) -> None:
        aws_inventory = AwsNormalizer().normalize(
            [
                *_aws_public_edge(internal=True),
                _aws_runtime_role(),
                _aws_execution_role(),
                _aws_task_definition(),
                _aws_ecs_service(),
                _aws_key(
                    "data",
                    key_usage="ENCRYPT_DECRYPT",
                    key_spec="SYMMETRIC_DEFAULT",
                    policy_actions=["kms:Decrypt"],
                ),
            ]
        )
        aws_load_balancer = aws_inventory.get_by_address("aws_lb.public")
        aws_workload = aws_inventory.get_by_address("aws_ecs_service.orders")
        assert aws_load_balancer is not None
        assert aws_workload is not None
        self.assertFalse(aws_load_balancer.public_exposure)
        self.assertFalse(aws_workload.get_metadata_field(AwsResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER))
        self.assertEqual(
            aws_facts(aws_workload).task_role_arn,
            _AWS_TASK_ROLE_ARN,
        )

        gcp_inventory = GcpNormalizer().normalize(
            [
                _gcp_cloud_run(public_ingress=False),
                _gcp_public_invoker(),
                _gcp_key("data", "ENCRYPT_DECRYPT"),
                _gcp_project_member(
                    "runtime_decrypter",
                    "roles/cloudkms.cryptoKeyDecrypter",
                ),
            ]
        )
        gcp_workload = gcp_inventory.get_by_address("google_cloud_run_v2_service.orders")
        assert gcp_workload is not None
        self.assertFalse(gcp_workload.public_exposure)
        self.assertEqual(
            gcp_facts(gcp_workload).service_account_member,
            _GCP_SERVICE_ACCOUNT_MEMBER,
        )

        azure_inventory = AzureNormalizer().normalize(
            [
                _azure_vault(),
                _azure_key(
                    "data",
                    key_type="RSA-HSM",
                    key_opts=["decrypt", "unwrapKey"],
                ),
                _azure_web_app(public=False),
                _azure_role_assignment(
                    "runtime_crypto",
                    role_id=_AZURE_CRYPTO_USER_ROLE_ID,
                    role_name="Key Vault Crypto User",
                ),
            ]
        )
        azure_workload = azure_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert azure_workload is not None
        self.assertFalse(azure_workload.public_access_configured)
        self.assertFalse(
            azure_facts(azure_workload).public_network_access_enabled,
        )
        self.assertEqual(
            azure_facts(azure_workload).principal_id,
            _AZURE_RUNTIME_PRINCIPAL_ID,
        )


if __name__ == "__main__":
    unittest.main()
