from __future__ import annotations

import unittest

from tfstride.models import IAMPolicyStatement, NormalizedResource, ResourceCategory
from tfstride.providers.aws.resource_decoration.resource_policies import MergeResourcePolicyResourcesStage
from tfstride.providers.aws.resource_decorator import AwsResourceDecorator
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsResourceIndexBuilder
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_decoration.storage import DecorateStorageRelationshipsStage
from tfstride.providers.azure.resource_decorator import AzureResourceDecorator
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureResourceIndexBuilder
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_decoration.kms_versions import NormalizeKmsCryptoKeyVersionPostureStage
from tfstride.providers.gcp.resource_decorator import GcpResourceDecorator
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpResourceIndexBuilder
from tfstride.providers.gcp.resource_types import GcpResourceType
from tfstride.providers.gcp.resource_utils import gcp_reference_key

_AWS_BUCKET_ADDRESS = "aws_s3_bucket.logs"
_AWS_BUCKET_ARN = "arn:aws:s3:::tfstride-logs"
_AWS_BUCKET_NAME = "tfstride-logs"
_AWS_POLICY_ADDRESS = "aws_s3_bucket_policy.logs"

_GCP_KEY_ADDRESS = "google_kms_crypto_key.customer"
_GCP_KEY_RING = "projects/demo/locations/global/keyRings/application"
_GCP_KEY_NAME = "customer"
_GCP_KEY_PATH = f"{_GCP_KEY_RING}/cryptoKeys/{_GCP_KEY_NAME}"
_GCP_VERSION_ADDRESS = "google_kms_crypto_key_version.customer_primary"

_AZURE_ACCOUNT_ADDRESS = "azurerm_storage_account.logs"
_AZURE_ACCOUNT_ID = (
    "/subscriptions/sub-0001/resourceGroups/application/providers/Microsoft.Storage/storageAccounts/tfstridelogs"
)
_AZURE_ACCOUNT_NAME = "tfstridelogs"
_AZURE_CONTAINER_ADDRESS = "azurerm_storage_container.objects"


def _aws_bucket() -> NormalizedResource:
    return NormalizedResource(
        address=_AWS_BUCKET_ADDRESS,
        provider="aws",
        resource_type="aws_s3_bucket",
        name="logs",
        category=ResourceCategory.DATA,
        identifier=_AWS_BUCKET_NAME,
        arn=_AWS_BUCKET_ARN,
        metadata={"bucket": _AWS_BUCKET_NAME},
    )


def _aws_bucket_policy(bucket_reference: str) -> NormalizedResource:
    return NormalizedResource(
        address=_AWS_POLICY_ADDRESS,
        provider="aws",
        resource_type="aws_s3_bucket_policy",
        name="logs",
        category=ResourceCategory.DATA,
        metadata={
            "bucket": bucket_reference,
            "policy_document": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": f"{_AWS_BUCKET_ARN}/*",
                    }
                ]
            },
        },
        policy_statements=[
            IAMPolicyStatement(
                effect="Allow",
                actions=["s3:GetObject"],
                resources=[f"{_AWS_BUCKET_ARN}/*"],
            )
        ],
    )


def _aws_decoration_snapshot(bucket_reference: str, *, reverse: bool) -> tuple[object, ...]:
    bucket = _aws_bucket()
    policy = _aws_bucket_policy(bucket_reference)
    resources = [bucket, policy]
    if reverse:
        resources.reverse()

    AwsResourceDecorator(stages=(MergeResourcePolicyResourcesStage(),)).decorate(resources)

    return (
        tuple(aws_facts(bucket).resource_policy_source_addresses),
        tuple(statement.actions for statement in bucket.policy_statements),
        tuple(policy.metadata_snapshot().get("unresolved_bucket_references", ())),
    )


def _gcp_key() -> NormalizedResource:
    return NormalizedResource(
        address=_GCP_KEY_ADDRESS,
        provider="gcp",
        resource_type=GcpResourceType.KMS_CRYPTO_KEY,
        name=_GCP_KEY_NAME,
        category=ResourceCategory.DATA,
        identifier=_GCP_KEY_PATH,
        metadata={
            GcpResourceMetadata.NAME: _GCP_KEY_NAME,
            GcpResourceMetadata.PROJECT: "demo",
            GcpResourceMetadata.KMS_KEY_RING: _GCP_KEY_RING,
            GcpResourceMetadata.KMS_CRYPTO_KEY_REFERENCE: _GCP_KEY_PATH,
            GcpResourceMetadata.KMS_PURPOSE: "ENCRYPT_DECRYPT",
        },
    )


def _gcp_key_version(key_reference: str) -> NormalizedResource:
    return NormalizedResource(
        address=_GCP_VERSION_ADDRESS,
        provider="gcp",
        resource_type=GcpResourceType.KMS_CRYPTO_KEY_VERSION,
        name="customer-primary",
        category=ResourceCategory.DATA,
        identifier=f"{_GCP_KEY_PATH}/cryptoKeyVersions/1",
        metadata={
            GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_CRYPTO_KEY_REFERENCE: key_reference,
        },
    )


def _gcp_decoration_snapshot(key_reference: str, *, reverse: bool) -> tuple[object, ...]:
    key = _gcp_key()
    version = _gcp_key_version(key_reference)
    resources = [key, version]
    if reverse:
        resources.reverse()

    GcpResourceDecorator(stages=(NormalizeKmsCryptoKeyVersionPostureStage(),)).decorate(resources)
    facts = gcp_facts(version)

    return (
        facts.kms_crypto_key_version_resolved_key_address,
        facts.kms_crypto_key_version_crypto_key_path,
        facts.kms_crypto_key_version_purpose,
        tuple(facts.kms_crypto_key_version_posture_uncertainties),
    )


def _azure_storage_account() -> NormalizedResource:
    return NormalizedResource(
        address=_AZURE_ACCOUNT_ADDRESS,
        provider="azure",
        resource_type=AzureResourceType.STORAGE_ACCOUNT,
        name="logs",
        category=ResourceCategory.DATA,
        identifier=_AZURE_ACCOUNT_ID,
        metadata={
            AzureResourceMetadata.NAME: _AZURE_ACCOUNT_NAME,
            AzureResourceMetadata.STORAGE_ACCOUNT_ID: _AZURE_ACCOUNT_ID,
            AzureResourceMetadata.ALLOW_NESTED_ITEMS_TO_BE_PUBLIC: True,
            AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED: True,
            AzureResourceMetadata.NETWORK_DEFAULT_ACTION: "Allow",
        },
    )


def _azure_storage_container(account_reference: str) -> NormalizedResource:
    return NormalizedResource(
        address=_AZURE_CONTAINER_ADDRESS,
        provider="azure",
        resource_type=AzureResourceType.STORAGE_CONTAINER,
        name="objects",
        category=ResourceCategory.DATA,
        identifier=(
            "/subscriptions/sub-0001/resourceGroups/application/providers/"
            "Microsoft.Storage/storageAccounts/tfstridelogs/blobServices/default/containers/objects"
        ),
        metadata={
            AzureResourceMetadata.STORAGE_ACCOUNT_REFERENCE: account_reference,
            AzureResourceMetadata.CONTAINER_ACCESS_TYPE: "blob",
        },
    )


def _azure_decoration_snapshot(account_reference: str, *, reverse: bool) -> tuple[object, ...]:
    account = _azure_storage_account()
    container = _azure_storage_container(account_reference)
    resources = [account, container]
    if reverse:
        resources.reverse()

    AzureResourceDecorator(stages=(DecorateStorageRelationshipsStage(),)).decorate(resources)

    return (
        azure_facts(container).resolved_storage_account_address,
        account.direct_internet_reachable,
        container.public_exposure,
        tuple(azure_facts(account).public_container_addresses),
        tuple(container.metadata_snapshot().get("unresolved_storage_account_references", ())),
    )


class ProviderResourceReferenceIndexCharacterizationTests(unittest.TestCase):
    def test_aws_unique_address_native_identifier_and_name_resolution_is_order_independent(self) -> None:
        bucket = _aws_bucket()
        index = AwsResourceIndexBuilder().build([bucket])
        references = (_AWS_BUCKET_ADDRESS, _AWS_BUCKET_ARN, _AWS_BUCKET_NAME)

        for reference in references:
            with self.subTest(reference=reference):
                self.assertIs(index.buckets.get(reference), bucket)
                expected = (
                    (_AWS_POLICY_ADDRESS,),
                    (["s3:GetObject"],),
                    (),
                )
                self.assertEqual(_aws_decoration_snapshot(reference, reverse=False), expected)
                self.assertEqual(_aws_decoration_snapshot(reference, reverse=True), expected)

    def test_gcp_unique_address_native_identifier_and_name_resolution_is_order_independent(self) -> None:
        key = _gcp_key()
        index = GcpResourceIndexBuilder().build([key])
        references = (
            f" {_GCP_KEY_ADDRESS}.id ",
            _GCP_KEY_PATH,
            _GCP_KEY_NAME,
        )

        for reference in references:
            with self.subTest(reference=reference):
                self.assertIs(index.resources_by_reference.get(gcp_reference_key(reference)), key)
                expected = (
                    _GCP_KEY_ADDRESS,
                    _GCP_KEY_PATH,
                    "ENCRYPT_DECRYPT",
                    (),
                )
                self.assertEqual(_gcp_decoration_snapshot(reference, reverse=False), expected)
                self.assertEqual(_gcp_decoration_snapshot(reference, reverse=True), expected)

    def test_azure_unique_address_native_identifier_and_name_resolution_is_order_independent(self) -> None:
        account = _azure_storage_account()
        index = AzureResourceIndexBuilder().build([account])
        references = (
            f"${{{_AZURE_ACCOUNT_ADDRESS}.id}}",
            f" {_AZURE_ACCOUNT_ID.upper()} ",
            _AZURE_ACCOUNT_NAME.upper(),
        )

        for reference in references:
            with self.subTest(reference=reference):
                self.assertIs(index.resolve(reference), account)
                expected = (
                    _AZURE_ACCOUNT_ADDRESS,
                    True,
                    True,
                    (_AZURE_CONTAINER_ADDRESS,),
                    (),
                )
                self.assertEqual(_azure_decoration_snapshot(reference, reverse=False), expected)
                self.assertEqual(_azure_decoration_snapshot(reference, reverse=True), expected)


if __name__ == "__main__":
    unittest.main()
