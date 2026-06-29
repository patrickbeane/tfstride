from __future__ import annotations

import unittest

from tfstride.providers.aws.metadata import (
    AWS_SHARED_CORE_METADATA_FIELD_NAMES,
    AwsResourceMetadata,
)
from tfstride.providers.contracts import DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT
from tfstride.resource_metadata import MetadataField, ResourceMetadata


def _metadata_field_names(namespace: type) -> set[str]:
    return {name for name, value in vars(namespace).items() if isinstance(value, MetadataField)}


class AwsResourceMetadataTests(unittest.TestCase):
    def test_aws_metadata_namespace_covers_classified_fields(self) -> None:
        ownership_contract = DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT
        expected_fields = ownership_contract.provider_owned_fields["aws"] | AWS_SHARED_CORE_METADATA_FIELD_NAMES

        self.assertEqual(_metadata_field_names(AwsResourceMetadata), expected_fields)

    def test_aws_metadata_namespace_aliases_shared_core_fields_only(self) -> None:
        ownership_contract = DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT
        aws_owned = ownership_contract.provider_owned_fields["aws"]

        for field_name in AWS_SHARED_CORE_METADATA_FIELD_NAMES:
            with self.subTest(field_name=field_name):
                self.assertIs(
                    getattr(AwsResourceMetadata, field_name),
                    getattr(ResourceMetadata, field_name),
                )

        for field_name in aws_owned:
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(ResourceMetadata, field_name))

    def test_aws_metadata_provider_fields_keep_existing_metadata_keys(self) -> None:
        expected_keys = {
            "SECURITY_GROUP_ID": "security_group_id",
            "ROLE_REFERENCE": "role",
            "BUCKET_NAME": "bucket",
            "BUCKET_ACL": "acl",
            "POLICY_DOCUMENT": "policy_document",
            "PUBLIC_ACCESS_BLOCK": "public_access_block",
            "RESOURCE_POLICY_SOURCE_ADDRESSES": "resource_policy_source_addresses",
            "S3_VERSIONING_STATUS": "s3_versioning_status",
            "S3_VERSIONING_SOURCE_ADDRESS": "s3_versioning_source_address",
            "S3_ENCRYPTION_ALGORITHM": "s3_encryption_algorithm",
            "S3_KMS_MASTER_KEY_ID": "s3_kms_master_key_id",
            "S3_BUCKET_KEY_ENABLED_STATE": "s3_bucket_key_enabled_state",
            "S3_ENCRYPTION_SOURCE_ADDRESS": "s3_encryption_source_address",
            "S3_VERSIONING_CONFIGURATION": "s3_versioning_configuration",
            "S3_SERVER_SIDE_ENCRYPTION_CONFIGURATION": "s3_server_side_encryption_configuration",
            "S3_POSTURE_UNCERTAINTIES": "s3_posture_uncertainties",
            "EKS_CLUSTER_ARN": "eks_cluster_arn",
            "EKS_CLUSTER_ROLE_ARN": "eks_cluster_role_arn",
            "EKS_ENDPOINT_PUBLIC_ACCESS_STATE": "eks_endpoint_public_access_state",
            "EKS_ENDPOINT_PRIVATE_ACCESS_STATE": "eks_endpoint_private_access_state",
            "EKS_PUBLIC_ACCESS_CIDRS": "eks_public_access_cidrs",
            "EKS_PUBLIC_ACCESS_CIDRS_STATE": "eks_public_access_cidrs_state",
            "EKS_CONTROL_PLANE_LOGGING_STATE": "eks_control_plane_logging_state",
            "EKS_ENABLED_CLUSTER_LOG_TYPES": "eks_enabled_cluster_log_types",
            "EKS_SECRETS_ENCRYPTION_STATE": "eks_secrets_encryption_state",
            "EKS_AUTHENTICATION_MODE": "eks_authentication_mode",
            "EKS_POSTURE_UNCERTAINTIES": "eks_posture_uncertainties",
        }

        for field_name, key in expected_keys.items():
            with self.subTest(field_name=field_name):
                self.assertEqual(getattr(AwsResourceMetadata, field_name).key, key)


if __name__ == "__main__":
    unittest.main()
