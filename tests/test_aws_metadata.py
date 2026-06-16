from __future__ import annotations

import unittest

from tfstride.providers.aws.metadata import (
    AWS_SHARED_CORE_METADATA_FIELD_NAMES,
    AwsResourceMetadata,
)
from tfstride.providers.contracts import DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT
from tfstride.resource_metadata import MetadataField, ResourceMetadata


def _metadata_field_names(namespace: type) -> set[str]:
    return {
        name
        for name, value in vars(namespace).items()
        if isinstance(value, MetadataField)
    }


class AwsResourceMetadataTests(unittest.TestCase):
    def test_aws_metadata_namespace_covers_classified_fields(self) -> None:
        ownership_contract = DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT
        expected_fields = (
            ownership_contract.provider_owned_fields["aws"]
            | ownership_contract.transitional_fields
            | AWS_SHARED_CORE_METADATA_FIELD_NAMES
        )

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

        for field_name in aws_owned | ownership_contract.transitional_fields:
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
        }

        for field_name, key in expected_keys.items():
            with self.subTest(field_name=field_name):
                self.assertEqual(getattr(AwsResourceMetadata, field_name).key, key)


if __name__ == "__main__":
    unittest.main()