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
    def test_aws_metadata_namespace_covers_owned_and_transitional_fields(self) -> None:
        ownership_contract = DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT
        expected_fields = (
            ownership_contract.provider_owned_fields["aws"]
            | ownership_contract.transitional_fields
            | AWS_SHARED_CORE_METADATA_FIELD_NAMES
        )

        self.assertEqual(_metadata_field_names(AwsResourceMetadata), expected_fields)

    def test_aws_metadata_namespace_preserves_underlying_field_objects(self) -> None:
        for field_name in _metadata_field_names(AwsResourceMetadata):
            with self.subTest(field_name=field_name):
                self.assertIs(
                    getattr(AwsResourceMetadata, field_name),
                    getattr(ResourceMetadata, field_name),
                )


if __name__ == "__main__":
    unittest.main()