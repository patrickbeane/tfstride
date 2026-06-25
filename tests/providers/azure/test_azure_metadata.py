from __future__ import annotations

import unittest
from typing import Any

from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.contracts import DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT
from tfstride.providers.metadata_ownership import (
    ProviderMetadataOwnershipError,
    ProviderMetadataWriteValidator,
)
from tfstride.resource_metadata import MetadataField, OptionalStringMetadataField


def _metadata_fields_by_name(namespace: type) -> dict[str, MetadataField[Any]]:
    return {name: value for name, value in vars(namespace).items() if isinstance(value, MetadataField)}


class AzureResourceMetadataTests(unittest.TestCase):
    def test_azure_metadata_namespace_matches_empty_ownership_contract(self) -> None:
        contract = DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT

        self.assertEqual(contract.provider_owned_fields["azure"], frozenset())
        self.assertEqual(_metadata_fields_by_name(AzureResourceMetadata), {})

    def test_azure_metadata_namespace_builds_an_empty_write_validator(self) -> None:
        validator = ProviderMetadataWriteValidator.build(
            provider="azure",
            namespace=AzureResourceMetadata,
        )

        with self.assertRaisesRegex(
            ProviderMetadataOwnershipError,
            "use a field from AzureResourceMetadata",
        ):
            validator.validate(OptionalStringMetadataField("unclassified"))


if __name__ == "__main__":
    unittest.main()
