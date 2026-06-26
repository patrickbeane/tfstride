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
    def test_azure_metadata_namespace_matches_ownership_contract(self) -> None:
        contract = DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT
        expected_fields = {
            "NAME",
            "STORAGE_ACCOUNT_ID",
            "STORAGE_ACCOUNT_REFERENCE",
            "RESOLVED_STORAGE_ACCOUNT_ADDRESS",
            "CONTAINER_ACCESS_TYPE",
            "MIN_TLS_VERSION",
            "NETWORK_DEFAULT_ACTION",
            "NETWORK_RULE_SOURCE_ADDRESS",
            "ALLOW_NESTED_ITEMS_TO_BE_PUBLIC",
            "SHARED_ACCESS_KEY_ENABLED",
            "PUBLIC_NETWORK_ACCESS_ENABLED",
            "PUBLIC_CONTAINER_ADDRESSES",
            "UNRESOLVED_STORAGE_ACCOUNT_REFERENCES",
            "STORAGE_POSTURE_UNCERTAINTIES",
            "LOCATION",
            "VIRTUAL_NETWORK_REFERENCE",
            "RESOLVED_VIRTUAL_NETWORK_ADDRESS",
            "NETWORK_SECURITY_GROUP_REFERENCE",
            "SUBNET_REFERENCE",
            "NETWORK_INTERFACE_REFERENCE",
            "PUBLIC_IP_ADDRESS",
            "VM_SIZE",
            "OS_TYPE",
            "DEFAULT_OUTBOUND_ACCESS_ENABLED",
            "IP_FORWARDING_ENABLED",
            "ADDRESS_SPACE",
            "ADDRESS_PREFIXES",
            "NETWORK_INTERFACE_REFERENCES",
            "PUBLIC_IP_REFERENCES",
            "RESOLVED_SUBNET_ADDRESSES",
            "RESOLVED_NETWORK_SECURITY_GROUP_ADDRESSES",
            "RESOLVED_NETWORK_INTERFACE_ADDRESSES",
            "RESOLVED_PUBLIC_IP_ADDRESSES",
            "ASSOCIATED_RESOURCE_ADDRESSES",
            "STANDALONE_RULE_ADDRESSES",
            "UNRESOLVED_RESOURCE_REFERENCES",
            "IP_CONFIGURATIONS",
            "NETWORK_SECURITY_RULES",
            "PUBLIC_COMPUTE_EXPOSURE_PATHS",
        }

        self.assertEqual(contract.provider_owned_fields["azure"], frozenset(expected_fields))
        self.assertEqual(set(_metadata_fields_by_name(AzureResourceMetadata)), expected_fields)

    def test_azure_metadata_namespace_builds_write_validator(self) -> None:
        validator = ProviderMetadataWriteValidator.build(
            provider="azure",
            namespace=AzureResourceMetadata,
        )

        validator.validate(AzureResourceMetadata.STORAGE_ACCOUNT_ID)
        with self.assertRaisesRegex(
            ProviderMetadataOwnershipError,
            "use a field from AzureResourceMetadata",
        ):
            validator.validate(OptionalStringMetadataField("unclassified"))


if __name__ == "__main__":
    unittest.main()
