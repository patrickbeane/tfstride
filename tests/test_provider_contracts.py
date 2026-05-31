from __future__ import annotations

import unittest
from dataclasses import fields

from tfstride.models import NormalizedResource
from tfstride.providers.contracts import (
    DEFAULT_PROVIDER_ENCAPSULATION_CONTRACT,
    DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT,
)
from tfstride.resource_metadata import MetadataField, ResourceMetadata


def _resource_metadata_field_names() -> set[str]:
    return {
        name
        for name, value in vars(ResourceMetadata).items()
        if isinstance(value, MetadataField)
    }


class ProviderEncapsulationContractTests(unittest.TestCase):
    def test_normalized_resource_fields_match_provider_contract(self) -> None:
        actual_fields = {
            field.name
            for field in fields(NormalizedResource)
            if not field.name.startswith("_")
        }

        self.assertEqual(
            actual_fields,
            DEFAULT_PROVIDER_ENCAPSULATION_CONTRACT.provider_neutral_resource_fields,
        )

    def test_normalized_resource_accessors_are_classified_by_provider_contract(self) -> None:
        actual_accessors = {
            name
            for name, value in vars(NormalizedResource).items()
            if isinstance(value, property)
        }
        provider_neutral = DEFAULT_PROVIDER_ENCAPSULATION_CONTRACT.provider_neutral_resource_accessors
        legacy_provider_owned = DEFAULT_PROVIDER_ENCAPSULATION_CONTRACT.legacy_provider_metadata_accessors
        classified_accessors = provider_neutral | legacy_provider_owned

        self.assertFalse(provider_neutral & legacy_provider_owned)
        self.assertEqual(legacy_provider_owned, frozenset())
        self.assertEqual(actual_accessors - classified_accessors, set())
        self.assertEqual(provider_neutral - actual_accessors, set())
        self.assertEqual(legacy_provider_owned - actual_accessors, set())

    def test_resource_metadata_fields_are_classified_by_ownership_contract(self) -> None:
        contract = DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT
        provider_owned = frozenset().union(*contract.provider_owned_fields.values())
        classified_fields = (
            contract.shared_core_fields
            | provider_owned
            | contract.transitional_fields
        )

        self.assertEqual(_resource_metadata_field_names(), classified_fields)
        self.assertFalse(contract.shared_core_fields & provider_owned)
        self.assertFalse(contract.shared_core_fields & contract.transitional_fields)
        self.assertFalse(provider_owned & contract.transitional_fields)

    def test_resource_metadata_ownership_contract_marks_known_boundaries(self) -> None:
        contract = DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT
        aws_owned = contract.provider_owned_fields["aws"]

        self.assertIn("DIRECT_INTERNET_REACHABLE", contract.shared_core_fields)
        self.assertIn("SECURITY_GROUP_ID", aws_owned)
        self.assertIn("TASK_ROLE_ARN", aws_owned)
        self.assertIn("BUCKET_NAME", contract.transitional_fields)
        self.assertIn("POLICY_DOCUMENT", contract.transitional_fields)
        self.assertNotIn("SECURITY_GROUP_ID", contract.shared_core_fields)

    def test_resource_metadata_ownership_contract_documents_migration_rules(self) -> None:
        guidelines = DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT.guidelines

        self.assertTrue(any("Provider-owned metadata" in item for item in guidelines))
        self.assertTrue(any("Transitional metadata" in item for item in guidelines))

    def test_provider_contract_documents_encapsulation_rules(self) -> None:
        guidelines = DEFAULT_PROVIDER_ENCAPSULATION_CONTRACT.guidelines

        self.assertTrue(any("Provider packages own provider-specific facts" in item for item in guidelines))
        self.assertTrue(any("Do not add new provider-specific convenience accessors" in item for item in guidelines))


if __name__ == "__main__":
    unittest.main()