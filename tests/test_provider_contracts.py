from __future__ import annotations

import unittest
from dataclasses import fields

from tfstride.models import NormalizedResource
from tfstride.providers.contracts import DEFAULT_PROVIDER_ENCAPSULATION_CONTRACT


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
        self.assertEqual(actual_accessors - classified_accessors, set())
        self.assertEqual(provider_neutral - actual_accessors, set())
        self.assertEqual(legacy_provider_owned - actual_accessors, set())

    def test_provider_contract_documents_encapsulation_rules(self) -> None:
        guidelines = DEFAULT_PROVIDER_ENCAPSULATION_CONTRACT.guidelines

        self.assertTrue(any("Provider packages own provider-specific facts" in item for item in guidelines))
        self.assertTrue(any("Do not add new provider-specific convenience accessors" in item for item in guidelines))


if __name__ == "__main__":
    unittest.main()