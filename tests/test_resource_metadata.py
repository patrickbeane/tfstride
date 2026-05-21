from __future__ import annotations

import unittest

from tfstride.resource_metadata import InventoryMetadata, ResourceMetadata


class ResourceMetadataFieldTests(unittest.TestCase):
    def test_bool_fields_apply_defaults_and_coerce_on_set(self) -> None:
        metadata = {}

        self.assertTrue(ResourceMetadata.VPC_ENABLED.get(metadata))
        self.assertFalse(ResourceMetadata.DIRECT_INTERNET_REACHABLE.get(metadata))

        ResourceMetadata.DIRECT_INTERNET_REACHABLE.set(metadata, 1)
        ResourceMetadata.VPC_ENABLED.set(metadata, "")

        self.assertTrue(ResourceMetadata.DIRECT_INTERNET_REACHABLE.get(metadata))
        self.assertFalse(ResourceMetadata.VPC_ENABLED.get(metadata))
        self.assertEqual(metadata["direct_internet_reachable"], True)
        self.assertEqual(metadata["vpc_enabled"], False)

    def test_optional_string_fields_trim_and_remove_empty_values(self) -> None:
        metadata = {}

        ResourceMetadata.ROLE_REFERENCE.set(metadata, " app-role ")
        self.assertEqual(ResourceMetadata.ROLE_REFERENCE.get(metadata), "app-role")
        self.assertEqual(metadata["role"], "app-role")

        ResourceMetadata.ROLE_REFERENCE.set(metadata, "  ")
        self.assertIsNone(ResourceMetadata.ROLE_REFERENCE.get(metadata))
        self.assertNotIn("role", metadata)

    def test_list_fields_filter_empty_values(self) -> None:
        metadata = {}

        ResourceMetadata.PUBLIC_ACCESS_REASONS.set(metadata, ["public IP", "", None, 443])

        self.assertEqual(ResourceMetadata.PUBLIC_ACCESS_REASONS.get(metadata), ["public IP", "443"])
        self.assertEqual(metadata["public_access_reasons"], ["public IP", "443"])

    def test_dict_fields_are_copied_on_get_and_set(self) -> None:
        metadata = {}
        policy = {"Statement": [{"Effect": "Allow"}]}

        ResourceMetadata.POLICY_DOCUMENT.set(metadata, policy)
        policy["Statement"][0]["Effect"] = "Deny"
        stored_policy = ResourceMetadata.POLICY_DOCUMENT.get(metadata)
        stored_policy["Statement"][0]["Effect"] = "Mutated"

        self.assertEqual(metadata["policy_document"], {"Statement": [{"Effect": "Allow"}]})
        self.assertEqual(ResourceMetadata.POLICY_DOCUMENT.get(metadata), {"Statement": [{"Effect": "Allow"}]})

    def test_dict_list_fields_filter_non_dicts_and_are_copied(self) -> None:
        metadata = {}
        trust_statements = [{"principals": ["*"]}, "ignored"]

        ResourceMetadata.TRUST_STATEMENTS.set(metadata, trust_statements)
        trust_statements[0]["principals"] = ["mutated"]
        returned = ResourceMetadata.TRUST_STATEMENTS.get(metadata)
        returned[0]["principals"] = ["also-mutated"]

        self.assertEqual(metadata["trust_statements"], [{"principals": ["*"]}])

    def test_bool_dict_fields_coerce_values_and_remove_none(self) -> None:
        metadata = {}

        ResourceMetadata.PUBLIC_ACCESS_BLOCK.set(
            metadata,
            {"block_public_policy": 1, "restrict_public_buckets": ""},
        )

        self.assertEqual(
            ResourceMetadata.PUBLIC_ACCESS_BLOCK.get(metadata),
            {"block_public_policy": True, "restrict_public_buckets": False},
        )

        ResourceMetadata.PUBLIC_ACCESS_BLOCK.set(metadata, None)
        self.assertIsNone(ResourceMetadata.PUBLIC_ACCESS_BLOCK.get(metadata))
        self.assertNotIn("public_access_block", metadata)

    def test_inventory_primary_account_id_uses_same_optional_string_semantics(self) -> None:
        metadata = {}

        InventoryMetadata.PRIMARY_ACCOUNT_ID.set(metadata, " 111122223333 ")
        self.assertEqual(InventoryMetadata.PRIMARY_ACCOUNT_ID.get(metadata), "111122223333")
        self.assertEqual(metadata["primary_account_id"], "111122223333")

        InventoryMetadata.PRIMARY_ACCOUNT_ID.set(metadata, None)
        self.assertIsNone(InventoryMetadata.PRIMARY_ACCOUNT_ID.get(metadata))
        self.assertNotIn("primary_account_id", metadata)


if __name__ == "__main__":
    unittest.main()
