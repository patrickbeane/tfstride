from __future__ import annotations

import unittest

from tfstride.resource_metadata import (
    BoolDictMetadataField,
    BoolMetadataField,
    DictListMetadataField,
    DictMetadataField,
    IntMapMetadataField,
    InventoryMetadata,
    OptionalIntMetadataField,
    OptionalStringMetadataField,
    ResourceMetadata,
    StringListMetadataField,
)


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
        field = OptionalStringMetadataField("role")

        field.set(metadata, " app-role ")
        self.assertEqual(field.get(metadata), "app-role")
        self.assertEqual(metadata["role"], "app-role")

        field.set(metadata, "  ")
        self.assertIsNone(field.get(metadata))
        self.assertNotIn("role", metadata)

    def test_list_fields_filter_empty_values(self) -> None:
        metadata = {}

        ResourceMetadata.PUBLIC_ACCESS_REASONS.set(metadata, ["public IP", "", None, 443])

        self.assertEqual(ResourceMetadata.PUBLIC_ACCESS_REASONS.get(metadata), ["public IP", "443"])
        self.assertEqual(metadata["public_access_reasons"], ["public IP", "443"])

    def test_list_fields_append_unique_values(self) -> None:
        metadata = {"public_access_reasons": ["existing", None]}

        ResourceMetadata.PUBLIC_ACCESS_REASONS.append_unique(metadata, "existing")
        ResourceMetadata.PUBLIC_ACCESS_REASONS.append_unique(metadata, "new")
        ResourceMetadata.PUBLIC_ACCESS_REASONS.append_unique(metadata, "new")
        ResourceMetadata.PUBLIC_ACCESS_REASONS.append_unique(metadata, None)
        ResourceMetadata.PUBLIC_ACCESS_REASONS.append_unique(metadata, "")

        self.assertEqual(ResourceMetadata.PUBLIC_ACCESS_REASONS.get(metadata), ["existing", "new"])
        self.assertEqual(metadata["public_access_reasons"], ["existing", "new"])

    def test_list_fields_extend_unique_values_in_one_write(self) -> None:
        metadata = {"public_access_reasons": ["existing", None]}

        ResourceMetadata.PUBLIC_ACCESS_REASONS.extend_unique(
            metadata,
            ["existing", "new", "new", None, "", "another"],
        )

        self.assertEqual(
            ResourceMetadata.PUBLIC_ACCESS_REASONS.get(metadata),
            ["existing", "new", "another"],
        )
        self.assertEqual(metadata["public_access_reasons"], ["existing", "new", "another"])

    def test_list_fields_extend_unique_noops_without_valid_values(self) -> None:
        metadata = {}

        ResourceMetadata.PUBLIC_ACCESS_REASONS.extend_unique(metadata, [None, ""])

        self.assertEqual(metadata, {})

    def test_dict_fields_are_copied_on_get_and_set(self) -> None:
        metadata = {}
        field = DictMetadataField("policy_document")
        policy = {"Statement": [{"Effect": "Allow"}]}

        field.set(metadata, policy)
        policy["Statement"][0]["Effect"] = "Deny"
        stored_policy = field.get(metadata)
        stored_policy["Statement"][0]["Effect"] = "Mutated"

        self.assertEqual(metadata["policy_document"], {"Statement": [{"Effect": "Allow"}]})
        self.assertEqual(field.get(metadata), {"Statement": [{"Effect": "Allow"}]})

    def test_dict_list_fields_filter_non_dicts_and_are_copied(self) -> None:
        metadata = {}
        field = DictListMetadataField("trust_statements")
        trust_statements = [{"principals": ["*"]}, "ignored"]

        field.set(metadata, trust_statements)
        trust_statements[0]["principals"] = ["mutated"]
        returned = field.get(metadata)
        returned[0]["principals"] = ["also-mutated"]

        self.assertEqual(metadata["trust_statements"], [{"principals": ["*"]}])

    def test_bool_dict_fields_coerce_values_and_remove_none(self) -> None:
        metadata = {}
        field = BoolDictMetadataField("public_access_block")

        field.set(
            metadata,
            {"block_public_policy": 1, "restrict_public_buckets": ""},
        )

        self.assertEqual(
            field.get(metadata),
            {"block_public_policy": True, "restrict_public_buckets": False},
        )

        field.set(metadata, None)
        self.assertIsNone(field.get(metadata))
        self.assertNotIn("public_access_block", metadata)

    def test_core_bool_fields_are_declared(self) -> None:
        fields = [
            (ResourceMetadata.PUBLIC_ACCESS_CONFIGURED, "public_access_configured"),
            (ResourceMetadata.DIRECT_INTERNET_REACHABLE, "direct_internet_reachable"),
            (ResourceMetadata.VPC_ENABLED, "vpc_enabled"),
        ]

        for field, key in fields:
            with self.subTest(key=key):
                self.assertIsInstance(field, BoolMetadataField)
                self.assertEqual(field.key, key)

    def test_core_string_list_fields_are_declared(self) -> None:
        fields = [
            (ResourceMetadata.PUBLIC_ACCESS_REASONS, "public_access_reasons"),
            (ResourceMetadata.PUBLIC_EXPOSURE_REASONS, "public_exposure_reasons"),
            (ResourceMetadata.INTERNET_INGRESS_REASONS, "internet_ingress_reasons"),
        ]

        for field, key in fields:
            with self.subTest(key=key):
                self.assertIsInstance(field, StringListMetadataField)
                self.assertEqual(field.key, key)

    def test_inventory_primary_account_id_uses_same_optional_string_semantics(self) -> None:
        metadata = {}

        InventoryMetadata.PRIMARY_ACCOUNT_ID.set(metadata, " 111122223333 ")
        self.assertEqual(InventoryMetadata.PRIMARY_ACCOUNT_ID.get(metadata), "111122223333")
        self.assertEqual(metadata["primary_account_id"], "111122223333")

        InventoryMetadata.PRIMARY_ACCOUNT_ID.set(metadata, None)
        self.assertIsNone(InventoryMetadata.PRIMARY_ACCOUNT_ID.get(metadata))
        self.assertNotIn("primary_account_id", metadata)

    def test_inventory_count_fields_use_optional_int_semantics(self) -> None:
        metadata = {}

        InventoryMetadata.TOTAL_INPUT_RESOURCES.set(metadata, 3)
        InventoryMetadata.PROVIDER_RESOURCE_COUNT.set(metadata, "2")
        InventoryMetadata.NORMALIZED_RESOURCE_COUNT.set(metadata, 1)

        self.assertEqual(InventoryMetadata.TOTAL_INPUT_RESOURCES.get(metadata), 3)
        self.assertEqual(InventoryMetadata.PROVIDER_RESOURCE_COUNT.get(metadata), 2)
        self.assertEqual(InventoryMetadata.NORMALIZED_RESOURCE_COUNT.get(metadata), 1)

        metadata["total_input_resources"] = "unknown"
        self.assertIsNone(InventoryMetadata.TOTAL_INPUT_RESOURCES.get(metadata))

        InventoryMetadata.NORMALIZED_RESOURCE_COUNT.set(metadata, None)
        self.assertNotIn("normalized_resource_count", metadata)

    def test_inventory_collection_fields_are_declared_and_coerce_values(self) -> None:
        metadata = {}

        InventoryMetadata.SUPPORTED_RESOURCE_TYPES.set(metadata, ["aws_vpc", "", None, 42])
        InventoryMetadata.UNSUPPORTED_RESOURCE_TYPES.set(
            metadata,
            {"aws_cloudwatch_log_group": "2", "invalid": "unknown", 3: 4},
        )

        self.assertIsInstance(InventoryMetadata.SUPPORTED_RESOURCE_TYPES, StringListMetadataField)
        self.assertIsInstance(InventoryMetadata.UNSUPPORTED_RESOURCE_TYPES, IntMapMetadataField)
        self.assertEqual(
            InventoryMetadata.SUPPORTED_RESOURCE_TYPES.get(metadata),
            ["aws_vpc", "42"],
        )
        self.assertEqual(
            InventoryMetadata.UNSUPPORTED_RESOURCE_TYPES.get(metadata),
            {"3": 4, "aws_cloudwatch_log_group": 2},
        )

        InventoryMetadata.UNSUPPORTED_RESOURCE_TYPES.set(metadata, None)
        self.assertNotIn("unsupported_resource_types", metadata)

    def test_inventory_count_fields_are_declared(self) -> None:
        fields = [
            (InventoryMetadata.TOTAL_INPUT_RESOURCES, "total_input_resources"),
            (InventoryMetadata.PROVIDER_RESOURCE_COUNT, "provider_resource_count"),
            (InventoryMetadata.NORMALIZED_RESOURCE_COUNT, "normalized_resource_count"),
        ]

        for field, key in fields:
            with self.subTest(key=key):
                self.assertIsInstance(field, OptionalIntMetadataField)
                self.assertEqual(field.key, key)


if __name__ == "__main__":
    unittest.main()
