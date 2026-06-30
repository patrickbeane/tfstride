from __future__ import annotations

import unittest

from tfstride.providers.kubernetes import (
    block_value,
    dedupe,
    first_unknown_block,
    is_broad_public_range,
    uncertainty_evidence,
    unknown_block_at_index,
)


class ProviderKubernetesHelperTests(unittest.TestCase):
    def test_broad_public_range_detects_zero_prefix_and_aliases(self) -> None:
        for value in ("0.0.0.0/0", "::/0", "any", "internet", "*"):
            with self.subTest(value=value):
                self.assertTrue(is_broad_public_range(value))

    def test_broad_public_range_rejects_narrow_or_invalid_values(self) -> None:
        for value in ("10.0.0.0/8", "192.0.2.0/24", "2001:db8::/32", "", None, "not-a-cidr"):
            with self.subTest(value=value):
                self.assertFalse(is_broad_public_range(value))

    def test_unknown_block_helpers_handle_mapping_list_and_boolean_shapes(self) -> None:
        self.assertEqual(first_unknown_block({"field": True}), {"field": True})
        self.assertEqual(first_unknown_block([{"field": True}]), {"field": True})
        self.assertIs(first_unknown_block(True), True)
        self.assertIsNone(first_unknown_block([]))
        self.assertEqual(unknown_block_at_index([{"first": True}, {"second": True}], 1), {"second": True})
        self.assertEqual(unknown_block_at_index({"field": True}, 0), {"field": True})
        self.assertIsNone(unknown_block_at_index({"field": True}, 1))
        self.assertEqual(
            unknown_block_at_index({"field": True}, 1, mapping_applies_to_any_index=True),
            {"field": True},
        )
        self.assertIsNone(unknown_block_at_index([], 0))

    def test_block_value_preserves_unknown_boolean_marker(self) -> None:
        self.assertEqual(block_value({"field": "value"}, "field"), "value")
        self.assertIs(block_value(True, "field"), True)
        self.assertIsNone(block_value(None, "field"))

    def test_dedupe_compacts_strings_stably(self) -> None:
        self.assertEqual(dedupe([" api ", "audit", "api", None, "", "audit", 7]), ["api", "audit", "7"])

    def test_uncertainty_evidence_filters_by_field_markers(self) -> None:
        self.assertEqual(
            uncertainty_evidence(
                [
                    "vpc_config.public_access_cidrs is unknown",
                    "access_config.authentication_mode is unknown",
                    "enabled_cluster_log_types is unknown",
                ],
                ("public_access_cidrs", "enabled_cluster_log_types"),
            ),
            [
                "vpc_config.public_access_cidrs is unknown",
                "enabled_cluster_log_types is unknown",
            ],
        )


if __name__ == "__main__":
    unittest.main()
