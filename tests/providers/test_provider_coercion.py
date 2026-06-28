from __future__ import annotations

import unittest

from tfstride.providers import coercion


class ProviderCoercionTests(unittest.TestCase):
    def test_common_shape_helpers_support_provider_options(self) -> None:
        self.assertTrue(coercion.as_bool("on"))
        self.assertFalse(coercion.as_bool("off"))
        self.assertTrue(coercion.as_bool("off", allow_on_off=False))

        self.assertEqual(coercion.as_list(("a", "b")), ["a", "b"])
        self.assertEqual(coercion.as_list(("a", "b"), expand_tuples=False), [("a", "b")])

        self.assertEqual(coercion.as_optional_int("443"), 443)
        self.assertIsNone(coercion.as_optional_int(""))
        self.assertEqual(coercion.compact([None, "", [], "value", 12]), ["value", "12"])
        self.assertEqual(coercion.compact_strings([" a ", "a", None, "b"]), ["a", "b"])

    def test_first_mapping_preserves_provider_list_semantics(self) -> None:
        values = ["not-a-block", {"name": "later"}]

        self.assertIsNone(coercion.first_mapping(values))
        self.assertEqual(coercion.first_mapping(values, scan_all=True), {"name": "later"})
        self.assertIsNone(coercion.first_mapping(({"name": "tuple"},)))
        self.assertEqual(coercion.first_mapping(({"name": "tuple"},), expand_tuples=True), {"name": "tuple"})

    def test_known_block_helpers_record_uncertainty(self) -> None:
        uncertainties: list[str] = []
        unknown_fields: list[str] = []

        self.assertIsNone(
            coercion.known_block_string(
                {"name": "private"},
                {"name": True},
                "name",
                uncertainties,
                path="private_service_connection[0]",
                unknown_fields=unknown_fields,
            )
        )

        self.assertEqual(uncertainties, ["private_service_connection[0].name is unknown after planning"])
        self.assertEqual(unknown_fields, ["name"])

        uncertainties.clear()
        self.assertEqual(
            coercion.known_block_bool_state(
                {"bucket_key_enabled": True},
                {},
                "bucket_key_enabled",
                uncertainties,
                path="rule",
            ),
            "enabled",
        )
        self.assertEqual(uncertainties, [])


if __name__ == "__main__":
    unittest.main()
