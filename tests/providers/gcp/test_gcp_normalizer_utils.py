from __future__ import annotations

import unittest

from tfstride.providers.gcp.coercion import (
    as_bool,
    as_list,
    as_optional_int,
    compact,
    first_item,
)
from tfstride.providers.gcp.resource_utils import last_path_segment


class GcpNormalizerUtilityTests(unittest.TestCase):
    def test_coercion_helpers_normalize_terraform_shapes(self) -> None:
        self.assertEqual(as_list(None), [])
        self.assertEqual(as_list("value"), ["value"])
        self.assertEqual(as_list(("a", "b")), ["a", "b"])
        self.assertEqual(compact(["a", None, "", [], 1]), ["a", "1"])
        self.assertTrue(as_bool("enabled"))
        self.assertFalse(as_bool("disabled"))
        self.assertEqual(as_optional_int("22"), 22)
        self.assertIsNone(as_optional_int("not-a-port"))
        self.assertEqual(first_item([{"name": "first"}]), {"name": "first"})
        self.assertIsNone(first_item(["not-a-map"]))

    def test_resource_helpers_extract_provider_identifiers(self) -> None:
        self.assertEqual(
            last_path_segment("projects/demo/global/networks/tfstride-main"),
            "tfstride-main",
        )
        self.assertIsNone(last_path_segment(""))


if __name__ == "__main__":
    unittest.main()
