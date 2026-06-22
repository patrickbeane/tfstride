from __future__ import annotations

import unittest

from tfstride.providers.names import normalize_provider_name


class ProviderNameTests(unittest.TestCase):
    def test_normalizes_provider_name(self) -> None:
        self.assertEqual(normalize_provider_name(" AWS "), "aws")

    def test_preserves_empty_name_for_caller_validation(self) -> None:
        self.assertEqual(normalize_provider_name("  "), "")


if __name__ == "__main__":
    unittest.main()
