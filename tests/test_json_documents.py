from __future__ import annotations

import unittest

from tfstride.providers.json_documents import load_json_document


class JsonDocumentTests(unittest.TestCase):
    def test_returns_mapping_input_unchanged(self) -> None:
        document = {"Statement": []}

        self.assertIs(load_json_document(document), document)

    def test_loads_json_object_strings(self) -> None:
        self.assertEqual(load_json_document('{"Statement": []}'), {"Statement": []})

    def test_rejects_non_object_json_values(self) -> None:
        for value in ("[1, 2, 3]", '"text"', "null", "true", "42"):
            with self.subTest(value=value):
                self.assertEqual(load_json_document(value), {})

    def test_rejects_blank_malformed_and_unsupported_values(self) -> None:
        for value in ("", "  ", "{not json", None, 42, ["not", "an", "object"]):
            with self.subTest(value=value):
                self.assertEqual(load_json_document(value), {})


if __name__ == "__main__":
    unittest.main()
