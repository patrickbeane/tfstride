from __future__ import annotations

import unittest

from tfstride.providers.gcp.attributes import (
    BoolAttribute,
    DictAttribute,
    DictListAttribute,
    GcpAttr,
    GcpValues,
    ListAttribute,
    OptionalIntAttribute,
    OptionalStringAttribute,
    RawAttribute,
    StringListAttribute,
)


class GcpAttributeTests(unittest.TestCase):
    def test_optional_string_trims_values_and_treats_blank_as_missing(self) -> None:
        values = GcpValues({"project": "  demo-project  ", "name": ""})

        self.assertEqual(values.get(GcpAttr.PROJECT), "demo-project")
        self.assertIsNone(values.get(GcpAttr.NAME))
        self.assertIsNone(values.get(OptionalStringAttribute("missing")))

    def test_bool_attribute_uses_default_and_provider_bool_coercion(self) -> None:
        values = GcpValues({"disabled": "enabled", "enable_logging": "false"})

        self.assertTrue(values.get(GcpAttr.DISABLED))
        self.assertFalse(values.get(GcpAttr.ENABLE_LOGGING))
        self.assertTrue(values.get(BoolAttribute("missing", default=True)))

    def test_optional_int_parses_numbers_and_ignores_invalid_values(self) -> None:
        values = GcpValues({"priority": "1000", "not_int": "high"})

        self.assertEqual(values.get(GcpAttr.PRIORITY), 1000)
        self.assertIsNone(values.get(OptionalIntAttribute("not_int")))
        self.assertIsNone(values.get(OptionalIntAttribute("missing")))

    def test_string_list_accepts_scalar_or_list_and_compacts_empty_values(self) -> None:
        values = GcpValues(
            {
                "members": ["user:a@example.com", "", None, "serviceAccount:svc@example.com"],
                "tags": "public",
            }
        )

        self.assertEqual(
            values.get(GcpAttr.MEMBERS),
            ["user:a@example.com", "serviceAccount:svc@example.com"],
        )
        self.assertEqual(values.get(GcpAttr.TAGS), ["public"])
        self.assertEqual(values.get(StringListAttribute("missing")), [])

    def test_dict_attributes_return_detached_copies(self) -> None:
        labels = {"env": "prod"}
        values = GcpValues({"labels": labels})

        parsed = values.get(GcpAttr.LABELS)
        parsed["env"] = "dev"

        self.assertEqual(labels, {"env": "prod"})
        self.assertEqual(values.get(DictAttribute("missing")), {})

    def test_dict_list_attributes_filter_non_dicts_and_return_detached_copies(self) -> None:
        allow = [{"protocol": "tcp"}, "bad", {"protocol": "udp"}]
        values = GcpValues({"allow": allow})

        parsed = values.get(GcpAttr.ALLOW)
        parsed[0]["protocol"] = "icmp"

        self.assertEqual(parsed, [{"protocol": "icmp"}, {"protocol": "udp"}])
        self.assertEqual(allow[0], {"protocol": "tcp"})
        self.assertEqual(values.get(DictListAttribute("missing")), [])

    def test_list_attribute_accepts_scalar_or_list_and_returns_detached_copy(self) -> None:
        policy = {"dead_letter_topic": "projects/demo/topics/dead"}
        values = GcpValues({"dead_letter_policy": [policy], "topic": "projects/demo/topics/events"})

        parsed = values.get(GcpAttr.DEAD_LETTER_POLICY)
        parsed[0]["dead_letter_topic"] = "changed"

        self.assertEqual(policy, {"dead_letter_topic": "projects/demo/topics/dead"})
        self.assertEqual(values.get(ListAttribute("topic")), ["projects/demo/topics/events"])
        self.assertEqual(values.get(ListAttribute("missing")), [])

    def test_raw_and_has_expose_boundary_without_coercion(self) -> None:
        values = GcpValues({"policy_data": '{"bindings": []}', "empty": None})

        self.assertTrue(values.has(GcpAttr.POLICY_DATA))
        self.assertTrue(values.has(RawAttribute("empty")))
        self.assertFalse(values.has(RawAttribute("missing")))
        self.assertEqual(values.raw(GcpAttr.POLICY_DATA), '{"bindings": []}')
        self.assertIsNone(values.raw(RawAttribute("missing")))

    def test_same_key_can_have_scalar_and_block_readers(self) -> None:
        scalar_values = GcpValues({"service_account": "deploy@example.iam.gserviceaccount.com"})
        block_values = GcpValues({"service_account": [{"email": "deploy@example.iam.gserviceaccount.com"}]})

        self.assertEqual(
            scalar_values.get(GcpAttr.SERVICE_ACCOUNT),
            "deploy@example.iam.gserviceaccount.com",
        )
        self.assertEqual(
            block_values.get(GcpAttr.SERVICE_ACCOUNT_BLOCKS),
            [{"email": "deploy@example.iam.gserviceaccount.com"}],
        )


if __name__ == "__main__":
    unittest.main()