from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tfstride.input.terraform_plan import TerraformPlanLoadError, load_terraform_plan


def _minimal_plan_payload(**extra: object) -> dict[str, object]:
    return {
        "terraform_version": "1.8.5",
        "planned_values": {"root_module": {"resources": []}},
        **extra,
    }


class TerraformPlanParserTests(unittest.TestCase):
    def test_parser_collects_root_and_child_module_resources(self) -> None:
        payload = {
            "terraform_version": "1.8.5",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "address": "aws_vpc.main",
                            "mode": "managed",
                            "type": "aws_vpc",
                            "name": "main",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {"id": "vpc-1"},
                        }
                    ],
                    "child_modules": [
                        {
                            "resources": [
                                {
                                    "address": "module.app.aws_instance.web",
                                    "mode": "managed",
                                    "type": "aws_instance",
                                    "name": "web",
                                    "provider_name": "registry.terraform.io/hashicorp/aws",
                                    "values": {"id": "i-123"},
                                }
                            ]
                        }
                    ],
                }
            },
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            plan_path = Path(tmp_dir) / "plan.json"
            plan_path.write_text(json.dumps(payload), encoding="utf-8")
            plan = load_terraform_plan(plan_path)

        self.assertEqual(plan.terraform_version, "1.8.5")
        self.assertEqual(len(plan.resources), 2)
        self.assertEqual(plan.resources[1].address, "module.app.aws_instance.web")

    def test_parser_preserves_resource_after_unknown_values(self) -> None:
        payload = {
            "terraform_version": "1.8.5",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "address": "azurerm_storage_account.logs",
                            "mode": "managed",
                            "type": "azurerm_storage_account",
                            "name": "logs",
                            "provider_name": "registry.terraform.io/hashicorp/azurerm",
                            "values": {"public_network_access_enabled": None},
                        }
                    ]
                }
            },
            "resource_changes": [
                {
                    "address": "azurerm_storage_account.logs",
                    "change": {
                        "after_unknown": {
                            "public_network_access_enabled": True,
                            "network_rules": [{"default_action": True}],
                        }
                    },
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            plan_path = Path(tmp_dir) / "plan.json"
            plan_path.write_text(json.dumps(payload), encoding="utf-8")
            plan = load_terraform_plan(plan_path)

        self.assertEqual(
            plan.resources[0].unknown_values,
            {
                "public_network_access_enabled": True,
                "network_rules": [{"default_action": True}],
            },
        )
        self.assertTrue(plan.resources[0].has_plan_time_unknown_values)

    def test_parser_rejects_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            plan_path = Path(tmp_dir) / "plan.json"
            plan_path.write_text("{", encoding="utf-8")

            with self.assertRaises(TerraformPlanLoadError) as context:
                load_terraform_plan(plan_path)

        self.assertIn("Failed to parse Terraform plan JSON", str(context.exception))

    def test_parser_rejects_non_plan_json_shape(self) -> None:
        payload = {"planned_values": {"root_module": {"resources": []}}}
        with tempfile.TemporaryDirectory() as tmp_dir:
            plan_path = Path(tmp_dir) / "plan.json"
            plan_path.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaises(TerraformPlanLoadError) as context:
                load_terraform_plan(plan_path)

        self.assertIn("missing `terraform_version`", str(context.exception))

    def test_parser_rejects_errored_plans(self) -> None:
        payload = _minimal_plan_payload(errored=True)
        with tempfile.TemporaryDirectory() as tmp_dir:
            plan_path = Path(tmp_dir) / "plan.json"
            plan_path.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaises(TerraformPlanLoadError) as context:
                load_terraform_plan(plan_path)

        self.assertIn("errored", str(context.exception))

    def test_parser_accepts_non_errored_and_missing_errored_flag(self) -> None:
        for extra in ({}, {"errored": False}):
            with self.subTest(extra=extra):
                payload = _minimal_plan_payload(**extra)
                with tempfile.TemporaryDirectory() as tmp_dir:
                    plan_path = Path(tmp_dir) / "plan.json"
                    plan_path.write_text(json.dumps(payload), encoding="utf-8")
                    plan = load_terraform_plan(plan_path)

                self.assertEqual(plan.resources, [])

    def test_parser_rejects_malformed_errored_flag(self) -> None:
        for value in ("true", 1, None):
            with self.subTest(value=value):
                payload = _minimal_plan_payload(errored=value)
                with tempfile.TemporaryDirectory() as tmp_dir:
                    plan_path = Path(tmp_dir) / "plan.json"
                    plan_path.write_text(json.dumps(payload), encoding="utf-8")

                    with self.assertRaises(TerraformPlanLoadError) as context:
                        load_terraform_plan(plan_path)

                self.assertIn("`errored` must be a boolean", str(context.exception))

    def test_parser_accepts_supported_and_missing_format_versions(self) -> None:
        for extra in ({}, {"format_version": "1.0"}, {"format_version": "1.2"}, {"format_version": "1.99"}):
            with self.subTest(extra=extra):
                payload = _minimal_plan_payload(**extra)
                with tempfile.TemporaryDirectory() as tmp_dir:
                    plan_path = Path(tmp_dir) / "plan.json"
                    plan_path.write_text(json.dumps(payload), encoding="utf-8")
                    plan = load_terraform_plan(plan_path)

                self.assertEqual(plan.resources, [])

    def test_parser_rejects_unsupported_format_versions(self) -> None:
        for value in ("99.0", "2.0", "0.2", "1", "1.x", "", 1.2, None):
            with self.subTest(value=value):
                payload = _minimal_plan_payload(format_version=value)
                with tempfile.TemporaryDirectory() as tmp_dir:
                    plan_path = Path(tmp_dir) / "plan.json"
                    plan_path.write_text(json.dumps(payload), encoding="utf-8")

                    with self.assertRaises(TerraformPlanLoadError) as context:
                        load_terraform_plan(plan_path)

                self.assertIn("format_version", str(context.exception))

    def test_parser_rejects_malformed_resource_entries(self) -> None:
        malformed_payloads = [
            (
                {
                    "terraform_version": "1.8.5",
                    "planned_values": {
                        "root_module": {
                            "resources": [
                                {
                                    "mode": "managed",
                                    "type": "aws_vpc",
                                    "name": "main",
                                    "values": {},
                                }
                            ]
                        }
                    },
                },
                "`planned_values.root_module.resources[0].address` must be a non-empty string",
            ),
            (
                {
                    "terraform_version": "1.8.5",
                    "planned_values": {
                        "root_module": {
                            "resources": [
                                {
                                    "address": "aws_vpc.main",
                                    "mode": "managed",
                                    "type": "aws_vpc",
                                    "name": "main",
                                    "values": [],
                                }
                            ]
                        }
                    },
                },
                "`planned_values.root_module.resources[0].values` must be an object",
            ),
            (
                {
                    "terraform_version": "1.8.5",
                    "planned_values": {
                        "root_module": {
                            "resources": [
                                {
                                    "address": "aws_vpc.main",
                                    "mode": "managed",
                                    "type": "aws_vpc",
                                    "name": "main",
                                    "provider_name": [],
                                    "values": {},
                                }
                            ]
                        }
                    },
                },
                "`planned_values.root_module.resources[0].provider_name` must be a string",
            ),
        ]

        for payload, expected_message in malformed_payloads:
            with self.subTest(expected_message=expected_message):
                with tempfile.TemporaryDirectory() as tmp_dir:
                    plan_path = Path(tmp_dir) / "plan.json"
                    plan_path.write_text(json.dumps(payload), encoding="utf-8")

                    with self.assertRaises(TerraformPlanLoadError) as context:
                        load_terraform_plan(plan_path)

                self.assertIn(expected_message, str(context.exception))

    def test_parser_rejects_malformed_resource_changes(self) -> None:
        payload = {
            "terraform_version": "1.8.5",
            "planned_values": {"root_module": {"resources": []}},
            "resource_changes": {},
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            plan_path = Path(tmp_dir) / "plan.json"
            plan_path.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaises(TerraformPlanLoadError) as context:
                load_terraform_plan(plan_path)

        self.assertIn("`resource_changes` must be an array", str(context.exception))

    def test_parser_rejects_malformed_module_collections(self) -> None:
        malformed_payloads = [
            (
                {
                    "terraform_version": "1.8.5",
                    "planned_values": {"root_module": {"resources": {}}},
                },
                "`planned_values.root_module.resources` must be an array",
            ),
            (
                {
                    "terraform_version": "1.8.5",
                    "planned_values": {"root_module": {"child_modules": ["not-an-object"]}},
                },
                "`planned_values.root_module.child_modules[0]` must be an object",
            ),
        ]

        for payload, expected_message in malformed_payloads:
            with self.subTest(expected_message=expected_message):
                with tempfile.TemporaryDirectory() as tmp_dir:
                    plan_path = Path(tmp_dir) / "plan.json"
                    plan_path.write_text(json.dumps(payload), encoding="utf-8")

                    with self.assertRaises(TerraformPlanLoadError) as context:
                        load_terraform_plan(plan_path)

                self.assertIn(expected_message, str(context.exception))


if __name__ == "__main__":
    unittest.main()
