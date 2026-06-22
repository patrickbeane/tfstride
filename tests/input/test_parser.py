from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tfstride.input.terraform_plan import TerraformPlanLoadError, load_terraform_plan


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
