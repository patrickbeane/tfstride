from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cloud_threat_modeler.input.terraform_plan import load_terraform_plan


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


if __name__ == "__main__":
    unittest.main()
