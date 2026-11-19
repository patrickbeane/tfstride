from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tfstride.app import TfStride
from tfstride.reporting.json_report import build_json_report_payload


class AwsTrustActionScopeIntegrationTests(unittest.TestCase):
    def test_tag_session_does_not_authorize_wildcard_role_assumption(self) -> None:
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                },
                {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:TagSession"},
            ],
        }
        payload = {
            "format_version": "1.2",
            "terraform_version": "1.9.8",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "address": "aws_iam_role.worker",
                            "mode": "managed",
                            "type": "aws_iam_role",
                            "name": "worker",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "name": "worker",
                                "arn": "arn:aws:iam::111122223333:role/worker",
                                "assume_role_policy": json.dumps(trust_policy),
                            },
                        }
                    ]
                }
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            plan_path = Path(directory) / "plan.json"
            plan_path.write_text(json.dumps(payload), encoding="utf-8")
            report = build_json_report_payload(TfStride().analyze_plan(plan_path))

        for output in ("findings", "trust_boundaries"):
            with self.subTest(output=output):
                self.assertEqual(report[output], [])
