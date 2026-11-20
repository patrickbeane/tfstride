from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from tfstride.app import TfStride
from tfstride.reporting.json_report import build_json_report_payload
from tfstride.reporting.report_contract import TFSReportPayload

_ROLE_ADDRESS = "aws_iam_role.worker"
_FOREIGN_ROLE = "arn:aws:iam::444455556666:role/deployer"
_TRUST_RULE_IDS = {"aws-role-trust-expansion", "aws-role-trust-missing-narrowing"}


class AwsTrustActionScopeIntegrationTests(unittest.TestCase):
    def _analyze_trust(self, statements: list[dict[str, Any]]) -> TFSReportPayload:
        payload = {
            "format_version": "1.2",
            "terraform_version": "1.9.8",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "address": _ROLE_ADDRESS,
                            "mode": "managed",
                            "type": "aws_iam_role",
                            "name": "worker",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "name": "worker",
                                "arn": "arn:aws:iam::111122223333:role/worker",
                                "assume_role_policy": json.dumps({"Version": "2012-10-17", "Statement": statements}),
                            },
                        }
                    ]
                }
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            plan_path = Path(directory) / "plan.json"
            plan_path.write_text(json.dumps(payload), encoding="utf-8")
            return build_json_report_payload(TfStride().analyze_plan(plan_path))

    def test_tag_session_does_not_authorize_wildcard_role_assumption(self) -> None:
        report = self._analyze_trust(
            [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                },
                {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:TagSession"},
            ]
        )

        for output in ("findings", "trust_boundaries"):
            with self.subTest(output=output):
                self.assertEqual(report[output], [])

    def test_supplemental_actions_and_statement_order_do_not_create_role_trust(self) -> None:
        for action in ("sts:TagSession", "sts:SetSourceIdentity", ["sts:TagSession", "sts:SetSourceIdentity"]):
            for reverse in (False, True):
                with self.subTest(action=action, reverse=reverse):
                    statements = [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        },
                        {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": action},
                    ]
                    report = self._analyze_trust(list(reversed(statements)) if reverse else statements)

                    self.assertEqual(report["findings"], [])
                    self.assertEqual(report["trust_boundaries"], [])
                    self.assertEqual(report["observations"], [])

    def test_supplemental_actions_do_not_bypass_assume_role_narrowing(self) -> None:
        for principal in (_FOREIGN_ROLE, "*"):
            for reverse in (False, True):
                with self.subTest(principal=principal, reverse=reverse):
                    statements = [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": _FOREIGN_ROLE},
                            "Action": "sts:AssumeRole",
                            "Condition": {"StringEquals": {"sts:ExternalId": "release-pipeline"}},
                        },
                        {"Effect": "Allow", "Principal": {"AWS": principal}, "Action": "sts:TagSession"},
                    ]
                    report = self._analyze_trust(list(reversed(statements)) if reverse else statements)

                    self.assertEqual(report["findings"], [])
                    self.assertEqual(
                        [(boundary["source"], boundary["target"]) for boundary in report["trust_boundaries"]],
                        [(_FOREIGN_ROLE, _ROLE_ADDRESS)],
                    )
                    self.assertEqual(
                        [observation["observation_id"] for observation in report["observations"]],
                        ["aws-role-trust-narrowed"],
                    )
                    evidence = {item["key"]: item["values"] for item in report["observations"][0]["evidence"]}
                    self.assertEqual(evidence["trust_principals"], [_FOREIGN_ROLE])

    def test_assume_role_actions_retain_real_trust_findings(self) -> None:
        cases = [
            ("AWS", _FOREIGN_ROLE, "sts:AssumeRole"),
            ("AWS", _FOREIGN_ROLE, ["sts:TagSession", "sts:AssumeRole", "sts:SetSourceIdentity"]),
            ("AWS", _FOREIGN_ROLE, "*"),
            ("AWS", _FOREIGN_ROLE, "sts:*"),
            ("AWS", _FOREIGN_ROLE, "sts:AssumeRole*"),
            ("AWS", _FOREIGN_ROLE, "sts:AssumeRol?"),
            ("AWS", _FOREIGN_ROLE, "sTs:aSsUmErOlE"),
            ("Federated", "arn:aws:iam::111122223333:saml-provider/CorpSSO", "sts:AssumeRoleWithSAML"),
            (
                "Federated",
                "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com",
                "sts:AssumeRoleWithWebIdentity",
            ),
        ]
        for kind, principal, action in cases:
            with self.subTest(kind=kind, principal=principal, action=action):
                report = self._analyze_trust([{"Effect": "Allow", "Principal": {kind: principal}, "Action": action}])

                self.assertEqual({finding["rule_id"] for finding in report["findings"]}, _TRUST_RULE_IDS)
                self.assertEqual(len(report["findings"]), 2)
                self.assertEqual(
                    [(boundary["source"], boundary["target"]) for boundary in report["trust_boundaries"]],
                    [(principal, _ROLE_ADDRESS)],
                )
                self.assertEqual(report["observations"], [])
                for finding in report["findings"]:
                    evidence = {item["key"]: item["values"] for item in finding["evidence"]}
                    self.assertEqual(evidence["trust_principals"], [principal])
                    self.assertEqual(finding["trust_boundary_id"], report["trust_boundaries"][0]["identifier"])

    def test_narrowed_supplemental_action_does_not_narrow_role_assumption(self) -> None:
        for reverse in (False, True):
            with self.subTest(reverse=reverse):
                statements = [
                    {"Effect": "Allow", "Principal": {"AWS": _FOREIGN_ROLE}, "Action": "sts:AssumeRole"},
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": _FOREIGN_ROLE},
                        "Action": "sts:TagSession",
                        "Condition": {"StringEquals": {"sts:ExternalId": "release-pipeline"}},
                    },
                ]
                report = self._analyze_trust(list(reversed(statements)) if reverse else statements)

                self.assertEqual({finding["rule_id"] for finding in report["findings"]}, _TRUST_RULE_IDS)
                self.assertEqual(report["observations"], [])
