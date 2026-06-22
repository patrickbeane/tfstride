from __future__ import annotations

import unittest

from tests.providers.gcp.rule_support.common import _org_policy_policy
from tests.providers.gcp.rule_support.iam import (
    _project_iam_binding,
    _project_iam_custom_role,
    _project_iam_member,
    _project_iam_policy,
)
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.providers.gcp.normalizer import GcpNormalizer


class GcpProjectIamRuleTests(unittest.TestCase):
    def test_project_iam_broad_principal_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _project_iam_member(
                    "roles/viewer",
                    member="allUsers",
                )
            ]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-project-iam-broad-principal")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["google_project_iam_member.binding"])
        self.assertIsNone(finding.trust_boundary_id)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["iam_binding"], ["member=allUsers", "role=roles/viewer"])

    def test_project_iam_broad_principal_includes_organization_guardrail_evidence(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _org_policy_policy(
                    "google_org_policy_policy.allowed_domains",
                    constraint="constraints/iam.allowedPolicyMemberDomains",
                    allowed_values=["C01abcd"],
                ),
                _project_iam_member(
                    "roles/viewer",
                    member="allUsers",
                ),
            ]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        finding = findings[0]
        self.assertEqual(finding.severity.value, "low")
        self.assertIsNotNone(finding.severity_reasoning)
        assert finding.severity_reasoning is not None
        self.assertEqual(finding.severity_reasoning.final_score, 1)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["organization_guardrails"],
            [
                "constraint=constraints/iam.allowedPolicyMemberDomains; "
                "scope=project:tfstride-demo; "
                "source=google_org_policy_policy.allowed_domains; "
                "allowed_values=C01abcd"
            ],
        )

    def test_project_iam_binding_broad_principal_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [_project_iam_binding("roles/viewer", members=["allAuthenticatedUsers", "group:ops@example.com"])]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-project-iam-broad-principal")
        self.assertEqual(finding.affected_resources, ["google_project_iam_binding.binding"])
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["iam_binding"], ["member=allAuthenticatedUsers", "role=roles/viewer"])

    def test_project_iam_privileged_role_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_project_iam_member("roles/owner")])

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-project-iam-privileged-role")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(finding.affected_resources, ["google_project_iam_member.binding"])
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["iam_binding"],
            ["member=serviceAccount:deploy@example.iam.gserviceaccount.com", "role=roles/owner"],
        )
        self.assertEqual(evidence["role_risk"], ["full project administration"])

    def test_project_iam_policy_privileged_role_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _project_iam_policy(
                    [
                        {"role": "roles/viewer", "members": ["group:ops@example.com"]},
                        {"role": "roles/owner", "members": ["group:admins@example.com"]},
                    ]
                )
            ]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-project-iam-privileged-role")
        self.assertEqual(finding.affected_resources, ["google_project_iam_policy.policy"])
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["iam_binding"], ["member=group:admins@example.com", "role=roles/owner"])

    def test_project_iam_admin_class_role_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_project_iam_member("roles/compute.admin")])

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual([finding.rule_id for finding in findings], ["gcp-project-iam-privileged-role"])
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(
            evidence["role_risk"],
            ["admin-level control over a GCP service or project security surface"],
        )

    def test_project_iam_custom_role_privileged_permissions_are_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _project_iam_custom_role(
                    role_id="deployAdmin",
                    permissions=["iam.serviceAccounts.actAs", "cloudfunctions.functions.update"],
                ),
                _project_iam_member("projects/tfstride-demo/roles/deployAdmin"),
            ]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual([finding.rule_id for finding in findings], ["gcp-project-iam-privileged-role"])
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(
            evidence["role_risk"],
            [
                "custom role includes high-impact permissions: cloudfunctions.functions.update, iam.serviceAccounts.actAs"
            ],
        )
        self.assertEqual(
            evidence["custom_role_permissions"],
            ["cloudfunctions.functions.update", "iam.serviceAccounts.actAs"],
        )

    def test_public_principal_with_privileged_role_reports_both_iam_findings(self) -> None:
        inventory = GcpNormalizer().normalize([_project_iam_member("roles/owner", member="allUsers")])

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(
            {finding.rule_id for finding in findings},
            {"gcp-project-iam-privileged-role", "gcp-project-iam-broad-principal"},
        )

    def test_project_iam_viewer_service_account_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize([_project_iam_member("roles/viewer")])

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
