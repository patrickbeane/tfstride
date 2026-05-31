from __future__ import annotations

import unittest

from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer


class GcpRuleTests(unittest.TestCase):
    def test_project_iam_broad_principal_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                TerraformResource(
                    address="google_project_iam_member.public_viewer",
                    mode="managed",
                    resource_type="google_project_iam_member",
                    name="public_viewer",
                    provider_name="registry.terraform.io/hashicorp/google",
                    values={
                        "project": "tfstride-demo",
                        "role": "roles/viewer",
                        "member": "allUsers",
                    },
                )
            ]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-project-iam-broad-principal")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["google_project_iam_member.public_viewer"])
        self.assertIsNone(finding.trust_boundary_id)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["iam_binding"], ["member=allUsers", "role=roles/viewer"])


if __name__ == "__main__":
    unittest.main()