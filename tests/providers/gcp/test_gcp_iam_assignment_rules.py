from __future__ import annotations

import unittest

from tests.providers.gcp.rule_support.data import (
    _kms_crypto_key_iam_member,
    _secret_manager_secret_iam_member,
)
from tests.providers.gcp.rule_support.iam import (
    _project_iam_custom_role,
    _project_iam_member,
    _service_account_iam_member,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer

_RULE_ID = "gcp-iam-privileged-assignment"


def _findings(resources: list[TerraformResource]):
    inventory = GcpNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class GcpIamAssignmentRuleTests(unittest.TestCase):
    def test_secret_manager_admin_assignment_is_detected(self) -> None:
        findings = _findings(
            [
                _secret_manager_secret_iam_member(
                    member="serviceAccount:deploy@example.iam.gserviceaccount.com",
                    role="roles/secretmanager.admin",
                )
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["google_secret_manager_secret_iam_member.public_accessor"])
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["iam_assignment"],
            [
                "address=google_secret_manager_secret_iam_member.public_accessor",
                "type=google_secret_manager_secret_iam_member",
                "role=roles/secretmanager.admin",
            ],
        )
        self.assertEqual(evidence["privilege_categories"], ["secrets-admin"])
        self.assertEqual(evidence["permission_patterns"], ["roles/secretmanager.admin"])
        self.assertEqual(
            evidence["grant_principals"],
            ["principal_type=service-account; principal=serviceAccount:deploy@example.iam.gserviceaccount.com"],
        )
        self.assertEqual(
            evidence["grant_scopes"], ["scope_kind=resource; scope_value=google_secret_manager_secret.api_key.id"]
        )
        self.assertEqual(evidence["grant_confidence"], ["high"])

    def test_kms_admin_assignment_is_detected(self) -> None:
        findings = _findings(
            [
                _kms_crypto_key_iam_member(
                    member="group:kms-admins@example.com",
                    role="roles/cloudkms.admin",
                )
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        evidence = _evidence_by_key(finding)
        self.assertEqual(evidence["privilege_categories"], ["key-admin"])
        self.assertEqual(evidence["permission_patterns"], ["roles/cloudkms.admin"])
        self.assertEqual(evidence["grant_principals"], ["principal_type=group; principal=group:kms-admins@example.com"])
        self.assertEqual(
            evidence["grant_scopes"],
            ["scope_kind=resource; scope_value=google_kms_crypto_key.customer.id"],
        )

    def test_custom_role_assignment_uses_normalized_permission_patterns(self) -> None:
        findings = _findings(
            [
                _project_iam_custom_role(
                    role_id="deployAdmin",
                    permissions=["iam.serviceAccounts.actAs", "secretmanager.secrets.update"],
                ),
                _secret_manager_secret_iam_member(
                    member="serviceAccount:deploy@example.iam.gserviceaccount.com",
                    role="projects/tfstride-demo/roles/deployAdmin",
                ),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["privilege_categories"], ["privilege-escalation", "secrets-admin"])
        self.assertEqual(
            evidence["permission_patterns"],
            ["iam.serviceAccounts.actAs", "secretmanager.secrets.update"],
        )
        self.assertEqual(
            evidence["assignment_facts"],
            [
                "source=google_secret_manager_secret_iam_member.public_accessor",
                "role=projects/tfstride-demo/roles/deployAdmin",
                "member=serviceAccount:deploy@example.iam.gserviceaccount.com",
                "scope_kind=resource",
                "scope_value=google_secret_manager_secret.api_key.id",
            ],
        )

    def test_unresolved_custom_role_does_not_overclaim_privilege(self) -> None:
        findings = _findings([_secret_manager_secret_iam_member(role="projects/tfstride-demo/roles/missing")])

        self.assertEqual(findings, [])

    def test_non_privileged_secret_accessor_assignment_stays_quiet(self) -> None:
        findings = _findings([_secret_manager_secret_iam_member()])

        self.assertEqual(findings, [])

    def test_legacy_scoped_iam_assignments_stay_with_existing_rules(self) -> None:
        findings = _findings([_project_iam_member("roles/owner"), _service_account_iam_member()])

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
