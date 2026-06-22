from __future__ import annotations

import unittest

from tests.providers.gcp.rule_support.common import _org_policy_policy
from tests.providers.gcp.rule_support.data import (
    _bigquery_dataset,
    _bigquery_dataset_iam_member,
)
from tests.providers.gcp.rule_support.iam import (
    _project_iam_member,
    _service_account,
    _service_account_iam_binding,
    _service_account_iam_member,
    _service_account_iam_policy,
    _service_account_key,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.providers.gcp.normalizer import GcpNormalizer


class GcpServiceAccountRuleTests(unittest.TestCase):
    def test_service_account_iam_public_principal_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_service_account(), _service_account_iam_binding()])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-service-account-iam-broad-principal"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-service-account-iam-broad-principal")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            ["google_service_account.deploy", "google_service_account_iam_binding.deploy_users"],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["iam_binding"],
            [
                "source=google_service_account_iam_binding.deploy_users",
                "member=allUsers",
                "role=roles/iam.serviceAccountUser",
            ],
        )
        self.assertEqual(evidence["trust_scope"], ["member is public GCP principal `allUsers`"])
        self.assertEqual(evidence["service_account_reference"], ["google_service_account.deploy.name"])

    def test_service_account_iam_domain_principal_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _service_account(),
                _service_account_iam_member(
                    role="roles/iam.serviceAccountUser",
                    member="domain:example.com",
                ),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-service-account-iam-broad-principal"})),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity.value, "medium")
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(evidence["trust_scope"], ["member grants a whole Google Workspace domain"])

    def test_service_account_iam_high_risk_role_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _service_account(),
                _service_account_iam_policy(
                    [
                        {"role": "roles/viewer", "members": ["group:ops@example.com"]},
                        {
                            "role": "roles/iam.serviceAccountTokenCreator",
                            "members": ["group:deploy@example.com"],
                        },
                    ]
                ),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-service-account-iam-privileged-role"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-service-account-iam-privileged-role")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            ["google_service_account.deploy", "google_service_account_iam_policy.deploy_policy"],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["iam_binding"],
            [
                "source=google_service_account_iam_policy.deploy_policy",
                "member=group:deploy@example.com",
                "role=roles/iam.serviceAccountTokenCreator",
            ],
        )
        self.assertEqual(evidence["role_risk"], ["service account token minting and impersonation"])

    def test_service_account_key_hygiene_includes_organization_guardrail_evidence(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _org_policy_policy(
                    "google_org_policy_policy.disable_sa_keys",
                    constraint="constraints/iam.disableServiceAccountKeyCreation",
                    enforced=True,
                ),
                _service_account(),
                _service_account_key(),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-service-account-key-hygiene"})),
        )

        finding = findings[0]
        self.assertEqual(finding.severity.value, "low")
        self.assertIsNotNone(finding.severity_reasoning)
        assert finding.severity_reasoning is not None
        self.assertEqual(finding.severity_reasoning.final_score, 1)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["organization_guardrails"],
            [
                "constraint=constraints/iam.disableServiceAccountKeyCreation; "
                "scope=project:tfstride-demo; "
                "source=google_org_policy_policy.disable_sa_keys; "
                "enforced=true"
            ],
        )

    def test_service_account_key_hygiene_detects_long_lived_key_without_keepers(self) -> None:
        inventory = GcpNormalizer().normalize([_service_account(), _service_account_key()])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-service-account-key-hygiene"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-service-account-key-hygiene")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(
            finding.affected_resources,
            ["google_service_account.deploy", "google_service_account_key.deploy"],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["key_context"],
            [
                "source=google_service_account_key.deploy",
                "service_account_reference=google_service_account.deploy.name",
                "key_algorithm=KEY_ALG_RSA_2048",
                "public_key_type=TYPE_X509_PEM_FILE",
            ],
        )
        self.assertEqual(
            evidence["key_risk"],
            [
                "Terraform manages a user-created service-account key",
                "validity window is 365 days and exceeds 180-day threshold",
                "no Terraform keepers rotation trigger observed",
            ],
        )
        self.assertEqual(
            evidence["validity_window"],
            [
                "valid_after=2026-01-01T00:00:00Z",
                "valid_before=2027-01-01T00:00:00Z",
                "validity_days=365",
            ],
        )
        self.assertEqual(
            evidence["rotation_control"],
            ["no Terraform keepers rotation trigger observed"],
        )

    def test_service_account_key_effective_access_detects_sensitive_data_grant(self) -> None:
        service_account = "serviceAccount:tfstride-deploy@tfstride-demo.iam.gserviceaccount.com"
        inventory = GcpNormalizer().normalize(
            [
                _service_account(),
                _service_account_key(),
                _bigquery_dataset(),
                _bigquery_dataset_iam_member(member=service_account),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-service-account-key-effective-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-service-account-key-effective-access")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            [
                "google_service_account.deploy",
                "google_service_account_key.deploy",
                "google_bigquery_dataset.analytics",
                "google_bigquery_dataset_iam_member.public_viewer",
            ],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["service_account_principals"],
            [
                "serviceAccount:tfstride-deploy@tfstride-demo.iam.gserviceaccount.com",
                "tfstride-deploy@tfstride-demo.iam.gserviceaccount.com",
            ],
        )
        self.assertEqual(
            evidence["effective_access"],
            [
                "resource=google_bigquery_dataset.analytics; "
                "source=google_bigquery_dataset_iam_member.public_viewer; "
                "scope=BigQuery dataset IAM; role=roles/bigquery.dataViewer; "
                "member=serviceAccount:tfstride-deploy@tfstride-demo.iam.gserviceaccount.com; "
                "risk=BigQuery dataset IAM grants roles/bigquery.dataViewer",
            ],
        )

    def test_service_account_key_effective_access_ignores_viewer_only_project_grant(self) -> None:
        service_account = "serviceAccount:tfstride-deploy@tfstride-demo.iam.gserviceaccount.com"
        inventory = GcpNormalizer().normalize(
            [
                _service_account(),
                _service_account_key(),
                _project_iam_member("roles/viewer", member=service_account),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-service-account-key-effective-access"})),
        )

        self.assertEqual(findings, [])

    def test_service_account_key_effective_access_detects_service_account_iam_grant(self) -> None:
        service_account = "serviceAccount:tfstride-deploy@tfstride-demo.iam.gserviceaccount.com"
        inventory = GcpNormalizer().normalize(
            [
                _service_account(),
                _service_account_key(),
                _service_account_iam_member(member=service_account),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-service-account-key-effective-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            [
                "google_service_account.deploy",
                "google_service_account_key.deploy",
                "google_service_account_iam_member.deploy_token_creator",
            ],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["effective_access"],
            [
                "resource=google_service_account.deploy; "
                "source=google_service_account_iam_member.deploy_token_creator; "
                "scope=service account IAM; role=roles/iam.serviceAccountTokenCreator; "
                "member=serviceAccount:tfstride-deploy@tfstride-demo.iam.gserviceaccount.com; "
                "risk=service account token minting and impersonation",
            ],
        )

    def test_service_account_iam_low_risk_group_binding_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _service_account(),
                _service_account_iam_member(
                    role="roles/viewer",
                    member="group:ops@example.com",
                ),
            ]
        )

        engine = StrideRuleEngine()

        self.assertEqual(
            engine.evaluate(
                inventory,
                [],
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-service-account-iam-broad-principal"})),
            ),
            [],
        )
        self.assertEqual(
            engine.evaluate(
                inventory,
                [],
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-service-account-iam-privileged-role"})),
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
