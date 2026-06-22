from __future__ import annotations

import unittest

from tests.providers.gcp.rule_support.compute import (
    _compute_instance,
    _compute_network,
    _compute_subnetwork,
    _public_compute_firewall,
)
from tests.providers.gcp.rule_support.data import (
    _bigquery_dataset,
    _bigquery_dataset_iam_member,
    _cloud_sql_instance,
    _kms_crypto_key,
    _secret_manager_secret,
    _secret_manager_secret_iam_member,
)
from tests.providers.gcp.rule_support.iam import (
    _project_iam_binding,
    _project_iam_custom_role,
    _project_iam_member,
)
from tests.providers.gcp.rule_support.serverless import (
    _cloud_run_service,
    _cloud_run_service_iam_member,
    _cloudfunctions_function,
    _cloudfunctions_function_iam_member,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.providers.gcp.normalizer import GcpNormalizer


class GcpSensitiveDataPathRuleTests(unittest.TestCase):
    def test_public_compute_service_account_secret_access_path_is_detected(self) -> None:
        service_account = "serviceAccount:tfstride-web@tfstride-demo.iam.gserviceaccount.com"
        inventory = GcpNormalizer().normalize(
            [
                _compute_network(),
                _compute_subnetwork(),
                _public_compute_firewall(),
                _compute_instance(),
                _secret_manager_secret(),
                _secret_manager_secret_iam_member(member=service_account),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-workload-sensitive-data-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-public-workload-sensitive-data-access")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            [
                "google_compute_instance.web",
                "google_secret_manager_secret.api_key",
                "google_secret_manager_secret_iam_member.public_accessor",
            ],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            "workload-to-data-store:google_compute_instance.web->google_secret_manager_secret.api_key",
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["workload_identity"], [service_account])
        self.assertEqual(
            evidence["data_access_path"],
            ["google_compute_instance.web reaches google_secret_manager_secret.api_key"],
        )
        self.assertIn(
            "google_secret_manager_secret_iam_member.public_accessor grants roles/secretmanager.secretAccessor",
            evidence["boundary_rationale"][0],
        )

    def test_public_cloud_run_service_account_bigquery_access_path_is_detected(self) -> None:
        service_account = "serviceAccount:tfstride-run@tfstride-demo.iam.gserviceaccount.com"
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run_service(),
                _cloud_run_service_iam_member(),
                _bigquery_dataset(),
                _bigquery_dataset_iam_member(member=service_account),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-workload-sensitive-data-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-public-workload-sensitive-data-access")
        self.assertEqual(
            finding.trust_boundary_id,
            "workload-to-data-store:google_cloud_run_v2_service.api->google_bigquery_dataset.analytics",
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["workload_identity"], [service_account])
        self.assertIn(
            "google_bigquery_dataset_iam_member.public_viewer grants roles/bigquery.dataViewer",
            evidence["boundary_rationale"][0],
        )

    def test_public_cloud_run_service_account_secret_access_path_is_detected(self) -> None:
        service_account = "serviceAccount:tfstride-run@tfstride-demo.iam.gserviceaccount.com"
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run_service(),
                _cloud_run_service_iam_member(),
                _secret_manager_secret(),
                _secret_manager_secret_iam_member(member=service_account),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-workload-sensitive-data-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-public-workload-sensitive-data-access")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            [
                "google_cloud_run_v2_service.api",
                "google_secret_manager_secret.api_key",
                "google_secret_manager_secret_iam_member.public_accessor",
            ],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            "workload-to-data-store:google_cloud_run_v2_service.api->google_secret_manager_secret.api_key",
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["public_exposure_reasons"],
            ["google_cloud_run_v2_service_iam_member.public_invoker grants roles/run.invoker to allUsers"],
        )
        self.assertEqual(evidence["workload_identity"], [service_account])
        self.assertEqual(
            evidence["data_access_path"],
            ["google_cloud_run_v2_service.api reaches google_secret_manager_secret.api_key"],
        )
        self.assertIn(
            "google_secret_manager_secret_iam_member.public_accessor grants roles/secretmanager.secretAccessor",
            evidence["boundary_rationale"][0],
        )

    def test_private_cloud_run_sensitive_data_path_is_not_reported(self) -> None:
        service_account = "serviceAccount:tfstride-run@tfstride-demo.iam.gserviceaccount.com"
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run_service(public_ingress=False),
                _cloud_run_service_iam_member(),
                _secret_manager_secret(),
                _secret_manager_secret_iam_member(member=service_account),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-workload-sensitive-data-access"})),
        )

        self.assertEqual(findings, [])

    def test_public_cloud_function_service_account_secret_access_path_is_detected(self) -> None:
        service_account = "serviceAccount:tfstride-fn@tfstride-demo.iam.gserviceaccount.com"
        inventory = GcpNormalizer().normalize(
            [
                _cloudfunctions_function(),
                _cloudfunctions_function_iam_member(),
                _secret_manager_secret(),
                _secret_manager_secret_iam_member(member=service_account),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-workload-sensitive-data-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(
            finding.affected_resources,
            [
                "google_cloudfunctions_function.fn",
                "google_secret_manager_secret.api_key",
                "google_secret_manager_secret_iam_member.public_accessor",
            ],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            "workload-to-data-store:google_cloudfunctions_function.fn->google_secret_manager_secret.api_key",
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["public_exposure_reasons"],
            [
                "google_cloudfunctions_function_iam_member.public_invoker grants "
                "roles/cloudfunctions.invoker to allUsers"
            ],
        )
        self.assertEqual(evidence["workload_identity"], [service_account])

    def test_project_iam_kms_access_path_is_detected_for_public_compute(self) -> None:
        service_account = "serviceAccount:tfstride-web@tfstride-demo.iam.gserviceaccount.com"
        inventory = GcpNormalizer().normalize(
            [
                _compute_network(),
                _compute_subnetwork(),
                _public_compute_firewall(),
                _compute_instance(),
                _kms_crypto_key(),
                _project_iam_member("roles/cloudkms.cryptoKeyDecrypter", member=service_account),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-workload-sensitive-data-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.affected_resources, ["google_compute_instance.web", "google_kms_crypto_key.customer"])
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertIn(
            "google_project_iam_member.binding grants roles/cloudkms.cryptoKeyDecrypter",
            evidence["boundary_rationale"][0],
        )

    def test_project_iam_custom_role_secret_access_path_is_detected_for_public_compute(self) -> None:
        service_account = "serviceAccount:tfstride-web@tfstride-demo.iam.gserviceaccount.com"
        inventory = GcpNormalizer().normalize(
            [
                _compute_network(),
                _compute_subnetwork(),
                _public_compute_firewall(),
                _compute_instance(),
                _secret_manager_secret(),
                _project_iam_custom_role(
                    role_id="secretReader",
                    permissions=["secretmanager.versions.access"],
                ),
                _project_iam_member("projects/tfstride-demo/roles/secretReader", member=service_account),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-workload-sensitive-data-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(
            finding.affected_resources,
            ["google_compute_instance.web", "google_secret_manager_secret.api_key"],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertIn(
            "google_project_iam_member.binding grants projects/tfstride-demo/roles/secretReader",
            evidence["boundary_rationale"][0],
        )

    def test_project_iam_binding_kms_access_path_is_detected_for_public_compute(self) -> None:
        service_account = "serviceAccount:tfstride-web@tfstride-demo.iam.gserviceaccount.com"
        inventory = GcpNormalizer().normalize(
            [
                _compute_network(),
                _compute_subnetwork(),
                _public_compute_firewall(),
                _compute_instance(),
                _kms_crypto_key(),
                _project_iam_binding("roles/cloudkms.cryptoKeyDecrypter", members=[service_account]),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-workload-sensitive-data-access"})),
        )

        self.assertEqual(len(findings), 1)
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertIn(
            "google_project_iam_binding.binding grants roles/cloudkms.cryptoKeyDecrypter",
            evidence["boundary_rationale"][0],
        )

    def test_private_compute_sensitive_data_path_is_not_reported(self) -> None:
        service_account = "serviceAccount:tfstride-web@tfstride-demo.iam.gserviceaccount.com"
        inventory = GcpNormalizer().normalize(
            [
                _compute_network(),
                _compute_subnetwork(),
                _compute_instance(public=False),
                _secret_manager_secret(),
                _secret_manager_secret_iam_member(member=service_account),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-workload-sensitive-data-access"})),
        )

        self.assertEqual(findings, [])

    def test_public_compute_to_private_cloud_sql_path_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _compute_network(),
                _compute_subnetwork(),
                _public_compute_firewall(),
                _compute_instance(),
                _cloud_sql_instance(
                    ipv4_enabled=False,
                    private_network="google_compute_network.main.id",
                ),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-workload-sensitive-data-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(
            finding.affected_resources,
            ["google_compute_instance.web", "google_sql_database_instance.app"],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            "workload-to-data-store:google_compute_instance.web->google_sql_database_instance.app",
        )


if __name__ == "__main__":
    unittest.main()
