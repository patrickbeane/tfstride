from __future__ import annotations

import unittest
from collections import Counter

from tests.integration.analysis_support import (
    AZURE_COMPUTE_FIXTURE_PATH,
    AZURE_FIXTURE_PATH,
    AZURE_IDENTITY_FIXTURE_PATH,
    AZURE_NIGHTMARE_FIXTURE_PATH,
    AZURE_NSG_PRECEDENCE_FIXTURE_PATH,
    AZURE_SAFE_FIXTURE_PATH,
    AZURE_STORAGE_FIXTURE_PATH,
    BASELINE_FIXTURE_PATH,
    FIXTURE_PATH,
    GCP_BASELINE_FIXTURE_PATH,
    GCP_CROSS_PROJECT_IAM_FIXTURE_PATH,
    GCP_FIXTURE_PATH,
    GCP_LB_COMPUTE_SQL_FIXTURE_PATH,
    GCP_NIGHTMARE_FIXTURE_PATH,
    GCP_SAFE_FIXTURE_PATH,
    GCP_SERVERLESS_FIXTURE_PATH,
    NIGHTMARE_FIXTURE_PATH,
    SAFE_FIXTURE_PATH,
    TFSIntegrationTestCase,
)
from tfstride.analysis.rule_registry import RulePolicy, default_rule_registry
from tfstride.app import TfStride
from tfstride.models import (
    BoundaryType,
    Severity,
)


class FixtureAnalysisIntegrationTests(TFSIntegrationTestCase):
    def test_analysis_normalizes_supported_resources_and_tracks_unsupported(self) -> None:
        self.assertEqual(len(self.result.inventory.resources), 23)
        self.assertIn("aws_cloudwatch_log_group.processor", self.result.inventory.unsupported_resources)
        resource_types = {resource.resource_type for resource in self.result.inventory.resources}
        self.assertIn("aws_security_group_rule", resource_types)
        self.assertIn("aws_nat_gateway", resource_types)
        self.assertIn("aws_iam_role_policy_attachment", resource_types)
        self.assertIn("aws_route_table_association", resource_types)

    def test_analysis_discovers_expected_trust_boundaries(self) -> None:
        boundary_types = {boundary.boundary_type for boundary in self.result.trust_boundaries}
        self.assertIn(BoundaryType.INTERNET_TO_SERVICE, boundary_types)
        self.assertIn(BoundaryType.PUBLIC_TO_PRIVATE, boundary_types)
        self.assertIn(BoundaryType.WORKLOAD_TO_DATA_STORE, boundary_types)
        self.assertIn(BoundaryType.CONTROL_TO_WORKLOAD, boundary_types)
        self.assertIn(BoundaryType.CROSS_ACCOUNT_OR_ROLE, boundary_types)

    def test_analysis_emits_deterministic_findings(self) -> None:
        findings_by_title = {finding.title: finding for finding in self.result.findings}
        expected_titles = {
            "Internet-exposed compute service permits overly broad ingress",
            "Cross-account or broad role trust lacks narrowing conditions",
            "Database is reachable from overly permissive sources",
            "Object storage is publicly accessible",
            "IAM policy grants wildcard privileges",
            "Workload role carries sensitive permissions",
            "Private data tier directly trusts the public application tier",
            "Role trust relationship expands blast radius",
        }
        self.assertTrue(expected_titles.issubset(findings_by_title))
        self.assertEqual(
            findings_by_title["Database is reachable from overly permissive sources"].severity, Severity.HIGH
        )
        self.assertEqual(findings_by_title["Workload role carries sensitive permissions"].severity, Severity.HIGH)

    def test_findings_include_structured_evidence_and_severity_reasoning(self) -> None:
        findings_by_title = {finding.title: finding for finding in self.result.findings}
        database_finding = findings_by_title["Database is reachable from overly permissive sources"]

        evidence_by_key = {item.key: item.values for item in database_finding.evidence}
        self.assertIn("security_group_rules", evidence_by_key)
        self.assertIn("network_path", evidence_by_key)
        self.assertIn("subnet_posture", evidence_by_key)
        self.assertIsNotNone(database_finding.severity_reasoning)
        self.assertEqual(database_finding.severity_reasoning.final_score, 6)
        self.assertEqual(database_finding.severity_reasoning.severity, Severity.HIGH)

    def test_unencrypted_rds_instances_are_detected_with_evidence(self) -> None:
        nightmare_result = self.engine.analyze_plan(NIGHTMARE_FIXTURE_PATH)
        findings_by_title = {finding.title: finding for finding in nightmare_result.findings}
        encryption_finding = findings_by_title["Database storage encryption is disabled"]

        self.assertEqual(encryption_finding.severity, Severity.MEDIUM)
        self.assertEqual(encryption_finding.affected_resources, ["aws_db_instance.customer"])
        self.assertIsNone(encryption_finding.trust_boundary_id)
        evidence_by_key = {item.key: item.values for item in encryption_finding.evidence}
        self.assertEqual(
            evidence_by_key["encryption_posture"],
            ["storage_encrypted is false", "engine is postgres"],
        )
        self.assertEqual(encryption_finding.severity_reasoning.final_score, 3)

    def test_fixture_scenarios_have_expected_finding_profiles(self) -> None:
        scenarios = {
            "safe": (SAFE_FIXTURE_PATH, 0, {}),
            "baseline": (BASELINE_FIXTURE_PATH, 6, {"medium": 5, "low": 1}),
            "mixed": (FIXTURE_PATH, 15, {"high": 4, "medium": 10, "low": 1}),
            "nightmare": (NIGHTMARE_FIXTURE_PATH, 25, {"high": 7, "medium": 17, "low": 1}),
            "gcp-safe": (GCP_SAFE_FIXTURE_PATH, 0, {}),
            "gcp-baseline": (GCP_BASELINE_FIXTURE_PATH, 4, {"high": 2, "medium": 2}),
            "gcp-lb-compute-sql": (GCP_LB_COMPUTE_SQL_FIXTURE_PATH, 1, {"medium": 1}),
            "gcp-serverless": (GCP_SERVERLESS_FIXTURE_PATH, 5, {"high": 2, "medium": 3}),
            "gcp-cross-project-iam": (GCP_CROSS_PROJECT_IAM_FIXTURE_PATH, 6, {"high": 3, "medium": 3}),
            "gcp-inventory": (GCP_FIXTURE_PATH, 23, {"high": 6, "medium": 17}),
            "gcp-nightmare": (GCP_NIGHTMARE_FIXTURE_PATH, 42, {"high": 14, "medium": 26, "low": 2}),
            "azure-safe": (AZURE_SAFE_FIXTURE_PATH, 0, {}),
            "azure-compute": (AZURE_COMPUTE_FIXTURE_PATH, 3, {"medium": 3}),
            "azure-identity": (AZURE_IDENTITY_FIXTURE_PATH, 5, {"high": 2, "medium": 3}),
            "azure-inventory": (AZURE_FIXTURE_PATH, 24, {"high": 3, "medium": 16, "low": 5}),
            "azure-nightmare": (AZURE_NIGHTMARE_FIXTURE_PATH, 36, {"high": 7, "medium": 24, "low": 5}),
            "azure-nsg-precedence": (AZURE_NSG_PRECEDENCE_FIXTURE_PATH, 1, {"medium": 1}),
            "azure-storage": (AZURE_STORAGE_FIXTURE_PATH, 7, {"high": 2, "medium": 5}),
        }

        expected_titles = {
            "safe": {},
            "baseline": {
                "IAM policy grants wildcard privileges": 1,
                "Sensitive data tier is transitively reachable from an internet-exposed path": 1,
                "Workload uses S3 without a VPC endpoint": 1,
                "VPC Flow Logs are not configured for a modeled VPC": 1,
                "Public Application Load Balancer is not associated with a WAF Web ACL": 1,
                "RDS database does not export engine CloudWatch logs": 1,
            },
            "mixed": {
                "Cross-account or broad role trust lacks narrowing conditions": 1,
                "Database is reachable from overly permissive sources": 1,
                "Private data tier directly trusts the public application tier": 1,
                "Workload role carries sensitive permissions": 1,
                "IAM policy grants wildcard privileges": 2,
                "IAM role has privileged assignment posture": 1,
                "Internet-exposed compute service permits overly broad ingress": 1,
                "Object storage is publicly accessible": 1,
                "Role trust relationship expands blast radius": 1,
                "Workload uses KMS without a VPC endpoint": 1,
                "Workload uses S3 without a VPC endpoint": 1,
                "VPC Flow Logs are not configured for a modeled VPC": 1,
                "Public Application Load Balancer is not associated with a WAF Web ACL": 1,
                "RDS database does not export engine CloudWatch logs": 1,
            },
            "nightmare": {
                "Cross-account or broad role trust lacks narrowing conditions": 2,
                "Database is reachable from overly permissive sources": 1,
                "Database storage encryption is disabled": 1,
                "RDS automated backup retention is disabled or too short": 1,
                "RDS deletion protection is disabled": 1,
                "Private data tier directly trusts the public application tier": 1,
                "Role trust relationship expands blast radius": 2,
                "Workload role carries sensitive permissions": 2,
                "IAM policy grants wildcard privileges": 3,
                "IAM role has privileged assignment posture": 2,
                "Internet-exposed compute service permits overly broad ingress": 2,
                "Object storage is publicly accessible": 2,
                "Workload uses KMS without a VPC endpoint": 1,
                "Workload uses S3 without a VPC endpoint": 1,
                "VPC Flow Logs are not configured for a modeled VPC": 1,
                "Public Application Load Balancer is not associated with a WAF Web ACL": 1,
                "RDS database does not export engine CloudWatch logs": 1,
            },
            "gcp-safe": {},
            "gcp-baseline": {
                "Cloud SQL point-in-time recovery is disabled": 1,
                "GCP project IAM binding grants a high-privilege role": 1,
                "GCP subnetwork Flow Logs are not configured": 1,
                "Inherited GCP IAM grant expands descendant blast radius": 1,
            },
            "gcp-lb-compute-sql": {
                "GCP subnetwork Flow Logs are not configured": 1,
            },
            "gcp-serverless": {
                "Cloud Functions function is publicly invokable": 1,
                "Cloud Run service is publicly invokable": 1,
                "GCP subnetwork Flow Logs are not configured": 1,
                "Internet-exposed GCP workload can access sensitive data services": 2,
            },
            "gcp-cross-project-iam": {
                "GCP project IAM binding grants a high-privilege role": 1,
                "GCP subnetwork Flow Logs are not configured": 1,
                "Sensitive GCP resource IAM binding allows broad or external access": 2,
                "Inherited GCP IAM grant reaches sensitive resources": 1,
                "Inherited GCP IAM grant expands descendant blast radius": 1,
            },
            "gcp-inventory": {
                "BigQuery IAM binding allows public or broad data access": 1,
                "Cloud SQL automated backups are disabled": 1,
                "Cloud SQL deletion protection is disabled": 1,
                "Cloud SQL instance accepts public authorized network access": 1,
                "Cloud SQL public IPv4 is enabled without private network access": 1,
                "Cloud SQL public client access does not require SSL": 1,
                "GCP compute instance disables OS Login": 1,
                "GCP service account user-managed key lacks rotation hygiene": 1,
                "GCP subnetwork Flow Logs are not configured": 1,
                "GCP service account key can exercise sensitive or privileged access": 1,
                "GCS bucket does not enforce Public Access Prevention": 1,
                "GCS bucket is publicly accessible": 1,
                "GCS sensitive bucket does not use customer-managed encryption": 1,
                "GCS sensitive bucket retention policy is insufficient": 1,
                "GCS sensitive bucket versioning is disabled": 1,
                "Internet-exposed GCP compute instance permits broad ingress": 1,
                "Internet-exposed GCP workload can access sensitive data services": 1,
                "Inherited GCP IAM grant expands descendant blast radius": 1,
                "Pub/Sub IAM binding allows public or broad data access": 1,
                "Sensitive GCP resource IAM binding allows broad or external access": 2,
                "Secret Manager secret does not use customer-managed encryption": 1,
                "Secret Manager lifecycle posture is incomplete": 1,
            },
            "gcp-nightmare": {
                "BigQuery IAM binding allows public or broad data access": 1,
                "Cloud Functions function is publicly invokable": 1,
                "Cloud Run service is publicly invokable": 1,
                "Cloud SQL automated backups are disabled": 1,
                "Cloud SQL deletion protection is disabled": 1,
                "Cloud SQL instance accepts public authorized network access": 1,
                "Cloud SQL public IPv4 is enabled without private network access": 1,
                "Cloud SQL public client access does not require SSL": 1,
                "GCP compute instance disables OS Login": 1,
                "GCP organization or folder IAM grants a high-privilege role": 1,
                "GCP organization or folder IAM grants access to broad principals": 1,
                "GCP project IAM binding grants a high-privilege role": 1,
                "GCP project IAM binding grants access to public principals": 1,
                "GCP service account user-managed key lacks rotation hygiene": 1,
                "GCP service account key can exercise sensitive or privileged access": 1,
                "GCS bucket does not enforce Public Access Prevention": 1,
                "GCS bucket is publicly accessible": 1,
                "GCS sensitive bucket does not use customer-managed encryption": 1,
                "GCS sensitive bucket retention policy is insufficient": 1,
                "GCS sensitive bucket versioning is disabled": 1,
                "GKE cluster does not enable Workload Identity": 1,
                "GKE cluster exposes a public control plane": 1,
                "GKE control plane allows broad authorized networks": 1,
                "GKE node metadata exposure is not hardened": 1,
                "GKE node pool uses broad node identity settings": 1,
                "GKE control-plane logging is incomplete": 1,
                "GKE network policy is not enabled": 1,
                "GKE secrets encryption is not configured": 1,
                "GKE legacy ABAC is enabled or unknown": 1,
                "GKE Shielded Nodes is not enabled": 1,
                "GCP subnetwork Flow Logs are not configured": 1,
                "Internet-exposed GCP compute instance permits broad ingress": 1,
                "Internet-exposed GCP workload can access sensitive data services": 3,
                "Inherited GCP IAM grant reaches sensitive resources": 1,
                "Inherited GCP IAM grant expands descendant blast radius": 1,
                "Pub/Sub IAM binding allows public or broad data access": 1,
                "Sensitive GCP resource IAM binding allows broad or external access": 2,
                "Secret Manager secret does not use customer-managed encryption": 1,
                "Secret Manager lifecycle posture is incomplete": 1,
            },
            "azure-safe": {},
            "azure-compute": {
                "Internet-exposed Azure virtual machine permits broad ingress": 1,
                "Azure Network Security Group lacks flow-log coverage": 2,
            },
            "azure-identity": {
                "Azure managed identity has broad RBAC authority": 1,
                "Internet-exposed Azure workload can access sensitive resources": 1,
                "Internet-exposed Azure virtual machine permits broad ingress": 1,
                "Azure Network Security Group lacks flow-log coverage": 1,
                "Azure resource lacks diagnostic settings": 1,
            },
            "azure-inventory": {
                "AKS control plane is public without narrow authorized IP ranges": 1,
                "AKS local accounts are not disabled": 1,
                "AKS RBAC posture is weak or not deterministic": 1,
                "AKS network policy is not configured": 1,
                "AKS workload identity is not fully enabled": 1,
                "AKS Key Management Service is not configured": 1,
                "AKS monitoring agent is not enabled": 1,
                "AKS Defender coverage is not enabled": 1,
                "AKS Azure Policy add-on is not enabled": 1,
                "Azure Key Vault allows unrestricted public network access": 1,
                "Azure Key Vault purge protection is disabled": 1,
                "Azure Key Vault lacks resolved private endpoint coverage": 1,
                "Azure Storage account permits Shared Key authorization": 1,
                "Azure Storage account permits nested public blob access": 1,
                "Azure Storage account allows TLS below 1.2": 1,
                "Azure Storage account allows unrestricted public network access": 1,
                "Azure Storage account lacks resolved private endpoint coverage": 1,
                "Azure Storage container is publicly accessible": 1,
                "Internet-exposed Azure virtual machine permits broad ingress": 1,
                "Azure Network Security Group lacks flow-log coverage": 2,
                "Azure resource lacks diagnostic settings": 3,
            },
            "azure-nightmare": {
                "AKS control plane is public without narrow authorized IP ranges": 1,
                "AKS local accounts are not disabled": 1,
                "AKS RBAC posture is weak or not deterministic": 1,
                "AKS network policy is not configured": 1,
                "AKS workload identity is not fully enabled": 1,
                "AKS Key Management Service is not configured": 1,
                "AKS monitoring agent is not enabled": 1,
                "AKS Defender coverage is not enabled": 1,
                "AKS Azure Policy add-on is not enabled": 1,
                "Azure Key Vault allows unrestricted public network access": 1,
                "Azure Key Vault purge protection is disabled": 1,
                "Azure Key Vault lacks resolved private endpoint coverage": 1,
                "Azure Storage account permits Shared Key authorization": 2,
                "Azure Storage account permits nested public blob access": 2,
                "Azure Storage account allows TLS below 1.2": 2,
                "Azure Storage account allows unrestricted public network access": 2,
                "Azure Storage account lacks resolved private endpoint coverage": 2,
                "Azure Storage container is publicly accessible": 3,
                "Azure managed identity has broad RBAC authority": 1,
                "Internet-exposed Azure workload can access sensitive resources": 1,
                "Internet-exposed Azure virtual machine permits broad ingress": 2,
                "Azure Network Security Group lacks flow-log coverage": 3,
                "Azure resource lacks diagnostic settings": 4,
            },
            "azure-nsg-precedence": {
                "Azure Network Security Group lacks flow-log coverage": 1,
            },
            "azure-storage": {
                "Azure Storage account permits Shared Key authorization": 1,
                "Azure Storage account permits nested public blob access": 1,
                "Azure Storage account allows TLS below 1.2": 1,
                "Azure Storage account allows unrestricted public network access": 1,
                "Azure Storage account lacks resolved private endpoint coverage": 1,
                "Azure Storage container is publicly accessible": 1,
                "Azure resource lacks diagnostic settings": 1,
            },
        }

        for name, (fixture_path, expected_count, expected_severities) in scenarios.items():
            with self.subTest(scenario=name):
                result = self.engine.analyze_plan(fixture_path)
                severity_counts = Counter(finding.severity.value for finding in result.findings)
                title_counts = Counter(finding.title for finding in result.findings)

                self.assertEqual(len(result.findings), expected_count)
                self.assertEqual(dict(severity_counts), expected_severities)
                self.assertEqual(dict(title_counts), expected_titles[name])

    def test_gcp_inherited_iam_blast_radius_fixture_findings_are_explicit(self) -> None:
        scenarios = {
            "gcp-baseline": {
                "fixture_path": GCP_BASELINE_FIXTURE_PATH,
                "severity": Severity.HIGH,
                "source": "google_project_iam_member.deploy_admin",
                "affected_count": 8,
                "iam_binding": [
                    "source=google_project_iam_member.deploy_admin",
                    "scope=project:tfstride-demo",
                    "member=group:deploy@example.com",
                    "role=projects/tfstride-demo/roles/deployAdmin",
                ],
                "role_risk": ["custom role includes high-impact permissions: iam.serviceAccounts.actAs"],
                "descendant_scope": [
                    "scope=project:tfstride-demo",
                    "descendant_count=7",
                    "resource_type_count=7",
                    "projects=tfstride-demo",
                ],
                "descendant_type": "google_project_iam_custom_role: 1",
                "descendant_resource": "google_storage_bucket.logs",
                "custom_role_permissions": ["iam.serviceAccounts.actAs"],
            },
            "gcp-cross-project-iam": {
                "fixture_path": GCP_CROSS_PROJECT_IAM_FIXTURE_PATH,
                "severity": Severity.HIGH,
                "source": "google_project_iam_member.partner_editor",
                "affected_count": 6,
                "iam_binding": [
                    "source=google_project_iam_member.partner_editor",
                    "scope=project:tfstride-demo",
                    "member=serviceAccount:deployer@partner-project.iam.gserviceaccount.com",
                    "role=roles/editor",
                ],
                "role_risk": ["broad write access across most project services"],
                "trust_scope": [
                    "service account belongs to project `partner-project`, outside resource project `tfstride-demo`"
                ],
                "descendant_scope": [
                    "scope=project:tfstride-demo",
                    "descendant_count=5",
                    "resource_type_count=5",
                    "projects=tfstride-demo",
                ],
                "descendant_type": "google_kms_crypto_key: 1",
                "descendant_resource": "google_service_account.web",
            },
            "gcp-inventory": {
                "fixture_path": GCP_FIXTURE_PATH,
                "severity": Severity.MEDIUM,
                "source": "google_project_iam_member.web_viewer",
                "affected_count": 18,
                "iam_binding": [
                    "source=google_project_iam_member.web_viewer",
                    "scope=project:tfstride-demo",
                    "member=serviceAccount:tfstride-web@example.iam.gserviceaccount.com",
                    "role=roles/viewer",
                ],
                "trust_scope": [
                    "service account belongs to project `example`, outside resource project `tfstride-demo`"
                ],
                "descendant_scope": [
                    "scope=project:tfstride-demo",
                    "descendant_count=17",
                    "resource_type_count=16",
                    "projects=tfstride-demo",
                ],
                "descendant_type": "google_compute_firewall: 2",
                "descendant_resource": "and 7 more descendant resources",
            },
            "gcp-nightmare": {
                "fixture_path": GCP_NIGHTMARE_FIXTURE_PATH,
                "severity": Severity.HIGH,
                "source": "google_project_iam_member.public_owner",
                "affected_count": 22,
                "iam_binding": [
                    "source=google_project_iam_member.public_owner",
                    "scope=project:tfstride-demo",
                    "member=allUsers",
                    "role=roles/owner",
                ],
                "role_risk": ["full project administration"],
                "trust_scope": ["member is public GCP principal `allUsers`"],
                "descendant_scope": [
                    "scope=project:tfstride-demo",
                    "descendant_count=21",
                    "resource_type_count=20",
                    "projects=tfstride-demo",
                ],
                "descendant_type": "google_cloud_run_v2_service: 1",
                "descendant_resource": "and 11 more descendant resources",
            },
        }

        for name, expected in scenarios.items():
            with self.subTest(scenario=name):
                result = self.engine.analyze_plan(expected["fixture_path"])
                blast_radius_findings = [
                    finding for finding in result.findings if finding.rule_id == "gcp-inherited-iam-blast-radius"
                ]

                self.assertEqual(len(blast_radius_findings), 1)
                finding = blast_radius_findings[0]
                evidence_by_key = {item.key: item.values for item in finding.evidence}

                self.assertEqual(finding.severity, expected["severity"])
                self.assertEqual(finding.affected_resources[0], expected["source"])
                self.assertEqual(len(finding.affected_resources), expected["affected_count"])
                self.assertEqual(evidence_by_key["iam_binding"], expected["iam_binding"])
                self.assertEqual(evidence_by_key["descendant_scope"], expected["descendant_scope"])
                self.assertIn(
                    expected["descendant_type"],
                    evidence_by_key["descendant_resource_types"],
                )
                self.assertIn(
                    expected["descendant_resource"],
                    evidence_by_key["descendant_resources"],
                )
                if "role_risk" in expected:
                    self.assertEqual(evidence_by_key["role_risk"], expected["role_risk"])
                else:
                    self.assertNotIn("role_risk", evidence_by_key)
                if "trust_scope" in expected:
                    self.assertEqual(evidence_by_key["trust_scope"], expected["trust_scope"])
                else:
                    self.assertNotIn("trust_scope", evidence_by_key)
                if "custom_role_permissions" in expected:
                    self.assertEqual(
                        evidence_by_key["custom_role_permissions"],
                        expected["custom_role_permissions"],
                    )

    def test_gcp_inherited_iam_blast_radius_is_absent_from_low_blast_fixtures(self) -> None:
        scenarios = {
            "gcp-safe": GCP_SAFE_FIXTURE_PATH,
            "gcp-lb-compute-sql": GCP_LB_COMPUTE_SQL_FIXTURE_PATH,
            "gcp-serverless": GCP_SERVERLESS_FIXTURE_PATH,
        }

        for name, fixture_path in scenarios.items():
            with self.subTest(scenario=name):
                result = self.engine.analyze_plan(fixture_path)

                self.assertNotIn(
                    "gcp-inherited-iam-blast-radius",
                    {finding.rule_id for finding in result.findings},
                )

    def test_gcp_fixture_auto_selects_provider_and_detects_public_boundaries(self) -> None:
        result = self.engine.analyze_plan(GCP_FIXTURE_PATH)

        self.assertEqual(result.inventory.provider, "gcp")
        self.assertEqual(len(result.inventory.resources), 23)
        self.assertEqual(result.inventory.unsupported_resources, [])
        self.assertEqual(result.analysis_coverage.resources.provider_resources, 23)
        self.assertEqual(result.analysis_coverage.resources.normalized_resources, 23)
        self.assertEqual(result.analysis_coverage.resources.unsupported_resources, 0)
        self.assertEqual(result.analysis_coverage.resources.unsupported_resource_types, {})
        self.assertEqual(len(result.findings), 23)
        findings_by_rule = {finding.rule_id: finding for finding in result.findings}
        finding = findings_by_rule["gcp-public-compute-broad-ingress"]
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertEqual(
            finding.affected_resources,
            ["google_compute_instance.web", "google_compute_firewall.public_ssh"],
        )
        self.assertEqual(
            findings_by_rule["gcp-compute-os-login-disabled"].affected_resources,
            ["google_compute_instance.web"],
        )
        self.assertEqual(
            findings_by_rule["gcp-service-account-key-hygiene"].affected_resources,
            ["google_service_account.web", "google_service_account_key.web"],
        )
        self.assertEqual(
            findings_by_rule["gcp-service-account-key-effective-access"].affected_resources,
            [
                "google_service_account.web",
                "google_service_account_key.web",
                "google_bigquery_dataset.analytics",
                "google_bigquery_dataset_iam_binding.analytics_viewers",
            ],
        )
        gcs_finding = findings_by_rule["gcp-gcs-public-access"]
        self.assertEqual(gcs_finding.severity, Severity.MEDIUM)
        self.assertEqual(gcs_finding.affected_resources, ["google_storage_bucket.logs"])
        self.assertEqual(
            findings_by_rule["gcp-gcs-public-access-prevention-not-enforced"].affected_resources,
            ["google_storage_bucket.logs"],
        )
        self.assertEqual(
            findings_by_rule["gcp-gcs-versioning-disabled"].affected_resources,
            ["google_storage_bucket.logs"],
        )
        self.assertEqual(
            findings_by_rule["gcp-gcs-customer-managed-encryption-missing"].affected_resources,
            ["google_storage_bucket.logs"],
        )
        self.assertEqual(
            findings_by_rule["gcp-gcs-retention-policy-insufficient"].affected_resources,
            ["google_storage_bucket.logs"],
        )
        self.assertEqual(
            findings_by_rule["gcp-secret-manager-customer-managed-encryption-missing"].affected_resources,
            ["google_secret_manager_secret.api_key"],
        )
        cloud_sql_public_finding = findings_by_rule["gcp-cloud-sql-public-authorized-network"]
        self.assertEqual(cloud_sql_public_finding.severity, Severity.HIGH)
        self.assertEqual(cloud_sql_public_finding.affected_resources, ["google_sql_database_instance.app"])
        cloud_sql_backup_finding = findings_by_rule["gcp-cloud-sql-backup-disabled"]
        self.assertEqual(cloud_sql_backup_finding.severity, Severity.MEDIUM)
        self.assertEqual(cloud_sql_backup_finding.affected_resources, ["google_sql_database_instance.app"])
        self.assertEqual(
            findings_by_rule["gcp-cloud-sql-public-ip-without-private-network"].affected_resources,
            ["google_sql_database_instance.app"],
        )
        self.assertEqual(
            findings_by_rule["gcp-cloud-sql-ssl-not-required"].affected_resources,
            ["google_sql_database_instance.app"],
        )
        self.assertEqual(
            findings_by_rule["gcp-cloud-sql-deletion-protection-disabled"].affected_resources,
            ["google_sql_database_instance.app"],
        )
        self.assertEqual(
            findings_by_rule["gcp-pubsub-public-access"].affected_resources,
            ["google_pubsub_topic.events", "google_pubsub_topic_iam_member.public_publisher"],
        )
        self.assertEqual(
            findings_by_rule["gcp-bigquery-public-access"].affected_resources,
            ["google_bigquery_dataset.analytics", "google_bigquery_dataset_iam_binding.analytics_viewers"],
        )
        self.assertEqual(
            findings_by_rule["gcp-public-workload-sensitive-data-access"].affected_resources,
            [
                "google_compute_instance.web",
                "google_bigquery_dataset.analytics",
                "google_bigquery_dataset_iam_binding.analytics_viewers",
            ],
        )
        sensitive_iam_findings = [
            finding for finding in result.findings if finding.rule_id == "gcp-sensitive-resource-iam-external-access"
        ]
        self.assertEqual(len(sensitive_iam_findings), 2)
        self.assertEqual(
            {finding.severity for finding in sensitive_iam_findings},
            {Severity.HIGH, Severity.MEDIUM},
        )
        self.assertEqual(len(result.trust_boundaries), 4)
        boundaries_by_target = {boundary.target: boundary for boundary in result.trust_boundaries}
        boundary = boundaries_by_target["google_compute_instance.web"]
        self.assertEqual(boundary.boundary_type, BoundaryType.INTERNET_TO_SERVICE)
        self.assertEqual(boundary.source, "internet")
        self.assertEqual(finding.trust_boundary_id, boundary.identifier)
        self.assertEqual(
            gcs_finding.trust_boundary_id,
            boundaries_by_target["google_storage_bucket.logs"].identifier,
        )
        self.assertEqual(
            cloud_sql_public_finding.trust_boundary_id,
            boundaries_by_target["google_sql_database_instance.app"].identifier,
        )
        self.assertIsNone(cloud_sql_backup_finding.trust_boundary_id)
        self.assertEqual(
            findings_by_rule["gcp-public-workload-sensitive-data-access"].trust_boundary_id,
            boundaries_by_target["google_bigquery_dataset.analytics"].identifier,
        )

    def test_safe_fixture_emits_observations_for_s3_block_and_private_encrypted_rds(self) -> None:
        result = self.engine.analyze_plan(SAFE_FIXTURE_PATH)
        observation_titles = [observation.title for observation in result.observations]
        observations_by_title = {observation.title: observation for observation in result.observations}

        self.assertEqual(
            observation_titles,
            [
                "RDS instance is private and storage encrypted",
                "S3 public access is reduced by a public access block",
            ],
        )

        bucket_observation = observations_by_title["S3 public access is reduced by a public access block"]
        bucket_evidence = {item.key: item.values for item in bucket_observation.evidence}
        self.assertEqual(
            bucket_evidence["mitigated_public_access"],
            [
                "bucket ACL `public-read` would otherwise grant public access",
                "bucket policy would otherwise allow anonymous access",
            ],
        )
        self.assertIn("block_public_acls is true", bucket_evidence["control_posture"])
        self.assertIn("block_public_policy is true", bucket_evidence["control_posture"])

        database_observation = observations_by_title["RDS instance is private and storage encrypted"]
        database_evidence = {item.key: item.values for item in database_observation.evidence}
        self.assertEqual(
            database_evidence["database_posture"],
            [
                "publicly_accessible is false",
                "storage_encrypted is true",
                "no attached security group allows internet ingress",
                "engine is postgres",
            ],
        )

    def test_safe_fixture_public_access_block_suppresses_bucket_exposure(self) -> None:
        result = self.engine.analyze_plan(SAFE_FIXTURE_PATH)
        bucket = result.inventory.get_by_address("aws_s3_bucket.artifacts")

        self.assertIsNotNone(bucket)
        self.assertFalse(bucket.public_exposure)
        self.assertIn("public_access_block", bucket.metadata)
        finding_titles = {finding.title for finding in result.findings}
        self.assertNotIn("Object storage is publicly accessible", finding_titles)

    def test_rule_policy_can_disable_rules_and_override_severity(self) -> None:
        enabled_rule_ids = default_rule_registry().default_enabled_rule_ids()
        enabled_rule_ids.remove("aws-database-permissive-ingress")
        engine = TfStride(
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset(enabled_rule_ids),
                severity_overrides={"aws-workload-role-sensitive-permissions": Severity.LOW},
            )
        )

        result = engine.analyze_plan(FIXTURE_PATH)
        finding_titles = {finding.title for finding in result.findings}
        workload_finding = next(
            finding for finding in result.findings if finding.rule_id == "aws-workload-role-sensitive-permissions"
        )

        self.assertNotIn("Database is reachable from overly permissive sources", finding_titles)
        self.assertEqual(workload_finding.severity, Severity.LOW)
        self.assertIsNotNone(workload_finding.severity_reasoning)
        self.assertEqual(workload_finding.severity_reasoning.severity, Severity.LOW)
        self.assertEqual(workload_finding.severity_reasoning.computed_severity, Severity.HIGH)


if __name__ == "__main__":
    unittest.main()
