from __future__ import annotations

import unittest

from tests.providers.gcp.rule_support.common import _normalized_gcp_resource
from tests.providers.gcp.rule_support.data import (
    _bigquery_dataset,
    _secret_manager_secret,
)
from tests.providers.gcp.rule_support.iam import (
    _project_iam_custom_role,
    _project_iam_member,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import (
    ResourceCategory,
    ResourceInventory,
)
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer


class GcpIamInheritanceRuleTests(unittest.TestCase):
    def test_inherited_project_iam_data_role_reaches_sensitive_descendant(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _secret_manager_secret(),
                _bigquery_dataset(),
                _project_iam_member(
                    "roles/secretmanager.secretAccessor",
                    member="group:secops@example.com",
                ),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-inherited-iam-sensitive-resource-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-inherited-iam-sensitive-resource-access")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(
            finding.affected_resources,
            [
                "google_project_iam_member.binding",
                "google_secret_manager_secret.api_key",
            ],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["iam_binding"],
            [
                "source=google_project_iam_member.binding",
                "scope=project:tfstride-demo",
                "member=group:secops@example.com",
                "role=roles/secretmanager.secretAccessor",
            ],
        )
        self.assertEqual(
            evidence["sensitive_descendants"],
            [
                "resource=google_secret_manager_secret.api_key; "
                "type=google_secret_manager_secret; "
                "risk=Secret Manager secret access through roles/secretmanager.secretAccessor"
            ],
        )

    def test_inherited_project_iam_viewer_does_not_reach_sensitive_descendant(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _secret_manager_secret(),
                _project_iam_member("roles/viewer", member="allUsers"),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-inherited-iam-sensitive-resource-access"})),
        )

        self.assertEqual(findings, [])

    def test_inherited_folder_iam_data_role_reaches_folder_descendant(self) -> None:
        secret = _normalized_gcp_resource(
            "google_secret_manager_secret.folder_api",
            "google_secret_manager_secret",
            ResourceCategory.DATA,
            identifier="projects/tfstride-folder/secrets/api",
            data_sensitivity="sensitive",
            metadata={
                GcpResourceMetadata.FOLDER_ID: "folders/12345",
                GcpResourceMetadata.PROJECT: "tfstride-folder",
            },
        )
        folder_iam = _normalized_gcp_resource(
            "google_folder_iam_member.secret_reader",
            "google_folder_iam_member",
            ResourceCategory.IAM,
            metadata={
                GcpResourceMetadata.FOLDER_ID: "folders/12345",
                GcpResourceMetadata.IAM_ROLE: "roles/secretmanager.secretAccessor",
                GcpResourceMetadata.IAM_MEMBER: "allUsers",
            },
        )
        inventory = ResourceInventory(provider="gcp", resources=[secret, folder_iam])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-inherited-iam-sensitive-resource-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            [
                "google_folder_iam_member.secret_reader",
                "google_secret_manager_secret.folder_api",
            ],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["iam_binding"],
            [
                "source=google_folder_iam_member.secret_reader",
                "scope=folder:12345",
                "member=allUsers",
                "role=roles/secretmanager.secretAccessor",
            ],
        )
        self.assertEqual(
            evidence["trust_scope"],
            ["member is public GCP principal `allUsers`"],
        )

    def test_inherited_project_iam_custom_role_data_permissions_are_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _project_iam_custom_role(
                    role_id="analyticsReader",
                    permissions=["bigquery.tables.getData"],
                ),
                _bigquery_dataset(),
                _project_iam_member(
                    "projects/tfstride-demo/roles/analyticsReader",
                    member="group:analytics@example.com",
                ),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-inherited-iam-sensitive-resource-access"})),
        )

        self.assertEqual(len(findings), 1)
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(evidence["custom_role_permissions"], ["bigquery.tables.getData"])
        self.assertEqual(
            evidence["sensitive_descendants"],
            [
                "resource=google_bigquery_dataset.analytics; type=google_bigquery_dataset; "
                "risk=BigQuery dataset data access through custom role "
                "projects/tfstride-demo/roles/analyticsReader"
            ],
        )

    def test_inherited_project_iam_privileged_role_reports_descendant_blast_radius(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _secret_manager_secret(),
                _bigquery_dataset(),
                _project_iam_member(
                    "roles/editor",
                    member="serviceAccount:deployer@partner-project.iam.gserviceaccount.com",
                ),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-inherited-iam-blast-radius"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-inherited-iam-blast-radius")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            [
                "google_project_iam_member.binding",
                "google_bigquery_dataset.analytics",
                "google_secret_manager_secret.api_key",
            ],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["iam_binding"],
            [
                "source=google_project_iam_member.binding",
                "scope=project:tfstride-demo",
                "member=serviceAccount:deployer@partner-project.iam.gserviceaccount.com",
                "role=roles/editor",
            ],
        )
        self.assertEqual(evidence["role_risk"], ["broad write access across most project services"])
        self.assertEqual(
            evidence["trust_scope"],
            ["service account belongs to project `partner-project`, outside resource project `tfstride-demo`"],
        )
        self.assertEqual(
            evidence["descendant_scope"],
            ["scope=project:tfstride-demo", "descendant_count=2", "resource_type_count=2", "projects=tfstride-demo"],
        )
        self.assertEqual(
            evidence["descendant_resource_types"],
            ["google_bigquery_dataset: 1", "google_secret_manager_secret: 1"],
        )

    def test_inherited_project_iam_low_risk_group_binding_is_not_blast_radius(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _secret_manager_secret(),
                _bigquery_dataset(),
                _project_iam_member("roles/viewer", member="group:ops@example.com"),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-inherited-iam-blast-radius"})),
        )

        self.assertEqual(findings, [])

    def test_inherited_folder_iam_broad_principal_reports_descendant_blast_radius(self) -> None:
        instance = _normalized_gcp_resource(
            "google_compute_instance.folder_web",
            "google_compute_instance",
            ResourceCategory.COMPUTE,
            metadata={GcpResourceMetadata.FOLDER_ID: "folders/12345"},
        )
        bucket = _normalized_gcp_resource(
            "google_storage_bucket.folder_logs",
            "google_storage_bucket",
            ResourceCategory.DATA,
            data_sensitivity="sensitive",
            metadata={GcpResourceMetadata.FOLDER_ID: "folders/12345"},
        )
        folder_iam = _normalized_gcp_resource(
            "google_folder_iam_member.domain_viewer",
            "google_folder_iam_member",
            ResourceCategory.IAM,
            metadata={
                GcpResourceMetadata.FOLDER_ID: "folders/12345",
                GcpResourceMetadata.IAM_ROLE: "roles/viewer",
                GcpResourceMetadata.IAM_MEMBER: "domain:example.com",
            },
        )
        inventory = ResourceInventory(provider="gcp", resources=[instance, bucket, folder_iam])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-inherited-iam-blast-radius"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(
            finding.affected_resources,
            [
                "google_folder_iam_member.domain_viewer",
                "google_compute_instance.folder_web",
                "google_storage_bucket.folder_logs",
            ],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["trust_scope"],
            ["member grants a whole Google Workspace domain"],
        )
        self.assertEqual(
            evidence["descendant_scope"],
            ["scope=folder:12345", "descendant_count=2", "resource_type_count=2", "folders=folders/12345"],
        )


if __name__ == "__main__":
    unittest.main()
