from __future__ import annotations

import unittest

from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer


def _project_iam_member(role: str, member: str = "serviceAccount:deploy@example.iam.gserviceaccount.com") -> TerraformResource:
    return TerraformResource(
        address="google_project_iam_member.binding",
        mode="managed",
        resource_type="google_project_iam_member",
        name="binding",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "project": "tfstride-demo",
            "role": role,
            "member": member,
        },
    )


def _storage_bucket(public_access_prevention: str | None = None) -> TerraformResource:
    values = {
        "name": "tfstride-logs",
        "location": "US",
    }
    if public_access_prevention is not None:
        values["public_access_prevention"] = public_access_prevention
    return TerraformResource(
        address="google_storage_bucket.logs",
        mode="managed",
        resource_type="google_storage_bucket",
        name="logs",
        provider_name="registry.terraform.io/hashicorp/google",
        values=values,
    )


def _storage_bucket_iam_member(
    member: str = "allUsers",
    role: str = "roles/storage.objectViewer",
    *,
    bucket: str = "google_storage_bucket.logs.name",
) -> TerraformResource:
    return TerraformResource(
        address="google_storage_bucket_iam_member.public_logs_reader",
        mode="managed",
        resource_type="google_storage_bucket_iam_member",
        name="public_logs_reader",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "bucket": bucket,
            "role": role,
            "member": member,
        },
    )


def _cloud_sql_instance(
    *,
    ipv4_enabled: bool = True,
    authorized_networks: list[dict[str, object]] | None = None,
    backup_enabled: bool = True,
    pitr_enabled: bool = True,
    private_network: str | None = None,
) -> TerraformResource:
    ip_configuration: dict[str, object] = {
        "ipv4_enabled": ipv4_enabled,
        "authorized_networks": authorized_networks if authorized_networks is not None else [],
    }
    if private_network is not None:
        ip_configuration["private_network"] = private_network
    return TerraformResource(
        address="google_sql_database_instance.app",
        mode="managed",
        resource_type="google_sql_database_instance",
        name="app",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "name": "tfstride-app-db",
            "database_version": "POSTGRES_15",
            "settings": [
                {
                    "backup_configuration": [
                        {
                            "enabled": backup_enabled,
                            "point_in_time_recovery_enabled": pitr_enabled,
                        }
                    ],
                    "ip_configuration": [ip_configuration],
                }
            ],
        },
    )


class GcpRuleTests(unittest.TestCase):
    def test_gcs_public_bucket_iam_member_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_storage_bucket(), _storage_bucket_iam_member()])

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-gcs-public-access")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["google_storage_bucket.logs"])
        self.assertIsNone(finding.trust_boundary_id)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["public_exposure_reasons"],
            [
                "google_storage_bucket_iam_member.public_logs_reader grants "
                "roles/storage.objectViewer to allUsers"
            ],
        )

    def test_gcs_all_authenticated_users_bucket_iam_member_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [_storage_bucket(), _storage_bucket_iam_member(member="allAuthenticatedUsers")]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual([finding.rule_id for finding in findings], ["gcp-gcs-public-access"])

    def test_gcs_public_access_prevention_suppresses_public_iam_grant(self) -> None:
        inventory = GcpNormalizer().normalize(
            [_storage_bucket(public_access_prevention="enforced"), _storage_bucket_iam_member()]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(findings, [])

    def test_gcs_non_public_member_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _storage_bucket(),
                _storage_bucket_iam_member(member="serviceAccount:reader@example.iam.gserviceaccount.com"),
            ]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(findings, [])

    def test_cloud_sql_public_authorized_network_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_sql_instance(
                    authorized_networks=[{"name": "anywhere", "value": "0.0.0.0/0"}],
                )
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(inventory, boundaries)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-cloud-sql-public-authorized-network")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(finding.affected_resources, ["google_sql_database_instance.app"])
        self.assertEqual(
            finding.trust_boundary_id,
            "internet-to-service:internet->google_sql_database_instance.app",
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["authorized_networks"], ["anywhere (0.0.0.0/0)"])
        self.assertEqual(
            evidence["public_exposure_reasons"],
            ["authorized network `anywhere` allows 0.0.0.0/0"],
        )

    def test_cloud_sql_backup_disabled_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_sql_instance(
                    ipv4_enabled=False,
                    backup_enabled=False,
                    pitr_enabled=False,
                    private_network="google_compute_network.main.id",
                )
            ]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-cloud-sql-backup-disabled")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["google_sql_database_instance.app"])
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["backup_posture"],
            [
                "backup_configuration.enabled is false",
                "point_in_time_recovery_enabled is false",
                "engine is POSTGRES_15",
            ],
        )

    def test_private_backed_up_cloud_sql_instance_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_sql_instance(
                    ipv4_enabled=False,
                    backup_enabled=True,
                    pitr_enabled=True,
                    private_network="google_compute_network.main.id",
                )
            ]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(findings, [])

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

    def test_project_iam_admin_class_role_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_project_iam_member("roles/compute.admin")])

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual([finding.rule_id for finding in findings], ["gcp-project-iam-privileged-role"])
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(
            evidence["role_risk"],
            ["admin-level control over a GCP service or project security surface"],
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