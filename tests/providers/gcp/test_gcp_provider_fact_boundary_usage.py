from __future__ import annotations

import unittest

from tests.providers.gcp.rule_support.compute import (
    _compute_instance,
    _compute_network,
    _compute_subnetwork,
    _gke_cluster,
    _public_compute_firewall,
)
from tests.providers.gcp.rule_support.data import (
    _cloud_sql_instance,
    _secret_manager_secret,
    _secret_manager_secret_iam_member,
    _storage_bucket,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


def _evaluate(resources: list[TerraformResource], rule_id: str):
    inventory = GcpNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({rule_id})),
    )


class GcpProviderFactBoundaryCharacterizationTests(unittest.TestCase):
    def test_storage_rule_keeps_provider_fact_evidence_shape(self) -> None:
        findings = _evaluate([_storage_bucket(versioning_enabled=False)], "gcp-gcs-versioning-disabled")

        self.assertEqual([finding.rule_id for finding in findings], ["gcp-gcs-versioning-disabled"])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["data_protection_posture"],
            ["versioning.enabled is false", "data_sensitivity is sensitive"],
        )

    def test_compute_rule_keeps_provider_fact_evidence_shape(self) -> None:
        findings = _evaluate(
            [
                _compute_network(),
                TerraformResource(
                    address="google_compute_firewall.admin",
                    mode="managed",
                    resource_type="google_compute_firewall",
                    name="admin",
                    provider_name="registry.terraform.io/hashicorp/google",
                    values={
                        "name": "tfstride-admin",
                        "network": "google_compute_network.main.name",
                        "direction": "INGRESS",
                        "source_ranges": ["0.0.0.0/0"],
                        "target_tags": ["web"],
                        "allow": [{"protocol": "tcp", "ports": ["22"]}],
                    },
                ),
                TerraformResource(
                    address="google_compute_instance.web",
                    mode="managed",
                    resource_type="google_compute_instance",
                    name="web",
                    provider_name="registry.terraform.io/hashicorp/google",
                    values={
                        "name": "tfstride-web",
                        "tags": ["web"],
                        "network_interface": [{"network": "google_compute_network.main.id", "access_config": [{}]}],
                    },
                ),
            ],
            "gcp-public-compute-broad-ingress",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["gcp-public-compute-broad-ingress"])
        self.assertEqual(
            findings[0].trust_boundary_id,
            "internet-to-service:internet->google_compute_instance.web",
        )
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["internet_ingress_reasons"],
            ["google_compute_firewall.admin ingress tcp 22 from 0.0.0.0/0"],
        )
        self.assertEqual(
            evidence["public_exposure_reasons"],
            ["compute instance has an external access config and matching firewall rules allow internet ingress"],
        )

    def test_gke_rule_keeps_provider_fact_evidence_shape(self) -> None:
        findings = _evaluate(
            [
                _gke_cluster(
                    authorized_networks=[{"display_name": "anywhere", "cidr_block": "0.0.0.0/0"}],
                    metadata_mode="GKE_METADATA",
                )
            ],
            "gcp-gke-broad-authorized-networks",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["gcp-gke-broad-authorized-networks"])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["authorized_networks"], ["anywhere (0.0.0.0/0)"])
        self.assertEqual(evidence["configured_authorized_network_count"], ["1"])

    def test_cloud_sql_rule_keeps_provider_fact_evidence_shape(self) -> None:
        findings = _evaluate(
            [_cloud_sql_instance(authorized_networks=[{"name": "anywhere", "value": "0.0.0.0/0"}])],
            "gcp-cloud-sql-public-authorized-network",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["gcp-cloud-sql-public-authorized-network"])
        self.assertEqual(
            findings[0].trust_boundary_id,
            "internet-to-service:internet->google_sql_database_instance.app",
        )
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["authorized_networks"], ["anywhere (0.0.0.0/0)"])
        self.assertEqual(
            evidence["public_exposure_reasons"],
            ["authorized network `anywhere` allows 0.0.0.0/0"],
        )

    def test_iam_sensitive_path_rule_keeps_provider_fact_evidence_shape(self) -> None:
        service_account = "serviceAccount:tfstride-web@tfstride-demo.iam.gserviceaccount.com"
        findings = _evaluate(
            [
                _compute_network(),
                _compute_subnetwork(),
                _public_compute_firewall(),
                _compute_instance(),
                _secret_manager_secret(),
                _secret_manager_secret_iam_member(member=service_account),
            ],
            "gcp-public-workload-sensitive-data-access",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["gcp-public-workload-sensitive-data-access"])
        self.assertEqual(
            findings[0].trust_boundary_id,
            "workload-to-data-store:google_compute_instance.web->google_secret_manager_secret.api_key",
        )
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["workload_identity"], [service_account])
        self.assertEqual(
            evidence["data_access_path"],
            ["google_compute_instance.web reaches google_secret_manager_secret.api_key"],
        )
        self.assertIn(
            "google_secret_manager_secret_iam_member.public_accessor grants roles/secretmanager.secretAccessor",
            evidence["boundary_rationale"][0],
        )


if __name__ == "__main__":
    unittest.main()
