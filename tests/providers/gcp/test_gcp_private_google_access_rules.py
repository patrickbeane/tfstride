from __future__ import annotations

import unittest

from tests.providers.gcp.rule_support.compute import (
    _compute_instance,
    _compute_network,
    _public_compute_firewall,
)
from tests.providers.gcp.rule_support.data import (
    _cloud_sql_instance,
    _kms_crypto_key,
    _kms_crypto_key_iam_member,
    _secret_manager_secret,
    _secret_manager_secret_iam_member,
    _storage_bucket,
    _storage_bucket_iam_member,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer

_RULE_ID = "gcp-private-workload-private-google-access-disabled"


def _private_google_access_subnetwork(*, enabled: bool | None = False) -> TerraformResource:
    values: dict[str, object] = {
        "name": "tfstride-app",
        "id": "google_compute_subnetwork.app",
        "self_link": "projects/tfstride-demo/regions/us-central1/subnetworks/tfstride-app",
        "network": "google_compute_network.main.id",
        "ip_cidr_range": "10.10.0.0/24",
    }
    unknown_values: dict[str, object] = {}
    if enabled is None:
        unknown_values["private_ip_google_access"] = True
    else:
        values["private_ip_google_access"] = enabled
    return TerraformResource(
        address="google_compute_subnetwork.app",
        mode="managed",
        resource_type="google_compute_subnetwork",
        name="app",
        provider_name="registry.terraform.io/hashicorp/google",
        values=values,
        unknown_values=unknown_values,
    )


def _service_networking_connection() -> TerraformResource:
    return TerraformResource(
        address="google_service_networking_connection.private_services",
        mode="managed",
        resource_type="google_service_networking_connection",
        name="private_services",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "network": "google_compute_network.main.id",
            "service": "servicenetworking.googleapis.com",
            "reserved_peering_ranges": ["private-services-range"],
            "peering": "servicenetworking-googleapis-com",
        },
    )


def _findings(*resources: TerraformResource):
    inventory = GcpNormalizer().normalize(list(resources))
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class GcpPrivateGoogleAccessRuleTests(unittest.TestCase):
    def test_private_compute_secret_access_with_disabled_private_google_access_is_detected(self) -> None:
        service_account = "serviceAccount:tfstride-web@tfstride-demo.iam.gserviceaccount.com"

        findings = _findings(
            _compute_network(),
            _private_google_access_subnetwork(enabled=False),
            _compute_instance(public=False),
            _secret_manager_secret(),
            _secret_manager_secret_iam_member(member=service_account),
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(
            finding.affected_resources,
            [
                "google_compute_instance.web",
                "google_compute_subnetwork.app",
                "google_secret_manager_secret.api_key",
            ],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            "workload-to-data-store:google_compute_instance.web->google_secret_manager_secret.api_key",
        )
        self.assertIn("does not imply the target data service is publicly exposed", finding.rationale)
        evidence = _evidence_by_key(finding)
        self.assertEqual(evidence["workload_identity"], [service_account])
        self.assertEqual(
            evidence["google_api_data_paths"],
            ["google_compute_instance.web reaches google_secret_manager_secret.api_key"],
        )
        self.assertIn(
            "google_compute_subnetwork.app: private_ip_google_access=false",
            evidence["workload_subnetwork_posture"][1],
        )
        self.assertIn(
            "private_service_access_connections=0",
            evidence["private_connectivity_coverage"],
        )

    def test_private_google_access_enabled_suppresses_private_workload_finding(self) -> None:
        service_account = "serviceAccount:tfstride-web@tfstride-demo.iam.gserviceaccount.com"

        findings = _findings(
            _compute_network(),
            _private_google_access_subnetwork(enabled=True),
            _compute_instance(public=False),
            _secret_manager_secret(),
            _secret_manager_secret_iam_member(member=service_account),
        )

        self.assertEqual(findings, [])

    def test_unknown_private_google_access_does_not_overclaim(self) -> None:
        service_account = "serviceAccount:tfstride-web@tfstride-demo.iam.gserviceaccount.com"

        findings = _findings(
            _compute_network(),
            _private_google_access_subnetwork(enabled=None),
            _compute_instance(public=False),
            _secret_manager_secret(),
            _secret_manager_secret_iam_member(member=service_account),
        )

        self.assertEqual(findings, [])

    def test_public_workload_is_left_to_public_sensitive_data_path_rule(self) -> None:
        service_account = "serviceAccount:tfstride-web@tfstride-demo.iam.gserviceaccount.com"

        findings = _findings(
            _compute_network(),
            _private_google_access_subnetwork(enabled=False),
            _public_compute_firewall(),
            _compute_instance(public=True),
            _secret_manager_secret(),
            _secret_manager_secret_iam_member(member=service_account),
        )

        self.assertEqual(findings, [])

    def test_gcs_path_requires_deterministic_boundary(self) -> None:
        findings_without_access_grant = _findings(
            _compute_network(),
            _private_google_access_subnetwork(enabled=False),
            _compute_instance(public=False),
            _storage_bucket(),
        )

        self.assertEqual(findings_without_access_grant, [])

        findings = _findings(
            _compute_network(),
            _private_google_access_subnetwork(enabled=False),
            _compute_instance(public=False),
            _storage_bucket(),
            _storage_bucket_iam_member(
                member="serviceAccount:tfstride-web@tfstride-demo.iam.gserviceaccount.com",
                role="roles/storage.objectViewer",
            ),
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["google_api_data_paths"],
            ["google_compute_instance.web reaches google_storage_bucket.logs"],
        )

    def test_cloud_sql_without_modeled_private_connectivity_is_detected(self) -> None:
        findings = _findings(
            _compute_network(),
            _private_google_access_subnetwork(enabled=False),
            _compute_instance(public=False),
            _cloud_sql_instance(private_network="google_compute_network.main.id", ipv4_enabled=False),
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["google_api_data_paths"],
            ["google_compute_instance.web reaches google_sql_database_instance.app"],
        )

    def test_cloud_sql_private_connectivity_suppresses_private_google_access_finding(self) -> None:
        findings = _findings(
            _compute_network(),
            _private_google_access_subnetwork(enabled=False),
            _compute_instance(public=False),
            _cloud_sql_instance(private_network="google_compute_network.main.id", ipv4_enabled=False),
            _service_networking_connection(),
        )

        self.assertEqual(findings, [])

    def test_kms_access_with_disabled_private_google_access_is_detected(self) -> None:
        findings = _findings(
            _compute_network(),
            _private_google_access_subnetwork(enabled=False),
            _compute_instance(public=False),
            _kms_crypto_key(),
            _kms_crypto_key_iam_member(
                member="serviceAccount:tfstride-web@tfstride-demo.iam.gserviceaccount.com",
            ),
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["google_api_data_paths"],
            ["google_compute_instance.web reaches google_kms_crypto_key.customer"],
        )


if __name__ == "__main__":
    unittest.main()
