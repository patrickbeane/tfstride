from __future__ import annotations

import unittest

from tests.providers.gcp.rule_support.compute import (
    _gke_cluster,
    _gke_node_pool,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.providers.gcp.normalizer import GcpNormalizer


class GcpGkeRuleTests(unittest.TestCase):
    def test_gke_public_control_plane_rule_detects_public_cluster(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _gke_cluster(
                    authorized_networks=[{"display_name": "admin", "cidr_block": "203.0.113.0/24"}],
                    workload_identity_pool="tfstride-demo.svc.id.goog",
                    node_service_account="gke-nodes@tfstride-demo.iam.gserviceaccount.com",
                    oauth_scopes=["https://www.googleapis.com/auth/logging.write"],
                    disable_legacy_endpoints="true",
                    metadata_mode="GKE_METADATA",
                )
            ]
        )
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gke-public-control-plane"})),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "gcp-gke-public-control-plane")
        self.assertEqual(findings[0].affected_resources, ["google_container_cluster.app"])

    def test_gke_broad_authorized_networks_rule_detects_anywhere_cidr(self) -> None:
        inventory = GcpNormalizer().normalize(
            [_gke_cluster(authorized_networks=[{"display_name": "anywhere", "cidr_block": "0.0.0.0/0"}])]
        )
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gke-broad-authorized-networks"})),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "gcp-gke-broad-authorized-networks")
        self.assertIn("anywhere (0.0.0.0/0)", findings[0].evidence[0].values)

    def test_gke_broad_authorized_networks_rule_detects_missing_config(self) -> None:
        inventory = GcpNormalizer().normalize([_gke_cluster(authorized_networks_configured=False)])
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gke-broad-authorized-networks"})),
        )

        self.assertEqual(len(findings), 1)
        self.assertIn("master authorized networks are not configured", findings[0].evidence[0].values)

    def test_gke_broad_authorized_networks_rule_ignores_private_or_restricted_cluster(self) -> None:
        private_inventory = GcpNormalizer().normalize([_gke_cluster(endpoint=None, private_endpoint=True)])
        restricted_inventory = GcpNormalizer().normalize(
            [_gke_cluster(authorized_networks=[{"display_name": "admin", "cidr_block": "203.0.113.0/24"}])]
        )

        for inventory in (private_inventory, restricted_inventory):
            findings = StrideRuleEngine().evaluate(
                inventory,
                detect_trust_boundaries(inventory),
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gke-broad-authorized-networks"})),
            )
            self.assertEqual(findings, [])

    def test_gke_workload_identity_disabled_rule_detects_missing_workload_pool(self) -> None:
        inventory = GcpNormalizer().normalize([_gke_cluster()])
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gke-workload-identity-disabled"})),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "gcp-gke-workload-identity-disabled")

    def test_gke_workload_identity_disabled_rule_ignores_enabled_cluster(self) -> None:
        inventory = GcpNormalizer().normalize([_gke_cluster(workload_identity_pool="tfstride-demo.svc.id.goog")])
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gke-workload-identity-disabled"})),
        )

        self.assertEqual(findings, [])

    def test_gke_legacy_metadata_rule_detects_cluster_and_node_pool(self) -> None:
        inventory = GcpNormalizer().normalize([_gke_cluster(), _gke_node_pool()])
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gke-legacy-metadata-endpoints-enabled"})),
        )

        self.assertEqual(
            [finding.affected_resources for finding in findings],
            [["google_container_cluster.app"], ["google_container_node_pool.app"]],
        )

    def test_gke_legacy_metadata_rule_ignores_hardened_node_pool(self) -> None:
        inventory = GcpNormalizer().normalize(
            [_gke_node_pool(disable_legacy_endpoints="true", metadata_mode="GKE_METADATA")]
        )
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gke-legacy-metadata-endpoints-enabled"})),
        )

        self.assertEqual(findings, [])

    def test_gke_broad_node_service_account_rule_detects_default_sa_and_scope(self) -> None:
        inventory = GcpNormalizer().normalize([_gke_node_pool()])
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gke-broad-node-service-account"})),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "gcp-gke-broad-node-service-account")
        self.assertEqual(findings[0].affected_resources, ["google_container_node_pool.app"])

    def test_gke_broad_node_service_account_rule_ignores_dedicated_limited_identity(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _gke_node_pool(
                    node_service_account="gke-nodes@tfstride-demo.iam.gserviceaccount.com",
                    oauth_scopes=["https://www.googleapis.com/auth/logging.write"],
                    disable_legacy_endpoints="true",
                    metadata_mode="GKE_METADATA",
                )
            ]
        )
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gke-broad-node-service-account"})),
        )

        self.assertEqual(findings, [])

    def test_gke_logging_network_policy_and_secrets_encryption_rules_detect_explicit_gaps(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _gke_cluster(
                    logging_service="logging.googleapis.com/none",
                    logging_components=[],
                    network_policy_enabled=False,
                    network_policy_provider="PROVIDER_UNSPECIFIED",
                    database_encryption_state="DECRYPTED",
                )
            ]
        )
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset(
                    {
                        "gcp-gke-control-plane-logging-incomplete",
                        "gcp-gke-network-policy-disabled",
                        "gcp-gke-secrets-encryption-not-configured",
                    }
                )
            ),
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [
                "gcp-gke-control-plane-logging-incomplete",
                "gcp-gke-network-policy-disabled",
                "gcp-gke-secrets-encryption-not-configured",
            ],
        )
        self.assertEqual([finding.severity.value for finding in findings], ["medium", "medium", "medium"])
        evidence_by_rule = {
            finding.rule_id: {item.key: item.values for item in finding.evidence} for finding in findings
        }
        self.assertEqual(
            evidence_by_rule["gcp-gke-control-plane-logging-incomplete"]["logging_posture"],
            [
                "control_plane_logging_state=disabled",
                "logging_service=logging.googleapis.com/none",
                "logging_components are not represented in planned values",
                "control-plane logging is disabled",
            ],
        )
        self.assertEqual(
            evidence_by_rule["gcp-gke-network-policy-disabled"]["network_policy_posture"],
            ["network_policy_state=disabled", "network_policy_provider=PROVIDER_UNSPECIFIED"],
        )
        self.assertEqual(
            evidence_by_rule["gcp-gke-secrets-encryption-not-configured"]["secret_encryption_posture"],
            [
                "secrets_encryption_state=disabled",
                "database_encryption_state=DECRYPTED",
                "database_encryption_key_name is not represented in planned values",
            ],
        )

    def test_gke_logging_rule_detects_missing_security_components(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _gke_cluster(
                    logging_service="logging.googleapis.com/kubernetes",
                    logging_components=["SYSTEM_COMPONENTS", "APISERVER"],
                )
            ]
        )
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gke-control-plane-logging-incomplete"})),
        )

        self.assertEqual([finding.rule_id for finding in findings], ["gcp-gke-control-plane-logging-incomplete"])
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertIn("missing security logging component: CONTROLLER_MANAGER", evidence["logging_posture"])
        self.assertIn("missing security logging component: SCHEDULER", evidence["logging_posture"])

    def test_gke_logging_network_policy_and_secrets_encryption_rules_ignore_configured_cluster(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _gke_cluster(
                    logging_service="logging.googleapis.com/kubernetes",
                    logging_components=["SYSTEM_COMPONENTS", "APISERVER", "SCHEDULER", "CONTROLLER_MANAGER"],
                    network_policy_enabled=True,
                    network_policy_provider="CALICO",
                    database_encryption_state="ENCRYPTED",
                    database_encryption_key_name=(
                        "projects/tfstride-demo/locations/global/keyRings/gke/cryptoKeys/secrets"
                    ),
                )
            ]
        )
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset(
                    {
                        "gcp-gke-control-plane-logging-incomplete",
                        "gcp-gke-network-policy-disabled",
                        "gcp-gke-secrets-encryption-not-configured",
                    }
                )
            ),
        )

        self.assertEqual(findings, [])

    def test_gke_unknown_posture_rules_emit_low_severity_uncertainty_findings(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _gke_cluster(
                    logging_components=[],
                    network_policy_enabled=None,
                    database_encryption_state=None,
                    database_encryption_key_name=None,
                    unknown_values={
                        "logging_service": True,
                        "logging_config": [{"enable_components": True}],
                        "network_policy": [{"enabled": True, "provider": True}],
                        "database_encryption": [{"state": True, "key_name": True}],
                    },
                )
            ]
        )
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset(
                    {
                        "gcp-gke-control-plane-logging-incomplete",
                        "gcp-gke-network-policy-disabled",
                        "gcp-gke-secrets-encryption-not-configured",
                    }
                )
            ),
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [
                "gcp-gke-control-plane-logging-incomplete",
                "gcp-gke-network-policy-disabled",
                "gcp-gke-secrets-encryption-not-configured",
            ],
        )
        self.assertEqual([finding.severity.value for finding in findings], ["low", "low", "low"])
        evidence_by_rule = {
            finding.rule_id: {item.key: item.values for item in finding.evidence} for finding in findings
        }
        self.assertEqual(
            evidence_by_rule["gcp-gke-control-plane-logging-incomplete"]["posture_uncertainty"],
            [
                "logging_config.enable_components is unknown after planning",
                "logging_service is unknown after planning",
            ],
        )
        self.assertEqual(
            evidence_by_rule["gcp-gke-network-policy-disabled"]["posture_uncertainty"],
            [
                "network_policy.enabled is unknown after planning",
                "network_policy.provider is unknown after planning",
            ],
        )
        self.assertEqual(
            evidence_by_rule["gcp-gke-secrets-encryption-not-configured"]["posture_uncertainty"],
            [
                "database_encryption.state is unknown after planning",
                "database_encryption.key_name is unknown after planning",
            ],
        )

    def test_gke_auth_and_hardening_rules_detect_explicit_gaps(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _gke_cluster(
                    legacy_abac_enabled=True,
                    client_certificate_enabled=True,
                    shielded_nodes_enabled=False,
                    binary_authorization_evaluation_mode="DISABLED",
                )
            ]
        )
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset(
                    {
                        "gcp-gke-legacy-abac-enabled-or-unknown",
                        "gcp-gke-client-certificate-auth-enabled-or-unknown",
                        "gcp-gke-shielded-nodes-disabled-or-unknown",
                        "gcp-gke-binary-authorization-not-enabled",
                    }
                )
            ),
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [
                "gcp-gke-legacy-abac-enabled-or-unknown",
                "gcp-gke-client-certificate-auth-enabled-or-unknown",
                "gcp-gke-shielded-nodes-disabled-or-unknown",
                "gcp-gke-binary-authorization-not-enabled",
            ],
        )
        self.assertEqual([finding.severity.value for finding in findings], ["medium", "medium", "medium", "medium"])
        evidence_by_rule = {
            finding.rule_id: {item.key: item.values for item in finding.evidence} for finding in findings
        }
        self.assertEqual(
            evidence_by_rule["gcp-gke-legacy-abac-enabled-or-unknown"]["legacy_abac_posture"],
            ["legacy_abac_state=enabled", "enable_legacy_abac=true"],
        )
        self.assertEqual(
            evidence_by_rule["gcp-gke-client-certificate-auth-enabled-or-unknown"]["client_certificate_auth_posture"],
            [
                "client_certificate_auth_state=enabled",
                "master_auth.client_certificate_config.issue_client_certificate=true",
            ],
        )
        self.assertEqual(
            evidence_by_rule["gcp-gke-shielded-nodes-disabled-or-unknown"]["shielded_nodes_posture"],
            ["shielded_nodes_state=disabled", "shielded_nodes.enabled=false"],
        )
        self.assertEqual(
            evidence_by_rule["gcp-gke-binary-authorization-not-enabled"]["binary_authorization_posture"],
            ["binary_authorization_state=disabled", "evaluation_mode=DISABLED"],
        )

    def test_gke_auth_and_hardening_rules_ignore_configured_cluster(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _gke_cluster(
                    legacy_abac_enabled=False,
                    client_certificate_enabled=False,
                    shielded_nodes_enabled=True,
                    binary_authorization_evaluation_mode="PROJECT_SINGLETON_POLICY_ENFORCE",
                )
            ]
        )
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset(
                    {
                        "gcp-gke-legacy-abac-enabled-or-unknown",
                        "gcp-gke-client-certificate-auth-enabled-or-unknown",
                        "gcp-gke-shielded-nodes-disabled-or-unknown",
                        "gcp-gke-binary-authorization-not-enabled",
                    }
                )
            ),
        )

        self.assertEqual(findings, [])

    def test_gke_client_certificate_and_binary_authorization_rules_ignore_unrepresented_fields(self) -> None:
        inventory = GcpNormalizer().normalize([_gke_cluster()])
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset(
                    {
                        "gcp-gke-client-certificate-auth-enabled-or-unknown",
                        "gcp-gke-binary-authorization-not-enabled",
                    }
                )
            ),
        )

        self.assertEqual(findings, [])

    def test_gke_auth_and_hardening_unknown_rules_emit_low_severity_uncertainty_findings(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _gke_cluster(
                    legacy_abac_enabled=None,
                    client_certificate_enabled=None,
                    shielded_nodes_enabled=None,
                    binary_authorization_evaluation_mode=None,
                    unknown_values={
                        "enable_legacy_abac": True,
                        "master_auth": [{"client_certificate_config": [{"issue_client_certificate": True}]}],
                        "shielded_nodes": [{"enabled": True}],
                        "binary_authorization": [{"evaluation_mode": True}],
                    },
                )
            ]
        )
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset(
                    {
                        "gcp-gke-legacy-abac-enabled-or-unknown",
                        "gcp-gke-client-certificate-auth-enabled-or-unknown",
                        "gcp-gke-shielded-nodes-disabled-or-unknown",
                        "gcp-gke-binary-authorization-not-enabled",
                    }
                )
            ),
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [
                "gcp-gke-legacy-abac-enabled-or-unknown",
                "gcp-gke-client-certificate-auth-enabled-or-unknown",
                "gcp-gke-shielded-nodes-disabled-or-unknown",
                "gcp-gke-binary-authorization-not-enabled",
            ],
        )
        self.assertEqual([finding.severity.value for finding in findings], ["low", "low", "low", "low"])
        evidence_by_rule = {
            finding.rule_id: {item.key: item.values for item in finding.evidence} for finding in findings
        }
        self.assertEqual(
            evidence_by_rule["gcp-gke-legacy-abac-enabled-or-unknown"]["posture_uncertainty"],
            ["enable_legacy_abac is unknown after planning"],
        )
        self.assertEqual(
            evidence_by_rule["gcp-gke-client-certificate-auth-enabled-or-unknown"]["posture_uncertainty"],
            ["master_auth.client_certificate_config.issue_client_certificate is unknown after planning"],
        )
        self.assertEqual(
            evidence_by_rule["gcp-gke-shielded-nodes-disabled-or-unknown"]["posture_uncertainty"],
            ["shielded_nodes.enabled is unknown after planning"],
        )
        self.assertEqual(
            evidence_by_rule["gcp-gke-binary-authorization-not-enabled"]["posture_uncertainty"],
            ["binary_authorization.evaluation_mode is unknown after planning"],
        )


if __name__ == "__main__":
    unittest.main()
