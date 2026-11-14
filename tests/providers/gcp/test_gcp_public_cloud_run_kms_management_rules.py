from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tests.providers.gcp.test_gcp_cloud_run_kms_operation_paths import (
    _custom_role,
    _key,
    _key_member,
    _project_member,
    _ring_member,
    _version,
)
from tests.providers.gcp.test_gcp_public_cloud_run_firestore_mutation_rules import (
    _as_resource,
    _evidence,
    _public_cloud_run,
    _public_invoker,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import ResourceInventory, StrideCategory, TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

_DISRUPTION_RULE = "gcp-public-cloud-run-kms-key-disruption"
_DELEGATION_RULE = "gcp-public-cloud-run-kms-authorization-delegation"
_WORKLOAD_ADDRESS = "google_cloud_run_v2_service.orders"
_PROJECT = "tfstride-demo"
_RING = f"projects/{_PROJECT}/locations/global/keyRings/application"


def _topic_with_cmek(
    name: str,
    *,
    key_name: str | None,
    unknown_key: bool = False,
) -> TerraformResource:
    return _terraform_resource(
        f"google_pubsub_topic.{name}",
        GcpResourceType.PUBSUB_TOPIC,
        {
            "name": name,
            "id": f"projects/{_PROJECT}/topics/{name}",
            "project": _PROJECT,
            "kms_key_name": key_name,
        },
        unknown_values={"kms_key_name": True} if unknown_key else None,
    )


def _version_for_key(
    address_name: str,
    key_name: str,
    version_number: int,
) -> TerraformResource:
    version_path = f"{_RING}/cryptoKeys/{key_name}/cryptoKeyVersions/{version_number}"
    return _terraform_resource(
        f"google_kms_crypto_key_version.{address_name}",
        GcpResourceType.KMS_CRYPTO_KEY_VERSION,
        {
            "crypto_key": f"google_kms_crypto_key.{key_name}.id",
            "id": version_path,
            "name": version_path,
            "state": "ENABLED",
            "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
            "protection_level": "SOFTWARE",
            "generate_time": "2026-07-19T00:00:00Z",
        },
    )


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = GcpNormalizer().normalize(resources)
    boundaries = detect_trust_boundaries(inventory)
    return StrideRuleEngine().evaluate(
        inventory,
        boundaries,
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _inventory_with_version_dependency(
    *, coherent: bool, custom_role_permissions: list[str] | None = None
) -> ResourceInventory:
    definition = _custom_role("runtime_admin", custom_role_permissions or [])
    role = str(definition.values["name"]) if custom_role_permissions is not None else "roles/cloudkms.admin"
    inventory = GcpNormalizer().normalize(
        [
            _public_cloud_run(),
            _public_invoker(),
            _as_resource(_key("data", "ENCRYPT_DECRYPT")),
            _as_resource(_version("data", "GOOGLE_SYMMETRIC_ENCRYPTION")),
            _version_for_key("data_secondary", "data", 2),
            _topic_with_cmek(
                "orders",
                key_name=f"{_RING}/cryptoKeys/data",
            ),
            *([definition] if custom_role_permissions is not None else []),
            _as_resource(_project_member("runtime_admin", role)),
        ]
    )
    key = inventory.get_by_address("google_kms_crypto_key.data")
    assert key is not None
    version_address = "google_kms_crypto_key_version.data"
    version_resource_name = f"{_RING}/cryptoKeys/data/cryptoKeyVersions/1"
    dependency = gcp_facts(key).kms_encryption_dependencies[0].copy()
    dependency["version_reference_is_explicit"] = True
    dependency["key_version_address"] = version_address
    dependency["key_version_resource_name"] = version_resource_name
    if coherent:
        dependency["candidate_targets"] = [
            {
                "address": version_address,
                "target_kind": "crypto_key_version",
            }
        ]
        dependency["reference_provenance"] = "planned_value"
        dependency["reference_kind"] = "crypto_key_version_resource_name"
        dependency["configured_key_reference"] = version_resource_name
    object.__setattr__(key, "_decoration_state_frozen", False)
    gcp_facts(key).set_kms_encryption_dependency_posture(
        dependencies=[dependency],
        uncertainties=[],
    )
    object.__setattr__(key, "_decoration_state_frozen", True)
    return inventory


class GcpPublicCloudRunKmsManagementRuleTests(unittest.TestCase):
    def test_rules_are_registered(self) -> None:
        registered = {rule_id for group in GCP_RULE_GROUP_IDS for rule_id in group}
        self.assertIn(_DISRUPTION_RULE, registered)
        self.assertIn(_DELEGATION_RULE, registered)

    def test_public_project_management_emits_distinct_findings_and_counts_grants_once(self) -> None:
        findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_key("data", "ENCRYPT_DECRYPT")),
                _as_resource(_key("secondary", "ENCRYPT_DECRYPT")),
                _as_resource(_version("data", "GOOGLE_SYMMETRIC_ENCRYPTION")),
                _as_resource(_project_member("runtime_admin", "roles/cloudkms.admin")),
            ],
            _DISRUPTION_RULE,
            _DELEGATION_RULE,
        )

        self.assertEqual(
            {finding.rule_id for finding in findings},
            {_DISRUPTION_RULE, _DELEGATION_RULE},
        )
        findings_by_rule = {finding.rule_id: finding for finding in findings}
        disruption = findings_by_rule[_DISRUPTION_RULE]
        delegation = findings_by_rule[_DELEGATION_RULE]
        self.assertEqual(disruption.category, StrideCategory.DENIAL_OF_SERVICE)
        self.assertEqual(delegation.category, StrideCategory.ELEVATION_OF_PRIVILEGE)
        self.assertEqual(disruption.trust_boundary_id, f"internet-to-service:internet->{_WORKLOAD_ADDRESS}")
        self.assertEqual(delegation.trust_boundary_id, f"internet-to-service:internet->{_WORKLOAD_ADDRESS}")
        assert disruption.severity_reasoning is not None
        assert delegation.severity_reasoning is not None
        self.assertEqual(disruption.severity_reasoning.blast_radius, 2)
        self.assertEqual(delegation.severity_reasoning.blast_radius, 2)
        self.assertIn("Cloud KMS disruption authority", disruption.rationale)
        self.assertIn("authorization-delegation authority", delegation.rationale)

        disruption_evidence = _evidence(disruption)
        delegation_evidence = _evidence(delegation)
        self.assertEqual(
            disruption_evidence["scope_breadth"],
            [
                "project_grants=1; key_ring_grants=0; exact_key_grants=0; "
                "target_paths=2; modeled_targets=1; modeled_keys=1; modeled_versions=1; "
                "blast_radius_basis=project_applicable_grant"
            ],
        )
        self.assertEqual(
            delegation_evidence["scope_breadth"],
            [
                "project_grants=1; key_ring_grants=0; exact_key_grants=0; "
                "target_paths=3; modeled_targets=3; modeled_keys=2; modeled_versions=0; "
                "blast_radius_basis=project_applicable_grant"
            ],
        )
        self.assertTrue(
            all("management_effect=disruption" in value for value in disruption_evidence["kms_management_paths"])
        )
        self.assertTrue(
            all("management_effect=delegation" in value for value in delegation_evidence["kms_management_paths"])
        )
        self.assertIn("iam_scope_is_key_version=false", disruption_evidence["authorization_scope"][1])

    def test_parent_key_dependencies_are_not_promoted_to_version_impact(self) -> None:
        findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_key("data", "ENCRYPT_DECRYPT")),
                _as_resource(_version("data", "GOOGLE_SYMMETRIC_ENCRYPTION")),
                _topic_with_cmek(
                    "orders",
                    key_name=f"{_RING}/cryptoKeys/data",
                ),
                _topic_with_cmek(
                    "archive",
                    key_name=f"{_RING}/cryptoKeys/data",
                ),
                _as_resource(_project_member("runtime_admin", "roles/cloudkms.admin")),
            ],
            _DISRUPTION_RULE,
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertNotIn("google_pubsub_topic.orders", finding.affected_resources)
        self.assertNotIn("google_pubsub_topic.archive", finding.affected_resources)
        assert finding.severity_reasoning is not None
        self.assertEqual(finding.severity_reasoning.blast_radius, 2)
        self.assertIn("No resolved downstream encrypted dependent resources", finding.rationale)
        evidence = _evidence(finding)
        self.assertEqual(
            evidence["downstream_dependencies"][0],
            "unique_dependency_count=0; unique_dependent_resource_count=0; "
            "unique_version_target_count=1; blast_radius_basis=no_resolved_downstream_dependents",
        )
        self.assertEqual(len(evidence["downstream_dependencies"]), 1)
        self.assertTrue(
            any(
                "operation=cloudkms.cryptoKeyVersions.destroy" in value and "target_type=crypto_key_version" in value
                for value in evidence["kms_management_paths"]
            )
        )

    def test_exact_version_dependency_projects_only_matching_version(self) -> None:
        inventory = _inventory_with_version_dependency(coherent=True)
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_DISRUPTION_RULE})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertIn("google_pubsub_topic.orders", finding.affected_resources)
        evidence = _evidence(finding)["downstream_dependencies"]
        self.assertEqual(
            evidence[0],
            "unique_dependency_count=1; unique_dependent_resource_count=1; "
            "unique_version_target_count=2; blast_radius_basis=downstream_encrypted_dependents",
        )
        self.assertEqual(len(evidence), 2)
        self.assertIn("cryptoKeyVersions/1", evidence[1])
        self.assertNotIn("cryptoKeyVersions/2", evidence[1])

    def test_inconsistent_version_dependency_is_not_projected(self) -> None:
        inventory = _inventory_with_version_dependency(coherent=False)
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_DISRUPTION_RULE})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertNotIn("google_pubsub_topic.orders", finding.affected_resources)
        self.assertEqual(
            _evidence(finding)["downstream_dependencies"][0],
            "unique_dependency_count=0; unique_dependent_resource_count=0; "
            "unique_version_target_count=2; blast_radius_basis=no_resolved_downstream_dependents",
        )

    def test_update_only_disruption_does_not_project_parent_key_dependents(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_key("data", "ENCRYPT_DECRYPT")),
                _as_resource(_version("data", "GOOGLE_SYMMETRIC_ENCRYPTION")),
                _topic_with_cmek(
                    "orders",
                    key_name=f"{_RING}/cryptoKeys/data",
                ),
                _as_resource(_project_member("runtime_admin", "roles/cloudkms.admin")),
            ]
        )
        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        update_paths = [
            path
            for path in gcp_facts(workload).cloud_run_kms_management_paths
            if path["operation"] == "cloudkms.cryptoKeyVersions.update"
        ]
        self.assertTrue(update_paths)
        object.__setattr__(workload, "_decoration_state_frozen", False)
        gcp_facts(workload).set_cloud_run_kms_management_paths(update_paths)
        object.__setattr__(workload, "_decoration_state_frozen", True)

        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_DISRUPTION_RULE})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertNotIn("google_pubsub_topic.orders", finding.affected_resources)
        self.assertIn("No deterministic CryptoKeyVersion destruction target", finding.rationale)
        self.assertEqual(
            _evidence(finding)["downstream_dependencies"],
            [
                "unique_dependency_count=0; unique_dependent_resource_count=0; "
                "unique_version_target_count=0; blast_radius_basis=no_resolved_downstream_dependents"
            ],
        )

    def test_unknown_cmek_dependency_does_not_enrich_disruption_blast_radius(self) -> None:
        findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_key("data", "ENCRYPT_DECRYPT")),
                _as_resource(_version("data", "GOOGLE_SYMMETRIC_ENCRYPTION")),
                _topic_with_cmek("orders", key_name=None, unknown_key=True),
                _as_resource(_project_member("runtime_admin", "roles/cloudkms.admin")),
            ],
            _DISRUPTION_RULE,
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertNotIn("google_pubsub_topic.orders", finding.affected_resources)
        evidence = _evidence(finding)
        self.assertEqual(
            evidence["downstream_dependencies"][0],
            "unique_dependency_count=0; unique_dependent_resource_count=0; "
            "unique_version_target_count=1; blast_radius_basis=no_resolved_downstream_dependents",
        )
        self.assertIn("No resolved downstream encrypted dependent resources", finding.rationale)

    def test_public_key_ring_and_exact_key_scopes_have_distinct_breadth(self) -> None:
        ring_findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_key("data", "ENCRYPT_DECRYPT")),
                _as_resource(_key("secondary", "ENCRYPT_DECRYPT")),
                _as_resource(_ring_member("runtime_ring_admin", "roles/cloudkms.admin")),
            ],
            _DELEGATION_RULE,
        )
        exact_findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_key("data", "ENCRYPT_DECRYPT")),
                _as_resource(_key_member("runtime_key_admin", "data", "roles/cloudkms.admin")),
            ],
            _DELEGATION_RULE,
        )

        self.assertEqual(len(ring_findings), 1)
        self.assertEqual(len(exact_findings), 1)
        assert ring_findings[0].severity_reasoning is not None
        assert exact_findings[0].severity_reasoning is not None
        self.assertEqual(ring_findings[0].severity_reasoning.blast_radius, 2)
        self.assertEqual(exact_findings[0].severity_reasoning.blast_radius, 1)
        self.assertIn(
            "key_ring_grants=1; exact_key_grants=0;",
            _evidence(ring_findings[0])["scope_breadth"][0],
        )
        self.assertIn(
            "key_ring_grants=0; exact_key_grants=1;",
            _evidence(exact_findings[0])["scope_breadth"][0],
        )

    def test_private_cloud_run_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _public_cloud_run(public_ingress=False),
                _public_invoker(),
                _as_resource(_key("data", "ENCRYPT_DECRYPT")),
                _as_resource(_project_member("runtime_admin", "roles/cloudkms.admin")),
            ],
            _DISRUPTION_RULE,
            _DELEGATION_RULE,
        )
        self.assertEqual(findings, [])

    def test_conditioned_management_grant_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _as_resource(_key("data", "ENCRYPT_DECRYPT")),
                _as_resource(
                    _project_member(
                        "runtime_admin",
                        "roles/cloudkms.admin",
                        condition={
                            "title": "business-hours",
                            "expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
                        },
                    )
                ),
            ],
            _DISRUPTION_RULE,
            _DELEGATION_RULE,
        )
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
