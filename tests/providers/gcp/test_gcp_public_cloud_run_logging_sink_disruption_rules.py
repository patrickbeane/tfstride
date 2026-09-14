from __future__ import annotations

import unittest

from tests.providers.gcp.test_gcp_cloud_run_logging_sink_audit_telemetry_disruption_paths import (
    _CUSTOM_ROLE_ADDRESS,
    _DENY_DELETE_SINK,
    _DESTINATION,
    _IAM_ADDRESS,
    _RUNTIME_DENY_PRINCIPAL,
    _SINK_ADDRESS,
    _SINK_RESOURCE_NAME,
    _custom_role,
    _deny_policy,
    _project_member,
    _sink,
)
from tests.providers.gcp.test_gcp_public_cloud_run_firestore_mutation_rules import (
    _PUBLIC_INVOKER_ADDRESS,
    _public_cloud_run,
    _public_invoker,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import ResourceInventory, StrideCategory, TerraformResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

_RULE_ID = "gcp-public-cloud-run-logging-sink-disruption"
_WORKLOAD_ADDRESS = "google_cloud_run_v2_service.orders"
_DELETE_SINK = "logging.sinks.delete"


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = GcpNormalizer().normalize(resources)
    return inventory, _evaluate_inventory(inventory, *(rule_ids or (_RULE_ID,)))


def _evaluate_inventory(inventory: ResourceInventory, *rule_ids: str):
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids or (_RULE_ID,))),
    )


def _resources(
    *,
    public_ingress: bool = True,
    sink: TerraformResource | None = None,
) -> list[TerraformResource]:
    return [
        _public_cloud_run(public_ingress=public_ingress),
        _public_invoker(),
        sink or _sink(),
        _custom_role(),
        _project_member(),
    ]


def _evidence(finding):
    return {item.key: item.values for item in finding.evidence}


class GcpPublicCloudRunLoggingSinkDisruptionRuleTests(unittest.TestCase):
    def test_rule_is_registered(self) -> None:
        registered = {rule_id for group in GCP_RULE_GROUP_IDS for rule_id in group}
        self.assertIn(_RULE_ID, registered)

    def test_public_workload_has_repudiation_finding_for_exact_sink_authority(self) -> None:
        _inventory, findings = _evaluate(_resources())

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.category, StrideCategory.REPUDIATION)
        self.assertEqual(
            finding.affected_resources,
            [
                _WORKLOAD_ADDRESS,
                _PUBLIC_INVOKER_ADDRESS,
                _SINK_ADDRESS,
                _CUSTOM_ROLE_ADDRESS,
                _IAM_ADDRESS,
            ],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            f"internet-to-service:internet->{_WORKLOAD_ADDRESS}",
        )
        evidence = _evidence(finding)
        self.assertIn(
            f"sink_resource_name={_SINK_RESOURCE_NAME}",
            evidence["logging_sink_audit_telemetry_disruption_paths"][0],
        )
        self.assertIn(f"destination={_DESTINATION}", evidence["logging_sink_audit_telemetry_disruption_paths"][0])
        self.assertIn(f"operation={_DELETE_SINK}", evidence["logging_sink_audit_telemetry_disruption_paths"][0])
        self.assertIn(
            "audit_telemetry_relevance_state=established",
            evidence["logging_sink_audit_telemetry_relevance_evidence"][0],
        )
        self.assertIn("Repudiation", evidence["assessment_scope"][0])
        self.assertIn("future export or recording", finding.rationale)
        self.assertIn("weakening auditability/accountability", finding.rationale)
        for nonclaim in (
            "successful API call",
            "retained source logs",
            "logs already delivered",
            "destination resource",
            "every project or out-of-plan sink",
            "historical audit-log erasure",
            "recovery/restoration",
        ):
            self.assertIn(nonclaim, finding.rationale)

    def test_private_workload_keeps_model_path_but_emits_no_finding(self) -> None:
        inventory, findings = _evaluate(_resources(public_ingress=False))

        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        self.assertTrue(gcp_facts(workload).cloud_run_logging_sink_audit_telemetry_disruption_paths)
        self.assertEqual(findings, [])

    def test_revoked_current_iam_authority_suppresses_stale_candidate(self) -> None:
        inventory, findings = _evaluate(_resources())
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        source = inventory.get_by_address(_IAM_ADDRESS)
        assert source is not None
        gcp_facts(source).set(GcpResourceMetadata.IAM_BINDINGS, [])
        gcp_facts(source).set(GcpResourceMetadata.IAM_ROLE, None)
        gcp_facts(source).set(GcpResourceMetadata.IAM_MEMBER, None)

        self.assertEqual(_evaluate_inventory(inventory), [])

    def test_new_current_iam_deny_suppresses_stale_candidate(self) -> None:
        inventory, findings = _evaluate(
            [
                *_resources(),
                _deny_policy(denied_permissions=["logging.googleapis.com/logMetrics.delete"]),
            ]
        )
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        deny_policy = inventory.get_by_address("google_iam_deny_policy.logging_sink")
        assert deny_policy is not None
        gcp_facts(deny_policy).set(
            GcpResourceMetadata.IAM_DENY_POLICY_RULES,
            [
                {
                    "denied_principals": [_RUNTIME_DENY_PRINCIPAL],
                    "denied_principals_state": "configured",
                    "exception_principals": [],
                    "exception_principals_state": "not_configured",
                    "denied_permissions": [_DENY_DELETE_SINK],
                    "denied_permissions_state": "configured",
                    "exception_permissions": [],
                    "exception_permissions_state": "not_configured",
                    "condition": None,
                    "condition_state": "not_configured",
                }
            ],
        )

        self.assertEqual(_evaluate_inventory(inventory), [])

    def test_changed_runtime_service_account_suppresses_stale_candidate(self) -> None:
        inventory, findings = _evaluate(_resources())
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        gcp_facts(workload).set(
            GcpResourceMetadata.SERVICE_ACCOUNT_EMAIL,
            "changed@tfstride-demo.iam.gserviceaccount.com",
        )
        gcp_facts(workload).set(
            GcpResourceMetadata.SERVICE_ACCOUNT_MEMBER,
            "serviceAccount:changed@tfstride-demo.iam.gserviceaccount.com",
        )

        self.assertEqual(_evaluate_inventory(inventory), [])

    def test_current_custom_role_uses_remaining_strong_identity_and_rejects_unresolved_identity(
        self,
    ) -> None:
        inventory, findings = _evaluate(_resources())
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        role = inventory.get_by_address(_CUSTOM_ROLE_ADDRESS)
        assert role is not None
        role_facts = gcp_facts(role)
        role_facts.set(GcpResourceMetadata.CUSTOM_ROLE_ID, None)

        self.assertEqual(
            [finding.rule_id for finding in _evaluate_inventory(inventory)],
            [_RULE_ID],
        )

        role.identifier = None
        role_facts.set(GcpResourceMetadata.NAME, None)

        self.assertEqual(_evaluate_inventory(inventory), [])

    def test_changed_or_disabled_sink_suppresses_stale_candidate(self) -> None:
        for change in ("target", "disabled"):
            with self.subTest(change=change):
                inventory, findings = _evaluate(_resources())
                self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
                sink = inventory.get_by_address(_SINK_ADDRESS)
                assert sink is not None
                facts = gcp_facts(sink)
                if change == "target":
                    facts.set(GcpResourceMetadata.LOGGING_SINK_NAME, "changed")
                else:
                    facts.set(GcpResourceMetadata.LOGGING_SINK_DISABLED, True)
                self.assertEqual(_evaluate_inventory(inventory), [])

    def test_destination_filter_and_exclusion_drift_suppress_relevance(self) -> None:
        mutations = {
            "destination": lambda facts: facts.set(GcpResourceMetadata.LOGGING_SINK_DESTINATION, None),
            "filter": lambda facts: facts.set(GcpResourceMetadata.LOGGING_SINK_FILTER, "severity>=ERROR"),
            "non-audit protobuf filter": lambda facts: facts.set(
                GcpResourceMetadata.LOGGING_SINK_FILTER,
                'protoPayload.@type="type.googleapis.com/google.cloud.storage.SomeEvent"',
            ),
            "unary-negative audit filter": lambda facts: facts.set(
                GcpResourceMetadata.LOGGING_SINK_FILTER,
                '-logName:"cloudaudit.googleapis.com"',
            ),
            "active exclusion": lambda facts: facts.set(
                GcpResourceMetadata.LOGGING_SINK_EXCLUSIONS,
                [
                    {
                        "name": "drop-debug",
                        "filter": "severity=DEBUG",
                        "filter_state": "configured",
                        "disabled_state": "configured",
                        "disabled": False,
                    }
                ],
            ),
        }
        for change, mutate in mutations.items():
            with self.subTest(change=change):
                inventory, findings = _evaluate(_resources())
                self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
                sink = inventory.get_by_address(_SINK_ADDRESS)
                assert sink is not None
                mutate(gcp_facts(sink))
                self.assertEqual(_evaluate_inventory(inventory), [])

    def test_valid_destination_drift_refreshes_current_evidence(self) -> None:
        inventory, findings = _evaluate(_resources())
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        new_destination = "pubsub.googleapis.com/projects/tfstride-demo/topics/audit-archive"
        sink = inventory.get_by_address(_SINK_ADDRESS)
        assert sink is not None
        gcp_facts(sink).set(GcpResourceMetadata.LOGGING_SINK_DESTINATION, new_destination)

        current_findings = _evaluate_inventory(inventory)
        self.assertEqual([finding.rule_id for finding in current_findings], [_RULE_ID])
        evidence = _evidence(current_findings[0])
        self.assertIn(
            f"destination={new_destination}",
            evidence["logging_sink_audit_telemetry_disruption_paths"][0],
        )
        self.assertNotIn(
            f"destination={_DESTINATION}",
            evidence["logging_sink_audit_telemetry_disruption_paths"][0],
        )

    def test_valid_positive_filter_drift_refreshes_current_evidence(self) -> None:
        inventory, findings = _evaluate(_resources())
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        new_filter = 'protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog"'
        sink = inventory.get_by_address(_SINK_ADDRESS)
        assert sink is not None
        gcp_facts(sink).set(GcpResourceMetadata.LOGGING_SINK_FILTER, new_filter)

        current_findings = _evaluate_inventory(inventory)
        self.assertEqual([finding.rule_id for finding in current_findings], [_RULE_ID])
        evidence = _evidence(current_findings[0])
        self.assertIn(f"sink_filter={new_filter}", evidence["logging_sink_audit_telemetry_relevance_evidence"][0])
        self.assertIn(
            "audit_telemetry_relevance_state=established",
            evidence["logging_sink_audit_telemetry_relevance_evidence"][0],
        )

    def test_unrelated_custom_role_permission_drift_refreshes_current_evidence(self) -> None:
        inventory, findings = _evaluate(_resources())
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        role = inventory.get_by_address(_CUSTOM_ROLE_ADDRESS)
        assert role is not None
        gcp_facts(role).set(
            GcpResourceMetadata.CUSTOM_ROLE_PERMISSIONS,
            [_DELETE_SINK, "logging.sinks.get"],
        )

        current_findings = _evaluate_inventory(inventory)
        self.assertEqual([finding.rule_id for finding in current_findings], [_RULE_ID])
        path_evidence = _evidence(current_findings[0])["logging_sink_audit_telemetry_disruption_paths"][0]
        self.assertIn(
            "custom_role_permissions=logging.sinks.delete,logging.sinks.get",
            path_evidence,
        )

    def test_duplicate_cached_paths_deduplicate_targets_and_evidence(self) -> None:
        inventory, findings = _evaluate(_resources())
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        paths = gcp_facts(workload).cloud_run_logging_sink_audit_telemetry_disruption_paths
        gcp_facts(workload).set_cloud_run_logging_sink_audit_telemetry_disruption_paths(paths + [dict(paths[0])])

        current_findings = _evaluate_inventory(inventory)
        self.assertEqual([finding.rule_id for finding in current_findings], [_RULE_ID])
        evidence = _evidence(current_findings[0])
        self.assertEqual(len(evidence["logging_sink_audit_telemetry_disruption_paths"]), 1)
        self.assertEqual(current_findings[0].affected_resources.count(_SINK_ADDRESS), 1)

    def test_stale_cached_target_address_is_rejected(self) -> None:
        inventory, findings = _evaluate(_resources())
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        paths = gcp_facts(workload).cloud_run_logging_sink_audit_telemetry_disruption_paths
        paths[0]["logging_sink_address"] = "google_logging_project_sink.stale"
        gcp_facts(workload).set_cloud_run_logging_sink_audit_telemetry_disruption_paths(paths)

        self.assertEqual(_evaluate_inventory(inventory), [])


if __name__ == "__main__":
    unittest.main()
