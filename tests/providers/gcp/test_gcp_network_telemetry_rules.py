from __future__ import annotations

import unittest
from typing import Any

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_types import GcpResourceType
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

_MISSING_FLOW_LOG_RULE = "gcp-subnetwork-flow-logs-not-configured"
_INCOMPLETE_CAPTURE_RULE = "gcp-subnetwork-flow-log-capture-incomplete"
_ALL_RULE_IDS = (_MISSING_FLOW_LOG_RULE, _INCOMPLETE_CAPTURE_RULE)
_MISSING = object()


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for rule_group in rule_groups for rule_id in rule_group)


def _subnetwork(
    log_config: object = _MISSING,
    *,
    name: str = "app",
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "name": f"tfstride-{name}",
        "id": f"google_compute_subnetwork.{name}",
        "self_link": f"projects/tfstride-demo/regions/us-central1/subnetworks/tfstride-{name}",
        "project": "tfstride-demo",
        "region": "us-central1",
        "network": "google_compute_network.main.id",
        "ip_cidr_range": "10.10.0.0/24",
    }
    if log_config is not _MISSING:
        values["log_config"] = log_config
    return _terraform_resource(
        f"google_compute_subnetwork.{name}",
        GcpResourceType.COMPUTE_SUBNETWORK,
        values,
        unknown_values=unknown_values,
    )


def _flow_log_config(**overrides: object) -> list[dict[str, object]]:
    values: dict[str, object] = {
        "aggregation_interval": "INTERVAL_5_SEC",
        "flow_sampling": 1.0,
        "metadata": "INCLUDE_ALL_METADATA",
    }
    values.update(overrides)
    return [values]


def _findings(resources: list[TerraformResource], *rule_ids: str):
    inventory = GcpNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class GcpNetworkTelemetryRuleTests(unittest.TestCase):
    def test_network_telemetry_rule_ids_are_registered(self) -> None:
        self.assertLessEqual(frozenset(_ALL_RULE_IDS), _flatten(GCP_RULE_GROUP_IDS))

    def test_subnetwork_without_flow_logs_is_detected(self) -> None:
        findings = _findings([_subnetwork()], _MISSING_FLOW_LOG_RULE)

        self.assertEqual([finding.rule_id for finding in findings], [_MISSING_FLOW_LOG_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        self.assertIn("does not configure VPC Flow Logs", findings[0].rationale)
        evidence = _evidence_by_key(findings[0])
        self.assertIn("flow_log_state=not_configured", evidence["subnetwork_flow_log_posture"])
        self.assertIn("network=google_compute_network.main.id", evidence["subnetwork_flow_log_posture"])

    def test_unknown_flow_log_block_is_reported_as_uncertain(self) -> None:
        findings = _findings(
            [_subnetwork(unknown_values={"log_config": True})],
            _MISSING_FLOW_LOG_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_MISSING_FLOW_LOG_RULE])
        self.assertEqual(findings[0].severity.value, "low")
        self.assertIn("unknown VPC Flow Logs configuration", findings[0].rationale)
        evidence = _evidence_by_key(findings[0])
        self.assertIn("flow_log_state=unknown", evidence["subnetwork_flow_log_posture"])
        self.assertEqual(evidence["posture_uncertainty"], ["log_config is unknown after planning"])

    def test_enabled_complete_flow_logs_are_quiet(self) -> None:
        findings = _findings([_subnetwork(_flow_log_config())], *_ALL_RULE_IDS)

        self.assertEqual(findings, [])

    def test_flow_log_sampling_below_full_capture_is_detected(self) -> None:
        findings = _findings(
            [_subnetwork(_flow_log_config(flow_sampling=0.5))],
            _INCOMPLETE_CAPTURE_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_INCOMPLETE_CAPTURE_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        evidence = _evidence_by_key(findings[0])
        self.assertIn("flow_sampling=0.5", evidence["subnetwork_flow_log_posture"])
        self.assertEqual(
            evidence["capture_posture"],
            ["flow_sampling=0.5 captures a sampled subset of flows"],
        )

    def test_flow_log_filter_and_metadata_exclusion_are_detected(self) -> None:
        findings = _findings(
            [
                _subnetwork(
                    _flow_log_config(
                        metadata="EXCLUDE_ALL_METADATA",
                        filter_expr="connection.dest_port != 22",
                    )
                )
            ],
            _INCOMPLETE_CAPTURE_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_INCOMPLETE_CAPTURE_RULE])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["capture_posture"],
            [
                "metadata=EXCLUDE_ALL_METADATA omits flow metadata used for investigation context",
                "filter_expr=connection.dest_port != 22 may exclude matching flow records",
            ],
        )

    def test_unknown_capture_fields_are_reported_as_uncertain(self) -> None:
        findings = _findings(
            [
                _subnetwork(
                    _flow_log_config(),
                    unknown_values={"log_config": [{"flow_sampling": True, "metadata": True}]},
                )
            ],
            _INCOMPLETE_CAPTURE_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_INCOMPLETE_CAPTURE_RULE])
        self.assertEqual(findings[0].severity.value, "low")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["capture_posture"],
            [
                "uncertainty=log_config.flow_sampling is unknown after planning",
                "uncertainty=log_config.metadata is unknown after planning",
            ],
        )


if __name__ == "__main__":
    unittest.main()
