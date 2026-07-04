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

_SCC_ASSET_DISCOVERY_RULE = "gcp-scc-asset-discovery-disabled"
_LOGGING_EXCLUSION_RULE = "gcp-logging-exclusion-drops-audit-security-logs"
_CENTRAL_AUDIT_SINK_RULE = "gcp-central-audit-sink-not-modeled"
_AUDIT_RULE_IDS = (
    _SCC_ASSET_DISCOVERY_RULE,
    _LOGGING_EXCLUSION_RULE,
    _CENTRAL_AUDIT_SINK_RULE,
)
_MISSING = object()


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for rule_group in rule_groups for rule_id in rule_group)


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = GcpNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


def _scc_settings(
    enable_asset_discovery: object = True,
    *,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "organization": "1234567890",
        "asset_discovery_config": [{"inclusion_mode": "ALL"}],
    }
    if enable_asset_discovery is not _MISSING:
        values["enable_asset_discovery"] = enable_asset_discovery
    return _terraform_resource(
        "google_scc_organization_settings.main",
        GcpResourceType.SCC_ORGANIZATION_SETTINGS,
        values,
        unknown_values=unknown_values,
    )


def _project_exclusion(
    filter_text: object = "severity=DEBUG",
    *,
    disabled: object = False,
    name: str = "drop_audit",
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "name": name,
        "project": "tfstride-demo",
        "description": "test exclusion",
    }
    if filter_text is not _MISSING:
        values["filter"] = filter_text
    if disabled is not _MISSING:
        values["disabled"] = disabled
    return _terraform_resource(
        f"google_logging_project_exclusion.{name}",
        GcpResourceType.LOGGING_PROJECT_EXCLUSION,
        values,
        unknown_values=unknown_values,
    )


def _project_sink() -> TerraformResource:
    return _terraform_resource(
        "google_logging_project_sink.audit",
        GcpResourceType.LOGGING_PROJECT_SINK,
        {
            "name": "audit",
            "project": "tfstride-demo",
            "destination": "storage.googleapis.com/tfstride-audit-logs",
            "filter": "logName:cloudaudit.googleapis.com",
        },
    )


class GcpAuditRuleTests(unittest.TestCase):
    def test_audit_rule_ids_are_registered(self) -> None:
        self.assertLessEqual(frozenset(_AUDIT_RULE_IDS), _flatten(GCP_RULE_GROUP_IDS))

    def test_scc_asset_discovery_disabled_is_detected(self) -> None:
        findings = _evaluate([_scc_settings(False)], _SCC_ASSET_DISCOVERY_RULE)

        self.assertEqual([finding.rule_id for finding in findings], [_SCC_ASSET_DISCOVERY_RULE])
        self.assertEqual(findings[0].affected_resources, ["google_scc_organization_settings.main"])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["scc_asset_discovery"],
            [
                "address=google_scc_organization_settings.main",
                "type=google_scc_organization_settings",
                "name=main",
                "identifier=google_scc_organization_settings.main",
                "asset_discovery_state=disabled",
                "organization=1234567890",
                "inclusion_mode=ALL",
            ],
        )

    def test_scc_asset_discovery_enabled_or_unknown_is_quiet(self) -> None:
        enabled_findings = _evaluate([_scc_settings(True)], _SCC_ASSET_DISCOVERY_RULE)
        unknown_findings = _evaluate(
            [_scc_settings(_MISSING, unknown_values={"enable_asset_discovery": True})],
            _SCC_ASSET_DISCOVERY_RULE,
        )

        self.assertEqual(enabled_findings, [])
        self.assertEqual(unknown_findings, [])

    def test_active_logging_exclusion_that_matches_audit_logs_is_detected(self) -> None:
        findings = _evaluate(
            [_project_exclusion("logName:cloudaudit.googleapis.com", disabled=False)],
            _LOGGING_EXCLUSION_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_LOGGING_EXCLUSION_RULE])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["logging_exclusion"],
            [
                "address=google_logging_project_exclusion.drop_audit",
                "type=google_logging_project_exclusion",
                "name=drop_audit",
                "identifier=drop_audit",
                "disabled=false",
                "filter=logName:cloudaudit.googleapis.com",
                "scope_type=project",
                "scope=tfstride-demo",
            ],
        )
        self.assertEqual(evidence["matched_log_streams"], ["matches Cloud Audit Logs"])

    def test_disabled_non_security_or_unknown_logging_exclusions_are_quiet(self) -> None:
        findings = _evaluate(
            [
                _project_exclusion("logName:cloudaudit.googleapis.com", disabled=True, name="disabled_audit"),
                _project_exclusion("severity=DEBUG", disabled=False, name="debug"),
                _project_exclusion(
                    "logName:cloudaudit.googleapis.com",
                    disabled=False,
                    name="unknown_disabled",
                    unknown_values={"disabled": True},
                ),
            ],
            _LOGGING_EXCLUSION_RULE,
        )

        self.assertEqual(findings, [])

    def test_central_audit_sink_missing_only_when_audit_resources_are_modeled(self) -> None:
        findings = _evaluate([_scc_settings(True)], _CENTRAL_AUDIT_SINK_RULE)
        empty_findings = _evaluate([], _CENTRAL_AUDIT_SINK_RULE)

        self.assertEqual([finding.rule_id for finding in findings], [_CENTRAL_AUDIT_SINK_RULE])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["missing_control"],
            ["no google_logging_project_sink or organization sink modeled"],
        )
        self.assertEqual(
            evidence["modeled_audit_security_resources"],
            ["google_scc_organization_settings.main (google_scc_organization_settings)"],
        )
        self.assertEqual(empty_findings, [])

    def test_modeled_logging_sink_suppresses_missing_central_sink(self) -> None:
        findings = _evaluate([_scc_settings(True), _project_sink()], _CENTRAL_AUDIT_SINK_RULE)

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
