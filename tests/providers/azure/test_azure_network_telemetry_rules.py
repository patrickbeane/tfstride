from __future__ import annotations

import unittest
from typing import Any

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS

_MISSING_FLOW_LOG_RULE = "azure-nsg-flow-logs-not-configured"
_DISABLED_FLOW_LOG_RULE = "azure-nsg-flow-log-disabled"
_MISSING_DESTINATION_RULE = "azure-nsg-flow-log-destination-missing"
_INSUFFICIENT_RETENTION_RULE = "azure-nsg-flow-log-retention-insufficient"
_ALL_RULE_IDS = (
    _MISSING_FLOW_LOG_RULE,
    _DISABLED_FLOW_LOG_RULE,
    _MISSING_DESTINATION_RULE,
    _INSUFFICIENT_RETENTION_RULE,
)
_MISSING = object()


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for rule_group in rule_groups for rule_id in rule_group)


def _resource(
    resource_type: str,
    name: str,
    values: dict[str, object],
    *,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values=values,
        unknown_values=unknown_values or {},
    )


def _network_security_group(
    *, name: str = "app", nsg_id: str = "azurerm_network_security_group.app.id"
) -> TerraformResource:
    return _resource(
        AzureResourceType.NETWORK_SECURITY_GROUP,
        name,
        {
            "id": nsg_id,
            "name": name,
            "location": "eastus",
        },
    )


def _flow_log(
    *,
    name: str = "app",
    target_id: object = "azurerm_network_security_group.app.id",
    enabled: object = True,
    storage_account_id: object = "azurerm_storage_account.flow_logs.id",
    retention_policy: object = _MISSING,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "id": f"/subscriptions/example/networkWatchers/watcher/flowLogs/{name}",
        "name": name,
        "network_watcher_name": "watcher",
        "resource_group_name": "rg-network",
        "version": 2,
    }
    if target_id is not _MISSING:
        values["network_security_group_id"] = target_id
    if enabled is not _MISSING:
        values["enabled"] = enabled
    if storage_account_id is not _MISSING:
        values["storage_account_id"] = storage_account_id
    if retention_policy is _MISSING:
        values["retention_policy"] = [{"enabled": True, "days": 30}]
    elif retention_policy is not None:
        values["retention_policy"] = retention_policy
    return _resource(
        AzureResourceType.NETWORK_WATCHER_FLOW_LOG,
        name,
        values,
        unknown_values=unknown_values,
    )


def _findings(resources: list[TerraformResource], *rule_ids: str):
    inventory = AzureNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AzureNetworkTelemetryRuleTests(unittest.TestCase):
    def test_network_telemetry_rule_ids_are_registered(self) -> None:
        self.assertLessEqual(frozenset(_ALL_RULE_IDS), _flatten(AZURE_RULE_GROUP_IDS))

    def test_network_security_group_without_flow_logs_is_detected(self) -> None:
        findings = _findings([_network_security_group()], _MISSING_FLOW_LOG_RULE)

        self.assertEqual([finding.rule_id for finding in findings], [_MISSING_FLOW_LOG_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        self.assertEqual(findings[0].affected_resources, ["azurerm_network_security_group.app"])
        evidence = _evidence_by_key(findings[0])
        self.assertIn("resolved_nsg_flow_log_count=0", evidence["flow_log_coverage"])
        self.assertIn("azurerm_network_watcher_flow_log resources are not modeled", evidence["flow_log_coverage"])

    def test_resolved_enabled_flow_log_with_destination_and_retention_is_quiet(self) -> None:
        findings = _findings([_network_security_group(), _flow_log()], *_ALL_RULE_IDS)

        self.assertEqual(findings, [])

    def test_unresolved_flow_log_target_suppresses_missing_nsg_finding(self) -> None:
        findings = _findings(
            [
                _network_security_group(),
                _flow_log(target_id=_MISSING, unknown_values={"network_security_group_id": True}),
            ],
            _MISSING_FLOW_LOG_RULE,
        )

        self.assertEqual(findings, [])

    def test_disabled_flow_log_is_detected(self) -> None:
        findings = _findings([_network_security_group(), _flow_log(enabled=False)], _DISABLED_FLOW_LOG_RULE)

        self.assertEqual([finding.rule_id for finding in findings], [_DISABLED_FLOW_LOG_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["flow_log_state"], ["flow_log_state=disabled"])

    def test_unknown_flow_log_enabled_state_is_reported_as_uncertain(self) -> None:
        findings = _findings(
            [
                _network_security_group(),
                _flow_log(enabled=_MISSING, unknown_values={"enabled": True}),
            ],
            _DISABLED_FLOW_LOG_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_DISABLED_FLOW_LOG_RULE])
        self.assertEqual(findings[0].severity.value, "low")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["flow_log_state"], ["flow_log_state=unknown"])
        self.assertEqual(evidence["posture_uncertainty"], ["uncertainty=enabled is unknown after planning"])

    def test_flow_log_without_storage_destination_is_detected(self) -> None:
        findings = _findings(
            [_network_security_group(), _flow_log(storage_account_id=_MISSING)],
            _MISSING_DESTINATION_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_MISSING_DESTINATION_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["log_destination"], ["storage_account_id is unset", "traffic_analytics_state=not_configured"]
        )

    def test_flow_log_unknown_storage_destination_is_reported_as_uncertain(self) -> None:
        findings = _findings(
            [
                _network_security_group(),
                _flow_log(storage_account_id=_MISSING, unknown_values={"storage_account_id": True}),
            ],
            _MISSING_DESTINATION_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_MISSING_DESTINATION_RULE])
        self.assertEqual(findings[0].severity.value, "low")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["posture_uncertainty"], ["uncertainty=storage_account_id is unknown after planning"])

    def test_flow_log_short_retention_is_detected(self) -> None:
        findings = _findings(
            [_network_security_group(), _flow_log(retention_policy=[{"enabled": True, "days": 3}])],
            _INSUFFICIENT_RETENTION_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_INSUFFICIENT_RETENTION_RULE])
        self.assertEqual(findings[0].severity.value, "low")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["retention_posture"],
            [
                "retention_state=enabled",
                "minimum_retention_days=7",
                "retention_issue=short_retention",
                "retention_days=3",
                "retention_policy={'enabled': True, 'days': 3}",
            ],
        )

    def test_flow_log_disabled_or_unknown_retention_is_detected(self) -> None:
        disabled_findings = _findings(
            [_network_security_group(), _flow_log(retention_policy=[{"enabled": False, "days": 0}])],
            _INSUFFICIENT_RETENTION_RULE,
        )
        unknown_findings = _findings(
            [
                _network_security_group(),
                _flow_log(
                    retention_policy=[{}],
                    unknown_values={"retention_policy": [{"enabled": True, "days": True}]},
                ),
            ],
            _INSUFFICIENT_RETENTION_RULE,
        )

        self.assertEqual([finding.rule_id for finding in disabled_findings], [_INSUFFICIENT_RETENTION_RULE])
        self.assertEqual(disabled_findings[0].severity.value, "low")
        self.assertEqual([finding.rule_id for finding in unknown_findings], [_INSUFFICIENT_RETENTION_RULE])
        self.assertEqual(unknown_findings[0].severity.value, "low")
        self.assertEqual(
            _evidence_by_key(unknown_findings[0])["posture_uncertainty"],
            [
                "uncertainty=retention_policy.enabled is unknown after planning",
                "uncertainty=retention_policy.days is unknown after planning",
            ],
        )


if __name__ == "__main__":
    unittest.main()
