from __future__ import annotations

import unittest
from pathlib import Path

from tests.providers.azure.test_azure_app_service_diagnostic_setting_audit_telemetry_disruption_paths import (
    _AZURE_DIAGNOSTIC_ID,
    _AZURE_DIAGNOSTIC_STATE_ID,
    _AZURE_WORKLOAD_ID,
    _STORAGE_ID,
    _azure_diagnostic_setting,
    _azure_workload,
    _valid_resources,
)
from tests.providers.test_public_workload_structured_data_topology_destruction_boundaries import (
    _azure_management_lock,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.app import TfStride
from tfstride.models import ResourceInventory, StrideCategory, TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS

_RULE_ID = "azure-public-app-service-diagnostic-setting-disruption"
_WORKLOAD_ADDRESS = "azurerm_linux_web_app.orders"
_DIAGNOSTIC_ADDRESS = "azurerm_monitor_diagnostic_setting.audit"
_ROLE_ADDRESS = "azurerm_role_definition.audit_telemetry"
_ASSIGNMENT_ADDRESS = "azurerm_role_assignment.audit_telemetry"
_DELETE_DIAGNOSTIC = "Microsoft.Insights/DiagnosticSettings/Delete"


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = AzureNormalizer().normalize(resources)
    return inventory, _evaluate_inventory(inventory, *(rule_ids or (_RULE_ID,)))


def _evaluate_inventory(inventory: ResourceInventory, *rule_ids: str):
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids or (_RULE_ID,))),
    )


def _evidence(finding):
    return {item.key: item.values for item in finding.evidence}


class AzurePublicAppServiceDiagnosticSettingDisruptionRuleTests(unittest.TestCase):
    def test_rule_is_registered(self) -> None:
        registered = {rule_id for group in AZURE_RULE_GROUP_IDS for rule_id in group}
        self.assertIn(_RULE_ID, registered)

    def test_public_workload_has_repudiation_finding_for_exact_current_authority(self) -> None:
        _inventory, findings = _evaluate(_valid_resources())

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.category, StrideCategory.REPUDIATION)
        self.assertEqual(
            finding.affected_resources,
            [
                _WORKLOAD_ADDRESS,
                _DIAGNOSTIC_ADDRESS,
                _ASSIGNMENT_ADDRESS,
                _ROLE_ADDRESS,
            ],
        )
        evidence = _evidence(finding)
        path_evidence = evidence["diagnostic_setting_audit_telemetry_disruption_paths"][0]
        self.assertIn(f"diagnostic_setting_id={_AZURE_DIAGNOSTIC_STATE_ID}", path_evidence)
        self.assertIn(f"diagnostic_setting_reference={_AZURE_DIAGNOSTIC_STATE_ID}", path_evidence)
        self.assertIn(f"diagnostic_setting_arm_id={_AZURE_DIAGNOSTIC_ID}", path_evidence)
        self.assertIn(f"operation={_DELETE_DIAGNOSTIC}", path_evidence)
        self.assertIn(
            "destination_basis=log_analytics_workspace", evidence["diagnostic_setting_destination_evidence"][0]
        )
        self.assertIn(
            "audit_telemetry_relevance_state=established",
            evidence["diagnostic_setting_audit_telemetry_relevance_evidence"][0],
        )
        self.assertIn(
            "modeled_management_lock_state=not_observed", evidence["diagnostic_setting_management_lock_evidence"][0]
        )
        self.assertIn("Repudiation", evidence["assessment_scope"][0])
        self.assertIn("future export or recording", finding.rationale)
        self.assertIn("weakening auditability/accountability", finding.rationale)
        for nonclaim in (
            "successful API call",
            "historical/source telemetry",
            "logs already delivered to Log Analytics",
            "logs already delivered to Storage",
            "logs already delivered to Event Hubs",
            "marketplace/partner destinations",
            "destination resource",
            "every parent-resource, subscription, or tenant diagnostic setting",
            "out-of-plan settings",
            "recovery/restoration",
        ):
            self.assertIn(nonclaim, finding.rationale)

    def test_private_workload_keeps_model_path_but_emits_no_finding(self) -> None:
        inventory, findings = _evaluate(_valid_resources(workload=_azure_workload(public=False)))

        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        self.assertTrue(azure_facts(workload).app_service_diagnostic_setting_audit_telemetry_disruption_paths)
        self.assertEqual(findings, [])

    def test_revoked_rbac_suppresses_stale_candidate(self) -> None:
        inventory, findings = _evaluate(_valid_resources())
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        role = inventory.get_by_address(_ROLE_ADDRESS)
        assert role is not None
        azure_facts(role).set(AzureResourceMetadata.ROLE_DEFINITION_ACTIONS, [])

        self.assertEqual(_evaluate_inventory(inventory), [])

    def test_changed_or_detached_runtime_identity_suppresses_stale_candidate(self) -> None:
        for change in ("principal", "detached"):
            with self.subTest(change=change):
                inventory, findings = _evaluate(_valid_resources())
                self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
                workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
                assert workload is not None
                facts = azure_facts(workload)
                if change == "principal":
                    facts.set(AzureResourceMetadata.PRINCIPAL_ID, "replacement-principal")
                else:
                    facts.set(AzureResourceMetadata.IDENTITY_TYPE, "None")
                self.assertEqual(_evaluate_inventory(inventory), [])

    def test_changed_exact_diagnostic_setting_target_suppresses_stale_candidate(self) -> None:
        inventory, findings = _evaluate(_valid_resources())
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        diagnostic = inventory.get_by_address(_DIAGNOSTIC_ADDRESS)
        assert diagnostic is not None
        azure_facts(diagnostic).set(
            AzureResourceMetadata.DIAGNOSTIC_SETTING_ID,
            f"{_AZURE_WORKLOAD_ID}|replacement",
        )

        self.assertEqual(_evaluate_inventory(inventory), [])

    def test_valid_destination_drift_refreshes_current_evidence(self) -> None:
        inventory, findings = _evaluate(_valid_resources())
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        diagnostic = inventory.get_by_address(_DIAGNOSTIC_ADDRESS)
        assert diagnostic is not None
        facts = azure_facts(diagnostic)
        facts.set(AzureResourceMetadata.DIAGNOSTIC_LOG_ANALYTICS_WORKSPACE_ID, None)
        facts.set(AzureResourceMetadata.DIAGNOSTIC_STORAGE_ACCOUNT_ID, _STORAGE_ID)

        current_findings = _evaluate_inventory(inventory)
        self.assertEqual([finding.rule_id for finding in current_findings], [_RULE_ID])
        evidence = _evidence(current_findings[0])
        self.assertIn("destination_basis=storage_account", evidence["diagnostic_setting_destination_evidence"][0])
        self.assertIn(f"storage_account_id={_STORAGE_ID}", evidence["diagnostic_setting_destination_evidence"][0])
        self.assertNotIn(
            "destination_basis=log_analytics_workspace", evidence["diagnostic_setting_destination_evidence"][0]
        )

    def test_missing_or_unresolved_destination_suppresses_candidate(self) -> None:
        missing = _azure_diagnostic_setting()
        missing.values.pop("log_analytics_workspace_id")
        unresolved = _azure_diagnostic_setting(unknown_values={"log_analytics_workspace_id": True})

        for case, diagnostic in (("missing", missing), ("unresolved", unresolved)):
            with self.subTest(case=case):
                self.assertEqual(_evaluate(_valid_resources(diagnostic=diagnostic))[1], [])

    def test_valid_audit_relevance_drift_refreshes_current_evidence(self) -> None:
        inventory, findings = _evaluate(_valid_resources())
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        diagnostic = inventory.get_by_address(_DIAGNOSTIC_ADDRESS)
        assert diagnostic is not None
        facts = azure_facts(diagnostic)
        facts.set(AzureResourceMetadata.DIAGNOSTIC_ENABLED_LOG_CATEGORY_GROUPS, [])
        facts.set(AzureResourceMetadata.DIAGNOSTIC_ENABLED_LOG_CATEGORIES, ["AppServiceAuditLogs"])
        facts.set(AzureResourceMetadata.DIAGNOSTIC_LOG_RECORDS, [{"category": "AppServiceAuditLogs"}])

        current_findings = _evaluate_inventory(inventory)
        self.assertEqual([finding.rule_id for finding in current_findings], [_RULE_ID])
        evidence = _evidence(current_findings[0])
        self.assertIn(
            "relevance_basis=audit_security_category",
            evidence["diagnostic_setting_audit_telemetry_relevance_evidence"][0],
        )
        self.assertIn(
            "matched_audit_security_category=AppServiceAuditLogs",
            evidence["diagnostic_setting_audit_telemetry_relevance_evidence"][0],
        )

    def test_loss_of_audit_relevance_suppresses_candidate(self) -> None:
        for category in (
            "AppServiceHTTPLogs",
            "AppServiceAuditLogsArchive",
            "SecurityPostureLogs",
        ):
            with self.subTest(category=category):
                inventory, findings = _evaluate(_valid_resources())
                self.assertEqual(
                    [finding.rule_id for finding in findings],
                    [_RULE_ID],
                )

                diagnostic = inventory.get_by_address(_DIAGNOSTIC_ADDRESS)
                assert diagnostic is not None
                facts = azure_facts(diagnostic)
                facts.set(
                    AzureResourceMetadata.DIAGNOSTIC_ENABLED_LOG_CATEGORY_GROUPS,
                    [],
                )
                facts.set(
                    AzureResourceMetadata.DIAGNOSTIC_ENABLED_LOG_CATEGORIES,
                    [category],
                )
                facts.set(
                    AzureResourceMetadata.DIAGNOSTIC_LOG_RECORDS,
                    [{"category": category}],
                )

                self.assertEqual(_evaluate_inventory(inventory), [])

    def test_blocking_or_unresolved_lock_suppresses_candidate(self) -> None:
        cases = {
            "can not delete": _azure_management_lock(scope=_AZURE_DIAGNOSTIC_ID),
            "read only": _azure_management_lock(scope=_AZURE_WORKLOAD_ID, level="ReadOnly"),
            "unresolved scope": _azure_management_lock(scope=_AZURE_WORKLOAD_ID, unknown_scope=True),
            "unresolved level": _azure_management_lock(scope=_AZURE_DIAGNOSTIC_ID, unknown_level=True),
        }
        for case, lock in cases.items():
            with self.subTest(case=case):
                self.assertEqual(_evaluate([*_valid_resources(), lock])[1], [])

    def test_valid_role_evidence_refresh_does_not_stale_kill_finding(self) -> None:
        inventory, findings = _evaluate(_valid_resources())
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        role = inventory.get_by_address(_ROLE_ADDRESS)
        assert role is not None
        azure_facts(role).set(
            AzureResourceMetadata.ROLE_DEFINITION_ACTIONS,
            [_DELETE_DIAGNOSTIC, "Microsoft.Insights/DiagnosticSettings/Read"],
        )

        current_findings = _evaluate_inventory(inventory)
        self.assertEqual([finding.rule_id for finding in current_findings], [_RULE_ID])
        path_evidence = _evidence(current_findings[0])["diagnostic_setting_audit_telemetry_disruption_paths"][0]
        self.assertIn("Microsoft.Insights/DiagnosticSettings/Read", path_evidence)

    def test_duplicate_cached_paths_deduplicate_deterministically(self) -> None:
        inventory, findings = _evaluate(_valid_resources())
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        facts = azure_facts(workload)
        paths = facts.app_service_diagnostic_setting_audit_telemetry_disruption_paths
        facts.set_app_service_diagnostic_setting_audit_telemetry_disruption_paths(paths + [dict(paths[0])])

        current_findings = _evaluate_inventory(inventory)
        self.assertEqual([finding.rule_id for finding in current_findings], [_RULE_ID])
        evidence = _evidence(current_findings[0])
        self.assertEqual(len(evidence["diagnostic_setting_audit_telemetry_disruption_paths"]), 1)
        self.assertEqual(current_findings[0].affected_resources.count(_DIAGNOSTIC_ADDRESS), 1)


class AzurePublicAppServiceKeyVaultAuditFixtureTests(unittest.TestCase):
    def test_key_vault_audit_event_setting_is_a_disruption_target(self) -> None:
        fixture = (
            Path(__file__).resolve().parents[3]
            / "fixtures"
            / "azure"
            / "sample_azure_key_vault_audit_disruption_plan.json"
        )
        result = TfStride().analyze_plan(fixture)

        findings = [finding for finding in result.findings if finding.rule_id == _RULE_ID]
        self.assertEqual(len(findings), 1)
        self.assertIn("azurerm_monitor_diagnostic_setting.key_vault_audit", findings[0].affected_resources)
        evidence = " ".join(
            value for item in findings[0].evidence if item.key.endswith("relevance_evidence") for value in item.values
        )
        self.assertIn("relevance_basis=audit_security_category", evidence)
        self.assertIn("AuditEvent", evidence)


if __name__ == "__main__":
    unittest.main()
