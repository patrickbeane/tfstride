from __future__ import annotations

import unittest

from tests.providers.azure.test_azure_app_service_diagnostic_setting_audit_telemetry_disruption_paths import (
    _built_in_assignment,  # pyright: ignore[reportPrivateUsage]
    _normalize,  # pyright: ignore[reportPrivateUsage]
    _valid_resources,  # pyright: ignore[reportPrivateUsage]
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import _resource
from tests.providers.test_public_workload_audit_telemetry_disruption_boundaries import (
    _azure_diagnostic_setting,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_PROVIDERS = "/subscriptions/sub-0001/resourceGroups/ops/providers/"
_SUBSCRIPTION_SCOPE = "/subscriptions/sub-0001"
_DIAGNOSTIC_ADDRESS = "azurerm_monitor_diagnostic_setting.audit"

_KEY_VAULT = (AzureResourceType.KEY_VAULT, "Microsoft.KeyVault/vaults/target")
_AKS = (AzureResourceType.KUBERNETES_CLUSTER, "Microsoft.ContainerService/managedClusters/target")
_FUNCTION_APP = (AzureResourceType.LINUX_FUNCTION_APP, "Microsoft.Web/sites/target")
_WEB_APP = (AzureResourceType.LINUX_WEB_APP, "Microsoft.Web/sites/target")
_STORAGE = (AzureResourceType.STORAGE_ACCOUNT, "Microsoft.Storage/storageAccounts/target")
_SQL_SERVER = (AzureResourceType.MSSQL_SERVER, "Microsoft.Sql/servers/target")
_POSTGRESQL = (AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER, "Microsoft.DBforPostgreSQL/flexibleServers/target")
_COSMOSDB = (AzureResourceType.COSMOSDB_ACCOUNT, "Microsoft.DocumentDB/databaseAccounts/target")


def _analyze(monitored: tuple[str, str], enabled_log: list[dict[str, object]]):
    resource_type, suffix = monitored
    resource_id = f"{_PROVIDERS}{suffix}"
    target = _resource(resource_type, {"id": resource_id, "name": "target"}, name="target")
    diagnostic = _azure_diagnostic_setting(target_id=resource_id, enabled_log=enabled_log)
    diagnostic.values["id"] = f"{resource_id}|audit"
    inventory, _context = _normalize(
        [
            *_valid_resources(
                diagnostic=diagnostic,
                assignment=_built_in_assignment(scope=_SUBSCRIPTION_SCOPE),
            ),
            target,
        ]
    )
    workload = inventory.get_by_address("azurerm_linux_web_app.orders")
    assert workload is not None
    facts = azure_facts(workload)
    return (
        facts.app_service_diagnostic_setting_audit_telemetry_disruption_paths,
        facts.app_service_diagnostic_setting_audit_telemetry_disruption_path_uncertainties,
    )


def _relevance_uncertainties(uncertainties: list[str]) -> list[str]:
    return [value for value in uncertainties if "audit relevance" in value]


class AzureDiagnosticRelevanceCatalogTests(unittest.TestCase):
    def test_documented_categories_and_all_logs_establish_relevance(self) -> None:
        cases = (
            ("key vault AuditEvent", _KEY_VAULT, {"category": "AuditEvent"}, "audit_security_category"),
            ("aks kube-audit", _AKS, {"category": "kube-audit"}, "audit_security_category"),
            ("aks kube-audit-admin", _AKS, {"category": "kube-audit-admin"}, "audit_security_category"),
            ("web app file audit", _WEB_APP, {"category": "AppServiceFileAuditLogs"}, "audit_security_category"),
            ("key vault allLogs", _KEY_VAULT, {"category_group": "allLogs"}, "audit_security_category_group"),
            ("aks allLogs", _AKS, {"category_group": "allLogs"}, "audit_security_category_group"),
            ("function app audit group", _FUNCTION_APP, {"category_group": "audit"}, "audit_security_category_group"),
            ("unmodeled audit group", _COSMOSDB, {"category_group": "audit"}, "audit_security_category_group"),
        )
        for case, monitored, log, basis in cases:
            with self.subTest(case=case):
                paths, uncertainties = _analyze(monitored, [log])
                self.assertEqual(len(paths), 1)
                self.assertEqual(paths[0]["audit_telemetry_relevance_evidence"]["relevance_basis"], basis)
                self.assertEqual(_relevance_uncertainties(uncertainties), [])

    def test_unresolved_cases_record_an_uncertainty_and_no_path(self) -> None:
        cases = (
            ("function app allLogs", _FUNCTION_APP, {"category_group": "allLogs"}),
            ("function app audit category", _FUNCTION_APP, {"category": "AppServiceAuditLogs"}),
            ("storage allLogs", _STORAGE, {"category_group": "allLogs"}),
            ("sql server audit category", _SQL_SERVER, {"category": "SQLSecurityAuditEvents"}),
            ("misplaced category", _WEB_APP, {"category": "AuditEvent"}),
            ("unmodeled category", _COSMOSDB, {"category": "DataPlaneRequests"}),
            ("unmodeled allLogs", _COSMOSDB, {"category_group": "allLogs"}),
            ("unknown group", _KEY_VAULT, {"category_group": "someFutureGroup"}),
        )
        for case, monitored, log in cases:
            with self.subTest(case=case):
                paths, uncertainties = _analyze(monitored, [log])
                self.assertEqual(paths, [])
                relevance = _relevance_uncertainties(uncertainties)
                self.assertEqual(len(relevance), 1)
                self.assertIn(_DIAGNOSTIC_ADDRESS, relevance[0])
                self.assertIn("documented category catalog", relevance[0])

    def test_documented_non_audit_settings_are_not_uncertain(self) -> None:
        cases = (
            ("postgresql allLogs has no audit category", _POSTGRESQL, {"category_group": "allLogs"}),
            ("web app http logs", _WEB_APP, {"category": "AppServiceHTTPLogs"}),
            ("key vault policy evaluation", _KEY_VAULT, {"category": "AzurePolicyEvaluationDetails"}),
            ("function app logs", _FUNCTION_APP, {"category": "FunctionAppLogs"}),
        )
        for case, monitored, log in cases:
            with self.subTest(case=case):
                paths, uncertainties = _analyze(monitored, [log])
                self.assertEqual(paths, [])
                self.assertEqual(_relevance_uncertainties(uncertainties), [])

    def test_an_established_signal_wins_over_unresolved_entries(self) -> None:
        paths, uncertainties = _analyze(
            _KEY_VAULT,
            [{"category": "SomeFutureCategory"}, {"category": "AuditEvent"}],
        )
        self.assertEqual(len(paths), 1)
        self.assertEqual(_relevance_uncertainties(uncertainties), [])

    def test_unresolved_entries_are_reported_individually(self) -> None:
        paths, uncertainties = _analyze(
            _KEY_VAULT,
            [{"category": "SomeFutureCategory"}, {"category": "AnotherFutureCategory"}],
        )
        self.assertEqual(paths, [])
        relevance = _relevance_uncertainties(uncertainties)
        self.assertEqual(len(relevance), 2)
        self.assertTrue(any("SomeFutureCategory" in value for value in relevance))
        self.assertTrue(any("AnotherFutureCategory" in value for value in relevance))


if __name__ == "__main__":
    unittest.main()
