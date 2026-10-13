from __future__ import annotations

import unittest

from tfstride.providers.azure.audit_rules import _DIAGNOSTIC_TARGET_TYPES  # pyright: ignore[reportPrivateUsage]
from tfstride.providers.azure.diagnostic_log_catalog import (
    cataloged_resource_types,
    category_audit_relevance,
    category_group_audit_relevance,
    diagnostic_log_catalog_entry,
)
from tfstride.providers.azure.resource_types import AzureResourceType


class AzureDiagnosticLogCatalogTests(unittest.TestCase):
    def test_every_diagnostic_target_type_has_an_entry(self) -> None:
        self.assertEqual(cataloged_resource_types(), frozenset(_DIAGNOSTIC_TARGET_TYPES))

    def test_entries_are_sourced_and_internally_consistent(self) -> None:
        for resource_type in sorted(cataloged_resource_types()):
            with self.subTest(resource_type=resource_type):
                entry = diagnostic_log_catalog_entry(resource_type)
                assert entry is not None
                self.assertTrue(entry.source.startswith("https://learn.microsoft.com/"))
                self.assertTrue(entry.arm_type.startswith("Microsoft."))
                self.assertEqual(entry.audit_categories & entry.other_categories, frozenset())
                if entry.all_logs_state == "carries_audit":
                    self.assertTrue(entry.audit_categories)
                if entry.all_logs_state == "no_audit":
                    self.assertFalse(entry.audit_categories)

    def test_documented_audit_categories_are_recognized_per_type(self) -> None:
        cases = (
            (AzureResourceType.LINUX_WEB_APP, "AppServiceAuditLogs"),
            (AzureResourceType.WINDOWS_WEB_APP, "AppServiceFileAuditLogs"),
            (AzureResourceType.KEY_VAULT, "AuditEvent"),
            (AzureResourceType.KUBERNETES_CLUSTER, "kube-audit"),
            (AzureResourceType.KUBERNETES_CLUSTER, "kube-audit-admin"),
        )
        for resource_type, category in cases:
            with self.subTest(resource_type=resource_type, category=category):
                self.assertEqual(category_audit_relevance(resource_type, category), "audit")

    def test_category_matching_ignores_case_and_padding(self) -> None:
        self.assertEqual(category_audit_relevance(AzureResourceType.KEY_VAULT, " auditevent "), "audit")
        self.assertEqual(category_audit_relevance(AzureResourceType.KUBERNETES_CLUSTER, "KUBE-AUDIT"), "audit")

    def test_documented_non_audit_categories_are_not_audit(self) -> None:
        cases = (
            (AzureResourceType.LINUX_WEB_APP, "AppServiceHTTPLogs"),
            (AzureResourceType.LINUX_WEB_APP, "AppServiceIPSecAuditLogs"),
            (AzureResourceType.KEY_VAULT, "AzurePolicyEvaluationDetails"),
            (AzureResourceType.KUBERNETES_CLUSTER, "kube-apiserver"),
            (AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER, "PostgreSQLLogs"),
            (AzureResourceType.LINUX_FUNCTION_APP, "FunctionAppLogs"),
        )
        for resource_type, category in cases:
            with self.subTest(resource_type=resource_type, category=category):
                self.assertEqual(category_audit_relevance(resource_type, category), "not_audit")

    def test_undocumented_or_misplaced_categories_are_unresolved(self) -> None:
        cases = (
            (AzureResourceType.LINUX_WEB_APP, "AuditEvent"),
            (AzureResourceType.KEY_VAULT, "AppServiceAuditLogs"),
            (AzureResourceType.MSSQL_SERVER, "SQLSecurityAuditEvents"),
            (AzureResourceType.STORAGE_ACCOUNT, "StorageRead"),
            (AzureResourceType.LINUX_FUNCTION_APP, "AppServiceAuditLogs"),
            (AzureResourceType.MSSQL_DATABASE, "SQLSecurityAuditEvents"),
            ("azurerm_unmodeled_thing", "AuditEvent"),
        )
        for resource_type, category in cases:
            with self.subTest(resource_type=resource_type, category=category):
                self.assertEqual(category_audit_relevance(resource_type, category), "unresolved")

    def test_audit_group_is_audit_for_any_resource_type(self) -> None:
        for resource_type in (*sorted(cataloged_resource_types()), "azurerm_unmodeled_thing"):
            with self.subTest(resource_type=resource_type):
                self.assertEqual(category_group_audit_relevance(resource_type, "audit"), "audit")
        self.assertEqual(category_group_audit_relevance(AzureResourceType.KEY_VAULT, " Audit "), "audit")

    def test_all_logs_group_follows_the_documented_category_list(self) -> None:
        expectations = {
            AzureResourceType.LINUX_WEB_APP: "audit",
            AzureResourceType.WINDOWS_WEB_APP: "audit",
            AzureResourceType.KEY_VAULT: "audit",
            AzureResourceType.KUBERNETES_CLUSTER: "audit",
            AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER: "not_audit",
            AzureResourceType.LINUX_FUNCTION_APP: "unresolved",
            AzureResourceType.FUNCTION_APP: "unresolved",
            AzureResourceType.WINDOWS_FUNCTION_APP: "unresolved",
            AzureResourceType.STORAGE_ACCOUNT: "unresolved",
            AzureResourceType.MSSQL_SERVER: "unresolved",
            "azurerm_unmodeled_thing": "unresolved",
        }
        for resource_type, expected in expectations.items():
            with self.subTest(resource_type=resource_type):
                self.assertEqual(category_group_audit_relevance(resource_type, "allLogs"), expected)
                self.assertEqual(category_group_audit_relevance(resource_type, "ALL_LOGS"), expected)

    def test_unknown_groups_are_unresolved(self) -> None:
        self.assertEqual(category_group_audit_relevance(AzureResourceType.KEY_VAULT, "someFutureGroup"), "unresolved")


if __name__ == "__main__":
    unittest.main()
