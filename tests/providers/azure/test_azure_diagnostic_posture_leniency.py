"""Pin that the diagnostic-setting posture rule stays lenient on purpose.

The posture rule (`azure-diagnostic-setting-audit-logs-incomplete`) claims a
setting "does not clearly enable audit logs". A wrong claim is noise on a
compliant configuration, so it only flags settings whose enabled categories and
groups show no audit or security signal at all. Cases the documented category
catalog cannot resolve stay quiet here, even though the disruption path, which
needs proof, treats them as not established.
"""

from __future__ import annotations

import unittest

from tests.providers.azure.test_azure_diagnostic_audit_relevance_parity import (
    _Case,  # pyright: ignore[reportPrivateUsage]
    _category,  # pyright: ignore[reportPrivateUsage]
    _group,  # pyright: ignore[reportPrivateUsage]
    _posture_accepts,  # pyright: ignore[reportPrivateUsage]
)
from tfstride.providers.azure.diagnostic_log_catalog import (
    cataloged_resource_types,
    category_audit_relevance,
    diagnostic_log_catalog_entry,
)
from tfstride.providers.azure.resource_types import AzureResourceType

_RESOURCE_NAMES = {
    AzureResourceType.LINUX_WEB_APP: "linux web app",
    AzureResourceType.WINDOWS_WEB_APP: "windows web app",
    AzureResourceType.LINUX_FUNCTION_APP: "linux function app",
    AzureResourceType.KEY_VAULT: "key vault",
    AzureResourceType.STORAGE_ACCOUNT: "storage account",
    AzureResourceType.MSSQL_SERVER: "sql server",
    AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER: "postgresql server",
    AzureResourceType.KUBERNETES_CLUSTER: "aks cluster",
}


def _accepts(resource: str, log: dict[str, object]) -> bool:
    return _posture_accepts(_Case(resource, log, posture_accepts=True, disruption_established=True))


class AzureDiagnosticPostureLeniencyTests(unittest.TestCase):
    def test_unresolved_catalog_cases_stay_quiet(self) -> None:
        cases = (
            # allLogs where the documented category list cannot show whether audit is present.
            ("linux function app", _group("allLogs")),
            ("storage account", _group("allLogs")),
            ("sql server", _group("allLogs")),
            # allLogs where the list has no audit category but the service may still emit audit
            # records inside another category, such as pgaudit output in PostgreSQLLogs.
            ("postgresql server", _group("allLogs")),
            # A documented audit category name used on a type that does not document it. The
            # catalog is a snapshot of Microsoft's reference and Azure adds categories over time.
            ("linux function app", _category("AppServiceAuditLogs")),
            ("linux web app", _category("AuditEvent")),
            ("key vault", _category("AppServiceAuditLogs")),
            ("sql server", _category("SQLSecurityAuditEvents")),
        )
        for resource, log in cases:
            with self.subTest(resource=resource, log=log):
                self.assertTrue(_accepts(resource, log))

    def test_settings_with_no_audit_signal_are_still_flagged(self) -> None:
        cases = (
            ("linux web app", _category("AppServiceHTTPLogs")),
            ("linux function app", _category("FunctionAppLogs")),
            ("key vault", _category("AzurePolicyEvaluationDetails")),
            ("aks cluster", _category("kube-apiserver")),
            ("postgresql server", _category("PostgreSQLLogs")),
            ("storage account", _category("StorageRead")),
        )
        for resource, log in cases:
            with self.subTest(resource=resource, log=log):
                self.assertFalse(_accepts(resource, log))

    def test_every_documented_audit_category_is_accepted(self) -> None:
        for resource_type in sorted(cataloged_resource_types()):
            entry = diagnostic_log_catalog_entry(resource_type)
            assert entry is not None
            for category in sorted(entry.audit_categories):
                with self.subTest(resource_type=resource_type, category=category):
                    self.assertEqual(category_audit_relevance(resource_type, category), "audit")
                    self.assertTrue(_accepts(_RESOURCE_NAMES[resource_type], _category(category)))
