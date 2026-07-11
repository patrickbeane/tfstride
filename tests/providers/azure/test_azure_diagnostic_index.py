from __future__ import annotations

import unittest

from tfstride.models import TerraformResource
from tfstride.providers.azure.diagnostic_index import build_azure_diagnostic_setting_index
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_types import AzureResourceType

_STORAGE_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/logs"
_KEY_VAULT_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.KeyVault/vaults/app"
_SQL_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Sql/servers/app-sql"


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


def _storage_account(
    *,
    name: str = "logs",
    storage_id: str = _STORAGE_ID,
    account_name: str = "logs",
) -> TerraformResource:
    return _resource(
        AzureResourceType.STORAGE_ACCOUNT,
        name,
        {
            "id": storage_id,
            "name": account_name,
            "allow_nested_items_to_be_public": False,
            "shared_access_key_enabled": False,
            "public_network_access_enabled": False,
        },
    )


def _key_vault(*, name: str = "app", vault_id: str = _KEY_VAULT_ID) -> TerraformResource:
    return _resource(
        AzureResourceType.KEY_VAULT,
        name,
        {
            "id": vault_id,
            "name": name,
            "public_network_access_enabled": False,
            "purge_protection_enabled": True,
        },
    )


def _mssql_server(*, name: str = "app", server_id: str = _SQL_ID) -> TerraformResource:
    return _resource(
        AzureResourceType.MSSQL_SERVER,
        name,
        {
            "id": server_id,
            "name": name,
            "public_network_access_enabled": False,
            "minimum_tls_version": "1.2",
        },
    )


def _diagnostic_setting(
    name: str,
    target_resource_id: object,
    *,
    log_categories: tuple[str, ...] = ("AuditEvent",),
    log_category_groups: tuple[str, ...] = (),
    metric_categories: tuple[str, ...] = ("AllMetrics",),
    log_analytics_workspace_id: str
    | None = "/subscriptions/sub-0001/resourceGroups/obs/providers/Microsoft.OperationalInsights/workspaces/sec",
    storage_account_id: str | None = None,
    eventhub_authorization_rule_id: str | None = None,
    eventhub_name: str | None = None,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "name": name,
        "target_resource_id": target_resource_id,
        "enabled_log": [
            *({"category": category} for category in log_categories),
            *({"category_group": category_group} for category_group in log_category_groups),
        ],
        "metric": [{"category": category, "enabled": True} for category in metric_categories],
    }
    if log_analytics_workspace_id is not None:
        values["log_analytics_workspace_id"] = log_analytics_workspace_id
    if storage_account_id is not None:
        values["storage_account_id"] = storage_account_id
    if eventhub_authorization_rule_id is not None:
        values["eventhub_authorization_rule_id"] = eventhub_authorization_rule_id
    if eventhub_name is not None:
        values["eventhub_name"] = eventhub_name
    return _resource(
        AzureResourceType.MONITOR_DIAGNOSTIC_SETTING,
        name,
        values,
        unknown_values=unknown_values,
    )


def _normalized(*resources: TerraformResource):
    return AzureNormalizer().normalize(list(resources))


class AzureDiagnosticSettingIndexTests(unittest.TestCase):
    def test_resolved_diagnostic_setting_targets_storage_account_by_azure_id(self) -> None:
        inventory = _normalized(
            _storage_account(),
            _diagnostic_setting(
                "storage_audit",
                _STORAGE_ID,
                log_categories=("StorageRead", "StorageWrite"),
                log_category_groups=("audit",),
                metric_categories=("Transaction",),
                storage_account_id="/subscriptions/sub-0001/resourceGroups/obs/providers/Microsoft.Storage/storageAccounts/audit",
                eventhub_authorization_rule_id="/subscriptions/sub-0001/eventhubAuthRules/audit",
                eventhub_name="security",
            ),
        )
        storage = inventory.get_by_address("azurerm_storage_account.logs")
        assert storage is not None

        index = build_azure_diagnostic_setting_index(inventory)
        coverage = index.coverage_for(storage)

        self.assertTrue(coverage.has_diagnostic_settings)
        self.assertEqual(tuple(index.settings_by_target_key), (_STORAGE_ID.lower(),))
        self.assertEqual(coverage.diagnostic_setting_addresses, ("azurerm_monitor_diagnostic_setting.storage_audit",))
        self.assertEqual(coverage.enabled_log_categories, ("StorageRead", "StorageWrite"))
        self.assertEqual(coverage.enabled_log_category_groups, ("audit",))
        self.assertEqual(coverage.metric_categories, ("Transaction",))
        self.assertEqual(
            coverage.destinations,
            (
                "log_analytics_workspace_id=/subscriptions/sub-0001/resourceGroups/obs/providers/Microsoft.OperationalInsights/workspaces/sec",
                "storage_account_id=/subscriptions/sub-0001/resourceGroups/obs/providers/Microsoft.Storage/storageAccounts/audit",
                "eventhub_authorization_rule_id=/subscriptions/sub-0001/eventhubAuthRules/audit",
                "eventhub_name=security",
            ),
        )
        self.assertEqual(coverage.settings[0].target_resource_id, _STORAGE_ID)
        self.assertEqual(coverage.settings[0].log_records[0]["category"], "StorageRead")
        self.assertEqual(coverage.settings[0].metric_records[0]["category"], "Transaction")
        self.assertEqual(index.unresolved_targets, ())

    def test_terraform_id_reference_target_resolves_deterministically(self) -> None:
        inventory = _normalized(
            _key_vault(),
            _diagnostic_setting("vault_audit", "azurerm_key_vault.app.id"),
        )
        vault = inventory.get_by_address("azurerm_key_vault.app")
        assert vault is not None

        coverage = build_azure_diagnostic_setting_index(inventory).coverage_for(vault)

        self.assertTrue(coverage.has_diagnostic_settings)
        self.assertEqual(coverage.diagnostic_setting_addresses, ("azurerm_monitor_diagnostic_setting.vault_audit",))
        self.assertEqual(coverage.settings[0].target_resource_id, "azurerm_key_vault.app.id")

    def test_multiple_diagnostic_settings_targeting_same_resource_are_preserved(self) -> None:
        inventory = _normalized(
            _mssql_server(),
            _diagnostic_setting(
                "sql_logs",
                _SQL_ID,
                log_categories=("SQLSecurityAuditEvents",),
                metric_categories=(),
            ),
            _diagnostic_setting(
                "sql_metrics",
                _SQL_ID,
                log_categories=(),
                metric_categories=("AllMetrics",),
                log_analytics_workspace_id=None,
                storage_account_id="/subscriptions/sub-0001/resourceGroups/obs/providers/Microsoft.Storage/storageAccounts/audit",
            ),
        )
        server = inventory.get_by_address("azurerm_mssql_server.app")
        assert server is not None

        coverage = build_azure_diagnostic_setting_index(inventory).coverage_for(server)

        self.assertEqual(
            coverage.diagnostic_setting_addresses,
            ("azurerm_monitor_diagnostic_setting.sql_logs", "azurerm_monitor_diagnostic_setting.sql_metrics"),
        )
        self.assertEqual(coverage.enabled_log_categories, ("SQLSecurityAuditEvents",))
        self.assertEqual(coverage.metric_categories, ("AllMetrics",))
        self.assertEqual(
            coverage.destinations,
            (
                "log_analytics_workspace_id=/subscriptions/sub-0001/resourceGroups/obs/providers/Microsoft.OperationalInsights/workspaces/sec",
                "storage_account_id=/subscriptions/sub-0001/resourceGroups/obs/providers/Microsoft.Storage/storageAccounts/audit",
            ),
        )

    def test_unresolved_target_is_retained_without_suppressing_real_resources(self) -> None:
        inventory = _normalized(
            _storage_account(account_name="shared"),
            _diagnostic_setting("external", "${data.azurerm_storage_account.shared.id}"),
            _diagnostic_setting("name_only", "shared"),
        )
        storage = inventory.get_by_address("azurerm_storage_account.logs")
        assert storage is not None

        index = build_azure_diagnostic_setting_index(inventory)

        self.assertFalse(index.coverage_for(storage).has_diagnostic_settings)
        self.assertEqual(len(index.unresolved_targets), 2)
        self.assertEqual(
            [target.diagnostic_setting_address for target in index.unresolved_targets],
            ["azurerm_monitor_diagnostic_setting.external", "azurerm_monitor_diagnostic_setting.name_only"],
        )
        self.assertEqual(index.unresolved_targets[0].target_resource_id, "${data.azurerm_storage_account.shared.id}")
        self.assertEqual(index.unresolved_targets[1].target_resource_id, "shared")

    def test_missing_or_computed_target_is_retained_as_unresolved_evidence(self) -> None:
        inventory = _normalized(
            _storage_account(),
            _diagnostic_setting(
                "pending",
                None,
                unknown_values={"target_resource_id": True, "enabled_log": [{"category": True}]},
            ),
        )
        storage = inventory.get_by_address("azurerm_storage_account.logs")
        assert storage is not None

        index = build_azure_diagnostic_setting_index(inventory)

        self.assertFalse(index.coverage_for(storage).has_diagnostic_settings)
        self.assertEqual(len(index.unresolved_targets), 1)
        self.assertEqual(
            index.unresolved_targets[0].diagnostic_setting_address, "azurerm_monitor_diagnostic_setting.pending"
        )
        self.assertIsNone(index.unresolved_targets[0].target_resource_id)
        self.assertEqual(index.unresolved_targets[0].enabled_log_categories, ("AuditEvent",))
        self.assertEqual(
            index.unresolved_targets[0].uncertainties,
            (
                "enabled_log.category is unknown after planning",
                "target_resource_id is unknown after planning",
            ),
        )


if __name__ == "__main__":
    unittest.main()
