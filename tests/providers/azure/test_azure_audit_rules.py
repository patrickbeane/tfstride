from __future__ import annotations

import unittest

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS

_AUDIT_RULE_IDS = (
    "azure-diagnostic-settings-missing",
    "azure-diagnostic-setting-no-log-destination",
    "azure-defender-pricing-tier-not-standard",
    "azure-security-center-auto-provisioning-disabled",
)
_STORAGE_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/logs"
_KEY_VAULT_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.KeyVault/vaults/app"
_SQL_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Sql/servers/app-sql"
_POSTGRESQL_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.DBforPostgreSQL/flexibleServers/app-pg"
_AKS_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.ContainerService/managedClusters/app"
_APP_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Web/sites/app"


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


def _storage_account() -> TerraformResource:
    return _resource(
        AzureResourceType.STORAGE_ACCOUNT,
        "logs",
        {
            "id": _STORAGE_ID,
            "name": "logs",
            "public_network_access_enabled": False,
            "allow_nested_items_to_be_public": False,
            "shared_access_key_enabled": False,
        },
    )


def _key_vault() -> TerraformResource:
    return _resource(
        AzureResourceType.KEY_VAULT,
        "app",
        {
            "id": _KEY_VAULT_ID,
            "name": "app",
            "public_network_access_enabled": False,
            "purge_protection_enabled": True,
        },
    )


def _mssql_server() -> TerraformResource:
    return _resource(
        AzureResourceType.MSSQL_SERVER,
        "app",
        {"id": _SQL_ID, "name": "app", "public_network_access_enabled": False, "minimum_tls_version": "1.2"},
    )


def _postgresql_server() -> TerraformResource:
    return _resource(
        AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER,
        "app",
        {
            "id": _POSTGRESQL_ID,
            "name": "app",
            "public_network_access_enabled": False,
            "ssl_minimal_tls_version_enforced": "TLS1_2",
            "geo_redundant_backup_enabled": True,
        },
    )


def _aks_cluster() -> TerraformResource:
    return _resource(
        AzureResourceType.KUBERNETES_CLUSTER,
        "app",
        {
            "id": _AKS_ID,
            "name": "app",
            "private_cluster_enabled": True,
            "local_account_disabled": True,
            "role_based_access_control_enabled": True,
            "network_profile": [{"network_policy": "azure"}],
        },
    )


def _web_app() -> TerraformResource:
    return _resource(
        AzureResourceType.LINUX_WEB_APP,
        "app",
        {
            "id": _APP_ID,
            "name": "app",
            "public_network_access_enabled": False,
            "site_config": [{"minimum_tls_version": "1.2"}],
        },
    )


def _diagnostic_setting(
    name: str,
    target_resource_id: object,
    *,
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
        "enabled_log": [{"category": "AuditEvent"}],
        "metric": [{"category": "AllMetrics", "enabled": True}],
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


def _defender_pricing(
    *, tier: object = "Standard", unknown_values: dict[str, object] | None = None
) -> TerraformResource:
    return _resource(
        AzureResourceType.SECURITY_CENTER_SUBSCRIPTION_PRICING,
        "storage",
        {"resource_type": "StorageAccounts", "tier": tier, "subplan": "DefenderForStorageV2"},
        unknown_values=unknown_values,
    )


def _auto_provisioning(
    auto_provision: object = "On", *, unknown_values: dict[str, object] | None = None
) -> TerraformResource:
    return _resource(
        AzureResourceType.SECURITY_CENTER_AUTO_PROVISIONING,
        "default",
        {"auto_provision": auto_provision},
        unknown_values=unknown_values,
    )


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = AzureNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AzureAuditRuleTests(unittest.TestCase):
    def test_audit_rule_ids_are_registered(self) -> None:
        registered = {rule_id for group in AZURE_RULE_GROUP_IDS for rule_id in group}
        self.assertLessEqual(set(_AUDIT_RULE_IDS), registered)

    def test_supported_sensitive_resources_without_diagnostic_settings_are_detected(self) -> None:
        findings = _evaluate(
            [_storage_account(), _key_vault(), _mssql_server(), _postgresql_server(), _aks_cluster(), _web_app()],
            "azure-diagnostic-settings-missing",
        )

        self.assertEqual(len(findings), 6)
        self.assertEqual({finding.rule_id for finding in findings}, {"azure-diagnostic-settings-missing"})
        self.assertEqual(
            {finding.affected_resources[0] for finding in findings},
            {
                "azurerm_storage_account.logs",
                "azurerm_key_vault.app",
                "azurerm_mssql_server.app",
                "azurerm_postgresql_flexible_server.app",
                "azurerm_kubernetes_cluster.app",
                "azurerm_linux_web_app.app",
            },
        )
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["diagnostic_coverage"],
            ["no resolved azurerm_monitor_diagnostic_setting targets this resource"],
        )

    def test_resolved_diagnostic_settings_suppress_missing_findings(self) -> None:
        findings = _evaluate(
            [
                _storage_account(),
                _key_vault(),
                _diagnostic_setting("storage_audit", _STORAGE_ID),
                _diagnostic_setting("vault_audit", "azurerm_key_vault.app.id"),
            ],
            "azure-diagnostic-settings-missing",
        )

        self.assertEqual(findings, [])

    def test_diagnostic_setting_without_log_destination_is_detected(self) -> None:
        findings = _evaluate(
            [_diagnostic_setting("audit", _STORAGE_ID, log_analytics_workspace_id=None, eventhub_name="security")],
            "azure-diagnostic-setting-no-log-destination",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-diagnostic-setting-no-log-destination"])
        evidence = _evidence_by_key(findings[0])
        self.assertIn("target_resource_id=" + _STORAGE_ID, evidence["diagnostic_setting"])
        self.assertEqual(evidence["diagnostic_categories"], ["log_category=AuditEvent", "metric_category=AllMetrics"])
        self.assertIn(
            "eventhub_name without eventhub_authorization_rule_id is not treated as a log destination",
            evidence["destination_posture"],
        )

    def test_diagnostic_setting_with_destination_or_unknown_destination_is_quiet(self) -> None:
        findings = _evaluate(
            [
                _diagnostic_setting("workspace", _STORAGE_ID),
                _diagnostic_setting(
                    "pending",
                    _KEY_VAULT_ID,
                    log_analytics_workspace_id=None,
                    unknown_values={"log_analytics_workspace_id": True},
                ),
            ],
            "azure-diagnostic-setting-no-log-destination",
        )

        self.assertEqual(findings, [])

    def test_defender_pricing_tier_and_auto_provisioning_posture_are_detected(self) -> None:
        findings = _evaluate(
            [_defender_pricing(tier="Free"), _auto_provisioning("Off")],
            "azure-defender-pricing-tier-not-standard",
            "azure-security-center-auto-provisioning-disabled",
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["azure-defender-pricing-tier-not-standard", "azure-security-center-auto-provisioning-disabled"],
        )
        defender_evidence = _evidence_by_key(findings[0])
        auto_evidence = _evidence_by_key(findings[1])
        self.assertIn("pricing_tier=Free", defender_evidence["defender_plan"])
        self.assertIn("resource_type=StorageAccounts", defender_evidence["defender_plan"])
        self.assertIn("auto_provisioning_state=disabled", auto_evidence["auto_provisioning_posture"])

    def test_standard_defender_enabled_auto_provisioning_and_unknown_values_are_quiet(self) -> None:
        findings = _evaluate(
            [
                _defender_pricing(tier="Standard"),
                _auto_provisioning("On"),
                _defender_pricing(tier=None, unknown_values={"tier": True}),
                _auto_provisioning("", unknown_values={"auto_provision": True}),
            ],
            "azure-defender-pricing-tier-not-standard",
            "azure-security-center-auto-provisioning-disabled",
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
