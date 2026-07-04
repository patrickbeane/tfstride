from __future__ import annotations

import unittest

from tfstride.models import ResourceCategory, TerraformResource
from tfstride.providers.azure.audit_normalizers import (
    normalize_advanced_threat_protection,
    normalize_monitor_diagnostic_setting,
    normalize_security_center_auto_provisioning,
    normalize_security_center_contact,
    normalize_security_center_setting,
    normalize_security_center_subscription_pricing,
    normalize_security_center_workspace,
)
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.resource_metadata import InventoryMetadata


def _resource(
    resource_type: str,
    values: dict[str, object],
    *,
    name: str = "example",
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


class AzureAuditNormalizerTests(unittest.TestCase):
    def test_monitor_diagnostic_setting_preserves_destinations_logs_and_metrics(self) -> None:
        normalized = normalize_monitor_diagnostic_setting(
            _resource(
                AzureResourceType.MONITOR_DIAGNOSTIC_SETTING,
                {
                    "id": "/subscriptions/example/providers/Microsoft.Insights/diagnosticSettings/audit",
                    "name": "audit",
                    "target_resource_id": "/subscriptions/example/resourceGroups/app/providers/Microsoft.KeyVault/vaults/app",
                    "log_analytics_workspace_id": "/subscriptions/example/resourceGroups/obs/providers/Microsoft.OperationalInsights/workspaces/sec",
                    "storage_account_id": "/subscriptions/example/resourceGroups/obs/providers/Microsoft.Storage/storageAccounts/logs",
                    "eventhub_authorization_rule_id": "/subscriptions/example/eventhubAuthRules/audit",
                    "eventhub_name": "security",
                    "enabled_log": [{"category": "AuditEvent"}, {"category_group": "allLogs"}],
                    "log": [{"category": "Administrative", "enabled": False}],
                    "metric": [{"category": "AllMetrics", "enabled": True}],
                },
                name="audit",
            )
        )
        facts = azure_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(
            normalized.identifier,
            "/subscriptions/example/providers/Microsoft.Insights/diagnosticSettings/audit",
        )
        self.assertEqual(facts.diagnostic_setting_id, normalized.identifier)
        self.assertEqual(facts.diagnostic_setting_name, "audit")
        self.assertEqual(
            facts.diagnostic_target_resource_id,
            "/subscriptions/example/resourceGroups/app/providers/Microsoft.KeyVault/vaults/app",
        )
        self.assertEqual(
            facts.diagnostic_log_analytics_workspace_id,
            "/subscriptions/example/resourceGroups/obs/providers/Microsoft.OperationalInsights/workspaces/sec",
        )
        self.assertEqual(
            facts.diagnostic_storage_account_id,
            "/subscriptions/example/resourceGroups/obs/providers/Microsoft.Storage/storageAccounts/logs",
        )
        self.assertEqual(
            facts.diagnostic_eventhub_authorization_rule_id, "/subscriptions/example/eventhubAuthRules/audit"
        )
        self.assertEqual(facts.diagnostic_eventhub_name, "security")
        self.assertEqual(facts.diagnostic_enabled_log_categories, ["AuditEvent"])
        self.assertEqual(facts.diagnostic_enabled_log_category_groups, ["allLogs"])
        self.assertEqual(facts.diagnostic_metric_categories, ["AllMetrics"])
        self.assertEqual(
            facts.diagnostic_log_records,
            [
                {"category": "AuditEvent"},
                {"category_group": "allLogs"},
                {"category": "Administrative", "enabled": False},
            ],
        )
        self.assertEqual(facts.diagnostic_metric_records, [{"category": "AllMetrics", "enabled": True}])
        self.assertEqual(facts.azure_security_posture_uncertainties, [])

    def test_security_center_subscription_pricing_preserves_defender_plan(self) -> None:
        normalized = normalize_security_center_subscription_pricing(
            _resource(
                AzureResourceType.SECURITY_CENTER_SUBSCRIPTION_PRICING,
                {
                    "resource_type": "VirtualMachines",
                    "tier": "Standard",
                    "subplan": "P2",
                    "extension": [
                        {
                            "name": "MdeDesignatedSubscription",
                            "additional_extension_properties": {"workspace": "central"},
                        }
                    ],
                },
                name="vm",
            )
        )
        facts = azure_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(facts.defender_resource_type, "VirtualMachines")
        self.assertEqual(facts.defender_pricing_tier, "Standard")
        self.assertEqual(facts.defender_subplan, "P2")
        self.assertEqual(facts.defender_extension_names, ["MdeDesignatedSubscription"])
        self.assertEqual(
            facts.defender_extensions,
            [
                {
                    "name": "MdeDesignatedSubscription",
                    "additional_extension_properties": {"workspace": "central"},
                }
            ],
        )
        self.assertEqual(facts.azure_security_posture_uncertainties, [])

    def test_security_center_support_resources_preserve_posture_states(self) -> None:
        auto = azure_facts(
            normalize_security_center_auto_provisioning(
                _resource(
                    AzureResourceType.SECURITY_CENTER_AUTO_PROVISIONING,
                    {"auto_provision": "On"},
                )
            )
        )
        contact = azure_facts(
            normalize_security_center_contact(
                _resource(
                    AzureResourceType.SECURITY_CENTER_CONTACT,
                    {
                        "email": "secops@example.com",
                        "phone": "+15555550100",
                        "alert_notifications": "On",
                        "alerts_to_admins": "Off",
                    },
                )
            )
        )
        workspace = azure_facts(
            normalize_security_center_workspace(
                _resource(
                    AzureResourceType.SECURITY_CENTER_WORKSPACE,
                    {
                        "scope": "/subscriptions/example",
                        "workspace_id": "/subscriptions/example/resourceGroups/obs/providers/Microsoft.OperationalInsights/workspaces/sec",
                    },
                )
            )
        )
        setting = azure_facts(
            normalize_security_center_setting(
                _resource(
                    AzureResourceType.SECURITY_CENTER_SETTING,
                    {"setting_name": "MCAS", "enabled": False},
                )
            )
        )
        threat_protection = azure_facts(
            normalize_advanced_threat_protection(
                _resource(
                    AzureResourceType.ADVANCED_THREAT_PROTECTION,
                    {
                        "target_resource_id": "/subscriptions/example/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/logs",
                        "enabled": True,
                    },
                )
            )
        )

        self.assertEqual(auto.security_center_auto_provisioning_state, "enabled")
        self.assertEqual(contact.security_center_contact_email, "secops@example.com")
        self.assertEqual(contact.security_center_contact_phone, "+15555550100")
        self.assertEqual(contact.security_center_alert_notifications_state, "enabled")
        self.assertEqual(contact.security_center_alerts_to_admins_state, "disabled")
        self.assertEqual(workspace.security_center_workspace_scope, "/subscriptions/example")
        self.assertEqual(
            workspace.security_center_workspace_id,
            "/subscriptions/example/resourceGroups/obs/providers/Microsoft.OperationalInsights/workspaces/sec",
        )
        self.assertEqual(setting.security_center_setting_name, "MCAS")
        self.assertEqual(setting.security_center_setting_state, "disabled")
        self.assertEqual(
            threat_protection.advanced_threat_protection_target_resource_id,
            "/subscriptions/example/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/logs",
        )
        self.assertEqual(threat_protection.advanced_threat_protection_state, "enabled")

    def test_unknown_diagnostic_and_security_fields_are_preserved(self) -> None:
        diagnostic = azure_facts(
            normalize_monitor_diagnostic_setting(
                _resource(
                    AzureResourceType.MONITOR_DIAGNOSTIC_SETTING,
                    {
                        "name": "audit",
                        "target_resource_id": None,
                        "enabled_log": [{"category": None}],
                        "metric": None,
                    },
                    unknown_values={
                        "target_resource_id": True,
                        "enabled_log": [{"category": True}],
                        "metric": True,
                    },
                )
            )
        )
        auto = azure_facts(
            normalize_security_center_auto_provisioning(
                _resource(
                    AzureResourceType.SECURITY_CENTER_AUTO_PROVISIONING,
                    {"auto_provision": None},
                    unknown_values={"auto_provision": True},
                )
            )
        )
        setting = azure_facts(
            normalize_security_center_setting(
                _resource(
                    AzureResourceType.SECURITY_CENTER_SETTING,
                    {"setting_name": "MCAS", "enabled": None},
                    unknown_values={"enabled": True},
                )
            )
        )

        self.assertEqual(diagnostic.diagnostic_target_resource_id, None)
        self.assertEqual(diagnostic.diagnostic_enabled_log_categories, [])
        self.assertEqual(diagnostic.diagnostic_metric_records, [])
        self.assertEqual(
            diagnostic.azure_security_posture_uncertainties,
            [
                "enabled_log.category is unknown after planning",
                "metric is unknown after planning",
                "target_resource_id is unknown after planning",
            ],
        )
        self.assertEqual(auto.security_center_auto_provisioning_state, "unknown")
        self.assertEqual(auto.azure_security_posture_uncertainties, ["auto_provision is unknown after planning"])
        self.assertEqual(setting.security_center_setting_state, "unknown")
        self.assertEqual(setting.azure_security_posture_uncertainties, ["enabled is unknown after planning"])

    def test_audit_security_resource_types_are_supported_without_findings(self) -> None:
        resources = [
            _resource(AzureResourceType.MONITOR_DIAGNOSTIC_SETTING, {"name": "diag"}),
            _resource(AzureResourceType.SECURITY_CENTER_SUBSCRIPTION_PRICING, {"resource_type": "StorageAccounts"}),
            _resource(AzureResourceType.SECURITY_CENTER_AUTO_PROVISIONING, {"auto_provision": "Off"}),
            _resource(AzureResourceType.SECURITY_CENTER_CONTACT, {"email": "secops@example.com"}),
            _resource(AzureResourceType.SECURITY_CENTER_WORKSPACE, {"scope": "/subscriptions/example"}),
            _resource(AzureResourceType.SECURITY_CENTER_SETTING, {"setting_name": "WDATP", "enabled": True}),
            _resource(AzureResourceType.ADVANCED_THREAT_PROTECTION, {"enabled": True}),
        ]

        inventory = AzureNormalizer().normalize(resources)

        self.assertEqual(inventory.unsupported_resources, [])
        self.assertEqual(InventoryMetadata.NORMALIZED_RESOURCE_COUNT.get(inventory.metadata), len(resources))
        self.assertEqual(
            [resource.resource_type for resource in inventory.resources],
            [resource.resource_type for resource in resources],
        )


if __name__ == "__main__":
    unittest.main()
