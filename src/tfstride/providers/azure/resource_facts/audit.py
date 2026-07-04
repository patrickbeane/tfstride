from __future__ import annotations

from typing import Any

from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_facts.base import AzureBaseFacts


class AzureAuditFacts(AzureBaseFacts):
    @property
    def diagnostic_setting_id(self) -> str | None:
        return self.get(AzureResourceMetadata.DIAGNOSTIC_SETTING_ID)

    @property
    def diagnostic_setting_name(self) -> str | None:
        return self.get(AzureResourceMetadata.DIAGNOSTIC_SETTING_NAME)

    @property
    def diagnostic_target_resource_id(self) -> str | None:
        return self.get(AzureResourceMetadata.DIAGNOSTIC_TARGET_RESOURCE_ID)

    @property
    def diagnostic_log_analytics_workspace_id(self) -> str | None:
        return self.get(AzureResourceMetadata.DIAGNOSTIC_LOG_ANALYTICS_WORKSPACE_ID)

    @property
    def diagnostic_storage_account_id(self) -> str | None:
        return self.get(AzureResourceMetadata.DIAGNOSTIC_STORAGE_ACCOUNT_ID)

    @property
    def diagnostic_eventhub_authorization_rule_id(self) -> str | None:
        return self.get(AzureResourceMetadata.DIAGNOSTIC_EVENTHUB_AUTHORIZATION_RULE_ID)

    @property
    def diagnostic_eventhub_name(self) -> str | None:
        return self.get(AzureResourceMetadata.DIAGNOSTIC_EVENTHUB_NAME)

    @property
    def diagnostic_marketplace_partner_resource_id(self) -> str | None:
        return self.get(AzureResourceMetadata.DIAGNOSTIC_MARKETPLACE_PARTNER_RESOURCE_ID)

    @property
    def diagnostic_enabled_log_categories(self) -> list[str]:
        return self.get(AzureResourceMetadata.DIAGNOSTIC_ENABLED_LOG_CATEGORIES)

    @property
    def diagnostic_enabled_log_category_groups(self) -> list[str]:
        return self.get(AzureResourceMetadata.DIAGNOSTIC_ENABLED_LOG_CATEGORY_GROUPS)

    @property
    def diagnostic_metric_categories(self) -> list[str]:
        return self.get(AzureResourceMetadata.DIAGNOSTIC_METRIC_CATEGORIES)

    @property
    def diagnostic_log_records(self) -> list[dict[str, Any]]:
        return self.get(AzureResourceMetadata.DIAGNOSTIC_LOG_RECORDS)

    @property
    def diagnostic_metric_records(self) -> list[dict[str, Any]]:
        return self.get(AzureResourceMetadata.DIAGNOSTIC_METRIC_RECORDS)

    @property
    def defender_resource_type(self) -> str | None:
        return self.get(AzureResourceMetadata.DEFENDER_RESOURCE_TYPE)

    @property
    def defender_pricing_tier(self) -> str | None:
        return self.get(AzureResourceMetadata.DEFENDER_PRICING_TIER)

    @property
    def defender_subplan(self) -> str | None:
        return self.get(AzureResourceMetadata.DEFENDER_SUBPLAN)

    @property
    def defender_extension_names(self) -> list[str]:
        return self.get(AzureResourceMetadata.DEFENDER_EXTENSION_NAMES)

    @property
    def defender_extensions(self) -> list[dict[str, Any]]:
        return self.get(AzureResourceMetadata.DEFENDER_EXTENSIONS)

    @property
    def security_center_auto_provisioning_state(self) -> str | None:
        return self.get(AzureResourceMetadata.SECURITY_CENTER_AUTO_PROVISIONING_STATE)

    @property
    def security_center_contact_email(self) -> str | None:
        return self.get(AzureResourceMetadata.SECURITY_CENTER_CONTACT_EMAIL)

    @property
    def security_center_contact_phone(self) -> str | None:
        return self.get(AzureResourceMetadata.SECURITY_CENTER_CONTACT_PHONE)

    @property
    def security_center_alert_notifications_state(self) -> str | None:
        return self.get(AzureResourceMetadata.SECURITY_CENTER_ALERT_NOTIFICATIONS_STATE)

    @property
    def security_center_alerts_to_admins_state(self) -> str | None:
        return self.get(AzureResourceMetadata.SECURITY_CENTER_ALERTS_TO_ADMINS_STATE)

    @property
    def security_center_workspace_scope(self) -> str | None:
        return self.get(AzureResourceMetadata.SECURITY_CENTER_WORKSPACE_SCOPE)

    @property
    def security_center_workspace_id(self) -> str | None:
        return self.get(AzureResourceMetadata.SECURITY_CENTER_WORKSPACE_ID)

    @property
    def security_center_setting_name(self) -> str | None:
        return self.get(AzureResourceMetadata.SECURITY_CENTER_SETTING_NAME)

    @property
    def security_center_setting_state(self) -> str | None:
        return self.get(AzureResourceMetadata.SECURITY_CENTER_SETTING_STATE)

    @property
    def advanced_threat_protection_target_resource_id(self) -> str | None:
        return self.get(AzureResourceMetadata.ADVANCED_THREAT_PROTECTION_TARGET_RESOURCE_ID)

    @property
    def advanced_threat_protection_state(self) -> str | None:
        return self.get(AzureResourceMetadata.ADVANCED_THREAT_PROTECTION_STATE)

    @property
    def azure_security_posture_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.AZURE_SECURITY_POSTURE_UNCERTAINTIES)
