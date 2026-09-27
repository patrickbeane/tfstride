from __future__ import annotations

from typing import Any

from tfstride.providers.azure.audit_telemetry_disruption_evidence import (
    AzureAppServiceDiagnosticSettingAuditTelemetryDisruptionPath,
)
from tfstride.providers.azure.key_vault_evidence import (
    AzureAppServiceKeyVaultManagementPath,
    AzureAppServiceKeyVaultOperationPath,
)
from tfstride.providers.azure.message_removal_evidence import (
    AzureAppServiceServiceBusMessageRemovalPath,
)
from tfstride.providers.azure.messaging_topology_destruction_evidence import (
    AzureAppServiceServiceBusTopologyDestructionPath,
)
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.object_storage_deletion_evidence import (
    AzureAppServiceBlobDeletionPath,
)
from tfstride.providers.azure.object_storage_topology_destruction_evidence import (
    AzureAppServiceStorageContainerTopologyDestructionPath,
)
from tfstride.providers.azure.protected_data_evidence import (
    AzureAppServiceServiceBusAccessPath,
    AzureAppServiceServiceBusProtectedDataConvergence,
    AzureAppServiceStorageAccessPath,
    AzureAppServiceStorageProtectedDataConvergence,
)
from tfstride.providers.azure.resource_facts.base import AzureBaseFacts
from tfstride.providers.azure.secret_management_evidence import (
    AzureAppServiceKeyVaultSecretManagementPath,
)
from tfstride.providers.azure.structured_data_deletion_evidence import (
    AzureAppServiceCosmosDbItemDeletionPath,
)
from tfstride.providers.azure.structured_data_topology_destruction_evidence import (
    AzureAppServiceCosmosDbTopologyDestructionPath,
)


class AzureAppServiceFacts(AzureBaseFacts):
    __slots__ = ()

    @property
    def app_service_id(self) -> str | None:
        return self.get(AzureResourceMetadata.APP_SERVICE_ID)

    @property
    def app_service_plan_reference(self) -> str | None:
        return self.get(AzureResourceMetadata.APP_SERVICE_PLAN_REFERENCE)

    @property
    def app_service_key_vault_reference_identity_id(self) -> str | None:
        return self.get(AzureResourceMetadata.APP_SERVICE_KEY_VAULT_REFERENCE_IDENTITY_ID)

    @property
    def app_service_secret_references(self) -> list[dict[str, Any]]:
        return self.get(AzureResourceMetadata.APP_SERVICE_SECRET_REFERENCES)

    @property
    def app_service_secret_posture_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.APP_SERVICE_SECRET_POSTURE_UNCERTAINTIES)

    @property
    def app_service_key_vault_access_paths(self) -> list[dict[str, Any]]:
        return self.get(AzureResourceMetadata.APP_SERVICE_KEY_VAULT_ACCESS_PATHS)

    @property
    def app_service_key_vault_access_path_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.APP_SERVICE_KEY_VAULT_ACCESS_PATH_UNCERTAINTIES)

    def set_app_service_key_vault_access_paths(self, values: list[dict[str, Any]]) -> None:
        self.set(AzureResourceMetadata.APP_SERVICE_KEY_VAULT_ACCESS_PATHS, values)

    def extend_app_service_key_vault_access_path_uncertainties(self, values: list[str]) -> None:
        self.extend(AzureResourceMetadata.APP_SERVICE_KEY_VAULT_ACCESS_PATH_UNCERTAINTIES, values)

    @property
    def app_service_key_vault_operation_paths(self) -> list[AzureAppServiceKeyVaultOperationPath]:
        return self.get(AzureResourceMetadata.APP_SERVICE_KEY_VAULT_OPERATION_PATHS)

    @property
    def app_service_key_vault_operation_path_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.APP_SERVICE_KEY_VAULT_OPERATION_PATH_UNCERTAINTIES)

    def set_app_service_key_vault_operation_paths(
        self,
        values: list[AzureAppServiceKeyVaultOperationPath],
    ) -> None:
        self.set(AzureResourceMetadata.APP_SERVICE_KEY_VAULT_OPERATION_PATHS, values)

    def extend_app_service_key_vault_operation_path_uncertainties(self, values: list[str]) -> None:
        self.extend(AzureResourceMetadata.APP_SERVICE_KEY_VAULT_OPERATION_PATH_UNCERTAINTIES, values)

    @property
    def app_service_key_vault_management_paths(self) -> list[AzureAppServiceKeyVaultManagementPath]:
        return self.get(AzureResourceMetadata.APP_SERVICE_KEY_VAULT_MANAGEMENT_PATHS)

    @property
    def app_service_key_vault_management_path_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.APP_SERVICE_KEY_VAULT_MANAGEMENT_PATH_UNCERTAINTIES)

    def set_app_service_key_vault_management_paths(
        self,
        values: list[AzureAppServiceKeyVaultManagementPath],
    ) -> None:
        self.set(AzureResourceMetadata.APP_SERVICE_KEY_VAULT_MANAGEMENT_PATHS, values)

    def extend_app_service_key_vault_management_path_uncertainties(self, values: list[str]) -> None:
        self.extend(AzureResourceMetadata.APP_SERVICE_KEY_VAULT_MANAGEMENT_PATH_UNCERTAINTIES, values)

    @property
    def app_service_key_vault_secret_management_paths(
        self,
    ) -> list[AzureAppServiceKeyVaultSecretManagementPath]:
        return self.get(AzureResourceMetadata.APP_SERVICE_KEY_VAULT_SECRET_MANAGEMENT_PATHS)

    @property
    def app_service_key_vault_secret_management_path_uncertainties(
        self,
    ) -> list[str]:
        return self.get(AzureResourceMetadata.APP_SERVICE_KEY_VAULT_SECRET_MANAGEMENT_PATH_UNCERTAINTIES)

    def set_app_service_key_vault_secret_management_paths(
        self,
        values: list[AzureAppServiceKeyVaultSecretManagementPath],
    ) -> None:
        self.set(
            AzureResourceMetadata.APP_SERVICE_KEY_VAULT_SECRET_MANAGEMENT_PATHS,
            values,
        )

    def extend_app_service_key_vault_secret_management_path_uncertainties(
        self,
        values: list[str],
    ) -> None:
        self.extend(
            AzureResourceMetadata.APP_SERVICE_KEY_VAULT_SECRET_MANAGEMENT_PATH_UNCERTAINTIES,
            values,
        )

    @property
    def app_service_storage_access_paths(self) -> list[AzureAppServiceStorageAccessPath]:
        return self.get(AzureResourceMetadata.APP_SERVICE_STORAGE_ACCESS_PATHS)

    @property
    def app_service_storage_access_path_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.APP_SERVICE_STORAGE_ACCESS_PATH_UNCERTAINTIES)

    def set_app_service_storage_access_paths(self, values: list[AzureAppServiceStorageAccessPath]) -> None:
        self.set(AzureResourceMetadata.APP_SERVICE_STORAGE_ACCESS_PATHS, values)

    def extend_app_service_storage_access_path_uncertainties(self, values: list[str]) -> None:
        self.extend(AzureResourceMetadata.APP_SERVICE_STORAGE_ACCESS_PATH_UNCERTAINTIES, values)

    @property
    def app_service_blob_deletion_paths(
        self,
    ) -> list[AzureAppServiceBlobDeletionPath]:
        return self.get(AzureResourceMetadata.APP_SERVICE_BLOB_DELETION_PATHS)

    @property
    def app_service_blob_deletion_path_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.APP_SERVICE_BLOB_DELETION_PATH_UNCERTAINTIES)

    def set_app_service_blob_deletion_paths(
        self,
        values: list[AzureAppServiceBlobDeletionPath],
    ) -> None:
        self.set(AzureResourceMetadata.APP_SERVICE_BLOB_DELETION_PATHS, values)

    def extend_app_service_blob_deletion_path_uncertainties(
        self,
        values: list[str],
    ) -> None:
        self.extend(
            AzureResourceMetadata.APP_SERVICE_BLOB_DELETION_PATH_UNCERTAINTIES,
            values,
        )

    @property
    def app_service_storage_container_topology_destruction_paths(
        self,
    ) -> list[AzureAppServiceStorageContainerTopologyDestructionPath]:
        return self.get(AzureResourceMetadata.APP_SERVICE_STORAGE_CONTAINER_TOPOLOGY_DESTRUCTION_PATHS)

    @property
    def app_service_storage_container_topology_destruction_path_uncertainties(
        self,
    ) -> list[str]:
        return self.get(AzureResourceMetadata.APP_SERVICE_STORAGE_CONTAINER_TOPOLOGY_DESTRUCTION_PATH_UNCERTAINTIES)

    def set_app_service_storage_container_topology_destruction_paths(
        self,
        values: list[AzureAppServiceStorageContainerTopologyDestructionPath],
    ) -> None:
        self.set(
            AzureResourceMetadata.APP_SERVICE_STORAGE_CONTAINER_TOPOLOGY_DESTRUCTION_PATHS,
            values,
        )

    def extend_app_service_storage_container_topology_destruction_path_uncertainties(
        self,
        values: list[str],
    ) -> None:
        self.extend(
            AzureResourceMetadata.APP_SERVICE_STORAGE_CONTAINER_TOPOLOGY_DESTRUCTION_PATH_UNCERTAINTIES,
            values,
        )

    @property
    def app_service_storage_protected_data_convergences(
        self,
    ) -> list[AzureAppServiceStorageProtectedDataConvergence]:
        return self.get(AzureResourceMetadata.APP_SERVICE_STORAGE_PROTECTED_DATA_CONVERGENCES)

    @property
    def app_service_storage_protected_data_convergence_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.APP_SERVICE_STORAGE_PROTECTED_DATA_CONVERGENCE_UNCERTAINTIES)

    def set_app_service_storage_protected_data_convergences(
        self,
        values: list[AzureAppServiceStorageProtectedDataConvergence],
    ) -> None:
        self.set(AzureResourceMetadata.APP_SERVICE_STORAGE_PROTECTED_DATA_CONVERGENCES, values)

    def extend_app_service_storage_protected_data_convergence_uncertainties(
        self,
        values: list[str],
    ) -> None:
        self.extend(
            AzureResourceMetadata.APP_SERVICE_STORAGE_PROTECTED_DATA_CONVERGENCE_UNCERTAINTIES,
            values,
        )

    @property
    def app_service_service_bus_access_paths(self) -> list[AzureAppServiceServiceBusAccessPath]:
        return self.get(AzureResourceMetadata.APP_SERVICE_SERVICE_BUS_ACCESS_PATHS)

    @property
    def app_service_service_bus_access_path_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.APP_SERVICE_SERVICE_BUS_ACCESS_PATH_UNCERTAINTIES)

    def set_app_service_service_bus_access_paths(
        self,
        values: list[AzureAppServiceServiceBusAccessPath],
    ) -> None:
        self.set(AzureResourceMetadata.APP_SERVICE_SERVICE_BUS_ACCESS_PATHS, values)

    def extend_app_service_service_bus_access_path_uncertainties(self, values: list[str]) -> None:
        self.extend(AzureResourceMetadata.APP_SERVICE_SERVICE_BUS_ACCESS_PATH_UNCERTAINTIES, values)

    @property
    def app_service_service_bus_message_removal_paths(
        self,
    ) -> list[AzureAppServiceServiceBusMessageRemovalPath]:
        return self.get(AzureResourceMetadata.APP_SERVICE_SERVICE_BUS_MESSAGE_REMOVAL_PATHS)

    @property
    def app_service_service_bus_message_removal_path_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.APP_SERVICE_SERVICE_BUS_MESSAGE_REMOVAL_PATH_UNCERTAINTIES)

    def set_app_service_service_bus_message_removal_paths(
        self,
        values: list[AzureAppServiceServiceBusMessageRemovalPath],
    ) -> None:
        self.set(
            AzureResourceMetadata.APP_SERVICE_SERVICE_BUS_MESSAGE_REMOVAL_PATHS,
            values,
        )

    def extend_app_service_service_bus_message_removal_path_uncertainties(
        self,
        values: list[str],
    ) -> None:
        self.extend(
            AzureResourceMetadata.APP_SERVICE_SERVICE_BUS_MESSAGE_REMOVAL_PATH_UNCERTAINTIES,
            values,
        )

    @property
    def app_service_service_bus_topology_destruction_paths(
        self,
    ) -> list[AzureAppServiceServiceBusTopologyDestructionPath]:
        return self.get(AzureResourceMetadata.APP_SERVICE_SERVICE_BUS_TOPOLOGY_DESTRUCTION_PATHS)

    @property
    def app_service_service_bus_topology_destruction_path_uncertainties(
        self,
    ) -> list[str]:
        return self.get(AzureResourceMetadata.APP_SERVICE_SERVICE_BUS_TOPOLOGY_DESTRUCTION_PATH_UNCERTAINTIES)

    def set_app_service_service_bus_topology_destruction_paths(
        self,
        values: list[AzureAppServiceServiceBusTopologyDestructionPath],
    ) -> None:
        self.set(
            AzureResourceMetadata.APP_SERVICE_SERVICE_BUS_TOPOLOGY_DESTRUCTION_PATHS,
            values,
        )

    def extend_app_service_service_bus_topology_destruction_path_uncertainties(
        self,
        values: list[str],
    ) -> None:
        self.extend(
            AzureResourceMetadata.APP_SERVICE_SERVICE_BUS_TOPOLOGY_DESTRUCTION_PATH_UNCERTAINTIES,
            values,
        )

    @property
    def app_service_service_bus_protected_data_convergences(
        self,
    ) -> list[AzureAppServiceServiceBusProtectedDataConvergence]:
        return self.get(AzureResourceMetadata.APP_SERVICE_SERVICE_BUS_PROTECTED_DATA_CONVERGENCES)

    @property
    def app_service_service_bus_protected_data_convergence_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.APP_SERVICE_SERVICE_BUS_PROTECTED_DATA_CONVERGENCE_UNCERTAINTIES)

    def set_app_service_service_bus_protected_data_convergences(
        self,
        values: list[AzureAppServiceServiceBusProtectedDataConvergence],
    ) -> None:
        self.set(AzureResourceMetadata.APP_SERVICE_SERVICE_BUS_PROTECTED_DATA_CONVERGENCES, values)

    def extend_app_service_service_bus_protected_data_convergence_uncertainties(
        self,
        values: list[str],
    ) -> None:
        self.extend(
            AzureResourceMetadata.APP_SERVICE_SERVICE_BUS_PROTECTED_DATA_CONVERGENCE_UNCERTAINTIES,
            values,
        )

    @property
    def app_service_cosmosdb_access_paths(self) -> list[dict[str, Any]]:
        return self.get(AzureResourceMetadata.APP_SERVICE_COSMOSDB_ACCESS_PATHS)

    @property
    def app_service_cosmosdb_access_path_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.APP_SERVICE_COSMOSDB_ACCESS_PATH_UNCERTAINTIES)

    def set_app_service_cosmosdb_access_paths(self, values: list[dict[str, Any]]) -> None:
        self.set(AzureResourceMetadata.APP_SERVICE_COSMOSDB_ACCESS_PATHS, values)

    def extend_app_service_cosmosdb_access_path_uncertainties(self, values: list[str]) -> None:
        self.extend(AzureResourceMetadata.APP_SERVICE_COSMOSDB_ACCESS_PATH_UNCERTAINTIES, values)

    @property
    def app_service_cosmosdb_item_deletion_paths(
        self,
    ) -> list[AzureAppServiceCosmosDbItemDeletionPath]:
        return self.get(AzureResourceMetadata.APP_SERVICE_COSMOSDB_ITEM_DELETION_PATHS)

    @property
    def app_service_cosmosdb_item_deletion_path_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.APP_SERVICE_COSMOSDB_ITEM_DELETION_PATH_UNCERTAINTIES)

    def set_app_service_cosmosdb_item_deletion_paths(
        self,
        values: list[AzureAppServiceCosmosDbItemDeletionPath],
    ) -> None:
        self.set(
            AzureResourceMetadata.APP_SERVICE_COSMOSDB_ITEM_DELETION_PATHS,
            values,
        )

    def extend_app_service_cosmosdb_item_deletion_path_uncertainties(
        self,
        values: list[str],
    ) -> None:
        self.extend(
            AzureResourceMetadata.APP_SERVICE_COSMOSDB_ITEM_DELETION_PATH_UNCERTAINTIES,
            values,
        )

    @property
    def app_service_cosmosdb_topology_destruction_paths(
        self,
    ) -> list[AzureAppServiceCosmosDbTopologyDestructionPath]:
        return self.get(AzureResourceMetadata.APP_SERVICE_COSMOSDB_TOPOLOGY_DESTRUCTION_PATHS)

    @property
    def app_service_cosmosdb_topology_destruction_path_uncertainties(
        self,
    ) -> list[str]:
        return self.get(AzureResourceMetadata.APP_SERVICE_COSMOSDB_TOPOLOGY_DESTRUCTION_PATH_UNCERTAINTIES)

    def set_app_service_cosmosdb_topology_destruction_paths(
        self,
        values: list[AzureAppServiceCosmosDbTopologyDestructionPath],
    ) -> None:
        self.set(
            AzureResourceMetadata.APP_SERVICE_COSMOSDB_TOPOLOGY_DESTRUCTION_PATHS,
            values,
        )

    def extend_app_service_cosmosdb_topology_destruction_path_uncertainties(
        self,
        values: list[str],
    ) -> None:
        self.extend(
            AzureResourceMetadata.APP_SERVICE_COSMOSDB_TOPOLOGY_DESTRUCTION_PATH_UNCERTAINTIES,
            values,
        )

    @property
    def app_service_diagnostic_setting_audit_telemetry_disruption_paths(
        self,
    ) -> list[AzureAppServiceDiagnosticSettingAuditTelemetryDisruptionPath]:
        return self.get(AzureResourceMetadata.APP_SERVICE_DIAGNOSTIC_SETTING_AUDIT_TELEMETRY_DISRUPTION_PATHS)

    @property
    def app_service_diagnostic_setting_audit_telemetry_disruption_path_uncertainties(
        self,
    ) -> list[str]:
        return self.get(
            AzureResourceMetadata.APP_SERVICE_DIAGNOSTIC_SETTING_AUDIT_TELEMETRY_DISRUPTION_PATH_UNCERTAINTIES
        )

    def set_app_service_diagnostic_setting_audit_telemetry_disruption_paths(
        self,
        values: list[AzureAppServiceDiagnosticSettingAuditTelemetryDisruptionPath],
    ) -> None:
        self.set(
            AzureResourceMetadata.APP_SERVICE_DIAGNOSTIC_SETTING_AUDIT_TELEMETRY_DISRUPTION_PATHS,
            values,
        )

    def extend_app_service_diagnostic_setting_audit_telemetry_disruption_path_uncertainties(
        self,
        values: list[str],
    ) -> None:
        self.extend(
            AzureResourceMetadata.APP_SERVICE_DIAGNOSTIC_SETTING_AUDIT_TELEMETRY_DISRUPTION_PATH_UNCERTAINTIES,
            values,
        )

    @property
    def app_service_vnet_integration_subnet_id(self) -> str | None:
        return self.get(AzureResourceMetadata.APP_SERVICE_VNET_INTEGRATION_SUBNET_ID)

    @property
    def app_service_ip_restriction_default_action(self) -> str | None:
        return self.get(AzureResourceMetadata.APP_SERVICE_IP_RESTRICTION_DEFAULT_ACTION)

    @property
    def app_service_scm_ip_restriction_default_action(self) -> str | None:
        return self.get(AzureResourceMetadata.APP_SERVICE_SCM_IP_RESTRICTION_DEFAULT_ACTION)

    @property
    def app_service_scm_use_main_ip_restriction(self) -> bool | None:
        return self.optional_bool(AzureResourceMetadata.APP_SERVICE_SCM_USE_MAIN_IP_RESTRICTION)

    @property
    def app_service_access_restrictions(self) -> list[dict[str, Any]]:
        return self.get(AzureResourceMetadata.APP_SERVICE_ACCESS_RESTRICTIONS)

    @property
    def app_service_restriction_inputs(self) -> dict[str, Any]:
        return self.get(AzureResourceMetadata.APP_SERVICE_RESTRICTION_INPUTS)

    @property
    def app_service_effective_ingress(self) -> dict[str, Any]:
        return self.get(AzureResourceMetadata.APP_SERVICE_EFFECTIVE_INGRESS)

    def set_app_service_effective_ingress(self, value: dict[str, Any]) -> None:
        self.set(AzureResourceMetadata.APP_SERVICE_EFFECTIVE_INGRESS, value)

    @property
    def app_service_scm_access_restrictions(self) -> list[dict[str, Any]]:
        return self.get(AzureResourceMetadata.APP_SERVICE_SCM_ACCESS_RESTRICTIONS)

    @property
    def ftps_state(self) -> str | None:
        return self.get(AzureResourceMetadata.FTPS_STATE)

    @property
    def app_service_auth_settings(self) -> dict[str, Any]:
        return self.get(AzureResourceMetadata.APP_SERVICE_AUTH_SETTINGS)

    @property
    def app_service_auth_settings_v2(self) -> dict[str, Any]:
        return self.get(AzureResourceMetadata.APP_SERVICE_AUTH_SETTINGS_V2)

    @property
    def app_service_legacy_auth_enabled_state(self) -> str | None:
        return _auth_string(self.app_service_auth_settings, "enabled_state")

    @property
    def app_service_legacy_unauthenticated_action(self) -> str | None:
        return _auth_string(self.app_service_auth_settings, "unauthenticated_action")

    @property
    def app_service_legacy_default_provider(self) -> str | None:
        return _auth_string(self.app_service_auth_settings, "default_provider")

    @property
    def app_service_legacy_token_store_state(self) -> str | None:
        return _auth_string(self.app_service_auth_settings, "token_store_state")

    @property
    def app_service_auth_v2_enabled_state(self) -> str | None:
        return _auth_string(self.app_service_auth_settings_v2, "auth_enabled_state")

    @property
    def app_service_auth_v2_require_authentication_state(self) -> str | None:
        return _auth_string(self.app_service_auth_settings_v2, "require_authentication_state")

    @property
    def app_service_auth_v2_unauthenticated_action(self) -> str | None:
        return _auth_string(self.app_service_auth_settings_v2, "unauthenticated_action")

    @property
    def app_service_auth_v2_default_provider(self) -> str | None:
        return _auth_string(self.app_service_auth_settings_v2, "default_provider")

    @property
    def app_service_auth_v2_token_store_state(self) -> str | None:
        return _auth_string(self.app_service_auth_settings_v2, "token_store_state")

    @property
    def app_service_auth_posture_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.APP_SERVICE_AUTH_POSTURE_UNCERTAINTIES)

    @property
    def container_image_references(self) -> list[dict[str, Any]]:
        return self.get(AzureResourceMetadata.CONTAINER_IMAGE_REFERENCES)

    @property
    def container_image_posture_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.CONTAINER_IMAGE_POSTURE_UNCERTAINTIES)

    @property
    def acr_write_paths(self) -> list[dict[str, Any]]:
        return self.get(AzureResourceMetadata.ACR_WRITE_PATHS)

    @property
    def acr_write_path_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.ACR_WRITE_PATH_UNCERTAINTIES)

    def set_acr_write_paths(self, values: list[dict[str, Any]]) -> None:
        self.set(AzureResourceMetadata.ACR_WRITE_PATHS, values)

    def extend_acr_write_path_uncertainties(self, values: list[str]) -> None:
        self.extend(AzureResourceMetadata.ACR_WRITE_PATH_UNCERTAINTIES, values)

    @property
    def app_service_posture_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.APP_SERVICE_POSTURE_UNCERTAINTIES)


def _auth_string(values: dict[str, Any], key: str) -> str | None:
    value = values.get(key)
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None
