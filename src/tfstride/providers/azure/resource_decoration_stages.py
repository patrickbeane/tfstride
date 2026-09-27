from __future__ import annotations

from typing import Protocol

from tfstride.models import NormalizedResource
from tfstride.providers.azure.resource_decoration.app_service_blob_deletion_paths import (
    ModelAppServiceBlobDeletionPathsStage,
)
from tfstride.providers.azure.resource_decoration.app_service_cosmosdb_access_paths import (
    ModelAppServiceCosmosDbAccessPathsStage,
)
from tfstride.providers.azure.resource_decoration.app_service_cosmosdb_item_deletion_paths import (
    ModelAppServiceCosmosDbItemDeletionPathsStage,
)
from tfstride.providers.azure.resource_decoration.app_service_cosmosdb_topology_destruction_paths import (
    ModelAppServiceCosmosDbTopologyDestructionPathsStage,
)
from tfstride.providers.azure.resource_decoration.app_service_diagnostic_setting_audit_telemetry_disruption_paths import (
    ModelAppServiceDiagnosticSettingAuditTelemetryDisruptionPathsStage,
)
from tfstride.providers.azure.resource_decoration.app_service_ingress import EvaluateAppServiceIngressStage
from tfstride.providers.azure.resource_decoration.app_service_key_vault_access_paths import (
    ModelAppServiceKeyVaultAccessPathsStage,
)
from tfstride.providers.azure.resource_decoration.app_service_key_vault_management_paths import (
    ModelAppServiceKeyVaultManagementPathsStage,
)
from tfstride.providers.azure.resource_decoration.app_service_key_vault_operation_paths import (
    ModelAppServiceKeyVaultOperationPathsStage,
)
from tfstride.providers.azure.resource_decoration.app_service_key_vault_protected_data_convergence import (
    ModelAppServiceKeyVaultProtectedDataConvergenceStage,
)
from tfstride.providers.azure.resource_decoration.app_service_key_vault_secret_management_paths import (
    ModelAppServiceKeyVaultSecretManagementPathsStage,
)
from tfstride.providers.azure.resource_decoration.app_service_service_bus_access_paths import (
    ModelAppServiceServiceBusAccessPathsStage,
)
from tfstride.providers.azure.resource_decoration.app_service_service_bus_message_removal_paths import (
    ModelAppServiceServiceBusMessageRemovalPathsStage,
)
from tfstride.providers.azure.resource_decoration.app_service_service_bus_topology_destruction_paths import (
    ModelAppServiceServiceBusTopologyDestructionPathsStage,
)
from tfstride.providers.azure.resource_decoration.app_service_storage_access_paths import (
    ModelAppServiceStorageAccessPathsStage,
)
from tfstride.providers.azure.resource_decoration.app_service_storage_container_topology_destruction_paths import (
    ModelAppServiceStorageContainerTopologyDestructionPathsStage,
)
from tfstride.providers.azure.resource_decoration.compute import ResolveVirtualMachineRelationshipsStage
from tfstride.providers.azure.resource_decoration.container_registry_write_paths import (
    ModelAppServiceAcrWritePathsStage,
)
from tfstride.providers.azure.resource_decoration.cosmosdb_nosql import (
    DecorateCosmosDbNoSqlRelationshipsStage,
)
from tfstride.providers.azure.resource_decoration.federated_identity import (
    ModelFederatedManagedIdentityTrustPathsStage,
)
from tfstride.providers.azure.resource_decoration.identity import DecorateManagedIdentityRoleAssignmentsStage
from tfstride.providers.azure.resource_decoration.key_vault import DecorateKeyVaultRelationshipsStage
from tfstride.providers.azure.resource_decoration.key_vault_encryption_dependencies import (
    ResolveAzureKeyVaultEncryptionDependenciesStage,
)
from tfstride.providers.azure.resource_decoration.key_vault_key_authorization import (
    NormalizeKeyVaultKeyAuthorizationPostureStage,
)
from tfstride.providers.azure.resource_decoration.key_vault_secret_authorization import (
    NormalizeKeyVaultSecretAuthorizationPostureStage,
)
from tfstride.providers.azure.resource_decoration.network_posture import (
    ResolveNetworkInterfaceRelationshipsStage,
    ResolveSubnetVirtualNetworkStage,
)
from tfstride.providers.azure.resource_decoration.network_security import (
    MergeNetworkSecurityRulesStage,
    ResolveNetworkSecurityAssociationsStage,
)
from tfstride.providers.azure.resource_decoration.network_symbolic_relationships import (
    ResolveAzureNetworkSymbolicRelationshipsStage,
)
from tfstride.providers.azure.resource_decoration.public_exposure import DerivePublicComputeExposureStage
from tfstride.providers.azure.resource_decoration.service_bus import DecorateServiceBusRelationshipsStage
from tfstride.providers.azure.resource_decoration.storage import DecorateStorageRelationshipsStage
from tfstride.providers.azure.resource_decoration.symbolic_relationships import (
    ResolveAzureSymbolicRelationshipsStage,
)
from tfstride.providers.azure.resource_index import AzureDecorationContext


class AzureDecorationStage(Protocol):
    name: str

    def apply(self, resources: list[NormalizedResource], context: AzureDecorationContext) -> None:
        """Apply one ordered Azure resource decoration step."""
        ...


def default_azure_decoration_stages() -> tuple[AzureDecorationStage, ...]:
    return (
        ResolveAzureSymbolicRelationshipsStage(),
        ResolveAzureNetworkSymbolicRelationshipsStage(),
        MergeNetworkSecurityRulesStage(),
        ResolveSubnetVirtualNetworkStage(),
        ResolveNetworkSecurityAssociationsStage(),
        ResolveNetworkInterfaceRelationshipsStage(),
        ResolveVirtualMachineRelationshipsStage(),
        DerivePublicComputeExposureStage(),
        EvaluateAppServiceIngressStage(),
        DecorateStorageRelationshipsStage(),
        DecorateServiceBusRelationshipsStage(),
        DecorateCosmosDbNoSqlRelationshipsStage(),
        DecorateKeyVaultRelationshipsStage(),
        ResolveAzureKeyVaultEncryptionDependenciesStage(),
        DecorateManagedIdentityRoleAssignmentsStage(),
        NormalizeKeyVaultKeyAuthorizationPostureStage(),
        NormalizeKeyVaultSecretAuthorizationPostureStage(),
        ModelAppServiceKeyVaultOperationPathsStage(),
        ModelAppServiceKeyVaultManagementPathsStage(),
        ModelAppServiceKeyVaultSecretManagementPathsStage(),
        ModelAppServiceCosmosDbAccessPathsStage(),
        ModelAppServiceCosmosDbItemDeletionPathsStage(),
        ModelAppServiceCosmosDbTopologyDestructionPathsStage(),
        ModelAppServiceDiagnosticSettingAuditTelemetryDisruptionPathsStage(),
        ModelAppServiceKeyVaultAccessPathsStage(),
        ModelAppServiceStorageAccessPathsStage(),
        ModelAppServiceBlobDeletionPathsStage(),
        ModelAppServiceStorageContainerTopologyDestructionPathsStage(),
        ModelAppServiceServiceBusAccessPathsStage(),
        ModelAppServiceServiceBusMessageRemovalPathsStage(),
        ModelAppServiceServiceBusTopologyDestructionPathsStage(),
        ModelAppServiceKeyVaultProtectedDataConvergenceStage(),
        ModelFederatedManagedIdentityTrustPathsStage(),
        ModelAppServiceAcrWritePathsStage(),
    )
