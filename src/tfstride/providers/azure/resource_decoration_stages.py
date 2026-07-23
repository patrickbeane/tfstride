from __future__ import annotations

from typing import Protocol

from tfstride.models import NormalizedResource
from tfstride.providers.azure.resource_decoration.app_service_key_vault_access_paths import (
    ModelAppServiceKeyVaultAccessPathsStage,
)
from tfstride.providers.azure.resource_decoration.app_service_service_bus_access_paths import (
    ModelAppServiceServiceBusAccessPathsStage,
)
from tfstride.providers.azure.resource_decoration.app_service_storage_access_paths import (
    ModelAppServiceStorageAccessPathsStage,
)
from tfstride.providers.azure.resource_decoration.compute import ResolveVirtualMachineRelationshipsStage
from tfstride.providers.azure.resource_decoration.container_registry_write_paths import (
    ModelAppServiceAcrWritePathsStage,
)
from tfstride.providers.azure.resource_decoration.federated_identity import (
    ModelFederatedManagedIdentityTrustPathsStage,
)
from tfstride.providers.azure.resource_decoration.identity import DecorateManagedIdentityRoleAssignmentsStage
from tfstride.providers.azure.resource_decoration.key_vault import DecorateKeyVaultRelationshipsStage
from tfstride.providers.azure.resource_decoration.network_posture import (
    ResolveNetworkInterfaceRelationshipsStage,
    ResolveSubnetVirtualNetworkStage,
)
from tfstride.providers.azure.resource_decoration.network_security import (
    MergeNetworkSecurityRulesStage,
    ResolveNetworkSecurityAssociationsStage,
)
from tfstride.providers.azure.resource_decoration.public_exposure import DerivePublicComputeExposureStage
from tfstride.providers.azure.resource_decoration.service_bus import DecorateServiceBusRelationshipsStage
from tfstride.providers.azure.resource_decoration.storage import DecorateStorageRelationshipsStage
from tfstride.providers.azure.resource_index import AzureDecorationContext


class AzureDecorationStage(Protocol):
    name: str

    def apply(self, resources: list[NormalizedResource], context: AzureDecorationContext) -> None:
        """Apply one ordered Azure resource decoration step."""
        ...


def default_azure_decoration_stages() -> tuple[AzureDecorationStage, ...]:
    return (
        MergeNetworkSecurityRulesStage(),
        ResolveSubnetVirtualNetworkStage(),
        ResolveNetworkSecurityAssociationsStage(),
        ResolveNetworkInterfaceRelationshipsStage(),
        ResolveVirtualMachineRelationshipsStage(),
        DerivePublicComputeExposureStage(),
        DecorateStorageRelationshipsStage(),
        DecorateServiceBusRelationshipsStage(),
        DecorateKeyVaultRelationshipsStage(),
        DecorateManagedIdentityRoleAssignmentsStage(),
        ModelAppServiceKeyVaultAccessPathsStage(),
        ModelAppServiceStorageAccessPathsStage(),
        ModelAppServiceServiceBusAccessPathsStage(),
        ModelFederatedManagedIdentityTrustPathsStage(),
        ModelAppServiceAcrWritePathsStage(),
    )
