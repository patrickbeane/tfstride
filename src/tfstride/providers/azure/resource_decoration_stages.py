from __future__ import annotations

from typing import Protocol

from tfstride.models import NormalizedResource
from tfstride.providers.azure.resource_decoration.compute import ResolveVirtualMachineRelationshipsStage
from tfstride.providers.azure.resource_decoration.network_posture import (
    ResolveNetworkInterfaceRelationshipsStage,
    ResolveSubnetVirtualNetworkStage,
)
from tfstride.providers.azure.resource_decoration.network_security import (
    MergeNetworkSecurityRulesStage,
    ResolveNetworkSecurityAssociationsStage,
)
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
        DecorateStorageRelationshipsStage(),
    )
