from __future__ import annotations

from tfstride.analysis.boundaries.types import BoundaryContributionContext
from tfstride.models import BoundaryType
from tfstride.providers.azure.resource_types import AZURE_COMPUTE_RESOURCE_TYPES


class AzureBoundaryContributor:
    def contribute(self, context: BoundaryContributionContext) -> None:
        if context.inventory.provider != "azure":
            return
        for virtual_machine in context.inventory.by_type(*AZURE_COMPUTE_RESOURCE_TYPES):
            if not virtual_machine.direct_internet_reachable:
                continue
            context.add_boundary(
                BoundaryType.INTERNET_TO_SERVICE,
                "internet",
                virtual_machine.address,
                f"Traffic can cross from the public internet to {virtual_machine.display_name}.",
                "The virtual machine has a public-IP path and the effective subnet/NIC NSG decisions allow internet ingress.",
            )
