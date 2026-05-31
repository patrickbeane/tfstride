from __future__ import annotations

from abc import ABC, abstractmethod

from tfstride.models import ResourceInventory, TerraformResource


class ProviderNormalizer(ABC):
    provider: str

    def owns_resource(self, resource: TerraformResource) -> bool:
        """Return whether this provider owns the Terraform resource."""
        return False

    @abstractmethod
    def normalize(self, resources: list[TerraformResource]) -> ResourceInventory:
        raise NotImplementedError