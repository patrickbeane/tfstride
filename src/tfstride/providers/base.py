from __future__ import annotations

from abc import ABC, abstractmethod

from tfstride.models import ResourceInventory, TerraformResource


class ProviderNormalizer(ABC):
    provider: str

    @abstractmethod
    def normalize(self, resources: list[TerraformResource]) -> ResourceInventory:
        raise NotImplementedError
