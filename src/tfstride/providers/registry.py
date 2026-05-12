from __future__ import annotations

from collections.abc import Iterable

from tfstride.models import ResourceInventory, TerraformResource
from tfstride.providers.base import ProviderNormalizer


class ProviderRegistryError(ValueError):
    """Raised when provider registry configuration or lookup fails."""


class ProviderNotRegisteredError(ProviderRegistryError):
    """Raised when a requested provider has no registered normalizer."""


class ProviderRegistry:
    def __init__(self, normalizers: Iterable[ProviderNormalizer] = ()) -> None:
        self._normalizers: dict[str, ProviderNormalizer] = {}
        for normalizer in normalizers:
            self.register(normalizer)

    def register(self, normalizer: ProviderNormalizer) -> None:
        provider = _normalize_provider_name(normalizer.provider)
        if not provider:
            raise ProviderRegistryError("Provider normalizers must define a non-empty provider name.")
        if provider in self._normalizers:
            raise ProviderRegistryError(f"Provider normalizer already registered for `{provider}`.")
        self._normalizers[provider] = normalizer

    def get(self, provider: str) -> ProviderNormalizer:
        provider_name = _normalize_provider_name(provider)
        try:
            return self._normalizers[provider_name]
        except KeyError as exc:
            raise ProviderNotRegisteredError(f"No provider normalizer registered for `{provider_name}`.") from exc

    def normalize(self, provider: str, resources: list[TerraformResource]) -> ResourceInventory:
        return self.get(provider).normalize(resources)

    def providers(self) -> tuple[str, ...]:
        return tuple(self._normalizers)


def _normalize_provider_name(provider: str) -> str:
    return str(provider).strip().lower()