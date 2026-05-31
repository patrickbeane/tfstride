from __future__ import annotations

from collections.abc import Iterable

from tfstride.models import ResourceInventory, TerraformResource
from tfstride.providers.base import ProviderNormalizer


class ProviderRegistryError(ValueError):
    """Raised when provider registry configuration or lookup fails."""


class ProviderNotRegisteredError(ProviderRegistryError):
    """Raised when a requested provider has no registered normalizer."""


class ProviderSelectionError(ProviderRegistryError):
    """Raised when a Terraform plan cannot be mapped to one provider."""


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

    def detect_provider(
        self,
        resources: list[TerraformResource],
        *,
        default_provider: str | None = None,
    ) -> str:
        counts = self.provider_resource_counts(resources)
        matched_providers = tuple(provider for provider, count in counts.items() if count > 0)
        if len(matched_providers) == 1:
            return matched_providers[0]
        if len(matched_providers) > 1:
            providers = ", ".join(matched_providers)
            raise ProviderSelectionError(
                "Terraform plan contains resources for multiple registered providers: "
                f"{providers}. Pass an explicit provider to analyze one provider at a time."
            )
        if default_provider is not None:
            normalized_default = _normalize_provider_name(default_provider)
            if not normalized_default:
                raise ProviderRegistryError("Default provider must be a non-empty provider name.")
            return normalized_default
        raise ProviderSelectionError("No registered provider matched Terraform plan resources.")

    def provider_resource_counts(self, resources: list[TerraformResource]) -> dict[str, int]:
        return {
            provider: sum(1 for resource in resources if normalizer.owns_resource(resource))
            for provider, normalizer in self._normalizers.items()
        }

    def normalize(self, provider: str, resources: list[TerraformResource]) -> ResourceInventory:
        return self.get(provider).normalize(resources)

    def normalize_detected(
        self,
        resources: list[TerraformResource],
        *,
        default_provider: str | None = None,
    ) -> ResourceInventory:
        provider = self.detect_provider(resources, default_provider=default_provider)
        return self.normalize(provider, resources)

    def providers(self) -> tuple[str, ...]:
        return tuple(self._normalizers)


def _normalize_provider_name(provider: str) -> str:
    return str(provider).strip().lower()