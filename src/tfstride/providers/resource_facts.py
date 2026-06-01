from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Protocol

from tfstride.models import NormalizedResource


class ProviderResourceFacts(Protocol):
    """Provider-owned facts exposed to shared analysis."""

    @property
    def bucket_name(self) -> str | None:
        raise NotImplementedError

    @property
    def bucket_acl(self) -> str:
        raise NotImplementedError

    @property
    def public_access_block(self) -> dict[str, bool] | None:
        raise NotImplementedError

    @property
    def policy_document(self) -> dict[str, Any]:
        raise NotImplementedError

    @property
    def trust_statements(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    @property
    def engine(self) -> str | None:
        raise NotImplementedError

    @property
    def resource_policy_source_addresses(self) -> list[str]:
        raise NotImplementedError

    @property
    def service_account_email(self) -> str | None:
        raise NotImplementedError

    @property
    def service_account_member(self) -> str | None:
        raise NotImplementedError

    @property
    def service_account_reference(self) -> str | None:
        raise NotImplementedError

    @property
    def network_tags(self) -> list[str]:
        raise NotImplementedError

    @property
    def internet_ingress_firewalls(self) -> list[str]:
        raise NotImplementedError

    @property
    def iam_role(self) -> str | None:
        raise NotImplementedError

    @property
    def iam_member(self) -> str | None:
        raise NotImplementedError


ProviderResourceFactsFactory = Callable[[NormalizedResource], ProviderResourceFacts]


class ProviderResourceFactsRegistryError(ValueError):
    """Raised when provider facts registry configuration or lookup fails."""


class ProviderResourceFactsNotRegisteredError(ProviderResourceFactsRegistryError):
    """Raised when a requested provider has no registered facts factory."""


@dataclass(frozen=True, slots=True)
class NeutralProviderResourceFacts:
    """Neutral facts for providers without a shared-analysis facts adapter yet."""

    resource: NormalizedResource

    @property
    def bucket_name(self) -> str | None:
        return None

    @property
    def bucket_acl(self) -> str:
        return ""

    @property
    def public_access_block(self) -> dict[str, bool] | None:
        return None

    @property
    def policy_document(self) -> dict[str, Any]:
        return {}

    @property
    def trust_statements(self) -> list[dict[str, Any]]:
        return []

    @property
    def engine(self) -> str | None:
        return None

    @property
    def resource_policy_source_addresses(self) -> list[str]:
        return []

    @property
    def service_account_email(self) -> str | None:
        return None

    @property
    def service_account_member(self) -> str | None:
        return None

    @property
    def service_account_reference(self) -> str | None:
        return None

    @property
    def network_tags(self) -> list[str]:
        return []

    @property
    def internet_ingress_firewalls(self) -> list[str]:
        return []

    @property
    def iam_role(self) -> str | None:
        return None

    @property
    def iam_member(self) -> str | None:
        return None


class ProviderResourceFactsRegistry:
    def __init__(
        self,
        factories: Iterable[tuple[str, ProviderResourceFactsFactory]] = (),
    ) -> None:
        self._factories: dict[str, ProviderResourceFactsFactory] = {}
        for provider, factory in factories:
            self.register(provider, factory)

    def register(self, provider: str, factory: ProviderResourceFactsFactory) -> None:
        provider_name = _normalize_provider_name(provider)
        if not provider_name:
            raise ProviderResourceFactsRegistryError(
                "Provider facts factories must define a non-empty provider name."
            )
        if provider_name in self._factories:
            raise ProviderResourceFactsRegistryError(
                f"Provider facts factory already registered for `{provider_name}`."
            )
        if not callable(factory):
            raise ProviderResourceFactsRegistryError(
                f"Provider facts factory for `{provider_name}` must be callable."
            )
        self._factories[provider_name] = factory

    def get(self, provider: str) -> ProviderResourceFactsFactory:
        provider_name = _normalize_provider_name(provider)
        try:
            return self._factories[provider_name]
        except KeyError as exc:
            raise ProviderResourceFactsNotRegisteredError(
                f"No provider facts factory registered for `{provider_name}`."
            ) from exc

    def facts_for(self, resource: NormalizedResource) -> ProviderResourceFacts:
        provider_name = _normalize_provider_name(resource.provider)
        factory = self._factories.get(provider_name)
        if factory is None:
            return NeutralProviderResourceFacts(resource)
        return factory(resource)

    def providers(self) -> tuple[str, ...]:
        return tuple(self._factories)


def _normalize_provider_name(provider: str) -> str:
    return str(provider).strip().lower()