from __future__ import annotations

from dataclasses import dataclass

from tfstride.models import NormalizedResource


@dataclass(frozen=True, slots=True)
class FirewallIngressSource:
    resource: NormalizedResource
    internet_ingress_reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FirewallIngressDecision:
    sources: tuple[FirewallIngressSource, ...]

    @property
    def has_internet_ingress(self) -> bool:
        return any(source.internet_ingress_reasons for source in self.sources)

    @property
    def internet_ingress_reasons(self) -> tuple[str, ...]:
        return tuple(reason for source in self.sources for reason in source.internet_ingress_reasons)

    @property
    def firewall_addresses(self) -> tuple[str, ...]:
        return tuple(source.resource.address for source in self.sources)
