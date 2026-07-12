from __future__ import annotations

from tfstride.providers.gcp.metadata import GcpResourceMetadata


class GcpComputeFacts:
    __slots__ = ()

    @property
    def os_login_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.OS_LOGIN_ENABLED)

    @property
    def network_tags(self) -> list[str]:
        return self.get(GcpResourceMetadata.NETWORK_TAGS)

    @property
    def internet_ingress_firewalls(self) -> list[str]:
        return self.get(GcpResourceMetadata.INTERNET_INGRESS_FIREWALLS)

    @property
    def fronted_by_internet_facing_load_balancer(self) -> bool:
        return self.get(GcpResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER)

    @property
    def internet_facing_load_balancer_addresses(self) -> list[str]:
        return self.get(GcpResourceMetadata.INTERNET_FACING_LOAD_BALANCER_ADDRESSES)
