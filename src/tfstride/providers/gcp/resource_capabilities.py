from __future__ import annotations

from types import MappingProxyType

from tfstride.providers.resource_capabilities import ResourceCapability


GCP_RESOURCE_CAPABILITIES: MappingProxyType[ResourceCapability, frozenset[str]] = MappingProxyType({})