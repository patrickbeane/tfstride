from __future__ import annotations

from collections.abc import Iterable, Mapping
from enum import Enum
from types import MappingProxyType

from tfstride.models import NormalizedResource
from tfstride.providers.names import normalize_provider_name


class ResourceCapability(str, Enum):
    WORKLOAD = "workload"
    SECURITY_GROUP_BACKED_WORKLOAD = "security_group_backed_workload"
    PUBLIC_COMPUTE = "public_compute"
    DATA_STORE = "data_store"
    PUBLIC_EDGE = "public_edge"
    IDENTITY_ROLE = "identity_role"
    IAM_POLICY = "iam_policy"
    NETWORK_SECURITY_GROUP = "network_security_group"
    SUBNET = "subnet"
    DATABASE = "database"
    OBJECT_STORAGE = "object_storage"
    SECRET_STORE = "secret_store"
    CONTROL_PLANE_SENSITIVE_DATA_STORE = "control_plane_sensitive_data_store"
    OBJECT_STORAGE_PUBLIC_ACCESS_CONTROL = "object_storage_public_access_control"
    KEY_MANAGEMENT = "key_management"
    SENSITIVE_RESOURCE_POLICY = "sensitive_resource_policy"
    SERVICE_RESOURCE_POLICY = "service_resource_policy"
    PROVIDER_MANAGED_EGRESS_WITHOUT_VPC = "provider_managed_egress_without_vpc"


ResourceCapabilityMap = Mapping[ResourceCapability, frozenset[str]]


class ProviderResourceCapabilityRegistryError(ValueError):
    """Raised when provider resource capability registration fails."""


class ProviderResourceCapabilityRegistry:
    def __init__(
        self,
        provider_capabilities: Iterable[tuple[str, ResourceCapabilityMap]] = (),
    ) -> None:
        self._capabilities: dict[str, Mapping[ResourceCapability, frozenset[str]]] = {}
        for provider, capabilities in provider_capabilities:
            self.register(provider, capabilities)

    def register(self, provider: str, capabilities: ResourceCapabilityMap) -> None:
        provider_name = normalize_provider_name(provider)
        if not provider_name:
            raise ProviderResourceCapabilityRegistryError(
                "Provider capabilities must define a non-empty provider name."
            )
        if provider_name in self._capabilities:
            raise ProviderResourceCapabilityRegistryError(
                f"Provider capabilities already registered for `{provider_name}`."
            )

        self._capabilities[provider_name] = MappingProxyType(_normalize_capability_map(provider_name, capabilities))

    def providers(self) -> tuple[str, ...]:
        return tuple(self._capabilities)

    def resource_types(self, capability: ResourceCapability | str) -> frozenset[str]:
        normalized_capability = _normalize_capability(capability)
        return frozenset(
            resource_type
            for provider_capabilities in self._capabilities.values()
            for resource_type in provider_capabilities.get(normalized_capability, frozenset())
        )

    def resource_types_for_provider(
        self,
        provider: str,
        capability: ResourceCapability | str,
    ) -> frozenset[str]:
        provider_name = normalize_provider_name(provider)
        normalized_capability = _normalize_capability(capability)
        provider_capabilities = self._capabilities.get(provider_name, {})
        return provider_capabilities.get(normalized_capability, frozenset())

    def has_capability(
        self,
        resource: NormalizedResource,
        capability: ResourceCapability | str,
    ) -> bool:
        return resource.resource_type in self.resource_types_for_provider(resource.provider, capability)


def _normalize_capability_map(
    provider_name: str,
    capabilities: ResourceCapabilityMap,
) -> dict[ResourceCapability, frozenset[str]]:
    if not isinstance(capabilities, Mapping):
        raise ProviderResourceCapabilityRegistryError(f"Provider capabilities for `{provider_name}` must be a mapping.")

    normalized: dict[ResourceCapability, frozenset[str]] = {}
    for capability, resource_types in capabilities.items():
        normalized_capability = _normalize_capability(capability)
        if isinstance(resource_types, str):
            raise ProviderResourceCapabilityRegistryError(
                f"Provider capabilities for `{provider_name}` must contain resource type collections."
            )
        normalized_types = frozenset(str(item).strip() for item in resource_types)
        if "" in normalized_types:
            raise ProviderResourceCapabilityRegistryError(
                f"Provider capabilities for `{provider_name}` contain an empty resource type."
            )
        normalized[normalized_capability] = normalized_types
    return normalized


def _normalize_capability(capability: ResourceCapability | str) -> ResourceCapability:
    try:
        return capability if isinstance(capability, ResourceCapability) else ResourceCapability(str(capability))
    except ValueError as exc:
        raise ProviderResourceCapabilityRegistryError(f"Unknown resource capability `{capability}`.") from exc
