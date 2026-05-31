from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.catalog import default_resource_capability_registry
from tfstride.providers.resource_capabilities import ResourceCapability


_DEFAULT_RESOURCE_CAPABILITY_REGISTRY = default_resource_capability_registry()

WORKLOAD_RESOURCE_TYPES = _DEFAULT_RESOURCE_CAPABILITY_REGISTRY.resource_types(
    ResourceCapability.WORKLOAD
)
SECURITY_GROUP_BACKED_WORKLOAD_RESOURCE_TYPES = _DEFAULT_RESOURCE_CAPABILITY_REGISTRY.resource_types(
    ResourceCapability.SECURITY_GROUP_BACKED_WORKLOAD
)
PUBLIC_COMPUTE_RESOURCE_TYPES = _DEFAULT_RESOURCE_CAPABILITY_REGISTRY.resource_types(
    ResourceCapability.PUBLIC_COMPUTE
)
DATA_STORE_RESOURCE_TYPES = _DEFAULT_RESOURCE_CAPABILITY_REGISTRY.resource_types(
    ResourceCapability.DATA_STORE
)
PUBLIC_EDGE_RESOURCE_TYPES = _DEFAULT_RESOURCE_CAPABILITY_REGISTRY.resource_types(
    ResourceCapability.PUBLIC_EDGE
)
IDENTITY_ROLE_RESOURCE_TYPES = _DEFAULT_RESOURCE_CAPABILITY_REGISTRY.resource_types(
    ResourceCapability.IDENTITY_ROLE
)
IAM_POLICY_RESOURCE_TYPES = _DEFAULT_RESOURCE_CAPABILITY_REGISTRY.resource_types(
    ResourceCapability.IAM_POLICY
)
NETWORK_SECURITY_GROUP_RESOURCE_TYPES = _DEFAULT_RESOURCE_CAPABILITY_REGISTRY.resource_types(
    ResourceCapability.NETWORK_SECURITY_GROUP
)
SUBNET_RESOURCE_TYPES = _DEFAULT_RESOURCE_CAPABILITY_REGISTRY.resource_types(
    ResourceCapability.SUBNET
)
DATABASE_RESOURCE_TYPES = _DEFAULT_RESOURCE_CAPABILITY_REGISTRY.resource_types(
    ResourceCapability.DATABASE
)
OBJECT_STORAGE_RESOURCE_TYPES = _DEFAULT_RESOURCE_CAPABILITY_REGISTRY.resource_types(
    ResourceCapability.OBJECT_STORAGE
)
SECRET_STORE_RESOURCE_TYPES = _DEFAULT_RESOURCE_CAPABILITY_REGISTRY.resource_types(
    ResourceCapability.SECRET_STORE
)
CONTROL_PLANE_SENSITIVE_DATA_STORE_TYPES = _DEFAULT_RESOURCE_CAPABILITY_REGISTRY.resource_types(
    ResourceCapability.CONTROL_PLANE_SENSITIVE_DATA_STORE
)
OBJECT_STORAGE_PUBLIC_ACCESS_CONTROL_RESOURCE_TYPES = (
    _DEFAULT_RESOURCE_CAPABILITY_REGISTRY.resource_types(
        ResourceCapability.OBJECT_STORAGE_PUBLIC_ACCESS_CONTROL
    )
)
KEY_MANAGEMENT_RESOURCE_TYPES = _DEFAULT_RESOURCE_CAPABILITY_REGISTRY.resource_types(
    ResourceCapability.KEY_MANAGEMENT
)
SENSITIVE_RESOURCE_POLICY_RESOURCE_TYPES = _DEFAULT_RESOURCE_CAPABILITY_REGISTRY.resource_types(
    ResourceCapability.SENSITIVE_RESOURCE_POLICY
)
SERVICE_RESOURCE_POLICY_RESOURCE_TYPES = _DEFAULT_RESOURCE_CAPABILITY_REGISTRY.resource_types(
    ResourceCapability.SERVICE_RESOURCE_POLICY
)
PROVIDER_MANAGED_EGRESS_WITHOUT_VPC_RESOURCE_TYPES = (
    _DEFAULT_RESOURCE_CAPABILITY_REGISTRY.resource_types(
        ResourceCapability.PROVIDER_MANAGED_EGRESS_WITHOUT_VPC
    )
)


def is_workload_resource(resource: NormalizedResource) -> bool:
    return _has_capability(resource, ResourceCapability.WORKLOAD)


def is_security_group_backed_workload_resource(resource: NormalizedResource) -> bool:
    return _has_capability(resource, ResourceCapability.SECURITY_GROUP_BACKED_WORKLOAD)


def is_public_compute_resource(resource: NormalizedResource) -> bool:
    return _has_capability(resource, ResourceCapability.PUBLIC_COMPUTE)


def is_data_store_resource(resource: NormalizedResource) -> bool:
    return _has_capability(resource, ResourceCapability.DATA_STORE)


def is_public_edge_resource(resource: NormalizedResource) -> bool:
    return _has_capability(resource, ResourceCapability.PUBLIC_EDGE)


def is_identity_role_resource(resource: NormalizedResource) -> bool:
    return _has_capability(resource, ResourceCapability.IDENTITY_ROLE)


def is_iam_policy_resource(resource: NormalizedResource) -> bool:
    return _has_capability(resource, ResourceCapability.IAM_POLICY)


def is_network_security_group_resource(resource: NormalizedResource) -> bool:
    return _has_capability(resource, ResourceCapability.NETWORK_SECURITY_GROUP)


def is_subnet_resource(resource: NormalizedResource) -> bool:
    return _has_capability(resource, ResourceCapability.SUBNET)


def is_database_resource(resource: NormalizedResource) -> bool:
    return _has_capability(resource, ResourceCapability.DATABASE)


def is_object_storage_resource(resource: NormalizedResource) -> bool:
    return _has_capability(resource, ResourceCapability.OBJECT_STORAGE)


def is_secret_store_resource(resource: NormalizedResource) -> bool:
    return _has_capability(resource, ResourceCapability.SECRET_STORE)


def is_control_plane_sensitive_data_store(resource: NormalizedResource) -> bool:
    return _has_capability(resource, ResourceCapability.CONTROL_PLANE_SENSITIVE_DATA_STORE)


def is_object_storage_public_access_control_resource(resource: NormalizedResource) -> bool:
    return _has_capability(resource, ResourceCapability.OBJECT_STORAGE_PUBLIC_ACCESS_CONTROL)


def is_key_management_resource(resource: NormalizedResource) -> bool:
    return _has_capability(resource, ResourceCapability.KEY_MANAGEMENT)


def has_provider_managed_egress_without_vpc(resource: NormalizedResource) -> bool:
    return (
        _has_capability(resource, ResourceCapability.PROVIDER_MANAGED_EGRESS_WITHOUT_VPC)
        and not resource.vpc_enabled
    )


def _has_capability(resource: NormalizedResource, capability: ResourceCapability) -> bool:
    return _DEFAULT_RESOURCE_CAPABILITY_REGISTRY.has_capability(resource, capability)