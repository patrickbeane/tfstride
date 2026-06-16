from __future__ import annotations

from types import MappingProxyType

from tfstride.providers.gcp.resource_types import (
    GCP_DATA_STORE_RESOURCE_TYPES,
    GCP_IAM_POLICY_RESOURCE_TYPES,
    GCP_NETWORK_SECURITY_GROUP_RESOURCE_TYPES,
    GCP_PUBLIC_EDGE_RESOURCE_TYPES,
    GCP_SENSITIVE_RESOURCE_POLICY_TYPES,
    GCP_SERVERLESS_WORKLOAD_RESOURCE_TYPES,
    GCP_WORKLOAD_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.resource_capabilities import ResourceCapability

GCP_RESOURCE_CAPABILITIES = MappingProxyType(
    {
        ResourceCapability.WORKLOAD: GCP_WORKLOAD_RESOURCE_TYPES,
        ResourceCapability.PUBLIC_COMPUTE: GCP_WORKLOAD_RESOURCE_TYPES,
        ResourceCapability.DATA_STORE: GCP_DATA_STORE_RESOURCE_TYPES,
        ResourceCapability.PUBLIC_EDGE: GCP_PUBLIC_EDGE_RESOURCE_TYPES,
        ResourceCapability.IDENTITY_ROLE: frozenset({GcpResourceType.SERVICE_ACCOUNT}),
        ResourceCapability.IAM_POLICY: GCP_IAM_POLICY_RESOURCE_TYPES,
        ResourceCapability.NETWORK_SECURITY_GROUP: GCP_NETWORK_SECURITY_GROUP_RESOURCE_TYPES,
        ResourceCapability.SUBNET: frozenset({GcpResourceType.COMPUTE_SUBNETWORK}),
        ResourceCapability.DATABASE: frozenset({GcpResourceType.SQL_DATABASE_INSTANCE}),
        ResourceCapability.OBJECT_STORAGE: frozenset({GcpResourceType.STORAGE_BUCKET}),
        ResourceCapability.SECRET_STORE: frozenset({GcpResourceType.SECRET_MANAGER_SECRET}),
        ResourceCapability.CONTROL_PLANE_SENSITIVE_DATA_STORE: frozenset(
            {GcpResourceType.SECRET_MANAGER_SECRET}
        ),
        ResourceCapability.KEY_MANAGEMENT: frozenset({GcpResourceType.KMS_CRYPTO_KEY}),
        ResourceCapability.PROVIDER_MANAGED_EGRESS_WITHOUT_VPC: GCP_SERVERLESS_WORKLOAD_RESOURCE_TYPES,
        ResourceCapability.SENSITIVE_RESOURCE_POLICY: GCP_SENSITIVE_RESOURCE_POLICY_TYPES,
    }
)