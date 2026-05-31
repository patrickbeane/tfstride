from __future__ import annotations

from types import MappingProxyType

from tfstride.providers.resource_capabilities import ResourceCapability


GCP_RESOURCE_CAPABILITIES = MappingProxyType(
    {
        ResourceCapability.WORKLOAD: frozenset({"google_compute_instance"}),
        ResourceCapability.PUBLIC_COMPUTE: frozenset({"google_compute_instance"}),
        ResourceCapability.DATA_STORE: frozenset({"google_storage_bucket"}),
        ResourceCapability.PUBLIC_EDGE: frozenset(
            {
                "google_compute_instance",
                "google_storage_bucket",
            }
        ),
        ResourceCapability.IAM_POLICY: frozenset({"google_project_iam_member"}),
        ResourceCapability.NETWORK_SECURITY_GROUP: frozenset({"google_compute_firewall"}),
        ResourceCapability.SUBNET: frozenset({"google_compute_subnetwork"}),
        ResourceCapability.OBJECT_STORAGE: frozenset({"google_storage_bucket"}),
    }
)