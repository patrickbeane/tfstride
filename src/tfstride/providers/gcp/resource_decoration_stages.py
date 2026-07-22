from __future__ import annotations

from typing import Protocol

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.resource_decoration.artifact_registry_write_paths import (
    ModelCloudRunArtifactRegistryWritePathsStage,
)
from tfstride.providers.gcp.resource_decoration.cloud_run_gcs_access_paths import (
    ModelCloudRunGcsAccessPathsStage,
)
from tfstride.providers.gcp.resource_decoration.cloud_run_secret_access_paths import (
    ModelCloudRunSecretAccessPathsStage,
)
from tfstride.providers.gcp.resource_decoration.iam_assignment import NormalizeIamAssignmentPostureStage
from tfstride.providers.gcp.resource_decoration.iam_bindings import DecorateSensitiveIamBindingsStage
from tfstride.providers.gcp.resource_decoration.load_balancer import DeriveLoadBalancerReachabilityStage
from tfstride.providers.gcp.resource_decoration.network_posture import DeriveNetworkPostureStage
from tfstride.providers.gcp.resource_decoration.public_exposure import DerivePublicExposureStage
from tfstride.providers.gcp.resource_decoration.workload_identity_federation import (
    ModelWorkloadIdentityFederationTrustPathsStage,
)
from tfstride.providers.gcp.resource_index import GcpDecorationContext


class GcpDecorationStage(Protocol):
    name: str

    def apply(self, resources: list[NormalizedResource], context: GcpDecorationContext) -> None:
        """Apply one ordered GCP resource decoration step."""
        ...


def default_gcp_decoration_stages() -> tuple[GcpDecorationStage, ...]:
    return (
        DeriveLoadBalancerReachabilityStage(),
        DeriveNetworkPostureStage(),
        DerivePublicExposureStage(),
        DecorateSensitiveIamBindingsStage(),
        ModelCloudRunGcsAccessPathsStage(),
        ModelCloudRunSecretAccessPathsStage(),
        ModelCloudRunArtifactRegistryWritePathsStage(),
        ModelWorkloadIdentityFederationTrustPathsStage(),
        NormalizeIamAssignmentPostureStage(),
    )
