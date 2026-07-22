from __future__ import annotations

from typing import Protocol

from tfstride.models import NormalizedResource
from tfstride.providers.aws.resource_decoration.api_gateway import ResolveApiGatewayRelationshipsStage
from tfstride.providers.aws.resource_decoration.ecr_write_paths import ModelWorkloadEcrWritePathsStage
from tfstride.providers.aws.resource_decoration.ecs import (
    MarkEcsLoadBalancerExposureStage,
    ResolveEcsServiceRelationshipsStage,
)
from tfstride.providers.aws.resource_decoration.ecs_s3_access_paths import (
    ModelEcsS3AccessPathsStage,
    ProjectEcsS3AccessPathsOntoServicesStage,
)
from tfstride.providers.aws.resource_decoration.ecs_secret_access_paths import (
    ModelEcsSecretAccessPathsStage,
    ProjectEcsSecretAccessPathsOntoServicesStage,
)
from tfstride.providers.aws.resource_decoration.iam import (
    MergeRolePolicyResourcesStage,
    NormalizeIamAssignmentPostureStage,
    ResolveInstanceProfileRolesStage,
)
from tfstride.providers.aws.resource_decoration.network_posture import (
    DeriveSubnetPostureStage,
    InferVpcIdsStage,
)
from tfstride.providers.aws.resource_decoration.oidc_trust import ResolveOidcProviderTrustStage
from tfstride.providers.aws.resource_decoration.public_exposure import (
    DerivePublicExposureStage,
)
from tfstride.providers.aws.resource_decoration.resource_policies import (
    ApplyS3PostureResourcesStage,
    ApplyS3PublicAccessBlocksStage,
    ApplySecretsManagerPostureResourcesStage,
    ApplySqsRedrivePolicyResourcesStage,
    MergeResourcePolicyResourcesStage,
)
from tfstride.providers.aws.resource_decoration.security_groups import (
    MergeStandaloneSecurityGroupRulesStage,
)
from tfstride.providers.aws.resource_index import AwsDecorationContext


class AwsDecorationStage(Protocol):
    name: str

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        """Apply one ordered AWS resource decoration step."""
        ...


def default_aws_decoration_stages() -> tuple[AwsDecorationStage, ...]:
    return (
        MergeStandaloneSecurityGroupRulesStage(),
        MergeRolePolicyResourcesStage(),
        NormalizeIamAssignmentPostureStage(),
        ResolveInstanceProfileRolesStage(),
        ResolveOidcProviderTrustStage(),
        ResolveEcsServiceRelationshipsStage(),
        ModelEcsSecretAccessPathsStage(),
        ModelEcsS3AccessPathsStage(),
        ModelWorkloadEcrWritePathsStage(),
        ResolveApiGatewayRelationshipsStage(),
        MergeResourcePolicyResourcesStage(),
        ApplyS3PublicAccessBlocksStage(),
        ApplyS3PostureResourcesStage(),
        ApplySecretsManagerPostureResourcesStage(),
        ApplySqsRedrivePolicyResourcesStage(),
        DeriveSubnetPostureStage(),
        InferVpcIdsStage(),
        DerivePublicExposureStage(),
        MarkEcsLoadBalancerExposureStage(),
        ProjectEcsSecretAccessPathsOntoServicesStage(),
        ProjectEcsS3AccessPathsOntoServicesStage(),
    )
