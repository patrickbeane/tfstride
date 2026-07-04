from __future__ import annotations

from typing import Protocol

from tfstride.models import NormalizedResource
from tfstride.providers.aws.resource_decoration.ecs import (
    MarkEcsLoadBalancerExposureStage,
    ResolveEcsServiceRelationshipsStage,
)
from tfstride.providers.aws.resource_decoration.iam import (
    MergeRolePolicyResourcesStage,
    ResolveInstanceProfileRolesStage,
)
from tfstride.providers.aws.resource_decoration.network_posture import (
    DeriveSubnetPostureStage,
    InferVpcIdsStage,
)
from tfstride.providers.aws.resource_decoration.public_exposure import (
    DerivePublicExposureStage,
)
from tfstride.providers.aws.resource_decoration.resource_policies import (
    ApplyS3PostureResourcesStage,
    ApplyS3PublicAccessBlocksStage,
    ApplySecretsManagerPostureResourcesStage,
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
        ResolveInstanceProfileRolesStage(),
        ResolveEcsServiceRelationshipsStage(),
        MergeResourcePolicyResourcesStage(),
        ApplyS3PublicAccessBlocksStage(),
        ApplyS3PostureResourcesStage(),
        ApplySecretsManagerPostureResourcesStage(),
        DeriveSubnetPostureStage(),
        InferVpcIdsStage(),
        DerivePublicExposureStage(),
        MarkEcsLoadBalancerExposureStage(),
    )
