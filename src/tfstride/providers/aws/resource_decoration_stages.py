from __future__ import annotations

from typing import Protocol

from tfstride.models import NormalizedResource
from tfstride.providers.aws.resource_decoration.api_gateway import ResolveApiGatewayRelationshipsStage
from tfstride.providers.aws.resource_decoration.ecr_write_paths import ModelWorkloadEcrWritePathsStage
from tfstride.providers.aws.resource_decoration.ecs import (
    MarkEcsLoadBalancerExposureStage,
    ResolveEcsServiceRelationshipsStage,
)
from tfstride.providers.aws.resource_decoration.ecs_cloudtrail_audit_telemetry_disruption_paths import (
    ModelEcsCloudTrailAuditTelemetryDisruptionPathsStage,
    ProjectEcsCloudTrailAuditTelemetryDisruptionPathsOntoServicesStage,
)
from tfstride.providers.aws.resource_decoration.ecs_dynamodb_access_paths import (
    ModelEcsDynamoDbAccessPathsStage,
    ProjectEcsDynamoDbAccessPathsOntoServicesStage,
)
from tfstride.providers.aws.resource_decoration.ecs_dynamodb_item_deletion_paths import (
    ModelEcsDynamoDbItemDeletionPathsStage,
    ProjectEcsDynamoDbItemDeletionPathsOntoServicesStage,
)
from tfstride.providers.aws.resource_decoration.ecs_dynamodb_table_topology_destruction_paths import (
    ModelEcsDynamoDbTableTopologyDestructionPathsStage,
    ProjectEcsDynamoDbTableTopologyDestructionPathsOntoServicesStage,
)
from tfstride.providers.aws.resource_decoration.ecs_kms_operation_paths import (
    ModelEcsKmsManagementPathsStage,
    ModelEcsKmsOperationPathsStage,
    ProjectEcsKmsManagementPathsOntoServicesStage,
    ProjectEcsKmsOperationPathsOntoServicesStage,
)
from tfstride.providers.aws.resource_decoration.ecs_messaging_access_paths import (
    ModelEcsMessagingAccessPathsStage,
    ProjectEcsMessagingAccessPathsOntoServicesStage,
)
from tfstride.providers.aws.resource_decoration.ecs_messaging_topology_destruction_paths import (
    ModelEcsMessagingTopologyDestructionPathsStage,
    ProjectEcsMessagingTopologyDestructionPathsOntoServicesStage,
)
from tfstride.providers.aws.resource_decoration.ecs_public_ingress import DeriveEcsPublicIngressStage
from tfstride.providers.aws.resource_decoration.ecs_s3_access_paths import (
    ModelEcsS3AccessPathsStage,
    ProjectEcsS3AccessPathsOntoServicesStage,
)
from tfstride.providers.aws.resource_decoration.ecs_s3_bucket_topology_destruction_paths import (
    ModelEcsS3BucketTopologyDestructionPathsStage,
    ProjectEcsS3BucketTopologyDestructionPathsOntoServicesStage,
)
from tfstride.providers.aws.resource_decoration.ecs_s3_object_deletion_paths import (
    ModelEcsS3ObjectDeletionPathsStage,
    ProjectEcsS3ObjectDeletionPathsOntoServicesStage,
)
from tfstride.providers.aws.resource_decoration.ecs_s3_protected_data_convergence import (
    ModelEcsS3ProtectedDataConvergenceStage,
)
from tfstride.providers.aws.resource_decoration.ecs_secret_access_paths import (
    ModelEcsSecretAccessPathsStage,
    ProjectEcsSecretAccessPathsOntoServicesStage,
)
from tfstride.providers.aws.resource_decoration.ecs_secret_management_paths import (
    ModelEcsSecretsManagerManagementPathsStage,
    ProjectEcsSecretsManagerManagementPathsOntoServicesStage,
)
from tfstride.providers.aws.resource_decoration.ecs_sqs_message_removal_paths import (
    ModelEcsSqsMessageRemovalPathsStage,
    ProjectEcsSqsMessageRemovalPathsOntoServicesStage,
)
from tfstride.providers.aws.resource_decoration.iam import (
    MergeRolePolicyResourcesStage,
    NormalizeIamAssignmentPostureStage,
    ResolveInstanceProfileRolesStage,
)
from tfstride.providers.aws.resource_decoration.kms import DecorateKmsRelationshipsStage
from tfstride.providers.aws.resource_decoration.kms_encryption_dependencies import (
    ResolveAwsKmsEncryptionDependenciesStage,
)
from tfstride.providers.aws.resource_decoration.kms_operation_authorization import (
    ModelKmsOperationAuthorizationStage,
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
from tfstride.providers.aws.resource_decoration.secrets_manager_operation_authorization import (
    ModelSecretsManagerOperationAuthorizationStage,
)
from tfstride.providers.aws.resource_decoration.security_groups import (
    MergeStandaloneSecurityGroupRulesStage,
)
from tfstride.providers.aws.resource_decoration.symbolic_relationships import (
    ResolveAwsSymbolicRelationshipsStage,
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
        ResolveAwsSymbolicRelationshipsStage(),
        MergeRolePolicyResourcesStage(),
        NormalizeIamAssignmentPostureStage(),
        DecorateKmsRelationshipsStage(),
        ModelKmsOperationAuthorizationStage(),
        ModelEcsKmsOperationPathsStage(),
        ModelEcsKmsManagementPathsStage(),
        ResolveInstanceProfileRolesStage(),
        ResolveOidcProviderTrustStage(),
        ResolveEcsServiceRelationshipsStage(),
        ModelEcsSecretAccessPathsStage(),
        ModelEcsMessagingAccessPathsStage(),
        ModelEcsDynamoDbAccessPathsStage(),
        ModelEcsDynamoDbItemDeletionPathsStage(),
        ModelEcsDynamoDbTableTopologyDestructionPathsStage(),
        ModelEcsCloudTrailAuditTelemetryDisruptionPathsStage(),
        ModelWorkloadEcrWritePathsStage(),
        ResolveApiGatewayRelationshipsStage(),
        MergeResourcePolicyResourcesStage(),
        ModelEcsS3AccessPathsStage(),
        ModelEcsMessagingTopologyDestructionPathsStage(),
        ApplyS3PublicAccessBlocksStage(),
        ApplyS3PostureResourcesStage(),
        ModelEcsS3BucketTopologyDestructionPathsStage(),
        ModelEcsS3ObjectDeletionPathsStage(),
        ApplySecretsManagerPostureResourcesStage(),
        ModelSecretsManagerOperationAuthorizationStage(),
        ModelEcsSecretsManagerManagementPathsStage(),
        ApplySqsRedrivePolicyResourcesStage(),
        ModelEcsSqsMessageRemovalPathsStage(),
        ResolveAwsKmsEncryptionDependenciesStage(),
        DeriveSubnetPostureStage(),
        InferVpcIdsStage(),
        DerivePublicExposureStage(),
        MarkEcsLoadBalancerExposureStage(),
        DeriveEcsPublicIngressStage(),
        ProjectEcsKmsOperationPathsOntoServicesStage(),
        ProjectEcsKmsManagementPathsOntoServicesStage(),
        ProjectEcsSecretsManagerManagementPathsOntoServicesStage(),
        ProjectEcsSecretAccessPathsOntoServicesStage(),
        ProjectEcsS3AccessPathsOntoServicesStage(),
        ProjectEcsS3BucketTopologyDestructionPathsOntoServicesStage(),
        ProjectEcsS3ObjectDeletionPathsOntoServicesStage(),
        ProjectEcsMessagingAccessPathsOntoServicesStage(),
        ProjectEcsSqsMessageRemovalPathsOntoServicesStage(),
        ProjectEcsMessagingTopologyDestructionPathsOntoServicesStage(),
        ProjectEcsDynamoDbAccessPathsOntoServicesStage(),
        ProjectEcsDynamoDbItemDeletionPathsOntoServicesStage(),
        ProjectEcsDynamoDbTableTopologyDestructionPathsOntoServicesStage(),
        ProjectEcsCloudTrailAuditTelemetryDisruptionPathsOntoServicesStage(),
        ModelEcsS3ProtectedDataConvergenceStage(),
    )
