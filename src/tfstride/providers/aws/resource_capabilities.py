from __future__ import annotations

from types import MappingProxyType

from tfstride.providers.resource_capabilities import ResourceCapability

AWS_RESOURCE_CAPABILITIES = MappingProxyType(
    {
        ResourceCapability.WORKLOAD: frozenset(
            {
                "aws_instance",
                "aws_lambda_function",
                "aws_ecs_service",
            }
        ),
        ResourceCapability.SECURITY_GROUP_BACKED_WORKLOAD: frozenset(
            {
                "aws_instance",
                "aws_ecs_service",
            }
        ),
        ResourceCapability.PUBLIC_COMPUTE: frozenset({"aws_instance"}),
        ResourceCapability.DATA_STORE: frozenset(
            {
                "aws_db_instance",
                "aws_s3_bucket",
                "aws_secretsmanager_secret",
            }
        ),
        ResourceCapability.PUBLIC_EDGE: frozenset(
            {
                "aws_instance",
                "aws_lb",
                "aws_cloudfront_distribution",
                "aws_api_gateway_rest_api",
                "aws_apigatewayv2_api",
                "aws_db_instance",
                "aws_s3_bucket",
            }
        ),
        ResourceCapability.IDENTITY_ROLE: frozenset({"aws_iam_role"}),
        ResourceCapability.IAM_POLICY: frozenset({"aws_iam_policy", "aws_iam_role"}),
        ResourceCapability.NETWORK_SECURITY_GROUP: frozenset({"aws_security_group"}),
        ResourceCapability.SUBNET: frozenset({"aws_subnet"}),
        ResourceCapability.DATABASE: frozenset({"aws_db_instance"}),
        ResourceCapability.OBJECT_STORAGE: frozenset({"aws_s3_bucket"}),
        ResourceCapability.SECRET_STORE: frozenset({"aws_secretsmanager_secret"}),
        ResourceCapability.CONTROL_PLANE_SENSITIVE_DATA_STORE: frozenset(
            {
                "aws_db_instance",
                "aws_secretsmanager_secret",
            }
        ),
        ResourceCapability.OBJECT_STORAGE_PUBLIC_ACCESS_CONTROL: frozenset({"aws_s3_bucket_public_access_block"}),
        ResourceCapability.KEY_MANAGEMENT: frozenset({"aws_kms_key"}),
        ResourceCapability.SENSITIVE_RESOURCE_POLICY: frozenset(
            {
                "aws_s3_bucket",
                "aws_kms_key",
                "aws_secretsmanager_secret",
            }
        ),
        ResourceCapability.SERVICE_RESOURCE_POLICY: frozenset(
            {
                "aws_lambda_function",
                "aws_sqs_queue",
                "aws_sns_topic",
            }
        ),
        ResourceCapability.PROVIDER_MANAGED_EGRESS_WITHOUT_VPC: frozenset({"aws_lambda_function"}),
    }
)
