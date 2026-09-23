from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource, ResourceInventory, TerraformResource
from tfstride.providers.aws.account_identity_normalizers import normalize_caller_identity, with_account_identity_inputs
from tfstride.providers.aws.api_gateway_normalizers import (
    normalize_api_gateway_authorizer,
    normalize_api_gateway_method,
    normalize_api_gateway_rest_api,
    normalize_api_gateway_stage,
    normalize_apigatewayv2_api,
    normalize_apigatewayv2_route,
    normalize_apigatewayv2_stage,
)
from tfstride.providers.aws.audit_normalizers import (
    normalize_accessanalyzer_analyzer,
    normalize_cloudtrail,
    normalize_config_configuration_recorder,
    normalize_config_configuration_recorder_status,
    normalize_config_delivery_channel,
    normalize_guardduty_detector,
    normalize_macie2_account,
    normalize_securityhub_account,
)
from tfstride.providers.aws.compute_normalizers import (
    normalize_ecs_cluster,
    normalize_ecs_service,
    normalize_ecs_task_definition,
    normalize_instance,
    normalize_lambda_function,
    normalize_lambda_function_url,
    normalize_lambda_permission,
)
from tfstride.providers.aws.data_normalizers import (
    normalize_db_instance,
    normalize_s3_bucket,
    normalize_s3_bucket_lifecycle_configuration,
    normalize_s3_bucket_object_lock_configuration,
    normalize_s3_bucket_policy,
    normalize_s3_bucket_public_access_block,
    normalize_s3_bucket_server_side_encryption_configuration,
    normalize_s3_bucket_versioning,
    normalize_secretsmanager_secret,
    normalize_secretsmanager_secret_policy,
    normalize_secretsmanager_secret_rotation,
    normalize_sns_topic,
    normalize_sqs_queue,
    normalize_sqs_queue_redrive_policy,
)
from tfstride.providers.aws.dynamodb_normalizers import (
    normalize_dynamodb_resource_policy,
    normalize_dynamodb_table,
)
from tfstride.providers.aws.ecr_normalizers import (
    normalize_ecr_registry_scanning_configuration,
    normalize_ecr_repository,
)
from tfstride.providers.aws.eks_normalizers import normalize_eks_addon, normalize_eks_cluster
from tfstride.providers.aws.iam_normalizers import (
    normalize_iam_instance_profile,
    normalize_iam_openid_connect_provider,
    normalize_iam_policy,
    normalize_iam_role,
    normalize_iam_role_policy,
    normalize_iam_role_policy_attachment,
)
from tfstride.providers.aws.kms_normalizers import (
    normalize_kms_alias,
    normalize_kms_grant,
    normalize_kms_key,
    normalize_kms_key_policy,
)
from tfstride.providers.aws.network_normalizers import (
    normalize_cloudfront_distribution,
    normalize_flow_log,
    normalize_internet_gateway,
    normalize_load_balancer,
    normalize_load_balancer_listener,
    normalize_load_balancer_listener_rule,
    normalize_load_balancer_target_group,
    normalize_nat_gateway,
    normalize_route_table,
    normalize_route_table_association,
    normalize_security_group,
    normalize_security_group_rule,
    normalize_subnet,
    normalize_vpc,
    normalize_vpc_endpoint,
    normalize_wafv2_web_acl,
    normalize_wafv2_web_acl_association,
)
from tfstride.providers.aws.resource_decorator import AwsResourceDecorator
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.normalization import ResourceNormalizer, normalize_provider_inventory
from tfstride.resource_helpers import parse_aws_account_id
from tfstride.resource_metadata import InventoryMetadata

_AWS_RESOURCE_NORMALIZERS: dict[str, ResourceNormalizer] = {
    "aws_accessanalyzer_analyzer": normalize_accessanalyzer_analyzer,
    "aws_caller_identity": normalize_caller_identity,
    "aws_api_gateway_rest_api": normalize_api_gateway_rest_api,
    "aws_api_gateway_method": normalize_api_gateway_method,
    "aws_api_gateway_stage": normalize_api_gateway_stage,
    "aws_api_gateway_authorizer": normalize_api_gateway_authorizer,
    "aws_apigatewayv2_api": normalize_apigatewayv2_api,
    "aws_apigatewayv2_route": normalize_apigatewayv2_route,
    "aws_apigatewayv2_stage": normalize_apigatewayv2_stage,
    "aws_cloudfront_distribution": normalize_cloudfront_distribution,
    "aws_cloudtrail": normalize_cloudtrail,
    "aws_config_configuration_recorder": normalize_config_configuration_recorder,
    "aws_config_configuration_recorder_status": normalize_config_configuration_recorder_status,
    "aws_config_delivery_channel": normalize_config_delivery_channel,
    "aws_db_instance": normalize_db_instance,
    "aws_dynamodb_resource_policy": normalize_dynamodb_resource_policy,
    "aws_dynamodb_table": normalize_dynamodb_table,
    "aws_ecs_cluster": normalize_ecs_cluster,
    "aws_ecs_service": normalize_ecs_service,
    "aws_ecs_task_definition": normalize_ecs_task_definition,
    "aws_ecr_registry_scanning_configuration": normalize_ecr_registry_scanning_configuration,
    "aws_ecr_repository": normalize_ecr_repository,
    "aws_eks_addon": normalize_eks_addon,
    "aws_eks_cluster": normalize_eks_cluster,
    "aws_flow_log": normalize_flow_log,
    "aws_iam_instance_profile": normalize_iam_instance_profile,
    "aws_iam_openid_connect_provider": normalize_iam_openid_connect_provider,
    "aws_iam_policy": normalize_iam_policy,
    "aws_iam_role": normalize_iam_role,
    "aws_iam_role_policy": normalize_iam_role_policy,
    "aws_guardduty_detector": normalize_guardduty_detector,
    "aws_iam_role_policy_attachment": normalize_iam_role_policy_attachment,
    "aws_instance": normalize_instance,
    "aws_internet_gateway": normalize_internet_gateway,
    "aws_kms_alias": normalize_kms_alias,
    "aws_kms_grant": normalize_kms_grant,
    "aws_kms_key": normalize_kms_key,
    "aws_kms_key_policy": normalize_kms_key_policy,
    "aws_lambda_function": normalize_lambda_function,
    "aws_lambda_function_url": normalize_lambda_function_url,
    "aws_lambda_permission": normalize_lambda_permission,
    "aws_lb": normalize_load_balancer,
    "aws_lb_listener": normalize_load_balancer_listener,
    "aws_lb_listener_rule": normalize_load_balancer_listener_rule,
    "aws_lb_target_group": normalize_load_balancer_target_group,
    "aws_macie2_account": normalize_macie2_account,
    "aws_nat_gateway": normalize_nat_gateway,
    "aws_route_table": normalize_route_table,
    "aws_route_table_association": normalize_route_table_association,
    "aws_s3_bucket": normalize_s3_bucket,
    "aws_s3_bucket_lifecycle_configuration": normalize_s3_bucket_lifecycle_configuration,
    "aws_s3_bucket_object_lock_configuration": normalize_s3_bucket_object_lock_configuration,
    "aws_s3_bucket_policy": normalize_s3_bucket_policy,
    "aws_s3_bucket_public_access_block": normalize_s3_bucket_public_access_block,
    "aws_s3_bucket_server_side_encryption_configuration": normalize_s3_bucket_server_side_encryption_configuration,
    "aws_s3_bucket_versioning": normalize_s3_bucket_versioning,
    "aws_secretsmanager_secret": normalize_secretsmanager_secret,
    "aws_secretsmanager_secret_policy": normalize_secretsmanager_secret_policy,
    "aws_secretsmanager_secret_rotation": normalize_secretsmanager_secret_rotation,
    "aws_securityhub_account": normalize_securityhub_account,
    "aws_security_group": normalize_security_group,
    "aws_security_group_rule": normalize_security_group_rule,
    "aws_sns_topic": normalize_sns_topic,
    "aws_sqs_queue": normalize_sqs_queue,
    "aws_sqs_queue_redrive_policy": normalize_sqs_queue_redrive_policy,
    "aws_subnet": normalize_subnet,
    "aws_vpc": normalize_vpc,
    "aws_vpc_endpoint": normalize_vpc_endpoint,
    "aws_wafv2_web_acl": normalize_wafv2_web_acl,
    "aws_wafv2_web_acl_association": normalize_wafv2_web_acl_association,
}
SUPPORTED_AWS_TYPES = set(_AWS_RESOURCE_NORMALIZERS)


class AwsNormalizer(ProviderNormalizer):
    provider = "aws"

    def __init__(self, resource_decorator: AwsResourceDecorator | None = None) -> None:
        self._resource_decorator = resource_decorator or AwsResourceDecorator()
        self._resource_normalizers = {
            resource_type: with_account_identity_inputs(normalizer)
            for resource_type, normalizer in _AWS_RESOURCE_NORMALIZERS.items()
        }

    def owns_resource(self, resource: TerraformResource) -> bool:
        return _is_aws_resource(resource)

    def normalize(self, resources: list[TerraformResource]) -> ResourceInventory:
        return normalize_provider_inventory(
            resources,
            provider=self.provider,
            owns_resource=self.owns_resource,
            resource_normalizers=self._resource_normalizers,
            decorate_resources=self._resource_decorator.decorate,
            enrich_inventory_metadata=_add_primary_account_id_metadata,
        )


def _is_aws_resource(resource: TerraformResource) -> bool:
    provider_name = str(resource.provider_name).strip().lower()
    return provider_name.endswith("/aws") or resource.resource_type.startswith("aws_")


def _add_primary_account_id_metadata(
    resources: list[NormalizedResource],
    metadata: dict[str, Any],
) -> None:
    InventoryMetadata.PRIMARY_ACCOUNT_ID.set(metadata, _infer_primary_account_id(resources))


def _infer_primary_account_id(resources: list[NormalizedResource]) -> str | None:
    caller_identity_facts = [
        aws_facts(resource) for resource in resources if resource.resource_type == "aws_caller_identity"
    ]
    caller_states = {facts.caller_identity_account_id_state for facts in caller_identity_facts}
    if caller_states & {"ambiguous", "invalid"}:
        return None

    caller_account_ids = {
        facts.caller_identity_account_id
        for facts in caller_identity_facts
        if facts.caller_identity_account_id is not None
    }
    if caller_account_ids:
        if caller_states != {"resolved"} or len(caller_account_ids) != 1:
            return None
        return next(iter(caller_account_ids))

    resource_account_ids: set[str] = set()
    for resource in resources:
        if resource.resource_type == "aws_caller_identity":
            continue
        account_id, invalid_account_segment = _resource_arn_account_evidence(resource.arn)
        if invalid_account_segment:
            return None
        if account_id is not None:
            resource_account_ids.add(account_id)

    if len(resource_account_ids) != 1:
        return None
    return next(iter(resource_account_ids))


def _resource_arn_account_evidence(
    arn: str | None,
) -> tuple[str | None, bool]:
    if not arn or not arn.startswith("arn:"):
        return None, False
    parts = arn.split(":")
    if len(parts) < 5 or not parts[4]:
        return None, False
    account_id = parse_aws_account_id(arn)
    return account_id, account_id is None
