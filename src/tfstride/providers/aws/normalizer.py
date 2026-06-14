from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from typing import Any

from tfstride.models import NormalizedResource, ResourceInventory, TerraformResource
from tfstride.providers.base import ProviderNormalizer
from tfstride.resource_helpers import parse_aws_account_id
from tfstride.resource_metadata import InventoryMetadata
from tfstride.providers.aws.compute_normalizers import (
    normalize_ecs_cluster,
    normalize_ecs_service,
    normalize_ecs_task_definition,
    normalize_instance,
    normalize_lambda_function,
    normalize_lambda_permission,
)
from tfstride.providers.aws.data_normalizers import (
    normalize_db_instance,
    normalize_kms_key,
    normalize_s3_bucket,
    normalize_s3_bucket_policy,
    normalize_s3_bucket_public_access_block,
    normalize_secretsmanager_secret,
    normalize_secretsmanager_secret_policy,
    normalize_sns_topic,
    normalize_sqs_queue,
)
from tfstride.providers.aws.iam_normalizers import (
    normalize_iam_instance_profile,
    normalize_iam_policy,
    normalize_iam_role,
    normalize_iam_role_policy,
    normalize_iam_role_policy_attachment,
)
from tfstride.providers.aws.network_normalizers import (
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
)
from tfstride.providers.aws.resource_decorator import AwsResourceDecorator


ResourceNormalizer = Callable[[TerraformResource], NormalizedResource]

_AWS_RESOURCE_NORMALIZERS: dict[str, ResourceNormalizer] = {
    "aws_db_instance": normalize_db_instance,
    "aws_ecs_cluster": normalize_ecs_cluster,
    "aws_ecs_service": normalize_ecs_service,
    "aws_ecs_task_definition": normalize_ecs_task_definition,
    "aws_iam_instance_profile": normalize_iam_instance_profile,
    "aws_iam_policy": normalize_iam_policy,
    "aws_iam_role": normalize_iam_role,
    "aws_iam_role_policy": normalize_iam_role_policy,
    "aws_iam_role_policy_attachment": normalize_iam_role_policy_attachment,
    "aws_instance": normalize_instance,
    "aws_internet_gateway": normalize_internet_gateway,
    "aws_kms_key": normalize_kms_key,
    "aws_lambda_function": normalize_lambda_function,
    "aws_lambda_permission": normalize_lambda_permission,
    "aws_lb": normalize_load_balancer,
    "aws_lb_listener": normalize_load_balancer_listener,
    "aws_lb_listener_rule": normalize_load_balancer_listener_rule,
    "aws_lb_target_group": normalize_load_balancer_target_group,
    "aws_nat_gateway": normalize_nat_gateway,
    "aws_route_table": normalize_route_table,
    "aws_route_table_association": normalize_route_table_association,
    "aws_s3_bucket": normalize_s3_bucket,
    "aws_s3_bucket_policy": normalize_s3_bucket_policy,
    "aws_s3_bucket_public_access_block": normalize_s3_bucket_public_access_block,
    "aws_secretsmanager_secret": normalize_secretsmanager_secret,
    "aws_secretsmanager_secret_policy": normalize_secretsmanager_secret_policy,
    "aws_security_group": normalize_security_group,
    "aws_security_group_rule": normalize_security_group_rule,
    "aws_sns_topic": normalize_sns_topic,
    "aws_sqs_queue": normalize_sqs_queue,
    "aws_subnet": normalize_subnet,
    "aws_vpc": normalize_vpc,
}
SUPPORTED_AWS_TYPES = set(_AWS_RESOURCE_NORMALIZERS)


class AwsNormalizer(ProviderNormalizer):
    provider = "aws"

    def __init__(self, resource_decorator: AwsResourceDecorator | None = None) -> None:
        self._resource_decorator = resource_decorator or AwsResourceDecorator()
        self._resource_normalizers = dict(_AWS_RESOURCE_NORMALIZERS)

    def owns_resource(self, resource: TerraformResource) -> bool:
        return _is_aws_resource(resource)

    def normalize(self, resources: list[TerraformResource]) -> ResourceInventory:
        aws_resources = [resource for resource in resources if self.owns_resource(resource)]
        unsupported_resource_types = Counter(
            resource.resource_type
            for resource in aws_resources
            if resource.resource_type not in SUPPORTED_AWS_TYPES
        )
        unsupported = sorted(
            resource.address for resource in aws_resources if resource.resource_type not in SUPPORTED_AWS_TYPES
        )
        normalized = [
            self._normalize_resource(resource)
            for resource in aws_resources
            if resource.resource_type in SUPPORTED_AWS_TYPES
        ]
        self._resource_decorator.decorate(normalized)
        primary_account_id = _infer_primary_account_id(normalized)
        metadata: dict[str, Any] = {}
        InventoryMetadata.PRIMARY_ACCOUNT_ID.set(metadata, primary_account_id)
        InventoryMetadata.SUPPORTED_RESOURCE_TYPES.set(metadata, sorted(SUPPORTED_AWS_TYPES))
        InventoryMetadata.TOTAL_INPUT_RESOURCES.set(metadata, len(resources))
        InventoryMetadata.PROVIDER_RESOURCE_COUNT.set(metadata, len(aws_resources))
        InventoryMetadata.NORMALIZED_RESOURCE_COUNT.set(metadata, len(normalized))
        InventoryMetadata.UNSUPPORTED_RESOURCE_TYPES.set(
            metadata,
            dict(sorted(unsupported_resource_types.items())),
        )
        return ResourceInventory(
            provider=self.provider,
            resources=normalized,
            unsupported_resources=unsupported,
            metadata=metadata,
        )

    def _normalize_resource(self, resource: TerraformResource) -> NormalizedResource:
        try:
            normalizer = self._resource_normalizers[resource.resource_type]
        except KeyError as exc:
            raise ValueError(f"Unsupported resource type reached normalizer: {resource.resource_type}") from exc
        return normalizer(resource)


def _is_aws_resource(resource: TerraformResource) -> bool:
    provider_name = str(resource.provider_name).strip().lower()
    return provider_name.endswith("/aws") or resource.resource_type.startswith("aws_")


def _infer_primary_account_id(resources: list[NormalizedResource]) -> str | None:
    accounts = Counter(
        account_id for account_id in (parse_aws_account_id(resource.arn) for resource in resources) if account_id
    )
    if not accounts:
        return None
    return accounts.most_common(1)[0][0]