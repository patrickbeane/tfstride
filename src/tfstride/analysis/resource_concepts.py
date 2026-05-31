from __future__ import annotations

from collections.abc import Iterable

from tfstride.models import NormalizedResource


WORKLOAD_RESOURCE_TYPES = frozenset({
    "aws_instance",
    "aws_lambda_function",
    "aws_ecs_service",
})
SECURITY_GROUP_BACKED_WORKLOAD_RESOURCE_TYPES = frozenset({
    "aws_instance",
    "aws_ecs_service",
})
PUBLIC_COMPUTE_RESOURCE_TYPES = frozenset({
    "aws_instance",
})
DATA_STORE_RESOURCE_TYPES = frozenset({
    "aws_db_instance",
    "aws_s3_bucket",
    "aws_secretsmanager_secret",
})
PUBLIC_EDGE_RESOURCE_TYPES = frozenset({
    "aws_instance",
    "aws_lb",
    "aws_db_instance",
    "aws_s3_bucket",
})
IDENTITY_ROLE_RESOURCE_TYPES = frozenset({
    "aws_iam_role",
})
IAM_POLICY_RESOURCE_TYPES = frozenset({
    "aws_iam_policy",
    "aws_iam_role",
})
NETWORK_SECURITY_GROUP_RESOURCE_TYPES = frozenset({
    "aws_security_group",
})
SUBNET_RESOURCE_TYPES = frozenset({
    "aws_subnet",
})
DATABASE_RESOURCE_TYPES = frozenset({
    "aws_db_instance",
})
OBJECT_STORAGE_RESOURCE_TYPES = frozenset({
    "aws_s3_bucket",
})
SECRET_STORE_RESOURCE_TYPES = frozenset({
    "aws_secretsmanager_secret",
})
CONTROL_PLANE_SENSITIVE_DATA_STORE_TYPES = frozenset({
    "aws_db_instance",
    "aws_secretsmanager_secret",
})
OBJECT_STORAGE_PUBLIC_ACCESS_CONTROL_RESOURCE_TYPES = frozenset({
    "aws_s3_bucket_public_access_block",
})
KEY_MANAGEMENT_RESOURCE_TYPES = frozenset({
    "aws_kms_key",
})
SENSITIVE_RESOURCE_POLICY_RESOURCE_TYPES = frozenset({
    "aws_s3_bucket",
    "aws_kms_key",
    "aws_secretsmanager_secret",
})
SERVICE_RESOURCE_POLICY_RESOURCE_TYPES = frozenset({
    "aws_lambda_function",
    "aws_sqs_queue",
    "aws_sns_topic",
})
PROVIDER_MANAGED_EGRESS_WITHOUT_VPC_RESOURCE_TYPES = frozenset({
    "aws_lambda_function",
})


def is_workload_resource(resource: NormalizedResource) -> bool:
    return _is_resource_type(resource, WORKLOAD_RESOURCE_TYPES)


def is_security_group_backed_workload_resource(resource: NormalizedResource) -> bool:
    return _is_resource_type(resource, SECURITY_GROUP_BACKED_WORKLOAD_RESOURCE_TYPES)


def is_public_compute_resource(resource: NormalizedResource) -> bool:
    return _is_resource_type(resource, PUBLIC_COMPUTE_RESOURCE_TYPES)


def is_data_store_resource(resource: NormalizedResource) -> bool:
    return _is_resource_type(resource, DATA_STORE_RESOURCE_TYPES)


def is_public_edge_resource(resource: NormalizedResource) -> bool:
    return _is_resource_type(resource, PUBLIC_EDGE_RESOURCE_TYPES)


def is_identity_role_resource(resource: NormalizedResource) -> bool:
    return _is_resource_type(resource, IDENTITY_ROLE_RESOURCE_TYPES)


def is_iam_policy_resource(resource: NormalizedResource) -> bool:
    return _is_resource_type(resource, IAM_POLICY_RESOURCE_TYPES)


def is_network_security_group_resource(resource: NormalizedResource) -> bool:
    return _is_resource_type(resource, NETWORK_SECURITY_GROUP_RESOURCE_TYPES)


def is_subnet_resource(resource: NormalizedResource) -> bool:
    return _is_resource_type(resource, SUBNET_RESOURCE_TYPES)


def is_database_resource(resource: NormalizedResource) -> bool:
    return _is_resource_type(resource, DATABASE_RESOURCE_TYPES)


def is_object_storage_resource(resource: NormalizedResource) -> bool:
    return _is_resource_type(resource, OBJECT_STORAGE_RESOURCE_TYPES)


def is_secret_store_resource(resource: NormalizedResource) -> bool:
    return _is_resource_type(resource, SECRET_STORE_RESOURCE_TYPES)


def is_control_plane_sensitive_data_store(resource: NormalizedResource) -> bool:
    return _is_resource_type(resource, CONTROL_PLANE_SENSITIVE_DATA_STORE_TYPES)


def is_object_storage_public_access_control_resource(resource: NormalizedResource) -> bool:
    return _is_resource_type(resource, OBJECT_STORAGE_PUBLIC_ACCESS_CONTROL_RESOURCE_TYPES)


def is_key_management_resource(resource: NormalizedResource) -> bool:
    return _is_resource_type(resource, KEY_MANAGEMENT_RESOURCE_TYPES)


def has_provider_managed_egress_without_vpc(resource: NormalizedResource) -> bool:
    return (
        _is_resource_type(resource, PROVIDER_MANAGED_EGRESS_WITHOUT_VPC_RESOURCE_TYPES)
        and not resource.vpc_enabled
    )


def _is_resource_type(
    resource: NormalizedResource,
    resource_types: Iterable[str],
) -> bool:
    return resource.resource_type in resource_types