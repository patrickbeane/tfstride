from __future__ import annotations

from collections.abc import Iterable

from tfstride.models import NormalizedResource


WORKLOAD_RESOURCE_TYPES = frozenset({
    "aws_instance",
    "aws_lambda_function",
    "aws_ecs_service",
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
NETWORK_SECURITY_GROUP_RESOURCE_TYPES = frozenset({
    "aws_security_group",
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


def is_workload_resource(resource: NormalizedResource) -> bool:
    return _is_resource_type(resource, WORKLOAD_RESOURCE_TYPES)


def is_data_store_resource(resource: NormalizedResource) -> bool:
    return _is_resource_type(resource, DATA_STORE_RESOURCE_TYPES)


def is_public_edge_resource(resource: NormalizedResource) -> bool:
    return _is_resource_type(resource, PUBLIC_EDGE_RESOURCE_TYPES)


def is_identity_role_resource(resource: NormalizedResource) -> bool:
    return _is_resource_type(resource, IDENTITY_ROLE_RESOURCE_TYPES)


def is_network_security_group_resource(resource: NormalizedResource) -> bool:
    return _is_resource_type(resource, NETWORK_SECURITY_GROUP_RESOURCE_TYPES)


def is_database_resource(resource: NormalizedResource) -> bool:
    return _is_resource_type(resource, DATABASE_RESOURCE_TYPES)


def is_object_storage_resource(resource: NormalizedResource) -> bool:
    return _is_resource_type(resource, OBJECT_STORAGE_RESOURCE_TYPES)


def is_secret_store_resource(resource: NormalizedResource) -> bool:
    return _is_resource_type(resource, SECRET_STORE_RESOURCE_TYPES)


def is_control_plane_sensitive_data_store(resource: NormalizedResource) -> bool:
    return _is_resource_type(resource, CONTROL_PLANE_SENSITIVE_DATA_STORE_TYPES)


def _is_resource_type(
    resource: NormalizedResource,
    resource_types: Iterable[str],
) -> bool:
    return resource.resource_type in resource_types