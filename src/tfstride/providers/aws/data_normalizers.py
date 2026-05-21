from __future__ import annotations

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.aws.coercion import as_list
from tfstride.providers.aws.network_normalizers import AWS_PROVIDER
from tfstride.providers.aws.policy_documents import load_json_document, parse_policy_statements
from tfstride.providers.aws.resource_utils import bucket_public_exposure_reasons
from tfstride.resource_helpers import policy_allows_public_access


def normalize_db_instance(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    publicly_accessible = bool(values.get("publicly_accessible", False))
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=values.get("id") or values.get("identifier"),
        arn=values.get("arn"),
        security_group_ids=as_list(values.get("vpc_security_group_ids")),
        public_access_configured=publicly_accessible,
        data_sensitivity="sensitive",
        metadata={
            "engine": values.get("engine"),
            "publicly_accessible": publicly_accessible,
            "public_access_reasons": (
                ["database instance is marked publicly_accessible"]
                if publicly_accessible
                else []
            ),
            "public_exposure_reasons": [],
            "storage_encrypted": bool(values.get("storage_encrypted", False)),
            "db_subnet_group_name": values.get("db_subnet_group_name"),
        },
    )


def normalize_s3_bucket(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    policy_document = load_json_document(values.get("policy"))
    bucket_acl = values.get("acl", "")
    public_policy = policy_allows_public_access(policy_document)
    public_access_configured = bucket_acl in {"public-read", "public-read-write", "website"} or public_policy
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=values.get("bucket") or values.get("id"),
        arn=values.get("arn"),
        public_access_configured=public_access_configured,
        public_exposure=public_access_configured,
        data_sensitivity="sensitive",
        policy_statements=parse_policy_statements(policy_document),
        metadata={
            "bucket": values.get("bucket"),
            "acl": bucket_acl,
            "policy_document": policy_document,
            "public_access_reasons": bucket_public_exposure_reasons(
                bucket_acl,
                public_policy=public_policy,
            ),
            "public_exposure_reasons": bucket_public_exposure_reasons(
                bucket_acl,
                public_policy=public_policy,
            ),
        },
    )


def normalize_s3_bucket_policy(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    policy_document = load_json_document(values.get("policy"))
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=values.get("id") or resource.address,
        policy_statements=parse_policy_statements(policy_document),
        metadata={
            "bucket": values.get("bucket"),
            "policy_document": policy_document,
        },
    )


def normalize_s3_bucket_public_access_block(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=values.get("id") or values.get("bucket") or resource.address,
        metadata={
            "bucket": values.get("bucket"),
            "block_public_acls": bool(values.get("block_public_acls", False)),
            "block_public_policy": bool(values.get("block_public_policy", False)),
            "ignore_public_acls": bool(values.get("ignore_public_acls", False)),
            "restrict_public_buckets": bool(values.get("restrict_public_buckets", False)),
        },
    )


def normalize_kms_key(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    policy_document = load_json_document(values.get("policy"))
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=values.get("key_id") or values.get("id"),
        arn=values.get("arn"),
        policy_statements=parse_policy_statements(policy_document),
        data_sensitivity="sensitive",
        metadata={
            "policy_document": policy_document,
            "key_usage": values.get("key_usage"),
            "enable_key_rotation": bool(values.get("enable_key_rotation", False)),
        },
    )


def normalize_sns_topic(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    policy_document = load_json_document(values.get("policy"))
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=values.get("name") or values.get("id"),
        arn=values.get("arn"),
        policy_statements=parse_policy_statements(policy_document),
        metadata={
            "policy_document": policy_document,
            "display_name": values.get("display_name"),
        },
    )


def normalize_sqs_queue(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    policy_document = load_json_document(values.get("policy"))
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=values.get("name") or values.get("id"),
        arn=values.get("arn"),
        policy_statements=parse_policy_statements(policy_document),
        metadata={
            "policy_document": policy_document,
            "queue_url": values.get("url"),
        },
    )


def normalize_secretsmanager_secret(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=values.get("name") or values.get("id"),
        arn=values.get("arn"),
        data_sensitivity="sensitive",
        metadata={
            "name": values.get("name"),
            "kms_key_id": values.get("kms_key_id"),
        },
    )


def normalize_secretsmanager_secret_policy(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    policy_document = load_json_document(values.get("policy"))
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=values.get("id") or resource.address,
        policy_statements=parse_policy_statements(policy_document),
        metadata={
            "secret_arn": values.get("secret_arn"),
            "policy_document": policy_document,
        },
    )
