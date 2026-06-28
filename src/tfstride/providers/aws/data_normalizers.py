from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.aws.coercion import as_list
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.network_normalizers import AWS_PROVIDER
from tfstride.providers.aws.policy_documents import parse_policy_statements
from tfstride.providers.aws.resource_mutations import aws_mutations
from tfstride.providers.aws.resource_utils import bucket_public_exposure_reasons
from tfstride.providers.coercion import first_mapping, known_block_bool_state, known_block_string
from tfstride.providers.json_documents import load_json_document
from tfstride.resource_helpers import policy_allows_public_access


def normalize_db_instance(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    publicly_accessible = bool(values.get("publicly_accessible", False))
    public_access_reasons = ["database instance is marked publicly_accessible"] if publicly_accessible else []
    normalized = NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=values.get("id") or values.get("identifier"),
        arn=values.get("arn"),
        security_group_ids=tuple(as_list(values.get("vpc_security_group_ids"))),
        public_access_configured=publicly_accessible,
        data_sensitivity="sensitive",
        metadata={
            AwsResourceMetadata.ENGINE: values.get("engine"),
            "db_subnet_group_name": values.get("db_subnet_group_name"),
        },
    )
    mutations = aws_mutations(normalized)
    mutations.set_publicly_accessible(publicly_accessible)
    mutations.set_public_access_reasons(public_access_reasons)
    mutations.set_public_exposure_reasons([])
    mutations.set_storage_encrypted(bool(values.get("storage_encrypted", False)))
    return normalized


def normalize_s3_bucket(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    policy_document = load_json_document(values.get("policy"))
    bucket_acl = values.get("acl", "")
    public_policy = policy_allows_public_access(policy_document)
    public_access_configured = bucket_acl in {"public-read", "public-read-write", "website"} or public_policy
    public_reasons = bucket_public_exposure_reasons(bucket_acl, public_policy=public_policy)
    normalized = NormalizedResource(
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
            AwsResourceMetadata.BUCKET_NAME: values.get("bucket"),
            AwsResourceMetadata.BUCKET_ACL: bucket_acl,
            AwsResourceMetadata.POLICY_DOCUMENT: policy_document,
        },
    )
    mutations = aws_mutations(normalized)
    mutations.set_public_access_reasons(public_reasons)
    mutations.set_public_exposure_reasons(public_reasons)
    return normalized


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
            AwsResourceMetadata.BUCKET_NAME: values.get("bucket"),
            AwsResourceMetadata.POLICY_DOCUMENT: policy_document,
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
            AwsResourceMetadata.BUCKET_NAME: values.get("bucket"),
            AwsResourceMetadata.BLOCK_PUBLIC_ACLS: bool(values.get("block_public_acls", False)),
            AwsResourceMetadata.BLOCK_PUBLIC_POLICY: bool(values.get("block_public_policy", False)),
            AwsResourceMetadata.IGNORE_PUBLIC_ACLS: bool(values.get("ignore_public_acls", False)),
            AwsResourceMetadata.RESTRICT_PUBLIC_BUCKETS: bool(values.get("restrict_public_buckets", False)),
        },
    )


def normalize_s3_bucket_versioning(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    versioning_configuration = first_mapping(values.get("versioning_configuration"), scan_all=True)
    unknown_configuration = first_mapping(unknown_values.get("versioning_configuration"), scan_all=True)
    uncertainties: list[str] = []
    status = known_block_string(
        versioning_configuration,
        unknown_configuration,
        "status",
        uncertainties,
        path="versioning_configuration",
    )
    if versioning_configuration is None and unknown_values.get("versioning_configuration") is True:
        uncertainties.append("versioning_configuration is unknown after planning")

    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=values.get("id") or values.get("bucket") or resource.address,
        metadata={
            AwsResourceMetadata.BUCKET_NAME: values.get("bucket"),
            AwsResourceMetadata.S3_VERSIONING_STATUS: status,
            AwsResourceMetadata.S3_VERSIONING_CONFIGURATION: dict(versioning_configuration)
            if versioning_configuration is not None
            else None,
            AwsResourceMetadata.S3_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_s3_bucket_server_side_encryption_configuration(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    rule = first_mapping(values.get("rule"), scan_all=True)
    encryption_default = (
        first_mapping(rule.get("apply_server_side_encryption_by_default"), scan_all=True) if rule else None
    )
    unknown_rule = first_mapping(unknown_values.get("rule"), scan_all=True)
    unknown_encryption_default = (
        first_mapping(unknown_rule.get("apply_server_side_encryption_by_default"), scan_all=True)
        if unknown_rule
        else None
    )
    uncertainties: list[str] = []
    algorithm = known_block_string(
        encryption_default,
        unknown_encryption_default,
        "sse_algorithm",
        uncertainties,
        path="rule.apply_server_side_encryption_by_default",
    )
    kms_key_id = known_block_string(
        encryption_default,
        unknown_encryption_default,
        "kms_master_key_id",
        uncertainties,
        path="rule.apply_server_side_encryption_by_default",
    )
    bucket_key_state = known_block_bool_state(
        rule,
        unknown_rule,
        "bucket_key_enabled",
        uncertainties,
        path="rule",
    )
    if rule is None and unknown_values.get("rule") is True:
        uncertainties.append("rule is unknown after planning")

    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=values.get("id") or values.get("bucket") or resource.address,
        metadata={
            AwsResourceMetadata.BUCKET_NAME: values.get("bucket"),
            AwsResourceMetadata.S3_ENCRYPTION_ALGORITHM: algorithm,
            AwsResourceMetadata.S3_KMS_MASTER_KEY_ID: kms_key_id,
            AwsResourceMetadata.S3_BUCKET_KEY_ENABLED_STATE: bucket_key_state,
            AwsResourceMetadata.S3_SERVER_SIDE_ENCRYPTION_CONFIGURATION: _s3_encryption_configuration(rule),
            AwsResourceMetadata.S3_POSTURE_UNCERTAINTIES: uncertainties,
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
            AwsResourceMetadata.POLICY_DOCUMENT: policy_document,
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
            AwsResourceMetadata.POLICY_DOCUMENT: policy_document,
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
            AwsResourceMetadata.POLICY_DOCUMENT: policy_document,
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
            AwsResourceMetadata.POLICY_DOCUMENT: policy_document,
        },
    )


def _s3_encryption_configuration(rule: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if rule is None:
        return None
    return {"rule": [dict(rule)]}
