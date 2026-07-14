from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.aws.coercion import as_list
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.network_normalizers import AWS_PROVIDER
from tfstride.providers.aws.policy_documents import parse_policy_statements
from tfstride.providers.aws.resource_mutations import aws_mutations
from tfstride.providers.aws.resource_utils import bucket_public_exposure_reasons
from tfstride.providers.coercion import (
    STATE_CONFIGURED,
    STATE_DISABLED,
    STATE_ENABLED,
    STATE_NOT_CONFIGURED,
    STATE_UNKNOWN,
    as_optional_int,
    attribute_unknown,
    first_mapping,
    known_block_bool_state,
    known_block_int,
    known_block_string,
    known_bool,
    known_string,
    known_string_list,
)
from tfstride.providers.json_documents import load_json_document
from tfstride.resource_helpers import policy_allows_public_access


def _rds_bool_state(value: bool | None) -> str:
    if value is True:
        return STATE_ENABLED
    if value is False:
        return STATE_DISABLED
    return STATE_UNKNOWN


def _known_top_level_int(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    key: str,
    uncertainties: list[str],
) -> int | None:
    if attribute_unknown(unknown_values, key):
        uncertainties.append(f"{key} is unknown after planning")
        return None
    value = values.get(key)
    if value is None:
        return None
    if isinstance(value, bool):
        uncertainties.append(f"{key} has an unrecognized value shape")
        return None
    parsed = as_optional_int(value)
    if parsed is None:
        uncertainties.append(f"{key} has an unrecognized value shape")
    return parsed


def normalize_db_instance(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []

    publicly_accessible_value = known_bool(
        values,
        unknown_values,
        "publicly_accessible",
        uncertainties,
        allow_string=False,
    )
    deletion_protection = known_bool(
        values,
        unknown_values,
        "deletion_protection",
        uncertainties,
        allow_string=False,
    )
    multi_az = known_bool(
        values,
        unknown_values,
        "multi_az",
        uncertainties,
        allow_string=False,
    )
    publicly_accessible = publicly_accessible_value is True
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
            AwsResourceMetadata.RDS_PUBLICLY_ACCESSIBLE_STATE: _rds_bool_state(publicly_accessible_value),
            AwsResourceMetadata.RDS_BACKUP_RETENTION_PERIOD: _known_top_level_int(
                values,
                unknown_values,
                "backup_retention_period",
                uncertainties,
            ),
            AwsResourceMetadata.RDS_DELETION_PROTECTION_STATE: _rds_bool_state(deletion_protection),
            AwsResourceMetadata.RDS_MULTI_AZ_STATE: _rds_bool_state(multi_az),
            AwsResourceMetadata.RDS_KMS_KEY_ID: known_string(
                values,
                unknown_values,
                "kms_key_id",
                uncertainties,
            ),
            AwsResourceMetadata.RDS_PERFORMANCE_INSIGHTS_ENABLED_STATE: _rds_bool_state(
                known_bool(values, unknown_values, "performance_insights_enabled", uncertainties, allow_string=False)
            ),
            AwsResourceMetadata.RDS_ENABLED_CLOUDWATCH_LOGS_EXPORTS: known_string_list(
                values, unknown_values, "enabled_cloudwatch_logs_exports", uncertainties
            ),
            AwsResourceMetadata.RDS_IAM_DATABASE_AUTHENTICATION_ENABLED_STATE: _rds_bool_state(
                known_bool(
                    values,
                    unknown_values,
                    "iam_database_authentication_enabled",
                    uncertainties,
                    allow_string=False,
                )
            ),
            AwsResourceMetadata.RDS_POSTURE_UNCERTAINTIES: uncertainties,
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


def normalize_s3_bucket_object_lock_configuration(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    enabled_value = known_string(values, unknown_values, "object_lock_enabled", uncertainties)
    enabled_state = _s3_object_lock_enabled_state(enabled_value, uncertainties)
    rule = first_mapping(values.get("rule"), scan_all=True)
    unknown_rule = first_mapping(unknown_values.get("rule"), scan_all=True)
    default_retention = first_mapping(rule.get("default_retention"), scan_all=True) if rule else None
    unknown_default_retention = (
        first_mapping(unknown_rule.get("default_retention"), scan_all=True) if unknown_rule else None
    )
    mode = known_block_string(
        default_retention,
        unknown_default_retention,
        "mode",
        uncertainties,
        path="rule.default_retention",
    )
    days = known_block_int(
        default_retention,
        unknown_default_retention,
        "days",
        uncertainties,
        path="rule.default_retention",
    )
    years = known_block_int(
        default_retention,
        unknown_default_retention,
        "years",
        uncertainties,
        path="rule.default_retention",
    )
    if rule is None and unknown_values.get("rule") is True:
        uncertainties.append("rule is unknown after planning")
    if default_retention is None and unknown_rule and unknown_rule.get("default_retention") is True:
        uncertainties.append("rule.default_retention is unknown after planning")

    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=values.get("id") or values.get("bucket") or resource.address,
        metadata={
            AwsResourceMetadata.BUCKET_NAME: values.get("bucket"),
            AwsResourceMetadata.S3_OBJECT_LOCK_ENABLED_STATE: enabled_state,
            AwsResourceMetadata.S3_OBJECT_LOCK_DEFAULT_RETENTION_MODE: mode,
            AwsResourceMetadata.S3_OBJECT_LOCK_DEFAULT_RETENTION_DAYS: days,
            AwsResourceMetadata.S3_OBJECT_LOCK_DEFAULT_RETENTION_YEARS: years,
            AwsResourceMetadata.S3_OBJECT_LOCK_CONFIGURATION: _s3_object_lock_configuration(enabled_value, rule),
            AwsResourceMetadata.S3_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_s3_bucket_lifecycle_configuration(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    rules = _s3_lifecycle_rules(values.get("rule"), unknown_values.get("rule"), uncertainties)
    rule_count = None if unknown_values.get("rule") is True else len(rules)

    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=values.get("id") or values.get("bucket") or resource.address,
        metadata={
            AwsResourceMetadata.BUCKET_NAME: values.get("bucket"),
            AwsResourceMetadata.S3_LIFECYCLE_RULES: rules,
            AwsResourceMetadata.S3_LIFECYCLE_RULE_COUNT: rule_count,
            AwsResourceMetadata.S3_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_kms_key(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
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
            AwsResourceMetadata.KMS_KEY_USAGE: known_string(values, unknown_values, "key_usage", uncertainties),
            AwsResourceMetadata.KMS_KEY_SPEC: known_string(values, unknown_values, "key_spec", uncertainties),
            AwsResourceMetadata.KMS_CUSTOMER_MASTER_KEY_SPEC: known_string(
                values,
                unknown_values,
                "customer_master_key_spec",
                uncertainties,
            ),
            AwsResourceMetadata.KMS_ENABLE_KEY_ROTATION_STATE: _kms_rotation_state(
                values,
                unknown_values,
                uncertainties,
            ),
            AwsResourceMetadata.KMS_DELETION_WINDOW_IN_DAYS: _known_top_level_int(
                values,
                unknown_values,
                "deletion_window_in_days",
                uncertainties,
            ),
            AwsResourceMetadata.KMS_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_sns_topic(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    policy_document = load_json_document(values.get("policy"))
    uncertainties: list[str] = []
    kms_master_key_id = known_string(
        values,
        unknown_values,
        "kms_master_key_id",
        uncertainties,
        require_string=True,
    )
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
            AwsResourceMetadata.SNS_DISPLAY_NAME: known_string(
                values,
                unknown_values,
                "display_name",
                uncertainties,
                require_string=True,
            ),
            AwsResourceMetadata.SNS_KMS_MASTER_KEY_ID: kms_master_key_id,
            AwsResourceMetadata.SNS_ENCRYPTION_OWNERSHIP_STATE: _messaging_encryption_ownership_state(
                kms_master_key_id,
                service_managed_sse_state=None,
                uncertainties=uncertainties,
            ),
            AwsResourceMetadata.SNS_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_sqs_queue(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    policy_document = load_json_document(values.get("policy"))
    uncertainties: list[str] = []
    kms_master_key_id = known_string(
        values,
        unknown_values,
        "kms_master_key_id",
        uncertainties,
        require_string=True,
    )
    managed_sse_state = _sqs_managed_sse_enabled_state(values, unknown_values, uncertainties)
    redrive_state, redrive_target_arn, redrive_max_receive_count, redrive_policy = _sqs_redrive_posture(
        values,
        unknown_values,
        uncertainties,
    )
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
            AwsResourceMetadata.SQS_QUEUE_URL: known_string(
                values,
                unknown_values,
                "url",
                uncertainties,
                require_string=True,
            ),
            AwsResourceMetadata.SQS_KMS_MASTER_KEY_ID: kms_master_key_id,
            AwsResourceMetadata.SQS_MANAGED_SSE_ENABLED_STATE: managed_sse_state,
            AwsResourceMetadata.SQS_ENCRYPTION_OWNERSHIP_STATE: _messaging_encryption_ownership_state(
                kms_master_key_id,
                service_managed_sse_state=managed_sse_state,
                uncertainties=uncertainties,
            ),
            AwsResourceMetadata.SQS_MESSAGE_RETENTION_SECONDS: _known_top_level_int(
                values,
                unknown_values,
                "message_retention_seconds",
                uncertainties,
            ),
            AwsResourceMetadata.SQS_REDRIVE_STATE: redrive_state,
            AwsResourceMetadata.SQS_REDRIVE_TARGET_ARN: redrive_target_arn,
            AwsResourceMetadata.SQS_REDRIVE_MAX_RECEIVE_COUNT: redrive_max_receive_count,
            AwsResourceMetadata.SQS_REDRIVE_POLICY: redrive_policy,
            AwsResourceMetadata.SQS_REDRIVE_SOURCE_ADDRESS: resource.address,
            AwsResourceMetadata.SQS_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_sqs_queue_redrive_policy(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    redrive_state, redrive_target_arn, redrive_max_receive_count, redrive_policy = _sqs_redrive_posture(
        values,
        unknown_values,
        uncertainties,
    )
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=values.get("id") or values.get("queue_url") or resource.address,
        metadata={
            AwsResourceMetadata.SQS_QUEUE_URL: known_string(
                values,
                unknown_values,
                "queue_url",
                uncertainties,
                require_string=True,
            ),
            AwsResourceMetadata.SQS_REDRIVE_STATE: redrive_state,
            AwsResourceMetadata.SQS_REDRIVE_TARGET_ARN: redrive_target_arn,
            AwsResourceMetadata.SQS_REDRIVE_MAX_RECEIVE_COUNT: redrive_max_receive_count,
            AwsResourceMetadata.SQS_REDRIVE_POLICY: redrive_policy,
            AwsResourceMetadata.SQS_REDRIVE_SOURCE_ADDRESS: resource.address,
            AwsResourceMetadata.SQS_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def _sqs_managed_sse_enabled_state(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    uncertainties: list[str],
) -> str:
    if attribute_unknown(unknown_values, "sqs_managed_sse_enabled"):
        uncertainties.append("sqs_managed_sse_enabled is unknown after planning")
        return STATE_UNKNOWN
    if "sqs_managed_sse_enabled" not in values or values.get("sqs_managed_sse_enabled") is None:
        return STATE_NOT_CONFIGURED
    value = known_bool(
        values,
        unknown_values,
        "sqs_managed_sse_enabled",
        uncertainties,
        allow_string=False,
    )
    if value is True:
        return STATE_ENABLED
    if value is False:
        return STATE_DISABLED
    return STATE_UNKNOWN


def _messaging_encryption_ownership_state(
    kms_master_key_id: str | None,
    *,
    service_managed_sse_state: str | None,
    uncertainties: list[str],
) -> str:
    if kms_master_key_id:
        return "service_managed" if _is_aws_managed_messaging_key(kms_master_key_id) else "customer_managed"
    if service_managed_sse_state == STATE_ENABLED:
        return "service_managed"
    if uncertainties:
        return STATE_UNKNOWN
    return "absent"


def _is_aws_managed_messaging_key(value: str) -> bool:
    key_id = value.strip().lower()
    return "alias/aws/" in key_id or key_id.startswith("aws/")


def _sqs_redrive_posture(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    uncertainties: list[str],
) -> tuple[str, str | None, int | None, dict[str, Any]]:
    if attribute_unknown(unknown_values, "redrive_policy"):
        uncertainties.append("redrive_policy is unknown after planning")
        return STATE_UNKNOWN, None, None, {}

    raw_policy = values.get("redrive_policy")
    if raw_policy in (None, ""):
        return STATE_NOT_CONFIGURED, None, None, {}
    if isinstance(raw_policy, Mapping):
        policy = dict(raw_policy)
    elif isinstance(raw_policy, str):
        try:
            loaded = json.loads(raw_policy)
        except json.JSONDecodeError:
            uncertainties.append("redrive_policy is not valid JSON")
            return STATE_UNKNOWN, None, None, {}
        if not isinstance(loaded, dict):
            uncertainties.append("redrive_policy has an unrecognized value shape")
            return STATE_UNKNOWN, None, None, {}
        policy = loaded
    else:
        uncertainties.append("redrive_policy has an unrecognized value shape")
        return STATE_UNKNOWN, None, None, {}

    raw_target_arn = policy.get("deadLetterTargetArn")
    target_arn = raw_target_arn.strip() if isinstance(raw_target_arn, str) and raw_target_arn.strip() else None
    if target_arn is None:
        uncertainties.append("redrive_policy.deadLetterTargetArn is not represented in the Terraform plan")

    raw_max_receive_count = policy.get("maxReceiveCount")
    max_receive_count = None if isinstance(raw_max_receive_count, bool) else as_optional_int(raw_max_receive_count)
    if max_receive_count is None:
        uncertainties.append("redrive_policy.maxReceiveCount has an unrecognized value shape")

    if target_arn is None or max_receive_count is None:
        return STATE_UNKNOWN, target_arn, max_receive_count, policy
    return STATE_CONFIGURED, target_arn, max_receive_count, policy


def normalize_secretsmanager_secret(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
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
            AwsResourceMetadata.NAME: values.get("name"),
            AwsResourceMetadata.SECRETS_MANAGER_KMS_KEY_ID: known_string(
                values,
                unknown_values,
                "kms_key_id",
                uncertainties,
            ),
            AwsResourceMetadata.SECRETS_MANAGER_RECOVERY_WINDOW_IN_DAYS: _known_top_level_int(
                values,
                unknown_values,
                "recovery_window_in_days",
                uncertainties,
            ),
            AwsResourceMetadata.SECRETS_MANAGER_REPLICATION: _secrets_manager_replication(
                values.get("replica"), unknown_values.get("replica"), uncertainties
            ),
            AwsResourceMetadata.SECRETS_MANAGER_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_secretsmanager_secret_rotation(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    rotation_rules = first_mapping(values.get("rotation_rules"), scan_all=True)
    raw_unknown_rotation_rules = unknown_values.get("rotation_rules")
    unknown_rotation_rules = (
        None if raw_unknown_rotation_rules is True else first_mapping(raw_unknown_rotation_rules, scan_all=True)
    )
    if rotation_rules is None and raw_unknown_rotation_rules is True:
        uncertainties.append("rotation_rules is unknown after planning")

    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=values.get("id") or values.get("secret_id") or resource.address,
        metadata={
            AwsResourceMetadata.SECRETS_MANAGER_ROTATION_SECRET_ID: known_string(
                values,
                unknown_values,
                "secret_id",
                uncertainties,
            ),
            AwsResourceMetadata.SECRETS_MANAGER_ROTATION_LAMBDA_ARN: known_string(
                values,
                unknown_values,
                "rotation_lambda_arn",
                uncertainties,
            ),
            AwsResourceMetadata.SECRETS_MANAGER_ROTATION_AUTOMATICALLY_AFTER_DAYS: known_block_int(
                rotation_rules,
                unknown_rotation_rules,
                "automatically_after_days",
                uncertainties,
                path="rotation_rules",
            ),
            AwsResourceMetadata.SECRETS_MANAGER_ROTATION_DURATION: known_block_string(
                rotation_rules,
                unknown_rotation_rules,
                "duration",
                uncertainties,
                path="rotation_rules",
            ),
            AwsResourceMetadata.SECRETS_MANAGER_ROTATION_SCHEDULE_EXPRESSION: known_block_string(
                rotation_rules,
                unknown_rotation_rules,
                "schedule_expression",
                uncertainties,
                path="rotation_rules",
            ),
            AwsResourceMetadata.SECRETS_MANAGER_ROTATION_RULES: _secrets_manager_rotation_rules(rotation_rules),
            AwsResourceMetadata.SECRETS_MANAGER_POSTURE_UNCERTAINTIES: uncertainties,
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


def _kms_rotation_state(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    uncertainties: list[str],
) -> str:
    previous_uncertainty_count = len(uncertainties)
    rotation_enabled = known_bool(
        values,
        unknown_values,
        "enable_key_rotation",
        uncertainties,
        allow_string=False,
    )
    if rotation_enabled is True:
        return STATE_ENABLED
    if rotation_enabled is False:
        return STATE_DISABLED
    if len(uncertainties) > previous_uncertainty_count:
        return STATE_UNKNOWN
    return STATE_DISABLED


def _s3_object_lock_enabled_state(value: str | None, uncertainties: list[str]) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized == STATE_ENABLED:
        return STATE_ENABLED
    if normalized == STATE_DISABLED:
        return STATE_DISABLED
    uncertainties.append("object_lock_enabled has an unrecognized value")
    return None


def _s3_object_lock_configuration(enabled_value: str | None, rule: Mapping[str, Any] | None) -> dict[str, Any] | None:
    configuration: dict[str, Any] = {}
    if enabled_value is not None:
        configuration["object_lock_enabled"] = enabled_value
    if rule is not None:
        configuration["rule"] = [dict(rule)]
    return configuration or None


def _s3_lifecycle_rules(
    rule_value: Any,
    unknown_rule_value: Any,
    uncertainties: list[str],
) -> list[dict[str, Any]]:
    if unknown_rule_value is True:
        uncertainties.append("rule is unknown after planning")
        return []

    rule_blocks = as_list(rule_value)
    unknown_blocks = as_list(unknown_rule_value)
    rules: list[dict[str, Any]] = []
    for index, rule in enumerate(rule_blocks):
        if not isinstance(rule, Mapping):
            uncertainties.append(f"rule[{index}] has an unrecognized value shape")
            continue
        unknown_block = unknown_blocks[index] if index < len(unknown_blocks) else None
        if unknown_block is True:
            uncertainties.append(f"rule[{index}] is unknown after planning")
            continue
        evidence = dict(rule)
        unknown_fields = _unknown_field_names(unknown_block)
        if unknown_fields:
            evidence["unknown_fields"] = unknown_fields
        rules.append(evidence)
    return rules


def _unknown_field_names(unknown_block: Any) -> list[str]:
    if not isinstance(unknown_block, Mapping):
        return []
    return sorted(str(key) for key, value in unknown_block.items() if value is True)


def _secrets_manager_rotation_rules(rotation_rules: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if rotation_rules is None:
        return None
    return dict(rotation_rules)


def _s3_encryption_configuration(rule: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if rule is None:
        return None
    return {"rule": [dict(rule)]}


def _secrets_manager_replication(
    replica_value: Any,
    unknown_replica: Any,
    uncertainties: list[str],
) -> list[dict[str, Any]]:
    if unknown_replica is True:
        uncertainties.append("replica is unknown after planning")
        return []

    replica_blocks = as_list(replica_value)
    unknown_blocks = as_list(unknown_replica)
    replication: list[dict[str, Any]] = []
    for index, replica in enumerate(replica_blocks):
        if not isinstance(replica, Mapping):
            uncertainties.append(f"replica[{index}] has an unrecognized value shape")
            continue

        unknown_block = unknown_blocks[index] if index < len(unknown_blocks) else None
        unknown_fields: list[str] = []
        replica_evidence: dict[str, Any] = {}
        for key in ("region", "kms_key_id", "status"):
            value = known_block_string(
                replica,
                unknown_block,
                key,
                uncertainties,
                path=f"replica[{index}]",
                unknown_fields=unknown_fields,
            )
            if value is not None:
                replica_evidence[key] = value
        if unknown_fields:
            replica_evidence["unknown_fields"] = unknown_fields
        if replica_evidence:
            replication.append(replica_evidence)
    return replication
