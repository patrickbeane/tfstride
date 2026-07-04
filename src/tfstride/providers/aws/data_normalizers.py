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
from tfstride.providers.coercion import (
    as_optional_int,
    attribute_unknown,
    first_mapping,
    known_block_bool_state,
    known_block_int,
    known_block_string,
    known_bool,
    known_string,
)
from tfstride.providers.json_documents import load_json_document
from tfstride.resource_helpers import policy_allows_public_access

_RDS_STATE_ENABLED = "enabled"
_RDS_STATE_DISABLED = "disabled"
_RDS_STATE_UNKNOWN = "unknown"
_KMS_STATE_ENABLED = "enabled"
_KMS_STATE_DISABLED = "disabled"
_KMS_STATE_UNKNOWN = "unknown"


def _rds_bool_state(value: bool | None) -> str:
    if value is True:
        return _RDS_STATE_ENABLED
    if value is False:
        return _RDS_STATE_DISABLED
    return _RDS_STATE_UNKNOWN


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
        return _KMS_STATE_ENABLED
    if rotation_enabled is False:
        return _KMS_STATE_DISABLED
    if len(uncertainties) > previous_uncertainty_count:
        return _KMS_STATE_UNKNOWN
    return _KMS_STATE_DISABLED


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
