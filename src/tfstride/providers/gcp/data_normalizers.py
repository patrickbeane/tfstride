from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.coercion import (
    STATE_CONFIGURED,
    STATE_DISABLED,
    STATE_ENABLED,
    STATE_NOT_CONFIGURED,
    STATE_UNKNOWN,
    as_list,
    as_optional_int,
    known_block_bool,
    known_block_string,
    value_is_unknown,
)
from tfstride.providers.gcp.attributes import GcpAttr, GcpAttribute, GcpValues
from tfstride.providers.gcp.coercion import as_bool, dedupe, first_item
from tfstride.providers.gcp.data_rule_utils import gcp_duration_seconds
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.network_normalizers import GCP_PROVIDER
from tfstride.providers.gcp.resource_mutations import gcp_mutations
from tfstride.providers.gcp.resource_utils import first_non_empty, resource_identifier, resource_name
from tfstride.providers.kubernetes import block_value, first_unknown_block


def normalize_storage_bucket(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    versioning_values = _first_block(values, GcpAttr.VERSIONING)
    encryption_values = _first_block(values, GcpAttr.ENCRYPTION)
    retention_policy_values = _first_block(values, GcpAttr.RETENTION_POLICY)
    versioning = GcpValues(versioning_values)
    encryption = GcpValues(encryption_values)
    retention_policy = GcpValues(retention_policy_values)
    default_kms_key_name = first_non_empty(encryption.get(GcpAttr.DEFAULT_KMS_KEY_NAME))
    retention_period_seconds = retention_policy.get(GcpAttr.RETENTION_PERIOD)
    retention_policy_locked = _optional_raw_bool(retention_policy_values, GcpAttr.IS_LOCKED.key)
    return _with_storage_encrypted(
        NormalizedResource(
            address=resource.address,
            provider=GCP_PROVIDER,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.DATA,
            identifier=resource_identifier(resource),
            data_sensitivity="sensitive",
            metadata={
                GcpResourceMetadata.NAME: resource_name(resource),
                GcpResourceMetadata.BUCKET_NAME: resource_name(resource),
                GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
                GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
                GcpResourceMetadata.LABELS: values.get(GcpAttr.LABELS),
                GcpResourceMetadata.UNIFORM_BUCKET_LEVEL_ACCESS: as_bool(
                    values.get(GcpAttr.UNIFORM_BUCKET_LEVEL_ACCESS)
                ),
                GcpResourceMetadata.PUBLIC_ACCESS_PREVENTION: values.get(GcpAttr.PUBLIC_ACCESS_PREVENTION),
                GcpResourceMetadata.GCS_VERSIONING_ENABLED: as_bool(versioning.get(GcpAttr.ENABLED)),
                GcpResourceMetadata.GCS_VERSIONING_CONFIGURATION: versioning_values,
                GcpResourceMetadata.GCS_DEFAULT_KMS_KEY_NAME: default_kms_key_name,
                GcpResourceMetadata.GCS_ENCRYPTION_CONFIGURATION: encryption_values,
                GcpResourceMetadata.GCS_RETENTION_PERIOD_SECONDS: retention_period_seconds,
                GcpResourceMetadata.GCS_RETENTION_POLICY_LOCKED: retention_policy_locked,
                GcpResourceMetadata.GCS_RETENTION_POLICY_CONFIGURATION: retention_policy_values,
                GcpResourceMetadata.GCS_RETENTION_POLICY_UNCERTAINTIES: _retention_policy_uncertainties(
                    resource.unknown_values
                ),
                "location": values.get(GcpAttr.LOCATION),
                "storage_class": values.get(GcpAttr.STORAGE_CLASS),
                "force_destroy": as_bool(values.get(GcpAttr.FORCE_DESTROY)),
                GcpResourceMetadata.CUSTOMER_MANAGED_ENCRYPTION: bool(default_kms_key_name),
            },
        )
    )


def normalize_secret_manager_secret(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    secret_id = first_non_empty(values.get(GcpAttr.SECRET_ID), values.get(GcpAttr.NAME), resource.name)
    project = first_non_empty(
        values.get(GcpAttr.PROJECT),
        _project_from_resource_path(values.get(GcpAttr.NAME)),
        _project_from_resource_path(values.get(GcpAttr.ID)),
    )
    name = first_non_empty(values.get(GcpAttr.NAME), _secret_resource_name(project, secret_id))
    replication_mode, replication, kms_key_names, uncertainties, customer_managed_encryption = (
        _secret_manager_replication_posture(values, resource.unknown_values)
    )
    ttl = _secret_manager_lifecycle_value(values, resource.unknown_values, GcpAttr.TTL, uncertainties)
    expire_time = _secret_manager_lifecycle_value(values, resource.unknown_values, GcpAttr.EXPIRE_TIME, uncertainties)
    version_destroy_ttl = _secret_manager_lifecycle_value(
        values,
        resource.unknown_values,
        GcpAttr.VERSION_DESTROY_TTL,
        uncertainties,
    )
    metadata: dict[object, object] = {
        GcpResourceMetadata.NAME: name,
        GcpResourceMetadata.SECRET_ID: secret_id,
        GcpResourceMetadata.PROJECT: project,
        GcpResourceMetadata.LABELS: values.get(GcpAttr.LABELS),
        GcpResourceMetadata.SECRET_MANAGER_REPLICATION_MODE: replication_mode,
        GcpResourceMetadata.SECRET_MANAGER_KMS_KEY_NAMES: kms_key_names,
        GcpResourceMetadata.SECRET_MANAGER_REPLICATION: replication,
        GcpResourceMetadata.SECRET_MANAGER_POSTURE_UNCERTAINTIES: uncertainties,
        GcpResourceMetadata.SECRET_MANAGER_TTL: ttl,
        GcpResourceMetadata.SECRET_MANAGER_EXPIRE_TIME: expire_time,
        GcpResourceMetadata.SECRET_MANAGER_VERSION_DESTROY_TTL: version_destroy_ttl,
        "annotations": values.get(GcpAttr.ANNOTATIONS),
        "topics": values.get(GcpAttr.TOPICS),
    }
    if customer_managed_encryption is not None:
        metadata[GcpResourceMetadata.CUSTOMER_MANAGED_ENCRYPTION] = customer_managed_encryption
    return _with_storage_encrypted(
        NormalizedResource(
            address=resource.address,
            provider=GCP_PROVIDER,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.DATA,
            identifier=first_non_empty(values.get(GcpAttr.ID), name, secret_id, resource.address),
            data_sensitivity="sensitive",
            metadata=metadata,
        )
    )


def normalize_pubsub_topic(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    name = first_non_empty(values.get(GcpAttr.NAME), resource.name)
    identifier = first_non_empty(values.get(GcpAttr.ID), name, resource.address)
    uncertainties: list[str] = []
    kms_key_name, cmek_state = _pubsub_cmek_posture(resource, uncertainties)
    message_retention_duration, message_retention_seconds, message_retention_state = _pubsub_message_retention_posture(
        resource,
        uncertainties,
    )
    metadata: dict[object, object] = {
        GcpResourceMetadata.NAME: name,
        GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
        GcpResourceMetadata.PUBSUB_TOPIC_REFERENCE: identifier,
        GcpResourceMetadata.LABELS: values.get(GcpAttr.LABELS),
        GcpResourceMetadata.PUBSUB_TOPIC_KMS_KEY_NAME: kms_key_name,
        GcpResourceMetadata.PUBSUB_TOPIC_CMEK_STATE: cmek_state,
        GcpResourceMetadata.PUBSUB_TOPIC_MESSAGE_RETENTION_DURATION: message_retention_duration,
        GcpResourceMetadata.PUBSUB_TOPIC_MESSAGE_RETENTION_SECONDS: message_retention_seconds,
        GcpResourceMetadata.PUBSUB_TOPIC_MESSAGE_RETENTION_STATE: message_retention_state,
        GcpResourceMetadata.PUBSUB_TOPIC_MESSAGE_STORAGE_POLICY: values.get(GcpAttr.MESSAGE_STORAGE_POLICY),
        GcpResourceMetadata.PUBSUB_TOPIC_SCHEMA_SETTINGS: values.get(GcpAttr.SCHEMA_SETTINGS),
        GcpResourceMetadata.PUBSUB_POSTURE_UNCERTAINTIES: uncertainties,
    }
    if cmek_state != STATE_UNKNOWN:
        metadata[GcpResourceMetadata.CUSTOMER_MANAGED_ENCRYPTION] = cmek_state == STATE_CONFIGURED
    return _with_storage_encrypted(
        NormalizedResource(
            address=resource.address,
            provider=GCP_PROVIDER,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.DATA,
            identifier=identifier,
            data_sensitivity="sensitive",
            metadata=metadata,
        )
    )


def normalize_pubsub_subscription(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    name = first_non_empty(values.get(GcpAttr.NAME), resource.name)
    identifier = first_non_empty(values.get(GcpAttr.ID), name, resource.address)
    topic_reference = first_non_empty(values.get(GcpAttr.TOPIC))
    uncertainties: list[str] = []
    message_retention_duration, message_retention_seconds, message_retention_state = _pubsub_message_retention_posture(
        resource,
        uncertainties,
    )
    (
        dead_letter_policy,
        dead_letter_policy_state,
        dead_letter_topic,
        dead_letter_max_delivery_attempts,
    ) = _pubsub_dead_letter_posture(resource, uncertainties)
    return _with_storage_encrypted(
        NormalizedResource(
            address=resource.address,
            provider=GCP_PROVIDER,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.DATA,
            identifier=identifier,
            data_sensitivity="sensitive",
            metadata={
                GcpResourceMetadata.NAME: name,
                GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
                GcpResourceMetadata.PUBSUB_SUBSCRIPTION_REFERENCE: identifier,
                GcpResourceMetadata.PUBSUB_TOPIC_REFERENCE: topic_reference,
                GcpResourceMetadata.LABELS: values.get(GcpAttr.LABELS),
                GcpResourceMetadata.PUBSUB_SUBSCRIPTION_ACK_DEADLINE_SECONDS: as_optional_int(
                    values.raw(GcpAttr.ACK_DEADLINE_SECONDS)
                ),
                GcpResourceMetadata.PUBSUB_SUBSCRIPTION_DEAD_LETTER_POLICY: dead_letter_policy,
                GcpResourceMetadata.PUBSUB_SUBSCRIPTION_DEAD_LETTER_POLICY_STATE: dead_letter_policy_state,
                GcpResourceMetadata.PUBSUB_SUBSCRIPTION_DEAD_LETTER_TOPIC: dead_letter_topic,
                GcpResourceMetadata.PUBSUB_SUBSCRIPTION_DEAD_LETTER_MAX_DELIVERY_ATTEMPTS: (
                    dead_letter_max_delivery_attempts
                ),
                GcpResourceMetadata.PUBSUB_SUBSCRIPTION_EXPIRATION_POLICY: values.get(GcpAttr.EXPIRATION_POLICY),
                GcpResourceMetadata.PUBSUB_SUBSCRIPTION_FILTER: values.get(GcpAttr.FILTER),
                GcpResourceMetadata.PUBSUB_SUBSCRIPTION_MESSAGE_RETENTION_DURATION: message_retention_duration,
                GcpResourceMetadata.PUBSUB_SUBSCRIPTION_MESSAGE_RETENTION_SECONDS: message_retention_seconds,
                GcpResourceMetadata.PUBSUB_SUBSCRIPTION_MESSAGE_RETENTION_STATE: message_retention_state,
                GcpResourceMetadata.PUBSUB_SUBSCRIPTION_PUSH_CONFIG: values.get(GcpAttr.PUSH_CONFIG),
                GcpResourceMetadata.PUBSUB_SUBSCRIPTION_RETAIN_ACKED_MESSAGES: as_bool(
                    values.get(GcpAttr.RETAIN_ACKED_MESSAGES)
                ),
                GcpResourceMetadata.PUBSUB_SUBSCRIPTION_RETRY_POLICY: values.get(GcpAttr.RETRY_POLICY),
                GcpResourceMetadata.PUBSUB_POSTURE_UNCERTAINTIES: uncertainties,
            },
        )
    )


def _pubsub_cmek_posture(
    resource: TerraformResource,
    uncertainties: list[str],
) -> tuple[str | None, str]:
    if value_is_unknown(resource.unknown_values.get(GcpAttr.KMS_KEY_NAME.key)):
        uncertainties.append("kms_key_name is unknown after planning")
        return None, STATE_UNKNOWN

    raw_key_name = resource.values.get(GcpAttr.KMS_KEY_NAME.key)
    if raw_key_name is None:
        return None, STATE_NOT_CONFIGURED
    if not isinstance(raw_key_name, str):
        uncertainties.append("kms_key_name has an unrecognized value shape")
        return None, STATE_UNKNOWN

    key_name = raw_key_name.strip()
    if not key_name:
        return None, STATE_NOT_CONFIGURED
    return key_name, STATE_CONFIGURED


def _pubsub_message_retention_posture(
    resource: TerraformResource,
    uncertainties: list[str],
) -> tuple[str | None, int | None, str]:
    if value_is_unknown(resource.unknown_values.get(GcpAttr.MESSAGE_RETENTION_DURATION.key)):
        uncertainties.append("message_retention_duration is unknown after planning")
        return None, None, STATE_UNKNOWN

    raw_duration = resource.values.get(GcpAttr.MESSAGE_RETENTION_DURATION.key)
    if raw_duration is None:
        return None, None, STATE_NOT_CONFIGURED
    if not isinstance(raw_duration, str):
        uncertainties.append("message_retention_duration has an unrecognized value shape")
        return None, None, STATE_UNKNOWN

    duration = raw_duration.strip()
    if not duration:
        return None, None, STATE_NOT_CONFIGURED
    seconds = gcp_duration_seconds(duration)
    if seconds is None:
        uncertainties.append("message_retention_duration has an unrecognized duration")
        return duration, None, STATE_UNKNOWN
    return duration, seconds, STATE_CONFIGURED


def _pubsub_dead_letter_posture(
    resource: TerraformResource,
    uncertainties: list[str],
) -> tuple[list[dict[str, Any]], str, str | None, int | None]:
    values = GcpValues(resource.values)
    policy = values.get(GcpAttr.DEAD_LETTER_POLICY)
    unknown_policy = resource.unknown_values.get(GcpAttr.DEAD_LETTER_POLICY.key)
    if unknown_policy is True:
        uncertainties.append("dead_letter_policy is unknown after planning")
        return policy, STATE_UNKNOWN, None, None
    if not policy:
        return [], STATE_NOT_CONFIGURED, None, None

    first_policy = first_item(policy)
    if first_policy is None:
        uncertainties.append("dead_letter_policy has an unrecognized value shape")
        return policy, STATE_UNKNOWN, None, None

    unknown_block = first_unknown_block(unknown_policy)
    topic_unknown = value_is_unknown(block_value(unknown_block, "dead_letter_topic"))
    attempts_unknown = value_is_unknown(block_value(unknown_block, "max_delivery_attempts"))
    if topic_unknown:
        uncertainties.append("dead_letter_policy.dead_letter_topic is unknown after planning")
    if attempts_unknown:
        uncertainties.append("dead_letter_policy.max_delivery_attempts is unknown after planning")

    raw_topic = first_policy.get("dead_letter_topic")
    dead_letter_topic = raw_topic.strip() if isinstance(raw_topic, str) and raw_topic.strip() else None
    if dead_letter_topic is None and not topic_unknown:
        uncertainties.append("dead_letter_policy.dead_letter_topic is not represented in the Terraform plan")

    raw_attempts = first_policy.get("max_delivery_attempts")
    max_delivery_attempts = None if attempts_unknown else as_optional_int(raw_attempts)
    if raw_attempts is not None and max_delivery_attempts is None and not attempts_unknown:
        uncertainties.append("dead_letter_policy.max_delivery_attempts has an unrecognized value shape")

    state = STATE_CONFIGURED if dead_letter_topic is not None and not topic_unknown else STATE_UNKNOWN
    return policy, state, dead_letter_topic, max_delivery_attempts


def normalize_bigquery_dataset(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    dataset_id = first_non_empty(values.get(GcpAttr.DATASET_ID), values.get(GcpAttr.NAME), resource.name)
    project = first_non_empty(values.get(GcpAttr.PROJECT), _project_from_resource_path(values.get(GcpAttr.ID)))
    name = first_non_empty(values.get(GcpAttr.ID), _bigquery_dataset_resource_name(project, dataset_id), dataset_id)
    encryption = GcpValues(_first_block(values, GcpAttr.DEFAULT_ENCRYPTION_CONFIGURATION))
    default_kms_key_name = first_non_empty(encryption.get(GcpAttr.KMS_KEY_NAME))
    return _with_storage_encrypted(
        NormalizedResource(
            address=resource.address,
            provider=GCP_PROVIDER,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.DATA,
            identifier=first_non_empty(values.get(GcpAttr.ID), name, dataset_id, resource.address),
            data_sensitivity="sensitive",
            metadata={
                GcpResourceMetadata.NAME: name,
                GcpResourceMetadata.PROJECT: project,
                GcpResourceMetadata.BIGQUERY_DATASET_ID: dataset_id,
                GcpResourceMetadata.BIGQUERY_DATASET_REFERENCE: first_non_empty(
                    values.get(GcpAttr.ID), name, dataset_id
                ),
                GcpResourceMetadata.BIGQUERY_DEFAULT_KMS_KEY_NAME: default_kms_key_name,
                GcpResourceMetadata.LABELS: values.get(GcpAttr.LABELS),
                "delete_contents_on_destroy": as_bool(values.get(GcpAttr.DELETE_CONTENTS_ON_DESTROY)),
                "default_table_expiration_ms": values.raw(GcpAttr.DEFAULT_TABLE_EXPIRATION_MS),
                "description": values.get(GcpAttr.DESCRIPTION),
                "friendly_name": values.get(GcpAttr.FRIENDLY_NAME),
                "location": values.get(GcpAttr.LOCATION),
                "max_time_travel_hours": values.raw(GcpAttr.MAX_TIME_TRAVEL_HOURS),
                "storage_billing_model": values.get(GcpAttr.STORAGE_BILLING_MODEL),
                GcpResourceMetadata.CUSTOMER_MANAGED_ENCRYPTION: bool(default_kms_key_name),
            },
        )
    )


def normalize_bigquery_table(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    dataset_id = first_non_empty(values.get(GcpAttr.DATASET_ID), values.get(GcpAttr.DATASET))
    table_id = first_non_empty(values.get(GcpAttr.TABLE_ID), values.get(GcpAttr.NAME), resource.name)
    project = first_non_empty(values.get(GcpAttr.PROJECT), _project_from_resource_path(values.get(GcpAttr.ID)))
    name = first_non_empty(
        values.get(GcpAttr.ID), _bigquery_table_resource_name(project, dataset_id, table_id), table_id
    )
    encryption = GcpValues(_first_block(values, GcpAttr.ENCRYPTION_CONFIGURATION))
    default_kms_key_name = first_non_empty(encryption.get(GcpAttr.KMS_KEY_NAME))
    return _with_storage_encrypted(
        NormalizedResource(
            address=resource.address,
            provider=GCP_PROVIDER,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.DATA,
            identifier=first_non_empty(values.get(GcpAttr.ID), name, table_id, resource.address),
            data_sensitivity="sensitive",
            metadata={
                GcpResourceMetadata.NAME: name,
                GcpResourceMetadata.PROJECT: project,
                GcpResourceMetadata.BIGQUERY_DATASET_ID: dataset_id,
                GcpResourceMetadata.BIGQUERY_DATASET_REFERENCE: dataset_id,
                GcpResourceMetadata.BIGQUERY_TABLE_ID: table_id,
                GcpResourceMetadata.BIGQUERY_TABLE_REFERENCE: first_non_empty(values.get(GcpAttr.ID), name, table_id),
                GcpResourceMetadata.BIGQUERY_DEFAULT_KMS_KEY_NAME: default_kms_key_name,
                GcpResourceMetadata.LABELS: values.get(GcpAttr.LABELS),
                "clustering": values.get(GcpAttr.CLUSTERING),
                "deletion_protection": as_bool(values.get(GcpAttr.DELETION_PROTECTION)),
                "description": values.get(GcpAttr.DESCRIPTION),
                "friendly_name": values.get(GcpAttr.FRIENDLY_NAME),
                "schema": values.raw(GcpAttr.SCHEMA),
                "time_partitioning": values.get(GcpAttr.TIME_PARTITIONING),
                "view": values.get(GcpAttr.VIEW),
                GcpResourceMetadata.CUSTOMER_MANAGED_ENCRYPTION: bool(default_kms_key_name),
            },
        )
    )


def normalize_kms_crypto_key(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    key_ring = first_non_empty(values.get(GcpAttr.KEY_RING))
    name = first_non_empty(values.get(GcpAttr.NAME), resource.name)
    identifier = first_non_empty(values.get(GcpAttr.ID), values.get(GcpAttr.SELF_LINK), name, resource.address)
    rotation_period, posture_uncertainties = _kms_rotation_period(values, resource.unknown_values)
    destroy_scheduled_duration = _kms_destroy_scheduled_duration(
        values,
        resource.unknown_values,
        posture_uncertainties,
    )
    return _with_storage_encrypted(
        NormalizedResource(
            address=resource.address,
            provider=GCP_PROVIDER,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.DATA,
            identifier=identifier,
            data_sensitivity="sensitive",
            metadata={
                GcpResourceMetadata.NAME: name,
                GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
                GcpResourceMetadata.PROJECT: first_non_empty(
                    values.get(GcpAttr.PROJECT),
                    _project_from_resource_path(key_ring),
                ),
                GcpResourceMetadata.KMS_CRYPTO_KEY_REFERENCE: identifier,
                GcpResourceMetadata.KMS_KEY_RING: key_ring,
                GcpResourceMetadata.KMS_PURPOSE: values.get(GcpAttr.PURPOSE),
                GcpResourceMetadata.KMS_ROTATION_PERIOD: rotation_period,
                GcpResourceMetadata.KMS_DESTROY_SCHEDULED_DURATION: destroy_scheduled_duration,
                GcpResourceMetadata.KMS_POSTURE_UNCERTAINTIES: posture_uncertainties,
                GcpResourceMetadata.LABELS: values.get(GcpAttr.LABELS),
                "import_only": as_bool(values.get(GcpAttr.IMPORT_ONLY)),
                "skip_initial_version_creation": as_bool(values.get(GcpAttr.SKIP_INITIAL_VERSION_CREATION)),
            },
        )
    )


def normalize_sql_database_instance(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    settings_values = _first_block(values, GcpAttr.SETTINGS)
    settings = GcpValues(settings_values)
    ip_configuration_values = _first_block(settings, GcpAttr.IP_CONFIGURATION)
    backup_configuration_values = _first_block(settings, GcpAttr.BACKUP_CONFIGURATION)
    ip_configuration = GcpValues(ip_configuration_values)
    backup_configuration = GcpValues(backup_configuration_values)
    settings_unknown = first_unknown_block(resource.unknown_values.get(GcpAttr.SETTINGS.key))
    insights_config_values = _first_block(settings, GcpAttr.INSIGHTS_CONFIG)
    insights_config_unknown = first_unknown_block(block_value(settings_unknown, GcpAttr.INSIGHTS_CONFIG.key))
    cloud_sql_posture_uncertainties: list[str] = []
    availability_type = known_block_string(
        settings_values,
        settings_unknown,
        GcpAttr.AVAILABILITY_TYPE.key,
        cloud_sql_posture_uncertainties,
        path=GcpAttr.SETTINGS.key,
    )
    connector_enforcement = known_block_string(
        settings_values,
        settings_unknown,
        GcpAttr.CONNECTOR_ENFORCEMENT.key,
        cloud_sql_posture_uncertainties,
        path=GcpAttr.SETTINGS.key,
    )
    cloud_sql_deletion_protection_enabled = known_block_bool(
        settings_values,
        settings_unknown,
        GcpAttr.DELETION_PROTECTION_ENABLED.key,
        cloud_sql_posture_uncertainties,
        path=GcpAttr.SETTINGS.key,
    )
    query_insights_enabled = known_block_bool(
        insights_config_values,
        insights_config_unknown,
        GcpAttr.QUERY_INSIGHTS_ENABLED.key,
        cloud_sql_posture_uncertainties,
        path=f"{GcpAttr.SETTINGS.key}.{GcpAttr.INSIGHTS_CONFIG.key}",
    )
    authorized_networks = _authorized_networks(ip_configuration)
    public_authorized_networks = [
        network for network in authorized_networks if _authorized_network_allows_internet(network)
    ]
    ipv4_enabled = _bool_with_default(ip_configuration, GcpAttr.IPV4_ENABLED, bool(authorized_networks))
    public_exposure = ipv4_enabled and bool(public_authorized_networks)
    public_access_reasons = ["Cloud SQL public IPv4 access is enabled"] if ipv4_enabled else []
    public_exposure_reasons = [
        f"authorized network `{_network_name(network)}` allows {_network_value(network)}"
        for network in public_authorized_networks
    ]
    private_network = first_non_empty(ip_configuration.get(GcpAttr.PRIVATE_NETWORK))
    backup_enabled = as_bool(backup_configuration.get(GcpAttr.ENABLED))
    pitr_enabled = as_bool(backup_configuration.get(GcpAttr.POINT_IN_TIME_RECOVERY_ENABLED))
    normalized = NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=resource_identifier(resource),
        vpc_id=private_network,
        public_access_configured=ipv4_enabled,
        public_exposure=public_exposure,
        data_sensitivity="sensitive",
        metadata={
            GcpResourceMetadata.NAME: resource_name(resource),
            GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
            GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
            GcpResourceMetadata.REGION: values.get(GcpAttr.REGION),
            GcpResourceMetadata.DATABASE_VERSION: values.get(GcpAttr.DATABASE_VERSION),
            GcpResourceMetadata.CLOUD_SQL_PRIVATE_NETWORK: private_network,
            GcpResourceMetadata.CLOUD_SQL_SSL_MODE: ip_configuration.get(GcpAttr.SSL_MODE),
            GcpResourceMetadata.CLOUD_SQL_AVAILABILITY_TYPE: availability_type,
            GcpResourceMetadata.CLOUD_SQL_CONNECTOR_ENFORCEMENT: connector_enforcement,
            GcpResourceMetadata.CLOUD_SQL_QUERY_INSIGHTS_ENABLED: query_insights_enabled,
            GcpResourceMetadata.CLOUD_SQL_QUERY_INSIGHTS_STATE: _query_insights_state(
                insights_config_values,
                insights_config_unknown,
                query_insights_enabled,
            ),
            GcpResourceMetadata.CLOUD_SQL_INSIGHTS_CONFIG: insights_config_values,
            GcpResourceMetadata.CLOUD_SQL_DELETION_PROTECTION_ENABLED: cloud_sql_deletion_protection_enabled,
            GcpResourceMetadata.CLOUD_SQL_DELETION_PROTECTION_STATE: _cloud_sql_deletion_protection_state(
                cloud_sql_deletion_protection_enabled
            ),
            GcpResourceMetadata.CLOUD_SQL_POSTURE_UNCERTAINTIES: cloud_sql_posture_uncertainties,
            GcpResourceMetadata.CLOUD_SQL_IPV4_ENABLED: ipv4_enabled,
            GcpResourceMetadata.CLOUD_SQL_BACKUP_ENABLED: backup_enabled,
            GcpResourceMetadata.CLOUD_SQL_POINT_IN_TIME_RECOVERY_ENABLED: pitr_enabled,
            GcpResourceMetadata.CLOUD_SQL_REQUIRE_SSL: as_bool(ip_configuration.get(GcpAttr.REQUIRE_SSL)),
            GcpResourceMetadata.CLOUD_SQL_AUTHORIZED_NETWORKS: authorized_networks,
            GcpResourceMetadata.CLOUD_SQL_BACKUP_CONFIGURATION: backup_configuration_values,
            GcpResourceMetadata.CLOUD_SQL_IP_CONFIGURATION: ip_configuration_values,
            GcpResourceMetadata.DELETION_PROTECTION: as_bool(values.get(GcpAttr.DELETION_PROTECTION)),
            GcpResourceMetadata.LABELS: values.get(GcpAttr.LABELS),
            "tier": settings.get(GcpAttr.TIER),
            "disk_type": settings.get(GcpAttr.DISK_TYPE),
            "disk_size": settings.raw(GcpAttr.DISK_SIZE),
        },
    )
    mutations = gcp_mutations(normalized)
    mutations.set_public_access(configured=ipv4_enabled, reasons=public_access_reasons)
    mutations.set_public_endpoint_posture(
        direct_internet_reachable=public_exposure,
        internet_ingress_capable=public_exposure,
        internet_ingress_reasons=public_exposure_reasons,
    )
    mutations.set_public_exposure(public_exposure, reasons=public_exposure_reasons)
    mutations.set_publicly_accessible(ipv4_enabled)
    mutations.set_storage_encrypted(True)
    return normalized


def _query_insights_state(
    insights_config: Mapping[str, Any],
    unknown_insights_config: Any,
    query_insights_enabled: bool | None,
) -> str:
    if unknown_insights_config is True:
        return STATE_UNKNOWN
    if query_insights_enabled is None:
        return STATE_UNKNOWN if insights_config or unknown_insights_config else STATE_NOT_CONFIGURED
    return STATE_ENABLED if query_insights_enabled else STATE_DISABLED


def _cloud_sql_deletion_protection_state(enabled: bool | None) -> str:
    if enabled is None:
        return STATE_UNKNOWN
    return STATE_ENABLED if enabled else STATE_DISABLED


def _first_block(values: GcpValues, attribute: GcpAttribute[Any]) -> dict[str, Any]:
    return first_item(values.get(attribute)) or {}


def _bool_with_default(values: GcpValues, attribute: GcpAttribute[Any], default: bool) -> bool:
    if not values.has(attribute):
        return default
    return as_bool(values.raw(attribute))


def _optional_raw_bool(values: Mapping[str, Any], key: str) -> bool | None:
    if key not in values:
        return None
    return as_bool(values.get(key))


def _kms_rotation_period(values: GcpValues, unknown_values: Mapping[str, Any]) -> tuple[str | None, list[str]]:
    if value_is_unknown(unknown_values.get(GcpAttr.ROTATION_PERIOD.key)):
        return None, ["rotation_period is unknown after planning"]
    return values.get(GcpAttr.ROTATION_PERIOD), []


def _kms_destroy_scheduled_duration(
    values: GcpValues,
    unknown_values: Mapping[str, Any],
    uncertainties: list[str],
) -> str | None:
    if value_is_unknown(unknown_values.get(GcpAttr.DESTROY_SCHEDULED_DURATION.key)):
        uncertainties.append("destroy_scheduled_duration is unknown after planning")
        return None
    value = values.raw(GcpAttr.DESTROY_SCHEDULED_DURATION)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _retention_policy_uncertainties(unknown_values: Mapping[str, Any]) -> list[str]:
    retention_unknown = unknown_values.get(GcpAttr.RETENTION_POLICY.key)
    if retention_unknown is True:
        return ["retention_policy is unknown after planning"]
    retention_block = first_item(retention_unknown)
    if not isinstance(retention_block, Mapping):
        return []

    uncertainties: list[str] = []
    for field_name in (GcpAttr.RETENTION_PERIOD.key, GcpAttr.IS_LOCKED.key):
        if retention_block.get(field_name) is True:
            uncertainties.append(f"retention_policy.{field_name} is unknown after planning")
    return uncertainties


def _secret_manager_lifecycle_value(
    values: GcpValues,
    unknown_values: Mapping[str, Any],
    attribute: GcpAttribute[str | None],
    uncertainties: list[str],
) -> str | None:
    if value_is_unknown(unknown_values.get(attribute.key)):
        uncertainties.append(f"{attribute.key} is unknown after planning")
        return None
    return values.get(attribute)


def _secret_manager_replication_posture(
    values: GcpValues,
    unknown_values: Mapping[str, Any],
) -> tuple[str, dict[str, Any], list[str], list[str], bool | None]:
    uncertainties: list[str] = []
    replication_unknown = unknown_values.get(GcpAttr.REPLICATION.key)
    if replication_unknown is True:
        uncertainties.append("replication is unknown after planning")
        return "unknown", {}, [], uncertainties, None

    replication_blocks = values.get(GcpAttr.REPLICATION)
    if not replication_blocks:
        uncertainties.append("replication is not represented in the Terraform plan")
        return "unknown", {}, [], uncertainties, None

    replication_block = first_item(replication_blocks)
    unknown_block = _first_unknown_mapping(replication_unknown)
    if not isinstance(replication_block, Mapping):
        uncertainties.append("replication has an unrecognized value shape")
        return "unknown", {}, [], uncertainties, None

    if "auto" in replication_block:
        return _automatic_secret_replication_posture(replication_block, unknown_block, uncertainties)
    if "user_managed" in replication_block:
        return _user_managed_secret_replication_posture(replication_block, unknown_block, uncertainties)

    uncertainties.append("replication mode is not represented in the Terraform plan")
    return "unknown", {}, [], uncertainties, None


def _automatic_secret_replication_posture(
    replication_block: Mapping[str, Any],
    unknown_block: Mapping[str, Any] | None,
    uncertainties: list[str],
) -> tuple[str, dict[str, Any], list[str], list[str], bool | None]:
    unknown_auto = _unknown_child(unknown_block, "auto")
    if unknown_auto is True:
        uncertainties.append("replication.auto is unknown after planning")
        return "automatic", {"mode": "automatic"}, [], uncertainties, None

    auto_block = first_item(replication_block.get("auto")) or {}
    auto_unknown = _first_unknown_mapping(unknown_auto)
    kms_key_names = _secret_manager_cmek_key_names(
        auto_block.get("customer_managed_encryption"),
        _unknown_child(auto_unknown, "customer_managed_encryption"),
        "replication.auto.customer_managed_encryption",
        uncertainties,
    )
    replication = {"mode": "automatic"}
    if kms_key_names:
        replication["kms_key_names"] = kms_key_names
    return (
        "automatic",
        replication,
        kms_key_names,
        uncertainties,
        _customer_managed_encryption_state(
            kms_key_names,
            uncertainties,
        ),
    )


def _user_managed_secret_replication_posture(
    replication_block: Mapping[str, Any],
    unknown_block: Mapping[str, Any] | None,
    uncertainties: list[str],
) -> tuple[str, dict[str, Any], list[str], list[str], bool | None]:
    unknown_user_managed = _unknown_child(unknown_block, "user_managed")
    if unknown_user_managed is True:
        uncertainties.append("replication.user_managed is unknown after planning")
        return "user_managed", {"mode": "user_managed"}, [], uncertainties, None

    user_managed_block = first_item(replication_block.get("user_managed")) or {}
    user_managed_unknown = _first_unknown_mapping(unknown_user_managed)
    replicas = as_list(user_managed_block.get("replicas"))
    unknown_replicas = _unknown_child(user_managed_unknown, "replicas")
    if unknown_replicas is True:
        uncertainties.append("replication.user_managed.replicas is unknown after planning")
        return "user_managed", {"mode": "user_managed"}, [], uncertainties, None

    replication: dict[str, Any] = {"mode": "user_managed"}
    replica_evidence: list[dict[str, Any]] = []
    kms_key_names: list[str] = []
    unknown_replica_blocks = as_list(unknown_replicas)
    for index, replica in enumerate(replicas):
        if not isinstance(replica, Mapping):
            uncertainties.append(f"replication.user_managed.replicas[{index}] has an unrecognized value shape")
            continue
        unknown_replica = unknown_replica_blocks[index] if index < len(unknown_replica_blocks) else None
        unknown_fields: list[str] = []
        item: dict[str, Any] = {}
        location = first_non_empty(replica.get(GcpAttr.LOCATION.key))
        if location is not None:
            item["location"] = location
        replica_kms_key_names = _secret_manager_cmek_key_names(
            replica.get("customer_managed_encryption"),
            _unknown_child(_first_unknown_mapping(unknown_replica), "customer_managed_encryption"),
            f"replication.user_managed.replicas[{index}].customer_managed_encryption",
            uncertainties,
            unknown_fields=unknown_fields,
        )
        if replica_kms_key_names:
            item["kms_key_names"] = replica_kms_key_names
            kms_key_names.extend(replica_kms_key_names)
        if unknown_fields:
            item["unknown_fields"] = unknown_fields
        if item:
            replica_evidence.append(item)
    if replica_evidence:
        replication["replicas"] = replica_evidence
    if kms_key_names:
        replication["kms_key_names"] = dedupe(kms_key_names)
    return (
        "user_managed",
        replication,
        dedupe(kms_key_names),
        uncertainties,
        _customer_managed_encryption_state(
            kms_key_names,
            uncertainties,
        ),
    )


def _secret_manager_cmek_key_names(
    blocks: Any,
    unknown_blocks: Any,
    path: str,
    uncertainties: list[str],
    *,
    unknown_fields: list[str] | None = None,
) -> list[str]:
    if unknown_blocks is True:
        uncertainties.append(f"{path} is unknown after planning")
        if unknown_fields is not None:
            unknown_fields.append("customer_managed_encryption")
        return []

    key_names: list[str] = []
    unknown_block_values = as_list(unknown_blocks)
    for index, block in enumerate(as_list(blocks)):
        if not isinstance(block, Mapping):
            uncertainties.append(f"{path}[{index}] has an unrecognized value shape")
            continue
        unknown_block = unknown_block_values[index] if index < len(unknown_block_values) else None
        if value_is_unknown(_unknown_child(_first_unknown_mapping(unknown_block), GcpAttr.KMS_KEY_NAME.key)):
            uncertainties.append(f"{path}[{index}].kms_key_name is unknown after planning")
            if unknown_fields is not None:
                unknown_fields.append("kms_key_name")
            continue
        kms_key_name = first_non_empty(block.get(GcpAttr.KMS_KEY_NAME.key))
        if kms_key_name is not None:
            key_names.append(kms_key_name)
    return dedupe(key_names)


def _customer_managed_encryption_state(kms_key_names: list[str], uncertainties: list[str]) -> bool | None:
    if kms_key_names:
        return True
    if uncertainties:
        return None
    return False


def _first_unknown_mapping(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    item = first_item(value)
    return item if isinstance(item, Mapping) else None


def _unknown_child(value: Mapping[str, Any] | None, key: str) -> Any:
    if value is None:
        return None
    return value.get(key)


def _with_storage_encrypted(resource: NormalizedResource) -> NormalizedResource:
    gcp_mutations(resource).set_storage_encrypted(True)
    return resource


def _secret_resource_name(project: object, secret_id: str | None) -> str | None:
    if not project or not secret_id:
        return None
    return f"projects/{project}/secrets/{secret_id}"


def _bigquery_dataset_resource_name(project: object, dataset_id: str | None) -> str | None:
    if not project or not dataset_id:
        return None
    return f"projects/{project}/datasets/{dataset_id}"


def _bigquery_table_resource_name(project: object, dataset_id: str | None, table_id: str | None) -> str | None:
    if not project or not dataset_id or not table_id:
        return None
    return f"projects/{project}/datasets/{dataset_id}/tables/{table_id}"


def _project_from_resource_path(value: object) -> str | None:
    text = first_non_empty(value)
    if text is None:
        return None
    parts = text.split("/")
    try:
        project_index = parts.index("projects") + 1
    except ValueError:
        return None
    if project_index >= len(parts):
        return None
    return first_non_empty(parts[project_index])


def _authorized_networks(ip_configuration: GcpValues) -> list[dict[str, Any]]:
    return ip_configuration.get(GcpAttr.AUTHORIZED_NETWORKS)


def _authorized_network_allows_internet(network: dict[str, Any]) -> bool:
    value = _network_value(network)
    if not value:
        return False
    try:
        parsed = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return parsed.prefixlen == 0


def _network_name(network: dict[str, Any]) -> str:
    return first_non_empty(GcpValues(network).get(GcpAttr.NAME), "unnamed") or "unnamed"


def _network_value(network: dict[str, Any]) -> str:
    return first_non_empty(GcpValues(network).get(GcpAttr.VALUE)) or "unknown"
