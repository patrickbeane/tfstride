from __future__ import annotations

import ipaddress
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.gcp.attributes import GcpAttr, GcpAttribute, GcpValues
from tfstride.providers.gcp.coercion import as_bool, first_item
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.network_normalizers import GCP_PROVIDER
from tfstride.providers.gcp.resource_mutations import gcp_mutations
from tfstride.providers.gcp.resource_utils import first_non_empty, resource_identifier, resource_name


def normalize_storage_bucket(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    versioning_values = _first_block(values, GcpAttr.VERSIONING)
    encryption_values = _first_block(values, GcpAttr.ENCRYPTION)
    versioning = GcpValues(versioning_values)
    encryption = GcpValues(encryption_values)
    default_kms_key_name = first_non_empty(encryption.get(GcpAttr.DEFAULT_KMS_KEY_NAME))
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
    return _with_storage_encrypted(
        NormalizedResource(
            address=resource.address,
            provider=GCP_PROVIDER,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.DATA,
            identifier=first_non_empty(values.get(GcpAttr.ID), name, secret_id, resource.address),
            data_sensitivity="sensitive",
            metadata={
                GcpResourceMetadata.NAME: name,
                GcpResourceMetadata.SECRET_ID: secret_id,
                GcpResourceMetadata.PROJECT: project,
                GcpResourceMetadata.LABELS: values.get(GcpAttr.LABELS),
                "annotations": values.get(GcpAttr.ANNOTATIONS),
                "replication": values.get(GcpAttr.REPLICATION),
                "topics": values.get(GcpAttr.TOPICS),
                "expire_time": values.get(GcpAttr.EXPIRE_TIME),
                "ttl": values.get(GcpAttr.TTL),
                "version_destroy_ttl": values.get(GcpAttr.VERSION_DESTROY_TTL),
            },
        )
    )


def normalize_pubsub_topic(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    name = first_non_empty(values.get(GcpAttr.NAME), resource.name)
    identifier = first_non_empty(values.get(GcpAttr.ID), name, resource.address)
    kms_key_name = first_non_empty(values.get(GcpAttr.KMS_KEY_NAME))
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
                GcpResourceMetadata.PUBSUB_TOPIC_REFERENCE: identifier,
                GcpResourceMetadata.LABELS: values.get(GcpAttr.LABELS),
                "kms_key_name": kms_key_name,
                "message_retention_duration": values.get(GcpAttr.MESSAGE_RETENTION_DURATION),
                "message_storage_policy": values.get(GcpAttr.MESSAGE_STORAGE_POLICY),
                "schema_settings": values.get(GcpAttr.SCHEMA_SETTINGS),
                GcpResourceMetadata.CUSTOMER_MANAGED_ENCRYPTION: bool(kms_key_name),
            },
        )
    )


def normalize_pubsub_subscription(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    name = first_non_empty(values.get(GcpAttr.NAME), resource.name)
    identifier = first_non_empty(values.get(GcpAttr.ID), name, resource.address)
    topic_reference = first_non_empty(values.get(GcpAttr.TOPIC))
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
                "ack_deadline_seconds": values.raw(GcpAttr.ACK_DEADLINE_SECONDS),
                "dead_letter_policy": values.get(GcpAttr.DEAD_LETTER_POLICY),
                "expiration_policy": values.get(GcpAttr.EXPIRATION_POLICY),
                "filter": values.get(GcpAttr.FILTER),
                "message_retention_duration": values.get(GcpAttr.MESSAGE_RETENTION_DURATION),
                "push_config": values.get(GcpAttr.PUSH_CONFIG),
                "retain_acked_messages": as_bool(values.get(GcpAttr.RETAIN_ACKED_MESSAGES)),
                "retry_policy": values.get(GcpAttr.RETRY_POLICY),
            },
        )
    )


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
                GcpResourceMetadata.KMS_ROTATION_PERIOD: values.get(GcpAttr.ROTATION_PERIOD),
                GcpResourceMetadata.LABELS: values.get(GcpAttr.LABELS),
                "destroy_scheduled_duration": values.raw(GcpAttr.DESTROY_SCHEDULED_DURATION),
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
            GcpResourceMetadata.CLOUD_SQL_IPV4_ENABLED: ipv4_enabled,
            GcpResourceMetadata.CLOUD_SQL_BACKUP_ENABLED: backup_enabled,
            GcpResourceMetadata.CLOUD_SQL_POINT_IN_TIME_RECOVERY_ENABLED: pitr_enabled,
            GcpResourceMetadata.CLOUD_SQL_REQUIRE_SSL: as_bool(ip_configuration.get(GcpAttr.REQUIRE_SSL)),
            GcpResourceMetadata.CLOUD_SQL_AUTHORIZED_NETWORKS: authorized_networks,
            GcpResourceMetadata.CLOUD_SQL_BACKUP_CONFIGURATION: backup_configuration_values,
            GcpResourceMetadata.CLOUD_SQL_IP_CONFIGURATION: ip_configuration_values,
            GcpResourceMetadata.DELETION_PROTECTION: as_bool(values.get(GcpAttr.DELETION_PROTECTION)),
            GcpResourceMetadata.LABELS: values.get(GcpAttr.LABELS),
            "availability_type": settings.get(GcpAttr.AVAILABILITY_TYPE),
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


def _first_block(values: GcpValues, attribute: GcpAttribute[Any]) -> dict[str, Any]:
    return first_item(values.get(attribute)) or {}


def _bool_with_default(values: GcpValues, attribute: GcpAttribute[Any], default: bool) -> bool:
    if not values.has(attribute):
        return default
    return as_bool(values.raw(attribute))


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
