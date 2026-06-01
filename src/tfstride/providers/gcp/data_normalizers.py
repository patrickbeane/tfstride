from __future__ import annotations

import ipaddress
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.gcp.coercion import as_bool, as_list, first_item
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.network_normalizers import GCP_PROVIDER
from tfstride.providers.gcp.resource_utils import first_non_empty, resource_identifier, resource_name


def normalize_storage_bucket(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=resource_identifier(resource),
        data_sensitivity="sensitive",
        metadata={
            GcpResourceMetadata.NAME.key: resource_name(resource),
            GcpResourceMetadata.BUCKET_NAME.key: resource_name(resource),
            GcpResourceMetadata.SELF_LINK.key: values.get("self_link"),
            GcpResourceMetadata.PROJECT.key: values.get("project"),
            GcpResourceMetadata.LABELS.key: values.get("labels") or {},
            GcpResourceMetadata.UNIFORM_BUCKET_LEVEL_ACCESS.key: as_bool(values.get("uniform_bucket_level_access")),
            GcpResourceMetadata.PUBLIC_ACCESS_PREVENTION.key: values.get("public_access_prevention"),
            "location": values.get("location"),
            "storage_class": values.get("storage_class"),
            "force_destroy": as_bool(values.get("force_destroy")),
        },
    )


def normalize_secret_manager_secret(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    secret_id = first_non_empty(values.get("secret_id"), values.get("name"), resource.name)
    project = first_non_empty(
        values.get("project"),
        _project_from_resource_path(values.get("name")),
        _project_from_resource_path(values.get("id")),
    )
    name = first_non_empty(values.get("name"), _secret_resource_name(project, secret_id))
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=first_non_empty(values.get("id"), name, secret_id, resource.address),
        data_sensitivity="sensitive",
        metadata={
            GcpResourceMetadata.NAME.key: name,
            GcpResourceMetadata.SECRET_ID.key: secret_id,
            GcpResourceMetadata.PROJECT.key: project,
            GcpResourceMetadata.LABELS.key: values.get("labels") or {},
            "annotations": values.get("annotations") or {},
            "replication": as_list(values.get("replication")),
            "topics": as_list(values.get("topics")),
            "expire_time": values.get("expire_time"),
            "ttl": values.get("ttl"),
            "version_destroy_ttl": values.get("version_destroy_ttl"),
            "storage_encrypted": True,
        },
    )


def normalize_kms_crypto_key(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    key_ring = first_non_empty(values.get("key_ring"))
    name = first_non_empty(values.get("name"), resource.name)
    identifier = first_non_empty(values.get("id"), values.get("self_link"), name, resource.address)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=identifier,
        data_sensitivity="sensitive",
        metadata={
            GcpResourceMetadata.NAME.key: name,
            GcpResourceMetadata.SELF_LINK.key: values.get("self_link"),
            GcpResourceMetadata.PROJECT.key: first_non_empty(
                values.get("project"),
                _project_from_resource_path(key_ring),
            ),
            GcpResourceMetadata.KMS_CRYPTO_KEY_REFERENCE.key: identifier,
            GcpResourceMetadata.KMS_KEY_RING.key: key_ring,
            GcpResourceMetadata.KMS_PURPOSE.key: values.get("purpose"),
            GcpResourceMetadata.KMS_ROTATION_PERIOD.key: values.get("rotation_period"),
            GcpResourceMetadata.LABELS.key: values.get("labels") or {},
            "destroy_scheduled_duration": values.get("destroy_scheduled_duration"),
            "import_only": as_bool(values.get("import_only", False)),
            "skip_initial_version_creation": as_bool(values.get("skip_initial_version_creation", False)),
            "storage_encrypted": True,
        },
    )


def normalize_sql_database_instance(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    settings = first_item(values.get("settings")) or {}
    ip_configuration = first_item(settings.get("ip_configuration")) or {}
    backup_configuration = first_item(settings.get("backup_configuration")) or {}
    authorized_networks = _authorized_networks(ip_configuration)
    public_authorized_networks = [
        network for network in authorized_networks if _authorized_network_allows_internet(network)
    ]
    ipv4_enabled = as_bool(ip_configuration.get("ipv4_enabled", bool(authorized_networks)))
    public_exposure = ipv4_enabled and bool(public_authorized_networks)
    public_access_reasons = ["Cloud SQL public IPv4 access is enabled"] if ipv4_enabled else []
    public_exposure_reasons = [
        f"authorized network `{_network_name(network)}` allows {_network_value(network)}"
        for network in public_authorized_networks
    ]
    private_network = first_non_empty(ip_configuration.get("private_network"))
    backup_enabled = as_bool(backup_configuration.get("enabled", False))
    pitr_enabled = as_bool(backup_configuration.get("point_in_time_recovery_enabled", False))
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
            GcpResourceMetadata.NAME.key: resource_name(resource),
            GcpResourceMetadata.SELF_LINK.key: values.get("self_link"),
            GcpResourceMetadata.PROJECT.key: values.get("project"),
            GcpResourceMetadata.REGION.key: values.get("region"),
            GcpResourceMetadata.DATABASE_VERSION.key: values.get("database_version"),
            GcpResourceMetadata.CLOUD_SQL_PRIVATE_NETWORK.key: private_network,
            GcpResourceMetadata.CLOUD_SQL_SSL_MODE.key: ip_configuration.get("ssl_mode"),
            GcpResourceMetadata.CLOUD_SQL_IPV4_ENABLED.key: ipv4_enabled,
            GcpResourceMetadata.CLOUD_SQL_BACKUP_ENABLED.key: backup_enabled,
            GcpResourceMetadata.CLOUD_SQL_POINT_IN_TIME_RECOVERY_ENABLED.key: pitr_enabled,
            GcpResourceMetadata.CLOUD_SQL_REQUIRE_SSL.key: as_bool(ip_configuration.get("require_ssl", False)),
            GcpResourceMetadata.CLOUD_SQL_AUTHORIZED_NETWORKS.key: authorized_networks,
            GcpResourceMetadata.CLOUD_SQL_BACKUP_CONFIGURATION.key: backup_configuration,
            GcpResourceMetadata.CLOUD_SQL_IP_CONFIGURATION.key: ip_configuration,
            GcpResourceMetadata.DELETION_PROTECTION.key: as_bool(values.get("deletion_protection", False)),
            GcpResourceMetadata.LABELS.key: values.get("labels") or {},
            "availability_type": settings.get("availability_type"),
            "tier": settings.get("tier"),
            "disk_type": settings.get("disk_type"),
            "disk_size": settings.get("disk_size"),
            "public_access_reasons": public_access_reasons,
            "public_exposure_reasons": public_exposure_reasons,
            "publicly_accessible": ipv4_enabled,
            "storage_encrypted": True,
        },
    )
    normalized.direct_internet_reachable = public_exposure
    normalized.internet_ingress_capable = public_exposure
    normalized.internet_ingress_reasons = public_exposure_reasons
    return normalized


def _secret_resource_name(project: object, secret_id: str | None) -> str | None:
    if not project or not secret_id:
        return None
    return f"projects/{project}/secrets/{secret_id}"


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


def _authorized_networks(ip_configuration: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        network
        for network in as_list(ip_configuration.get("authorized_networks"))
        if isinstance(network, dict)
    ]


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
    return first_non_empty(network.get("name"), "unnamed") or "unnamed"


def _network_value(network: dict[str, Any]) -> str:
    return first_non_empty(network.get("value")) or "unknown"