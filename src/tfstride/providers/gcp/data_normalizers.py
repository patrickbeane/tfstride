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