from __future__ import annotations

from tfstride.providers.azure.network_normalizers.flow_logs import normalize_network_watcher_flow_log
from tfstride.providers.azure.network_normalizers.private_endpoint_dns import (
    normalize_private_dns_zone,
    normalize_private_dns_zone_virtual_network_link,
    normalize_private_endpoint,
)
from tfstride.providers.azure.network_normalizers.public_edge import (
    normalize_application_gateway,
    normalize_load_balancer,
    normalize_public_ip,
)
from tfstride.providers.azure.network_normalizers.vnet_nsg import (
    normalize_network_interface,
    normalize_network_interface_security_group_association,
    normalize_network_security_group,
    normalize_network_security_rule,
    normalize_subnet,
    normalize_subnet_network_security_group_association,
    normalize_virtual_network,
)

__all__ = [
    "normalize_application_gateway",
    "normalize_load_balancer",
    "normalize_network_interface",
    "normalize_network_interface_security_group_association",
    "normalize_network_security_group",
    "normalize_network_security_rule",
    "normalize_network_watcher_flow_log",
    "normalize_private_dns_zone",
    "normalize_private_dns_zone_virtual_network_link",
    "normalize_private_endpoint",
    "normalize_public_ip",
    "normalize_subnet",
    "normalize_subnet_network_security_group_association",
    "normalize_virtual_network",
]
