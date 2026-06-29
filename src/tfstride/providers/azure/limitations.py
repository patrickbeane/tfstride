from __future__ import annotations

AZURE_LIMITATIONS = (
    "Azure support currently covers AzureRM storage posture, Key Vault network and privileged-access posture, "
    "SQL Database posture (public network access, firewall, TLS, security alerting), PostgreSQL Flexible Server "
    "posture (public network access, firewall, TLS/SSL, geo-redundant backup), Private Endpoint coverage "
    "for supported data-plane resources, AKS control-plane posture findings, and public "
    "virtual-machine exposure through public-IP, NIC, subnet, and NSG relationships; broader Azure RBAC "
    "hierarchy, MySQL, Private Endpoint DNS correctness, load-balancer, and broader platform-service "
    "modeling are not implemented yet.",
)
