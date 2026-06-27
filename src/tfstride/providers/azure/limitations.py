from __future__ import annotations

AZURE_LIMITATIONS = (
    "Azure support currently covers AzureRM storage posture, Key Vault network and privileged-access posture, "
    "SQL Database posture (public network access, firewall, TLS, security alerting), and public virtual-machine "
    "exposure through public-IP, NIC, subnet, and NSG relationships; broader Azure RBAC hierarchy, database "
    "(PostgreSQL, MySQL), load-balancer, private-endpoint, and platform-service modeling are not implemented yet.",
)
