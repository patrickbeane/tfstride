# tfSTRIDE Threat Model Report

- Analyzed file: `sample_azure_compute_plan.json`
- Provider: `azure`
- Normalized resources: `10`
- Unsupported resources: `0`

## Summary

This run identified **1 trust boundaries** and **3 findings** across **10 normalized resources**.

- High severity findings: `0`
- Medium severity findings: `3`
- Low severity findings: `0`

## Analysis Coverage

- Terraform resources seen: `10`
- Provider resources considered: `10`
- Normalized resources: `10`
- Unsupported resources: `0`
- Registered rules: `202`
- Enabled rules: `202`
- Disabled rules: `0`
- Severity overrides: `0`
- Unresolved in-plan references: `0`
- Findings by rule:
  - `azure-public-compute-broad-ingress`: `1`
  - `azure-nsg-flow-logs-not-configured`: `2`

## Discovered Trust Boundaries

### `internet-to-service`

- Source: `internet`
- Target: `azurerm_linux_virtual_machine.web`
- Description: Traffic can cross from the public internet to azurerm_linux_virtual_machine.web.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

## Findings

### High

No findings in this severity band.

### Medium

#### Azure Network Security Group lacks flow-log coverage

- STRIDE category: Repudiation
- Affected resources: `azurerm_network_security_group.web_subnet`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +0, lateral_movement +2, blast_radius +1, final_score 3 => medium
- Rationale: azurerm_network_security_group.web_subnet does not have a resolved azurerm_network_watcher_flow_log targeting the NSG in this Terraform plan. Network traffic metadata for incident response, threat hunting, and segmentation review may be unavailable unless NSG flow logs are configured elsewhere.
- Recommended mitigation: Configure an `azurerm_network_watcher_flow_log` for the NSG, route logs to durable storage, and keep retention long enough for incident response and network investigation workflows.
- Evidence:
  - target network security group: address=azurerm_network_security_group.web_subnet; resource_type=azurerm_network_security_group; identifier=/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/tfstride/providers/Microsoft.Network/networkSecurityGroups/web-subnet; name=web-subnet
  - flow log coverage: target_nsg_identifier=/subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/tfstride/providers/microsoft.network/networksecuritygroups/web-subnet; target_nsg_identifier=azurerm_network_security_group.web_subnet; target_nsg_identifier=azurerm_network_security_group.web_subnet.id; target_nsg_identifier=web-subnet; resolved_nsg_flow_log_count=0; azurerm_network_watcher_flow_log resources are not modeled

#### Azure Network Security Group lacks flow-log coverage

- STRIDE category: Repudiation
- Affected resources: `azurerm_network_security_group.web_nic`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +0, lateral_movement +2, blast_radius +1, final_score 3 => medium
- Rationale: azurerm_network_security_group.web_nic does not have a resolved azurerm_network_watcher_flow_log targeting the NSG in this Terraform plan. Network traffic metadata for incident response, threat hunting, and segmentation review may be unavailable unless NSG flow logs are configured elsewhere.
- Recommended mitigation: Configure an `azurerm_network_watcher_flow_log` for the NSG, route logs to durable storage, and keep retention long enough for incident response and network investigation workflows.
- Evidence:
  - target network security group: address=azurerm_network_security_group.web_nic; resource_type=azurerm_network_security_group; identifier=/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/tfstride/providers/Microsoft.Network/networkSecurityGroups/web-nic; name=web-nic
  - flow log coverage: target_nsg_identifier=/subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/tfstride/providers/microsoft.network/networksecuritygroups/web-nic; target_nsg_identifier=azurerm_network_security_group.web_nic; target_nsg_identifier=azurerm_network_security_group.web_nic.id; target_nsg_identifier=web-nic; resolved_nsg_flow_log_count=0; azurerm_network_watcher_flow_log resources are not modeled

#### Internet-exposed Azure virtual machine permits broad ingress

- STRIDE category: Spoofing
- Affected resources: `azurerm_linux_virtual_machine.web`, `azurerm_network_interface.web`, `azurerm_public_ip.web`, `azurerm_network_security_group.web_nic`, `azurerm_network_security_group.web_subnet`
- Trust boundary: `internet-to-service:internet->azurerm_linux_virtual_machine.web`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +0, lateral_movement +1, blast_radius +1, final_score 4 => medium
- Rationale: azurerm_linux_virtual_machine.web has a public-IP path and the effective Azure NSG decisions across its subnet and network interface permit administrative access or all ports from internet sources. This exposes the guest to direct probing and credential attacks.
- Recommended mitigation: Remove the public IP where possible, restrict subnet and NIC NSG rules to expected client CIDRs and service ports, and use Azure Bastion, VPN, or Just-In-Time VM access for administration.
- Evidence:
  - public ip path: azurerm_linux_virtual_machine.web -> azurerm_network_interface.web -> azurerm_public_ip.web (203.0.113.10)
  - network security path: azurerm_linux_virtual_machine.web -> azurerm_network_interface.web -> azurerm_network_security_group.web_nic; azurerm_linux_virtual_machine.web -> azurerm_network_interface.web -> azurerm_network_security_group.web_subnet
  - network security rules: azurerm_network_security_group.web_nic rule allow-ssh priority 200 allows tcp 22 from Internet; azurerm_network_security_group.web_subnet rule allow-internet-tcp priority 300 allows tcp 0-65535 from Internet
  - public exposure reasons: virtual machine has a public IP path and effective subnet/NIC NSG decisions allow internet ingress

### Low

No findings in this severity band.

## Limitations / Unsupported Resources

- Azure support currently covers AzureRM storage posture, Key Vault network and privileged-access posture, SQL Database posture (public network access, firewall, TLS, security alerting), PostgreSQL Flexible Server posture (public network access, firewall, TLS/SSL, geo-redundant backup), Private Endpoint coverage for supported data-plane resources, AKS control-plane posture findings, and public virtual-machine exposure through public-IP, NIC, subnet, and NSG relationships; broader Azure RBAC hierarchy, MySQL, Private Endpoint DNS correctness, load-balancer, and broader platform-service modeling are not implemented yet.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
