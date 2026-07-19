# tfSTRIDE Threat Model Report

- Analyzed file: `sample_azure_nsg_precedence_plan.json`
- Provider: `azure`
- Normalized resources: `7`
- Unsupported resources: `0`

## Summary

This run identified **0 trust boundaries** and **1 findings** across **7 normalized resources**.

- High severity findings: `0`
- Medium severity findings: `1`
- Low severity findings: `0`

## Analysis Coverage

- Terraform resources seen: `7`
- Provider resources considered: `7`
- Normalized resources: `7`
- Unsupported resources: `0`
- Registered rules: `248`
- Enabled rules: `248`
- Disabled rules: `0`
- Severity overrides: `0`
- Unresolved in-plan references: `0`
- Findings by rule:
  - `azure-nsg-flow-logs-not-configured`: `1`

## Discovered Trust Boundaries

No trust boundaries were discovered.

## Findings

### High

No findings in this severity band.

### Medium

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

### Low

No findings in this severity band.

## Limitations / Unsupported Resources

- Azure support currently covers AzureRM storage posture, Key Vault network and privileged-access posture, SQL Database posture (public network access, firewall, TLS, security alerting), PostgreSQL Flexible Server posture (public network access, firewall, TLS/SSL, geo-redundant backup), Private Endpoint coverage for supported data-plane resources, AKS control-plane posture findings, and public virtual-machine exposure through public-IP, NIC, subnet, and NSG relationships; broader Azure RBAC hierarchy, MySQL, Private Endpoint DNS correctness, load-balancer, and broader platform-service modeling are not implemented yet.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
