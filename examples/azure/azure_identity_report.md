# tfSTRIDE Threat Model Report

- Analyzed file: `sample_azure_identity_plan.json`
- Provider: `azure`
- Normalized resources: `13`
- Unsupported resources: `0`

## Summary

This run identified **1 trust boundaries** and **5 findings** across **13 normalized resources**.

- High severity findings: `2`
- Medium severity findings: `3`
- Low severity findings: `0`

## Analysis Coverage

- Terraform resources seen: `13`
- Provider resources considered: `13`
- Normalized resources: `13`
- Unsupported resources: `0`
- Registered rules: `248`
- Enabled rules: `248`
- Disabled rules: `0`
- Severity overrides: `0`
- Unresolved in-plan references: `0`
- Findings by rule:
  - `azure-public-compute-broad-ingress`: `1`
  - `azure-nsg-flow-logs-not-configured`: `1`
  - `azure-managed-identity-broad-rbac`: `1`
  - `azure-public-workload-sensitive-resource-access`: `1`
  - `azure-diagnostic-settings-missing`: `1`

## Discovered Trust Boundaries

### `internet-to-service`

- Source: `internet`
- Target: `azurerm_linux_virtual_machine.web`
- Description: Traffic can cross from the public internet to azurerm_linux_virtual_machine.web.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

## Findings

### High

#### Azure managed identity has broad RBAC authority

- STRIDE category: Elevation of Privilege
- Affected resources: `azurerm_user_assigned_identity.deploy`, `azurerm_role_assignment.subscription_owner`, `azurerm_role_assignment.storage_owner`, `azurerm_storage_account.logs`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +3, data_sensitivity +2, lateral_movement +1, blast_radius +2, final_score 8 => high
- Rationale: azurerm_user_assigned_identity.deploy has Azure role assignments with broad scope or high-impact built-in roles. These grants expand what the managed identity can do if the workload or deployment path using it is compromised.
- Recommended mitigation: Replace broad managed identity role assignments with least-privilege resource-scoped roles, split deployment and runtime identities, and avoid subscription or resource-group scope unless required.
- Evidence:
  - managed identity: address=azurerm_user_assigned_identity.deploy; identity_type=UserAssigned; principal_id=11111111-1111-1111-1111-111111111111; client_id=22222222-2222-2222-2222-222222222222
  - role assignments: source=azurerm_role_assignment.subscription_owner; role=Owner; scope=/subscriptions/00000000-0000-0000-0000-000000000000; scope_kind=subscription; signals=subscription_scope,broad_builtin_role; source=azurerm_role_assignment.storage_owner; role=Storage Blob Data Owner; scope=azurerm_storage_account.logs.id; scope_kind=resource; target=azurerm_storage_account.logs; signals=broad_builtin_role,sensitive_resource_scope
  - breadth signals: subscription_scope; broad_builtin_role; sensitive_resource_scope
  - privileged access: grant_1=role=Owner; categories=full-admin,iam-admin,policy-admin; scope_kind=subscription; confidence=high; grant_2=role=Storage Blob Data Owner; categories=data-admin; scope_kind=resource; confidence=high
  - privilege categories: full-admin; iam-admin; policy-admin; data-admin

#### Internet-exposed Azure workload can access sensitive resources

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_linux_virtual_machine.web`, `azurerm_user_assigned_identity.deploy`, `azurerm_role_assignment.storage_owner`, `azurerm_storage_account.logs`
- Trust boundary: `internet-to-service:internet->azurerm_linux_virtual_machine.web`
- Severity reasoning: internet_exposure +2, privilege_breadth +3, data_sensitivity +2, lateral_movement +1, blast_radius +2, final_score 10 => high
- Rationale: azurerm_user_assigned_identity.deploy is usable by an internet-exposed Azure workload and has a deterministic role assignment to a sensitive Azure resource. This creates a clear public workload to sensitive resource path if the workload identity is abused.
- Recommended mitigation: Remove direct internet exposure from the workload, restrict NSG ingress to trusted paths, and narrow the managed identity role assignment to the minimum sensitive resource operations required.
- Evidence:
  - public workloads: address=azurerm_linux_virtual_machine.web; public_exposure=true; public_exposure_reasons=virtual machine has a public IP path and effective subnet/NIC NSG decisions allow internet ingress
  - managed identity: address=azurerm_user_assigned_identity.deploy; identity_type=UserAssigned; principal_id=11111111-1111-1111-1111-111111111111; client_id=22222222-2222-2222-2222-222222222222
  - sensitive resource assignments: source=azurerm_role_assignment.storage_owner; role=Storage Blob Data Owner; scope=azurerm_storage_account.logs.id; scope_kind=resource; target=azurerm_storage_account.logs; signals=broad_builtin_role,sensitive_resource_scope

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

#### Azure resource lacks diagnostic settings

- STRIDE category: Repudiation
- Affected resources: `azurerm_storage_account.logs`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: azurerm_storage_account.logs has no resolved Azure Monitor diagnostic setting in this Terraform plan. Security-relevant data-plane, control-plane, or platform logs may not be routed to a retained logging destination for investigation and alerting.
- Recommended mitigation: Add an Azure Monitor diagnostic setting for the resource and route security-relevant logs and metrics to a retained Log Analytics workspace, storage account, Event Hub, or approved partner destination.
- Evidence:
  - target resource: address=azurerm_storage_account.logs; type=azurerm_storage_account; name=tfstrideidentitylogs; identifier=/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/tfstride/providers/Microsoft.Storage/storageAccounts/tfstrideidentitylogs
  - diagnostic coverage: no resolved azurerm_monitor_diagnostic_setting targets this resource

#### Internet-exposed Azure virtual machine permits broad ingress

- STRIDE category: Spoofing
- Affected resources: `azurerm_linux_virtual_machine.web`, `azurerm_network_interface.web`, `azurerm_public_ip.web`, `azurerm_network_security_group.web_nic`
- Trust boundary: `internet-to-service:internet->azurerm_linux_virtual_machine.web`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +0, lateral_movement +1, blast_radius +1, final_score 4 => medium
- Rationale: azurerm_linux_virtual_machine.web has a public-IP path and the effective Azure NSG decisions across its subnet and network interface permit administrative access or all ports from internet sources. This exposes the guest to direct probing and credential attacks.
- Recommended mitigation: Remove the public IP where possible, restrict subnet and NIC NSG rules to expected client CIDRs and service ports, and use Azure Bastion, VPN, or Just-In-Time VM access for administration.
- Evidence:
  - public ip path: azurerm_linux_virtual_machine.web -> azurerm_network_interface.web -> azurerm_public_ip.web (203.0.113.40)
  - network security path: azurerm_linux_virtual_machine.web -> azurerm_network_interface.web -> azurerm_network_security_group.web_nic
  - network security rules: azurerm_network_security_group.web_nic rule allow-ssh priority 200 allows tcp 22 from Internet
  - public exposure reasons: virtual machine has a public IP path and effective subnet/NIC NSG decisions allow internet ingress

### Low

No findings in this severity band.

## Controls Observed

### Azure managed identity principal is modeled

- Category: `iam`
- Affected resources: `azurerm_user_assigned_identity.deploy`
- Rationale: azurerm_user_assigned_identity.deploy exposes a `UserAssigned` managed identity principal. Role assignments are connected only when principal IDs are known in the Terraform plan.
- Evidence:
  - identity type: UserAssigned
  - principal id: 11111111-1111-1111-1111-111111111111
  - client id: 22222222-2222-2222-2222-222222222222
  - tenant id: 00000000-0000-0000-0000-000000000001
  - analysis scope: managed identity role assignments are connected when principal IDs are deterministic; transitive access findings are not emitted from managed identity assignments yet

### Azure managed identity principal is modeled

- Category: `iam`
- Affected resources: `azurerm_linux_virtual_machine.web`
- Rationale: azurerm_linux_virtual_machine.web exposes a `UserAssigned` managed identity principal. Role assignments are connected only when principal IDs are known in the Terraform plan.
- Evidence:
  - identity type: UserAssigned
  - attached identity references: azurerm_user_assigned_identity.deploy.id
  - analysis scope: managed identity role assignments are connected when principal IDs are deterministic; transitive access findings are not emitted from managed identity assignments yet

### Azure managed identity role assignment is connected

- Category: `iam`
- Affected resources: `azurerm_user_assigned_identity.deploy`, `azurerm_role_assignment.subscription_owner`, `azurerm_role_assignment.storage_owner`
- Rationale: azurerm_user_assigned_identity.deploy has Azure role assignments whose `principal_id` matches this managed identity. Scope breadth is reported separately from any downstream exposure rule.
- Evidence:
  - role assignment sources: azurerm_role_assignment.subscription_owner; azurerm_role_assignment.storage_owner
  - role definition names: Owner; Storage Blob Data Owner
  - scopes: /subscriptions/00000000-0000-0000-0000-000000000000; azurerm_storage_account.logs.id
  - scope kinds: subscription; resource
  - target resources: azurerm_storage_account.logs
  - breadth signals: subscription_scope; broad_builtin_role; sensitive_resource_scope
  - analysis scope: identity-to-role connection is modeled without inferring transitive data exposure

## Limitations / Unsupported Resources

- Azure support currently covers AzureRM storage posture, Key Vault network and privileged-access posture, SQL Database posture (public network access, firewall, TLS, security alerting), PostgreSQL Flexible Server posture (public network access, firewall, TLS/SSL, geo-redundant backup), Private Endpoint coverage for supported data-plane resources, AKS control-plane posture findings, and public virtual-machine exposure through public-IP, NIC, subnet, and NSG relationships; broader Azure RBAC hierarchy, MySQL, Private Endpoint DNS correctness, load-balancer, and broader platform-service modeling are not implemented yet.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
