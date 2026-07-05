# tfSTRIDE Threat Model Report

- Analyzed file: `sample_azure_nightmare_plan.json`
- Provider: `azure`
- Normalized resources: `27`
- Unsupported resources: `0`

## Summary

This run identified **5 trust boundaries** and **33 findings** across **27 normalized resources**.

- High severity findings: `7`
- Medium severity findings: `21`
- Low severity findings: `5`

## Analysis Coverage

- Terraform resources seen: `27`
- Provider resources considered: `27`
- Normalized resources: `27`
- Unsupported resources: `0`
- Registered rules: `164`
- Enabled rules: `164`
- Disabled rules: `0`
- Severity overrides: `0`
- Unresolved in-plan references: `0`
- Findings by rule:
  - `azure-public-compute-broad-ingress`: `2`
  - `azure-storage-container-public-access`: `3`
  - `azure-storage-account-nested-public-access-enabled`: `2`
  - `azure-storage-account-shared-key-enabled`: `2`
  - `azure-storage-account-minimum-tls-below-1-2`: `2`
  - `azure-storage-account-public-network-unrestricted`: `2`
  - `azure-storage-account-missing-private-endpoint`: `2`
  - `azure-key-vault-public-network-access`: `1`
  - `azure-key-vault-missing-private-endpoint`: `1`
  - `azure-key-vault-purge-protection-disabled`: `1`
  - `azure-managed-identity-broad-rbac`: `1`
  - `azure-public-workload-sensitive-resource-access`: `1`
  - `azure-diagnostic-settings-missing`: `4`
  - `azure-aks-api-server-public-unrestricted`: `1`
  - `azure-aks-local-accounts-not-disabled`: `1`
  - `azure-aks-rbac-posture-weak`: `1`
  - `azure-aks-network-policy-missing`: `1`
  - `azure-aks-workload-identity-not-enabled`: `1`
  - `azure-aks-key-management-service-not-configured`: `1`
  - `azure-aks-monitoring-agent-not-enabled`: `1`
  - `azure-aks-defender-not-enabled`: `1`
  - `azure-aks-azure-policy-not-enabled`: `1`

## Discovered Trust Boundaries

### `internet-to-service`

- Source: `internet`
- Target: `azurerm_storage_account.assets`
- Description: Traffic can cross from the public internet to azurerm_storage_account.assets.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

### `internet-to-service`

- Source: `internet`
- Target: `azurerm_linux_virtual_machine.web`
- Description: Traffic can cross from the public internet to azurerm_linux_virtual_machine.web.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

### `internet-to-service`

- Source: `internet`
- Target: `azurerm_storage_account.logs`
- Description: Traffic can cross from the public internet to azurerm_storage_account.logs.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

### `internet-to-service`

- Source: `internet`
- Target: `azurerm_windows_virtual_machine.admin`
- Description: Traffic can cross from the public internet to azurerm_windows_virtual_machine.admin.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

### `internet-to-service`

- Source: `internet`
- Target: `azurerm_key_vault.application`
- Description: Traffic can cross from the public internet to azurerm_key_vault.application.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

## Findings

### High

#### AKS control plane is public without narrow authorized IP ranges

- STRIDE category: Elevation of Privilege
- Affected resources: `azurerm_kubernetes_cluster.platform`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +1, data_sensitivity +0, lateral_movement +1, blast_radius +2, final_score 6 => high
- Rationale: azurerm_kubernetes_cluster.platform has AKS private cluster mode disabled and does not define narrow authorized IP ranges for the Kubernetes API server. The control plane is publicly reachable without a reviewed source range restriction.
- Recommended mitigation: Enable private cluster mode where possible, or configure `api_server_access_profile.authorized_ip_ranges` with narrow trusted CIDRs and avoid internet-wide source ranges.
- Evidence:
  - target resource: address=azurerm_kubernetes_cluster.platform; type=azurerm_kubernetes_cluster
  - control plane posture: private_cluster_state=disabled; authorized_ip_ranges_state=not_configured; api_server_vnet_integration_state=unknown

#### Azure Storage account permits Shared Key authorization

- STRIDE category: Elevation of Privilege
- Affected resources: `azurerm_storage_account.assets`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +2, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 7 => high
- Rationale: azurerm_storage_account.assets permits Shared Key authorization. Account keys provide broad data-plane authority and are harder to constrain and attribute than Microsoft Entra ID identities.
- Recommended mitigation: Disable Shared Key authorization where supported, use Microsoft Entra ID and managed identities, and configure the AzureRM provider to use Azure AD for storage operations.
- Evidence:
  - authorization posture: shared_access_key_enabled is true

#### Azure Storage account permits Shared Key authorization

- STRIDE category: Elevation of Privilege
- Affected resources: `azurerm_storage_account.logs`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +2, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 7 => high
- Rationale: azurerm_storage_account.logs permits Shared Key authorization. Account keys provide broad data-plane authority and are harder to constrain and attribute than Microsoft Entra ID identities.
- Recommended mitigation: Disable Shared Key authorization where supported, use Microsoft Entra ID and managed identities, and configure the AzureRM provider to use Azure AD for storage operations.
- Evidence:
  - authorization posture: shared_access_key_enabled is true

#### Azure Storage account permits nested public blob access

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_storage_account.assets`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +1, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 6 => high
- Rationale: azurerm_storage_account.assets permits containers and blobs to opt into anonymous public access. This account-level setting allows a subordinate container configuration to expose stored data.
- Recommended mitigation: Set `allow_nested_items_to_be_public` to `false` so containers and blobs cannot opt into anonymous public access.
- Evidence:
  - public access posture: allow_nested_items_to_be_public is true

#### Azure Storage account permits nested public blob access

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_storage_account.logs`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +1, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 6 => high
- Rationale: azurerm_storage_account.logs permits containers and blobs to opt into anonymous public access. This account-level setting allows a subordinate container configuration to expose stored data.
- Recommended mitigation: Set `allow_nested_items_to_be_public` to `false` so containers and blobs cannot opt into anonymous public access.
- Evidence:
  - public access posture: allow_nested_items_to_be_public is true

#### Azure managed identity has broad RBAC authority

- STRIDE category: Elevation of Privilege
- Affected resources: `azurerm_user_assigned_identity.deploy`, `azurerm_role_assignment.storage_owner`, `azurerm_storage_account.logs`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +3, data_sensitivity +2, lateral_movement +1, blast_radius +1, final_score 7 => high
- Rationale: azurerm_user_assigned_identity.deploy has Azure role assignments with broad scope or high-impact built-in roles. These grants expand what the managed identity can do if the workload or deployment path using it is compromised.
- Recommended mitigation: Replace broad managed identity role assignments with least-privilege resource-scoped roles, split deployment and runtime identities, and avoid subscription or resource-group scope unless required.
- Evidence:
  - managed identity: address=azurerm_user_assigned_identity.deploy; identity_type=UserAssigned; principal_id=11111111-1111-1111-1111-111111111111; client_id=22222222-2222-2222-2222-222222222222
  - role assignments: source=azurerm_role_assignment.storage_owner; role=Storage Blob Data Owner; scope=azurerm_storage_account.logs.id; scope_kind=resource; target=azurerm_storage_account.logs; signals=broad_builtin_role,sensitive_resource_scope
  - breadth signals: broad_builtin_role; sensitive_resource_scope

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

#### AKS Defender coverage is not enabled

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_kubernetes_cluster.platform`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +0, lateral_movement +2, blast_radius +1, final_score 3 => medium
- Rationale: azurerm_kubernetes_cluster.platform does not show deterministic Microsoft Defender for Containers coverage. Missing Defender signals can reduce runtime threat detection and security recommendations for AKS workloads.
- Recommended mitigation: Enable Microsoft Defender for Containers for AKS clusters that need runtime threat detection, vulnerability recommendations, and security posture monitoring.
- Evidence:
  - target resource: address=azurerm_kubernetes_cluster.platform; type=azurerm_kubernetes_cluster
  - defender posture: defender_state=not_configured

#### AKS Key Management Service is not configured

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_kubernetes_cluster.platform`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: azurerm_kubernetes_cluster.platform does not show deterministic AKS Key Management Service configuration with a Key Vault key. Kubernetes secrets may not have customer-controlled encryption key ownership represented in the Terraform plan.
- Recommended mitigation: Configure AKS Key Management Service with a customer-managed Key Vault key for Kubernetes secrets where customer key ownership or stronger secrets encryption posture is required.
- Evidence:
  - target resource: address=azurerm_kubernetes_cluster.platform; type=azurerm_kubernetes_cluster
  - secret encryption posture: key_management_service_state=not_configured; key_vault_key_id is not represented in planned values

#### AKS monitoring agent is not enabled

- STRIDE category: Repudiation
- Affected resources: `azurerm_kubernetes_cluster.platform`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +0, lateral_movement +2, blast_radius +1, final_score 3 => medium
- Rationale: azurerm_kubernetes_cluster.platform does not show deterministic AKS monitoring through the OMS agent and Log Analytics. Missing cluster telemetry can limit detection and investigation of control-plane and workload activity.
- Recommended mitigation: Enable the OMS agent or the current Azure Monitor integration for AKS and route cluster telemetry to a retained Log Analytics workspace or centralized logging pipeline.
- Evidence:
  - target resource: address=azurerm_kubernetes_cluster.platform; type=azurerm_kubernetes_cluster
  - monitoring posture: oms_agent_state=not_configured; log_analytics_workspace_id is not represented in planned values

#### Azure Key Vault allows unrestricted public network access

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_key_vault.application`
- Trust boundary: `internet-to-service:internet->azurerm_key_vault.application`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 5 => medium
- Rationale: azurerm_key_vault.application enables its public endpoint with an effective `Allow` network ACL default action. Network reachability does not itself grant data access, but it exposes the sensitive service endpoint to internet clients.
- Recommended mitigation: Disable public network access where possible, or configure Key Vault network ACLs with a default action of `Deny` and use reviewed subnets, IP ranges, or private endpoints.
- Evidence:
  - network exposure: public_network_access_enabled is true; effective network_acls.default_action is Allow; network exposure is evaluated separately from identity authorization

#### Azure Key Vault lacks resolved private endpoint coverage

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_key_vault.application`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 5 => medium
- Rationale: azurerm_key_vault.application does not have a resolved private endpoint and may allow public Key Vault data-plane access depending on firewall settings. This finding does not claim secret exposure; identity authorization is evaluated separately.
- Recommended mitigation: Add a Private Endpoint for the vault, verify data-plane clients use the private path, and explicitly disable public network access where possible.
- Evidence:
  - target resource: address=azurerm_key_vault.application; type=azurerm_key_vault
  - public network fallback: public_network_fallback_state=enabled; public_network_access_enabled is true
  - private endpoint coverage: no resolved private endpoint targets this resource
  - network acl posture: effective default_action is Allow

#### Azure Key Vault purge protection is disabled

- STRIDE category: Tampering
- Affected resources: `azurerm_key_vault.application`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: azurerm_key_vault.application does not enable purge protection. A principal with sufficient deletion authority could permanently remove vault contents during the retention window.
- Recommended mitigation: Enable purge protection and retain soft-deleted vault objects long enough to recover from accidental or malicious deletion.
- Evidence:
  - recovery posture: purge_protection_enabled is false

#### Azure Storage account allows TLS below 1.2

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_storage_account.assets`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 5 => medium
- Rationale: azurerm_storage_account.assets accepts `TLS1_1` as its minimum protocol version. Deprecated TLS versions weaken transport protection for storage data-plane requests.
- Recommended mitigation: Set `min_tls_version` to `TLS1_2` and remove clients that require deprecated TLS versions.
- Evidence:
  - transport posture: min_tls_version is TLS1_1

#### Azure Storage account allows TLS below 1.2

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_storage_account.logs`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 5 => medium
- Rationale: azurerm_storage_account.logs accepts `TLS1_0` as its minimum protocol version. Deprecated TLS versions weaken transport protection for storage data-plane requests.
- Recommended mitigation: Set `min_tls_version` to `TLS1_2` and remove clients that require deprecated TLS versions.
- Evidence:
  - transport posture: min_tls_version is TLS1_0

#### Azure Storage account allows unrestricted public network access

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_storage_account.assets`
- Trust boundary: `internet-to-service:internet->azurerm_storage_account.assets`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 5 => medium
- Rationale: azurerm_storage_account.assets enables its public network endpoint with an effective `Allow` default action. Storage data-plane endpoints are reachable without a default-deny network boundary.
- Recommended mitigation: Disable public network access where possible, or set the effective storage network default action to `Deny` and allow only reviewed subnets, IP ranges, or private endpoints.
- Evidence:
  - network posture: public_network_access_enabled is true; effective default_action is Allow; network rule source is azurerm_storage_account_network_rules.assets

#### Azure Storage account allows unrestricted public network access

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_storage_account.logs`
- Trust boundary: `internet-to-service:internet->azurerm_storage_account.logs`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 5 => medium
- Rationale: azurerm_storage_account.logs enables its public network endpoint with an effective `Allow` default action. Storage data-plane endpoints are reachable without a default-deny network boundary.
- Recommended mitigation: Disable public network access where possible, or set the effective storage network default action to `Deny` and allow only reviewed subnets, IP ranges, or private endpoints.
- Evidence:
  - network posture: public_network_access_enabled is true; effective default_action is Allow; network rule source is azurerm_storage_account_network_rules.logs

#### Azure Storage account lacks resolved private endpoint coverage

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_storage_account.assets`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 5 => medium
- Rationale: azurerm_storage_account.assets does not have a resolved private endpoint and may remain reachable through public Azure Storage data-plane endpoints. Network rules can reduce exposure, but they are not equivalent to private-endpoint-only access unless public network fallback is disabled.
- Recommended mitigation: Add a Private Endpoint for the required storage subresources, verify clients use private paths, and explicitly disable public network access where possible.
- Evidence:
  - target resource: address=azurerm_storage_account.assets; type=azurerm_storage_account
  - public network fallback: public_network_fallback_state=enabled; public_network_access_enabled is true
  - private endpoint coverage: no resolved private endpoint targets this resource
  - network acl posture: effective default_action is Allow; network rule source is azurerm_storage_account_network_rules.assets

#### Azure Storage account lacks resolved private endpoint coverage

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_storage_account.logs`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 5 => medium
- Rationale: azurerm_storage_account.logs does not have a resolved private endpoint and may remain reachable through public Azure Storage data-plane endpoints. Network rules can reduce exposure, but they are not equivalent to private-endpoint-only access unless public network fallback is disabled.
- Recommended mitigation: Add a Private Endpoint for the required storage subresources, verify clients use private paths, and explicitly disable public network access where possible.
- Evidence:
  - target resource: address=azurerm_storage_account.logs; type=azurerm_storage_account
  - public network fallback: public_network_fallback_state=enabled; public_network_access_enabled is true
  - private endpoint coverage: no resolved private endpoint targets this resource
  - network acl posture: effective default_action is Allow; network rule source is azurerm_storage_account_network_rules.logs

#### Azure Storage container is publicly accessible

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_storage_account.assets`, `azurerm_storage_container.public_assets`
- Trust boundary: `internet-to-service:internet->azurerm_storage_account.assets`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 5 => medium
- Rationale: azurerm_storage_container.public_assets permits anonymous `blob` access through a storage account that allows nested public access and unrestricted public network reachability.
- Recommended mitigation: Set the container access type to `private`, disable nested public access on the storage account, and use scoped identities or time-limited access mechanisms for intentional object sharing.
- Evidence:
  - public exposure reasons: container_access_type is blob; azurerm_storage_account.assets allows nested items to be public; azurerm_storage_account.assets is reachable through its public network endpoint

#### Azure Storage container is publicly accessible

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_storage_account.logs`, `azurerm_storage_container.public_logs`
- Trust boundary: `internet-to-service:internet->azurerm_storage_account.logs`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 5 => medium
- Rationale: azurerm_storage_container.public_logs permits anonymous `container` access through a storage account that allows nested public access and unrestricted public network reachability.
- Recommended mitigation: Set the container access type to `private`, disable nested public access on the storage account, and use scoped identities or time-limited access mechanisms for intentional object sharing.
- Evidence:
  - public exposure reasons: container_access_type is container; azurerm_storage_account.logs allows nested items to be public; azurerm_storage_account.logs is reachable through its public network endpoint

#### Azure Storage container is publicly accessible

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_storage_account.logs`, `azurerm_storage_container.public_backups`
- Trust boundary: `internet-to-service:internet->azurerm_storage_account.logs`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 5 => medium
- Rationale: azurerm_storage_container.public_backups permits anonymous `blob` access through a storage account that allows nested public access and unrestricted public network reachability.
- Recommended mitigation: Set the container access type to `private`, disable nested public access on the storage account, and use scoped identities or time-limited access mechanisms for intentional object sharing.
- Evidence:
  - public exposure reasons: container_access_type is blob; azurerm_storage_account.logs allows nested items to be public; azurerm_storage_account.logs is reachable through its public network endpoint

#### Azure resource lacks diagnostic settings

- STRIDE category: Repudiation
- Affected resources: `azurerm_storage_account.assets`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 5 => medium
- Rationale: azurerm_storage_account.assets has no resolved Azure Monitor diagnostic setting in this Terraform plan. Security-relevant data-plane, control-plane, or platform logs may not be routed to a retained logging destination for investigation and alerting.
- Recommended mitigation: Add an Azure Monitor diagnostic setting for the resource and route security-relevant logs and metrics to a retained Log Analytics workspace, storage account, Event Hub, or approved partner destination.
- Evidence:
  - target resource: address=azurerm_storage_account.assets; type=azurerm_storage_account; name=tfstridepublicassets; identifier=/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/tfstride/providers/Microsoft.Storage/storageAccounts/tfstridepublicassets
  - diagnostic coverage: no resolved azurerm_monitor_diagnostic_setting targets this resource

#### Azure resource lacks diagnostic settings

- STRIDE category: Repudiation
- Affected resources: `azurerm_storage_account.logs`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 5 => medium
- Rationale: azurerm_storage_account.logs has no resolved Azure Monitor diagnostic setting in this Terraform plan. Security-relevant data-plane, control-plane, or platform logs may not be routed to a retained logging destination for investigation and alerting.
- Recommended mitigation: Add an Azure Monitor diagnostic setting for the resource and route security-relevant logs and metrics to a retained Log Analytics workspace, storage account, Event Hub, or approved partner destination.
- Evidence:
  - target resource: address=azurerm_storage_account.logs; type=azurerm_storage_account; name=tfstridepubliclogs; identifier=/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/tfstride/providers/Microsoft.Storage/storageAccounts/tfstridepubliclogs
  - diagnostic coverage: no resolved azurerm_monitor_diagnostic_setting targets this resource

#### Azure resource lacks diagnostic settings

- STRIDE category: Repudiation
- Affected resources: `azurerm_kubernetes_cluster.platform`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +1, lateral_movement +1, blast_radius +1, final_score 5 => medium
- Rationale: azurerm_kubernetes_cluster.platform has no resolved Azure Monitor diagnostic setting in this Terraform plan. Security-relevant data-plane, control-plane, or platform logs may not be routed to a retained logging destination for investigation and alerting.
- Recommended mitigation: Add an Azure Monitor diagnostic setting for the resource and route security-relevant logs and metrics to a retained Log Analytics workspace, storage account, Event Hub, or approved partner destination.
- Evidence:
  - target resource: address=azurerm_kubernetes_cluster.platform; type=azurerm_kubernetes_cluster; name=tfstride-platform; identifier=/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/tfstride/providers/Microsoft.ContainerService/managedClusters/tfstride-platform
  - diagnostic coverage: no resolved azurerm_monitor_diagnostic_setting targets this resource

#### Azure resource lacks diagnostic settings

- STRIDE category: Repudiation
- Affected resources: `azurerm_key_vault.application`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 5 => medium
- Rationale: azurerm_key_vault.application has no resolved Azure Monitor diagnostic setting in this Terraform plan. Security-relevant data-plane, control-plane, or platform logs may not be routed to a retained logging destination for investigation and alerting.
- Recommended mitigation: Add an Azure Monitor diagnostic setting for the resource and route security-relevant logs and metrics to a retained Log Analytics workspace, storage account, Event Hub, or approved partner destination.
- Evidence:
  - target resource: address=azurerm_key_vault.application; type=azurerm_key_vault; name=tfstride-application; identifier=/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/tfstride/providers/Microsoft.KeyVault/vaults/tfstride-application
  - diagnostic coverage: no resolved azurerm_monitor_diagnostic_setting targets this resource

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

#### Internet-exposed Azure virtual machine permits broad ingress

- STRIDE category: Spoofing
- Affected resources: `azurerm_windows_virtual_machine.admin`, `azurerm_network_interface.admin`, `azurerm_public_ip.admin`, `azurerm_network_security_group.admin_nic`, `azurerm_network_security_group.web_subnet`
- Trust boundary: `internet-to-service:internet->azurerm_windows_virtual_machine.admin`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +0, lateral_movement +1, blast_radius +1, final_score 4 => medium
- Rationale: azurerm_windows_virtual_machine.admin has a public-IP path and the effective Azure NSG decisions across its subnet and network interface permit administrative access or all ports from internet sources. This exposes the guest to direct probing and credential attacks.
- Recommended mitigation: Remove the public IP where possible, restrict subnet and NIC NSG rules to expected client CIDRs and service ports, and use Azure Bastion, VPN, or Just-In-Time VM access for administration.
- Evidence:
  - public ip path: azurerm_windows_virtual_machine.admin -> azurerm_network_interface.admin -> azurerm_public_ip.admin (203.0.113.20)
  - network security path: azurerm_windows_virtual_machine.admin -> azurerm_network_interface.admin -> azurerm_network_security_group.admin_nic; azurerm_windows_virtual_machine.admin -> azurerm_network_interface.admin -> azurerm_network_security_group.web_subnet
  - network security rules: azurerm_network_security_group.admin_nic rule allow-rdp priority 200 allows tcp 3389 from Internet; azurerm_network_security_group.web_subnet rule allow-internet-tcp priority 300 allows tcp 0-65535 from Internet
  - public exposure reasons: virtual machine has a public IP path and effective subnet/NIC NSG decisions allow internet ingress

### Low

#### AKS Azure Policy add-on is not enabled

- STRIDE category: Tampering
- Affected resources: `azurerm_kubernetes_cluster.platform`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +0, lateral_movement +0, blast_radius +1, final_score 1 => low
- Rationale: azurerm_kubernetes_cluster.platform does not deterministically enable the Azure Policy add-on. Without the add-on, Kubernetes policy and governance controls may rely on external review instead of in-cluster policy enforcement.
- Recommended mitigation: Enable the Azure Policy add-on for AKS where policy-as-code enforcement, guardrails, or compliance reporting are expected for Kubernetes resources.
- Evidence:
  - target resource: address=azurerm_kubernetes_cluster.platform; type=azurerm_kubernetes_cluster
  - azure policy posture: azure_policy_state=unknown

#### AKS RBAC posture is weak or not deterministic

- STRIDE category: Elevation of Privilege
- Affected resources: `azurerm_kubernetes_cluster.platform`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +1, data_sensitivity +0, lateral_movement +0, blast_radius +1, final_score 2 => low
- Rationale: azurerm_kubernetes_cluster.platform has weak or non-deterministic AKS RBAC posture. Kubernetes RBAC should be explicitly enabled, and Azure RBAC integration should not be disabled when the Azure Active Directory RBAC block is represented in the Terraform plan.
- Recommended mitigation: Enable Kubernetes RBAC explicitly, use Microsoft Entra ID integration for administrative access, and avoid disabling Azure RBAC integration when the cluster relies on Azure authorization controls.
- Evidence:
  - target resource: address=azurerm_kubernetes_cluster.platform; type=azurerm_kubernetes_cluster
  - rbac posture: kubernetes_rbac_state=unknown; aad_rbac_state=not_configured; aad_managed_state=unknown; aad_azure_rbac_state=unknown; kubernetes RBAC state is unknown

#### AKS local accounts are not disabled

- STRIDE category: Spoofing
- Affected resources: `azurerm_kubernetes_cluster.platform`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +1, data_sensitivity +0, lateral_movement +0, blast_radius +1, final_score 2 => low
- Rationale: azurerm_kubernetes_cluster.platform does not deterministically disable AKS local accounts. Local cluster accounts can weaken centralized Microsoft Entra ID identity, auditing, and access control if they remain enabled.
- Recommended mitigation: Set `local_account_disabled` to `true`, use Microsoft Entra ID-backed authentication, and review any break-glass access paths separately.
- Evidence:
  - target resource: address=azurerm_kubernetes_cluster.platform; type=azurerm_kubernetes_cluster
  - authentication posture: local_account_state=unknown

#### AKS network policy is not configured

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_kubernetes_cluster.platform`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +0, lateral_movement +1, blast_radius +1, final_score 2 => low
- Rationale: azurerm_kubernetes_cluster.platform does not have deterministic AKS network policy configured. Without a pod network policy provider, Kubernetes workloads have weaker pod-level traffic isolation and lateral-movement controls.
- Recommended mitigation: Configure an AKS network policy provider such as Azure, Cilium, or Calico, then define pod-level network policies for sensitive namespaces and workloads.
- Evidence:
  - target resource: address=azurerm_kubernetes_cluster.platform; type=azurerm_kubernetes_cluster
  - network policy posture: network_policy_state=unknown; network_policy is not represented in planned values

#### AKS workload identity is not fully enabled

- STRIDE category: Elevation of Privilege
- Affected resources: `azurerm_kubernetes_cluster.platform`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +1, data_sensitivity +0, lateral_movement +0, blast_radius +1, final_score 2 => low
- Rationale: azurerm_kubernetes_cluster.platform does not deterministically enable AKS workload identity and its OIDC issuer. Pods may need to rely on broader node credentials, static secrets, or less auditable identity paths for Azure resource access.
- Recommended mitigation: Enable the AKS OIDC issuer and workload identity, bind Kubernetes service accounts to narrow managed identities, and avoid relying on node credentials or static secrets for Azure API access.
- Evidence:
  - target resource: address=azurerm_kubernetes_cluster.platform; type=azurerm_kubernetes_cluster
  - workload identity posture: oidc_issuer_state=unknown; workload_identity_state=unknown

## Controls Observed

### Azure managed identity principal is modeled

- Category: `iam`
- Affected resources: `azurerm_linux_virtual_machine.web`
- Rationale: azurerm_linux_virtual_machine.web exposes a `UserAssigned` managed identity principal. Role assignments are connected only when principal IDs are known in the Terraform plan.
- Evidence:
  - identity type: UserAssigned
  - attached identity references: azurerm_user_assigned_identity.deploy.id
  - analysis scope: managed identity role assignments are connected when principal IDs are deterministic; transitive access findings are not emitted from managed identity assignments yet

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

### Azure managed identity role assignment is connected

- Category: `iam`
- Affected resources: `azurerm_user_assigned_identity.deploy`, `azurerm_role_assignment.storage_owner`
- Rationale: azurerm_user_assigned_identity.deploy has Azure role assignments whose `principal_id` matches this managed identity. Scope breadth is reported separately from any downstream exposure rule.
- Evidence:
  - role assignment sources: azurerm_role_assignment.storage_owner
  - role definition names: Storage Blob Data Owner
  - scopes: azurerm_storage_account.logs.id
  - scope kinds: resource
  - target resources: azurerm_storage_account.logs
  - breadth signals: broad_builtin_role; sensitive_resource_scope
  - analysis scope: identity-to-role connection is modeled without inferring transitive data exposure

## Limitations / Unsupported Resources

- Azure support currently covers AzureRM storage posture, Key Vault network and privileged-access posture, SQL Database posture (public network access, firewall, TLS, security alerting), PostgreSQL Flexible Server posture (public network access, firewall, TLS/SSL, geo-redundant backup), Private Endpoint coverage for supported data-plane resources, AKS control-plane posture findings, and public virtual-machine exposure through public-IP, NIC, subnet, and NSG relationships; broader Azure RBAC hierarchy, MySQL, Private Endpoint DNS correctness, load-balancer, and broader platform-service modeling are not implemented yet.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
