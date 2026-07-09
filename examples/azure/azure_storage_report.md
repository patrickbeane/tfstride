# tfSTRIDE Threat Model Report

- Analyzed file: `sample_azure_storage_plan.json`
- Provider: `azure`
- Normalized resources: `3`
- Unsupported resources: `1`

## Summary

This run identified **1 trust boundaries** and **7 findings** across **3 normalized resources**.

- High severity findings: `2`
- Medium severity findings: `5`
- Low severity findings: `0`

## Analysis Coverage

- Terraform resources seen: `4`
- Provider resources considered: `4`
- Normalized resources: `3`
- Unsupported resources: `1`
- Registered rules: `179`
- Enabled rules: `179`
- Disabled rules: `0`
- Severity overrides: `0`
- Unresolved in-plan references: `0`
- Unsupported resource types:
  - `azurerm_storage_share`: `1`
- Findings by rule:
  - `azure-storage-container-public-access`: `1`
  - `azure-storage-account-nested-public-access-enabled`: `1`
  - `azure-storage-account-shared-key-enabled`: `1`
  - `azure-storage-account-minimum-tls-below-1-2`: `1`
  - `azure-storage-account-public-network-unrestricted`: `1`
  - `azure-storage-account-missing-private-endpoint`: `1`
  - `azure-diagnostic-settings-missing`: `1`

## Discovered Trust Boundaries

### `internet-to-service`

- Source: `internet`
- Target: `azurerm_storage_account.assets`
- Description: Traffic can cross from the public internet to azurerm_storage_account.assets.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

## Findings

### High

#### Azure Storage account permits Shared Key authorization

- STRIDE category: Elevation of Privilege
- Affected resources: `azurerm_storage_account.assets`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +2, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 7 => high
- Rationale: azurerm_storage_account.assets permits Shared Key authorization. Account keys provide broad data-plane authority and are harder to constrain and attribute than Microsoft Entra ID identities.
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

### Medium

#### Azure Storage account allows TLS below 1.2

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_storage_account.assets`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 5 => medium
- Rationale: azurerm_storage_account.assets accepts `TLS1_1` as its minimum protocol version. Deprecated TLS versions weaken transport protection for storage data-plane requests.
- Recommended mitigation: Set `min_tls_version` to `TLS1_2` and remove clients that require deprecated TLS versions.
- Evidence:
  - transport posture: min_tls_version is TLS1_1

#### Azure Storage account allows unrestricted public network access

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_storage_account.assets`
- Trust boundary: `internet-to-service:internet->azurerm_storage_account.assets`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 5 => medium
- Rationale: azurerm_storage_account.assets enables its public network endpoint with an effective `Allow` default action. Storage data-plane endpoints are reachable without a default-deny network boundary.
- Recommended mitigation: Disable public network access where possible, or set the effective storage network default action to `Deny` and allow only reviewed subnets, IP ranges, or private endpoints.
- Evidence:
  - network posture: public_network_access_enabled is true; effective default_action is Allow; network rule source is azurerm_storage_account_network_rules.assets

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

#### Azure Storage container is publicly accessible

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_storage_account.assets`, `azurerm_storage_container.public_assets`
- Trust boundary: `internet-to-service:internet->azurerm_storage_account.assets`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 5 => medium
- Rationale: azurerm_storage_container.public_assets permits anonymous `blob` access through a storage account that allows nested public access and unrestricted public network reachability.
- Recommended mitigation: Set the container access type to `private`, disable nested public access on the storage account, and use scoped identities or time-limited access mechanisms for intentional object sharing.
- Evidence:
  - public exposure reasons: container_access_type is blob; azurerm_storage_account.assets allows nested items to be public; azurerm_storage_account.assets is reachable through its public network endpoint

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

### Low

No findings in this severity band.

## Limitations / Unsupported Resources

- Azure support currently covers AzureRM storage posture, Key Vault network and privileged-access posture, SQL Database posture (public network access, firewall, TLS, security alerting), PostgreSQL Flexible Server posture (public network access, firewall, TLS/SSL, geo-redundant backup), Private Endpoint coverage for supported data-plane resources, AKS control-plane posture findings, and public virtual-machine exposure through public-IP, NIC, subnet, and NSG relationships; broader Azure RBAC hierarchy, MySQL, Private Endpoint DNS correctness, load-balancer, and broader platform-service modeling are not implemented yet.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
- Unsupported resource skipped: `azurerm_storage_share.legacy`
