# tfSTRIDE Threat Model Report

- Analyzed file: `sample_azure_plan.json`
- Provider: `azure`
- Normalized resources: `13`
- Unsupported resources: `2`

## Summary

This run identified **2 trust boundaries** and **6 findings** across **13 normalized resources**.

- High severity findings: `2`
- Medium severity findings: `4`
- Low severity findings: `0`

## Analysis Coverage

- Terraform resources seen: `15`
- Provider resources considered: `15`
- Normalized resources: `13`
- Unsupported resources: `2`
- Registered rules: `54`
- Enabled rules: `54`
- Disabled rules: `0`
- Severity overrides: `0`
- Unresolved in-plan references: `0`
- Unsupported resource types:
  - `azurerm_key_vault`: `1`
  - `azurerm_kubernetes_cluster`: `1`
- Findings by rule:
  - `azure-public-compute-broad-ingress`: `1`
  - `azure-storage-container-public-access`: `1`
  - `azure-storage-account-nested-public-access-enabled`: `1`
  - `azure-storage-account-shared-key-enabled`: `1`
  - `azure-storage-account-minimum-tls-below-1-2`: `1`
  - `azure-storage-account-public-network-unrestricted`: `1`

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

#### Azure Storage container is publicly accessible

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_storage_account.assets`, `azurerm_storage_container.public_assets`
- Trust boundary: `internet-to-service:internet->azurerm_storage_account.assets`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 5 => medium
- Rationale: azurerm_storage_container.public_assets permits anonymous `blob` access through a storage account that allows nested public access and unrestricted public network reachability.
- Recommended mitigation: Set the container access type to `private`, disable nested public access on the storage account, and use scoped identities or time-limited access mechanisms for intentional object sharing.
- Evidence:
  - public exposure reasons: container_access_type is blob; azurerm_storage_account.assets allows nested items to be public; azurerm_storage_account.assets is reachable through its public network endpoint

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

- Azure support currently covers AzureRM storage posture and public virtual-machine exposure through public-IP, NIC, subnet, and NSG relationships; Azure identity, database, load-balancer, private-endpoint, and broader platform-service modeling are not implemented yet.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
- Unsupported resource skipped: `azurerm_key_vault.application`
- Unsupported resource skipped: `azurerm_kubernetes_cluster.platform`
