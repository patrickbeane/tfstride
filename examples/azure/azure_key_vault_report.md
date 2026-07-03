# tfSTRIDE Threat Model Report

- Analyzed file: `sample_azure_key_vault_plan.json`
- Provider: `azure`
- Normalized resources: `8`
- Unsupported resources: `0`

## Summary

This run identified **1 trust boundaries** and **5 findings** across **8 normalized resources**.

- High severity findings: `1`
- Medium severity findings: `3`
- Low severity findings: `1`

## Analysis Coverage

- Terraform resources seen: `8`
- Provider resources considered: `8`
- Normalized resources: `8`
- Unsupported resources: `0`
- Registered rules: `131`
- Enabled rules: `131`
- Disabled rules: `0`
- Severity overrides: `0`
- Unresolved in-plan references: `0`
- Findings by rule:
  - `azure-key-vault-public-network-access`: `1`
  - `azure-key-vault-missing-private-endpoint`: `2`
  - `azure-key-vault-privileged-access`: `1`
  - `azure-key-vault-purge-protection-disabled`: `1`

## Discovered Trust Boundaries

### `internet-to-service`

- Source: `internet`
- Target: `azurerm_key_vault.public`
- Description: Traffic can cross from the public internet to azurerm_key_vault.public.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

## Findings

### High

#### Azure Key Vault grants privileged identity access

- STRIDE category: Elevation of Privilege
- Affected resources: `azurerm_key_vault.public`, `azurerm_key_vault_access_policy.operators`, `azurerm_role_assignment.key_vault_admin`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +3, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 6 => high
- Rationale: azurerm_key_vault.public grants broad data-plane or authorization-management authority through a Key Vault access policy or vault-scoped Azure role assignment. This identity risk is present independently of whether the vault public endpoint is reachable.
- Recommended mitigation: Replace broad Key Vault access policies and privileged vault-scoped roles with least-privilege RBAC assignments, narrow principals, and separate administrative from data-plane duties.
- Evidence:
  - privileged access policies: source=azurerm_key_vault_access_policy.operators; object_id=00000000-0000-0000-0000-000000000020; secret_permissions=[delete, get, list, purge, recover, set]
  - privileged role assignments: source=azurerm_role_assignment.key_vault_admin; role=Key Vault Administrator; principal_id=00000000-0000-0000-0000-000000000030; principal_type=ServicePrincipal
  - authorization scope: identity authorization is evaluated separately from network exposure

### Medium

#### Azure Key Vault allows unrestricted public network access

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_key_vault.public`
- Trust boundary: `internet-to-service:internet->azurerm_key_vault.public`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 5 => medium
- Rationale: azurerm_key_vault.public enables its public endpoint with an effective `Allow` network ACL default action. Network reachability does not itself grant data access, but it exposes the sensitive service endpoint to internet clients.
- Recommended mitigation: Disable public network access where possible, or configure Key Vault network ACLs with a default action of `Deny` and use reviewed subnets, IP ranges, or private endpoints.
- Evidence:
  - network exposure: public_network_access_enabled is true; effective network_acls.default_action is Allow; network exposure is evaluated separately from identity authorization

#### Azure Key Vault lacks resolved private endpoint coverage

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_key_vault.public`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 5 => medium
- Rationale: azurerm_key_vault.public does not have a resolved private endpoint and may allow public Key Vault data-plane access depending on firewall settings. This finding does not claim secret exposure; identity authorization is evaluated separately.
- Recommended mitigation: Add a Private Endpoint for the vault, verify data-plane clients use the private path, and explicitly disable public network access where possible.
- Evidence:
  - target resource: address=azurerm_key_vault.public; type=azurerm_key_vault
  - public network fallback: public_network_fallback_state=enabled; public_network_access_enabled is true
  - private endpoint coverage: no resolved private endpoint targets this resource
  - network acl posture: effective default_action is Allow

#### Azure Key Vault purge protection is disabled

- STRIDE category: Tampering
- Affected resources: `azurerm_key_vault.public`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: azurerm_key_vault.public does not enable purge protection. A principal with sufficient deletion authority could permanently remove vault contents during the retention window.
- Recommended mitigation: Enable purge protection and retain soft-deleted vault objects long enough to recover from accidental or malicious deletion.
- Evidence:
  - recovery posture: purge_protection_enabled is false

### Low

#### Azure Key Vault lacks resolved private endpoint coverage

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_key_vault.restricted`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +1, lateral_movement +0, blast_radius +0, final_score 1 => low
- Rationale: azurerm_key_vault.restricted does not have a resolved private endpoint and may allow public Key Vault data-plane access depending on firewall settings. This finding does not claim secret exposure; identity authorization is evaluated separately.
- Recommended mitigation: Add a Private Endpoint for the vault, verify data-plane clients use the private path, and explicitly disable public network access where possible.
- Evidence:
  - target resource: address=azurerm_key_vault.restricted; type=azurerm_key_vault
  - public network fallback: public_network_fallback_state=enabled; public_network_access_enabled is true
  - private endpoint coverage: no resolved private endpoint targets this resource
  - network acl posture: effective default_action is Deny; network rule source is azurerm_key_vault.restricted

## Controls Observed

### Azure Key Vault network access is restricted

- Category: `data-protection`
- Affected resources: `azurerm_key_vault.private`
- Rationale: azurerm_key_vault.private is not broadly reachable through its public endpoint. Network controls are evaluated separately from the identities authorized to use the vault.
- Evidence:
  - network posture: public_network_access_enabled is false

### Azure Key Vault network access is restricted

- Category: `data-protection`
- Affected resources: `azurerm_key_vault.restricted`
- Rationale: azurerm_key_vault.restricted is not broadly reachable through its public endpoint. Network controls are evaluated separately from the identities authorized to use the vault.
- Evidence:
  - network posture: public_network_access_enabled is true; effective network_acls.default_action is Deny; allowed IP rule is 198.51.100.10; allowed subnet is azurerm_subnet.app.id

### Azure Key Vault identity authorization is modeled separately from network access

- Category: `iam`
- Affected resources: `azurerm_key_vault.private`
- Rationale: azurerm_key_vault.private uses vault access policies. Network reachability does not imply authorization, and privileged grants are evaluated independently.
- Evidence:
  - authorization model: vault access policies
  - access policy sources: azurerm_key_vault.private

### Azure Key Vault identity authorization is modeled separately from network access

- Category: `iam`
- Affected resources: `azurerm_key_vault.public`
- Rationale: azurerm_key_vault.public uses Azure RBAC. Network reachability does not imply authorization, and privileged grants are evaluated independently.
- Evidence:
  - authorization model: Azure RBAC
  - access policy sources: azurerm_key_vault_access_policy.operators
  - role assignment sources: azurerm_role_assignment.key_vault_admin

## Limitations / Unsupported Resources

- Azure support currently covers AzureRM storage posture, Key Vault network and privileged-access posture, SQL Database posture (public network access, firewall, TLS, security alerting), PostgreSQL Flexible Server posture (public network access, firewall, TLS/SSL, geo-redundant backup), Private Endpoint coverage for supported data-plane resources, AKS control-plane posture findings, and public virtual-machine exposure through public-IP, NIC, subnet, and NSG relationships; broader Azure RBAC hierarchy, MySQL, Private Endpoint DNS correctness, load-balancer, and broader platform-service modeling are not implemented yet.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
