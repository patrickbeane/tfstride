# tfSTRIDE Threat Model Report

- Analyzed file: `sample_azure_key_vault_plan.json`
- Provider: `azure`
- Normalized resources: `8`
- Unsupported resources: `0`

## Summary

This run identified **1 trust boundaries** and **11 findings** across **8 normalized resources**.

- High severity findings: `1`
- Medium severity findings: `9`
- Low severity findings: `1`

## Analysis Coverage

- Terraform resources seen: `8`
- Provider resources considered: `8`
- Normalized resources: `8`
- Unsupported resources: `0`
- Registered rules: `240`
- Enabled rules: `240`
- Disabled rules: `0`
- Severity overrides: `0`
- Unresolved in-plan references: `0`
- Findings by rule:
  - `azure-key-vault-public-network-access`: `1`
  - `azure-key-vault-missing-private-endpoint`: `2`
  - `azure-key-vault-privileged-access`: `1`
  - `azure-key-vault-purge-protection-disabled`: `1`
  - `azure-key-vault-secret-certificate-lifecycle-incomplete`: `2`
  - `azure-key-vault-key-rotation-policy-incomplete`: `1`
  - `azure-diagnostic-settings-missing`: `3`

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

#### Azure Key Vault key rotation posture is incomplete

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_key_vault_key.signing`, `azurerm_key_vault.public`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: azurerm_key_vault_key.signing does not show bounded Key Vault key rotation and expiry governance. This finding concerns cryptographic key lifecycle posture for dependent data; it does not assert access to secrets or data-plane compromise.
- Recommended mitigation: Configure Key Vault key rotation policies with bounded expiry and automatic rotation intervals, and keep key validity windows aligned with cryptographic lifecycle and compliance requirements.
- Evidence:
  - target resource: address=azurerm_key_vault_key.signing; type=azurerm_key_vault_key; identifier=signing; key_vault_reference=azurerm_key_vault.public.id; resolved_key_vault_address=azurerm_key_vault.public
  - rotation issues: key has no rotation_policy
  - key posture: key_type=RSA; key_size=unset; curve=unset; key_ops=unset; minimum_rsa_key_size_bits=2048; expiration_date=unset; not_before_date=unset; maximum_key_expiry_days=730; maximum_rotation_interval_days=365
  - rotation policy: rotation_policy_present=false; expire_after=unset; notify_before_expiry=unset; automatic.time_after_creation=unset; automatic.time_before_expiry=unset

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

#### Azure Key Vault secret or certificate lifecycle posture is incomplete

- STRIDE category: Denial of Service
- Affected resources: `azurerm_key_vault_secret.api_key`, `azurerm_key_vault.public`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: azurerm_key_vault_secret.api_key does not show deterministic Key Vault secret or certificate lifecycle posture. Explicit expiry and bounded validity reduce stale secret and certificate material, but do not replace identity review or rotation automation.
- Recommended mitigation: Configure explicit expiry for Key Vault secrets and certificates, keep validity windows bounded, and pair lifecycle settings with rotation automation appropriate for the secret or certificate type.
- Evidence:
  - target resource: address=azurerm_key_vault_secret.api_key; type=azurerm_key_vault_secret; identifier=api-key; key_vault_reference=azurerm_key_vault.public.id; resolved_key_vault_address=azurerm_key_vault.public
  - lifecycle issues: secret has no expiration_date
  - lifecycle posture: expiration_date=unset; not_before_date=unset; certificate_policy.validity_in_months=unset; maximum_lifetime_days=730; maximum_certificate_validity_months=24

#### Azure Key Vault secret or certificate lifecycle posture is incomplete

- STRIDE category: Denial of Service
- Affected resources: `azurerm_key_vault_certificate.tls`, `azurerm_key_vault.public`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: azurerm_key_vault_certificate.tls does not show deterministic Key Vault secret or certificate lifecycle posture. Explicit expiry and bounded validity reduce stale secret and certificate material, but do not replace identity review or rotation automation.
- Recommended mitigation: Configure explicit expiry for Key Vault secrets and certificates, keep validity windows bounded, and pair lifecycle settings with rotation automation appropriate for the secret or certificate type.
- Evidence:
  - target resource: address=azurerm_key_vault_certificate.tls; type=azurerm_key_vault_certificate; identifier=tls; key_vault_reference=azurerm_key_vault.public.id; resolved_key_vault_address=azurerm_key_vault.public
  - lifecycle issues: certificate has no expiration_date
  - lifecycle posture: expiration_date=unset; not_before_date=unset; certificate_policy.validity_in_months=unset; maximum_lifetime_days=730; maximum_certificate_validity_months=24

#### Azure resource lacks diagnostic settings

- STRIDE category: Repudiation
- Affected resources: `azurerm_key_vault.private`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: azurerm_key_vault.private has no resolved Azure Monitor diagnostic setting in this Terraform plan. Security-relevant data-plane, control-plane, or platform logs may not be routed to a retained logging destination for investigation and alerting.
- Recommended mitigation: Add an Azure Monitor diagnostic setting for the resource and route security-relevant logs and metrics to a retained Log Analytics workspace, storage account, Event Hub, or approved partner destination.
- Evidence:
  - target resource: address=azurerm_key_vault.private; type=azurerm_key_vault; name=tfstride-private; identifier=/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/tfstride/providers/Microsoft.KeyVault/vaults/tfstride-private
  - diagnostic coverage: no resolved azurerm_monitor_diagnostic_setting targets this resource

#### Azure resource lacks diagnostic settings

- STRIDE category: Repudiation
- Affected resources: `azurerm_key_vault.restricted`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: azurerm_key_vault.restricted has no resolved Azure Monitor diagnostic setting in this Terraform plan. Security-relevant data-plane, control-plane, or platform logs may not be routed to a retained logging destination for investigation and alerting.
- Recommended mitigation: Add an Azure Monitor diagnostic setting for the resource and route security-relevant logs and metrics to a retained Log Analytics workspace, storage account, Event Hub, or approved partner destination.
- Evidence:
  - target resource: address=azurerm_key_vault.restricted; type=azurerm_key_vault; name=tfstride-restricted; identifier=/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/tfstride/providers/Microsoft.KeyVault/vaults/tfstride-restricted
  - diagnostic coverage: no resolved azurerm_monitor_diagnostic_setting targets this resource

#### Azure resource lacks diagnostic settings

- STRIDE category: Repudiation
- Affected resources: `azurerm_key_vault.public`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 5 => medium
- Rationale: azurerm_key_vault.public has no resolved Azure Monitor diagnostic setting in this Terraform plan. Security-relevant data-plane, control-plane, or platform logs may not be routed to a retained logging destination for investigation and alerting.
- Recommended mitigation: Add an Azure Monitor diagnostic setting for the resource and route security-relevant logs and metrics to a retained Log Analytics workspace, storage account, Event Hub, or approved partner destination.
- Evidence:
  - target resource: address=azurerm_key_vault.public; type=azurerm_key_vault; name=tfstride-public; identifier=/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/tfstride/providers/Microsoft.KeyVault/vaults/tfstride-public
  - diagnostic coverage: no resolved azurerm_monitor_diagnostic_setting targets this resource

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
