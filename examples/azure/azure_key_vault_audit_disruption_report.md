# tfSTRIDE Threat Model Report

- Analyzed file: `sample_azure_key_vault_audit_disruption_plan.json`
- Provider: `azure`
- Normalized resources: `4`
- Unsupported resources: `0`

## Summary

This run identified **0 trust boundaries** and **8 findings** across **4 normalized resources**.

- High severity findings: `2`
- Medium severity findings: `6`
- Low severity findings: `0`

## Analysis Coverage

- Terraform resources seen: `4`
- Provider resources considered: `4`
- Normalized resources: `4`
- Unsupported resources: `0`
- Resources with plan-time unknown values: `0`
- Registered provider rules (Azure): `116`
- Enabled provider rules (Azure): `116`
- Disabled rules: `0`
- Severity overrides: `0`
- Configuration-reference resolution: `0 symbolic`, `0 ambiguous`, `0 unresolved`, `0 unsupported`
- Recorded unresolved modeled references: `0`
- Findings by rule:
  - `azure-managed-identity-broad-rbac`: `1`
  - `azure-app-service-public-network-access-not-disabled`: `1`
  - `azure-app-service-minimum-tls-unknown`: `1`
  - `azure-app-service-vnet-integration-missing`: `1`
  - `azure-app-service-access-restrictions-not-default-deny`: `1`
  - `azure-app-service-scm-access-unrestricted`: `1`
  - `azure-public-app-service-diagnostic-setting-disruption`: `1`
  - `azure-diagnostic-settings-missing`: `1`

Sensitive resource labels are assumptions based on resource class. tfSTRIDE does not assess stored data contents from the plan.

## Discovered Trust Boundaries

No trust boundaries were discovered.

## Findings

### High

#### Azure managed identity has broad RBAC authority

- STRIDE category: Elevation of Privilege
- Affected resources: `azurerm_linux_web_app.orders`, `azurerm_role_assignment.monitoring`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +2, data_sensitivity +1, lateral_movement +1, blast_radius +2, final_score 6 => high
- Rationale: azurerm_linux_web_app.orders has Azure role assignments with broad scope or high-impact built-in roles. These grants expand what the managed identity can do if the workload or deployment path using it is compromised.
- Recommended mitigation: Replace broad managed identity role assignments with least-privilege resource-scoped roles, split deployment and runtime identities, and avoid subscription or resource-group scope unless required.
- Evidence:
  - managed identity: address=azurerm_linux_web_app.orders; identity_type=SystemAssigned; principal_id=app-system-principal-id
  - role assignments: source=azurerm_role_assignment.monitoring; role=Monitoring Contributor; scope=/subscriptions/sub-0001; scope_kind=subscription; signals=subscription_scope
  - breadth signals: subscription_scope

#### Public Azure App Service identity can disrupt audit telemetry export

- STRIDE category: Repudiation
- Affected resources: `azurerm_linux_web_app.orders`, `azurerm_monitor_diagnostic_setting.key_vault_audit`, `azurerm_key_vault.orders`, `azurerm_role_assignment.monitoring`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +2, data_sensitivity +2, lateral_movement +1, blast_radius +1, final_score 8 => high
- Rationale: azurerm_linux_web_app.orders permits external ingress within the evidenced scope and its current App Service runtime identity has deterministic Microsoft.Insights/DiagnosticSettings/Delete authority over 1 exact diagnostic setting that currently export modeled audit/security telemetry to log_analytics_workspace /subscriptions/sub-0001/resourceGroups/obs/providers/Microsoft.OperationalInsights/workspaces/security. A compromise of the public workload could request deletion of those exact diagnostic-setting targets, disrupting future export or recording of the modeled audit/security telemetry and weakening auditability/accountability. This plan-local evidence does not establish a successful API call or deletion, deletion of historical/source telemetry, deletion of logs already delivered to Log Analytics, deletion of logs already delivered to Storage, deletion of logs already delivered to Event Hubs, deletion of logs already delivered to marketplace/partner destinations, deletion of the destination resource, disruption of every parent-resource, subscription, or tenant diagnostic setting, disruption of out-of-plan settings, recovery/restoration, or broader service availability impact.
- Recommended mitigation: Restrict public App Service ingress and grant its runtime identity only the exact Microsoft.Insights/DiagnosticSettings/Delete action and diagnostic-setting target required. Keep diagnostic-setting administration on separate operational identities and preserve a modeled audit/security telemetry destination protected from public workload credentials.
- Evidence:
  - public endpoint: address=azurerm_linux_web_app.orders; type=azurerm_linux_web_app; site=main; public_network_access_enabled=true; assessment_scope=default_endpoint_access_restrictions
  - effective public ingress: workload=azurerm_linux_web_app.orders; site=main; state=unrestricted; external_access=allowed; allowed_source_cidrs=["0.0.0.0/0","::/0"]; default_action=Allow; default_action_source=implicit_allow_without_rules; decision={"allowed_source_cidrs":["0.0.0.0/0","::/0"],"blocked_source_cidrs":[],"default_action":"Allow","default_action_source":"implicit_allow_without_rules","endpoint_evidence":"public_network_access_enabled=true","external_access":"allowed","header_partition_complete":true,"header_witness_limit":32,"restriction_state":"unrestricted","rule_evidence":[],"rule_order":"priority_with_unresolved_ties","source_scopes":[{"default_possible":true,"possible_actions":["Allow"],"rule_indices":[],"source_cidrs":["0.0.0.0/0"],"state":"allowed"},{"default_possible":true,"possible_actions":["Allow"],"rule_indices":[],"source_cidrs":["::/0"],"state":"allowed"}],"state":"unrestricted","uncertainties":[]}
  - app service authentication: workload=azurerm_linux_web_app.orders; auth_settings_v2={"auth_enabled_state":"not_configured","require_authentication_state":"not_configured","token_store_state":"not_configured"}; auth_settings={"enabled_state":"not_configured","token_store_state":"not_configured"}; Authentication qualifies request access independently of network reachability; application-level authentication is not established by this plan.
  - runtime identity: identity_address=azurerm_linux_web_app.orders; identity_kind=system_assigned; principal_id=app-system-principal-id; credential_context=workload_runtime
  - diagnostic setting audit telemetry disruption paths: diagnostic_setting_address=azurerm_monitor_diagnostic_setting.key_vault_audit; diagnostic_setting_name=key-vault-audit; diagnostic_setting_id=/subscriptions/sub-0001/resourceGroups/ops/providers/Microsoft.KeyVault/vaults/orders-kv|key-vault-audit; diagnostic_setting_reference=/subscriptions/sub-0001/resourceGroups/ops/providers/Microsoft.KeyVault/vaults/orders-kv|key-vault-audit; diagnostic_setting_arm_id=/subscriptions/sub-0001/resourceGroups/ops/providers/Microsoft.KeyVault/vaults/orders-kv/providers/Microsoft.Insights/diagnosticSettings/key-vault-audit; monitored_resource_address=azurerm_key_vault.orders; monitored_resource_id=/subscriptions/sub-0001/resourceGroups/ops/providers/Microsoft.KeyVault/vaults/orders-kv; operation=Microsoft.Insights/DiagnosticSettings/Delete; operation_class=diagnostic_setting_deletion; target_granularity=diagnostic_setting; target_scope=exact_monitor_diagnostic_setting; role_assignment_address=azurerm_role_assignment.monitoring; authorization_sources=azurerm_role_assignment.monitoring; role=Monitoring Contributor; role_kind=built_in; role_actions=Microsoft.Insights/DiagnosticSettings/*; role_not_actions=none; authorization_state=granted; operation_evaluation=deterministic_allowed
  - diagnostic setting destination evidence: diagnostic_setting_address=azurerm_monitor_diagnostic_setting.key_vault_audit; destination_basis=log_analytics_workspace; log_analytics_workspace_id=/subscriptions/sub-0001/resourceGroups/obs/providers/Microsoft.OperationalInsights/workspaces/security; storage_account_id=unknown; eventhub_authorization_rule_id=unknown; eventhub_name=unknown; marketplace_partner_resource_id=unknown; destination_state=configured
  - diagnostic setting audit telemetry relevance evidence: diagnostic_setting_address=azurerm_monitor_diagnostic_setting.key_vault_audit; relevance_basis=audit_security_category; matched_audit_security_category=AuditEvent; matched_audit_security_category_group=unknown; enabled_log_categories=AuditEvent; enabled_log_category_groups=none; audit_telemetry_relevance_state=established
  - diagnostic setting management lock evidence: diagnostic_setting_address=azurerm_monitor_diagnostic_setting.key_vault_audit; modeled_management_lock_state=not_observed; deletion_compatibility_state=compatible; blocking_lock_present=false
  - diagnostic setting outcome evidence: diagnostic_setting_address=azurerm_monitor_diagnostic_setting.key_vault_audit; successful_operation_observed=false; historical_log_deletion_authorized_by_operation=false; historical_log_deletion_observed=false; destination_resource_deletion_authorized_by_operation=false; destination_resource_deletion_observed=false; all_resource_diagnostic_settings_evaluated=false; out_of_plan_diagnostic_settings_evaluated=false; telemetry_recovery_state=not_established_by_modeled_azure_diagnostic_setting_evidence; restoration_observed=false; uncertainties=none
  - assessment scope: establishes=Repudiation risk from deterministic Microsoft.Insights/DiagnosticSettings/Delete authority over exact currently audit/security-relevant diagnostic settings; effect=compromise of the public App Service could disrupt future export or recording of the modeled audit/security telemetry to the configured destination, weakening auditability/accountability; does_not_establish=successful API operation, diagnostic-setting deletion, historical or source telemetry deletion, deletion of logs already delivered to any destination, destination-resource deletion, disruption of every or out-of-plan diagnostic setting, recovery/restoration, or broader service availability impact

### Medium

#### Azure App Service SCM endpoint access is unrestricted

- STRIDE category: Elevation of Privilege
- Affected resources: `azurerm_linux_web_app.orders`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +1, data_sensitivity +0, lateral_movement +1, blast_radius +1, final_score 5 => medium
- Rationale: azurerm_linux_web_app.orders permits SCM/Kudu requests from every source in at least one IP address family without access restrictions requiring particular request headers. The deployment endpoint exposes privileged application management operations; authentication remains a separate access control.
- Recommended mitigation: Restrict SCM/Kudu access with explicit SCM access restrictions or inherit a default-deny main-site restriction set, and keep deployment operations behind trusted networks or private build agents.
- Evidence:
  - target resource: address=azurerm_linux_web_app.orders; type=azurerm_linux_web_app
  - network posture: public_network_fallback_state=enabled; public_network_access_enabled is true
  - public endpoint: address=azurerm_linux_web_app.orders; type=azurerm_linux_web_app; site=scm; public_network_access_enabled=true; assessment_scope=default_endpoint_access_restrictions
  - effective public ingress: workload=azurerm_linux_web_app.orders; site=scm; state=unrestricted; external_access=allowed; allowed_source_cidrs=["0.0.0.0/0","::/0"]; default_action=Allow; default_action_source=implicit_allow_without_rules; decision={"allowed_source_cidrs":["0.0.0.0/0","::/0"],"blocked_source_cidrs":[],"default_action":"Allow","default_action_source":"implicit_allow_without_rules","endpoint_evidence":"public_network_access_enabled=true","external_access":"allowed","header_partition_complete":true,"header_witness_limit":32,"inheritance":"separate","restriction_state":"unrestricted","rule_evidence":[],"rule_order":"priority_with_unresolved_ties","source_scopes":[{"default_possible":true,"possible_actions":["Allow"],"rule_indices":[],"source_cidrs":["0.0.0.0/0"],"state":"allowed"},{"default_possible":true,"possible_actions":["Allow"],"rule_indices":[],"source_cidrs":["::/0"],"state":"allowed"}],"state":"unrestricted","uncertainties":[]}
  - app service authentication: workload=azurerm_linux_web_app.orders; auth_settings_v2={"auth_enabled_state":"not_configured","require_authentication_state":"not_configured","token_store_state":"not_configured"}; auth_settings={"enabled_state":"not_configured","token_store_state":"not_configured"}; Authentication qualifies request access independently of network reachability; application-level authentication is not established by this plan.
  - scm access restrictions: scm_use_main_ip_restriction is not represented; scm_ip_restriction_default_action is not represented; scm_ip_restriction_count=0

#### Azure App Service access restrictions are not default deny

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_linux_web_app.orders`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +0, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: azurerm_linux_web_app.orders does not establish a default-deny access restriction posture for the main site. This configuration finding does not establish effective ingress; earlier matching rules can still block requests.
- Recommended mitigation: Set the App Service `ip_restriction_default_action` to `Deny` and allow only reviewed client CIDRs, service tags, or subnet-based paths when the app intentionally keeps public network access.
- Evidence:
  - target resource: address=azurerm_linux_web_app.orders; type=azurerm_linux_web_app
  - network posture: public_network_fallback_state=enabled; public_network_access_enabled is true
  - public endpoint: address=azurerm_linux_web_app.orders; type=azurerm_linux_web_app; site=main; public_network_access_enabled=true; assessment_scope=default_endpoint_access_restrictions
  - effective public ingress: workload=azurerm_linux_web_app.orders; site=main; state=unrestricted; external_access=allowed; allowed_source_cidrs=["0.0.0.0/0","::/0"]; default_action=Allow; default_action_source=implicit_allow_without_rules; decision={"allowed_source_cidrs":["0.0.0.0/0","::/0"],"blocked_source_cidrs":[],"default_action":"Allow","default_action_source":"implicit_allow_without_rules","endpoint_evidence":"public_network_access_enabled=true","external_access":"allowed","header_partition_complete":true,"header_witness_limit":32,"restriction_state":"unrestricted","rule_evidence":[],"rule_order":"priority_with_unresolved_ties","source_scopes":[{"default_possible":true,"possible_actions":["Allow"],"rule_indices":[],"source_cidrs":["0.0.0.0/0"],"state":"allowed"},{"default_possible":true,"possible_actions":["Allow"],"rule_indices":[],"source_cidrs":["::/0"],"state":"allowed"}],"state":"unrestricted","uncertainties":[]}
  - app service authentication: workload=azurerm_linux_web_app.orders; auth_settings_v2={"auth_enabled_state":"not_configured","require_authentication_state":"not_configured","token_store_state":"not_configured"}; auth_settings={"enabled_state":"not_configured","token_store_state":"not_configured"}; Authentication qualifies request access independently of network reachability; application-level authentication is not established by this plan.
  - access restrictions: ip_restriction_default_action is not represented; ip_restriction_count=0

#### Azure App Service does not configure VNet integration

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_linux_web_app.orders`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +1, lateral_movement +0, blast_radius +1, final_score 4 => medium
- Rationale: azurerm_linux_web_app.orders does not have VNet integration configured, so outbound access to private Azure resources may rely on public endpoints or service-level firewall exceptions.
- Recommended mitigation: Configure regional VNet integration for App Service workloads that call private Azure resources, then prefer private endpoints, service endpoints, or tightly scoped service firewalls for outbound dependencies.
- Evidence:
  - target resource: address=azurerm_linux_web_app.orders; type=azurerm_linux_web_app
  - vnet integration: virtual_network_subnet_id is not configured
  - network posture: public_network_fallback_state=enabled; public_network_access_enabled is true
  - public endpoint: address=azurerm_linux_web_app.orders; type=azurerm_linux_web_app; site=main; public_network_access_enabled=true; assessment_scope=default_endpoint_access_restrictions
  - effective public ingress: workload=azurerm_linux_web_app.orders; site=main; state=unrestricted; external_access=allowed; allowed_source_cidrs=["0.0.0.0/0","::/0"]; default_action=Allow; default_action_source=implicit_allow_without_rules; decision={"allowed_source_cidrs":["0.0.0.0/0","::/0"],"blocked_source_cidrs":[],"default_action":"Allow","default_action_source":"implicit_allow_without_rules","endpoint_evidence":"public_network_access_enabled=true","external_access":"allowed","header_partition_complete":true,"header_witness_limit":32,"restriction_state":"unrestricted","rule_evidence":[],"rule_order":"priority_with_unresolved_ties","source_scopes":[{"default_possible":true,"possible_actions":["Allow"],"rule_indices":[],"source_cidrs":["0.0.0.0/0"],"state":"allowed"},{"default_possible":true,"possible_actions":["Allow"],"rule_indices":[],"source_cidrs":["::/0"],"state":"allowed"}],"state":"unrestricted","uncertainties":[]}
  - app service authentication: workload=azurerm_linux_web_app.orders; auth_settings_v2={"auth_enabled_state":"not_configured","require_authentication_state":"not_configured","token_store_state":"not_configured"}; auth_settings={"enabled_state":"not_configured","token_store_state":"not_configured"}; Authentication qualifies request access independently of network reachability; application-level authentication is not established by this plan.

#### Azure App Service minimum TLS version is not deterministic

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_linux_web_app.orders`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +0, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: azurerm_linux_web_app.orders does not expose a deterministic minimum TLS version in the Terraform plan. tfSTRIDE cannot prove the app enforces TLS 1.2 or newer from the available data.
- Recommended mitigation: Set the App Service or Function App `minimum_tls_version` explicitly to `1.2` or newer so the planned endpoint posture is reviewable before deployment.
- Evidence:
  - target resource: address=azurerm_linux_web_app.orders; type=azurerm_linux_web_app
  - transport posture: minimum_tls_version is not represented in planned values
  - network posture: public_network_fallback_state=enabled; public_network_access_enabled is true
  - public endpoint: address=azurerm_linux_web_app.orders; type=azurerm_linux_web_app; site=main; public_network_access_enabled=true; assessment_scope=default_endpoint_access_restrictions
  - effective public ingress: workload=azurerm_linux_web_app.orders; site=main; state=unrestricted; external_access=allowed; allowed_source_cidrs=["0.0.0.0/0","::/0"]; default_action=Allow; default_action_source=implicit_allow_without_rules; decision={"allowed_source_cidrs":["0.0.0.0/0","::/0"],"blocked_source_cidrs":[],"default_action":"Allow","default_action_source":"implicit_allow_without_rules","endpoint_evidence":"public_network_access_enabled=true","external_access":"allowed","header_partition_complete":true,"header_witness_limit":32,"restriction_state":"unrestricted","rule_evidence":[],"rule_order":"priority_with_unresolved_ties","source_scopes":[{"default_possible":true,"possible_actions":["Allow"],"rule_indices":[],"source_cidrs":["0.0.0.0/0"],"state":"allowed"},{"default_possible":true,"possible_actions":["Allow"],"rule_indices":[],"source_cidrs":["::/0"],"state":"allowed"}],"state":"unrestricted","uncertainties":[]}
  - app service authentication: workload=azurerm_linux_web_app.orders; auth_settings_v2={"auth_enabled_state":"not_configured","require_authentication_state":"not_configured","token_store_state":"not_configured"}; auth_settings={"enabled_state":"not_configured","token_store_state":"not_configured"}; Authentication qualifies request access independently of network reachability; application-level authentication is not established by this plan.

#### Azure App Service public network access is not disabled

- STRIDE category: Information Disclosure
- Affected resources: `azurerm_linux_web_app.orders`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +0, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: azurerm_linux_web_app.orders does not explicitly disable public network access. App Service public endpoint reachability depends on this setting and any additional platform access controls; leave it disabled unless the app intentionally accepts public traffic.
- Recommended mitigation: Set `public_network_access_enabled` to `false` for private apps, or document the required public entry path and pair it with authentication, access restrictions, and monitored ingress controls.
- Evidence:
  - target resource: address=azurerm_linux_web_app.orders; type=azurerm_linux_web_app
  - network posture: public_network_fallback_state=enabled; public_network_access_enabled is true
  - public endpoint: address=azurerm_linux_web_app.orders; type=azurerm_linux_web_app; site=main; public_network_access_enabled=true; assessment_scope=default_endpoint_access_restrictions
  - effective public ingress: workload=azurerm_linux_web_app.orders; site=main; state=unrestricted; external_access=allowed; allowed_source_cidrs=["0.0.0.0/0","::/0"]; default_action=Allow; default_action_source=implicit_allow_without_rules; decision={"allowed_source_cidrs":["0.0.0.0/0","::/0"],"blocked_source_cidrs":[],"default_action":"Allow","default_action_source":"implicit_allow_without_rules","endpoint_evidence":"public_network_access_enabled=true","external_access":"allowed","header_partition_complete":true,"header_witness_limit":32,"restriction_state":"unrestricted","rule_evidence":[],"rule_order":"priority_with_unresolved_ties","source_scopes":[{"default_possible":true,"possible_actions":["Allow"],"rule_indices":[],"source_cidrs":["0.0.0.0/0"],"state":"allowed"},{"default_possible":true,"possible_actions":["Allow"],"rule_indices":[],"source_cidrs":["::/0"],"state":"allowed"}],"state":"unrestricted","uncertainties":[]}
  - app service authentication: workload=azurerm_linux_web_app.orders; auth_settings_v2={"auth_enabled_state":"not_configured","require_authentication_state":"not_configured","token_store_state":"not_configured"}; auth_settings={"enabled_state":"not_configured","token_store_state":"not_configured"}; Authentication qualifies request access independently of network reachability; application-level authentication is not established by this plan.

#### Azure resource lacks diagnostic settings

- STRIDE category: Repudiation
- Affected resources: `azurerm_linux_web_app.orders`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +1, lateral_movement +0, blast_radius +1, final_score 4 => medium
- Rationale: azurerm_linux_web_app.orders has no resolved Azure Monitor diagnostic setting in this Terraform plan. Security-relevant data-plane, control-plane, or platform logs may not be routed to a retained logging destination for investigation and alerting.
- Recommended mitigation: Add an Azure Monitor diagnostic setting for the resource and route security-relevant logs and metrics to a retained Log Analytics workspace, storage account, Event Hub, or approved partner destination.
- Evidence:
  - target resource: address=azurerm_linux_web_app.orders; type=azurerm_linux_web_app; name=orders; identifier=/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Web/sites/orders
  - public endpoint: address=azurerm_linux_web_app.orders; type=azurerm_linux_web_app; site=main; public_network_access_enabled=true; assessment_scope=default_endpoint_access_restrictions
  - effective public ingress: workload=azurerm_linux_web_app.orders; site=main; state=unrestricted; external_access=allowed; allowed_source_cidrs=["0.0.0.0/0","::/0"]; default_action=Allow; default_action_source=implicit_allow_without_rules; decision={"allowed_source_cidrs":["0.0.0.0/0","::/0"],"blocked_source_cidrs":[],"default_action":"Allow","default_action_source":"implicit_allow_without_rules","endpoint_evidence":"public_network_access_enabled=true","external_access":"allowed","header_partition_complete":true,"header_witness_limit":32,"restriction_state":"unrestricted","rule_evidence":[],"rule_order":"priority_with_unresolved_ties","source_scopes":[{"default_possible":true,"possible_actions":["Allow"],"rule_indices":[],"source_cidrs":["0.0.0.0/0"],"state":"allowed"},{"default_possible":true,"possible_actions":["Allow"],"rule_indices":[],"source_cidrs":["::/0"],"state":"allowed"}],"state":"unrestricted","uncertainties":[]}
  - app service authentication: workload=azurerm_linux_web_app.orders; auth_settings_v2={"auth_enabled_state":"not_configured","require_authentication_state":"not_configured","token_store_state":"not_configured"}; auth_settings={"enabled_state":"not_configured","token_store_state":"not_configured"}; Authentication qualifies request access independently of network reachability; application-level authentication is not established by this plan.
  - diagnostic coverage: no resolved azurerm_monitor_diagnostic_setting targets this resource

### Low

No findings in this severity band.

## Controls Observed

### Azure Key Vault network access is restricted

- Category: `data-protection`
- Affected resources: `azurerm_key_vault.orders`
- Rationale: azurerm_key_vault.orders is not broadly reachable through its public endpoint. Network controls are evaluated separately from the identities authorized to use the vault.
- Evidence:
  - network posture: public_network_access_enabled is false

### Azure managed identity principal is modeled

- Category: `iam`
- Affected resources: `azurerm_linux_web_app.orders`
- Rationale: azurerm_linux_web_app.orders exposes a `SystemAssigned` managed identity principal. Role assignments are connected only when principal IDs are known in the Terraform plan.
- Evidence:
  - identity type: SystemAssigned
  - principal id: app-system-principal-id
  - tenant id: tenant-id
  - analysis scope: managed identity role assignments are connected when principal IDs are deterministic; transitive access findings are not emitted from managed identity assignments yet

### Azure managed identity role assignment is connected

- Category: `iam`
- Affected resources: `azurerm_linux_web_app.orders`, `azurerm_role_assignment.monitoring`
- Rationale: azurerm_linux_web_app.orders has Azure role assignments whose `principal_id` matches this managed identity. Scope breadth is reported separately from any downstream exposure rule.
- Evidence:
  - role assignment sources: azurerm_role_assignment.monitoring
  - role definition names: Monitoring Contributor
  - role definition ids: /subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/749f88d5-cbae-40b8-bcfc-e573ddc772fa
  - scopes: /subscriptions/sub-0001
  - scope kinds: subscription
  - breadth signals: subscription_scope
  - analysis scope: identity-to-role connection is modeled without inferring transitive data exposure

## Limitations / Unsupported Resources

- Azure support covers a curated AzureRM set including Storage, Service Bus, Container Registry, Key Vault, SQL/PostgreSQL, App Service/Function Apps, AKS, networking and public edge, Private Endpoint/DNS-zone-group, diagnostic/Defender, and RBAC/identity posture. Remaining limitations include full Private DNS record correctness, broader RBAC hierarchy, MySQL, runtime application authentication and routing, full AKS node/workload posture, and unsupported platform services; analysis remains plan-local. Azure deny assignments are not evaluated for modeled Blob authorization.
- The engine reasons over Terraform planned values only and does not validate runtime drift, runtime audit evidence, or post-deployment control-plane activity.
