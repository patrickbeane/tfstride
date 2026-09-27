# AzureRM Provider Coverage

Azure is an actively supported provider, intentionally scoped, covering virtual machine/App Service/Function App edge exposure, workload-to-data paths, Key Vault CMK-backed cryptographic paths, managed identity/RBAC, and diagnostics/Defender posture.

AzureRM provider detection uses provider source paths ending in `/azurerm` and Terraform resource types prefixed with `azurerm_`. Adjacent providers such as AzAPI, AzureAD, and Azure DevOps are not claimed as AzureRM support.

## Modeled Resources and Families

This is a concise coverage map. Reports identify unsupported AzureRM resource types encountered in each plan.

* `azurerm_storage_account`
* `azurerm_storage_account_network_rules`
* `azurerm_storage_container`
* `azurerm_servicebus_namespace`
* `azurerm_servicebus_namespace_network_rule_set`
* `azurerm_servicebus_namespace_customer_managed_key`
* `azurerm_servicebus_queue`
* `azurerm_servicebus_topic`
* `azurerm_servicebus_subscription`
* `azurerm_container_registry`
* `azurerm_key_vault`
* `azurerm_key_vault_access_policy`
* `azurerm_key_vault_secret`
* `azurerm_key_vault_key`
* `azurerm_key_vault_certificate`
* `azurerm_user_assigned_identity`
* `azurerm_federated_identity_credential`
* `azurerm_role_definition`
* `azurerm_role_assignment`
* `azurerm_virtual_network`
* `azurerm_subnet`
* `azurerm_network_security_group`
* `azurerm_network_security_rule`
* `azurerm_network_watcher_flow_log`
* `azurerm_subnet_network_security_group_association`
* `azurerm_network_interface`
* `azurerm_network_interface_security_group_association`
* `azurerm_public_ip`
* `azurerm_lb`
* `azurerm_application_gateway`
* `azurerm_private_dns_zone`
* `azurerm_private_dns_zone_virtual_network_link`
* `azurerm_linux_virtual_machine`
* `azurerm_windows_virtual_machine`
* `azurerm_private_endpoint`
* `azurerm_linux_web_app`
* `azurerm_windows_web_app`
* `azurerm_function_app`
* `azurerm_linux_function_app`
* `azurerm_windows_function_app`
* `azurerm_kubernetes_cluster`
* `azurerm_mssql_server`
* `azurerm_mssql_database`
* `azurerm_mssql_firewall_rule`
* `azurerm_mssql_virtual_network_rule`
* `azurerm_mssql_server_security_alert_policy`
* `azurerm_postgresql_flexible_server`
* `azurerm_postgresql_flexible_server_database`
* `azurerm_postgresql_flexible_server_firewall_rule`
* `azurerm_postgresql_flexible_server_configuration`
* `azurerm_cosmosdb_account`
* `azurerm_cosmosdb_sql_database`
* `azurerm_cosmosdb_sql_container`
* `azurerm_cosmosdb_sql_role_definition`
* `azurerm_cosmosdb_sql_role_assignment`
* `azurerm_monitor_diagnostic_setting`
* `azurerm_security_center_subscription_pricing`
* `azurerm_security_center_auto_provisioning`
* `azurerm_security_center_contact`
* `azurerm_security_center_workspace`
* `azurerm_security_center_setting`
* `azurerm_advanced_threat_protection`

## Trust Boundaries

Azure trust-boundary records currently cover public storage and Key Vault endpoints plus virtual machines that are reachable through a public IP and effective subnet/NIC NSG decisions.

## Rule Coverage

### Public exposure & edge
* Public storage posture
* Load Balancer and Application Gateway public exposure, and Application Gateway WAF posture
* Precedence-aware broad NSG ingress, and public virtual machines with broad administrative or all-port ingress
* Deterministic public-workload-to-sensitive-resource exposure paths where the required plan facts are available

### Container & image integrity
* App Service and Function App container images without digest pins, and literal sensitive app settings
* Runtime managed identities with exact ACR write access
* Container Registry public-network fallback, admin-account, anonymous-pull, Premium CMK, and private-endpoint posture

### App Service / Function App platform posture
* Public access, platform authentication, TLS, managed-identity, VNet-integration, access-restriction, and SCM posture
* App Service Key Vault reference identity/access paths

App Service normalization also calculates `app_service_effective_ingress` for the
main site and SCM site independently. Each result distinguishes `unrestricted`,
`restricted`, `blocked`, and `unresolved` access and retains source CIDRs, possible
winning rules, default-action evidence, and unresolved constraints. These states
describe the default endpoint's access restrictions across IPv4, IPv6, and
modeled request headers. A narrow public-IP allowlist remains restricted external
access; it does not establish privacy. `external_access=allowed` proves that the
restrictions permit at least one globally routable source, including any required
header witness. It does not establish public routing to an internal App Service
Environment or access through a private endpoint.

Rules use numeric priority followed by preserved list order for modern AzureRM
App Service resources. Conflicting equal-priority rules on legacy Function Apps
retain uncertainty because their ordering contract is not established. tfSTRIDE
does not introduce deny precedence or sort ties by resource address or rule name.
Explicit planned default actions take precedence, including defaults materialized
by AzureRM. When a managed resource has a known unset default, Azure's implicit
behavior applies: allow without rules, deny with rules. Unknown collections,
actions, priorities, and defaults remain uncertain only on subsets where they
could change a decision. Missing data-source inputs are not treated as managed
resource defaults.

Literal IP/CIDR and comma-separated source ranges are evaluated directly. Service
tags, subnet service-endpoint selectors, `AnyVnets`, and unsupported header
patterns retain their constraints without online expansion. Supported exact
header filters are evaluated using a bounded request partition; incomplete
partitions may establish individual witnesses but cannot establish exhaustive
denial. Unknown header values cannot reuse stale planned values. SCM inherits the
main restrictions only when inheritance is established; unknown inheritance
retains both alternatives. Platform authentication is evaluated independently.
An explicitly disabled public endpoint blocks this ingress; unknown endpoint
configuration does not become a public-access claim.

Public-workload data paths, platform-authentication findings, and exposure-based
severity now require a definite allowed external subset from this evaluator.
Ingress is rebuilt once per analysis from current normalized inputs, so stale
decoration metadata cannot preserve or suppress exposure. Findings include the
winning restriction/default decisions, source scopes, request constraints, and
authentication posture. Authentication does not make a reachable endpoint private.
Blocked or unresolved ingress does not remove workload-to-data authorization facts.
Configuration-posture findings can still report an enabled public endpoint or a
broad configured rule when effective ingress is blocked; those settings alone do
not increase the internet-exposure severity factor. The SCM unrestricted-access
finding requires unrestricted effective SCM ingress across the evaluated address
families and request constraints, independently of main-site ingress.

The restriction semantics follow
[Microsoft's App Service access restriction model](https://learn.microsoft.com/azure/app-service/overview-access-restrictions)
and the modern AzureRM
[restriction list schema](https://github.com/hashicorp/terraform-provider-azurerm/blob/main/internal/services/appservice/helpers/shared_schema.go).

### Workload-to-data paths
* Exact public App Service-to-Key Vault, Storage, Service Bus, and Cosmos DB for NoSQL read and mutation paths across account, database, and container scopes
* Exact public App Service-to-Service Bus receive and destructive-settlement paths for modeled queues and subscriptions, including namespace-scoped RBAC fanout
* Public App Service ARM topology-deletion paths for modeled Service Bus namespaces, queues, topics, and subscriptions, with plan-local management-lock compatibility
* Public App Service Blob deletion paths with container-namespace scope, versioning, soft-delete, HNS, and permanent-delete compatibility evidence
* Public App Service Blob container-topology disruption paths for exact RBAC container-delete authority, with protected-content emptiness left unestablished
* Public App Service Cosmos DB item-deletion and control-plane account/database/container topology-disruption paths with native backup and management-lock evidence
* Public App Service Key Vault secret-value tampering and recoverable or permanent secret-disruption paths for runtime identity authority
* External, explicitly denied, or incompatible Key Vault paths stay quiet; condition-dependent, incomplete, ambiguous, or unresolved expected paths remain uncertainty where modeled

### Data-store posture
* Storage encryption ownership, Blob versioning, soft-delete, HNS, and permanent-delete recovery posture
* SQL and PostgreSQL public access, recovery, and transport hardening
* Cosmos DB for NoSQL customer-managed encryption, Continuous backup/recovery, minimum TLS, public network, local authentication, and Private Endpoint posture
* Service Bus namespace public-network, minimum-TLS, local/SAS-auth, Premium CMK, and private-endpoint posture, plus queue/subscription status, auto-forwarding, TTL, lock-duration, and dead-letter evidence

### Key Vault & cryptographic paths
* Key Vault network/recovery/authorization posture, exact versioned/versionless key identities, key expiration, HSM-backed key types, rotation, and cryptographic operations
* Legacy access-policy and native RBAC source/scope, supported built-in/custom key permissions, and condition/uncertainty posture
* Exact encrypted-resource dependencies and operation-aware downstream blast-radius enrichment
* Public App Service and Function App-to-Key Vault decrypt, unwrap, and signing paths for attached runtime identities and compatible key options
* Public App Service Key Vault key-disruption and authorization-delegation paths for data-plane lifecycle or ARM control-plane authority
* Key Vault secret and certificate lifecycle posture

### Networking & telemetry
* Private Endpoint coverage, DNS posture, and public fallback for supported data-plane resources
* NSG Flow Logs coverage, enabled-state, destination, and retention posture

### Audit & detection
* Diagnostic settings coverage, diagnostic log destination, and audit-category completeness
* Public App Service managed identities with current `Microsoft.Insights/DiagnosticSettings/Delete` authority over an exact audit-relevant diagnostic-setting ARM target, subject to current destination and management-lock compatibility and reported as prospective Repudiation risk
* Defender pricing and auto-provisioning posture

### IAM & identity
* Custom RBAC role breadth and assigned blast radius
* Privileged built-in RBAC assignments, managed identity broad RBAC assignments, and federated managed identity privilege paths

### Kubernetes (AKS)
* Control-plane, auth, network-policy, workload-identity, KMS, monitoring, Defender, and Azure Policy posture

Key Vault key and secret posture, public workload cryptographic-operation paths, and public workload key or secret administration paths are plan-local and require modeled authorization. See [Public Workload Secret Integrity and Availability Paths](../analysis/secret-management-paths.md).

## Scope & Limitations

* Azure service breadth is intentionally scoped; see the resource and rule lists above for current coverage.
* Identity analysis is scoped to managed identities, federated identity credentials, exact issuer/subject/audience trust paths, role assignments, custom role definitions, Key Vault access policies, built-in privileged RBAC roles, and vault-scoped role assignments when they resolve deterministically in the plan.
* Private Endpoint analysis is scoped to coverage, DNS-zone-group posture, and public-fallback posture for supported Storage, Key Vault, SQL, Premium Service Bus namespace, and Premium Container Registry resources.
* Diagnostic analysis is scoped to resolved diagnostic settings for supported sensitive resources and modeled Defender/Security Center resources.
* AKS support covers public/private API posture, authorized IP restrictions, local account usage, RBAC posture, network policy posture, workload identity/OIDC, KMS, monitoring, Defender, and Azure Policy signals when represented in the plan.
* App Service support covers modeled platform authentication and strict sensitive app-setting delivery, but does not verify application-level authentication, application code, or routing behavior outside the Terraform plan.
* Messaging findings establish modeled managed-identity authority, not successful payload retrieval, settlement or topology deletion, replay, or recovery; see [Public Workload Messaging Disclosure and Disruption Paths](../analysis/messaging-paths.md).
* Diagnostic-setting disruption findings establish current authority over an exact modeled ARM extension-resource target, not a successful operation, historical/source or already-delivered telemetry deletion, destination-resource deletion, disruption of every diagnostic setting on the parent resource or across the subscription/tenant, out-of-plan disruption, or recovery/restoration.
* Deeper AKS workload/node posture, full Private DNS record correctness, App Service routing/application-level authentication modeling, and broader Azure RBAC hierarchy modeling are not covered yet.
* Azure observations distinguish restricted network posture, identity authorization posture, private-endpoint uncertainty, and unresolved Azure plan values.

See [Cross-Provider Threat-Path Semantics](../analysis/path-semantics.md) for how these findings relate to the shared cross-provider evidence model, including how network telemetry and public edge-protection checks are implemented per provider.
