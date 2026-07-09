# tfSTRIDE & Policy Gate

`tfstride` turns Terraform plan JSON into evidence-backed cloud threat models - trust boundaries, STRIDE findings, and observed controls - before `terraform apply`. It reasons over **relationships and trust paths across resources**, not just per-resource configuration.

**Zero runtime dependencies for the base CLI/core engine** (`dependencies = []`). The default install has no transitive packages; dashboard and development extras are intentionally separate. That keeps the supply-chain surface small for a tool run against production-account plan files.

> **Use an IaC scanner** such as Checkov, Trivy, or Snyk IaC to ask: *which resource-level controls are missing?*
> **Use `tfstride`** to ask: *what architecture risk - and which trust paths - does this plan introduce?*

An IaC scanner may flag the load balancer, the subnet, and the database as separate findings. `tfstride` connects them into the path that matters:

```markdown
#### Sensitive data tier is transitively reachable from an internet-exposed path

- STRIDE category: Information Disclosure
- Affected resources: `aws_lb.web`, `aws_instance.app`, `aws_db_instance.app`
- Rationale: `aws_db_instance.app` is not directly public, but internet traffic can reach
  `aws_lb.web`, move through `aws_instance.app`, and cross into the private data tier -
  a quieter transitive exposure path than a directly public data store.
- Evidence:
  - internet reaches `aws_lb.web`
  - `aws_lb.web` reaches `aws_instance.app`
  - `aws_instance.app` reaches `aws_db_instance.app`
```

`--fail-on` turns a finding like the one above into a CI gate:

```text
Policy gate failed: 3 finding(s) meet or exceed `high` (3 high).
```

Generated example output - see [`examples/aws/aws_alb_ec2_rds_report.md`](examples/aws/aws_alb_ec2_rds_report.md).

Where `tfstride` fits beside IaC scanners:

| A reviewer's question | Better fit |
| --- | --- |
| Does this change create a path from the internet to a private data tier? | `tfstride` |
| Does a workload inherit privileges that expand blast radius if compromised? | `tfstride` |
| Is cross-account, cross-project, or federated trust narrowed by supported conditions? | `tfstride` |
| Broad policy catalogs and compliance checks across all resources? | Checkov / Trivy / Snyk IaC |

Full comparison - different jobs, transitive exposure, workload blast radius, scope & limits - in [`docs/when-to-use-tfstride.md`](docs/when-to-use-tfstride.md).

## What It Does

`tfstride` analyzes Terraform plan JSON and produces evidence-backed reports for supported cloud providers.

It currently supports AWS, GCP, and AzureRM through provider plugins for normalization, decoration, rule contribution, metadata, resource facts, and trust-boundary analysis.

Core capabilities:

* Offline Terraform plan analysis
* Provider-aware normalization for supported cloud resources
* Trust-boundary detection
* STRIDE-oriented security findings
* Stable finding fingerprints
* Markdown, JSON, and SARIF 2.1.0 output
* CI policy gating with `--fail-on low|medium|high`
* Suppressions and baselines for incremental adoption
* Repo-level TOML configuration
* Optional FastAPI dashboard

## Quickstart

Run directly from source:

```bash
PYTHONPATH=src python3 -m tfstride fixtures/aws/sample_aws_plan.json
```

Install locally:

```bash
python3 -m pip install -e .
tfstride fixtures/aws/sample_aws_plan.json --output threat-model.md
```

Generate Terraform plan JSON:

```bash
terraform plan -out tfplan
terraform show -json tfplan > tfplan.json
```

Analyze a plan:

```bash
tfstride tfplan.json --quiet --output threat-model.md
```

Emit JSON and SARIF:

```bash
tfstride tfplan.json \
  --quiet \
  --json-output threat-model.json \
  --sarif-output threat-model.sarif
```

Gate a plan in CI:

```bash
tfstride tfplan.json --quiet --fail-on high
```

Provider detection defaults to `auto`. For mixed-provider plans, select a provider explicitly:

```bash
tfstride tfplan.json --provider aws --quiet
tfstride tfplan.json --provider gcp --quiet
tfstride tfplan.json --provider azure --quiet
```

List registered rules:

```bash
tfstride --list-rules
tfstride --list-rules --json
```

## Provider Support

| Provider | Status          | Coverage Summary                                                                                                                                     |
| -------- | --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| AWS      | Deepest support | EC2, ECS/Fargate, Lambda and Function URLs, ALB listener TLS posture, EKS control-plane/add-on posture, RDS endpoint/recovery/encryption posture, S3 public/encryption/versioning posture, Secrets Manager recovery/encryption/rotation posture, KMS rotation/deletion posture, VPC endpoint/private service posture, VPC Flow Logs telemetry posture, account audit/detection posture, IAM and privileged role-assignment posture, SNS/SQS, VPC routing, security groups, trust boundaries, and control observations. |
| GCP      | Active support  | Compute, GKE control-plane/auth/hardening posture, Cloud SQL, GCS public/encryption/versioning/retention posture, load balancer TLS posture, subnet Flow Logs telemetry posture, Private Service Access and Private Google Access posture, Secret Manager lifecycle/encryption posture, KMS rotation/destruction posture, audit logging/SCC posture, IAM and privileged assignment posture, Cloud Run, Cloud Functions, Pub/Sub, BigQuery, firewall posture, and workload-to-data paths. |
| Azure    | Active support  | Azure Storage public/encryption/recovery/private-endpoint posture, Key Vault network/key/secret lifecycle posture, SQL/PostgreSQL recovery and exposure posture, App Service/Function Apps access posture, AKS control-plane/auth/add-on posture, Load Balancer/Application Gateway exposure, NSG Flow Logs telemetry posture, diagnostic settings/Defender posture, managed identity, built-in RBAC, and custom RBAC posture, NSG-aware public ingress, public VM exposure, and workload-to-sensitive-resource paths. |

Unsupported resources are skipped and called out in the report.

<details>
<summary>Detailed AWS resource coverage</summary>

AWS support currently includes:

* `aws_instance`
* `aws_ecs_service`
* `aws_ecs_task_definition`
* `aws_ecs_cluster`
* `aws_eks_cluster`
* `aws_eks_addon`
* `aws_security_group`
* `aws_security_group_rule`
* `aws_nat_gateway`
* `aws_lb`
* `aws_lb_listener`
* `aws_lb_listener_rule`
* `aws_lb_target_group`
* `aws_db_instance`
* `aws_s3_bucket`
* `aws_s3_bucket_policy`
* `aws_s3_bucket_public_access_block`
* `aws_s3_bucket_versioning`
* `aws_s3_bucket_server_side_encryption_configuration`
* `aws_iam_role`
* `aws_iam_policy`
* `aws_iam_role_policy`
* `aws_iam_role_policy_attachment`
* `aws_iam_instance_profile`
* `aws_lambda_function`
* `aws_lambda_function_url`
* `aws_lambda_permission`
* `aws_kms_key`
* `aws_sns_topic`
* `aws_sqs_queue`
* `aws_secretsmanager_secret`
* `aws_secretsmanager_secret_rotation`
* `aws_secretsmanager_secret_policy`
* `aws_subnet`
* `aws_vpc`
* `aws_internet_gateway`
* `aws_route_table`
* `aws_route_table_association`
* `aws_vpc_endpoint`
* `aws_flow_log`
* `aws_cloudtrail`
* `aws_guardduty_detector`
* `aws_securityhub_account`
* `aws_config_configuration_recorder`

AWS rule coverage includes public compute ingress, public Lambda Function URL invocation, ALB listener HTTP/TLS certificate/SSL-policy posture, EKS public endpoint/CIDR/private-endpoint posture, EKS secrets encryption, authentication mode, control-plane logging, and VPC CNI network-policy posture, VPC Flow Logs coverage, traffic-type, and destination posture, S3 public-access/encryption/versioning posture, RDS public endpoint, backup retention, deletion protection, and customer-managed KMS posture, Secrets Manager customer-managed key, recovery-window, and rotation posture, KMS key rotation and deletion-window posture, workload use of S3, KMS, or Secrets Manager without modeled VPC endpoint coverage, broad VPC endpoint policies, CloudTrail multi-region, log-validation, event-selector, data-event, and Insights posture, GuardDuty, Security Hub, and AWS Config baseline posture, IAM wildcard permissions, privileged role-assignment posture, workload-role sensitive permissions, resource-policy exposure, tier segmentation, transitive private-data exposure, control-plane-to-sensitive-workload chains, and role-trust narrowing.

</details>

<details>
<summary>Detailed GCP resource coverage</summary>

GCP support currently includes normalization and analysis for:

* `google_compute_instance`
* `google_container_cluster`
* `google_container_node_pool`
* `google_compute_network`
* `google_compute_subnetwork`
* `google_compute_firewall`
* GCP firewall policy, rule, and association resources
* `google_compute_route`
* `google_compute_router`
* `google_compute_router_nat`
* `google_compute_forwarding_rule`
* `google_compute_global_forwarding_rule`
* `google_compute_backend_service`
* `google_compute_backend_bucket`
* `google_compute_url_map`
* `google_compute_region_url_map`
* `google_compute_target_http_proxy`
* `google_compute_target_https_proxy`
* `google_compute_region_target_http_proxy`
* `google_compute_region_target_https_proxy`
* `google_compute_ssl_policy`
* `google_compute_managed_ssl_certificate`
* `google_compute_service_attachment`
* `google_compute_global_address`
* `google_service_networking_connection`
* `google_network_connectivity_service_connection_policy`
* `google_cloud_run_service`
* `google_cloud_run_v2_service`
* Cloud Run IAM member, binding, and policy resources
* `google_cloudfunctions_function`
* `google_cloudfunctions2_function`
* Cloud Functions IAM member, binding, and policy resources
* Organization, folder, and project IAM member, binding, and policy resources
* Project and organization custom IAM roles
* `google_service_account`
* `google_service_account_key`
* GCP service-account IAM member, binding, and policy resources
* `google_pubsub_topic`
* `google_pubsub_subscription`
* Pub/Sub IAM member, binding, and policy resources
* `google_bigquery_dataset`
* `google_bigquery_table`
* BigQuery dataset and table IAM member, binding, and policy resources
* `google_sql_database_instance`
* `google_secret_manager_secret`
* Secret Manager secret IAM member, binding, and policy resources
* `google_kms_crypto_key`
* Cloud KMS crypto-key and key-ring IAM member, binding, and policy resources
* `google_storage_bucket`
* GCS bucket IAM member, binding, and policy resources
* `google_logging_project_sink`
* `google_logging_organization_sink`
* `google_logging_project_exclusion`
* `google_logging_organization_exclusion`
* `google_scc_organization_settings`

GCP trust-boundary coverage includes public compute, GKE control planes, Cloud Run, Cloud Functions, external forwarding rules, Cloud SQL, GCS buckets, Cloud NAT posture, and workload-to-sensitive-data paths through GCE, Cloud Run, and Cloud Functions service accounts.

GCP rule coverage includes public compute ingress, external load balancer HTTP/TLS and SSL-policy posture, GKE public control-plane and authorized-network posture, Workload Identity, legacy metadata, node identity, control-plane logging, network policy, secrets encryption, legacy ABAC, client-certificate auth, Shielded Nodes, and Binary Authorization posture, subnet Flow Logs coverage and capture-completeness posture, Cloud SQL exposure, private-service-access, and recovery posture, Private Google Access posture for private workloads, GCS public-access, encryption, versioning, and retention posture, Secret Manager customer-managed encryption and lifecycle posture, Cloud KMS rotation and key-version destruction posture, Security Command Center asset-discovery posture, logging exclusions that drop audit/security logs, logging sink destination/filter coverage, central audit sink modeling, broad IAM access to sensitive services, privileged IAM assignment posture, internet-exposed workloads with sensitive data access, broad organization/folder/project IAM principals, service-account key hygiene, and custom-role permission expansion.

GCP currently emphasizes findings and evidence over provider-specific positive observation records; dedicated GCP observation records are still limited.

</details>

<details>
<summary>Detailed Azure resource coverage</summary>

Azure support currently includes normalization, decoration, and analysis for AzureRM resources:

* `azurerm_storage_account`
* `azurerm_storage_account_network_rules`
* `azurerm_storage_container`
* `azurerm_key_vault`
* `azurerm_key_vault_access_policy`
* `azurerm_key_vault_secret`
* `azurerm_key_vault_key`
* `azurerm_key_vault_certificate`
* `azurerm_user_assigned_identity`
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
* `azurerm_monitor_diagnostic_setting`
* `azurerm_security_center_subscription_pricing`
* `azurerm_security_center_auto_provisioning`
* `azurerm_security_center_contact`
* `azurerm_security_center_workspace`
* `azurerm_security_center_setting`
* `azurerm_advanced_threat_protection`

AzureRM provider detection uses provider source paths ending in `/azurerm` and Terraform resource types prefixed with `azurerm_`. Adjacent providers such as AzAPI, AzureAD, and Azure DevOps are not claimed as AzureRM support.

Azure trust-boundary coverage includes public storage and Key Vault endpoints plus virtual machines that are reachable through a public IP and effective subnet/NIC NSG decisions.

Azure rule coverage includes public storage posture, storage encryption ownership and recovery posture, Key Vault network/recovery/authorization posture, Key Vault key rotation and key-strength posture, Key Vault secret and certificate lifecycle posture, SQL and PostgreSQL public access, recovery, and transport hardening, App Service public access, TLS, managed-identity, VNet-integration, access-restriction, and SCM posture, Private Endpoint coverage, DNS posture, and public fallback for supported data-plane resources, Load Balancer and Application Gateway public exposure, NSG Flow Logs coverage, enabled-state, destination, and retention posture, diagnostic settings coverage, diagnostic log destination and audit-category completeness, Defender pricing and auto-provisioning posture, custom RBAC role breadth and assigned blast radius, privileged built-in RBAC assignments, managed identity broad RBAC assignments, AKS control-plane, auth, network-policy, workload-identity, KMS, monitoring, Defender, and Azure Policy posture, precedence-aware broad NSG ingress, public virtual machines with broad administrative or all-port ingress, and deterministic public-workload-to-sensitive-resource exposure paths where the required plan facts are available.

Azure identity analysis is scoped to managed identities, role assignments, custom role definitions, Key Vault access policies, built-in privileged RBAC roles, and vault-scoped role assignments when they resolve deterministically in the Terraform plan. Private Endpoint analysis is scoped to deterministic coverage, DNS-zone-group posture, and public-fallback posture for supported Storage, Key Vault, and SQL resources. Diagnostic analysis is scoped to resolved diagnostic settings for supported sensitive resources and modeled Defender/Security Center resources. Network telemetry analysis is provider-local: AWS checks modeled VPC Flow Logs, GCP checks subnet Flow Logs, and Azure checks modeled Network Watcher flow logs for NSGs. AKS support covers public/private API posture, authorized IP restrictions, local account usage, RBAC posture, network policy posture, workload identity/OIDC, KMS, monitoring, Defender, and Azure Policy signals when represented in the plan. Deeper AKS workload/node posture, full Private DNS record correctness, App Service routing/auth modeling, and broader unsupported platform services are reported as unsupported rather than silently treated as analyzed.

Azure observations distinguish restricted network posture, identity authorization posture, private-endpoint uncertainty, and unresolved Azure plan values.

</details>

## Output Formats

`tfstride` can produce:

* Markdown reports for human review
* JSON reports for automation and dashboards
* SARIF 2.1.0 for scanner-compatible integrations

The JSON report contract is versioned for downstream consumers.

Current report identity:

```text
kind: "tfstride-report"
version: "1.1"
```

Top-level JSON sections include:

* `summary`
* `filtering`
* `analysis_coverage`
* `inventory`
* `trust_boundaries`
* `findings`
* `suppressed_findings`
* `baselined_findings`
* `observations`
* `limitations`

## Suppressions, Baselines, and Config

Suppressions are explicit, reviewable exceptions. Selectors can include fields such as `rule_id`, `resource`, `trust_boundary_id`, `severity`, `title`, or `fingerprint`.

Example suppression file:

```json
{
  "version": "1.0",
  "suppressions": [
    {
      "id": "accept-cross-account-trust",
      "rule_id": "aws-role-trust-expansion",
      "reason": "Tracked in SEC-123 until the deploy role is narrowed."
    }
  ]
}
```

Capture a baseline and gate only on new findings:

```bash
tfstride tfplan.json --quiet --baseline-output baseline.json
tfstride tfplan.json --quiet --baseline baseline.json --fail-on high
```

Use repo config:

```bash
tfstride tfplan.json --config ./tfstride.toml --json-output threat-model.json
```

Example `tfstride.toml`:

```toml
version = "1.0"
title = "Platform Threat Model"
provider = "auto"
fail_on = "high"
baseline = ".tfstride/baseline.json"
suppressions = ".tfstride/suppressions.json"

[rules]
disable = ["aws-role-trust-expansion"]

[rules.severity_overrides]
aws-iam-wildcard-permissions = "low"
```

CLI flags override config values when both are present.

## CI Usage

Policy gating returns exit code `3` when findings meet or exceed the requested threshold.

Minimal pre-apply gate:

```bash
terraform plan -out tfplan
terraform show -json tfplan > tfplan.json
tfstride tfplan.json --quiet --fail-on medium --output threat-model.md --sarif-output threat-model.sarif
terraform apply tfplan
```

GitHub Actions example:

```yaml
name: threat-model

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: python -m pip install -e .
      - run: terraform plan -out tfplan
      - run: terraform show -json tfplan > tfplan.json
      - run: tfstride tfplan.json --quiet --fail-on high --sarif-output tfstride.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: tfstride.sarif
```

## Dashboard

The repo includes an optional FastAPI dashboard in `apps/dashboard/`. It reuses the same engine, findings, and JSON contract as the CLI.

Install dashboard dependencies:

```bash
python3 -m pip install -e '.[dashboard]'
```

Run locally:

```bash
uvicorn apps.dashboard.main:app --reload --port 8001
```

Useful routes:

* `/`: upload form for plan analysis
* `/scenarios`: built-in fixture gallery
* `/demo/{scenario_id}`: built-in demo scenarios
* `/analyze`: upload form POST target
* `/api/analyze`: multipart upload endpoint returning the JSON report contract
* `/api/docs`: OpenAPI docs
* `/healthz`: health endpoint

Deployment examples are included under `apps/dashboard/deploy/`.

## Architecture

`tfstride` is intentionally simple and explainable.

Pipeline:

1. Parse Terraform plan JSON into raw resource records.
2. Auto-select the provider.
3. Normalize supported resources into a provider-agnostic internal model.
4. Run provider-owned decoration for relationships such as role attachments, resource policies, route or NAT posture, public exposure, and workload identities.
5. Build shared analysis indexes.
6. Detect trust boundaries through shared neutral contributors plus the selected provider's boundary contributor.
7. Evaluate STRIDE-oriented rules through the rule registry and provider rule contributions.
8. Observe clear risk-reducing controls.
9. Render Markdown, JSON, or SARIF output.

Current trust boundary types:

* `internet-to-service`
* `public-subnet-to-private-subnet`
* `workload-to-data-store`
* `cross-account-or-role-access`
* `admin-to-workload-plane`

Provider-specific behavior is exposed through plugin contribution points for:

* normalization
* resource capabilities
* resource facts
* rule contributions
* rule metadata catalogs
* trust-boundary contributors
* provider-specific analysis index extensions

Provider-specific rule detectors live in provider-owned domain modules and are wired through each provider's rule contribution root, while rule metadata remains in provider-owned catalogs.

Privileged identity assignment posture is normalized into a shared provider-neutral vocabulary for evidence and parity tests, while findings stay provider-owned so AWS IAM, GCP IAM, and Azure RBAC semantics remain separate.

## Repo Layout

* `src/tfstride/`: CLI, analysis engine, provider plugins, filtering, config, and models
* `src/tfstride/analysis/`: shared rule evaluation, trust-boundary detection, indexes, concepts, coverage, and observations
* `src/tfstride/providers/aws/`: AWS normalization, decoration, rules, facts, metadata, and boundaries
* `src/tfstride/providers/gcp/`: GCP normalization, decoration, rules, facts, metadata, and boundaries
* `src/tfstride/providers/azure/`: AzureRM normalization, decoration, rules, facts, metadata, and boundaries
* `src/tfstride/reporting/`: Markdown, JSON, and SARIF rendering
* `fixtures/`: Terraform plan JSON samples
* `examples/`: generated example reports
* `apps/dashboard/`: optional FastAPI dashboard
* `tests/`: unit, provider, integration, and golden-report coverage

## Demo Assets

The repo includes ready-to-run Terraform plan fixtures and generated example reports.

<details>
<summary>AWS demo assets</summary>

| Scenario                           | Plan                                                                  | Report                                                         |
| ---------------------------------- | --------------------------------------------------------------------- | -------------------------------------------------------------- |
| Safe                               | `fixtures/aws/sample_aws_safe_plan.json`                              | `examples/aws/aws_safe_report.md`                              |
| Baseline                           | `fixtures/aws/sample_aws_baseline_plan.json`                          | `examples/aws/aws_baseline_report.md`                          |
| Realistic ALB / EC2 / RDS          | `fixtures/aws/sample_aws_alb_ec2_rds_plan.json`                       | `examples/aws/aws_alb_ec2_rds_report.md`                       |
| ECS / Fargate                      | `fixtures/aws/sample_aws_ecs_fargate_plan.json`                       | `examples/aws/aws_ecs_fargate_report.md`                       |
| Cross-account trust, unconstrained | `fixtures/aws/sample_aws_cross_account_trust_unconstrained_plan.json` | `examples/aws/aws_cross_account_trust_unconstrained_report.md` |
| Cross-account trust, narrowed      | `fixtures/aws/sample_aws_cross_account_trust_constrained_plan.json`   | `examples/aws/aws_cross_account_trust_constrained_report.md`   |
| Lambda deploy-role                 | `fixtures/aws/sample_aws_lambda_deploy_role_plan.json`                | `examples/aws/aws_lambda_deploy_role_report.md`                |
| Mixed inventory                    | `fixtures/aws/sample_aws_plan.json`                                   | `examples/aws/aws_inventory_report.md`                         |
| Nightmare                          | `fixtures/aws/sample_aws_nightmare_plan.json`                         | `examples/aws/aws_nightmare_report.md`                         |

</details>

<details>
<summary>GCP demo assets</summary>

| Scenario                            | Plan                                                  | Report                                         |
| ----------------------------------- | ----------------------------------------------------- | ---------------------------------------------- |
| Safe                                | `fixtures/gcp/sample_gcp_safe_plan.json`              | `examples/gcp/gcp_safe_report.md`              |
| Baseline                            | `fixtures/gcp/sample_gcp_baseline_plan.json`          | `examples/gcp/gcp_baseline_report.md`          |
| Load balancer / compute / Cloud SQL | `fixtures/gcp/sample_gcp_lb_compute_sql_plan.json`    | `examples/gcp/gcp_lb_compute_sql_report.md`    |
| Serverless                          | `fixtures/gcp/sample_gcp_serverless_plan.json`        | `examples/gcp/gcp_serverless_report.md`        |
| Cross-project IAM                   | `fixtures/gcp/sample_gcp_cross_project_iam_plan.json` | `examples/gcp/gcp_cross_project_iam_report.md` |
| Mixed inventory                     | `fixtures/gcp/sample_gcp_plan.json`                   | `examples/gcp/gcp_inventory_report.md`         |
| Nightmare                           | `fixtures/gcp/sample_gcp_nightmare_plan.json`         | `examples/gcp/gcp_nightmare_report.md`         |

</details>

<details>
<summary>Azure demo assets</summary>

| Scenario         | Plan                                                   | Report                                             |
| ---------------- | ------------------------------------------------------ | -------------------------------------------------- |
| Safe storage     | `fixtures/azure/sample_azure_safe_plan.json`           | `examples/azure/azure_safe_report.md`              |
| Storage posture  | `fixtures/azure/sample_azure_storage_plan.json`        | `examples/azure/azure_storage_report.md`           |
| Public compute   | `fixtures/azure/sample_azure_compute_plan.json`        | `examples/azure/azure_compute_report.md`           |
| Key Vault        | `fixtures/azure/sample_azure_key_vault_plan.json`      | `examples/azure/azure_key_vault_report.md`         |
| Managed identity | `fixtures/azure/sample_azure_identity_plan.json`       | `examples/azure/azure_identity_report.md`          |
| NSG precedence   | `fixtures/azure/sample_azure_nsg_precedence_plan.json` | `examples/azure/azure_nsg_precedence_report.md`    |
| Mixed inventory  | `fixtures/azure/sample_azure_plan.json`                | `examples/azure/azure_inventory_report.md`         |
| Nightmare        | `fixtures/azure/sample_azure_nightmare_plan.json`      | `examples/azure/azure_nightmare_report.md`         |

</details>

Additional Azure regression fixtures cover Private Endpoint normalization/posture and unknown storage posture under `fixtures/azure/`; they are intentionally not all generated as demo reports.

## Development Checks

Install the development extras, then run the full test suite and quality gates:

```bash
python3 -m pip install -e '.[dev,dashboard]'
python3 -m pytest
ruff check .
ruff format --check .
vulture src tests --min-confidence 100
```

The suite is also compatible with stdlib discovery:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Limitations

* AWS is currently the deepest provider implementation.
* GCP support is broad across core workload, data, Kubernetes, private-connectivity, public-edge TLS, and audit/security-posture checks, but still has limited provider-specific positive observation records compared with its finding coverage.
* Azure service breadth is intentionally scoped, but now covers Storage, Key Vault, SQL/PostgreSQL, App Service/Function Apps, AKS posture, Private Endpoint and DNS-zone-group posture, Load Balancer/Application Gateway exposure, diagnostics/Defender posture, NSG flow-log telemetry posture, managed identity, built-in RBAC, and custom RBAC posture, NSG-based public ingress, public virtual-machine exposure, and deterministic sensitive-resource exposure paths.
* Audit, detection, and private-connectivity checks are based on modeled Terraform resources. They do not prove runtime log delivery, DNS resolution, endpoint routing, or cloud-control state outside the plan.
* Deeper managed Kubernetes workload/node posture, full Private Endpoint DNS record correctness, App Service routing/auth modeling, and broader Azure RBAC hierarchy modeling are not covered yet.
* Terraform resource coverage is scoped to security-relevant resources, relationships, and trust paths rather than exhaustive provider parity.
* Subnet classification prefers explicit route table associations when available, but does not model main-route-table inheritance or every routing edge case.
* Identity assignment analysis is deterministic and plan-local: AWS focuses on inline policies, standalone policies, role-policy attachments, and trust policies; GCP focuses on modeled IAM bindings/members and custom roles; Azure focuses on modeled RBAC assignments, managed identities, custom roles, and Key Vault access policies.
* Condition narrowing focuses on high-signal keys such as `SourceArn`, `SourceAccount`, and `ExternalId` rather than every service-specific authorization condition.
* The analyzer works from Terraform plan data only; it does not perform runtime validation, cloud API calls, or drift detection.
* Architecture diagrams and graph visualization are not generated yet.

## Why This Project Exists

Terraform plans are readable, but they are still easy to misjudge when network posture, IAM trust, and data-tier exposure interact.

`tfstride` exists to make those paths explicit with repeatable analysis, concrete evidence, and CI-friendly outputs. It is intentionally scoped to security-relevant resources, relationships, and trust paths across each supported provider rather than pretending to be a full cloud policy engine.

## License

MIT
