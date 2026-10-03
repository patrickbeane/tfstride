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

Core capabilities:

* Offline Terraform plan analysis
* Provider-aware normalization for supported cloud resources
* Trust-boundary detection
* STRIDE-oriented security findings
* Stable finding fingerprints
* Markdown, JSON, and SARIF output
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

`tfstride` supports AWS, GCP, and AzureRM through provider plugins for normalization, decoration, rule contribution, metadata, resource facts, and trust-boundary analysis. Coverage is provider-native and plan-local - similar threat outcomes are parity-tested across providers, but AWS IAM, GCP IAM, and Azure RBAC semantics are never treated as interchangeable.

| Provider | Status | Highlights | Coverage details |
| --- | --- | --- | --- |
| **AWS** | Deepest support | EC2/ECS/Lambda edge & data-plane paths, ECR image integrity, RDS/DynamoDB/S3/Secrets Manager posture, DynamoDB/S3 deletion, recovery, and topology disruption, SQS/SNS messaging-disruption paths, CloudTrail audit-telemetry disruption, KMS/key-disruption paths, IAM/OIDC trust, audit & detection posture | [docs/providers/aws.md](docs/providers/aws.md) |
| **GCP** | Active support | Compute/Cloud Run/Functions edge & data-plane paths, Artifact Registry image integrity, Cloud SQL/Firestore/GCS/Pub/Sub posture, Firestore/GCS deletion, recovery, and topology disruption, Pub/Sub messaging-disruption paths, Cloud Logging sink disruption, KMS CMEK paths, IAM & Workload Identity Federation, SCC & logging posture | [docs/providers/gcp.md](docs/providers/gcp.md) |
| **Azure** | Active support | VM/App Service/Function App edge & data-plane paths, ACR image integrity, Storage/SQL/PostgreSQL/Cosmos DB/Service Bus posture, Cosmos DB/Blob deletion, recovery, and topology disruption, Service Bus messaging-disruption paths, diagnostic-setting disruption, Key Vault CMK paths, managed identity & RBAC, Defender & diagnostic posture | [docs/providers/azure.md](docs/providers/azure.md) |

Unsupported resources are skipped and called out in the report rather than silently treated as analyzed.

## Cross-Provider Path Analysis

Beyond per-resource posture checks, `tfstride` models multi-resource security paths that hold across AWS, GCP, and AzureRM, while keeping each provider's native identity, key, and authorization semantics intact:

* **Managed-key authority** - distinguishes cryptographic operations from disruptive or delegating administration while preserving provider-native authorization and recovery semantics. → [docs/analysis/managed-key-paths.md](docs/analysis/managed-key-paths.md)
* **Managed-key dependencies** - resolves supported encrypted resources to their exact provider-native keys and enriches key-disruption findings with modeled downstream blast radius. → [docs/analysis/managed-key-paths.md](docs/analysis/managed-key-paths.md)
* **Protected-data convergence** - flags when a public workload has both read/receive access to protected data and decrypt/unwrap authority over that data's exact customer-managed key. → [docs/analysis/protected-data-convergence.md](docs/analysis/protected-data-convergence.md)
* **Secret integrity & availability** - distinguishes runtime authority to modify a secret from authority to disable, destroy, delete, or purge it. → [docs/analysis/secret-management-paths.md](docs/analysis/secret-management-paths.md)
* **Object-storage disruption, recovery, and topology destruction** - distinguishes writes and metadata mutation from logical, version, generation, and bucket/container deletion while preserving provider-native scope, recovery, and prerequisite evidence. → [docs/analysis/object-storage-paths.md](docs/analysis/object-storage-paths.md)
* **Structured-data disruption, recovery, and topology destruction** - separates record mutation, item/entity deletion, and table/database/account/container deletion while preserving provider-native scope, protection, and recovery evidence. → [docs/analysis/structured-data-paths.md](docs/analysis/structured-data-paths.md)
* **Messaging disclosure and disruption** - distinguishes send/publish, receive/pull, message removal, and modeled topology deletion while preserving provider-native targets and delivery evidence. → [docs/analysis/messaging-paths.md](docs/analysis/messaging-paths.md)
* **Public-workload audit-telemetry disruption** *(introduced in 0.4.40)* - reports a Repudiation risk when a currently public workload's runtime identity has current authority to disrupt an exact audit/security telemetry target: ECS task-role authority to stop or delete a CloudTrail trail, Cloud Run service-account authority to delete a project logging sink, or App Service managed-identity authority to delete a diagnostic setting. Current provider-native authorization, target state, destination, telemetry relevance, and operation constraints are revalidated before emission. → [docs/analysis/path-semantics.md#audit-telemetry-disruption](docs/analysis/path-semantics.md#audit-telemetry-disruption)

Findings and enrichment across these path families require deterministic modeled evidence. Exact symbolic first-apply references may qualify when resolution is unambiguous. Denied or incompatible evidence stays quiet; condition-dependent, ambiguous, unresolved, unsupported, or incomplete expected relationships remain visible as uncertainty where applicable. For how trust boundaries, evidence, and this "quiet vs. promoted" vocabulary work across providers, see [docs/analysis/path-semantics.md](docs/analysis/path-semantics.md).

## Output Formats

`tfstride` can produce:

* Markdown reports for human review
* JSON reports for automation and dashboards
* SARIF 2.1.0 for scanner-compatible integrations

The JSON report contract is versioned for downstream consumers.

Current report identity:

```text
kind: "tfstride-report"
version: "1.2"
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

`analysis_coverage.references` reports configuration-reference outcomes independently: symbolically resolved, ambiguous, unresolved, and unsupported relationships. The legacy `unresolved_reference_count` field remains separate and counts unresolved modeled-reference metadata rather than graph-resolution outcomes.

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

Identity, workload data-plane, and managed-key findings all follow the same pattern: a shared provider-neutral vocabulary for evidence and parity tests, with findings themselves staying provider-owned. See [docs/analysis/path-semantics.md](docs/analysis/path-semantics.md) for exactly how that plays out across AWS IAM, GCP IAM, and Azure RBAC.

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
basedpyright
ruff check .
ruff format --check .
vulture src tests --min-confidence 100
```

The scoped basedpyright gate protects provider/plugin contracts, configuration-reference and symbolic relationship resolution, metadata ownership, and the typed managed-key, protected-data convergence, and secret-management pipelines; it is intentionally not full-repository strict mode yet.

The suite is also compatible with stdlib discovery:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Limitations

* AWS is currently the deepest provider implementation; GCP and Azure are both under active/broad support but intentionally scoped - see each provider doc for current coverage and provider-specific limits.
* Managed-key blast-radius evidence counts exact in-plan dependency relationships; it does not claim coverage of external consumers or prove which key version protects runtime data unless the provider model establishes that relationship (details in [docs/analysis/managed-key-paths.md](docs/analysis/managed-key-paths.md)).
* Object-storage recovery and topology-prerequisite evidence is provider-native and plan-local. It does not prove successful deletion, bucket/container emptiness, out-of-plan descendants, target recoverability, or runtime recovery (details in [docs/analysis/object-storage-paths.md](docs/analysis/object-storage-paths.md)).
* Structured-data protection and recovery evidence is provider-native and plan-local. It does not prove successful deletion, out-of-plan descendants, immediate item-level undo, or restoration (details in [docs/analysis/structured-data-paths.md](docs/analysis/structured-data-paths.md)).
* Messaging findings establish plan-local operation authority, not successful payload retrieval, message or topology deletion, replay, or recovery; runtime receipt handles, acknowledgement IDs, and lock tokens are never invented (details in [docs/analysis/messaging-paths.md](docs/analysis/messaging-paths.md)).
* Public-workload audit-telemetry disruption findings describe potential future recording or export disruption for the exact modeled target, weakening auditability/accountability. They do not establish a successful API call or deletion, historical/source telemetry deletion, deletion of telemetry already delivered to a destination, destination-resource deletion, account-, project-, subscription-, or tenant-wide disruption, out-of-plan disruption, or recovery/restoration.
* Audit, detection, and private-connectivity checks are based on modeled Terraform resources. They do not prove runtime log delivery, DNS resolution, endpoint routing, or cloud-control state outside the plan.
* Terraform resource coverage is scoped to security-relevant resources, relationships, and trust paths rather than exhaustive provider parity.
* Subnet classification prefers explicit route table associations when available, but does not model main-route-table inheritance or every routing edge case.
* Identity-assignment analysis is deterministic and plan-local - AWS, GCP, and Azure each model a different set of native identity constructs; see each provider doc for specifics.
* The analyzer works from Terraform plan data only; it does not perform runtime validation, cloud API calls, or drift detection.
* Architecture diagrams and graph visualization are not generated yet.

## Why This Project Exists

Terraform plans are readable, but they are still easy to misjudge when network posture, IAM trust, and data-tier exposure interact.

`tfstride` exists to make those paths explicit with repeatable analysis, concrete evidence, and CI-friendly outputs. It is intentionally scoped to security-relevant resources, relationships, and trust paths across each supported provider rather than pretending to be a full cloud policy engine.

## License

MIT
