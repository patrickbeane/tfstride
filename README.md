# tfSTRIDE & Policy Gate

`tfstride` converts Terraform plan JSON into reviewable cloud threat models, trust boundaries, STRIDE-oriented findings, and observed protective controls for AWS infrastructure before deployment.

## Overview

This project turns Terraform plan JSON into a cloud threat model for AWS infrastructure before deployment. It normalizes supported resources, identifies trust boundaries, evaluates rule-based STRIDE checks, and produces evidence-backed findings plus observed protective controls for human review and CI gating.

The engine is intentionally small and explainable: no LLMs in the core path, no full graph engine, and no runtime cloud access. The goal is to make risky infrastructure patterns easier to review before `terraform apply`.

## Features

- offline Terraform plan analysis with no LLM in the core pipeline
- trust-boundary detection plus STRIDE-oriented findings
- IAM graph resolution for inline policies, role attachments, and EC2 instance profiles present in the plan
- initial ECS/Fargate workload modeling via ECS service and task definition normalization
- resource-policy analysis for sensitive data services and invoke/publish/queue surfaces
- condition-aware narrowing for trust and resource policies using supported source constraints
- informational controls observed for clear mitigating signals
- machine-readable JSON output with stable finding fingerprints
- markdown and SARIF 2.1.0 output
- CLI rule registry listing in text and JSON for reviewable rule IDs, STRIDE categories, tags, and mitigations
- CI policy gating with `--fail-on low|medium|high`
- suppressions and baselines to focus gating on active new findings
- repo-level TOML config for provider selection, default gating, rule selection, and severity overrides
- automation-friendly `--quiet` mode and non-zero exit behavior
- zero runtime dependencies for the core CLI engine, with optional dashboard dependencies
- AWS-first analysis behind a provider registry with initial GCP inventory normalization

## Quickstart

Run directly from source:

```bash
PYTHONPATH=src python3 -m tfstride fixtures/sample_aws_plan.json
```

Install the CLI locally:

```bash
python3 -m pip install -e .
tfstride fixtures/sample_aws_plan.json --output threat-model.md
```

Generate a Terraform plan JSON from an infrastructure repo:

```bash
terraform plan -out tfplan
terraform show -json tfplan > tfplan.json
```

Gate a plan in CI and emit SARIF alongside the markdown report:

```bash
tfstride tfplan.json --quiet --fail-on high --output threat-model.md --sarif-output threat-model.sarif
```

Emit a machine-readable JSON report:

```bash
tfstride tfplan.json --quiet --json-output threat-model.json
```

Provider detection defaults to `auto`. For mixed-provider plans, select one provider explicitly:

```bash
tfstride tfplan.json --provider aws --quiet
tfstride tfplan.json --provider gcp --quiet --json-output threat-model.json
```

List the registered rules and their metadata without analyzing a plan:

```bash
tfstride --list-rules
tfstride --list-rules --json
```

The JSON report contract is versioned for downstream consumers. The current report payload uses:

- `kind: "tfstride-report"`
- `version: "1.1"`

Capture the current unsuppressed findings as a baseline and later gate only on new findings:

```bash
tfstride tfplan.json --quiet --baseline-output baseline.json
tfstride tfplan.json --quiet --fail-on high --baseline baseline.json
```

Use a checked-in repo config so CI and local runs share the same defaults:

```bash
tfstride tfplan.json --quiet
tfstride tfplan.json --config ./tfstride.toml --json-output threat-model.json
```

## Dashboard

The repo also includes a thin FastAPI dashboard in `apps/dashboard/`. It reuses the same engine, findings, and JSON contract as the CLI rather than adding a second analysis path.

Install the web dependencies:

```bash
python3 -m pip install -e '.[dashboard]'
```

Run the dashboard locally from the repo root:

```bash
uvicorn apps.dashboard.main:app --reload --port 8001
```

Useful routes:

- `/`: upload form for plan analysis
- `/scenarios`: built-in fixture gallery page
- `/demo/{scenario_id}`: built-in fixture scenarios such as `safe`, `mixed`, and `nightmare`
- `/analyze`: upload form POST target that renders an HTML report
- `/api/analyze`: multipart upload endpoint that returns the JSON report contract
- `/api/docs`: OpenAPI docs for the dashboard API
- `/healthz`: simple health endpoint for process and proxy checks

Deployment notes:

- a repo-tracked `systemd` unit example lives at `apps/dashboard/deploy/tfstride-dashboard.service`
- the checked-in example assumes the app lives at `/home/fleet/tfstride`, runs as user `fleet`, binds `uvicorn` to `127.0.0.1:8001`, and sets `PYTHONPATH` to the repo `src/` directory
- copy that unit to `/etc/systemd/system/tfstride-dashboard.service` on the host, then run `sudo systemctl daemon-reload && sudo systemctl enable --now tfstride-dashboard`
- a simple Caddy reverse-proxy example lives at `apps/dashboard/deploy/Caddyfile.example`

## Example Output

Example finding excerpt:

```markdown
#### Database is reachable from overly permissive sources

- STRIDE category: Information Disclosure
- Trust boundary: `workload-to-data-store:aws_instance.app->aws_db_instance.app`
- Severity reasoning: internet_exposure +2, data_sensitivity +2, lateral_movement +1, blast_radius +1, final_score 6 => high
- Evidence:
  - security group rules: aws_security_group.db ingress tcp 5432 from 0.0.0.0/0
  - network path: database trusts security groups attached to internet-exposed workloads
```

Expected outcome on a failing plan:

```text
Policy gate failed: 3 finding(s) meet or exceed `high` (3 high).
```

## CI Usage

GitHub Actions example with SARIF upload and high-severity gating:

Policy gating returns exit code `3` when findings meet or exceed the requested threshold.

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

Pre-apply gating example:

```bash
terraform plan -out tfplan
terraform show -json tfplan > tfplan.json
tfstride tfplan.json --quiet --fail-on medium --output threat-model.md --sarif-output threat-model.sarif
terraform apply tfplan
```

## Demo Scenarios

The repo includes several ready-to-run Terraform plan fixtures:

- `sample_aws_alb_ec2_rds_plan.json`: public ALB, private EC2 app tier, and private encrypted RDS to demonstrate a composed transitive data-path finding on a common web architecture
- `sample_aws_baseline_plan.json`: mostly segmented environment with a deliberate IAM hygiene issue and a non-obvious private-data path to demonstrate the baseline detector surface
- `sample_aws_cross_account_trust_unconstrained_plan.json`: minimal cross-account assume-role trust without narrowing conditions to exercise the IAM trust finding path
- `sample_aws_cross_account_trust_constrained_plan.json`: similar cross-account trust narrowed by `ExternalId`, `SourceArn`, and `SourceAccount` so the report surfaces the control instead of the finding
- `sample_aws_ecs_fargate_plan.json`: ECS service and task definition coverage for Fargate-style workloads, task roles, execution roles, and private data access
- `sample_aws_lambda_deploy_role_plan.json`: private Lambda deployment path with scoped S3 access and deliberate cross-account trust to exercise IAM and trust findings without public-network noise
- `sample_gcp_plan.json`: Google provider smoke fixture that auto-selects GCP and normalizes the initial compute, network, IAM, and storage inventory set
- `sample_aws_safe_plan.json`: private-by-default reference environment with protected storage, private database access, and no active findings
- `sample_aws_plan.json`: mixed case with public exposure, permissive database reachability, risky IAM, and cross-account trust
- `sample_aws_nightmare_plan.json`: deliberately broken environment with stacked public access, public storage, wildcard IAM, risky workload roles, and blast-radius expansion

## Architecture

Input:

- Terraform plan JSON generated by `terraform show -json`

Pipeline:

1. Parse the Terraform plan into raw resource records.
2. Auto-select the provider, normalize supported resources into a provider-agnostic internal model, and decorate in-plan AWS relationships such as role attachments, resource policies, route-table posture, and public-access blocks.
3. Build shared analysis indexes for role lookup, security-group membership, public workloads by security group, and attached security groups.
4. Detect trust boundaries such as internet-to-service, public-to-private segmentation, workload-to-data-store access, control-plane-to-workload relationships, and cross-account trust.
5. Evaluate rule-based STRIDE checks through a `RuleEvaluationContext` that carries the inventory, boundary index, rule registry, rule policy, and shared analysis indexes.
6. Observe clear risk-reducing controls.
7. Render markdown and optionally JSON or SARIF output.

The engine is intentionally simple and explainable:

- trust boundaries model crossings that matter for review rather than a full graph engine
- rules operate on normalized infrastructure facts, not raw Terraform JSON
- severity uses a small additive model across internet exposure, privilege breadth, data sensitivity, lateral movement, and blast radius

Current trust boundary types:

- `internet-to-service`
- `public-subnet-to-private-subnet`
- `workload-to-data-store`
- `cross-account-or-role-access`
- `admin-to-workload-plane`

Current rules include:

- internet-exposed compute with overly broad ingress
- databases reachable from public or otherwise permissive sources
- unencrypted RDS storage
- public S3 exposure
- sensitive resource policies that allow public or cross-account access
- service resource policies that allow public or cross-account access
- wildcard IAM privileges
- workload roles with sensitive permissions
- missing segmentation between public workloads and private data tiers
- sensitive data tiers transitively reachable from internet-exposed paths
- broad or cross-account control-plane paths that reach workloads with private database or secret access
- trust relationships that expand blast radius
- cross-account or broad trust without narrowing conditions

Outputs include:

- summary counts and discovered trust boundaries
- findings grouped by severity with rationale, mitigation, evidence, and severity reasoning
- controls observed when the engine sees clear mitigating signals such as S3 public access blocks, narrowed trust, or private encrypted RDS
- analysis coverage showing resource coverage, unsupported types, rule posture, finding counts, and unresolved in-plan references
- JSON output with normalized resources, findings, observations, fingerprints, and filtering summary
- markdown for human review
- SARIF 2.1.0 for scanner-compatible integrations

### Internal Modeling Notes

- `ResourceMetadata` and `InventoryMetadata` define typed metadata fields for normalized and inventory-level enrichment.
- New provider-specific or decorator-derived facts should usually be added as typed metadata fields and accessed through `get_metadata_field()`, `set_metadata_field()`, or `append_metadata_field()`.
- `NormalizedResource` properties are reserved for stable, broadly used normalized concepts such as network posture, public exposure, identity relationships, and data sensitivity.
- `AnalysisIndexes` is computed once from the inventory and reused by trust-boundary detection and rule detectors. Add shared lookup needs there instead of rebuilding detector-local maps.
- `resource_concepts.py` centralizes conceptual resource groups and predicates such as workloads, data stores, public edges, identity roles, and security groups. Prefer those helpers over scattered hard-coded resource-type sets when the semantics match exactly.

## JSON Contract

The JSON report is intended to be the stable machine interface for future dashboards and automation.

Top-level sections:

- `kind`
- `version`
- `tool`
- `title`
- `analyzed_file`
- `analyzed_path`
- `summary`
- `filtering`
- `analysis_coverage`
- `inventory`
- `trust_boundaries`
- `findings`
- `suppressed_findings`
- `baselined_findings`
- `observations`
- `limitations`

Contract notes:

- additive fields may appear within the same major version
- breaking structural changes should increment the major version
- `inventory.resources` and `trust_boundaries` are serialized in stable sorted order for downstream consumers
- `analysis_coverage` summarizes parsed resource coverage, enabled rules, severity overrides, finding counts by rule, and unresolved in-plan references

## Suppressions And Baselines

Suppressions are explicit, reviewable exceptions. The CLI accepts a JSON file with one or more selectors such as `rule_id`, `resource`, `trust_boundary_id`, `severity`, `title`, or `fingerprint`.

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

Baselines are generated by the tool and keyed by stable finding fingerprints so CI can focus on newly introduced findings:

```bash
tfstride tfplan.json --quiet --baseline-output baseline.json
tfstride tfplan.json --quiet --baseline baseline.json --fail-on high
```

## Repo Config

The CLI auto-discovers `tfstride.toml` from the current working directory or the plan file directory. You can also pass it explicitly with `--config`.

CLI flags still win over config values when both are present.

Example:

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

Supported config keys:

- `title`
- `provider`
- `fail_on`
- `baseline`
- `suppressions`
- `rules.enable`
- `rules.disable`
- `rules.severity_overrides`

## Supported AWS Resources

The MVP intentionally supports a focused resource set:

- `aws_instance`
- `aws_ecs_service`
- `aws_ecs_task_definition`
- `aws_ecs_cluster`
- `aws_security_group`
- `aws_security_group_rule`
- `aws_nat_gateway`
- `aws_lb`
- `aws_db_instance`
- `aws_s3_bucket`
- `aws_s3_bucket_policy`
- `aws_s3_bucket_public_access_block`
- `aws_iam_role`
- `aws_iam_policy`
- `aws_iam_role_policy`
- `aws_iam_role_policy_attachment`
- `aws_iam_instance_profile`
- `aws_lambda_function`
- `aws_lambda_permission`
- `aws_kms_key`
- `aws_sns_topic`
- `aws_sqs_queue`
- `aws_secretsmanager_secret`
- `aws_secretsmanager_secret_policy`
- `aws_subnet`
- `aws_vpc`
- `aws_internet_gateway`
- `aws_route_table`
- `aws_route_table_association`

Unsupported resources are skipped and called out in the report.

## GCP Support

The GCP provider is registered for provider detection and supports initial inventory normalization for `google_compute_instance`, `google_compute_network`, `google_compute_subnetwork`, `google_compute_firewall`, `google_project_iam_member`, and `google_storage_bucket`.

GCP trust-boundary detection, controls observed, and STRIDE rule coverage are not implemented yet, so GCP reports currently expose normalized inventory and coverage without findings.

## Repo Layout (Abridged)

```text
.
├── fixtures/
│   ├── sample_aws_alb_ec2_rds_plan.json
│   ├── sample_aws_baseline_plan.json
│   ├── sample_aws_cross_account_trust_constrained_plan.json
│   ├── sample_aws_cross_account_trust_unconstrained_plan.json
│   ├── sample_aws_ecs_fargate_plan.json
│   ├── sample_aws_lambda_deploy_role_plan.json
│   ├── sample_aws_nightmare_plan.json
│   ├── sample_aws_plan.json
│   ├── sample_aws_safe_plan.json
│   └── sample_gcp_plan.json
├── examples/
│   ├── alb_ec2_rds_report.md
│   ├── baseline_report.md
│   ├── gcp_inventory_report.md
│   ├── lambda_deploy_role_report.md
│   ├── nightmare_report.md
│   ├── sample_report.md
│   └── safe_report.md
├── apps/
│   └── dashboard/
│       ├── api_models.py
│       ├── deploy/
│       │   ├── Caddyfile.example
│       │   └── tfstride-dashboard.service
│       ├── static/dashboard.css
│       ├── templates/
│       │   ├── base.html
│       │   ├── index.html
│       │   ├── report.html
│       │   └── scenarios.html
│       └── main.py
├── src/
│   └── tfstride/
│       ├── __init__.py
│       ├── analysis/
│       │   ├── control_observations.py
│       │   ├── coverage.py
│       │   ├── iam_rules.py
│       │   ├── indexes.py
│       │   ├── network_data_rules.py
│       │   ├── path_chain_rules.py
│       │   ├── policy_conditions.py
│       │   ├── policy_trust_rules.py
│       │   ├── posture_rules.py
│       │   ├── resource_concepts.py
│       │   ├── rule_definitions.py
│       │   ├── rule_registry.py
│       │   ├── stride_rules.py
│       │   └── trust_boundaries.py
│       ├── input/
│       │   └── terraform_plan.py
│       ├── providers/
│       │   ├── base.py
│       │   ├── catalog.py
│       │   ├── registry.py
│       │   └── aws/
│       │       ├── compute_normalizers.py
│       │       ├── data_normalizers.py
│       │       ├── iam_normalizers.py
│       │       ├── network_normalizers.py
│       │       ├── normalizer.py
│       │       ├── resource_decorator.py
│       │       ├── resource_decoration_stages.py
│       │       └── resource_index.py
│       ├── reporting/
│       │   ├── json_report.py
│       │   ├── markdown.py
│       │   └── sarif.py
│       ├── app.py
│       ├── cli.py
│       ├── config.py
│       ├── filtering.py
│       ├── models.py
│       └── resource_metadata.py
└── tests/
```

## Limitations

- AWS remains the only provider with trust-boundary, rule, and control-observation coverage today
- GCP support is limited to initial inventory normalization for selected core resource types
- Azure provider support is not registered yet
- deliberately incomplete Terraform resource coverage
- subnet classification prefers explicit route table associations when available, but does not model main-route-table inheritance or every routing edge case
- IAM analysis focuses on inline policies, standalone policies, role-policy attachments, and trust policies rather than a full attachment graph
- supported condition narrowing is intentionally focused on keys such as `SourceArn`, `SourceAccount`, and `ExternalId` rather than every service-specific authorization condition
- no runtime validation, cloud API calls, or drift detection
- no architecture diagrams or graph visualization

## Sample Assets

- Safe:
  [`fixtures/sample_aws_safe_plan.json`](fixtures/sample_aws_safe_plan.json),
  [`examples/safe_report.md`](examples/safe_report.md)
- Baseline:
  [`fixtures/sample_aws_baseline_plan.json`](fixtures/sample_aws_baseline_plan.json),
  [`examples/baseline_report.md`](examples/baseline_report.md)
- Realistic ALB / EC2 / RDS:
  [`fixtures/sample_aws_alb_ec2_rds_plan.json`](fixtures/sample_aws_alb_ec2_rds_plan.json),
  [`examples/alb_ec2_rds_report.md`](examples/alb_ec2_rds_report.md)
- ECS / Fargate:
  [`fixtures/sample_aws_ecs_fargate_plan.json`](fixtures/sample_aws_ecs_fargate_plan.json)
- Cross-account trust, unconstrained:
  [`fixtures/sample_aws_cross_account_trust_unconstrained_plan.json`](fixtures/sample_aws_cross_account_trust_unconstrained_plan.json)
- Cross-account trust, narrowed:
  [`fixtures/sample_aws_cross_account_trust_constrained_plan.json`](fixtures/sample_aws_cross_account_trust_constrained_plan.json)
- Lambda deploy-role:
  [`fixtures/sample_aws_lambda_deploy_role_plan.json`](fixtures/sample_aws_lambda_deploy_role_plan.json),
  [`examples/lambda_deploy_role_report.md`](examples/lambda_deploy_role_report.md)
- GCP initial inventory:
  [`fixtures/sample_gcp_plan.json`](fixtures/sample_gcp_plan.json),
  [`examples/gcp_inventory_report.md`](examples/gcp_inventory_report.md)
- Mixed:
  [`fixtures/sample_aws_plan.json`](fixtures/sample_aws_plan.json),
  [`examples/sample_report.md`](examples/sample_report.md)
- Nightmare:
  [`fixtures/sample_aws_nightmare_plan.json`](fixtures/sample_aws_nightmare_plan.json),
  [`examples/nightmare_report.md`](examples/nightmare_report.md)

## Testing

Run the unit tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Why This Project Exists

Terraform plans are readable, but they are still easy to misjudge when network posture, IAM trust, and data-tier exposure interact. This project exists to make those paths explicit with repeatable analysis, concrete evidence, and CI-friendly outputs.

It is intentionally scoped to a small AWS-first surface area so the output stays understandable and stable rather than pretending to be a full cloud policy engine.

## License

MIT