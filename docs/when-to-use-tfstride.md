# How tfSTRIDE Complements IaC Scanners

tfSTRIDE is not a replacement for tools like Checkov, Trivy, or Snyk IaC.

Those tools are better fits for broad IaC policy coverage, compliance checks,
and resource-level best-practice scanning. tfSTRIDE is narrower: it analyzes
Terraform plan JSON for provider-aware architecture-risk patterns,
trust-boundary crossings, workload-to-data paths, identity blast radius, and
STRIDE-oriented findings that are useful during infrastructure review.

tfSTRIDE is best used as an architecture-risk layer beside your existing IaC 
scanner, not as a replacement for one.

Use both when the workflows overlap:

```text
IaC scanner -> broad security baseline
tfSTRIDE    -> architecture-risk and trust-boundary review
```

## Different Jobs

| Question                                                                                       | Better fit               |
| ---------------------------------------------------------------------------------------------- | ------------------------ |
| Is this storage bucket missing versioning, logging, lifecycle, or public-access controls?      | Checkov, Trivy, Snyk IaC |
| Is this load balancer missing access logs, WAF, or header hardening?                           | Checkov, Trivy, Snyk IaC |
| Does this Terraform change create a path from the internet to a private data tier?             | tfSTRIDE                 |
| Does a workload inherit privileges that expand blast radius if compromised?                    | tfSTRIDE                 |
| Is cross-account, cross-project, or federated trust narrowed by provider-supported conditions? | tfSTRIDE                 |
| Do I need code-scanning output for broad policy catalogs?                                      | Checkov, Trivy, Snyk IaC |
| Do I need SARIF output for architecture-risk findings?                                         | tfSTRIDE                 |

## What tfSTRIDE Adds

tfSTRIDE focuses on findings that need context across multiple resources.

### Transitive Exposure

An IaC scanner may report a public load balancer, subnet posture, firewall or
security group rules, and database settings as separate findings.

tfSTRIDE tries to answer the architecture question:

> Can internet traffic reach an application tier that can then reach sensitive
> data?

Example finding using AWS resources:

```text
Sensitive data tier is transitively reachable from an internet-exposed path

internet -> aws_lb.web -> aws_instance.app -> aws_db_instance.app
```

The database may not be directly public, but the path still matters during a
security review. The same type of graph analysis applies to equivalent GCP and
Azure resource relationships where tfSTRIDE has coverage.

### Tier Segmentation

Generic scanners are good at detecting public ingress and missing hardening
controls. tfSTRIDE adds the tiering context:

```text
Private data tier directly trusts the public application tier
```

That finding ties together subnet posture, firewall or security group trust,
public-facing workloads, and database reachability across providers. The goal is
to make lateral movement risk visible before `terraform apply`.

### Workload Blast Radius

Broad IAM findings are common in IaC scanners. tfSTRIDE tries to connect those
permissions to the workload that receives them.

Example using AWS resources:

```text
Workload role carries sensitive permissions

aws_lambda_function.processor inherits:
- iam:PassRole
- kms:Decrypt
- s3:*
- sts:AssumeRole
```

The review question is not only "is this policy broad?" It is "what can this
workload do if it is compromised?" The same idea applies to GCP service accounts
and Azure managed identities.

### Cross-Boundary Trust Narrowing

tfSTRIDE distinguishes broad or cross-boundary trust from trust that is narrowed
by supported conditions. On AWS this includes assume-role conditions such as
`ExternalId`, `SourceArn`, and `SourceAccount`. Provider-specific narrowing
controls on GCP and Azure are evaluated where tfSTRIDE has coverage.

Example:

```text
Finding:
Cross-account or broad role trust lacks narrowing conditions

Control observed:
Cross-account or broad role trust is narrowed by assume-role conditions
```

That distinction is useful when reviewing deployment roles, CI/CD roles,
federated trust paths, and identity relationships that cross trust boundaries.

## Provider Coverage

tfSTRIDE supports AWS, GCP, and Azure Terraform provider analysis with active
coverage across compute, storage, IAM, networking, and managed database
resources. Coverage depth varies by provider and resource type.

| Provider | Status          | Coverage Summary                                                                                                                                                                                                                                                                        |
| -------- | --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| AWS      | Deepest support | EC2, ECS/Fargate, Lambda and Function URLs, EKS control-plane/add-on posture, RDS endpoint/recovery/encryption posture, S3 public/encryption/versioning posture, IAM, KMS, SNS/SQS, Secrets Manager, VPC routing, security groups, trust boundaries, and control observations.          |
| GCP      | Active support  | Compute, GKE control-plane/auth/hardening posture, Cloud SQL, GCS public/encryption/versioning/retention posture, IAM, Cloud Run, Cloud Functions, Pub/Sub, BigQuery, Secret Manager, KMS, firewall posture, and workload-to-data paths.                                                |
| Azure    | Active support  | Storage public/encryption/recovery/private-endpoint posture, Key Vault, SQL/PostgreSQL, App Service/Function Apps, AKS control-plane/auth/add-on posture, managed identity/custom RBAC posture, NSG-aware public ingress, public VM exposure, and workload-to-sensitive-resource paths. |

## When To Use tfSTRIDE

Use tfSTRIDE when you want to:

* review Terraform plan changes before infrastructure ships
* add architecture-risk context to pull requests
* identify trust-boundary crossings across AWS, GCP, or Azure infrastructure
* explain why a combination of resources creates risk
* produce human-readable Markdown reports for security review
* produce SARIF for architecture-risk findings in code-scanning workflows
* gate CI on new high-severity architecture-risk findings
* keep analysis deterministic and independent of LLM-generated findings

tfSTRIDE is especially useful for:

* platform teams using Terraform
* cloud security engineers reviewing infrastructure changes
* DevSecOps teams adding pre-apply review gates
* consultants doing Terraform or cloud architecture reviews
* teams that already run IaC scanners but still need design-review context

## When Not To Use tfSTRIDE

Do not use tfSTRIDE as your only IaC security tool if you need:

* broad cloud security baseline coverage across all resources
* large general-purpose policy catalogs
* compliance benchmarks
* Kubernetes manifest, Helm chart, CloudFormation, ARM/Bicep template, Dockerfile, or container image scanning
* vulnerability or secret scanning
* runtime cloud posture management
* drift detection from live cloud APIs
* ticketing, ownership, or enterprise workflow features
* exhaustive coverage for every AWS, GCP, or Azure resource type

Run Checkov, Trivy, Snyk IaC, or another policy scanner for broad coverage.
Run tfSTRIDE for the smaller set of findings where architecture context matters.

## How To Run It In The Same Pipeline

A practical CI setup can run both classes of tools:

```bash
terraform plan -out tfplan
terraform show -json tfplan > tfplan.json

# Broad IaC policy scan
checkov -f tfplan.json --framework terraform_plan

# Architecture-risk review
tfstride tfplan.json \
  --quiet \
  --fail-on high \
  --output tfstride-report.md \
  --sarif-output tfstride.sarif
```

Use baselines or suppressions for accepted findings so the gate focuses on new
risk.

## Scope And Limits

tfSTRIDE is intentionally narrow:

* AWS, GCP, and Azure Terraform provider support
* incomplete resource coverage within each provider
* Terraform plan JSON input only
* no runtime cloud API calls
* no drift detection
* no LLM-generated findings
* no claim to replace established IaC scanners

That scope is deliberate. The goal is to make a focused set of architecture-risk
findings easy to review, explain, and gate in CI.

## Best Used With

tfSTRIDE works best alongside tools like Checkov, Trivy, or Snyk IaC.

A good review pipeline uses broad scanners for baseline controls, then uses
tfSTRIDE for composed architecture-risk findings that require cross-resource
context.

## Short Version

Use IaC scanners to answer:

> Which resource-level security controls are missing?

Use tfSTRIDE to answer:

> What architecture risk does this Terraform plan introduce?