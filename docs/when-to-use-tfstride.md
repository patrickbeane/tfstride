# How tfSTRIDE Complements IaC Scanners

tfSTRIDE is not a replacement for tools like Checkov, Trivy, or Snyk IaC.

Those tools are better fits for broad IaC policy coverage, compliance checks,
and resource-level best-practice scanning. tfSTRIDE is narrower: it analyzes
Terraform plan JSON for architecture-risk patterns, trust-boundary crossings,
and STRIDE-oriented findings that are useful during infrastructure review.

tfSTRIDE is best used as an architecture-risk layer beside your existing IaC 
scanner, not as a replacement for one.

Use both when the workflows overlap:

```text
IaC scanner -> broad security baseline
tfSTRIDE    -> architecture-risk and trust-boundary review
```

## Different Jobs

| Question | Better fit |
| --- | --- |
| Is this bucket missing versioning, logging, lifecycle, or public-access block settings? | Checkov, Trivy, Snyk IaC |
| Is this ALB missing access logs, WAF, or header hardening? | Checkov, Trivy, Snyk IaC |
| Does this Terraform change create a path from the internet to a private data tier? | tfSTRIDE |
| Does a workload inherit privileges that expand blast radius if compromised? | tfSTRIDE |
| Is cross-account trust narrowed by conditions such as `ExternalId`, `SourceArn`, or `SourceAccount`? | tfSTRIDE |
| Do I need code-scanning output for broad policy catalogs? | Checkov, Trivy, Snyk IaC |
| Do I need SARIF output for tfSTRIDE architecture-risk findings? | tfSTRIDE |

## What tfSTRIDE Adds

tfSTRIDE focuses on findings that need context across multiple resources.

### Transitive Exposure

An IaC scanner may report a public load balancer, subnet posture, security group
rules, and database settings as separate findings.

tfSTRIDE tries to answer the architecture question:

> Can internet traffic reach an application tier that can then reach sensitive
> data?

Example finding:

```text
Sensitive data tier is transitively reachable from an internet-exposed path

internet -> aws_lb.web -> aws_instance.app -> aws_db_instance.app
```

The database may not be directly public, but the path still matters during a
security review.

### Tier Segmentation

Generic scanners are good at detecting public ingress and missing hardening
controls. tfSTRIDE adds the tiering context:

```text
Private data tier directly trusts the public application tier
```

That finding ties together subnet posture, security group trust, public-facing
workloads, and database reachability. The goal is to make lateral movement risk
visible before `terraform apply`.

### Workload Blast Radius

Broad IAM findings are common in IaC scanners. tfSTRIDE tries to connect those
permissions to the workload that receives them.

Example:

```text
Workload role carries sensitive permissions

aws_lambda_function.processor inherits:
- iam:PassRole
- kms:Decrypt
- s3:*
- sts:AssumeRole
```

The review question is not only "is this policy broad?" It is "what can this
workload do if it is compromised?"

### Cross-Account Trust Narrowing

tfSTRIDE distinguishes broad or cross-account trust from trust that is narrowed
by supported assume-role conditions.

Example:

```text
Finding:
Cross-account or broad role trust lacks narrowing conditions

Control observed:
Cross-account or broad role trust is narrowed by assume-role conditions
```

That distinction is useful when reviewing deployment roles, CI/CD roles, and
federated trust paths.

## When To Use tfSTRIDE

Use tfSTRIDE when you want to:

- review Terraform plan changes before infrastructure ships
- add architecture-risk context to pull requests
- identify trust-boundary crossings in AWS infrastructure
- explain why a combination of resources creates risk
- produce human-readable Markdown reports for security review
- produce SARIF for tfSTRIDE findings in code-scanning workflows
- gate CI on new high-severity architecture-risk findings
- keep analysis deterministic and independent of LLM-generated findings

tfSTRIDE is especially useful for:

- platform teams using Terraform
- cloud security engineers reviewing AWS changes
- DevSecOps teams adding pre-apply review gates
- consultants doing Terraform/cloud architecture reviews
- teams that already run IaC scanners but still need design-review context

## When Not To Use tfSTRIDE

Do not use tfSTRIDE as your only IaC security tool if you need:

- broad AWS security baseline coverage
- multi-cloud IaC scanning
- Kubernetes, Helm, CloudFormation, ARM, or Dockerfile scanning
- large policy catalogs
- compliance benchmarks
- vulnerability or secret scanning
- runtime cloud posture management
- ticketing, ownership, or enterprise workflow features

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

tfSTRIDE is intentionally narrow today:

- AWS-focused
- Terraform plan JSON input
- incomplete resource coverage
- no runtime cloud API calls
- no drift detection
- no LLM-generated findings
- no claim to replace established IaC scanners

That scope is deliberate. The goal is to make a focused set of architecture-risk
findings easy to review, explain, and gate in CI.

## Best Used With

tfSTRIDE works best alongside tools like Checkov, Trivy, or Snyk IaC.

A good review pipeline uses broad scanners for baseline controls, then uses tfSTRIDE for composed architecture-risk findings that require cross-resource context.

## Short Version

Use IaC scanners to answer:

> Which resource-level security controls are missing?

Use tfSTRIDE to answer:

> What architecture risk does this Terraform plan introduce?