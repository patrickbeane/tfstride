# Cloud Threat Model Report

- Analyzed file: `sample_aws_plan.json`
- Provider: `aws`
- Normalized resources: `14`
- Unsupported resources: `1`

## Summary

This run identified **10 trust boundaries** and **8 findings** across **14 normalized resources**.

- High severity findings: `3`
- Medium severity findings: `5`
- Low severity findings: `0`

## Discovered Trust Boundaries

### `internet-to-service`

- Source: `internet`
- Target: `aws_lb.web`
- Description: Traffic can cross from the public internet to aws_lb.web.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

### `internet-to-service`

- Source: `internet`
- Target: `aws_instance.app`
- Description: Traffic can cross from the public internet to aws_instance.app.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

### `internet-to-service`

- Source: `internet`
- Target: `aws_db_instance.app`
- Description: Traffic can cross from the public internet to aws_db_instance.app.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

### `internet-to-service`

- Source: `internet`
- Target: `aws_s3_bucket.assets`
- Description: Traffic can cross from the public internet to aws_s3_bucket.assets.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

### `public-subnet-to-private-subnet`

- Source: `aws_subnet.public_app`
- Target: `aws_subnet.private_data`
- Description: Traffic can move from aws_subnet.public_app toward aws_subnet.private_data.
- Rationale: The VPC contains both publicly routable and private network segments that should be treated as separate trust zones.

### `workload-to-data-store`

- Source: `aws_instance.app`
- Target: `aws_db_instance.app`
- Description: aws_instance.app can interact with aws_db_instance.app.
- Rationale: Application or function workloads cross into a higher-sensitivity data plane when they reach databases or object storage.

### `workload-to-data-store`

- Source: `aws_lambda_function.processor`
- Target: `aws_db_instance.app`
- Description: aws_lambda_function.processor can interact with aws_db_instance.app.
- Rationale: Application or function workloads cross into a higher-sensitivity data plane when they reach databases or object storage.

### `workload-to-data-store`

- Source: `aws_lambda_function.processor`
- Target: `aws_s3_bucket.assets`
- Description: aws_lambda_function.processor can interact with aws_s3_bucket.assets.
- Rationale: Application or function workloads cross into a higher-sensitivity data plane when they reach databases or object storage.

### `admin-to-workload-plane`

- Source: `aws_iam_role.workload`
- Target: `aws_lambda_function.processor`
- Description: aws_iam_role.workload governs actions performed by aws_lambda_function.processor.
- Rationale: IAM configuration acts as a control-plane boundary because the workload inherits whatever privileges the role carries.

### `cross-account-or-role-access`

- Source: `arn:aws:iam::999988887777:root`
- Target: `aws_iam_role.workload`
- Description: aws_iam_role.workload trusts arn:aws:iam::999988887777:root.
- Rationale: A foreign AWS account can cross into this role's trust boundary.

## Findings

### High

#### Database is reachable from overly permissive sources

- STRIDE category: Information Disclosure
- Affected resources: `aws_db_instance.app`, `aws_security_group.db`
- Trust boundary: `internet-to-service:internet->aws_db_instance.app`
- Rationale: aws_db_instance.app is a sensitive data store, but its network controls allow either direct internet ingress or access from internet-facing application security groups. That weakens the expected separation between the workload tier and the data tier.
- Recommended mitigation: Keep databases off public paths, allow ingress only from narrowly scoped application security groups, and enforce authentication plus encryption independently of network policy.

#### Private data tier directly trusts the public application tier

- STRIDE category: Tampering
- Affected resources: `aws_db_instance.app`, `aws_instance.app`, `aws_security_group.db`
- Trust boundary: `public-subnet-to-private-subnet:aws_subnet.public_app->aws_subnet.private_data`
- Rationale: aws_db_instance.app accepts traffic from security groups attached to internet-facing workloads. A compromise of the public tier can therefore move laterally into the private data tier.
- Recommended mitigation: Introduce tighter tier segmentation with dedicated security groups, narrow ingress to specific services and ports, and keep the data tier reachable only through controlled application paths.

#### Workload role carries sensitive permissions

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_lambda_function.processor`, `aws_iam_role.workload`
- Trust boundary: `admin-to-workload-plane:aws_iam_role.workload->aws_lambda_function.processor`
- Rationale: aws_lambda_function.processor inherits sensitive privileges from aws_iam_role.workload, including iam:PassRole, kms:Decrypt, s3:*, sts:AssumeRole. If the workload is compromised, those credentials can be reused for privilege escalation, data access, or role chaining.
- Recommended mitigation: Split high-privilege actions into separate roles, scope permissions to named resources, and remove role-passing or cross-role permissions from general application identities.

### Medium

#### IAM policy grants wildcard privileges

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_iam_role.workload`
- Trust boundary: `not-applicable`
- Rationale: aws_iam_role.workload contains allow statements with wildcard actions or resources. That makes the resulting access difficult to reason about and expands blast radius.
- Recommended mitigation: Replace wildcard actions and resources with narrowly scoped permissions tied to the exact services, APIs, and ARNs required by the workload.

#### IAM policy grants wildcard privileges

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_iam_policy.admin_like`
- Trust boundary: `not-applicable`
- Rationale: aws_iam_policy.admin_like contains allow statements with wildcard actions or resources. That makes the resulting access difficult to reason about and expands blast radius.
- Recommended mitigation: Replace wildcard actions and resources with narrowly scoped permissions tied to the exact services, APIs, and ARNs required by the workload.

#### Internet-exposed compute service permits overly broad ingress

- STRIDE category: Spoofing
- Affected resources: `aws_instance.app`, `aws_security_group.app`
- Trust boundary: `internet-to-service:internet->aws_instance.app`
- Rationale: aws_instance.app is reachable from the internet and at least one attached security group allows administrative access or all ports from 0.0.0.0/0. That broad ingress raises the chance of unauthenticated probing and credential attacks.
- Recommended mitigation: Restrict ingress to expected client ports, remove direct administrative exposure, and place management access behind a controlled bastion, VPN, or SSM Session Manager.

#### Object storage is publicly accessible

- STRIDE category: Information Disclosure
- Affected resources: `aws_s3_bucket.assets`
- Trust boundary: `internet-to-service:internet->aws_s3_bucket.assets`
- Rationale: aws_s3_bucket.assets appears to be public through ACLs or bucket policy. Public object access is a common source of unintended data disclosure.
- Recommended mitigation: Use private bucket ACLs, block public access, and grant object access through scoped IAM roles or signed requests instead of anonymous principals.

#### Role trust relationship expands blast radius

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_iam_role.workload`
- Trust boundary: `cross-account-or-role-access:arn:aws:iam::999988887777:root->aws_iam_role.workload`
- Rationale: aws_iam_role.workload can be assumed by arn:aws:iam::999988887777:root. Broad or foreign-account trust relationships increase the chance that compromise in one identity domain spills into another.
- Recommended mitigation: Limit trust policies to the exact service principals or roles required, prefer role ARNs over account root where possible, and add conditions such as `ExternalId` or source ARN checks.

### Low

No findings in this severity band.

## Limitations / Unsupported Resources

- AWS support is intentionally limited to a curated v1 resource set rather than the full Terraform AWS provider.
- Subnet public/private classification uses Terraform plan attributes plus route-table heuristics and does not model every association resource.
- IAM analysis focuses on inline role policies, standalone policy documents, and trust policies; it does not yet build a full attachment graph.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or resource-based policies beyond basic S3 checks.
- Unsupported resource skipped: `aws_cloudwatch_log_group.processor`
