# Cloud Threat Model Report

- Analyzed file: `sample_aws_nightmare_plan.json`
- Provider: `aws`
- Normalized resources: `25`
- Unsupported resources: `0`

## Summary

This run identified **19 trust boundaries** and **14 findings** across **25 normalized resources**.

- High severity findings: `5`
- Medium severity findings: `9`
- Low severity findings: `0`

## Discovered Trust Boundaries

### `internet-to-service`

- Source: `internet`
- Target: `aws_lb.web`
- Description: Traffic can cross from the public internet to aws_lb.web.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

### `internet-to-service`

- Source: `internet`
- Target: `aws_instance.frontend`
- Description: Traffic can cross from the public internet to aws_instance.frontend.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

### `internet-to-service`

- Source: `internet`
- Target: `aws_instance.admin`
- Description: Traffic can cross from the public internet to aws_instance.admin.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

### `internet-to-service`

- Source: `internet`
- Target: `aws_s3_bucket.assets`
- Description: Traffic can cross from the public internet to aws_s3_bucket.assets.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

### `internet-to-service`

- Source: `internet`
- Target: `aws_s3_bucket.backups`
- Description: Traffic can cross from the public internet to aws_s3_bucket.backups.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

### `public-subnet-to-private-subnet`

- Source: `aws_subnet.public_web`
- Target: `aws_subnet.private_ops`
- Description: Traffic can move from aws_subnet.public_web toward aws_subnet.private_ops.
- Rationale: The VPC contains both publicly routable and private network segments that should be treated as separate trust zones.

### `public-subnet-to-private-subnet`

- Source: `aws_subnet.public_web`
- Target: `aws_subnet.private_data`
- Description: Traffic can move from aws_subnet.public_web toward aws_subnet.private_data.
- Rationale: The VPC contains both publicly routable and private network segments that should be treated as separate trust zones.

### `workload-to-data-store`

- Source: `aws_instance.frontend`
- Target: `aws_db_instance.customer`
- Description: aws_instance.frontend can interact with aws_db_instance.customer.
- Rationale: Application or function workloads cross into a higher-sensitivity data plane when database ingress security groups explicitly trust the workload security group.

### `workload-to-data-store`

- Source: `aws_instance.admin`
- Target: `aws_db_instance.customer`
- Description: aws_instance.admin can interact with aws_db_instance.customer.
- Rationale: Application or function workloads cross into a higher-sensitivity data plane when database ingress security groups explicitly trust the workload security group.

### `workload-to-data-store`

- Source: `aws_lambda_function.processor`
- Target: `aws_db_instance.customer`
- Description: aws_lambda_function.processor can interact with aws_db_instance.customer.
- Rationale: Application or function workloads cross into a higher-sensitivity data plane when database ingress security groups explicitly trust the workload security group.

### `workload-to-data-store`

- Source: `aws_lambda_function.processor`
- Target: `aws_s3_bucket.assets`
- Description: aws_lambda_function.processor can interact with aws_s3_bucket.assets.
- Rationale: Application or function workloads cross into a higher-sensitivity data plane when their attached role allows S3 actions such as *.

### `workload-to-data-store`

- Source: `aws_lambda_function.processor`
- Target: `aws_s3_bucket.backups`
- Description: aws_lambda_function.processor can interact with aws_s3_bucket.backups.
- Rationale: Application or function workloads cross into a higher-sensitivity data plane when their attached role allows S3 actions such as *.

### `admin-to-workload-plane`

- Source: `aws_iam_role.app`
- Target: `aws_lambda_function.processor`
- Description: aws_iam_role.app governs actions performed by aws_lambda_function.processor.
- Rationale: IAM configuration acts as a control-plane boundary because the workload inherits whatever privileges the role carries.

### `workload-to-data-store`

- Source: `aws_lambda_function.deployer`
- Target: `aws_db_instance.customer`
- Description: aws_lambda_function.deployer can interact with aws_db_instance.customer.
- Rationale: Application or function workloads cross into a higher-sensitivity data plane when database ingress security groups explicitly trust the workload security group.

### `workload-to-data-store`

- Source: `aws_lambda_function.deployer`
- Target: `aws_s3_bucket.assets`
- Description: aws_lambda_function.deployer can interact with aws_s3_bucket.assets.
- Rationale: Application or function workloads cross into a higher-sensitivity data plane when their attached role allows S3 actions such as s3:*.

### `workload-to-data-store`

- Source: `aws_lambda_function.deployer`
- Target: `aws_s3_bucket.backups`
- Description: aws_lambda_function.deployer can interact with aws_s3_bucket.backups.
- Rationale: Application or function workloads cross into a higher-sensitivity data plane when their attached role allows S3 actions such as s3:*.

### `admin-to-workload-plane`

- Source: `aws_iam_role.pipeline`
- Target: `aws_lambda_function.deployer`
- Description: aws_iam_role.pipeline governs actions performed by aws_lambda_function.deployer.
- Rationale: IAM configuration acts as a control-plane boundary because the workload inherits whatever privileges the role carries.

### `cross-account-or-role-access`

- Source: `*`
- Target: `aws_iam_role.app`
- Description: aws_iam_role.app trusts any principal.
- Rationale: An additional role or principal can cross into this role's trust boundary.

### `cross-account-or-role-access`

- Source: `arn:aws:iam::444455556666:root`
- Target: `aws_iam_role.pipeline`
- Description: aws_iam_role.pipeline trusts arn:aws:iam::444455556666:root.
- Rationale: A foreign AWS account can cross into this role's trust boundary.

## Findings

### High

#### Database is reachable from overly permissive sources

- STRIDE category: Information Disclosure
- Affected resources: `aws_db_instance.customer`, `aws_security_group.db`
- Trust boundary: `workload-to-data-store:aws_instance.admin->aws_db_instance.customer`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +1, blast_radius +1, final_score 6 => high
- Rationale: aws_db_instance.customer is a sensitive data store, but database is not marked directly internet reachable, but its security groups allow internet-origin ingress, and database trusts security groups attached to internet-exposed workloads. That weakens the expected separation between the workload tier and the data tier.
- Recommended mitigation: Keep databases off public paths, allow ingress only from narrowly scoped application security groups, and enforce authentication plus encryption independently of network policy.
- Evidence:
  - security group rules: aws_security_group.db ingress tcp 5432 from 0.0.0.0/0 (Postgres from internet); aws_security_group.db ingress tcp 5432 from sg-bad-admin-001, sg-bad-front-001 (Postgres from public tiers)
  - network path: database is not marked directly internet reachable, but its security groups allow internet-origin ingress; database trusts security groups attached to internet-exposed workloads; aws_security_group.db allows sg-bad-front-001, sg-bad-admin-001 attached to aws_instance.admin, aws_instance.frontend, aws_lb.web
  - subnet posture: aws_instance.admin sits in public subnet aws_subnet.public_web with an internet route; aws_instance.frontend sits in public subnet aws_subnet.public_web with an internet route; aws_lb.web sits in public subnet aws_subnet.public_web with an internet route

#### Private data tier directly trusts the public application tier

- STRIDE category: Tampering
- Affected resources: `aws_db_instance.customer`, `aws_instance.admin`, `aws_instance.frontend`, `aws_lb.web`, `aws_security_group.db`
- Trust boundary: `public-subnet-to-private-subnet:aws_subnet.public_web->aws_subnet.private_ops`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +2, blast_radius +1, final_score 7 => high
- Rationale: aws_db_instance.customer accepts traffic from security groups attached to internet-facing workloads. A compromise of the public tier can therefore move laterally into the private data tier.
- Recommended mitigation: Introduce tighter tier segmentation with dedicated security groups, narrow ingress to specific services and ports, and keep the data tier reachable only through controlled application paths.
- Evidence:
  - security group rules: aws_security_group.db ingress tcp 5432 from sg-bad-admin-001, sg-bad-front-001 (Postgres from public tiers)
  - network path: aws_security_group.db allows sg-bad-front-001, sg-bad-admin-001 attached to aws_instance.admin, aws_instance.frontend, aws_lb.web
  - subnet posture: aws_instance.admin sits in public subnet aws_subnet.public_web with an internet route; aws_instance.frontend sits in public subnet aws_subnet.public_web with an internet route; aws_lb.web sits in public subnet aws_subnet.public_web with an internet route

#### Role trust relationship expands blast radius

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_iam_role.app`
- Trust boundary: `cross-account-or-role-access:*->aws_iam_role.app`
- Severity reasoning: internet_exposure +0, privilege_breadth +2, data_sensitivity +0, lateral_movement +2, blast_radius +2, final_score 6 => high
- Rationale: aws_iam_role.app can be assumed by *. Broad or foreign-account trust relationships increase the chance that compromise in one identity domain spills into another.
- Recommended mitigation: Limit trust policies to the exact service principals or roles required, prefer role ARNs over account root where possible, and add conditions such as `ExternalId` or source ARN checks.
- Evidence:
  - trust principals: *
  - trust path: trust policy allows any AWS principal

#### Workload role carries sensitive permissions

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_lambda_function.processor`, `aws_iam_role.app`
- Trust boundary: `admin-to-workload-plane:aws_iam_role.app->aws_lambda_function.processor`
- Severity reasoning: internet_exposure +0, privilege_breadth +2, data_sensitivity +1, lateral_movement +1, blast_radius +2, final_score 6 => high
- Rationale: aws_lambda_function.processor inherits sensitive privileges from aws_iam_role.app, including *, kms:Decrypt, sts:AssumeRole. If the workload is compromised, those credentials can be reused for privilege escalation, data access, or role chaining.
- Recommended mitigation: Split high-privilege actions into separate roles, scope permissions to named resources, and remove role-passing or cross-role permissions from general application identities.
- Evidence:
  - iam actions: *; kms:Decrypt; sts:AssumeRole
  - policy statements: Allow actions=[*, kms:Decrypt, sts:AssumeRole] resources=[*]

#### Workload role carries sensitive permissions

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_lambda_function.deployer`, `aws_iam_role.pipeline`
- Trust boundary: `admin-to-workload-plane:aws_iam_role.pipeline->aws_lambda_function.deployer`
- Severity reasoning: internet_exposure +0, privilege_breadth +2, data_sensitivity +1, lateral_movement +1, blast_radius +2, final_score 6 => high
- Rationale: aws_lambda_function.deployer inherits sensitive privileges from aws_iam_role.pipeline, including iam:PassRole, s3:*. If the workload is compromised, those credentials can be reused for privilege escalation, data access, or role chaining.
- Recommended mitigation: Split high-privilege actions into separate roles, scope permissions to named resources, and remove role-passing or cross-role permissions from general application identities.
- Evidence:
  - iam actions: iam:PassRole; s3:*
  - policy statements: Allow actions=[iam:*, iam:PassRole, s3:*] resources=[*]

### Medium

#### Database storage encryption is disabled

- STRIDE category: Information Disclosure
- Affected resources: `aws_db_instance.customer`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: aws_db_instance.customer stores sensitive data, but `storage_encrypted` is disabled. That weakens data-at-rest protections for underlying storage, snapshots, and backup handling.
- Recommended mitigation: Enable RDS storage encryption with a managed KMS key, enforce encryption by default in database modules, and migrate plaintext instances to encrypted replacements where needed.
- Evidence:
  - encryption posture: storage_encrypted is false; engine is postgres

#### IAM policy grants wildcard privileges

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_iam_role.app`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +2, data_sensitivity +0, lateral_movement +1, blast_radius +2, final_score 5 => medium
- Rationale: aws_iam_role.app contains allow statements with wildcard actions or resources. That makes the resulting access difficult to reason about and expands blast radius.
- Recommended mitigation: Replace wildcard actions and resources with narrowly scoped permissions tied to the exact services, APIs, and ARNs required by the workload.
- Evidence:
  - iam actions: *
  - iam resources: *
  - policy statements: Allow actions=[*, kms:Decrypt, sts:AssumeRole] resources=[*]

#### IAM policy grants wildcard privileges

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_iam_role.pipeline`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +2, data_sensitivity +0, lateral_movement +1, blast_radius +2, final_score 5 => medium
- Rationale: aws_iam_role.pipeline contains allow statements with wildcard actions or resources. That makes the resulting access difficult to reason about and expands blast radius.
- Recommended mitigation: Replace wildcard actions and resources with narrowly scoped permissions tied to the exact services, APIs, and ARNs required by the workload.
- Evidence:
  - iam actions: iam:*; s3:*
  - iam resources: *
  - policy statements: Allow actions=[iam:*, iam:PassRole, s3:*] resources=[*]

#### IAM policy grants wildcard privileges

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_iam_policy.admin_like`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +2, data_sensitivity +0, lateral_movement +1, blast_radius +2, final_score 5 => medium
- Rationale: aws_iam_policy.admin_like contains allow statements with wildcard actions or resources. That makes the resulting access difficult to reason about and expands blast radius.
- Recommended mitigation: Replace wildcard actions and resources with narrowly scoped permissions tied to the exact services, APIs, and ARNs required by the workload.
- Evidence:
  - iam actions: ec2:*; iam:*; s3:*
  - iam resources: *
  - policy statements: Allow actions=[ec2:*, s3:*, iam:*] resources=[*]

#### Internet-exposed compute service permits overly broad ingress

- STRIDE category: Spoofing
- Affected resources: `aws_instance.frontend`, `aws_security_group.frontend`
- Trust boundary: `internet-to-service:internet->aws_instance.frontend`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +0, lateral_movement +1, blast_radius +1, final_score 4 => medium
- Rationale: aws_instance.frontend is reachable from the internet and at least one attached security group allows administrative access or all ports from 0.0.0.0/0. That broad ingress raises the chance of unauthenticated probing and credential attacks.
- Recommended mitigation: Restrict ingress to expected client ports, remove direct administrative exposure, and place management access behind a controlled bastion, VPN, or SSM Session Manager.
- Evidence:
  - security group rules: aws_security_group.frontend ingress tcp 0-65535 from 0.0.0.0/0 (Everything from the internet)
  - public exposure reasons: instance requests an associated public IP address; instance is in a public subnet and attached security groups allow internet ingress
  - subnet posture: aws_instance.frontend sits in public subnet aws_subnet.public_web with an internet route

#### Internet-exposed compute service permits overly broad ingress

- STRIDE category: Spoofing
- Affected resources: `aws_instance.admin`, `aws_security_group.admin`
- Trust boundary: `internet-to-service:internet->aws_instance.admin`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +0, lateral_movement +1, blast_radius +1, final_score 4 => medium
- Rationale: aws_instance.admin is reachable from the internet and at least one attached security group allows administrative access or all ports from 0.0.0.0/0. That broad ingress raises the chance of unauthenticated probing and credential attacks.
- Recommended mitigation: Restrict ingress to expected client ports, remove direct administrative exposure, and place management access behind a controlled bastion, VPN, or SSM Session Manager.
- Evidence:
  - security group rules: aws_security_group.admin ingress tcp 3389 from 0.0.0.0/0 (RDP from internet)
  - public exposure reasons: instance requests an associated public IP address; instance is in a public subnet and attached security groups allow internet ingress
  - subnet posture: aws_instance.admin sits in public subnet aws_subnet.public_web with an internet route

#### Object storage is publicly accessible

- STRIDE category: Information Disclosure
- Affected resources: `aws_s3_bucket.assets`
- Trust boundary: `internet-to-service:internet->aws_s3_bucket.assets`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 5 => medium
- Rationale: aws_s3_bucket.assets appears to be public through ACLs or bucket policy. Public object access is a common source of unintended data disclosure.
- Recommended mitigation: Use private bucket ACLs, block public access, and grant object access through scoped IAM roles or signed requests instead of anonymous principals.
- Evidence:
  - public exposure reasons: bucket ACL `public-read` grants public access; bucket policy allows anonymous access

#### Object storage is publicly accessible

- STRIDE category: Information Disclosure
- Affected resources: `aws_s3_bucket.backups`
- Trust boundary: `internet-to-service:internet->aws_s3_bucket.backups`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 5 => medium
- Rationale: aws_s3_bucket.backups appears to be public through ACLs or bucket policy. Public object access is a common source of unintended data disclosure.
- Recommended mitigation: Use private bucket ACLs, block public access, and grant object access through scoped IAM roles or signed requests instead of anonymous principals.
- Evidence:
  - public exposure reasons: bucket ACL `public-read-write` grants public access

#### Role trust relationship expands blast radius

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_iam_role.pipeline`
- Trust boundary: `cross-account-or-role-access:arn:aws:iam::444455556666:root->aws_iam_role.pipeline`
- Severity reasoning: internet_exposure +0, privilege_breadth +1, data_sensitivity +0, lateral_movement +2, blast_radius +2, final_score 5 => medium
- Rationale: aws_iam_role.pipeline can be assumed by arn:aws:iam::444455556666:root. Broad or foreign-account trust relationships increase the chance that compromise in one identity domain spills into another.
- Recommended mitigation: Limit trust policies to the exact service principals or roles required, prefer role ARNs over account root where possible, and add conditions such as `ExternalId` or source ARN checks.
- Evidence:
  - trust principals: arn:aws:iam::444455556666:root
  - trust path: trust principal belongs to foreign account 444455556666

### Low

No findings in this severity band.

## Limitations / Unsupported Resources

- AWS support is intentionally limited to a curated v1 resource set rather than the full Terraform AWS provider.
- Subnet public/private classification prefers explicit route table associations and NAT or internet routes when present, but it does not model main-route-table inheritance or every routing edge case.
- IAM analysis focuses on inline role policies, standalone policy documents, role-policy attachments, and trust policies; it does not yet build a full attachment graph.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or resource-based policies beyond scoped S3 public-access checks.
