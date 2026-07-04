# tfSTRIDE Threat Model Report

- Analyzed file: `sample_aws_ecs_fargate_plan.json`
- Provider: `aws`
- Normalized resources: `21`
- Unsupported resources: `0`

## Summary

This run identified **6 trust boundaries** and **8 findings** across **21 normalized resources**.

- High severity findings: `0`
- Medium severity findings: `8`
- Low severity findings: `0`

## Analysis Coverage

- Terraform resources seen: `21`
- Provider resources considered: `21`
- Normalized resources: `21`
- Unsupported resources: `0`
- Registered rules: `150`
- Enabled rules: `150`
- Disabled rules: `0`
- Severity overrides: `0`
- Unresolved in-plan references: `0`
- Findings by rule:
  - `aws-secretsmanager-customer-managed-kms-key-missing`: `1`
  - `aws-secretsmanager-rotation-not-configured-or-too-long`: `1`
  - `aws-workload-secretsmanager-vpc-endpoint-missing`: `1`
  - `aws-iam-wildcard-permissions`: `2`
  - `aws-workload-role-sensitive-permissions`: `1`
  - `aws-private-data-transitive-exposure`: `2`

## Discovered Trust Boundaries

### `internet-to-service`

- Source: `internet`
- Target: `aws_lb.web`
- Description: Traffic can cross from the public internet to aws_lb.web.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

### `public-subnet-to-private-subnet`

- Source: `aws_subnet.public_a`
- Target: `aws_subnet.private_app`
- Description: Traffic can move from aws_subnet.public_a toward aws_subnet.private_app.
- Rationale: The VPC contains both publicly routable and private network segments that should be treated as separate trust zones.

### `public-subnet-to-private-subnet`

- Source: `aws_subnet.public_b`
- Target: `aws_subnet.private_app`
- Description: Traffic can move from aws_subnet.public_b toward aws_subnet.private_app.
- Rationale: The VPC contains both publicly routable and private network segments that should be treated as separate trust zones.

### `workload-to-data-store`

- Source: `aws_ecs_service.app`
- Target: `aws_db_instance.app`
- Description: aws_ecs_service.app can interact with aws_db_instance.app.
- Rationale: Application or function workloads cross into a higher-sensitivity data plane when database ingress security groups explicitly trust the workload security group.

### `workload-to-data-store`

- Source: `aws_ecs_service.app`
- Target: `aws_secretsmanager_secret.app`
- Description: aws_ecs_service.app can interact with aws_secretsmanager_secret.app.
- Rationale: Application or function workloads cross into a higher-sensitivity secret plane when their attached role allows Secrets Manager retrieval actions such as secretsmanager:GetSecretValue.

### `admin-to-workload-plane`

- Source: `aws_iam_role.task`
- Target: `aws_ecs_service.app`
- Description: aws_iam_role.task governs actions performed by aws_ecs_service.app.
- Rationale: IAM configuration acts as a control-plane boundary because the workload inherits whatever privileges the role carries.

## Findings

### High

No findings in this severity band.

### Medium

#### IAM policy grants wildcard privileges

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_iam_role.task`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +1, data_sensitivity +0, lateral_movement +1, blast_radius +2, final_score 4 => medium
- Rationale: aws_iam_role.task contains allow statements with wildcard actions or resources. That makes the resulting access difficult to reason about and expands blast radius.
- Recommended mitigation: Replace wildcard actions and resources with narrowly scoped permissions tied to the exact services, APIs, and ARNs required by the workload.
- Evidence:
  - iam resources: *
  - policy statements: Allow actions=[secretsmanager:GetSecretValue] resources=[*]

#### IAM policy grants wildcard privileges

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_iam_role.execution`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +1, data_sensitivity +0, lateral_movement +1, blast_radius +2, final_score 4 => medium
- Rationale: aws_iam_role.execution contains allow statements with wildcard actions or resources. That makes the resulting access difficult to reason about and expands blast radius.
- Recommended mitigation: Replace wildcard actions and resources with narrowly scoped permissions tied to the exact services, APIs, and ARNs required by the workload.
- Evidence:
  - iam resources: *
  - policy statements: Allow actions=[logs:CreateLogStream, logs:PutLogEvents] resources=[*]

#### Secrets Manager rotation is not configured or too infrequent

- STRIDE category: Information Disclosure
- Affected resources: `aws_secretsmanager_secret.app`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: aws_secretsmanager_secret.app does not show a deterministic Secrets Manager rotation resource in the Terraform plan. Static or manually rotated secrets can remain valid longer after disclosure, service compromise, or operator error.
- Recommended mitigation: Configure `aws_secretsmanager_secret_rotation` with a rotation Lambda and a rotation interval aligned to the organization secret lifecycle policy, such as 90 days or less for sensitive application secrets.
- Evidence:
  - target resource: address=aws_secretsmanager_secret.app; type=aws_secretsmanager_secret; identifier=ecs-app-secret; arn=arn:aws:secretsmanager:us-east-1:111122223333:secret:ecs-app-secret
  - rotation posture: rotation_state=not_configured; maximum_rotation_interval_days=90; aws_secretsmanager_secret_rotation resource was not resolved for this secret

#### Secrets Manager secret does not use a customer-managed KMS key

- STRIDE category: Information Disclosure
- Affected resources: `aws_secretsmanager_secret.app`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: aws_secretsmanager_secret.app does not show a deterministic customer-managed KMS key in the Terraform plan. Secrets Manager AWS-managed encryption may still apply; this finding concerns customer key ownership, rotation, audit separation, and compliance posture.
- Recommended mitigation: Configure `kms_key_id` with a customer-managed KMS key for secrets where key ownership, rotation, audit separation, or compliance controls are required.
- Evidence:
  - target resource: address=aws_secretsmanager_secret.app; type=aws_secretsmanager_secret; identifier=ecs-app-secret; arn=arn:aws:secretsmanager:us-east-1:111122223333:secret:ecs-app-secret
  - encryption ownership: customer_managed_kms_state=not_configured; kms_key_id is unset; AWS-managed encryption may still apply; this finding concerns customer key control

#### Sensitive data tier is transitively reachable from an internet-exposed path

- STRIDE category: Information Disclosure
- Affected resources: `aws_lb.web`, `aws_ecs_service.app`, `aws_db_instance.app`, `aws_security_group.ecs`
- Trust boundary: `workload-to-data-store:aws_ecs_service.app->aws_db_instance.app`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +2, blast_radius +1, final_score 5 => medium
- Rationale: aws_db_instance.app is not directly public, but internet traffic can first reach aws_lb.web, move through aws_lb.web can reach aws_ecs_service.app, and then cross into the private data tier through aws_ecs_service.app. That creates a quieter transitive exposure path than a directly public data store.
- Recommended mitigation: Keep internet-adjacent entry points from chaining into workloads that retain database or secret access, narrow edge-to-workload and workload-to-workload trust, and isolate sensitive data access behind more deliberate service boundaries.
- Evidence:
  - network path: internet reaches aws_lb.web; aws_lb.web reaches aws_ecs_service.app; aws_ecs_service.app reaches aws_db_instance.app
  - security group rules: aws_security_group.ecs ingress tcp 8080 from sg-ecs-alb
  - subnet posture: aws_lb.web sits in public subnet aws_subnet.public_a with an internet route; aws_lb.web sits in public subnet aws_subnet.public_b with an internet route; aws_ecs_service.app sits in private subnet aws_subnet.private_app
  - data tier posture: aws_db_instance.app is not directly public; database has no direct internet ingress path
  - boundary rationale: Application or function workloads cross into a higher-sensitivity data plane when database ingress security groups explicitly trust the workload security group.

#### Sensitive data tier is transitively reachable from an internet-exposed path

- STRIDE category: Information Disclosure
- Affected resources: `aws_lb.web`, `aws_ecs_service.app`, `aws_secretsmanager_secret.app`, `aws_security_group.ecs`
- Trust boundary: `workload-to-data-store:aws_ecs_service.app->aws_secretsmanager_secret.app`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +2, blast_radius +1, final_score 5 => medium
- Rationale: aws_secretsmanager_secret.app is not directly public, but internet traffic can first reach aws_lb.web, move through aws_lb.web can reach aws_ecs_service.app, and then cross into the private data tier through aws_ecs_service.app. That creates a quieter transitive exposure path than a directly public data store.
- Recommended mitigation: Keep internet-adjacent entry points from chaining into workloads that retain database or secret access, narrow edge-to-workload and workload-to-workload trust, and isolate sensitive data access behind more deliberate service boundaries.
- Evidence:
  - network path: internet reaches aws_lb.web; aws_lb.web reaches aws_ecs_service.app; aws_ecs_service.app reaches aws_secretsmanager_secret.app
  - security group rules: aws_security_group.ecs ingress tcp 8080 from sg-ecs-alb
  - subnet posture: aws_lb.web sits in public subnet aws_subnet.public_a with an internet route; aws_lb.web sits in public subnet aws_subnet.public_b with an internet route; aws_ecs_service.app sits in private subnet aws_subnet.private_app
  - data tier posture: aws_secretsmanager_secret.app is not directly public
  - boundary rationale: Application or function workloads cross into a higher-sensitivity secret plane when their attached role allows Secrets Manager retrieval actions such as secretsmanager:GetSecretValue.

#### Workload role carries sensitive permissions

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_ecs_service.app`, `aws_iam_role.task`
- Trust boundary: `admin-to-workload-plane:aws_iam_role.task->aws_ecs_service.app`
- Severity reasoning: internet_exposure +0, privilege_breadth +1, data_sensitivity +1, lateral_movement +1, blast_radius +2, final_score 5 => medium
- Rationale: aws_ecs_service.app inherits sensitive privileges from aws_iam_role.task, including secretsmanager:GetSecretValue. If the workload is compromised, those credentials can be reused for privilege escalation, data access, or role chaining.
- Recommended mitigation: Split high-privilege actions into separate roles, scope permissions to named resources, and remove role-passing or cross-role permissions from general application identities.
- Evidence:
  - iam actions: secretsmanager:GetSecretValue
  - policy statements: Allow actions=[secretsmanager:GetSecretValue] resources=[*]

#### Workload uses Secrets Manager without a VPC endpoint

- STRIDE category: Information Disclosure
- Affected resources: `aws_ecs_service.app`, `aws_iam_role.task`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +1, data_sensitivity +1, lateral_movement +1, blast_radius +1, final_score 4 => medium
- Rationale: aws_ecs_service.app runs in VPC `vpc-ecs-001` and inherits Secrets Manager secret retrieval from aws_iam_role.task, but the Terraform plan does not show a Secrets Manager interface VPC endpoint for that VPC. Calls to the sensitive service may therefore depend on public AWS service endpoints, NAT, or another egress path.
- Recommended mitigation: Add a Secrets Manager interface VPC endpoint with private DNS enabled for VPC workloads that retrieve secrets, and narrow endpoint policies where possible.
- Evidence:
  - target workload: address=aws_ecs_service.app; type=aws_ecs_service; vpc_id=vpc-ecs-001; subnet_ids=[subnet-ecs-private-app]; security_group_ids=[sg-ecs-service]
  - sensitive service dependency: service=secretsmanager; role=aws_iam_role.task; actions=[secretsmanager:GetSecretValue]; resources=[*]
  - vpc endpoint coverage: vpc_id=vpc-ecs-001; service=secretsmanager; expected_endpoint_type=interface; vpc_endpoint_coverage=missing
  - policy statements: Allow actions=[secretsmanager:GetSecretValue] resources=[*]

### Low

No findings in this severity band.

## Controls Observed

### RDS instance is private and storage encrypted

- Category: `data-protection`
- Affected resources: `aws_db_instance.app`
- Rationale: aws_db_instance.app is kept off direct internet paths and has storage encryption enabled, which reduces straightforward data exposure risk.
- Evidence:
  - database posture: publicly_accessible is false; storage_encrypted is true; no attached security group allows internet ingress; engine is postgres

## Limitations / Unsupported Resources

- AWS support is intentionally limited to a curated v1 resource set rather than the full Terraform AWS provider.
- Subnet public/private classification prefers explicit route table associations and NAT or internet routes when present, but it does not model main-route-table inheritance or every routing edge case.
- IAM analysis resolves inline role policies, customer-managed role-policy attachments, and EC2 instance profiles present in the plan, but it does not expand AWS-managed policy documents that are not materialized in Terraform state.
- Resource-policy analysis focuses on explicit policy documents and Lambda permission resources present in the plan; it does not model every service-specific condition key or every downstream runtime authorization path.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
