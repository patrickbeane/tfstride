# tfSTRIDE Threat Model Report

- Analyzed file: `sample_aws_ecs_topology_wildcard_plan.json`
- Provider: `aws`
- Normalized resources: `27`
- Unsupported resources: `0`

## Summary

This run identified **6 trust boundaries** and **21 findings** across **27 normalized resources**.

- High severity findings: `3`
- Medium severity findings: `15`
- Low severity findings: `3`

## Analysis Coverage

- Terraform resources seen: `27`
- Provider resources considered: `27`
- Normalized resources: `27`
- Unsupported resources: `0`
- Resources with plan-time unknown values: `0`
- Registered provider rules (AWS): `104`
- Enabled provider rules (AWS): `104`
- Disabled rules: `0`
- Severity overrides: `0`
- Configuration-reference resolution: `0 symbolic`, `0 ambiguous`, `0 unresolved`, `0 unsupported`
- Recorded unresolved modeled references: `0`
- Findings by rule:
  - `aws-public-alb-waf-missing`: `1`
  - `aws-rds-cloudwatch-log-exports-missing`: `1`
  - `aws-dynamodb-customer-managed-kms-key-missing`: `2`
  - `aws-dynamodb-deletion-protection-disabled-or-unknown`: `2`
  - `aws-public-ecs-dynamodb-table-topology-disruption`: `1`
  - `aws-public-ecs-messaging-topology-disruption`: `1`
  - `aws-sns-customer-managed-encryption-missing`: `1`
  - `aws-sqs-customer-managed-encryption-missing`: `1`
  - `aws-sqs-dead-letter-queue-not-configured`: `1`
  - `aws-secretsmanager-customer-managed-kms-key-missing`: `1`
  - `aws-secretsmanager-rotation-not-configured-or-too-long`: `1`
  - `aws-workload-secretsmanager-vpc-endpoint-missing`: `1`
  - `aws-vpc-flow-logs-not-configured`: `1`
  - `aws-iam-wildcard-permissions`: `2`
  - `aws-iam-privileged-role-assignment`: `1`
  - `aws-workload-role-sensitive-permissions`: `1`
  - `aws-private-data-transitive-exposure`: `2`

Sensitive resource labels are assumptions based on resource class. tfSTRIDE does not assess stored data contents from the plan.

## Discovered Trust Boundaries

### `internet-to-service`

- Source: `internet`
- Target: `aws_lb.web`
- Description: Traffic can cross from the public internet to aws_lb.web.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

### `public-subnet-to-private-subnet`

- Source: `aws_subnet.public_a`
- Target: `aws_subnet.private_app`
- Description: aws_subnet.public_a and aws_subnet.private_app occupy separate trust zones in the same network.
- Rationale: VPC membership resolves to `aws_vpc.main`. The network contains a publicly routable segment and a private trust zone. Common network membership does not establish packet reachability; routes and traffic controls require separate evaluation.

### `public-subnet-to-private-subnet`

- Source: `aws_subnet.public_b`
- Target: `aws_subnet.private_app`
- Description: aws_subnet.public_b and aws_subnet.private_app occupy separate trust zones in the same network.
- Rationale: VPC membership resolves to `aws_vpc.main`. The network contains a publicly routable segment and a private trust zone. Common network membership does not establish packet reachability; routes and traffic controls require separate evaluation.

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
- Description: aws_ecs_service.app uses aws_iam_role.task as its runtime identity.
- Rationale: The workload inherits permissions from the attached identity. This attachment does not establish authority to modify or operate the workload.

## Findings

### High

#### IAM role has privileged assignment posture

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_iam_role.task`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +2, data_sensitivity +2, lateral_movement +0, blast_radius +3, final_score 7 => high
- Rationale: aws_iam_role.task has deterministic privileged IAM assignment posture: secrets-admin. If this role is attached to a workload or assumable by a control-plane principal, those privileges increase blast radius.
- Recommended mitigation: Review high-impact IAM role permissions, split administrative and runtime duties, scope resources to named ARNs, and avoid attaching broad IAM, role-passing, secrets, KMS, data, network, or audit administration permissions to general workload roles.
- Evidence:
  - iam role: address=aws_iam_role.task; type=aws_iam_role; arn=arn:aws:iam::111122223333:role/app-task-role; identifier=app-task-role
  - privileged access: grant_1=categories=[secrets-admin]; scope=account; confidence=high
  - privilege categories: secrets-admin
  - grant scopes: scope_kind=account; scope_value=*
  - grant confidence: high
  - inline policy sources: inline_policy_name=task-data-access

#### Internet-facing ECS service can delete DynamoDB table topology

- STRIDE category: Denial of Service
- Affected resources: `aws_lb.web`, `aws_lb_listener.https`, `aws_lb_target_group.app`, `aws_ecs_service.app`, `aws_ecs_task_definition.app`, `aws_iam_role.task`, `aws_dynamodb_table.archive`, `aws_dynamodb_table.orders`
- Trust boundary: `internet-to-service:internet->aws_lb.web`
- Severity reasoning: internet_exposure +2, privilege_breadth +3, data_sensitivity +2, lateral_movement +1, blast_radius +2, final_score 10 => high
- Rationale: aws_ecs_service.app is reachable through an internet-facing load balancer and its ECS task role has deterministic DynamoDB table-topology deletion authority (dynamodb:DeleteTable) across 2 exact modeled DynamoDB tables. A compromise of the public workload could request deletion of those table topologies, subject to provider deletion prerequisites. Some of this authority is granted through wildcard resource patterns rather than exact ARNs, so it may also extend to tables outside this plan. Point-in-time recovery posture is preserved as provider-native evidence; it does not establish table emptiness, successful deletion, item or replica impact, restoration, or out-of-plan table topology.
- Recommended mitigation: Reduce public ingress to the ECS service and restrict its task role to only the exact dynamodb:DeleteTable action and modeled table scopes required at runtime. Keep table-topology deletion with a separate operational identity, enable deletion protection and point-in-time recovery, and do not treat recovery configuration as proof of successful deletion or restoration.
- Evidence:
  - network path: internet reaches aws_lb.web through aws_lb_listener.https (HTTPS TCP 443); aws_lb_listener.https forwards through aws_lb_target_group.app to aws_ecs_service.app container=app (HTTP TCP 8080)
  - public ingress: listener=aws_lb_listener.https; action_source=aws_lb_listener.https; target_group=aws_lb_target_group.app; service=aws_ecs_service.app; container=app:8080; target_weight=1; conditions=[]; request_witness={"host_header":"a.example","http_request_method":"DELETE","path_pattern":"/"}; authentication_actions=[]; evaluation_scope=modeled_listener_container_and_security_group_permissions
  - network permissions: listener=aws_lb_listener.https; target_group=aws_lb_target_group.app; check=container_binding; state=allowed; evidence={"container_name":"app","container_port":8080,"network_mode":"awsvpc","protocol":"tcp","task_definition_address":"aws_ecs_task_definition.app"}; listener=aws_lb_listener.https; target_group=aws_lb_target_group.app; check=listener_ingress; state=allowed; evidence={"cidr":"0.0.0.0/0","internet_source_witness":"8.8.8.8","port":443,"protocol":"tcp","rule_direction":"ingress","rule_path":["ingress",0],"rule_source_address":"aws_security_group.alb","security_group_address":"aws_security_group.alb","selector":"cidr"}; listener=aws_lb_listener.https; target_group=aws_lb_target_group.app; check=load_balancer_egress; state=allowed; evidence={"cidr":"0.0.0.0/0","port":8080,"protocol":"tcp","rule_direction":"egress","rule_path":["egress",0],"rule_source_address":"aws_security_group.alb","security_group_address":"aws_security_group.alb","selector":"cidr"}; listener=aws_lb_listener.https; target_group=aws_lb_target_group.app; check=service_ingress; state=allowed; evidence={"peer_security_group_addresses":["aws_security_group.alb"],"port":8080,"protocol":"tcp","rule_direction":"ingress","rule_path":["ingress",0],"rule_source_address":"aws_security_group.ecs","security_group_address":"aws_security_group.ecs","selector":"security_group"}
  - task definitions: address=aws_ecs_task_definition.app
  - task roles: address=aws_iam_role.task; reference=arn:aws:iam::111122223333:role/app-task-role; arn=arn:aws:iam::111122223333:role/app-task-role; role_kind=ecs_task_role; credential_context=workload_runtime; authorization_state=allowed
  - dynamodb table topology destruction paths: table_address=aws_dynamodb_table.archive; table_name=archive; table_reference=arn:aws:dynamodb:us-east-1:111122223333:table/archive; table_arn=arn:aws:dynamodb:us-east-1:111122223333:table/archive; operation=dynamodb:DeleteTable; operation_class=table_deletion; target_granularity=table_topology; target_scope=exact_dynamodb_table; grant_resource_scopes=table_pattern; grant_resources=*; task_definition=aws_ecs_task_definition.app; task_role=aws_iam_role.task; grant_basis=same_account_identity_policy; account_relationship=same_account; authorization_sources=aws_iam_role.task; matched_actions=dynamodb:DeleteTable; authorization_state=allowed; operation_evaluation=deterministic_allowed; table_address=aws_dynamodb_table.orders; table_name=orders; table_reference=arn:aws:dynamodb:us-east-1:111122223333:table/orders; table_arn=arn:aws:dynamodb:us-east-1:111122223333:table/orders; operation=dynamodb:DeleteTable; operation_class=table_deletion; target_granularity=table_topology; target_scope=exact_dynamodb_table; grant_resource_scopes=table_pattern; grant_resources=*; task_definition=aws_ecs_task_definition.app; task_role=aws_iam_role.task; grant_basis=same_account_identity_policy; account_relationship=same_account; authorization_sources=aws_iam_role.task; matched_actions=dynamodb:DeleteTable; authorization_state=allowed; operation_evaluation=deterministic_allowed
  - table deletion constraint evidence: table_address=aws_dynamodb_table.archive; deletion_protection_state=not_configured; deletion_protection_enabled=false; provider_default_applied=true; deletion_compatibility_state=compatible; uncertainties=none; table_address=aws_dynamodb_table.orders; deletion_protection_state=not_configured; deletion_protection_enabled=false; provider_default_applied=true; deletion_compatibility_state=compatible; uncertainties=none
  - table deletion recovery evidence: table_address=aws_dynamodb_table.archive; pitr_state=enabled; pitr_enabled=true; pitr_recovery_period_days=14; table_recovery_state=pitr_restore_to_new_table_configured; restore_target_kind=new_table; successful_deletion_observed=false; restoration_observed=false; runtime_table_state_evaluated=false; descendant_impact_evaluated=false; out_of_plan_table_topology_evaluated=false; uncertainties=none; table_address=aws_dynamodb_table.orders; pitr_state=enabled; pitr_enabled=true; pitr_recovery_period_days=14; table_recovery_state=pitr_restore_to_new_table_configured; restore_target_kind=new_table; successful_deletion_observed=false; restoration_observed=false; runtime_table_state_evaluated=false; descendant_impact_evaluated=false; out_of_plan_table_topology_evaluated=false; uncertainties=none
  - assessment scope: establishes=deterministic dynamodb:DeleteTable authority for an ECS task role over exact modeled DynamoDB table topology, granted by exact resources or by resource patterns covering each table, with Denial of Service effect; does_not_establish=table emptiness, successful deletion, item or replica impact, restoration, or authority over out-of-plan table topology

#### Internet-facing ECS service can delete messaging topology

- STRIDE category: Denial of Service
- Affected resources: `aws_lb.web`, `aws_lb_listener.https`, `aws_lb_target_group.app`, `aws_ecs_service.app`, `aws_ecs_task_definition.app`, `aws_iam_role.task`, `aws_sns_topic.events`, `aws_sqs_queue.orders`
- Trust boundary: `internet-to-service:internet->aws_lb.web`
- Severity reasoning: internet_exposure +2, privilege_breadth +2, data_sensitivity +1, lateral_movement +1, blast_radius +2, final_score 8 => high
- Rationale: aws_ecs_service.app is reachable through an internet-facing load balancer and its ECS task role has deterministic messaging topology-deletion authority (sqs:DeleteQueue and sns:DeleteTopic) across 2 exact modeled messaging target(s). A compromise of the public workload could delete exact modeled SQS queues or SNS topics, disrupting messaging topology and availability. Some of this authority is granted through wildcard resource patterns rather than exact ARNs, so it may also extend to messaging targets outside this plan. This is plan-local authorization evidence; it does not establish successful deletion, descendant-resource impact, recovery, or out-of-plan topology.
- Recommended mitigation: Reduce public ingress to the ECS service and remove `sqs:DeleteQueue` and `sns:DeleteTopic` from internet-facing task roles. Scope messaging permissions to exact runtime operations and use separate operational identities for queue and topic topology changes.
- Evidence:
  - network path: internet reaches aws_lb.web through aws_lb_listener.https (HTTPS TCP 443); aws_lb_listener.https forwards through aws_lb_target_group.app to aws_ecs_service.app container=app (HTTP TCP 8080)
  - public ingress: listener=aws_lb_listener.https; action_source=aws_lb_listener.https; target_group=aws_lb_target_group.app; service=aws_ecs_service.app; container=app:8080; target_weight=1; conditions=[]; request_witness={"host_header":"a.example","http_request_method":"DELETE","path_pattern":"/"}; authentication_actions=[]; evaluation_scope=modeled_listener_container_and_security_group_permissions
  - network permissions: listener=aws_lb_listener.https; target_group=aws_lb_target_group.app; check=container_binding; state=allowed; evidence={"container_name":"app","container_port":8080,"network_mode":"awsvpc","protocol":"tcp","task_definition_address":"aws_ecs_task_definition.app"}; listener=aws_lb_listener.https; target_group=aws_lb_target_group.app; check=listener_ingress; state=allowed; evidence={"cidr":"0.0.0.0/0","internet_source_witness":"8.8.8.8","port":443,"protocol":"tcp","rule_direction":"ingress","rule_path":["ingress",0],"rule_source_address":"aws_security_group.alb","security_group_address":"aws_security_group.alb","selector":"cidr"}; listener=aws_lb_listener.https; target_group=aws_lb_target_group.app; check=load_balancer_egress; state=allowed; evidence={"cidr":"0.0.0.0/0","port":8080,"protocol":"tcp","rule_direction":"egress","rule_path":["egress",0],"rule_source_address":"aws_security_group.alb","security_group_address":"aws_security_group.alb","selector":"cidr"}; listener=aws_lb_listener.https; target_group=aws_lb_target_group.app; check=service_ingress; state=allowed; evidence={"peer_security_group_addresses":["aws_security_group.alb"],"port":8080,"protocol":"tcp","rule_direction":"ingress","rule_path":["ingress",0],"rule_source_address":"aws_security_group.ecs","security_group_address":"aws_security_group.ecs","selector":"security_group"}
  - task definitions: address=aws_ecs_task_definition.app
  - task roles: address=aws_iam_role.task; arn=arn:aws:iam::111122223333:role/app-task-role; role_kind=ecs_task_role; credential_context=workload_runtime; authorization_state=allowed
  - messaging topology destruction paths: target_address=aws_sns_topic.events; target_type=aws_sns_topic; target_name=orders-events; target_arn=arn:aws:sns:us-east-1:111122223333:orders-events; operation=sns:DeleteTopic; operation_class=topic_deletion; target_granularity=topic_topology; target_scope=exact_sns_topic; grant_resource_scopes=topic_pattern; grant_resources=*; task_definition=aws_ecs_task_definition.app; task_role=aws_iam_role.task; authorization_sources=aws_iam_role.task; authorization_bases=identity_policy; same_account=true; authorization_state=allowed; operation_evaluation=deterministic_allowed; target_address=aws_sqs_queue.orders; target_type=aws_sqs_queue; target_name=orders; target_arn=arn:aws:sqs:us-east-1:111122223333:orders; operation=sqs:DeleteQueue; operation_class=queue_deletion; target_granularity=queue_topology; target_scope=exact_sqs_queue; grant_resource_scopes=queue_pattern; grant_resources=*; task_definition=aws_ecs_task_definition.app; task_role=aws_iam_role.task; authorization_sources=aws_iam_role.task; authorization_bases=identity_policy; same_account=true; authorization_state=allowed; operation_evaluation=deterministic_allowed
  - topology deletion outcome evidence: target_address=aws_sns_topic.events; operation=sns:DeleteTopic; outcome_evidence_scope=plan_local_messaging_topology_deletion_authority; successful_deletion_observed=False; recovery_state=not_established_by_modeled_aws_messaging_topology_evidence; descendant_impact_evaluated=False; out_of_plan_topology_evaluated=False; target_address=aws_sqs_queue.orders; operation=sqs:DeleteQueue; outcome_evidence_scope=plan_local_messaging_topology_deletion_authority; successful_deletion_observed=False; recovery_state=not_established_by_modeled_aws_messaging_topology_evidence; descendant_impact_evaluated=False; out_of_plan_topology_evaluated=False
  - assessment scope: establishes=deterministic sqs:DeleteQueue and sns:DeleteTopic authority for an ECS task role over exact modeled SQS queue or SNS topic topology, granted by exact resources or by resource patterns covering each target, with Denial of Service effect; does_not_establish=successful topology deletion, descendant-resource impact, recovery, or out-of-plan messaging topology

### Medium

#### DynamoDB deletion protection is disabled or unknown

- STRIDE category: Denial of Service
- Affected resources: `aws_dynamodb_table.orders`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: aws_dynamodb_table.orders does not configure DynamoDB deletion protection. Accidental or malicious delete operations can remove the table without this additional control-plane guardrail.
- Recommended mitigation: Enable DynamoDB deletion protection for persistent tables and require an explicit reviewed change before destructive table deletion.
- Evidence:
  - target resource: address=aws_dynamodb_table.orders; resource_type=aws_dynamodb_table; identifier=orders; table_arn=arn:aws:dynamodb:us-east-1:111122223333:table/orders
  - deletion protection: deletion_protection_state=not_configured

#### DynamoDB deletion protection is disabled or unknown

- STRIDE category: Denial of Service
- Affected resources: `aws_dynamodb_table.archive`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: aws_dynamodb_table.archive does not configure DynamoDB deletion protection. Accidental or malicious delete operations can remove the table without this additional control-plane guardrail.
- Recommended mitigation: Enable DynamoDB deletion protection for persistent tables and require an explicit reviewed change before destructive table deletion.
- Evidence:
  - target resource: address=aws_dynamodb_table.archive; resource_type=aws_dynamodb_table; identifier=archive; table_arn=arn:aws:dynamodb:us-east-1:111122223333:table/archive
  - deletion protection: deletion_protection_state=not_configured

#### IAM policy grants wildcard privileges

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_iam_role.task`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +1, data_sensitivity +0, lateral_movement +1, blast_radius +2, final_score 4 => medium
- Rationale: aws_iam_role.task contains allow statements with wildcard actions or resources. That makes the resulting access difficult to reason about and expands blast radius.
- Recommended mitigation: Replace wildcard actions and resources with narrowly scoped permissions tied to the exact services, APIs, and ARNs required by the workload.
- Evidence:
  - iam resources: *
  - policy statements: Allow actions=[secretsmanager:GetSecretValue] resources=[*]; Allow actions=[sqs:DeleteQueue, sns:DeleteTopic, dynamodb:DeleteTable] resources=[*]

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

#### Public Application Load Balancer is not associated with a WAF Web ACL

- STRIDE category: Tampering
- Affected resources: `aws_lb.web`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +0, lateral_movement +1, blast_radius +1, final_score 4 => medium
- Rationale: aws_lb.web is an internet-facing Application Load Balancer, but the Terraform plan does not show a deterministic AWS WAFv2 Web ACL association targeting it. Public edge traffic can reach the ALB without a modeled WAF or edge protection policy.
- Recommended mitigation: Associate an AWS WAFv2 Web ACL with internet-facing Application Load Balancers and keep the association modeled in Terraform so public edge protection is reviewable before deployment.
- Evidence:
  - target load balancer: address=aws_lb.web; type=aws_lb; arn=arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/web/1234; load_balancer_type=application; public_exposure=true; load balancer is internet-facing and attached security groups allow internet ingress
  - waf association coverage: target_resource_arn=arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/web/1234; resolved_web_acl_association_count=0; modeled_web_acl_association_count=0

#### SNS topic does not use a customer-managed KMS key

- STRIDE category: Information Disclosure
- Affected resources: `aws_sns_topic.events`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: aws_sns_topic.events does not configure a customer-managed KMS key for SNS message encryption. This is an encryption ownership and key-control posture finding; it does not claim that the topic is unencrypted.
- Recommended mitigation: Configure `kms_master_key_id` with a customer-managed KMS key for SNS topics where key ownership, rotation, audit separation, or compliance controls are required.
- Evidence:
  - target resource: address=aws_sns_topic.events; resource_type=aws_sns_topic; identifier=orders-events; arn=arn:aws:sns:us-east-1:111122223333:orders-events
  - encryption ownership: encryption_ownership_state=absent; kms_master_key_id=unset; finding_scope=customer-managed key ownership and control posture

#### SQS queue does not configure a dead-letter queue

- STRIDE category: Denial of Service
- Affected resources: `aws_sqs_queue.orders`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: aws_sqs_queue.orders does not configure an SQS dead-letter queue. Poison messages or repeated delivery failures can consume subscriber capacity and reduce recovery options for failed processing.
- Recommended mitigation: Configure an SQS `redrive_policy` or `aws_sqs_queue_redrive_policy` with a reviewed dead-letter queue and maximum receive count so poison messages do not repeatedly consume subscriber capacity.
- Evidence:
  - target resource: address=aws_sqs_queue.orders; resource_type=aws_sqs_queue; identifier=orders; arn=arn:aws:sqs:us-east-1:111122223333:orders
  - dead letter posture: redrive_state=not_configured; dead_letter_target_arn=unset; max_receive_count=unset; redrive_source_address=aws_sqs_queue.orders

#### SQS queue does not use a customer-managed KMS key

- STRIDE category: Information Disclosure
- Affected resources: `aws_sqs_queue.orders`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: aws_sqs_queue.orders does not configure a customer-managed KMS key for SQS message encryption. This is an encryption ownership and key-control posture finding; it does not claim that the queue is unencrypted.
- Recommended mitigation: Configure `kms_master_key_id` with a customer-managed KMS key for SQS queues where key ownership, rotation, audit separation, or compliance controls are required.
- Evidence:
  - target resource: address=aws_sqs_queue.orders; resource_type=aws_sqs_queue; identifier=orders; arn=arn:aws:sqs:us-east-1:111122223333:orders
  - encryption ownership: encryption_ownership_state=absent; kms_master_key_id=unset; sqs_managed_sse_enabled_state=not_configured; finding_scope=customer-managed key ownership and control posture

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

#### VPC Flow Logs are not configured for a modeled VPC

- STRIDE category: Repudiation
- Affected resources: `aws_vpc.main`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +0, lateral_movement +1, blast_radius +2, final_score 3 => medium
- Rationale: aws_vpc.main does not have a resolved aws_flow_log targeting the VPC in this Terraform plan. Network traffic metadata for incident response, threat hunting, and segmentation review may be unavailable unless Flow Logs are configured elsewhere.
- Recommended mitigation: Enable VPC Flow Logs for production VPCs, route them to a retained CloudWatch Logs, S3, or Firehose destination, and manage Flow Log resources in Terraform so network telemetry posture is reviewable.
- Evidence:
  - target vpc: address=aws_vpc.main; type=aws_vpc; identifier=vpc-00000006; cidr_block=10.60.0.0/16
  - flow log coverage: target_vpc_id=vpc-00000006; resolved_vpc_flow_log_count=0; aws_flow_log resources are not modeled

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
- Rationale: aws_ecs_service.app runs in VPC `vpc-00000006` and inherits Secrets Manager secret retrieval from aws_iam_role.task, but the Terraform plan does not show a Secrets Manager interface VPC endpoint for that VPC. Calls to the sensitive service may therefore depend on public AWS service endpoints, NAT, or another egress path.
- Recommended mitigation: Add a Secrets Manager interface VPC endpoint with private DNS enabled for VPC workloads that retrieve secrets, and narrow endpoint policies where possible.
- Evidence:
  - target workload: address=aws_ecs_service.app; type=aws_ecs_service; vpc_id=vpc-00000006; subnet_ids=[subnet-ecs-private-app]; security_group_ids=[sg-ecs-service]
  - sensitive service dependency: service=secretsmanager; role=aws_iam_role.task; actions=[secretsmanager:GetSecretValue]; resources=[*]
  - vpc endpoint coverage: vpc_id=vpc-00000006; service=secretsmanager; expected_endpoint_type=interface; vpc_endpoint_coverage=missing
  - policy statements: Allow actions=[secretsmanager:GetSecretValue] resources=[*]

### Low

#### DynamoDB table does not use a deterministic customer-managed KMS key

- STRIDE category: Information Disclosure
- Affected resources: `aws_dynamodb_table.orders`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +1, lateral_movement +0, blast_radius +1, final_score 2 => low
- Rationale: aws_dynamodb_table.orders uses an AWS-owned key rather than a customer-managed KMS key. DynamoDB remains encrypted at rest; this finding concerns key ownership, rotation, audit separation, and compliance posture.
- Recommended mitigation: Configure DynamoDB server-side encryption with a customer-managed KMS key where key ownership, rotation, audit separation, or compliance controls are required.
- Evidence:
  - target resource: address=aws_dynamodb_table.orders; resource_type=aws_dynamodb_table; identifier=orders; table_arn=arn:aws:dynamodb:us-east-1:111122223333:table/orders
  - encryption ownership: encryption_ownership_state=aws_owned; encryption_configuration_state=not_configured; kms_key_arn=unset; storage_encrypted=true; finding_scope=customer-managed key ownership and control posture; DynamoDB remains encrypted at rest when an AWS-owned or AWS-managed key is used

#### DynamoDB table does not use a deterministic customer-managed KMS key

- STRIDE category: Information Disclosure
- Affected resources: `aws_dynamodb_table.archive`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +1, lateral_movement +0, blast_radius +1, final_score 2 => low
- Rationale: aws_dynamodb_table.archive uses an AWS-owned key rather than a customer-managed KMS key. DynamoDB remains encrypted at rest; this finding concerns key ownership, rotation, audit separation, and compliance posture.
- Recommended mitigation: Configure DynamoDB server-side encryption with a customer-managed KMS key where key ownership, rotation, audit separation, or compliance controls are required.
- Evidence:
  - target resource: address=aws_dynamodb_table.archive; resource_type=aws_dynamodb_table; identifier=archive; table_arn=arn:aws:dynamodb:us-east-1:111122223333:table/archive
  - encryption ownership: encryption_ownership_state=aws_owned; encryption_configuration_state=not_configured; kms_key_arn=unset; storage_encrypted=true; finding_scope=customer-managed key ownership and control posture; DynamoDB remains encrypted at rest when an AWS-owned or AWS-managed key is used

#### RDS database does not export engine CloudWatch logs

- STRIDE category: Repudiation
- Affected resources: `aws_db_instance.app`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +1, lateral_movement +0, blast_radius +1, final_score 2 => low
- Rationale: aws_db_instance.app (engine `postgres`) does not export any of the baseline CloudWatch Logs expected for its engine family (postgresql). Without these log exports the database lacks the basic observability posture needed to investigate errors, slow queries, and audit activity from CloudWatch.
- Recommended mitigation: Enable the CloudWatch Logs exports expected for the RDS engine family (for example `postgresql` for PostgreSQL, `error` and `slowquery` for MySQL/MariaDB) so errors, slow queries, and audit activity are captured for investigation.
- Evidence:
  - target resource: address=aws_db_instance.app; type=aws_db_instance; identifier=ecs-app-db; engine=postgres
  - log export posture: enabled_cloudwatch_logs_exports=[]; expected_log_exports=['postgresql']; engine-family baseline log exports are absent

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
- The engine reasons over Terraform planned values only and does not validate runtime drift, runtime audit evidence, or post-deployment control-plane activity.
