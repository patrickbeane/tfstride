# AWS Provider Coverage

AWS is `tfstride`'s deepest provider implementation, covering compute and container edge exposure, workload-to-data paths, KMS-backed cryptographic paths, IAM/OIDC trust, and account-level audit/detection posture.

## Modeled Resources and Families

This is a concise coverage map. Reports identify unsupported AWS resource types encountered in each plan.

* `aws_instance`
* `aws_ecs_service`
* `aws_ecs_task_definition`
* `aws_ecr_repository`
* `aws_ecr_registry_scanning_configuration`
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
* `aws_cloudfront_distribution`
* `aws_api_gateway_rest_api`
* `aws_api_gateway_method`
* `aws_api_gateway_stage`
* `aws_api_gateway_authorizer`
* `aws_apigatewayv2_api`
* `aws_apigatewayv2_route`
* `aws_apigatewayv2_stage`
* `aws_wafv2_web_acl`
* `aws_wafv2_web_acl_association`
* `aws_db_instance`
* `aws_dynamodb_table`
* `aws_s3_bucket`
* `aws_s3_bucket_lifecycle_configuration`
* `aws_s3_bucket_object_lock_configuration`
* `aws_s3_bucket_policy`
* `aws_s3_bucket_public_access_block`
* `aws_s3_bucket_versioning`
* `aws_s3_bucket_server_side_encryption_configuration`
* `aws_iam_role`
* `aws_iam_policy`
* `aws_iam_role_policy`
* `aws_iam_role_policy_attachment`
* `aws_iam_instance_profile`
* `aws_iam_openid_connect_provider`
* `aws_lambda_function`
* `aws_lambda_function_url`
* `aws_lambda_permission`
* `aws_kms_key`
* `aws_kms_alias`
* `aws_kms_grant`
* `aws_kms_key_policy`
* `aws_sns_topic`
* `aws_sqs_queue`
* `aws_sqs_queue_redrive_policy`
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
* `aws_config_configuration_recorder_status`
* `aws_config_delivery_channel`
* `aws_accessanalyzer_analyzer`
* `aws_macie2_account`
* `aws_caller_identity`

## Account-resolution primitive

`AwsResourceIndex.account_identities.resolve(resource)` returns an immutable account-resolution result with an account ID, partition, state (`resolved`, `unknown`, `ambiguous`, or `invalid`), evidence, and uncertainty reasons. A known, validated own ARN takes precedence over caller credentials and unrelated accounts in the plan. Normalization retains the original identity inputs and their unknown state so stale planned ARN values cannot establish ownership.

Caller-identity fallback requires an explicit matching provider configuration and a managed resource type whose creation establishes ownership in that account. The initial fallback set covers IAM roles/policies/instance profiles/OIDC providers, S3 buckets, KMS keys/aliases, Secrets Manager secrets, SNS topics, SQS queues, Lambda functions, DynamoDB tables, and API Gateway APIs. Data lookups, attachments, and other resource types do not inherit ownership from credentials. Missing scope and incomplete or conflicting scoped callers remain unresolved, with evidence retained.

Role-trust findings, resource-policy findings, KMS-grant findings, trust boundaries, narrowed-trust observations, and trust-based workload paths classify principals against the target resource's account. Findings and observations retain the account-resolution evidence and uncertainty. Unknown ownership cannot establish foreign-account access, but wildcard and account-root breadth remain meaningful independently. A proven same-account KMS root retains lower-severity treatment as account-level IAM delegation; it does not grant every identity key access. KMS grants are classified against the key's owner, not the grant declaration's provider credentials.

`inventory.primary_account_id` retains its existing summary behavior and is not consulted by this trust classification. Resolve resource references with the existing provider-aware reference views before resolving the selected target's account. Separate workload-to-data authorization consumers are outside this trust migration.

## Rule Coverage

### Public exposure & edge
* Public compute ingress and public Lambda Function URL invocation
* CloudFront viewer HTTP/TLS/WAF and standard access-log posture
* Public API Gateway CORS/WAF, route authorization, and stage access-log posture
* ALB listener HTTP/TLS certificate/SSL-policy posture, and public ALB WAF association posture
* EKS public endpoint/CIDR/private-endpoint posture

### Container & image integrity
* ECS/Lambda container images without digest pins
* Exact ECR mutable-tag correlation, and runtime identities with exact ECR write access to their deployed image repository
* ECS literal sensitive environment values
* ECR mutable tags, customer-managed encryption, and repository scanning posture

### Workload-to-data paths
* Public ECS service-to-Secrets Manager, S3, SNS/SQS, and DynamoDB mutation paths
* Exact public ECS-to-SQS receive and message-removal paths; `DeleteMessage` requires receive authority for runtime receipt handles, while `PurgeQueue` is independent
* Public ECS SQS queue and SNS topic topology-deletion paths for `DeleteQueue` and `DeleteTopic`
* Public ECS S3 `DeleteObject` and `DeleteObjectVersion` disruption paths with exact object, prefix, bucket-namespace, and version/Object Lock evidence
* Public ECS S3 bucket-topology disruption paths for exact `s3:DeleteBucket` authority, with emptiness and access-point state left unestablished
* Public ECS DynamoDB item-deletion and table-topology disruption paths for exact item operations or `DeleteTable` authority, with deletion-protection and point-in-time-recovery evidence
* Public ECS secret-value tampering and secret-deletion disruption paths for task-role authority
* Execution/task-role access broader than consumed references
* Native Secrets Manager or SSM delivery references and explicitly denied paths stay quiet; condition-dependent, incomplete, or unresolved expected management paths remain uncertainty where modeled

### Kubernetes (EKS)
* Secrets encryption, authentication mode, control-plane logging, and VPC CNI network-policy posture

### Networking & telemetry
* VPC Flow Logs coverage, traffic-type, and destination posture
* Workload use of S3, KMS, or Secrets Manager without modeled VPC endpoint coverage, and broad VPC endpoint policies

### Data-store posture
* S3 public-access/encryption/versioning/Object Lock/recovery posture
* RDS public endpoint, backup retention, deletion protection, customer-managed KMS, Multi-AZ, Performance Insights, engine-log export, and IAM authentication posture
* DynamoDB customer-managed key ownership, point-in-time recovery, and deletion-protection posture
* Secrets Manager customer-managed key, recovery-window, and rotation posture

### KMS & cryptographic paths
* KMS key lifecycle, exact key/alias identity, key-policy completeness, lockout-safety configuration, grant operations and constraints, cryptographic capabilities, and authorization
* Exact encrypted-resource dependencies and downstream blast-radius enrichment
* Public ECS decrypt, signing, and MAC-generation paths that require task-role authority and public load-balancer reachability
* Public ECS KMS key-disruption and authorization-delegation paths that require task-role management authority

### Messaging
* SNS/SQS encryption ownership, SQS retention, and redrive posture

### Audit & detection
* CloudTrail multi-region, log-validation, event-selector, data-event, and Insights posture
* Public ECS task roles with current `cloudtrail:StopLogging` or `cloudtrail:DeleteTrail` authority over an exact current CloudTrail trail, reported as prospective Repudiation risk
* GuardDuty, Security Hub, AWS Config, Access Analyzer, and Macie account posture

### IAM & identity
* IAM wildcard permissions and privileged role-assignment posture
* OIDC provider resolution and federated trust narrowing
* Workload-role sensitive permissions, resource-policy exposure, and tier segmentation
* Transitive private-data exposure, control-plane-to-sensitive-workload chains, and role-trust narrowing

KMS and secret-management posture, public workload cryptographic-operation paths, and public workload key or secret administration paths are plan-local and require modeled authorization. See [Public Workload Secret Integrity and Availability Paths](../analysis/secret-management-paths.md).

## Scope & Limitations

* AWS is currently `tfstride`'s deepest provider implementation.
* Identity-assignment analysis is deterministic and plan-local, focused on inline policies, standalone policies, role-policy attachments, OIDC providers, and trust policies.
* Condition narrowing focuses on high-signal keys such as `SourceArn`, `SourceAccount`, and `ExternalId` rather than every service-specific authorization condition.
* Messaging findings establish modeled task-role authority, not successful payload retrieval, message or topology deletion, replay, or recovery; see [Public Workload Messaging Disclosure and Disruption Paths](../analysis/messaging-paths.md).
* CloudTrail disruption findings establish current authority over an exact modeled trail, not a successful operation, historical CloudTrail event or destination-log deletion, destination-resource deletion, account-wide or out-of-plan disruption, or recovery/restoration.

See [Cross-Provider Threat-Path Semantics](../analysis/path-semantics.md) for how these findings relate to the shared cross-provider evidence model.
