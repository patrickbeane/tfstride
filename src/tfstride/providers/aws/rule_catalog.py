from __future__ import annotations

from tfstride.analysis.rule_registry import RuleMetadata
from tfstride.models import StrideCategory

AWS_RULE_METADATA = (
    RuleMetadata(
        rule_id="aws-public-compute-broad-ingress",
        title="Internet-exposed compute service permits overly broad ingress",
        category=StrideCategory.SPOOFING,
        recommended_mitigation=(
            "Restrict ingress to expected client ports, remove direct administrative exposure, "
            "and place management access behind a controlled bastion, VPN, or SSM Session Manager."
        ),
        tags=("aws", "network", "compute", "internet"),
        severity_factors=("internet_exposure", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-lambda-public-invocation",
        title="Lambda function allows public invocation",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Require AWS_IAM authorization for Lambda Function URLs unless anonymous invocation is intentional, "
            "and avoid wildcard Lambda permissions unless they are narrowed by source ARN or source account "
            "conditions."
        ),
        tags=("aws", "lambda", "serverless", "public-access", "invocation"),
        severity_factors=("internet_exposure", "privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-load-balancer-http-public-listener",
        title="Public AWS load balancer listener uses plaintext HTTP",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Terminate HTTPS on public ALB or NLB listeners, redirect HTTP to HTTPS where possible, "
            "and keep plaintext listeners internal or behind another explicit TLS termination layer."
        ),
        tags=("aws", "load-balancer", "alb", "tls", "public-access"),
        severity_factors=("internet_exposure", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-load-balancer-listener-tls-certificate-missing",
        title="Public AWS load balancer TLS listener lacks deterministic certificate evidence",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Attach an ACM or IAM server certificate to public HTTPS/TLS listeners and keep certificate "
            "references explicit in Terraform so planned listener posture is reviewable."
        ),
        tags=("aws", "load-balancer", "alb", "tls", "certificate"),
        severity_factors=("internet_exposure", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-load-balancer-listener-ssl-policy-weak-or-unknown",
        title="Public AWS load balancer TLS listener has weak or unknown SSL policy",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Use a current ELB security policy that enforces TLS 1.2 or newer, retire legacy SSL/TLS clients, "
            "and keep `ssl_policy` deterministic in Terraform for public HTTPS/TLS listeners."
        ),
        tags=("aws", "load-balancer", "alb", "tls", "ssl-policy"),
        severity_factors=("internet_exposure", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-public-alb-waf-missing",
        title="Public Application Load Balancer is not associated with a WAF Web ACL",
        category=StrideCategory.TAMPERING,
        recommended_mitigation=(
            "Associate an AWS WAFv2 Web ACL with internet-facing Application Load Balancers and keep the "
            "association modeled in Terraform so public edge protection is reviewable before deployment."
        ),
        tags=("aws", "load-balancer", "alb", "waf", "wafv2", "public-edge"),
        severity_factors=("internet_exposure", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-cloudfront-viewer-http-allowed",
        title="CloudFront distribution allows viewer HTTP",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Set CloudFront cache behavior viewer_protocol_policy to redirect-to-https or https-only for public "
            "distributions, and keep exceptions explicit and reviewed."
        ),
        tags=("aws", "cloudfront", "cdn", "tls", "http", "public-edge"),
        severity_factors=("internet_exposure", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-cloudfront-viewer-tls-policy-weak-or-unknown",
        title="CloudFront distribution has weak or unknown viewer TLS policy",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Configure CloudFront viewer certificates with a minimum protocol version of TLS 1.2 or newer, and keep "
            "the minimum_protocol_version deterministic in Terraform for public distributions."
        ),
        tags=("aws", "cloudfront", "cdn", "tls", "certificate", "public-edge"),
        severity_factors=("internet_exposure", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-cloudfront-access-logging-not-configured",
        title="Public CloudFront distribution does not configure access logging",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Configure CloudFront `logging_config.bucket` for public distributions, use a dedicated retained "
            "S3 destination with appropriate access controls, and set a reviewed prefix where it improves "
            "log organization."
        ),
        tags=("aws", "cloudfront", "cdn", "logging", "access-logs", "public-edge"),
        severity_factors=("internet_exposure", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-public-cloudfront-waf-missing",
        title="Public CloudFront distribution lacks modeled WAF protection",
        category=StrideCategory.TAMPERING,
        recommended_mitigation=(
            "Attach an AWS WAFv2 Web ACL to public CloudFront distributions with web_acl_id and keep the association "
            "modeled in Terraform so public edge protection is reviewable before deployment."
        ),
        tags=("aws", "cloudfront", "cdn", "waf", "wafv2", "public-edge"),
        severity_factors=("internet_exposure", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-api-gateway-cors-permissive",
        title="Public API Gateway HTTP API reflects all origins via CORS",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Scope API Gateway v2 CORS `allow_origins` to reviewed origins for public HTTP APIs, "
            "avoid wildcard origins, and never pair `allow_credentials` with a wildcard origin list."
        ),
        tags=("aws", "api-gateway", "serverless", "cors", "public-edge"),
        severity_factors=("internet_exposure", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-public-api-gateway-waf-missing",
        title="Public API Gateway endpoint lacks modeled WAF protection",
        category=StrideCategory.TAMPERING,
        recommended_mitigation=(
            "Attach an AWS WAFv2 Web ACL to public API Gateway endpoints with an "
            "`aws_wafv2_web_acl_association` targeting the API stage, and keep the association modeled in "
            "Terraform so public edge protection is reviewable before deployment."
        ),
        tags=("aws", "api-gateway", "serverless", "waf", "wafv2", "public-edge"),
        severity_factors=("internet_exposure", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-api-gateway-public-route-authorization-none",
        title="Public API Gateway method or route permits unauthenticated requests",
        category=StrideCategory.SPOOFING,
        recommended_mitigation=(
            "Configure an API Gateway authorizer, IAM authorization, or another reviewed authentication "
            "mechanism for public methods and routes unless anonymous access is an explicit product requirement."
        ),
        tags=("aws", "api-gateway", "serverless", "authentication", "public-edge"),
        severity_factors=("internet_exposure", "privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-api-gateway-stage-access-logs-missing",
        title="Public API Gateway stage lacks an access log destination",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Configure `access_log_settings.destination_arn` for public API Gateway stages and deliver "
            "request logs to a retained, access-controlled CloudWatch Logs group or supported destination."
        ),
        tags=("aws", "api-gateway", "serverless", "logging", "public-edge"),
        severity_factors=("internet_exposure", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-cloudtrail-multi-region-disabled",
        title="CloudTrail is not configured for multi-region auditing",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Configure account-level CloudTrail trails with `is_multi_region_trail = true`, include global "
            "service events where appropriate, and centralize logs in a protected S3 bucket or logging account."
        ),
        tags=("aws", "cloudtrail", "audit", "logging", "account-posture"),
        severity_factors=("lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-cloudtrail-log-file-validation-disabled",
        title="CloudTrail log file validation is disabled",
        category=StrideCategory.TAMPERING,
        recommended_mitigation=(
            "Enable CloudTrail log file validation so delivered log files can be integrity-checked during incident "
            "response, forensics, or compliance review."
        ),
        tags=("aws", "cloudtrail", "audit", "log-integrity", "account-posture"),
        severity_factors=("lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-cloudtrail-management-events-disabled",
        title="CloudTrail management events are explicitly disabled",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Enable CloudTrail management events for account and control-plane API activity, and avoid selector "
            "configurations that explicitly exclude management events from the trail."
        ),
        tags=("aws", "cloudtrail", "audit", "management-events", "account-posture"),
        severity_factors=("lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-cloudtrail-data-events-not-modeled",
        title="CloudTrail data event selectors are not modeled",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Add CloudTrail data event selectors for sensitive data-plane resources such as S3 objects or Lambda "
            "functions when those operations need retained audit coverage."
        ),
        tags=("aws", "cloudtrail", "audit", "data-events", "account-posture"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-cloudtrail-insight-selectors-missing",
        title="CloudTrail Insights selectors are not configured",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Configure CloudTrail Insights selectors such as ApiCallRateInsight or ApiErrorRateInsight where "
            "control-plane anomaly detection is expected for the account trail."
        ),
        tags=("aws", "cloudtrail", "audit", "insights", "account-posture"),
        severity_factors=("lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-guardduty-detector-disabled-or-missing",
        title="GuardDuty detector is disabled or not modeled",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Enable GuardDuty detectors in active regions and keep detector resources or account-baseline modules "
            "visible in Terraform so threat-detection posture is reviewable before deployment."
        ),
        tags=("aws", "guardduty", "threat-detection", "account-posture"),
        severity_factors=("lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-securityhub-account-missing",
        title="Security Hub account enablement is not modeled",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Enable Security Hub for the account baseline and keep `aws_securityhub_account` or an equivalent "
            "account-control module represented in Terraform so control findings are consistently aggregated."
        ),
        tags=("aws", "securityhub", "security-monitoring", "account-posture"),
        severity_factors=("lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-config-recorder-disabled-or-missing",
        title="AWS Config recorder is disabled or not modeled",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Enable the AWS Config recorder and keep `aws_config_configuration_recorder` "
            "(with `aws_config_configuration_recorder_status`) or an equivalent account-baseline module "
            "represented in Terraform so resource configuration changes are reviewable before deployment."
        ),
        tags=("aws", "config", "audit", "account-posture"),
        severity_factors=("lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-config-delivery-channel-missing",
        title="AWS Config delivery channel is not modeled",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Configure an `aws_config_delivery_channel` pointing to a durable S3 bucket and optionally an SNS "
            "topic, or represent the equivalent account-baseline module in Terraform so configuration history is "
            "exported and reviewable before deployment."
        ),
        tags=("aws", "config", "audit", "account-posture"),
        severity_factors=("lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-access-analyzer-not-configured",
        title="IAM Access Analyzer is not configured",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Create an `aws_accessanalyzer_analyzer` (account or organization scope) for the account baseline so "
            "external and unused access to IAM resources is detected and reviewable before deployment."
        ),
        tags=("aws", "access-analyzer", "audit", "account-posture"),
        severity_factors=("lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-macie-not-enabled-for-sensitive-storage",
        title="Amazon Macie is not enabled for sensitive S3 storage",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Enable Amazon Macie with an `aws_macie2_account` resource for the account baseline so sensitive "
            "data in the modeled Amazon S3 storage is discovered and classified before deployment."
        ),
        tags=("aws", "macie", "data-classification", "account-posture"),
        severity_factors=("lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-database-permissive-ingress",
        title="Database is reachable from overly permissive sources",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Keep databases off public paths, allow ingress only from narrowly scoped application "
            "security groups, and enforce authentication plus encryption independently of network policy."
        ),
        tags=("aws", "network", "database"),
        severity_factors=("internet_exposure", "data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-rds-storage-encryption-disabled",
        title="Database storage encryption is disabled",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Enable RDS storage encryption with a managed KMS key, enforce encryption by default in "
            "database modules, and migrate plaintext instances to encrypted replacements where needed."
        ),
        tags=("aws", "database", "encryption"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-rds-public-endpoint-enabled",
        title="RDS database endpoint is publicly accessible",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Disable `publicly_accessible` for private databases, place RDS instances in private subnets, "
            "and restrict database ingress to expected application security groups or controlled operator paths."
        ),
        tags=("aws", "database", "rds", "public-access"),
        severity_factors=("internet_exposure", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-rds-backup-retention-insufficient",
        title="RDS automated backup retention is disabled or too short",
        category=StrideCategory.DENIAL_OF_SERVICE,
        recommended_mitigation=(
            "Enable RDS automated backups and retain backups for a recovery window that matches business "
            "requirements, incident response timelines, and compliance expectations."
        ),
        tags=("aws", "database", "rds", "backup", "recovery"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-rds-deletion-protection-disabled",
        title="RDS deletion protection is disabled",
        category=StrideCategory.DENIAL_OF_SERVICE,
        recommended_mitigation=(
            "Enable RDS deletion protection for persistent databases and require an explicit reviewed change "
            "before destructive instance deletion."
        ),
        tags=("aws", "database", "rds", "recovery", "deletion-protection"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-rds-customer-managed-kms-key-missing",
        title="RDS encrypted storage does not use a customer-managed KMS key",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Use a customer-managed KMS key for RDS storage encryption where key ownership, rotation, "
            "audit separation, or compliance controls are required."
        ),
        tags=("aws", "database", "rds", "encryption", "kms"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-rds-multi-az-disabled",
        title="RDS instance is not deployed across multiple Availability Zones",
        category=StrideCategory.DENIAL_OF_SERVICE,
        recommended_mitigation=(
            "Enable Multi-AZ for RDS instances that require availability, so a standby in a second AZ can "
            "perform automatic failover during AZ-level outages or maintenance events."
        ),
        tags=("aws", "database", "rds", "availability", "high-availability"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-rds-performance-insights-disabled",
        title="RDS Performance Insights is disabled",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Enable RDS Performance Insights for production databases to expose query-level load, wait "
            "events, and regression signals that support operational detection and investigation."
        ),
        tags=("aws", "database", "rds", "observability", "performance-insights"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-rds-cloudwatch-log-exports-missing",
        title="RDS database does not export engine CloudWatch logs",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Enable the CloudWatch Logs exports expected for the RDS engine family (for example `postgresql` "
            "for PostgreSQL, `error` and `slowquery` for MySQL/MariaDB) so errors, slow queries, and audit "
            "activity are captured for investigation."
        ),
        tags=("aws", "database", "rds", "observability", "logging"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-rds-iam-auth-disabled",
        title="RDS IAM database authentication is disabled",
        category=StrideCategory.SPOOFING,
        recommended_mitigation=(
            "Enable RDS IAM database authentication where supported so database access relies on short-lived "
            "AWS-signed tokens issued via IAM instead of long-lived static database credentials."
        ),
        tags=("aws", "database", "rds", "authentication", "iam"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-s3-public-access",
        title="Object storage is publicly accessible",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Remove public ACL or bucket policy access, enable an S3 public access block, "
            "and serve content through a controlled CDN or origin access pattern when public distribution is required."
        ),
        tags=("aws", "storage", "public-access"),
        severity_factors=("internet_exposure", "privilege_breadth", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-s3-customer-managed-encryption-missing",
        title="S3 bucket does not use customer-managed SSE-KMS encryption",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Configure S3 default server-side encryption with SSE-KMS or DSSE-KMS and a customer-managed KMS "
            "key where key ownership, rotation, audit separation, or compliance controls are required."
        ),
        tags=("aws", "s3", "storage", "encryption", "kms"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-s3-versioning-disabled",
        title="S3 bucket versioning is not enabled",
        category=StrideCategory.TAMPERING,
        recommended_mitigation=(
            "Enable S3 bucket versioning for sensitive buckets and pair it with lifecycle policies that retain "
            "recoverable object versions for the expected recovery window."
        ),
        tags=("aws", "s3", "storage", "recovery", "versioning"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-s3-object-lock-retention-missing",
        title="S3 Object Lock default retention is missing or too short",
        category=StrideCategory.DENIAL_OF_SERVICE,
        recommended_mitigation=(
            "Enable S3 Object Lock with default retention for buckets that require immutable recovery "
            "protection, choose Governance or Compliance mode intentionally, and align retention duration "
            "with recovery and compliance objectives."
        ),
        tags=("aws", "s3", "storage", "immutability", "object-lock", "retention"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-s3-lifecycle-noncurrent-retention-insufficient",
        title="S3 lifecycle expires noncurrent versions too quickly",
        category=StrideCategory.DENIAL_OF_SERVICE,
        recommended_mitigation=(
            "Keep noncurrent object versions for a recovery window that matches operational detection and "
            "restore objectives. Avoid lifecycle expiration periods that remove recoverable versions before "
            "operators can respond to accidental or malicious destructive changes."
        ),
        tags=("aws", "s3", "storage", "recovery", "lifecycle", "retention"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-secretsmanager-customer-managed-kms-key-missing",
        title="Secrets Manager secret does not use a customer-managed KMS key",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Configure `kms_key_id` with a customer-managed KMS key for secrets where key ownership, "
            "rotation, audit separation, or compliance controls are required."
        ),
        tags=("aws", "secretsmanager", "secrets", "encryption", "kms"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-secretsmanager-recovery-window-too-short",
        title="Secrets Manager deletion recovery window is too short",
        category=StrideCategory.DENIAL_OF_SERVICE,
        recommended_mitigation=(
            "Use a Secrets Manager recovery window that gives operators enough time to detect and restore "
            "accidental or malicious secret deletion before permanent removal."
        ),
        tags=("aws", "secretsmanager", "secrets", "recovery", "deletion-protection"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-secretsmanager-rotation-not-configured-or-too-long",
        title="Secrets Manager rotation is not configured or too infrequent",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Configure `aws_secretsmanager_secret_rotation` with a rotation Lambda and a rotation interval aligned "
            "to the organization secret lifecycle policy, such as 90 days or less for sensitive application secrets."
        ),
        tags=("aws", "secretsmanager", "secrets", "rotation", "lifecycle"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-kms-key-rotation-disabled-or-unknown",
        title="KMS key rotation is disabled or unknown",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Enable automatic annual rotation for customer-managed symmetric KMS keys that protect sensitive "
            "storage, secrets, databases, or Kubernetes secrets, and keep key usage and key spec deterministic in "
            "Terraform for review."
        ),
        tags=("aws", "kms", "encryption", "rotation", "lifecycle"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-kms-key-deletion-window-too-short",
        title="KMS key deletion window is too short",
        category=StrideCategory.DENIAL_OF_SERVICE,
        recommended_mitigation=(
            "Use a longer KMS deletion window for customer-managed keys so operators have enough time to detect "
            "and cancel accidental or malicious scheduled key deletion before dependent encrypted data becomes "
            "unrecoverable."
        ),
        tags=("aws", "kms", "encryption", "recovery", "deletion-protection"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-workload-secretsmanager-vpc-endpoint-missing",
        title="Workload uses Secrets Manager without a VPC endpoint",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Add a Secrets Manager interface VPC endpoint with private DNS enabled for VPC workloads that retrieve "
            "secrets, and narrow endpoint policies where possible."
        ),
        tags=("aws", "vpc-endpoint", "private-connectivity", "secretsmanager", "workload"),
        severity_factors=("internet_exposure", "privilege_breadth", "data_sensitivity", "lateral_movement"),
    ),
    RuleMetadata(
        rule_id="aws-workload-kms-vpc-endpoint-missing",
        title="Workload uses KMS without a VPC endpoint",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Add a KMS interface VPC endpoint with private DNS enabled for VPC workloads that perform key "
            "operations, and narrow endpoint policies where possible."
        ),
        tags=("aws", "vpc-endpoint", "private-connectivity", "kms", "workload"),
        severity_factors=("internet_exposure", "privilege_breadth", "data_sensitivity", "lateral_movement"),
    ),
    RuleMetadata(
        rule_id="aws-workload-s3-vpc-endpoint-missing",
        title="Workload uses S3 without a VPC endpoint",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Add an S3 gateway or interface VPC endpoint for VPC workloads that access S3, route expected private "
            "subnets through it, and use endpoint policies where possible."
        ),
        tags=("aws", "vpc-endpoint", "private-connectivity", "s3", "workload"),
        severity_factors=("internet_exposure", "privilege_breadth", "data_sensitivity", "lateral_movement"),
    ),
    RuleMetadata(
        rule_id="aws-vpc-endpoint-policy-broad-access",
        title="VPC endpoint policy allows broad service access",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Attach explicit VPC endpoint policies for S3, Secrets Manager, and KMS endpoints, scope principals, "
            "actions, and resources to expected workloads and targets, and avoid relying on the default broad "
            "endpoint policy where private service access is security-sensitive."
        ),
        tags=("aws", "vpc-endpoint", "private-connectivity", "policy", "data"),
        severity_factors=("privilege_breadth", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-vpc-flow-logs-not-configured",
        title="VPC Flow Logs are not configured for a modeled VPC",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Enable VPC Flow Logs for production VPCs, route them to a retained CloudWatch Logs, S3, or Firehose "
            "destination, and manage Flow Log resources in Terraform so network telemetry posture is reviewable."
        ),
        tags=("aws", "vpc", "flow-logs", "network-telemetry", "logging"),
        severity_factors=("lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-vpc-flow-log-traffic-type-incomplete",
        title="VPC Flow Log does not capture all traffic",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Set VPC Flow Log `traffic_type` to `ALL` where investigation and segmentation review require both "
            "accepted and rejected traffic records, and keep the field deterministic in Terraform plans."
        ),
        tags=("aws", "vpc", "flow-logs", "network-telemetry", "traffic-coverage"),
        severity_factors=("lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-vpc-flow-log-destination-missing",
        title="VPC Flow Log destination is missing or unknown",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Configure VPC Flow Logs with a deterministic CloudWatch Logs, S3, or Firehose destination and ensure "
            "the delivery role or destination policy permits log delivery."
        ),
        tags=("aws", "vpc", "flow-logs", "network-telemetry", "log-destination"),
        severity_factors=("lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-eks-api-endpoint-public-unrestricted",
        title="EKS Kubernetes API endpoint is public without narrow CIDR restrictions",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Disable public endpoint access where possible, enable private endpoint access, or restrict "
            "`vpc_config.public_access_cidrs` to narrow trusted CIDRs."
        ),
        tags=("aws", "eks", "kubernetes", "control-plane", "public-access"),
        severity_factors=("internet_exposure", "privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-eks-private-endpoint-not-enabled",
        title="EKS private API endpoint is not enabled",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Enable the EKS private endpoint for private workloads, then restrict or disable public endpoint access "
            "based on operator access requirements."
        ),
        tags=("aws", "eks", "kubernetes", "control-plane", "private-endpoint"),
        severity_factors=("internet_exposure", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-eks-secrets-encryption-not-configured",
        title="EKS secrets encryption is not configured",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Configure EKS `encryption_config` with a KMS key and include `secrets` in the encrypted resources."
        ),
        tags=("aws", "eks", "kubernetes", "secrets", "encryption", "kms"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-eks-control-plane-logging-incomplete",
        title="EKS control-plane logging is disabled or incomplete",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Enable EKS control-plane log types `api`, `audit`, and `authenticator`, and route logs to retained "
            "CloudWatch log groups or a centralized logging pipeline."
        ),
        tags=("aws", "eks", "kubernetes", "logging", "audit"),
        severity_factors=("lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-eks-authentication-mode-weak-or-unknown",
        title="EKS authentication mode is weak or unknown",
        category=StrideCategory.SPOOFING,
        recommended_mitigation=(
            "Use the EKS access management API where supported, prefer `API` or `API_AND_CONFIG_MAP`, and review "
            "legacy ConfigMap-only cluster access paths."
        ),
        tags=("aws", "eks", "kubernetes", "authentication", "access-management"),
        severity_factors=("privilege_breadth", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-eks-vpc-cni-network-policy-not-enabled",
        title="EKS VPC CNI network policy is not enabled",
        category=StrideCategory.TAMPERING,
        recommended_mitigation=(
            "Enable VPC CNI network policy support where the cluster relies on AWS VPC CNI for pod-level traffic "
            "controls, and validate compatible EKS, CNI, and node-agent deployment requirements."
        ),
        tags=("aws", "eks", "kubernetes", "network-policy", "vpc-cni"),
        severity_factors=("lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-sensitive-resource-policy-external-access",
        title="Sensitive resource policy allows broad or cross-account access",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Limit resource policies to exact service principals or workload roles, avoid wildcard "
            "foreign-account, and account-root principals where more specific identities are possible, "
            "and require source-account or source-ARN constraints where supported."
        ),
        tags=("aws", "resource-policy", "data"),
        severity_factors=(
            "internet_exposure",
            "privilege_breadth",
            "data_sensitivity",
            "lateral_movement",
            "blast_radius",
        ),
    ),
    RuleMetadata(
        rule_id="aws-service-resource-policy-external-access",
        title="Service resource policy allows broad or cross-account access",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Limit resource policies to exact service principals or workload roles, avoid wildcard "
            "foreign-account, and account-root principals where more specific identities are possible, "
            "and require source-account or source-ARN constraints where supported."
        ),
        tags=("aws", "resource-policy", "service"),
        severity_factors=("internet_exposure", "privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-iam-wildcard-permissions",
        title="IAM policy grants wildcard privileges",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Replace wildcard actions and resources with narrowly scoped permissions tied to the exact "
            "services, APIs, and ARNs required by the workload."
        ),
        tags=("aws", "iam", "permissions"),
        severity_factors=("privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-iam-privileged-role-assignment",
        title="IAM role has privileged assignment posture",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Review high-impact IAM role permissions, split administrative and runtime duties, scope resources "
            "to named ARNs, and avoid attaching broad IAM, role-passing, secrets, KMS, data, network, or audit "
            "administration permissions to general workload roles."
        ),
        tags=("aws", "iam", "privileged-access", "role-assignment"),
        severity_factors=("privilege_breadth", "data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-workload-role-sensitive-permissions",
        title="Workload role carries sensitive permissions",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Split high-privilege actions into separate roles, scope permissions to named resources, "
            "and remove role-passing or cross-role permissions from general application identities."
        ),
        tags=("aws", "iam", "workload"),
        severity_factors=("internet_exposure", "privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-missing-tier-segmentation",
        title="Private data tier directly trusts the public application tier",
        category=StrideCategory.TAMPERING,
        recommended_mitigation=(
            "Introduce tighter tier segmentation with dedicated security groups, narrow ingress to "
            "specific services and ports, and keep the data tier reachable only through controlled application paths."
        ),
        tags=("aws", "network", "segmentation"),
        severity_factors=("internet_exposure", "data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-private-data-transitive-exposure",
        title="Sensitive data tier is transitively reachable from an internet-exposed path",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Keep internet-adjacent entry points from chaining into workloads that retain database or secret access, "
            "narrow edge-to-workload and workload-to-workload trust, and isolate sensitive data access behind more "
            "deliberate service boundaries."
        ),
        tags=("aws", "network", "segmentation", "transitive-path"),
        severity_factors=("data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-control-plane-sensitive-workload-chain",
        title="Broad or cross-account control-plane path can influence a sensitive workload",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Keep external CI or deployment principals away from runtime workload roles, separate deployment "
            "and execution identities, require narrowing conditions on cross-account trust, and avoid giving "
            "data-bearing workloads broad secret or database access where a smaller brokered path would work."
        ),
        tags=("aws", "iam", "control-plane", "transitive-path"),
        severity_factors=("privilege_breadth", "data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-role-trust-expansion",
        title="Role trust relationship expands blast radius",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Limit trust policies to the exact service principals or roles required, prefer role ARNs "
            "over account root where possible, and add conditions such as `ExternalId`, source ARN, "
            "SAML audience, or OIDC audience and subject checks."
        ),
        tags=("aws", "iam", "trust"),
        severity_factors=("privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-role-trust-missing-narrowing",
        title="Cross-account or broad role trust lacks narrowing conditions",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Keep the trusted principal as specific as possible and add supported assume-role "
            "conditions such as `ExternalId`, `SourceArn`, `SourceAccount`, `SAML:aud`, or "
            "provider-specific OIDC `aud` and `sub` checks when crossing accounts or trusting "
            "broad or federated principals."
        ),
        tags=("aws", "iam", "trust", "cross-account"),
        severity_factors=("privilege_breadth", "lateral_movement", "blast_radius"),
    ),
)
