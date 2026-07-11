from __future__ import annotations

import re
import unittest

from tests.helpers.paths import SOURCE_ROOT
from tfstride.models import NormalizedResource, ResourceCategory
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.resource_facts import (
    AwsIamFacts,
    AwsResourceFacts,
    AwsSqlFacts,
    AwsStorageFacts,
    aws_fact_domains,
    aws_facts,
)
from tfstride.providers.resource_facts import (
    NeutralProviderComputeFacts,
    NeutralProviderWorkloadFacts,
)


def _resource(metadata: dict[str, object] | None = None) -> NormalizedResource:
    return NormalizedResource(
        address="aws_ecs_service.app",
        provider="aws",
        resource_type="aws_ecs_service",
        name="app",
        category=ResourceCategory.COMPUTE,
        metadata=metadata,
    )


class AwsResourceFactsTests(unittest.TestCase):
    def test_reads_aws_provider_metadata(self) -> None:
        resource = _resource(
            {
                "cluster": "arn:aws:ecs:us-east-1:111122223333:cluster/app",
                "task_definition": "app:7",
                "task_role_arn": "arn:aws:iam::111122223333:role/task",
                "requires_compatibilities": ["FARGATE"],
                "engine": "postgres",
                "rds_publicly_accessible_state": "enabled",
                "rds_backup_retention_period": 7,
                "rds_deletion_protection_state": "enabled",
                "rds_multi_az_state": "disabled",
                "rds_kms_key_id": "arn:aws:kms:us-east-1:111122223333:key/rds",
                "rds_posture_uncertainties": ["backup_retention_period is unknown after planning"],
                "kms_key_usage": "ENCRYPT_DECRYPT",
                "kms_key_spec": "SYMMETRIC_DEFAULT",
                "kms_customer_master_key_spec": "SYMMETRIC_DEFAULT",
                "kms_enable_key_rotation_state": "enabled",
                "kms_deletion_window_in_days": 30,
                "kms_posture_uncertainties": ["enable_key_rotation is unknown after planning"],
                "trust_statements": [{"Effect": "Allow"}],
                "s3_versioning_status": "Enabled",
                "s3_versioning_source_address": "aws_s3_bucket_versioning.logs",
                "s3_versioning_configuration": {"status": "Enabled"},
                "s3_encryption_algorithm": "aws:kms",
                "s3_kms_master_key_id": "arn:aws:kms:us-east-1:111122223333:key/storage",
                "s3_bucket_key_enabled_state": "enabled",
                "s3_encryption_source_address": "aws_s3_bucket_server_side_encryption_configuration.logs",
                "s3_server_side_encryption_configuration": {"rule": []},
                "s3_posture_uncertainties": ["aws_s3_bucket_versioning.logs: status is unknown"],
                "secrets_manager_kms_key_id": "arn:aws:kms:us-east-1:111122223333:key/secrets",
                "secrets_manager_recovery_window_in_days": 14,
                "secrets_manager_rotation_secret_id": "aws_secretsmanager_secret.app.id",
                "secrets_manager_rotation_source_address": "aws_secretsmanager_secret_rotation.app",
                "secrets_manager_rotation_lambda_arn": ("arn:aws:lambda:us-east-1:111122223333:function:rotate-secret"),
                "secrets_manager_rotation_automatically_after_days": 30,
                "secrets_manager_rotation_duration": "2h",
                "secrets_manager_rotation_schedule_expression": "rate(30 days)",
                "secrets_manager_rotation_rules": {"automatically_after_days": 30},
                "unresolved_secret_references": ["aws_secretsmanager_secret.missing.id"],
                "secrets_manager_replication": [
                    {
                        "region": "us-west-2",
                        "kms_key_id": "arn:aws:kms:us-west-2:111122223333:key/secrets-replica",
                    }
                ],
                "secrets_manager_posture_uncertainties": ["kms_key_id is unknown after planning"],
                "eks_cluster_arn": "arn:aws:eks:us-east-1:111122223333:cluster/app",
                "eks_cluster_role_arn": "arn:aws:iam::111122223333:role/eks-control-plane",
                "eks_kubernetes_version": "1.29",
                "eks_endpoint_public_access_state": "enabled",
                "eks_endpoint_private_access_state": "disabled",
                "eks_public_access_cidrs": ["0.0.0.0/0"],
                "eks_public_access_cidrs_state": "configured",
                "eks_subnet_ids": ["subnet-a", "subnet-b"],
                "eks_security_group_ids": ["sg-client"],
                "eks_cluster_security_group_id": "sg-cluster",
                "eks_vpc_config": {"endpoint_public_access": True},
                "eks_enabled_cluster_log_types": ["api", "audit", "authenticator"],
                "eks_control_plane_logging_state": "configured",
                "eks_encryption_config": [
                    {
                        "key_arn": "arn:aws:kms:us-east-1:111122223333:key/eks",
                        "resources": ["secrets"],
                    }
                ],
                "eks_encryption_config_state": "configured",
                "eks_secrets_encryption_state": "enabled",
                "eks_encryption_key_arn": "arn:aws:kms:us-east-1:111122223333:key/eks",
                "eks_encryption_resources": ["secrets"],
                "eks_access_config_state": "configured",
                "eks_authentication_mode": "API_AND_CONFIG_MAP",
                "eks_bootstrap_cluster_creator_admin_permissions_state": "enabled",
                "eks_access_config": {"authentication_mode": "API_AND_CONFIG_MAP"},
                "eks_addon_name": "vpc-cni",
                "eks_addon_cluster_name": "app",
                "eks_addon_version": "v1.18.1-eksbuild.1",
                "eks_addon_configuration_values": '{"env":{}}',
                "eks_addon_configuration_keys": ["env"],
                "eks_addon_preserve_state": "enabled",
                "eks_addon_service_account_role_arn": "arn:aws:iam::111122223333:role/eks-vpc-cni",
                "eks_addon_target_class": "networking",
                "lambda_function_url": "https://abc.lambda-url.us-east-1.on.aws/",
                "lambda_function_url_authorization_type": "AWS_IAM",
                "lambda_function_url_qualifier": "prod",
                "lambda_function_url_invoke_mode": "BUFFERED",
                "lambda_function_url_cors": {"allow_origins": ["https://example.com"]},
                "lambda_function_url_cors_allow_credentials_state": "enabled",
                "lambda_function_url_cors_allow_headers": ["authorization"],
                "lambda_function_url_cors_allow_methods": ["GET"],
                "lambda_function_url_cors_allow_origins": ["https://example.com"],
                "lambda_function_url_cors_expose_headers": ["x-request-id"],
                "lambda_function_url_cors_max_age": 3600,
                "lambda_function_url_posture_uncertainties": ["authorization_type is unknown after planning"],
                "load_balancer_listener_protocol": "HTTPS",
                "load_balancer_listener_certificate_arn": ("arn:aws:acm:us-east-1:111122223333:certificate/listener"),
                "load_balancer_listener_ssl_policy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
                "load_balancer_listener_tls_uncertainties": ["ssl_policy is unknown after planning"],
                "cloudfront_distribution_id": "E123",
                "cloudfront_distribution_arn": "arn:aws:cloudfront::111122223333:distribution/E123",
                "cloudfront_domain_name": "d111111abcdef8.cloudfront.net",
                "cloudfront_enabled_state": "enabled",
                "cloudfront_ipv6_enabled_state": "disabled",
                "cloudfront_http_version": "http2and3",
                "cloudfront_default_root_object": "index.html",
                "cloudfront_aliases": ["www.example.com"],
                "cloudfront_web_acl_id": "arn:aws:wafv2:us-east-1:111122223333:global/webacl/cdn/abc",
                "cloudfront_default_cache_behavior": {
                    "target_origin_id": "app",
                    "viewer_protocol_policy": "redirect-to-https",
                    "cache_policy_id": "managed-cache",
                    "allowed_methods": ["GET", "HEAD", "OPTIONS"],
                    "cached_methods": ["GET", "HEAD"],
                },
                "cloudfront_default_viewer_protocol_policy": "redirect-to-https",
                "cloudfront_default_allowed_methods": ["GET", "HEAD", "OPTIONS"],
                "cloudfront_default_cached_methods": ["GET", "HEAD"],
                "cloudfront_ordered_cache_behaviors": [
                    {"path_pattern": "/api/*", "viewer_protocol_policy": "https-only"}
                ],
                "cloudfront_ordered_viewer_protocol_policies": ["https-only"],
                "cloudfront_origins": [{"origin_id": "app", "domain_name": "app.example.com"}],
                "cloudfront_origin_ids": ["app"],
                "cloudfront_origin_domain_names": ["app.example.com"],
                "cloudfront_viewer_certificate": {
                    "certificate_source": "acm",
                    "cloudfront_default_certificate_state": "disabled",
                    "acm_certificate_arn": "arn:aws:acm:us-east-1:111122223333:certificate/cdn",
                    "minimum_protocol_version": "TLSv1.2_2021",
                    "ssl_support_method": "sni-only",
                },
                "cloudfront_viewer_certificate_source": "acm",
                "cloudfront_default_certificate_state": "disabled",
                "cloudfront_minimum_protocol_version": "TLSv1.2_2021",
                "cloudfront_ssl_support_method": "sni-only",
                "cloudfront_acm_certificate_arn": "arn:aws:acm:us-east-1:111122223333:certificate/cdn",
                "cloudfront_logging_state": "configured",
                "cloudfront_logging_config": {
                    "bucket_name": "logs.s3.amazonaws.com",
                    "prefix": "cloudfront/",
                    "include_cookies": False,
                },
                "cloudfront_logging_bucket": "logs.s3.amazonaws.com",
                "cloudfront_logging_prefix": "cloudfront/",
                "cloudfront_posture_uncertainties": [
                    "viewer_certificate.minimum_protocol_version is unknown after planning"
                ],
                "web_acl_id": "app/abc",
                "web_acl_name": "app-edge",
                "web_acl_arn": "arn:aws:wafv2:us-east-1:111122223333:regional/webacl/app/abc",
                "web_acl_scope": "REGIONAL",
                "web_acl_default_action": "allow",
                "web_acl_default_action_evidence": {"allow": [{}]},
                "web_acl_rules": [{"name": "aws-managed-common", "priority": 1}],
                "web_acl_rule_names": ["aws-managed-common"],
                "web_acl_association_resource_arn": (
                    "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/web/abc"
                ),
                "web_acl_association_web_acl_arn": ("arn:aws:wafv2:us-east-1:111122223333:regional/webacl/app/abc"),
                "edge_protection_posture_uncertainties": ["web_acl_arn is unknown after planning"],
                "audit_detection_posture_uncertainties": ["enable_logging is unknown after planning"],
                "privileged_access_grants": [
                    {
                        "provider": "aws",
                        "principal_type": "role",
                        "principal_identifier": "arn:aws:iam::111122223333:role/app",
                        "principal_display_name": "aws_iam_role.app",
                        "principal_source_address": "aws_iam_role.app",
                        "scope_kind": "account",
                        "scope_value": "*",
                        "scope_source_address": None,
                        "privilege_categories": ["full-admin"],
                        "confidence": "high",
                        "assignment_source_address": "aws_iam_role.app",
                        "role_name": "app",
                        "role_id": "arn:aws:iam::111122223333:role/app",
                        "permission_patterns": ["*"],
                        "evidence": ["action=*", "resource=*"],
                        "uncertainties": [],
                    }
                ],
                "iam_assignment_posture_uncertainties": ["arn:aws:iam::111122223333:policy/pending"],
                "cloudtrail_s3_bucket_name": "audit-logs",
                "cloudtrail_s3_key_prefix": "cloudtrail",
                "cloudtrail_kms_key_id": "arn:aws:kms:us-east-1:111122223333:key/audit",
                "cloudtrail_cloudwatch_logs_group_arn": (
                    "arn:aws:logs:us-east-1:111122223333:log-group:/aws/cloudtrail"
                ),
                "cloudtrail_cloudwatch_logs_role_arn": "arn:aws:iam::111122223333:role/cloudtrail-logs",
                "cloudtrail_enable_logging_state": "enabled",
                "cloudtrail_log_file_validation_state": "enabled",
                "cloudtrail_multi_region_state": "enabled",
                "cloudtrail_global_service_events_state": "enabled",
                "cloudtrail_organization_trail_state": "disabled",
                "cloudtrail_event_selectors": [{"read_write_type": "All"}],
                "cloudtrail_insight_selectors": ["ApiCallRateInsight"],
                "guardduty_enable_state": "enabled",
                "guardduty_finding_publishing_frequency": "FIFTEEN_MINUTES",
                "guardduty_datasources": {"s3_logs": [{"enable": True}]},
                "guardduty_features": [{"name": "EKS_AUDIT_LOGS", "status": "ENABLED"}],
                "securityhub_enable_default_standards_state": "disabled",
                "securityhub_auto_enable_controls_state": "enabled",
                "securityhub_control_finding_generator": "SECURITY_CONTROL",
                "config_recorder_name": "default",
                "config_recorder_role_arn": "arn:aws:iam::111122223333:role/config",
                "config_recorder_all_supported_state": "enabled",
                "config_recorder_include_global_resource_types_state": "enabled",
                "config_recorder_resource_types": ["AWS::S3::Bucket"],
                "config_recorder_recording_strategy_use_only": "ALL_SUPPORTED_RESOURCE_TYPES",
                "config_recorder_recording_group": {"all_supported": True},
                "config_recorder_recording_strategy": {"use_only": "ALL_SUPPORTED_RESOURCE_TYPES"},
                "vpc_endpoint_id": "vpce-secrets",
                "vpc_endpoint_service_name": "com.amazonaws.us-east-1.secretsmanager",
                "vpc_endpoint_service_family": "secretsmanager",
                "vpc_endpoint_type": "Interface",
                "vpc_endpoint_vpc_id": "vpc-123",
                "vpc_endpoint_route_table_ids": ["rtb-private"],
                "vpc_endpoint_subnet_ids": ["subnet-a", "subnet-b"],
                "vpc_endpoint_security_group_ids": ["sg-endpoint"],
                "vpc_endpoint_private_dns_enabled_state": "enabled",
                "vpc_endpoint_policy_document": {"Statement": [{"Effect": "Allow"}]},
                "vpc_endpoint_dns_entries": [
                    {
                        "dns_name": "vpce-secrets-abc.secretsmanager.us-east-1.vpce.amazonaws.com",
                        "hosted_zone_id": "Z1HUB23UULQXV",
                    }
                ],
                "vpc_endpoint_dns_names": ["vpce-secrets-abc.secretsmanager.us-east-1.vpce.amazonaws.com"],
                "vpc_endpoint_posture_uncertainties": ["private_dns_enabled is unknown after planning"],
                "flow_log_id": "fl-123",
                "flow_log_target_type": "vpc",
                "flow_log_target_id": "vpc-123",
                "flow_log_traffic_type": "ALL",
                "flow_log_destination_type": "cloud-watch-logs",
                "flow_log_destination": "arn:aws:logs:us-east-1:111122223333:log-group:/aws/vpc-flow-logs",
                "flow_log_log_group_name": "/aws/vpc-flow-logs",
                "flow_log_iam_role_arn": "arn:aws:iam::111122223333:role/vpc-flow-logs",
                "flow_log_max_aggregation_interval": 60,
                "flow_log_destination_options": {"file_format": "plain-text"},
                "flow_log_posture_uncertainties": ["traffic_type is unknown after planning"],
                "eks_posture_uncertainties": ["vpc_config.endpoint_public_access is unknown after planning"],
            }
        )

        facts = aws_facts(resource)

        self.assertIsInstance(facts, AwsResourceFacts)
        self.assertEqual(facts.cluster_reference, "arn:aws:ecs:us-east-1:111122223333:cluster/app")
        self.assertEqual(facts.task_definition_reference, "app:7")
        self.assertEqual(facts.task_role_arn, "arn:aws:iam::111122223333:role/task")
        self.assertEqual(facts.requires_compatibilities, ["FARGATE"])
        self.assertEqual(facts.engine, "postgres")
        self.assertEqual(facts.rds_publicly_accessible_state, "enabled")
        self.assertTrue(facts.rds_publicly_accessible)
        self.assertEqual(facts.rds_backup_retention_period, 7)
        self.assertEqual(facts.rds_deletion_protection_state, "enabled")
        self.assertTrue(facts.rds_deletion_protection)
        self.assertEqual(facts.rds_multi_az_state, "disabled")
        self.assertFalse(facts.rds_multi_az)
        self.assertEqual(facts.rds_kms_key_id, "arn:aws:kms:us-east-1:111122223333:key/rds")
        self.assertEqual(facts.rds_posture_uncertainties, ["backup_retention_period is unknown after planning"])
        self.assertEqual(facts.kms_key_usage, "ENCRYPT_DECRYPT")
        self.assertEqual(facts.kms_key_spec, "SYMMETRIC_DEFAULT")
        self.assertEqual(facts.kms_customer_master_key_spec, "SYMMETRIC_DEFAULT")
        self.assertEqual(facts.kms_enable_key_rotation_state, "enabled")
        self.assertTrue(facts.kms_enable_key_rotation)
        self.assertEqual(facts.kms_deletion_window_in_days, 30)
        self.assertEqual(facts.kms_posture_uncertainties, ["enable_key_rotation is unknown after planning"])
        self.assertEqual(facts.trust_statements, [{"Effect": "Allow"}])
        self.assertEqual(facts.s3_versioning_status, "Enabled")
        self.assertTrue(facts.s3_versioning_enabled)
        self.assertEqual(facts.s3_versioning_source_address, "aws_s3_bucket_versioning.logs")
        self.assertEqual(facts.s3_versioning_configuration, {"status": "Enabled"})
        self.assertEqual(facts.s3_encryption_algorithm, "aws:kms")
        self.assertEqual(facts.s3_kms_master_key_id, "arn:aws:kms:us-east-1:111122223333:key/storage")
        self.assertEqual(facts.s3_bucket_key_enabled_state, "enabled")
        self.assertTrue(facts.s3_bucket_key_enabled)
        self.assertEqual(
            facts.s3_encryption_source_address,
            "aws_s3_bucket_server_side_encryption_configuration.logs",
        )
        self.assertEqual(facts.s3_server_side_encryption_configuration, {"rule": []})
        self.assertEqual(facts.s3_posture_uncertainties, ["aws_s3_bucket_versioning.logs: status is unknown"])
        self.assertEqual(facts.secrets_manager_kms_key_id, "arn:aws:kms:us-east-1:111122223333:key/secrets")
        self.assertEqual(facts.secrets_manager_recovery_window_in_days, 14)
        self.assertEqual(facts.secrets_manager_rotation_secret_id, "aws_secretsmanager_secret.app.id")
        self.assertEqual(facts.secrets_manager_rotation_source_address, "aws_secretsmanager_secret_rotation.app")
        self.assertEqual(
            facts.secrets_manager_rotation_lambda_arn,
            "arn:aws:lambda:us-east-1:111122223333:function:rotate-secret",
        )
        self.assertEqual(facts.secrets_manager_rotation_automatically_after_days, 30)
        self.assertEqual(facts.secrets_manager_rotation_duration, "2h")
        self.assertEqual(facts.secrets_manager_rotation_schedule_expression, "rate(30 days)")
        self.assertEqual(facts.secrets_manager_rotation_rules, {"automatically_after_days": 30})
        self.assertEqual(facts.unresolved_secret_references, ["aws_secretsmanager_secret.missing.id"])
        self.assertEqual(
            facts.secrets_manager_replication,
            [
                {
                    "region": "us-west-2",
                    "kms_key_id": "arn:aws:kms:us-west-2:111122223333:key/secrets-replica",
                }
            ],
        )
        self.assertEqual(facts.secrets_manager_posture_uncertainties, ["kms_key_id is unknown after planning"])
        self.assertEqual(facts.eks_cluster_arn, "arn:aws:eks:us-east-1:111122223333:cluster/app")
        self.assertEqual(facts.eks_cluster_role_arn, "arn:aws:iam::111122223333:role/eks-control-plane")
        self.assertEqual(facts.eks_kubernetes_version, "1.29")
        self.assertEqual(facts.eks_endpoint_public_access_state, "enabled")
        self.assertEqual(facts.eks_endpoint_private_access_state, "disabled")
        self.assertEqual(facts.eks_public_access_cidrs, ["0.0.0.0/0"])
        self.assertEqual(facts.eks_public_access_cidrs_state, "configured")
        self.assertEqual(facts.eks_subnet_ids, ["subnet-a", "subnet-b"])
        self.assertEqual(facts.eks_security_group_ids, ["sg-client"])
        self.assertEqual(facts.eks_cluster_security_group_id, "sg-cluster")
        self.assertEqual(facts.eks_vpc_config, {"endpoint_public_access": True})
        self.assertEqual(facts.eks_enabled_cluster_log_types, ["api", "audit", "authenticator"])
        self.assertEqual(facts.eks_control_plane_logging_state, "configured")
        self.assertEqual(
            facts.eks_encryption_config,
            [{"key_arn": "arn:aws:kms:us-east-1:111122223333:key/eks", "resources": ["secrets"]}],
        )
        self.assertEqual(facts.eks_encryption_config_state, "configured")
        self.assertEqual(facts.eks_secrets_encryption_state, "enabled")
        self.assertEqual(facts.eks_encryption_key_arn, "arn:aws:kms:us-east-1:111122223333:key/eks")
        self.assertEqual(facts.eks_encryption_resources, ["secrets"])
        self.assertEqual(facts.eks_access_config_state, "configured")
        self.assertEqual(facts.eks_authentication_mode, "API_AND_CONFIG_MAP")
        self.assertEqual(facts.eks_bootstrap_cluster_creator_admin_permissions_state, "enabled")
        self.assertEqual(facts.eks_access_config, {"authentication_mode": "API_AND_CONFIG_MAP"})
        self.assertEqual(facts.eks_addon_name, "vpc-cni")
        self.assertEqual(facts.eks_addon_cluster_name, "app")
        self.assertEqual(facts.eks_addon_version, "v1.18.1-eksbuild.1")
        self.assertEqual(facts.eks_addon_configuration_values, '{"env":{}}')
        self.assertEqual(facts.eks_addon_configuration_keys, ["env"])
        self.assertEqual(facts.eks_addon_preserve_state, "enabled")
        self.assertTrue(facts.eks_addon_preserve)
        self.assertEqual(facts.eks_addon_service_account_role_arn, "arn:aws:iam::111122223333:role/eks-vpc-cni")
        self.assertEqual(facts.eks_addon_target_class, "networking")
        self.assertEqual(facts.lambda_function_url, "https://abc.lambda-url.us-east-1.on.aws/")
        self.assertEqual(facts.lambda_function_url_authorization_type, "AWS_IAM")
        self.assertEqual(facts.lambda_function_url_qualifier, "prod")
        self.assertEqual(facts.lambda_function_url_invoke_mode, "BUFFERED")
        self.assertEqual(facts.lambda_function_url_cors, {"allow_origins": ["https://example.com"]})
        self.assertEqual(facts.lambda_function_url_cors_allow_credentials_state, "enabled")
        self.assertTrue(facts.lambda_function_url_cors_allow_credentials)
        self.assertEqual(facts.lambda_function_url_cors_allow_headers, ["authorization"])
        self.assertEqual(facts.lambda_function_url_cors_allow_methods, ["GET"])
        self.assertEqual(facts.lambda_function_url_cors_allow_origins, ["https://example.com"])
        self.assertEqual(facts.lambda_function_url_cors_expose_headers, ["x-request-id"])
        self.assertEqual(facts.lambda_function_url_cors_max_age, 3600)
        self.assertEqual(
            facts.lambda_function_url_posture_uncertainties,
            ["authorization_type is unknown after planning"],
        )
        self.assertEqual(facts.load_balancer_listener_protocol, "HTTPS")
        self.assertEqual(
            facts.load_balancer_listener_certificate_arn,
            "arn:aws:acm:us-east-1:111122223333:certificate/listener",
        )
        self.assertEqual(facts.load_balancer_listener_ssl_policy, "ELBSecurityPolicy-TLS13-1-2-2021-06")
        self.assertEqual(
            facts.load_balancer_listener_tls_uncertainties,
            ["ssl_policy is unknown after planning"],
        )
        self.assertEqual(facts.cloudfront_distribution_id, "E123")
        self.assertEqual(facts.cloudfront_distribution_arn, "arn:aws:cloudfront::111122223333:distribution/E123")
        self.assertEqual(facts.cloudfront_domain_name, "d111111abcdef8.cloudfront.net")
        self.assertEqual(facts.cloudfront_enabled_state, "enabled")
        self.assertTrue(facts.cloudfront_enabled)
        self.assertEqual(facts.cloudfront_ipv6_enabled_state, "disabled")
        self.assertFalse(facts.cloudfront_ipv6_enabled)
        self.assertEqual(facts.cloudfront_http_version, "http2and3")
        self.assertEqual(facts.cloudfront_default_root_object, "index.html")
        self.assertEqual(facts.cloudfront_aliases, ["www.example.com"])
        self.assertEqual(facts.cloudfront_web_acl_id, "arn:aws:wafv2:us-east-1:111122223333:global/webacl/cdn/abc")
        self.assertEqual(
            facts.cloudfront_default_cache_behavior,
            {
                "target_origin_id": "app",
                "viewer_protocol_policy": "redirect-to-https",
                "cache_policy_id": "managed-cache",
                "allowed_methods": ["GET", "HEAD", "OPTIONS"],
                "cached_methods": ["GET", "HEAD"],
            },
        )
        self.assertEqual(facts.cloudfront_default_viewer_protocol_policy, "redirect-to-https")
        self.assertEqual(facts.cloudfront_default_allowed_methods, ["GET", "HEAD", "OPTIONS"])
        self.assertEqual(facts.cloudfront_default_cached_methods, ["GET", "HEAD"])
        self.assertEqual(
            facts.cloudfront_ordered_cache_behaviors,
            [{"path_pattern": "/api/*", "viewer_protocol_policy": "https-only"}],
        )
        self.assertEqual(facts.cloudfront_ordered_viewer_protocol_policies, ["https-only"])
        self.assertEqual(facts.cloudfront_origins, [{"origin_id": "app", "domain_name": "app.example.com"}])
        self.assertEqual(facts.cloudfront_origin_ids, ["app"])
        self.assertEqual(facts.cloudfront_origin_domain_names, ["app.example.com"])
        self.assertEqual(
            facts.cloudfront_viewer_certificate,
            {
                "certificate_source": "acm",
                "cloudfront_default_certificate_state": "disabled",
                "acm_certificate_arn": "arn:aws:acm:us-east-1:111122223333:certificate/cdn",
                "minimum_protocol_version": "TLSv1.2_2021",
                "ssl_support_method": "sni-only",
            },
        )
        self.assertEqual(facts.cloudfront_viewer_certificate_source, "acm")
        self.assertEqual(facts.cloudfront_default_certificate_state, "disabled")
        self.assertFalse(facts.cloudfront_default_certificate)
        self.assertEqual(facts.cloudfront_minimum_protocol_version, "TLSv1.2_2021")
        self.assertEqual(facts.cloudfront_ssl_support_method, "sni-only")
        self.assertEqual(facts.cloudfront_acm_certificate_arn, "arn:aws:acm:us-east-1:111122223333:certificate/cdn")
        self.assertIsNone(facts.cloudfront_iam_certificate_id)
        self.assertEqual(facts.cloudfront_logging_state, "configured")
        self.assertEqual(
            facts.cloudfront_logging_config,
            {"bucket_name": "logs.s3.amazonaws.com", "prefix": "cloudfront/", "include_cookies": False},
        )
        self.assertEqual(facts.cloudfront_logging_bucket, "logs.s3.amazonaws.com")
        self.assertEqual(facts.cloudfront_logging_prefix, "cloudfront/")
        self.assertEqual(
            facts.cloudfront_posture_uncertainties,
            ["viewer_certificate.minimum_protocol_version is unknown after planning"],
        )
        self.assertEqual(facts.web_acl_id, "app/abc")
        self.assertEqual(facts.web_acl_name, "app-edge")
        self.assertEqual(facts.web_acl_arn, "arn:aws:wafv2:us-east-1:111122223333:regional/webacl/app/abc")
        self.assertEqual(facts.web_acl_scope, "REGIONAL")
        self.assertEqual(facts.web_acl_default_action, "allow")
        self.assertEqual(facts.web_acl_default_action_evidence, {"allow": [{}]})
        self.assertEqual(facts.web_acl_rules, [{"name": "aws-managed-common", "priority": 1}])
        self.assertEqual(facts.web_acl_rule_names, ["aws-managed-common"])
        self.assertEqual(
            facts.web_acl_association_resource_arn,
            "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/web/abc",
        )
        self.assertEqual(
            facts.web_acl_association_web_acl_arn,
            "arn:aws:wafv2:us-east-1:111122223333:regional/webacl/app/abc",
        )
        self.assertEqual(facts.edge_protection_posture_uncertainties, ["web_acl_arn is unknown after planning"])
        self.assertEqual(facts.audit_detection_posture_uncertainties, ["enable_logging is unknown after planning"])
        self.assertEqual(len(facts.privileged_access_grants), 1)
        self.assertEqual(facts.privileged_access_grants[0].privilege_categories[0].value, "full-admin")
        self.assertEqual(
            facts.iam_assignment_posture_uncertainties,
            ["arn:aws:iam::111122223333:policy/pending"],
        )
        self.assertEqual(facts.privileged_access_posture.provider, "aws")
        self.assertEqual(
            facts.privileged_access_posture.unresolved_assignments,
            ("arn:aws:iam::111122223333:policy/pending",),
        )
        self.assertEqual(facts.cloudtrail_s3_bucket_name, "audit-logs")
        self.assertEqual(facts.cloudtrail_s3_key_prefix, "cloudtrail")
        self.assertEqual(facts.cloudtrail_kms_key_id, "arn:aws:kms:us-east-1:111122223333:key/audit")
        self.assertEqual(
            facts.cloudtrail_cloudwatch_logs_group_arn,
            "arn:aws:logs:us-east-1:111122223333:log-group:/aws/cloudtrail",
        )
        self.assertEqual(facts.cloudtrail_cloudwatch_logs_role_arn, "arn:aws:iam::111122223333:role/cloudtrail-logs")
        self.assertEqual(facts.cloudtrail_enable_logging_state, "enabled")
        self.assertTrue(facts.cloudtrail_enable_logging)
        self.assertEqual(facts.cloudtrail_log_file_validation_state, "enabled")
        self.assertTrue(facts.cloudtrail_log_file_validation_enabled)
        self.assertEqual(facts.cloudtrail_multi_region_state, "enabled")
        self.assertTrue(facts.cloudtrail_multi_region)
        self.assertEqual(facts.cloudtrail_global_service_events_state, "enabled")
        self.assertTrue(facts.cloudtrail_global_service_events)
        self.assertEqual(facts.cloudtrail_organization_trail_state, "disabled")
        self.assertFalse(facts.cloudtrail_organization_trail)
        self.assertEqual(facts.cloudtrail_event_selectors, [{"read_write_type": "All"}])
        self.assertEqual(facts.cloudtrail_insight_selectors, ["ApiCallRateInsight"])
        self.assertEqual(facts.guardduty_enable_state, "enabled")
        self.assertTrue(facts.guardduty_enabled)
        self.assertEqual(facts.guardduty_finding_publishing_frequency, "FIFTEEN_MINUTES")
        self.assertEqual(facts.guardduty_datasources, {"s3_logs": [{"enable": True}]})
        self.assertEqual(facts.guardduty_features, [{"name": "EKS_AUDIT_LOGS", "status": "ENABLED"}])
        self.assertEqual(facts.securityhub_enable_default_standards_state, "disabled")
        self.assertFalse(facts.securityhub_enable_default_standards)
        self.assertEqual(facts.securityhub_auto_enable_controls_state, "enabled")
        self.assertTrue(facts.securityhub_auto_enable_controls)
        self.assertEqual(facts.securityhub_control_finding_generator, "SECURITY_CONTROL")
        self.assertEqual(facts.config_recorder_name, "default")
        self.assertEqual(facts.config_recorder_role_arn, "arn:aws:iam::111122223333:role/config")
        self.assertEqual(facts.config_recorder_all_supported_state, "enabled")
        self.assertTrue(facts.config_recorder_all_supported)
        self.assertEqual(facts.config_recorder_include_global_resource_types_state, "enabled")
        self.assertTrue(facts.config_recorder_include_global_resource_types)
        self.assertEqual(facts.config_recorder_resource_types, ["AWS::S3::Bucket"])
        self.assertEqual(facts.config_recorder_recording_strategy_use_only, "ALL_SUPPORTED_RESOURCE_TYPES")
        self.assertEqual(facts.config_recorder_recording_group, {"all_supported": True})
        self.assertEqual(facts.config_recorder_recording_strategy, {"use_only": "ALL_SUPPORTED_RESOURCE_TYPES"})
        self.assertEqual(facts.vpc_endpoint_id, "vpce-secrets")
        self.assertEqual(facts.vpc_endpoint_service_name, "com.amazonaws.us-east-1.secretsmanager")
        self.assertEqual(facts.vpc_endpoint_service_family, "secretsmanager")
        self.assertEqual(facts.vpc_endpoint_type, "Interface")
        self.assertEqual(facts.vpc_endpoint_vpc_id, "vpc-123")
        self.assertEqual(facts.vpc_endpoint_route_table_ids, ["rtb-private"])
        self.assertEqual(facts.vpc_endpoint_subnet_ids, ["subnet-a", "subnet-b"])
        self.assertEqual(facts.vpc_endpoint_security_group_ids, ["sg-endpoint"])
        self.assertEqual(facts.vpc_endpoint_private_dns_enabled_state, "enabled")
        self.assertTrue(facts.vpc_endpoint_private_dns_enabled)
        self.assertEqual(facts.vpc_endpoint_policy_document, {"Statement": [{"Effect": "Allow"}]})
        self.assertEqual(
            facts.vpc_endpoint_dns_entries,
            [
                {
                    "dns_name": "vpce-secrets-abc.secretsmanager.us-east-1.vpce.amazonaws.com",
                    "hosted_zone_id": "Z1HUB23UULQXV",
                }
            ],
        )
        self.assertEqual(
            facts.vpc_endpoint_dns_names,
            ["vpce-secrets-abc.secretsmanager.us-east-1.vpce.amazonaws.com"],
        )
        self.assertEqual(facts.vpc_endpoint_posture_uncertainties, ["private_dns_enabled is unknown after planning"])
        self.assertEqual(facts.flow_log_id, "fl-123")
        self.assertEqual(facts.flow_log_target_type, "vpc")
        self.assertEqual(facts.flow_log_target_id, "vpc-123")
        self.assertEqual(facts.flow_log_traffic_type, "ALL")
        self.assertEqual(facts.flow_log_destination_type, "cloud-watch-logs")
        self.assertEqual(
            facts.flow_log_destination,
            "arn:aws:logs:us-east-1:111122223333:log-group:/aws/vpc-flow-logs",
        )
        self.assertEqual(facts.flow_log_log_group_name, "/aws/vpc-flow-logs")
        self.assertEqual(facts.flow_log_iam_role_arn, "arn:aws:iam::111122223333:role/vpc-flow-logs")
        self.assertEqual(facts.flow_log_max_aggregation_interval, 60)
        self.assertEqual(facts.flow_log_destination_options, {"file_format": "plain-text"})
        self.assertEqual(facts.flow_log_posture_uncertainties, ["traffic_type is unknown after planning"])
        self.assertEqual(
            facts.eks_posture_uncertainties,
            ["vpc_config.endpoint_public_access is unknown after planning"],
        )

    def test_writes_aws_provider_metadata_through_resource_fields(self) -> None:
        resource = _resource()
        facts = aws_facts(resource)

        facts.set_network_mode("awsvpc")
        facts.set_task_role_arn("arn:aws:iam::111122223333:role/task")
        facts.add_unresolved_task_definition_reference("app:7")
        facts.add_unresolved_task_definition_reference("app:7")
        facts.add_public_exposure_reason("service is internet-facing")
        facts.set_s3_versioning_posture(
            status="Suspended",
            configuration={"status": "Suspended"},
            source_address="aws_s3_bucket_versioning.logs",
        )
        facts.set_s3_encryption_posture(
            algorithm="AES256",
            kms_master_key_id=None,
            bucket_key_enabled_state="disabled",
            configuration={"rule": []},
            source_address="aws_s3_bucket_server_side_encryption_configuration.logs",
        )
        facts.extend_s3_posture_uncertainties(["status is unknown", "status is unknown"])
        facts.set_secrets_manager_rotation_posture(
            secret_id="aws_secretsmanager_secret.app.id",
            source_address="aws_secretsmanager_secret_rotation.app",
            rotation_lambda_arn="arn:aws:lambda:us-east-1:111122223333:function:rotate-secret",
            automatically_after_days=30,
            duration="2h",
            schedule_expression="rate(30 days)",
            rotation_rules={"automatically_after_days": 30},
        )
        facts.extend_secrets_manager_posture_uncertainties(["rotation_rules is unknown", "rotation_rules is unknown"])
        facts.add_unresolved_secret_reference("aws_secretsmanager_secret.missing.id")

        self.assertEqual(facts.network_mode, "awsvpc")
        self.assertEqual(facts.task_role_arn, "arn:aws:iam::111122223333:role/task")
        self.assertEqual(
            resource.get_metadata_field(AwsResourceMetadata.UNRESOLVED_TASK_DEFINITION_REFERENCES),
            ["app:7"],
        )
        self.assertEqual(resource.public_exposure_reasons, ["service is internet-facing"])
        self.assertEqual(facts.s3_versioning_status, "Suspended")
        self.assertFalse(facts.s3_versioning_enabled)
        self.assertEqual(facts.s3_versioning_source_address, "aws_s3_bucket_versioning.logs")
        self.assertEqual(facts.s3_versioning_configuration, {"status": "Suspended"})
        self.assertEqual(facts.s3_encryption_algorithm, "AES256")
        self.assertIsNone(facts.s3_kms_master_key_id)
        self.assertEqual(facts.s3_bucket_key_enabled_state, "disabled")
        self.assertFalse(facts.s3_bucket_key_enabled)
        self.assertEqual(
            facts.s3_encryption_source_address,
            "aws_s3_bucket_server_side_encryption_configuration.logs",
        )
        self.assertEqual(facts.s3_server_side_encryption_configuration, {"rule": []})
        self.assertEqual(facts.s3_posture_uncertainties, ["status is unknown"])
        self.assertEqual(facts.secrets_manager_rotation_secret_id, "aws_secretsmanager_secret.app.id")
        self.assertEqual(facts.secrets_manager_rotation_source_address, "aws_secretsmanager_secret_rotation.app")
        self.assertEqual(
            facts.secrets_manager_rotation_lambda_arn,
            "arn:aws:lambda:us-east-1:111122223333:function:rotate-secret",
        )
        self.assertEqual(facts.secrets_manager_rotation_automatically_after_days, 30)
        self.assertEqual(facts.secrets_manager_rotation_duration, "2h")
        self.assertEqual(facts.secrets_manager_rotation_schedule_expression, "rate(30 days)")
        self.assertEqual(facts.secrets_manager_rotation_rules, {"automatically_after_days": 30})
        self.assertEqual(facts.secrets_manager_posture_uncertainties, ["rotation_rules is unknown"])
        self.assertEqual(facts.unresolved_secret_references, ["aws_secretsmanager_secret.missing.id"])
        self.assertFalse(hasattr(resource, "task_role_arn"))

    def test_s3_posture_facts_default_to_missing_when_not_modeled(self) -> None:
        facts = aws_facts(_resource())

        self.assertIsNone(facts.s3_versioning_status)
        self.assertIsNone(facts.s3_versioning_enabled)
        self.assertIsNone(facts.s3_versioning_source_address)
        self.assertEqual(facts.s3_versioning_configuration, {})
        self.assertIsNone(facts.s3_encryption_algorithm)
        self.assertIsNone(facts.s3_kms_master_key_id)
        self.assertIsNone(facts.s3_bucket_key_enabled_state)
        self.assertIsNone(facts.s3_bucket_key_enabled)
        self.assertIsNone(facts.s3_encryption_source_address)
        self.assertEqual(facts.s3_server_side_encryption_configuration, {})
        self.assertEqual(facts.s3_posture_uncertainties, [])
        self.assertIsNone(facts.secrets_manager_kms_key_id)
        self.assertIsNone(facts.secrets_manager_recovery_window_in_days)
        self.assertEqual(facts.secrets_manager_replication, [])
        self.assertIsNone(facts.secrets_manager_rotation_secret_id)
        self.assertIsNone(facts.secrets_manager_rotation_source_address)
        self.assertIsNone(facts.secrets_manager_rotation_lambda_arn)
        self.assertIsNone(facts.secrets_manager_rotation_automatically_after_days)
        self.assertIsNone(facts.secrets_manager_rotation_duration)
        self.assertIsNone(facts.secrets_manager_rotation_schedule_expression)
        self.assertEqual(facts.secrets_manager_rotation_rules, {})
        self.assertEqual(facts.unresolved_secret_references, [])
        self.assertEqual(facts.secrets_manager_posture_uncertainties, [])
        self.assertIsNone(facts.eks_cluster_arn)
        self.assertIsNone(facts.eks_cluster_role_arn)
        self.assertIsNone(facts.eks_kubernetes_version)
        self.assertIsNone(facts.eks_endpoint_public_access_state)
        self.assertIsNone(facts.eks_endpoint_private_access_state)
        self.assertEqual(facts.eks_public_access_cidrs, [])
        self.assertIsNone(facts.eks_public_access_cidrs_state)
        self.assertEqual(facts.eks_subnet_ids, [])
        self.assertEqual(facts.eks_security_group_ids, [])
        self.assertIsNone(facts.eks_cluster_security_group_id)
        self.assertEqual(facts.eks_vpc_config, {})
        self.assertEqual(facts.eks_enabled_cluster_log_types, [])
        self.assertIsNone(facts.eks_control_plane_logging_state)
        self.assertEqual(facts.eks_encryption_config, [])
        self.assertIsNone(facts.eks_encryption_config_state)
        self.assertIsNone(facts.eks_secrets_encryption_state)
        self.assertIsNone(facts.eks_encryption_key_arn)
        self.assertEqual(facts.eks_encryption_resources, [])
        self.assertIsNone(facts.eks_access_config_state)
        self.assertIsNone(facts.eks_authentication_mode)
        self.assertIsNone(facts.eks_bootstrap_cluster_creator_admin_permissions_state)
        self.assertEqual(facts.eks_access_config, {})
        self.assertIsNone(facts.eks_addon_name)
        self.assertIsNone(facts.eks_addon_cluster_name)
        self.assertIsNone(facts.eks_addon_version)
        self.assertIsNone(facts.eks_addon_configuration_values)
        self.assertEqual(facts.eks_addon_configuration_keys, [])
        self.assertIsNone(facts.eks_addon_preserve_state)
        self.assertIsNone(facts.eks_addon_preserve)
        self.assertIsNone(facts.eks_addon_service_account_role_arn)
        self.assertIsNone(facts.eks_addon_target_class)
        self.assertIsNone(facts.lambda_function_url)
        self.assertIsNone(facts.lambda_function_url_authorization_type)
        self.assertIsNone(facts.lambda_function_url_qualifier)
        self.assertIsNone(facts.lambda_function_url_invoke_mode)
        self.assertEqual(facts.lambda_function_url_cors, {})
        self.assertIsNone(facts.lambda_function_url_cors_allow_credentials_state)
        self.assertIsNone(facts.lambda_function_url_cors_allow_credentials)
        self.assertEqual(facts.lambda_function_url_cors_allow_headers, [])
        self.assertEqual(facts.lambda_function_url_cors_allow_methods, [])
        self.assertEqual(facts.lambda_function_url_cors_allow_origins, [])
        self.assertEqual(facts.lambda_function_url_cors_expose_headers, [])
        self.assertIsNone(facts.lambda_function_url_cors_max_age)
        self.assertEqual(facts.lambda_function_url_posture_uncertainties, [])
        self.assertIsNone(facts.load_balancer_listener_protocol)
        self.assertIsNone(facts.load_balancer_listener_certificate_arn)
        self.assertIsNone(facts.load_balancer_listener_ssl_policy)
        self.assertEqual(facts.load_balancer_listener_tls_uncertainties, [])
        self.assertIsNone(facts.cloudfront_distribution_id)
        self.assertIsNone(facts.cloudfront_distribution_arn)
        self.assertIsNone(facts.cloudfront_domain_name)
        self.assertIsNone(facts.cloudfront_enabled_state)
        self.assertIsNone(facts.cloudfront_enabled)
        self.assertIsNone(facts.cloudfront_ipv6_enabled_state)
        self.assertIsNone(facts.cloudfront_ipv6_enabled)
        self.assertIsNone(facts.cloudfront_http_version)
        self.assertIsNone(facts.cloudfront_default_root_object)
        self.assertEqual(facts.cloudfront_aliases, [])
        self.assertIsNone(facts.cloudfront_web_acl_id)
        self.assertEqual(facts.cloudfront_default_cache_behavior, {})
        self.assertIsNone(facts.cloudfront_default_viewer_protocol_policy)
        self.assertEqual(facts.cloudfront_default_allowed_methods, [])
        self.assertEqual(facts.cloudfront_default_cached_methods, [])
        self.assertEqual(facts.cloudfront_ordered_cache_behaviors, [])
        self.assertEqual(facts.cloudfront_ordered_viewer_protocol_policies, [])
        self.assertEqual(facts.cloudfront_origins, [])
        self.assertEqual(facts.cloudfront_origin_ids, [])
        self.assertEqual(facts.cloudfront_origin_domain_names, [])
        self.assertEqual(facts.cloudfront_viewer_certificate, {})
        self.assertIsNone(facts.cloudfront_viewer_certificate_source)
        self.assertIsNone(facts.cloudfront_default_certificate_state)
        self.assertIsNone(facts.cloudfront_default_certificate)
        self.assertIsNone(facts.cloudfront_minimum_protocol_version)
        self.assertIsNone(facts.cloudfront_ssl_support_method)
        self.assertIsNone(facts.cloudfront_acm_certificate_arn)
        self.assertIsNone(facts.cloudfront_iam_certificate_id)
        self.assertIsNone(facts.cloudfront_logging_state)
        self.assertEqual(facts.cloudfront_logging_config, {})
        self.assertIsNone(facts.cloudfront_logging_bucket)
        self.assertIsNone(facts.cloudfront_logging_prefix)
        self.assertEqual(facts.cloudfront_posture_uncertainties, [])
        self.assertIsNone(facts.web_acl_id)
        self.assertIsNone(facts.web_acl_name)
        self.assertIsNone(facts.web_acl_arn)
        self.assertIsNone(facts.web_acl_scope)
        self.assertIsNone(facts.web_acl_default_action)
        self.assertEqual(facts.web_acl_default_action_evidence, {})
        self.assertEqual(facts.web_acl_rules, [])
        self.assertEqual(facts.web_acl_rule_names, [])
        self.assertIsNone(facts.web_acl_association_resource_arn)
        self.assertIsNone(facts.web_acl_association_web_acl_arn)
        self.assertEqual(facts.edge_protection_posture_uncertainties, [])
        self.assertEqual(facts.audit_detection_posture_uncertainties, [])
        self.assertIsNone(facts.cloudtrail_s3_bucket_name)
        self.assertIsNone(facts.cloudtrail_s3_key_prefix)
        self.assertIsNone(facts.cloudtrail_kms_key_id)
        self.assertIsNone(facts.cloudtrail_cloudwatch_logs_group_arn)
        self.assertIsNone(facts.cloudtrail_cloudwatch_logs_role_arn)
        self.assertIsNone(facts.cloudtrail_enable_logging_state)
        self.assertIsNone(facts.cloudtrail_enable_logging)
        self.assertIsNone(facts.cloudtrail_log_file_validation_state)
        self.assertIsNone(facts.cloudtrail_log_file_validation_enabled)
        self.assertIsNone(facts.cloudtrail_multi_region_state)
        self.assertIsNone(facts.cloudtrail_multi_region)
        self.assertIsNone(facts.cloudtrail_global_service_events_state)
        self.assertIsNone(facts.cloudtrail_global_service_events)
        self.assertIsNone(facts.cloudtrail_organization_trail_state)
        self.assertIsNone(facts.cloudtrail_organization_trail)
        self.assertEqual(facts.cloudtrail_event_selectors, [])
        self.assertEqual(facts.cloudtrail_insight_selectors, [])
        self.assertIsNone(facts.guardduty_enable_state)
        self.assertIsNone(facts.guardduty_enabled)
        self.assertIsNone(facts.guardduty_finding_publishing_frequency)
        self.assertEqual(facts.guardduty_datasources, {})
        self.assertEqual(facts.guardduty_features, [])
        self.assertIsNone(facts.securityhub_enable_default_standards_state)
        self.assertIsNone(facts.securityhub_enable_default_standards)
        self.assertIsNone(facts.securityhub_auto_enable_controls_state)
        self.assertIsNone(facts.securityhub_auto_enable_controls)
        self.assertIsNone(facts.securityhub_control_finding_generator)
        self.assertIsNone(facts.config_recorder_name)
        self.assertIsNone(facts.config_recorder_role_arn)
        self.assertIsNone(facts.config_recorder_all_supported_state)
        self.assertIsNone(facts.config_recorder_all_supported)
        self.assertIsNone(facts.config_recorder_include_global_resource_types_state)
        self.assertIsNone(facts.config_recorder_include_global_resource_types)
        self.assertEqual(facts.config_recorder_resource_types, [])
        self.assertIsNone(facts.config_recorder_recording_strategy_use_only)
        self.assertEqual(facts.config_recorder_recording_group, {})
        self.assertEqual(facts.config_recorder_recording_strategy, {})
        self.assertIsNone(facts.vpc_endpoint_id)
        self.assertIsNone(facts.vpc_endpoint_service_name)
        self.assertIsNone(facts.vpc_endpoint_service_family)
        self.assertIsNone(facts.vpc_endpoint_type)
        self.assertIsNone(facts.vpc_endpoint_vpc_id)
        self.assertEqual(facts.vpc_endpoint_route_table_ids, [])
        self.assertEqual(facts.vpc_endpoint_subnet_ids, [])
        self.assertEqual(facts.vpc_endpoint_security_group_ids, [])
        self.assertIsNone(facts.vpc_endpoint_private_dns_enabled_state)
        self.assertIsNone(facts.vpc_endpoint_private_dns_enabled)
        self.assertEqual(facts.vpc_endpoint_policy_document, {})
        self.assertEqual(facts.vpc_endpoint_dns_entries, [])
        self.assertEqual(facts.vpc_endpoint_dns_names, [])
        self.assertEqual(facts.vpc_endpoint_posture_uncertainties, [])
        self.assertIsNone(facts.flow_log_id)
        self.assertIsNone(facts.flow_log_target_type)
        self.assertIsNone(facts.flow_log_target_id)
        self.assertIsNone(facts.flow_log_traffic_type)
        self.assertIsNone(facts.flow_log_destination_type)
        self.assertIsNone(facts.flow_log_destination)
        self.assertIsNone(facts.flow_log_log_group_name)
        self.assertIsNone(facts.flow_log_iam_role_arn)
        self.assertIsNone(facts.flow_log_max_aggregation_interval)
        self.assertEqual(facts.flow_log_destination_options, {})
        self.assertEqual(facts.flow_log_posture_uncertainties, [])
        self.assertIsNone(facts.rds_publicly_accessible_state)
        self.assertIsNone(facts.rds_publicly_accessible)
        self.assertIsNone(facts.rds_backup_retention_period)
        self.assertIsNone(facts.rds_deletion_protection_state)
        self.assertIsNone(facts.rds_deletion_protection)
        self.assertIsNone(facts.rds_multi_az_state)
        self.assertIsNone(facts.rds_multi_az)
        self.assertIsNone(facts.rds_kms_key_id)
        self.assertEqual(facts.rds_posture_uncertainties, [])
        self.assertIsNone(facts.kms_key_usage)
        self.assertIsNone(facts.kms_key_spec)
        self.assertIsNone(facts.kms_customer_master_key_spec)
        self.assertIsNone(facts.kms_enable_key_rotation_state)
        self.assertIsNone(facts.kms_enable_key_rotation)
        self.assertIsNone(facts.kms_deletion_window_in_days)
        self.assertEqual(facts.kms_posture_uncertainties, [])
        self.assertEqual(facts.eks_posture_uncertainties, [])

    def test_policy_document_is_mutated_only_through_facts_facade(self) -> None:
        resource = _resource()
        facts = aws_facts(resource)
        policy_document = {"Statement": [{"Effect": "Allow"}]}

        facts.set_policy_document(policy_document)
        policy_document["Statement"].append({"Effect": "Deny"})

        self.assertEqual(facts.policy_document, {"Statement": [{"Effect": "Allow"}]})

    def test_raw_aws_facts_expose_only_aws_owned_fact_properties(self) -> None:
        facts = aws_facts(_resource())
        unsupported_defaults = {
            "uniform_bucket_level_access",
            "public_access_prevention",
            "versioning_enabled",
            "default_kms_key_name",
            "customer_managed_encryption",
            "project",
            "reference_values",
            "iam_target_reference",
            "iam_bindings",
            "custom_role_id",
            "custom_role_permissions",
            "organization_id",
            "folder_id",
            "service_account_email",
            "service_account_member",
            "service_account_reference",
            "iam_role",
            "iam_member",
            "authorized_networks",
            "backup_enabled",
            "point_in_time_recovery_enabled",
            "ipv4_enabled",
            "private_network",
            "require_ssl",
            "ssl_mode",
            "deletion_protection",
            "os_login_enabled",
            "network_tags",
            "internet_ingress_firewalls",
            "fronted_by_internet_facing_load_balancer",
            "internet_facing_load_balancer_addresses",
            "load_balancer_frontends",
            "load_balancer_reachable_backends",
            "gke_endpoint",
            "gke_private_endpoint_enabled",
            "gke_private_nodes_enabled",
            "gke_master_authorized_networks",
            "gke_workload_identity_enabled",
            "gke_workload_identity_pool",
            "gke_node_service_account",
            "gke_node_oauth_scopes",
            "gke_node_metadata_mode",
            "gke_legacy_metadata_endpoints_enabled",
            "workload_identity_members",
            "workload_identity_scopes",
        }

        for fact_name in sorted(unsupported_defaults):
            with self.subTest(fact_name=fact_name):
                self.assertFalse(hasattr(facts, fact_name))

    def test_aws_fact_domains_add_neutral_defaults_at_analysis_boundary(self) -> None:
        resource = _resource(
            {
                AwsResourceMetadata.BUCKET_NAME: "logs",
                AwsResourceMetadata.BUCKET_ACL: "private",
                AwsResourceMetadata.POLICY_DOCUMENT: {"Statement": []},
                AwsResourceMetadata.TRUST_STATEMENTS: [{"Effect": "Allow"}],
                AwsResourceMetadata.ENGINE: "postgres",
                AwsResourceMetadata.RDS_BACKUP_RETENTION_PERIOD: 7,
                AwsResourceMetadata.RDS_DELETION_PROTECTION_STATE: "enabled",
                AwsResourceMetadata.RDS_PUBLICLY_ACCESSIBLE_STATE: "disabled",
                AwsResourceMetadata.S3_VERSIONING_STATUS: "Enabled",
            }
        )

        domains = aws_fact_domains(resource)

        self.assertIsInstance(domains.storage, AwsStorageFacts)
        self.assertIsInstance(domains.iam, AwsIamFacts)
        self.assertIsInstance(domains.sql, AwsSqlFacts)
        self.assertIsInstance(domains.compute, NeutralProviderComputeFacts)
        self.assertIsInstance(domains.workload, NeutralProviderWorkloadFacts)
        self.assertEqual(domains.storage.bucket_name, "logs")
        self.assertEqual(domains.storage.bucket_acl, "private")
        self.assertTrue(domains.storage.s3_versioning_enabled)
        self.assertIsNone(domains.storage.uniform_bucket_level_access)
        self.assertEqual(domains.iam.policy_document, {"Statement": []})
        self.assertEqual(domains.iam.trust_statements, [{"Effect": "Allow"}])
        self.assertEqual(domains.iam.reference_values, [])
        self.assertIsNone(domains.iam.service_account_email)
        self.assertEqual(domains.sql.engine, "postgres")
        self.assertTrue(domains.sql.backup_enabled)
        self.assertTrue(domains.sql.deletion_protection)
        self.assertFalse(domains.sql.ipv4_enabled)
        self.assertEqual(domains.sql.authorized_networks, [])
        self.assertFalse(domains.compute.fronted_by_internet_facing_load_balancer)
        self.assertEqual(domains.workload.workload_identity_members, [])

    def test_aws_provider_metadata_access_is_centralized_in_namespace_and_facts(self) -> None:
        aws_provider_root = SOURCE_ROOT / "providers" / "aws"
        resource_metadata_reference = re.compile(r"\bResourceMetadata\b")
        offenders: list[str] = []

        for path in sorted(aws_provider_root.glob("*.py")):
            text = path.read_text(encoding="utf-8")
            if path.name == "metadata.py":
                if "get_metadata_field(" in text or "set_metadata_field(" in text:
                    offenders.append(path.name)
                continue
            if path.name == "resource_facts.py":
                if resource_metadata_reference.search(text):
                    offenders.append(path.name)
                continue
            if (
                resource_metadata_reference.search(text)
                or "get_metadata_field(" in text
                or "set_metadata_field(" in text
            ):
                offenders.append(path.name)

        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
