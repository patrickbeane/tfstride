from __future__ import annotations

import unittest

from tfstride.providers.aws.metadata import (
    AWS_SHARED_CORE_METADATA_FIELD_NAMES,
    AwsResourceMetadata,
)
from tfstride.providers.contracts import DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT
from tfstride.resource_metadata import MetadataField, ResourceMetadata


def _metadata_field_names(namespace: type) -> set[str]:
    return {name for name, value in vars(namespace).items() if isinstance(value, MetadataField)}


class AwsResourceMetadataTests(unittest.TestCase):
    def test_aws_metadata_namespace_covers_classified_fields(self) -> None:
        ownership_contract = DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT
        expected_fields = ownership_contract.provider_owned_fields["aws"] | AWS_SHARED_CORE_METADATA_FIELD_NAMES

        self.assertEqual(_metadata_field_names(AwsResourceMetadata), expected_fields)

    def test_aws_metadata_namespace_aliases_shared_core_fields_only(self) -> None:
        ownership_contract = DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT
        aws_owned = ownership_contract.provider_owned_fields["aws"]

        for field_name in AWS_SHARED_CORE_METADATA_FIELD_NAMES:
            with self.subTest(field_name=field_name):
                self.assertIs(
                    getattr(AwsResourceMetadata, field_name),
                    getattr(ResourceMetadata, field_name),
                )

        for field_name in aws_owned:
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(ResourceMetadata, field_name))

    def test_aws_metadata_provider_fields_keep_existing_metadata_keys(self) -> None:
        expected_keys = {
            "SECURITY_GROUP_ID": "security_group_id",
            "ROLE_REFERENCE": "role",
            "BUCKET_NAME": "bucket",
            "BUCKET_ACL": "acl",
            "POLICY_DOCUMENT": "policy_document",
            "PUBLIC_ACCESS_BLOCK": "public_access_block",
            "RESOURCE_POLICY_SOURCE_ADDRESSES": "resource_policy_source_addresses",
            "S3_VERSIONING_STATUS": "s3_versioning_status",
            "S3_VERSIONING_SOURCE_ADDRESS": "s3_versioning_source_address",
            "S3_ENCRYPTION_ALGORITHM": "s3_encryption_algorithm",
            "S3_KMS_MASTER_KEY_ID": "s3_kms_master_key_id",
            "S3_BUCKET_KEY_ENABLED_STATE": "s3_bucket_key_enabled_state",
            "S3_ENCRYPTION_SOURCE_ADDRESS": "s3_encryption_source_address",
            "S3_VERSIONING_CONFIGURATION": "s3_versioning_configuration",
            "S3_SERVER_SIDE_ENCRYPTION_CONFIGURATION": "s3_server_side_encryption_configuration",
            "S3_POSTURE_UNCERTAINTIES": "s3_posture_uncertainties",
            "RDS_PUBLICLY_ACCESSIBLE_STATE": "rds_publicly_accessible_state",
            "RDS_BACKUP_RETENTION_PERIOD": "rds_backup_retention_period",
            "RDS_DELETION_PROTECTION_STATE": "rds_deletion_protection_state",
            "RDS_MULTI_AZ_STATE": "rds_multi_az_state",
            "RDS_KMS_KEY_ID": "rds_kms_key_id",
            "RDS_POSTURE_UNCERTAINTIES": "rds_posture_uncertainties",
            "KMS_KEY_USAGE": "kms_key_usage",
            "KMS_KEY_SPEC": "kms_key_spec",
            "KMS_CUSTOMER_MASTER_KEY_SPEC": "kms_customer_master_key_spec",
            "KMS_ENABLE_KEY_ROTATION_STATE": "kms_enable_key_rotation_state",
            "KMS_DELETION_WINDOW_IN_DAYS": "kms_deletion_window_in_days",
            "KMS_POSTURE_UNCERTAINTIES": "kms_posture_uncertainties",
            "EKS_CLUSTER_ARN": "eks_cluster_arn",
            "EKS_CLUSTER_ROLE_ARN": "eks_cluster_role_arn",
            "EKS_ENDPOINT_PUBLIC_ACCESS_STATE": "eks_endpoint_public_access_state",
            "EKS_ENDPOINT_PRIVATE_ACCESS_STATE": "eks_endpoint_private_access_state",
            "EKS_PUBLIC_ACCESS_CIDRS": "eks_public_access_cidrs",
            "EKS_PUBLIC_ACCESS_CIDRS_STATE": "eks_public_access_cidrs_state",
            "EKS_CONTROL_PLANE_LOGGING_STATE": "eks_control_plane_logging_state",
            "EKS_ENABLED_CLUSTER_LOG_TYPES": "eks_enabled_cluster_log_types",
            "EKS_SECRETS_ENCRYPTION_STATE": "eks_secrets_encryption_state",
            "EKS_AUTHENTICATION_MODE": "eks_authentication_mode",
            "EKS_ADDON_NAME": "eks_addon_name",
            "EKS_ADDON_CLUSTER_NAME": "eks_addon_cluster_name",
            "EKS_ADDON_VERSION": "eks_addon_version",
            "EKS_ADDON_CONFIGURATION_VALUES": "eks_addon_configuration_values",
            "EKS_ADDON_CONFIGURATION_KEYS": "eks_addon_configuration_keys",
            "EKS_ADDON_PRESERVE_STATE": "eks_addon_preserve_state",
            "EKS_ADDON_SERVICE_ACCOUNT_ROLE_ARN": "eks_addon_service_account_role_arn",
            "EKS_ADDON_TARGET_CLASS": "eks_addon_target_class",
            "EKS_POSTURE_UNCERTAINTIES": "eks_posture_uncertainties",
            "LAMBDA_FUNCTION_URL": "lambda_function_url",
            "LAMBDA_FUNCTION_URL_AUTHORIZATION_TYPE": "lambda_function_url_authorization_type",
            "LAMBDA_FUNCTION_URL_QUALIFIER": "lambda_function_url_qualifier",
            "LAMBDA_FUNCTION_URL_INVOKE_MODE": "lambda_function_url_invoke_mode",
            "LAMBDA_FUNCTION_URL_CORS": "lambda_function_url_cors",
            "LAMBDA_FUNCTION_URL_CORS_ALLOW_CREDENTIALS_STATE": ("lambda_function_url_cors_allow_credentials_state"),
            "LAMBDA_FUNCTION_URL_CORS_ALLOW_HEADERS": "lambda_function_url_cors_allow_headers",
            "LAMBDA_FUNCTION_URL_CORS_ALLOW_METHODS": "lambda_function_url_cors_allow_methods",
            "LAMBDA_FUNCTION_URL_CORS_ALLOW_ORIGINS": "lambda_function_url_cors_allow_origins",
            "LAMBDA_FUNCTION_URL_CORS_EXPOSE_HEADERS": "lambda_function_url_cors_expose_headers",
            "LAMBDA_FUNCTION_URL_CORS_MAX_AGE": "lambda_function_url_cors_max_age",
            "LAMBDA_FUNCTION_URL_POSTURE_UNCERTAINTIES": "lambda_function_url_posture_uncertainties",
            "LOAD_BALANCER_LISTENER_PROTOCOL": "load_balancer_listener_protocol",
            "LOAD_BALANCER_LISTENER_CERTIFICATE_ARN": "load_balancer_listener_certificate_arn",
            "LOAD_BALANCER_LISTENER_SSL_POLICY": "load_balancer_listener_ssl_policy",
            "LOAD_BALANCER_LISTENER_TLS_UNCERTAINTIES": "load_balancer_listener_tls_uncertainties",
            "VPC_ENDPOINT_ID": "vpc_endpoint_id",
            "VPC_ENDPOINT_SERVICE_NAME": "vpc_endpoint_service_name",
            "VPC_ENDPOINT_SERVICE_FAMILY": "vpc_endpoint_service_family",
            "VPC_ENDPOINT_TYPE": "vpc_endpoint_type",
            "VPC_ENDPOINT_VPC_ID": "vpc_endpoint_vpc_id",
            "VPC_ENDPOINT_ROUTE_TABLE_IDS": "vpc_endpoint_route_table_ids",
            "VPC_ENDPOINT_SUBNET_IDS": "vpc_endpoint_subnet_ids",
            "VPC_ENDPOINT_SECURITY_GROUP_IDS": "vpc_endpoint_security_group_ids",
            "VPC_ENDPOINT_PRIVATE_DNS_ENABLED_STATE": "vpc_endpoint_private_dns_enabled_state",
            "VPC_ENDPOINT_POLICY_DOCUMENT": "vpc_endpoint_policy_document",
            "VPC_ENDPOINT_DNS_ENTRIES": "vpc_endpoint_dns_entries",
            "VPC_ENDPOINT_DNS_NAMES": "vpc_endpoint_dns_names",
            "VPC_ENDPOINT_POSTURE_UNCERTAINTIES": "vpc_endpoint_posture_uncertainties",
        }

        for field_name, key in expected_keys.items():
            with self.subTest(field_name=field_name):
                self.assertEqual(getattr(AwsResourceMetadata, field_name).key, key)


if __name__ == "__main__":
    unittest.main()
