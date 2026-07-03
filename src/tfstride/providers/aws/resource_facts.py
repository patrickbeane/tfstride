from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, TypeVar

from tfstride.models import NormalizedResource
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.metadata_ownership import ProviderMetadataWriteValidator
from tfstride.providers.resource_facts import (
    NeutralProviderComputeFacts,
    NeutralProviderIamFacts,
    NeutralProviderSqlFacts,
    NeutralProviderStorageFacts,
    NeutralProviderWorkloadFacts,
    ProviderResourceFactDomains,
)
from tfstride.resource_metadata import MetadataField, StringListMetadataField

_MetadataValue = TypeVar("_MetadataValue")
_AWS_METADATA_WRITE_VALIDATOR = ProviderMetadataWriteValidator.build(
    provider="aws",
    namespace=AwsResourceMetadata,
)
_S3_BUCKET_KEY_ENABLED = "enabled"
_S3_BUCKET_KEY_DISABLED = "disabled"
_STATE_ENABLED = "enabled"
_STATE_DISABLED = "disabled"


@dataclass(frozen=True, slots=True)
class AwsResourceFacts:
    """AWS-owned view over provider-specific resource metadata."""

    resource: NormalizedResource

    def get(self, field: MetadataField[_MetadataValue]) -> _MetadataValue:
        return self.resource.get_metadata_field(field)

    def set(self, field: MetadataField[_MetadataValue], value: _MetadataValue) -> None:
        _AWS_METADATA_WRITE_VALIDATOR.validate(field)
        self.resource.set_metadata_field(field, value)

    def append(self, field: StringListMetadataField, value: str | None) -> None:
        _AWS_METADATA_WRITE_VALIDATOR.validate(field)
        self.resource.append_metadata_field(field, value)

    def extend(self, field: StringListMetadataField, values: Sequence[str | None]) -> None:
        _AWS_METADATA_WRITE_VALIDATOR.validate(field)
        self.resource.extend_metadata_field(field, values)

    @property
    def security_group_id(self) -> str | None:
        return self.get(AwsResourceMetadata.SECURITY_GROUP_ID)

    @property
    def role_reference(self) -> str | None:
        return self.get(AwsResourceMetadata.ROLE_REFERENCE)

    @property
    def role_references(self) -> list[str]:
        return self.get(AwsResourceMetadata.ROLE_REFERENCES)

    @property
    def resolved_role_references(self) -> list[str]:
        return self.get(AwsResourceMetadata.RESOLVED_ROLE_REFERENCES)

    @property
    def iam_instance_profile(self) -> str | None:
        return self.get(AwsResourceMetadata.IAM_INSTANCE_PROFILE)

    @property
    def policy_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.POLICY_ARN)

    @property
    def policy_name(self) -> str | None:
        return self.get(AwsResourceMetadata.POLICY_NAME)

    @property
    def cluster_reference(self) -> str | None:
        return self.get(AwsResourceMetadata.CLUSTER_REFERENCE)

    @property
    def name(self) -> str | None:
        return self.get(AwsResourceMetadata.NAME)

    @property
    def resource_name(self) -> str | None:
        return self.name

    @property
    def task_definition_reference(self) -> str | None:
        return self.get(AwsResourceMetadata.TASK_DEFINITION_REFERENCE)

    @property
    def task_definition_family(self) -> str | None:
        return self.get(AwsResourceMetadata.TASK_DEFINITION_FAMILY)

    @property
    def task_definition_revision(self) -> int | None:
        return self.get(AwsResourceMetadata.TASK_DEFINITION_REVISION)

    @property
    def network_mode(self) -> str | None:
        return self.get(AwsResourceMetadata.NETWORK_MODE)

    @property
    def requires_compatibilities(self) -> list[str]:
        return self.get(AwsResourceMetadata.REQUIRES_COMPATIBILITIES)

    @property
    def task_role_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.TASK_ROLE_ARN)

    @property
    def execution_role_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.EXECUTION_ROLE_ARN)

    @property
    def secret_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.SECRET_ARN)

    @property
    def function_name(self) -> str | None:
        return self.get(AwsResourceMetadata.FUNCTION_NAME)

    @property
    def lambda_function_url_function_reference(self) -> str | None:
        return self.function_name

    @property
    def lambda_function_url(self) -> str | None:
        return self.get(AwsResourceMetadata.LAMBDA_FUNCTION_URL)

    @property
    def lambda_function_url_authorization_type(self) -> str | None:
        return self.get(AwsResourceMetadata.LAMBDA_FUNCTION_URL_AUTHORIZATION_TYPE)

    @property
    def lambda_function_url_qualifier(self) -> str | None:
        return self.get(AwsResourceMetadata.LAMBDA_FUNCTION_URL_QUALIFIER)

    @property
    def lambda_function_url_invoke_mode(self) -> str | None:
        return self.get(AwsResourceMetadata.LAMBDA_FUNCTION_URL_INVOKE_MODE)

    @property
    def lambda_function_url_cors(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.LAMBDA_FUNCTION_URL_CORS)

    @property
    def lambda_function_url_cors_allow_credentials_state(self) -> str | None:
        return self.get(AwsResourceMetadata.LAMBDA_FUNCTION_URL_CORS_ALLOW_CREDENTIALS_STATE)

    @property
    def lambda_function_url_cors_allow_credentials(self) -> bool | None:
        return _bool_from_state(self.lambda_function_url_cors_allow_credentials_state)

    @property
    def lambda_function_url_cors_allow_headers(self) -> list[str]:
        return self.get(AwsResourceMetadata.LAMBDA_FUNCTION_URL_CORS_ALLOW_HEADERS)

    @property
    def lambda_function_url_cors_allow_methods(self) -> list[str]:
        return self.get(AwsResourceMetadata.LAMBDA_FUNCTION_URL_CORS_ALLOW_METHODS)

    @property
    def lambda_function_url_cors_allow_origins(self) -> list[str]:
        return self.get(AwsResourceMetadata.LAMBDA_FUNCTION_URL_CORS_ALLOW_ORIGINS)

    @property
    def lambda_function_url_cors_expose_headers(self) -> list[str]:
        return self.get(AwsResourceMetadata.LAMBDA_FUNCTION_URL_CORS_EXPOSE_HEADERS)

    @property
    def lambda_function_url_cors_max_age(self) -> int | None:
        return self.get(AwsResourceMetadata.LAMBDA_FUNCTION_URL_CORS_MAX_AGE)

    @property
    def lambda_function_url_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.LAMBDA_FUNCTION_URL_POSTURE_UNCERTAINTIES)

    @property
    def load_balancer_listener_protocol(self) -> str | None:
        return self.get(AwsResourceMetadata.LOAD_BALANCER_LISTENER_PROTOCOL)

    @property
    def load_balancer_listener_certificate_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.LOAD_BALANCER_LISTENER_CERTIFICATE_ARN)

    @property
    def load_balancer_listener_ssl_policy(self) -> str | None:
        return self.get(AwsResourceMetadata.LOAD_BALANCER_LISTENER_SSL_POLICY)

    @property
    def load_balancer_listener_tls_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.LOAD_BALANCER_LISTENER_TLS_UNCERTAINTIES)

    @property
    def route_table_id(self) -> str | None:
        return self.get(AwsResourceMetadata.ROUTE_TABLE_ID)

    @property
    def subnet_id(self) -> str | None:
        return self.get(AwsResourceMetadata.SUBNET_ID)

    @property
    def routes(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.ROUTES)

    @property
    def map_public_ip_on_launch(self) -> bool:
        return self.get(AwsResourceMetadata.MAP_PUBLIC_IP_ON_LAUNCH)

    @property
    def block_public_acls(self) -> bool:
        return self.get(AwsResourceMetadata.BLOCK_PUBLIC_ACLS)

    @property
    def block_public_policy(self) -> bool:
        return self.get(AwsResourceMetadata.BLOCK_PUBLIC_POLICY)

    @property
    def ignore_public_acls(self) -> bool:
        return self.get(AwsResourceMetadata.IGNORE_PUBLIC_ACLS)

    @property
    def restrict_public_buckets(self) -> bool:
        return self.get(AwsResourceMetadata.RESTRICT_PUBLIC_BUCKETS)

    @property
    def policy_document(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.POLICY_DOCUMENT)

    @property
    def public_access_block(self) -> dict[str, bool] | None:
        return self.get(AwsResourceMetadata.PUBLIC_ACCESS_BLOCK)

    @property
    def bucket_name(self) -> str | None:
        return self.get(AwsResourceMetadata.BUCKET_NAME)

    @property
    def bucket_acl(self) -> str:
        return self.get(AwsResourceMetadata.BUCKET_ACL) or ""

    @property
    def s3_versioning_status(self) -> str | None:
        return self.get(AwsResourceMetadata.S3_VERSIONING_STATUS)

    @property
    def s3_versioning_enabled(self) -> bool | None:
        status = self.s3_versioning_status
        if status is None:
            return None
        normalized = status.strip().lower()
        if normalized == "enabled":
            return True
        if normalized in {"disabled", "suspended"}:
            return False
        return None

    @property
    def s3_versioning_source_address(self) -> str | None:
        return self.get(AwsResourceMetadata.S3_VERSIONING_SOURCE_ADDRESS)

    @property
    def s3_versioning_configuration(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.S3_VERSIONING_CONFIGURATION)

    @property
    def s3_encryption_algorithm(self) -> str | None:
        return self.get(AwsResourceMetadata.S3_ENCRYPTION_ALGORITHM)

    @property
    def s3_kms_master_key_id(self) -> str | None:
        return self.get(AwsResourceMetadata.S3_KMS_MASTER_KEY_ID)

    @property
    def s3_bucket_key_enabled_state(self) -> str | None:
        return self.get(AwsResourceMetadata.S3_BUCKET_KEY_ENABLED_STATE)

    @property
    def s3_bucket_key_enabled(self) -> bool | None:
        state = self.s3_bucket_key_enabled_state
        if state == _S3_BUCKET_KEY_ENABLED:
            return True
        if state == _S3_BUCKET_KEY_DISABLED:
            return False
        return None

    @property
    def s3_encryption_source_address(self) -> str | None:
        return self.get(AwsResourceMetadata.S3_ENCRYPTION_SOURCE_ADDRESS)

    @property
    def s3_server_side_encryption_configuration(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.S3_SERVER_SIDE_ENCRYPTION_CONFIGURATION)

    @property
    def s3_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.S3_POSTURE_UNCERTAINTIES)

    @property
    def eks_cluster_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_CLUSTER_ARN)

    @property
    def eks_cluster_role_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_CLUSTER_ROLE_ARN)

    @property
    def eks_kubernetes_version(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_KUBERNETES_VERSION)

    @property
    def eks_endpoint_public_access_state(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_ENDPOINT_PUBLIC_ACCESS_STATE)

    @property
    def eks_endpoint_private_access_state(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_ENDPOINT_PRIVATE_ACCESS_STATE)

    @property
    def eks_public_access_cidrs(self) -> list[str]:
        return self.get(AwsResourceMetadata.EKS_PUBLIC_ACCESS_CIDRS)

    @property
    def eks_public_access_cidrs_state(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_PUBLIC_ACCESS_CIDRS_STATE)

    @property
    def eks_subnet_ids(self) -> list[str]:
        return self.get(AwsResourceMetadata.EKS_SUBNET_IDS)

    @property
    def eks_security_group_ids(self) -> list[str]:
        return self.get(AwsResourceMetadata.EKS_SECURITY_GROUP_IDS)

    @property
    def eks_cluster_security_group_id(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_CLUSTER_SECURITY_GROUP_ID)

    @property
    def eks_vpc_config(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.EKS_VPC_CONFIG)

    @property
    def eks_enabled_cluster_log_types(self) -> list[str]:
        return self.get(AwsResourceMetadata.EKS_ENABLED_CLUSTER_LOG_TYPES)

    @property
    def eks_control_plane_logging_state(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_CONTROL_PLANE_LOGGING_STATE)

    @property
    def eks_encryption_config(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.EKS_ENCRYPTION_CONFIG)

    @property
    def eks_encryption_config_state(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_ENCRYPTION_CONFIG_STATE)

    @property
    def eks_secrets_encryption_state(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_SECRETS_ENCRYPTION_STATE)

    @property
    def eks_encryption_key_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_ENCRYPTION_KEY_ARN)

    @property
    def eks_encryption_resources(self) -> list[str]:
        return self.get(AwsResourceMetadata.EKS_ENCRYPTION_RESOURCES)

    @property
    def eks_access_config_state(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_ACCESS_CONFIG_STATE)

    @property
    def eks_authentication_mode(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_AUTHENTICATION_MODE)

    @property
    def eks_bootstrap_cluster_creator_admin_permissions_state(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_BOOTSTRAP_CLUSTER_CREATOR_ADMIN_PERMISSIONS_STATE)

    @property
    def eks_access_config(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.EKS_ACCESS_CONFIG)

    @property
    def eks_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.EKS_POSTURE_UNCERTAINTIES)

    @property
    def eks_addon_name(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_ADDON_NAME)

    @property
    def eks_addon_cluster_name(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_ADDON_CLUSTER_NAME)

    @property
    def eks_addon_version(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_ADDON_VERSION)

    @property
    def eks_addon_configuration_values(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_ADDON_CONFIGURATION_VALUES)

    @property
    def eks_addon_configuration_keys(self) -> list[str]:
        return self.get(AwsResourceMetadata.EKS_ADDON_CONFIGURATION_KEYS)

    @property
    def eks_addon_preserve_state(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_ADDON_PRESERVE_STATE)

    @property
    def eks_addon_preserve(self) -> bool | None:
        return _bool_from_state(self.eks_addon_preserve_state)

    @property
    def eks_addon_service_account_role_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_ADDON_SERVICE_ACCOUNT_ROLE_ARN)

    @property
    def eks_addon_target_class(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_ADDON_TARGET_CLASS)

    @property
    def rds_publicly_accessible_state(self) -> str | None:
        return self.get(AwsResourceMetadata.RDS_PUBLICLY_ACCESSIBLE_STATE)

    @property
    def rds_publicly_accessible(self) -> bool | None:
        return _bool_from_state(self.rds_publicly_accessible_state)

    @property
    def rds_backup_retention_period(self) -> int | None:
        return self.get(AwsResourceMetadata.RDS_BACKUP_RETENTION_PERIOD)

    @property
    def rds_deletion_protection_state(self) -> str | None:
        return self.get(AwsResourceMetadata.RDS_DELETION_PROTECTION_STATE)

    @property
    def rds_deletion_protection(self) -> bool | None:
        return _bool_from_state(self.rds_deletion_protection_state)

    @property
    def rds_multi_az_state(self) -> str | None:
        return self.get(AwsResourceMetadata.RDS_MULTI_AZ_STATE)

    @property
    def rds_multi_az(self) -> bool | None:
        return _bool_from_state(self.rds_multi_az_state)

    @property
    def rds_kms_key_id(self) -> str | None:
        return self.get(AwsResourceMetadata.RDS_KMS_KEY_ID)

    @property
    def rds_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.RDS_POSTURE_UNCERTAINTIES)

    @property
    def engine(self) -> str | None:
        return self.get(AwsResourceMetadata.ENGINE)

    @property
    def trust_statements(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.TRUST_STATEMENTS)

    def set_resolved_role_references(self, values: list[str]) -> None:
        self.set(AwsResourceMetadata.RESOLVED_ROLE_REFERENCES, values)

    def set_network_mode(self, value: str | None) -> None:
        self.set(AwsResourceMetadata.NETWORK_MODE, value)

    def set_requires_compatibilities(self, values: list[str]) -> None:
        self.set(AwsResourceMetadata.REQUIRES_COMPATIBILITIES, values)

    def set_task_role_arn(self, value: str | None) -> None:
        self.set(AwsResourceMetadata.TASK_ROLE_ARN, value)

    def set_execution_role_arn(self, value: str | None) -> None:
        self.set(AwsResourceMetadata.EXECUTION_ROLE_ARN, value)

    def set_public_access_block(self, value: dict[str, bool] | None) -> None:
        self.set(AwsResourceMetadata.PUBLIC_ACCESS_BLOCK, value)

    def set_route_table_ids(self, values: list[str]) -> None:
        self.set(AwsResourceMetadata.ROUTE_TABLE_IDS, values)

    def set_internet_ingress(self, value: bool) -> None:
        self.set(AwsResourceMetadata.INTERNET_INGRESS, value)

    def set_public_access_configured(self, value: bool) -> None:
        self.set(AwsResourceMetadata.PUBLIC_ACCESS_CONFIGURED, value)

    def has_public_access_reasons(self) -> bool:
        return self.resource.has_metadata_field(AwsResourceMetadata.PUBLIC_ACCESS_REASONS)

    def has_public_exposure_reasons(self) -> bool:
        return self.resource.has_metadata_field(AwsResourceMetadata.PUBLIC_EXPOSURE_REASONS)

    def add_public_exposure_reason(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.PUBLIC_EXPOSURE_REASONS, value)

    def set_fronted_by_internet_facing_load_balancer(self, value: bool) -> None:
        self.set(AwsResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER, value)

    def set_internet_facing_load_balancer_addresses(self, values: list[str]) -> None:
        self.set(AwsResourceMetadata.INTERNET_FACING_LOAD_BALANCER_ADDRESSES, values)

    def set_policy_document(self, value: dict[str, Any] | None) -> None:
        self.set(AwsResourceMetadata.POLICY_DOCUMENT, value)

    def set_s3_versioning_posture(
        self,
        *,
        status: str | None,
        configuration: dict[str, Any] | None,
        source_address: str | None,
    ) -> None:
        self.set(AwsResourceMetadata.S3_VERSIONING_STATUS, status)
        self.set(AwsResourceMetadata.S3_VERSIONING_CONFIGURATION, configuration)
        self.set(AwsResourceMetadata.S3_VERSIONING_SOURCE_ADDRESS, source_address)

    def set_s3_encryption_posture(
        self,
        *,
        algorithm: str | None,
        kms_master_key_id: str | None,
        bucket_key_enabled_state: str | None,
        configuration: dict[str, Any] | None,
        source_address: str | None,
    ) -> None:
        self.set(AwsResourceMetadata.S3_ENCRYPTION_ALGORITHM, algorithm)
        self.set(AwsResourceMetadata.S3_KMS_MASTER_KEY_ID, kms_master_key_id)
        self.set(AwsResourceMetadata.S3_BUCKET_KEY_ENABLED_STATE, bucket_key_enabled_state)
        self.set(AwsResourceMetadata.S3_SERVER_SIDE_ENCRYPTION_CONFIGURATION, configuration)
        self.set(AwsResourceMetadata.S3_ENCRYPTION_SOURCE_ADDRESS, source_address)

    def extend_s3_posture_uncertainties(self, values: Sequence[str | None]) -> None:
        self.extend(AwsResourceMetadata.S3_POSTURE_UNCERTAINTIES, values)

    def add_standalone_rule_address(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.STANDALONE_RULE_ADDRESSES, value)

    def add_inline_policy_resource_address(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.INLINE_POLICY_RESOURCE_ADDRESSES, value)

    def add_inline_policy_name(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.INLINE_POLICY_NAMES, value)

    def add_unresolved_attached_policy_arn(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_ATTACHED_POLICY_ARNS, value)

    def add_attached_policy_arn(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.ATTACHED_POLICY_ARNS, value)

    def add_attached_policy_address(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.ATTACHED_POLICY_ADDRESSES, value)

    def add_unresolved_role_references(self, values: Sequence[str | None]) -> None:
        self.extend(AwsResourceMetadata.UNRESOLVED_ROLE_REFERENCES, values)

    def add_resolved_role_addresses(self, values: Sequence[str | None]) -> None:
        self.extend(AwsResourceMetadata.RESOLVED_ROLE_ADDRESSES, values)

    def add_unresolved_instance_profile(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_INSTANCE_PROFILES, value)

    def add_resolved_instance_profile_address(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.RESOLVED_INSTANCE_PROFILE_ADDRESSES, value)

    def add_unresolved_cluster_reference(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_CLUSTER_REFERENCES, value)

    def add_resolved_cluster_address(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.RESOLVED_CLUSTER_ADDRESSES, value)

    def add_unresolved_task_definition_reference(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_TASK_DEFINITION_REFERENCES, value)

    def add_resolved_task_definition_address(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.RESOLVED_TASK_DEFINITION_ADDRESSES, value)

    def add_resolved_task_role_address(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.RESOLVED_TASK_ROLE_ADDRESSES, value)

    def add_unresolved_task_role_arn(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_TASK_ROLE_ARNS, value)

    def add_resolved_execution_role_address(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.RESOLVED_EXECUTION_ROLE_ADDRESSES, value)

    def add_unresolved_execution_role_arn(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_EXECUTION_ROLE_ARNS, value)

    def add_unresolved_bucket_reference(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_BUCKET_REFERENCES, value)

    def add_unresolved_secret_arn(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_SECRET_ARNS, value)

    def add_unresolved_function_reference(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_FUNCTION_REFERENCES, value)

    def add_resource_policy_source_address(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES, value)

    @property
    def resource_policy_source_addresses(self) -> list[str]:
        return self.get(AwsResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES)


def _bool_from_state(state: str | None) -> bool | None:
    if state == _STATE_ENABLED:
        return True
    if state == _STATE_DISABLED:
        return False
    return None


class AwsStorageFacts(AwsResourceFacts, NeutralProviderStorageFacts):
    __slots__ = ()


class AwsIamFacts(AwsResourceFacts, NeutralProviderIamFacts):
    __slots__ = ()


class AwsSqlFacts(AwsResourceFacts, NeutralProviderSqlFacts):
    __slots__ = ()

    @property
    def backup_enabled(self) -> bool | None:
        period = self.rds_backup_retention_period
        if period is None:
            return None
        return period > 0

    @property
    def deletion_protection(self) -> bool | None:
        return self.rds_deletion_protection

    @property
    def ipv4_enabled(self) -> bool | None:
        return self.rds_publicly_accessible


def aws_facts(resource: NormalizedResource) -> AwsResourceFacts:
    return AwsResourceFacts(resource)


def aws_fact_domains(resource: NormalizedResource) -> ProviderResourceFactDomains:
    return ProviderResourceFactDomains(
        storage=AwsStorageFacts(resource),
        iam=AwsIamFacts(resource),
        sql=AwsSqlFacts(resource),
        compute=NeutralProviderComputeFacts(),
        workload=NeutralProviderWorkloadFacts(),
    )
