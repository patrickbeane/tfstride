from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, TypeVar

from tfstride.identity import PrivilegedAccessGrant, PrivilegedAccessPosture
from tfstride.models import NormalizedResource
from tfstride.providers.aws.iam_assignment_posture import deserialize_privileged_access_grants
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.coercion import STATE_DISABLED, STATE_ENABLED
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
    def unresolved_attached_policy_arns(self) -> list[str]:
        return self.get(AwsResourceMetadata.UNRESOLVED_ATTACHED_POLICY_ARNS)

    @property
    def attached_policy_arns(self) -> list[str]:
        return self.get(AwsResourceMetadata.ATTACHED_POLICY_ARNS)

    @property
    def attached_policy_addresses(self) -> list[str]:
        return self.get(AwsResourceMetadata.ATTACHED_POLICY_ADDRESSES)

    @property
    def inline_policy_resource_addresses(self) -> list[str]:
        return self.get(AwsResourceMetadata.INLINE_POLICY_RESOURCE_ADDRESSES)

    @property
    def inline_policy_names(self) -> list[str]:
        return self.get(AwsResourceMetadata.INLINE_POLICY_NAMES)

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
    def secrets_manager_kms_key_id(self) -> str | None:
        return self.get(AwsResourceMetadata.SECRETS_MANAGER_KMS_KEY_ID)

    @property
    def secrets_manager_recovery_window_in_days(self) -> int | None:
        return self.get(AwsResourceMetadata.SECRETS_MANAGER_RECOVERY_WINDOW_IN_DAYS)

    @property
    def secrets_manager_replication(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.SECRETS_MANAGER_REPLICATION)

    @property
    def secrets_manager_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.SECRETS_MANAGER_POSTURE_UNCERTAINTIES)

    @property
    def unresolved_secret_references(self) -> list[str]:
        return self.get(AwsResourceMetadata.UNRESOLVED_SECRET_REFERENCES)

    @property
    def secrets_manager_rotation_secret_id(self) -> str | None:
        return self.get(AwsResourceMetadata.SECRETS_MANAGER_ROTATION_SECRET_ID)

    @property
    def secrets_manager_rotation_source_address(self) -> str | None:
        return self.get(AwsResourceMetadata.SECRETS_MANAGER_ROTATION_SOURCE_ADDRESS)

    @property
    def secrets_manager_rotation_lambda_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.SECRETS_MANAGER_ROTATION_LAMBDA_ARN)

    @property
    def secrets_manager_rotation_automatically_after_days(self) -> int | None:
        return self.get(AwsResourceMetadata.SECRETS_MANAGER_ROTATION_AUTOMATICALLY_AFTER_DAYS)

    @property
    def secrets_manager_rotation_duration(self) -> str | None:
        return self.get(AwsResourceMetadata.SECRETS_MANAGER_ROTATION_DURATION)

    @property
    def secrets_manager_rotation_schedule_expression(self) -> str | None:
        return self.get(AwsResourceMetadata.SECRETS_MANAGER_ROTATION_SCHEDULE_EXPRESSION)

    @property
    def secrets_manager_rotation_rules(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.SECRETS_MANAGER_ROTATION_RULES)

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
    def api_gateway_api_id(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_API_ID)

    @property
    def api_gateway_name(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_NAME)

    @property
    def api_gateway_description(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_DESCRIPTION)

    @property
    def api_gateway_protocol_type(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_PROTOCOL_TYPE)

    @property
    def api_gateway_api_endpoint(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_API_ENDPOINT)

    @property
    def api_gateway_execution_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_EXECUTION_ARN)

    @property
    def api_gateway_endpoint_types(self) -> list[str]:
        return self.get(AwsResourceMetadata.API_GATEWAY_ENDPOINT_TYPES)

    @property
    def api_gateway_vpc_endpoint_ids(self) -> list[str]:
        return self.get(AwsResourceMetadata.API_GATEWAY_VPC_ENDPOINT_IDS)

    @property
    def api_gateway_endpoint_configuration(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.API_GATEWAY_ENDPOINT_CONFIGURATION)

    @property
    def api_gateway_execute_api_endpoint_state(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_EXECUTE_API_ENDPOINT_STATE)

    @property
    def api_gateway_public_endpoint_state(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_PUBLIC_ENDPOINT_STATE)

    @property
    def api_gateway_route_selection_expression(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_ROUTE_SELECTION_EXPRESSION)

    @property
    def api_gateway_cors_configuration(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.API_GATEWAY_CORS_CONFIGURATION)

    @property
    def api_gateway_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.API_GATEWAY_POSTURE_UNCERTAINTIES)

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
    def cloudfront_distribution_id(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_DISTRIBUTION_ID)

    @property
    def cloudfront_distribution_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_DISTRIBUTION_ARN)

    @property
    def cloudfront_domain_name(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_DOMAIN_NAME)

    @property
    def cloudfront_enabled_state(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_ENABLED_STATE)

    @property
    def cloudfront_enabled(self) -> bool | None:
        return _bool_from_state(self.cloudfront_enabled_state)

    @property
    def cloudfront_ipv6_enabled_state(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_IPV6_ENABLED_STATE)

    @property
    def cloudfront_ipv6_enabled(self) -> bool | None:
        return _bool_from_state(self.cloudfront_ipv6_enabled_state)

    @property
    def cloudfront_http_version(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_HTTP_VERSION)

    @property
    def cloudfront_default_root_object(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_DEFAULT_ROOT_OBJECT)

    @property
    def cloudfront_aliases(self) -> list[str]:
        return self.get(AwsResourceMetadata.CLOUDFRONT_ALIASES)

    @property
    def cloudfront_web_acl_id(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_WEB_ACL_ID)

    @property
    def cloudfront_default_cache_behavior(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.CLOUDFRONT_DEFAULT_CACHE_BEHAVIOR)

    @property
    def cloudfront_default_viewer_protocol_policy(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_DEFAULT_VIEWER_PROTOCOL_POLICY)

    @property
    def cloudfront_default_allowed_methods(self) -> list[str]:
        return self.get(AwsResourceMetadata.CLOUDFRONT_DEFAULT_ALLOWED_METHODS)

    @property
    def cloudfront_default_cached_methods(self) -> list[str]:
        return self.get(AwsResourceMetadata.CLOUDFRONT_DEFAULT_CACHED_METHODS)

    @property
    def cloudfront_ordered_cache_behaviors(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.CLOUDFRONT_ORDERED_CACHE_BEHAVIORS)

    @property
    def cloudfront_ordered_viewer_protocol_policies(self) -> list[str]:
        return self.get(AwsResourceMetadata.CLOUDFRONT_ORDERED_VIEWER_PROTOCOL_POLICIES)

    @property
    def cloudfront_origins(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.CLOUDFRONT_ORIGINS)

    @property
    def cloudfront_origin_ids(self) -> list[str]:
        return self.get(AwsResourceMetadata.CLOUDFRONT_ORIGIN_IDS)

    @property
    def cloudfront_origin_domain_names(self) -> list[str]:
        return self.get(AwsResourceMetadata.CLOUDFRONT_ORIGIN_DOMAIN_NAMES)

    @property
    def cloudfront_viewer_certificate(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.CLOUDFRONT_VIEWER_CERTIFICATE)

    @property
    def cloudfront_viewer_certificate_source(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_VIEWER_CERTIFICATE_SOURCE)

    @property
    def cloudfront_default_certificate_state(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_DEFAULT_CERTIFICATE_STATE)

    @property
    def cloudfront_default_certificate(self) -> bool | None:
        return _bool_from_state(self.cloudfront_default_certificate_state)

    @property
    def cloudfront_minimum_protocol_version(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_MINIMUM_PROTOCOL_VERSION)

    @property
    def cloudfront_ssl_support_method(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_SSL_SUPPORT_METHOD)

    @property
    def cloudfront_acm_certificate_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_ACM_CERTIFICATE_ARN)

    @property
    def cloudfront_iam_certificate_id(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_IAM_CERTIFICATE_ID)

    @property
    def cloudfront_logging_state(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_LOGGING_STATE)

    @property
    def cloudfront_logging_config(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.CLOUDFRONT_LOGGING_CONFIG)

    @property
    def cloudfront_logging_bucket(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_LOGGING_BUCKET)

    @property
    def cloudfront_logging_prefix(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDFRONT_LOGGING_PREFIX)

    @property
    def cloudfront_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.CLOUDFRONT_POSTURE_UNCERTAINTIES)

    @property
    def web_acl_id(self) -> str | None:
        return self.get(AwsResourceMetadata.WEB_ACL_ID)

    @property
    def web_acl_name(self) -> str | None:
        return self.get(AwsResourceMetadata.WEB_ACL_NAME)

    @property
    def web_acl_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.WEB_ACL_ARN)

    @property
    def web_acl_scope(self) -> str | None:
        return self.get(AwsResourceMetadata.WEB_ACL_SCOPE)

    @property
    def web_acl_default_action(self) -> str | None:
        return self.get(AwsResourceMetadata.WEB_ACL_DEFAULT_ACTION)

    @property
    def web_acl_default_action_evidence(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.WEB_ACL_DEFAULT_ACTION_EVIDENCE)

    @property
    def web_acl_rules(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.WEB_ACL_RULES)

    @property
    def web_acl_rule_names(self) -> list[str]:
        return self.get(AwsResourceMetadata.WEB_ACL_RULE_NAMES)

    @property
    def web_acl_association_resource_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.WEB_ACL_ASSOCIATION_RESOURCE_ARN)

    @property
    def web_acl_association_web_acl_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.WEB_ACL_ASSOCIATION_WEB_ACL_ARN)

    @property
    def edge_protection_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.EDGE_PROTECTION_POSTURE_UNCERTAINTIES)

    @property
    def audit_detection_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.AUDIT_DETECTION_POSTURE_UNCERTAINTIES)

    @property
    def privileged_access_grants(self) -> tuple[PrivilegedAccessGrant, ...]:
        return deserialize_privileged_access_grants(self.get(AwsResourceMetadata.PRIVILEGED_ACCESS_GRANTS))

    @property
    def iam_assignment_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.IAM_ASSIGNMENT_POSTURE_UNCERTAINTIES)

    @property
    def privileged_access_posture(self) -> PrivilegedAccessPosture:
        return PrivilegedAccessPosture(
            provider="aws",
            grants=self.privileged_access_grants,
            unresolved_assignments=self.iam_assignment_posture_uncertainties,
        )

    @property
    def cloudtrail_s3_bucket_name(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDTRAIL_S3_BUCKET_NAME)

    @property
    def cloudtrail_s3_key_prefix(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDTRAIL_S3_KEY_PREFIX)

    @property
    def cloudtrail_kms_key_id(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDTRAIL_KMS_KEY_ID)

    @property
    def cloudtrail_cloudwatch_logs_group_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDTRAIL_CLOUDWATCH_LOGS_GROUP_ARN)

    @property
    def cloudtrail_cloudwatch_logs_role_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDTRAIL_CLOUDWATCH_LOGS_ROLE_ARN)

    @property
    def cloudtrail_enable_logging_state(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDTRAIL_ENABLE_LOGGING_STATE)

    @property
    def cloudtrail_enable_logging(self) -> bool | None:
        return _bool_from_state(self.cloudtrail_enable_logging_state)

    @property
    def cloudtrail_log_file_validation_state(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDTRAIL_LOG_FILE_VALIDATION_STATE)

    @property
    def cloudtrail_log_file_validation_enabled(self) -> bool | None:
        return _bool_from_state(self.cloudtrail_log_file_validation_state)

    @property
    def cloudtrail_multi_region_state(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDTRAIL_MULTI_REGION_STATE)

    @property
    def cloudtrail_multi_region(self) -> bool | None:
        return _bool_from_state(self.cloudtrail_multi_region_state)

    @property
    def cloudtrail_global_service_events_state(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDTRAIL_GLOBAL_SERVICE_EVENTS_STATE)

    @property
    def cloudtrail_global_service_events(self) -> bool | None:
        return _bool_from_state(self.cloudtrail_global_service_events_state)

    @property
    def cloudtrail_organization_trail_state(self) -> str | None:
        return self.get(AwsResourceMetadata.CLOUDTRAIL_ORGANIZATION_TRAIL_STATE)

    @property
    def cloudtrail_organization_trail(self) -> bool | None:
        return _bool_from_state(self.cloudtrail_organization_trail_state)

    @property
    def cloudtrail_event_selectors(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.CLOUDTRAIL_EVENT_SELECTORS)

    @property
    def cloudtrail_insight_selectors(self) -> list[str]:
        return self.get(AwsResourceMetadata.CLOUDTRAIL_INSIGHT_SELECTORS)

    @property
    def guardduty_enable_state(self) -> str | None:
        return self.get(AwsResourceMetadata.GUARDDUTY_ENABLE_STATE)

    @property
    def guardduty_enabled(self) -> bool | None:
        return _bool_from_state(self.guardduty_enable_state)

    @property
    def guardduty_finding_publishing_frequency(self) -> str | None:
        return self.get(AwsResourceMetadata.GUARDDUTY_FINDING_PUBLISHING_FREQUENCY)

    @property
    def guardduty_datasources(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.GUARDDUTY_DATASOURCES)

    @property
    def guardduty_features(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.GUARDDUTY_FEATURES)

    @property
    def securityhub_enable_default_standards_state(self) -> str | None:
        return self.get(AwsResourceMetadata.SECURITYHUB_ENABLE_DEFAULT_STANDARDS_STATE)

    @property
    def securityhub_enable_default_standards(self) -> bool | None:
        return _bool_from_state(self.securityhub_enable_default_standards_state)

    @property
    def securityhub_auto_enable_controls_state(self) -> str | None:
        return self.get(AwsResourceMetadata.SECURITYHUB_AUTO_ENABLE_CONTROLS_STATE)

    @property
    def securityhub_auto_enable_controls(self) -> bool | None:
        return _bool_from_state(self.securityhub_auto_enable_controls_state)

    @property
    def securityhub_control_finding_generator(self) -> str | None:
        return self.get(AwsResourceMetadata.SECURITYHUB_CONTROL_FINDING_GENERATOR)

    @property
    def config_recorder_name(self) -> str | None:
        return self.get(AwsResourceMetadata.CONFIG_RECORDER_NAME)

    @property
    def config_recorder_role_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.CONFIG_RECORDER_ROLE_ARN)

    @property
    def config_recorder_all_supported_state(self) -> str | None:
        return self.get(AwsResourceMetadata.CONFIG_RECORDER_ALL_SUPPORTED_STATE)

    @property
    def config_recorder_all_supported(self) -> bool | None:
        return _bool_from_state(self.config_recorder_all_supported_state)

    @property
    def config_recorder_include_global_resource_types_state(self) -> str | None:
        return self.get(AwsResourceMetadata.CONFIG_RECORDER_INCLUDE_GLOBAL_RESOURCE_TYPES_STATE)

    @property
    def config_recorder_include_global_resource_types(self) -> bool | None:
        return _bool_from_state(self.config_recorder_include_global_resource_types_state)

    @property
    def config_recorder_resource_types(self) -> list[str]:
        return self.get(AwsResourceMetadata.CONFIG_RECORDER_RESOURCE_TYPES)

    @property
    def config_recorder_recording_strategy_use_only(self) -> str | None:
        return self.get(AwsResourceMetadata.CONFIG_RECORDER_RECORDING_STRATEGY_USE_ONLY)

    @property
    def config_recorder_recording_group(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.CONFIG_RECORDER_RECORDING_GROUP)

    @property
    def config_recorder_recording_strategy(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.CONFIG_RECORDER_RECORDING_STRATEGY)

    @property
    def config_recorder_status_name(self) -> str | None:
        return self.get(AwsResourceMetadata.CONFIG_RECORDER_STATUS_NAME)

    @property
    def config_recorder_status_is_enabled_state(self) -> str | None:
        return self.get(AwsResourceMetadata.CONFIG_RECORDER_IS_ENABLED_STATE)

    @property
    def config_recorder_status_is_enabled(self) -> bool | None:
        return _bool_from_state(self.config_recorder_status_is_enabled_state)

    @property
    def config_delivery_channel_name(self) -> str | None:
        return self.get(AwsResourceMetadata.CONFIG_DELIVERY_CHANNEL_NAME)

    @property
    def config_delivery_channel_s3_bucket_name(self) -> str | None:
        return self.get(AwsResourceMetadata.CONFIG_DELIVERY_CHANNEL_S3_BUCKET_NAME)

    @property
    def config_delivery_channel_s3_key_prefix(self) -> str | None:
        return self.get(AwsResourceMetadata.CONFIG_DELIVERY_CHANNEL_S3_KEY_PREFIX)

    @property
    def config_delivery_channel_sns_topic_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.CONFIG_DELIVERY_CHANNEL_SNS_TOPIC_ARN)

    @property
    def access_analyzer_name(self) -> str | None:
        return self.get(AwsResourceMetadata.ACCESS_ANALYZER_NAME)

    @property
    def access_analyzer_type(self) -> str | None:
        return self.get(AwsResourceMetadata.ACCESS_ANALYZER_TYPE)

    @property
    def access_analyzer_status(self) -> str | None:
        return self.get(AwsResourceMetadata.ACCESS_ANALYZER_STATUS)

    @property
    def access_analyzer_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.ACCESS_ANALYZER_ARN)

    @property
    def access_analyzer_configuration(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.ACCESS_ANALYZER_CONFIGURATION)

    @property
    def macie_account_status(self) -> str | None:
        return self.get(AwsResourceMetadata.MACIE_ACCOUNT_STATUS)

    @property
    def macie_account_status_state(self) -> str | None:
        return self.get(AwsResourceMetadata.MACIE_ACCOUNT_STATUS_STATE)

    @property
    def macie_account_enabled(self) -> bool | None:
        return _bool_from_state(self.macie_account_status_state)

    @property
    def macie_finding_publishing_frequency(self) -> str | None:
        return self.get(AwsResourceMetadata.MACIE_FINDING_PUBLISHING_FREQUENCY)

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
    def vpc_endpoint_id(self) -> str | None:
        return self.get(AwsResourceMetadata.VPC_ENDPOINT_ID)

    @property
    def vpc_endpoint_service_name(self) -> str | None:
        return self.get(AwsResourceMetadata.VPC_ENDPOINT_SERVICE_NAME)

    @property
    def vpc_endpoint_service_family(self) -> str | None:
        return self.get(AwsResourceMetadata.VPC_ENDPOINT_SERVICE_FAMILY)

    @property
    def vpc_endpoint_type(self) -> str | None:
        return self.get(AwsResourceMetadata.VPC_ENDPOINT_TYPE)

    @property
    def vpc_endpoint_vpc_id(self) -> str | None:
        return self.get(AwsResourceMetadata.VPC_ENDPOINT_VPC_ID)

    @property
    def vpc_endpoint_route_table_ids(self) -> list[str]:
        return self.get(AwsResourceMetadata.VPC_ENDPOINT_ROUTE_TABLE_IDS)

    @property
    def vpc_endpoint_subnet_ids(self) -> list[str]:
        return self.get(AwsResourceMetadata.VPC_ENDPOINT_SUBNET_IDS)

    @property
    def vpc_endpoint_security_group_ids(self) -> list[str]:
        return self.get(AwsResourceMetadata.VPC_ENDPOINT_SECURITY_GROUP_IDS)

    @property
    def vpc_endpoint_private_dns_enabled_state(self) -> str | None:
        return self.get(AwsResourceMetadata.VPC_ENDPOINT_PRIVATE_DNS_ENABLED_STATE)

    @property
    def vpc_endpoint_private_dns_enabled(self) -> bool | None:
        return _bool_from_state(self.vpc_endpoint_private_dns_enabled_state)

    @property
    def vpc_endpoint_policy_document(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.VPC_ENDPOINT_POLICY_DOCUMENT)

    @property
    def vpc_endpoint_dns_entries(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.VPC_ENDPOINT_DNS_ENTRIES)

    @property
    def vpc_endpoint_dns_names(self) -> list[str]:
        return self.get(AwsResourceMetadata.VPC_ENDPOINT_DNS_NAMES)

    @property
    def vpc_endpoint_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.VPC_ENDPOINT_POSTURE_UNCERTAINTIES)

    @property
    def flow_log_id(self) -> str | None:
        return self.get(AwsResourceMetadata.FLOW_LOG_ID)

    @property
    def flow_log_target_type(self) -> str | None:
        return self.get(AwsResourceMetadata.FLOW_LOG_TARGET_TYPE)

    @property
    def flow_log_target_id(self) -> str | None:
        return self.get(AwsResourceMetadata.FLOW_LOG_TARGET_ID)

    @property
    def flow_log_traffic_type(self) -> str | None:
        return self.get(AwsResourceMetadata.FLOW_LOG_TRAFFIC_TYPE)

    @property
    def flow_log_destination_type(self) -> str | None:
        return self.get(AwsResourceMetadata.FLOW_LOG_DESTINATION_TYPE)

    @property
    def flow_log_destination(self) -> str | None:
        return self.get(AwsResourceMetadata.FLOW_LOG_DESTINATION)

    @property
    def flow_log_log_group_name(self) -> str | None:
        return self.get(AwsResourceMetadata.FLOW_LOG_LOG_GROUP_NAME)

    @property
    def flow_log_iam_role_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.FLOW_LOG_IAM_ROLE_ARN)

    @property
    def flow_log_max_aggregation_interval(self) -> int | None:
        return self.get(AwsResourceMetadata.FLOW_LOG_MAX_AGGREGATION_INTERVAL)

    @property
    def flow_log_destination_options(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.FLOW_LOG_DESTINATION_OPTIONS)

    @property
    def flow_log_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.FLOW_LOG_POSTURE_UNCERTAINTIES)

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
    def s3_object_lock_enabled_state(self) -> str | None:
        return self.get(AwsResourceMetadata.S3_OBJECT_LOCK_ENABLED_STATE)

    @property
    def s3_object_lock_enabled(self) -> bool | None:
        return _bool_from_state(self.s3_object_lock_enabled_state)

    @property
    def s3_object_lock_default_retention_mode(self) -> str | None:
        return self.get(AwsResourceMetadata.S3_OBJECT_LOCK_DEFAULT_RETENTION_MODE)

    @property
    def s3_object_lock_default_retention_days(self) -> int | None:
        return self.get(AwsResourceMetadata.S3_OBJECT_LOCK_DEFAULT_RETENTION_DAYS)

    @property
    def s3_object_lock_default_retention_years(self) -> int | None:
        return self.get(AwsResourceMetadata.S3_OBJECT_LOCK_DEFAULT_RETENTION_YEARS)

    @property
    def s3_object_lock_source_address(self) -> str | None:
        return self.get(AwsResourceMetadata.S3_OBJECT_LOCK_SOURCE_ADDRESS)

    @property
    def s3_object_lock_configuration(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.S3_OBJECT_LOCK_CONFIGURATION)

    @property
    def s3_lifecycle_rules(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.S3_LIFECYCLE_RULES)

    @property
    def s3_lifecycle_rule_count(self) -> int | None:
        return self.get(AwsResourceMetadata.S3_LIFECYCLE_RULE_COUNT)

    @property
    def s3_lifecycle_source_address(self) -> str | None:
        return self.get(AwsResourceMetadata.S3_LIFECYCLE_SOURCE_ADDRESS)

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
    def rds_performance_insights_enabled_state(self) -> str | None:
        return self.get(AwsResourceMetadata.RDS_PERFORMANCE_INSIGHTS_ENABLED_STATE)

    @property
    def rds_performance_insights_enabled(self) -> bool | None:
        return _bool_from_state(self.rds_performance_insights_enabled_state)

    @property
    def rds_enabled_cloudwatch_logs_exports(self) -> list[str]:
        return self.get(AwsResourceMetadata.RDS_ENABLED_CLOUDWATCH_LOGS_EXPORTS)

    @property
    def rds_iam_database_authentication_enabled_state(self) -> str | None:
        return self.get(AwsResourceMetadata.RDS_IAM_DATABASE_AUTHENTICATION_ENABLED_STATE)

    @property
    def rds_iam_database_authentication_enabled(self) -> bool | None:
        return _bool_from_state(self.rds_iam_database_authentication_enabled_state)

    @property
    def rds_kms_key_id(self) -> str | None:
        return self.get(AwsResourceMetadata.RDS_KMS_KEY_ID)

    @property
    def rds_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.RDS_POSTURE_UNCERTAINTIES)

    @property
    def kms_key_usage(self) -> str | None:
        return self.get(AwsResourceMetadata.KMS_KEY_USAGE)

    @property
    def kms_key_spec(self) -> str | None:
        return self.get(AwsResourceMetadata.KMS_KEY_SPEC)

    @property
    def kms_customer_master_key_spec(self) -> str | None:
        return self.get(AwsResourceMetadata.KMS_CUSTOMER_MASTER_KEY_SPEC)

    @property
    def kms_enable_key_rotation_state(self) -> str | None:
        return self.get(AwsResourceMetadata.KMS_ENABLE_KEY_ROTATION_STATE)

    @property
    def kms_enable_key_rotation(self) -> bool | None:
        return _bool_from_state(self.kms_enable_key_rotation_state)

    @property
    def kms_deletion_window_in_days(self) -> int | None:
        return self.get(AwsResourceMetadata.KMS_DELETION_WINDOW_IN_DAYS)

    @property
    def kms_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.KMS_POSTURE_UNCERTAINTIES)

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

    def set_s3_object_lock_posture(
        self,
        *,
        enabled_state: str | None,
        default_retention_mode: str | None,
        default_retention_days: int | None,
        default_retention_years: int | None,
        configuration: dict[str, Any] | None,
        source_address: str | None,
    ) -> None:
        self.set(AwsResourceMetadata.S3_OBJECT_LOCK_ENABLED_STATE, enabled_state)
        self.set(AwsResourceMetadata.S3_OBJECT_LOCK_DEFAULT_RETENTION_MODE, default_retention_mode)
        self.set(AwsResourceMetadata.S3_OBJECT_LOCK_DEFAULT_RETENTION_DAYS, default_retention_days)
        self.set(AwsResourceMetadata.S3_OBJECT_LOCK_DEFAULT_RETENTION_YEARS, default_retention_years)
        self.set(AwsResourceMetadata.S3_OBJECT_LOCK_CONFIGURATION, configuration)
        self.set(AwsResourceMetadata.S3_OBJECT_LOCK_SOURCE_ADDRESS, source_address)

    def set_s3_lifecycle_posture(
        self,
        *,
        rules: list[dict[str, Any]],
        rule_count: int | None,
        source_address: str | None,
    ) -> None:
        self.set(AwsResourceMetadata.S3_LIFECYCLE_RULES, rules)
        self.set(AwsResourceMetadata.S3_LIFECYCLE_RULE_COUNT, rule_count)
        self.set(AwsResourceMetadata.S3_LIFECYCLE_SOURCE_ADDRESS, source_address)

    def extend_s3_posture_uncertainties(self, values: Sequence[str | None]) -> None:
        self.extend(AwsResourceMetadata.S3_POSTURE_UNCERTAINTIES, values)

    def set_secrets_manager_rotation_posture(
        self,
        *,
        secret_id: str | None,
        source_address: str | None,
        rotation_lambda_arn: str | None,
        automatically_after_days: int | None,
        duration: str | None,
        schedule_expression: str | None,
        rotation_rules: dict[str, Any] | None,
    ) -> None:
        self.set(AwsResourceMetadata.SECRETS_MANAGER_ROTATION_SECRET_ID, secret_id)
        self.set(AwsResourceMetadata.SECRETS_MANAGER_ROTATION_SOURCE_ADDRESS, source_address)
        self.set(AwsResourceMetadata.SECRETS_MANAGER_ROTATION_LAMBDA_ARN, rotation_lambda_arn)
        self.set(AwsResourceMetadata.SECRETS_MANAGER_ROTATION_AUTOMATICALLY_AFTER_DAYS, automatically_after_days)
        self.set(AwsResourceMetadata.SECRETS_MANAGER_ROTATION_DURATION, duration)
        self.set(AwsResourceMetadata.SECRETS_MANAGER_ROTATION_SCHEDULE_EXPRESSION, schedule_expression)
        self.set(AwsResourceMetadata.SECRETS_MANAGER_ROTATION_RULES, rotation_rules)

    def extend_secrets_manager_posture_uncertainties(self, values: Sequence[str | None]) -> None:
        self.extend(AwsResourceMetadata.SECRETS_MANAGER_POSTURE_UNCERTAINTIES, values)

    def set_privileged_access_grants(self, values: Sequence[dict[str, Any]]) -> None:
        self.set(AwsResourceMetadata.PRIVILEGED_ACCESS_GRANTS, list(values))

    def extend_iam_assignment_posture_uncertainties(self, values: Sequence[str | None]) -> None:
        self.extend(AwsResourceMetadata.IAM_ASSIGNMENT_POSTURE_UNCERTAINTIES, values)

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

    def add_unresolved_secret_reference(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_SECRET_REFERENCES, value)

    def add_unresolved_function_reference(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_FUNCTION_REFERENCES, value)

    def add_resource_policy_source_address(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES, value)

    @property
    def resource_policy_source_addresses(self) -> list[str]:
        return self.get(AwsResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES)


def _bool_from_state(state: str | None) -> bool | None:
    if state == STATE_ENABLED:
        return True
    if state == STATE_DISABLED:
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
