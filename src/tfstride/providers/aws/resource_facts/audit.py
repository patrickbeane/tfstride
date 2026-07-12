from __future__ import annotations

from typing import Any

from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.resource_facts.base import _bool_from_state


class AwsAuditFacts:
    __slots__ = ()

    @property
    def audit_detection_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.AUDIT_DETECTION_POSTURE_UNCERTAINTIES)

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
