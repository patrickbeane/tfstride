from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.resource_facts.base import AwsBaseFacts, _bool_from_state


class AwsDataFacts(AwsBaseFacts):
    __slots__ = ()

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

    def add_unresolved_secret_arn(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_SECRET_ARNS, value)

    def add_unresolved_secret_reference(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_SECRET_REFERENCES, value)
