from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.resource_facts.base import _bool_from_state

_S3_BUCKET_KEY_ENABLED = "enabled"
_S3_BUCKET_KEY_DISABLED = "disabled"


class AwsStorageFacts:
    __slots__ = ()

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

    def set_public_access_block(self, value: dict[str, bool] | None) -> None:
        self.set(AwsResourceMetadata.PUBLIC_ACCESS_BLOCK, value)

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

    def add_unresolved_bucket_reference(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_BUCKET_REFERENCES, value)
