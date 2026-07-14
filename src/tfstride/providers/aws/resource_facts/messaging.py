from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.resource_facts.base import AwsBaseFacts, _bool_from_state


class AwsMessagingFacts(AwsBaseFacts):
    __slots__ = ()

    @property
    def sns_display_name(self) -> str | None:
        return self.get(AwsResourceMetadata.SNS_DISPLAY_NAME)

    @property
    def sns_kms_master_key_id(self) -> str | None:
        return self.get(AwsResourceMetadata.SNS_KMS_MASTER_KEY_ID)

    @property
    def sns_encryption_ownership_state(self) -> str | None:
        return self.get(AwsResourceMetadata.SNS_ENCRYPTION_OWNERSHIP_STATE)

    @property
    def sns_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.SNS_POSTURE_UNCERTAINTIES)

    @property
    def sqs_queue_url(self) -> str | None:
        return self.get(AwsResourceMetadata.SQS_QUEUE_URL)

    @property
    def sqs_kms_master_key_id(self) -> str | None:
        return self.get(AwsResourceMetadata.SQS_KMS_MASTER_KEY_ID)

    @property
    def sqs_managed_sse_enabled_state(self) -> str | None:
        return self.get(AwsResourceMetadata.SQS_MANAGED_SSE_ENABLED_STATE)

    @property
    def sqs_managed_sse_enabled(self) -> bool | None:
        return _bool_from_state(self.sqs_managed_sse_enabled_state)

    @property
    def sqs_encryption_ownership_state(self) -> str | None:
        return self.get(AwsResourceMetadata.SQS_ENCRYPTION_OWNERSHIP_STATE)

    @property
    def sqs_message_retention_seconds(self) -> int | None:
        return self.get(AwsResourceMetadata.SQS_MESSAGE_RETENTION_SECONDS)

    @property
    def sqs_redrive_state(self) -> str | None:
        return self.get(AwsResourceMetadata.SQS_REDRIVE_STATE)

    @property
    def sqs_redrive_target_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.SQS_REDRIVE_TARGET_ARN)

    @property
    def sqs_redrive_max_receive_count(self) -> int | None:
        return self.get(AwsResourceMetadata.SQS_REDRIVE_MAX_RECEIVE_COUNT)

    @property
    def sqs_redrive_policy(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.SQS_REDRIVE_POLICY)

    @property
    def sqs_redrive_source_address(self) -> str | None:
        return self.get(AwsResourceMetadata.SQS_REDRIVE_SOURCE_ADDRESS)

    @property
    def sqs_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.SQS_POSTURE_UNCERTAINTIES)

    @property
    def unresolved_sqs_queue_references(self) -> list[str]:
        return self.get(AwsResourceMetadata.UNRESOLVED_SQS_QUEUE_REFERENCES)

    def set_sqs_redrive_posture(
        self,
        *,
        state: str,
        target_arn: str | None,
        max_receive_count: int | None,
        policy: dict[str, Any] | None,
        source_address: str | None,
    ) -> None:
        self.set(AwsResourceMetadata.SQS_REDRIVE_STATE, state)
        self.set(AwsResourceMetadata.SQS_REDRIVE_TARGET_ARN, target_arn)
        self.set(AwsResourceMetadata.SQS_REDRIVE_MAX_RECEIVE_COUNT, max_receive_count)
        self.set(AwsResourceMetadata.SQS_REDRIVE_POLICY, policy)
        self.set(AwsResourceMetadata.SQS_REDRIVE_SOURCE_ADDRESS, source_address)

    def extend_sqs_posture_uncertainties(self, values: Sequence[str | None]) -> None:
        self.extend(AwsResourceMetadata.SQS_POSTURE_UNCERTAINTIES, values)

    def add_unresolved_sqs_queue_reference(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_SQS_QUEUE_REFERENCES, value)
