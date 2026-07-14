from __future__ import annotations

from typing import Any

from tfstride.providers.coercion import STATE_CONFIGURED, STATE_NOT_CONFIGURED
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_facts.base import GcpBaseFacts


class GcpMessagingFacts(GcpBaseFacts):
    __slots__ = ()

    @property
    def pubsub_topic_kms_key_name(self) -> str | None:
        return self.get(GcpResourceMetadata.PUBSUB_TOPIC_KMS_KEY_NAME)

    @property
    def pubsub_topic_cmek_state(self) -> str | None:
        return self.get(GcpResourceMetadata.PUBSUB_TOPIC_CMEK_STATE)

    @property
    def pubsub_topic_customer_managed_encryption(self) -> bool | None:
        state = self.pubsub_topic_cmek_state
        if state == STATE_CONFIGURED:
            return True
        if state == STATE_NOT_CONFIGURED:
            return False
        return None

    @property
    def pubsub_topic_message_retention_duration(self) -> str | None:
        return self.get(GcpResourceMetadata.PUBSUB_TOPIC_MESSAGE_RETENTION_DURATION)

    @property
    def pubsub_topic_message_retention_seconds(self) -> int | None:
        return self.get(GcpResourceMetadata.PUBSUB_TOPIC_MESSAGE_RETENTION_SECONDS)

    @property
    def pubsub_topic_message_retention_state(self) -> str | None:
        return self.get(GcpResourceMetadata.PUBSUB_TOPIC_MESSAGE_RETENTION_STATE)

    @property
    def pubsub_topic_message_storage_policy(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.PUBSUB_TOPIC_MESSAGE_STORAGE_POLICY)

    @property
    def pubsub_topic_schema_settings(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.PUBSUB_TOPIC_SCHEMA_SETTINGS)

    @property
    def pubsub_subscription_ack_deadline_seconds(self) -> int | None:
        return self.get(GcpResourceMetadata.PUBSUB_SUBSCRIPTION_ACK_DEADLINE_SECONDS)

    @property
    def pubsub_subscription_dead_letter_policy(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.PUBSUB_SUBSCRIPTION_DEAD_LETTER_POLICY)

    @property
    def pubsub_subscription_dead_letter_policy_state(self) -> str | None:
        return self.get(GcpResourceMetadata.PUBSUB_SUBSCRIPTION_DEAD_LETTER_POLICY_STATE)

    @property
    def pubsub_subscription_dead_letter_topic(self) -> str | None:
        return self.get(GcpResourceMetadata.PUBSUB_SUBSCRIPTION_DEAD_LETTER_TOPIC)

    @property
    def pubsub_subscription_dead_letter_max_delivery_attempts(self) -> int | None:
        return self.get(GcpResourceMetadata.PUBSUB_SUBSCRIPTION_DEAD_LETTER_MAX_DELIVERY_ATTEMPTS)

    @property
    def pubsub_subscription_expiration_policy(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.PUBSUB_SUBSCRIPTION_EXPIRATION_POLICY)

    @property
    def pubsub_subscription_filter(self) -> str | None:
        return self.get(GcpResourceMetadata.PUBSUB_SUBSCRIPTION_FILTER)

    @property
    def pubsub_subscription_message_retention_duration(self) -> str | None:
        return self.get(GcpResourceMetadata.PUBSUB_SUBSCRIPTION_MESSAGE_RETENTION_DURATION)

    @property
    def pubsub_subscription_message_retention_seconds(self) -> int | None:
        return self.get(GcpResourceMetadata.PUBSUB_SUBSCRIPTION_MESSAGE_RETENTION_SECONDS)

    @property
    def pubsub_subscription_message_retention_state(self) -> str | None:
        return self.get(GcpResourceMetadata.PUBSUB_SUBSCRIPTION_MESSAGE_RETENTION_STATE)

    @property
    def pubsub_subscription_push_config(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.PUBSUB_SUBSCRIPTION_PUSH_CONFIG)

    @property
    def pubsub_subscription_retain_acked_messages(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.PUBSUB_SUBSCRIPTION_RETAIN_ACKED_MESSAGES)

    @property
    def pubsub_subscription_retry_policy(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.PUBSUB_SUBSCRIPTION_RETRY_POLICY)

    @property
    def pubsub_posture_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.PUBSUB_POSTURE_UNCERTAINTIES)
