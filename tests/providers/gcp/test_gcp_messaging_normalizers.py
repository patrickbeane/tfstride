from __future__ import annotations

from tests.providers.gcp.normalizer_support import GcpNormalizerTestCase, _terraform_resource
from tfstride.providers.coercion import STATE_CONFIGURED, STATE_NOT_CONFIGURED, STATE_UNKNOWN
from tfstride.providers.gcp.data_normalizers import normalize_pubsub_subscription, normalize_pubsub_topic
from tfstride.providers.gcp.resource_facts import gcp_facts


class GcpMessagingNormalizerTests(GcpNormalizerTestCase):
    def test_pubsub_topic_normalizes_cmek_and_message_retention_posture(self) -> None:
        normalized = normalize_pubsub_topic(
            _terraform_resource(
                "google_pubsub_topic.events",
                "google_pubsub_topic",
                {
                    "name": "events",
                    "project": "tfstride-demo",
                    "kms_key_name": "projects/tfstride-demo/locations/global/keyRings/app/cryptoKeys/pubsub",
                    "message_retention_duration": "604800s",
                    "message_storage_policy": [{"allowed_persistence_regions": ["us-central1"]}],
                    "schema_settings": [{"schema": "projects/tfstride-demo/schemas/events"}],
                },
            )
        )

        facts = gcp_facts(normalized)

        self.assertEqual(facts.pubsub_topic_cmek_state, STATE_CONFIGURED)
        self.assertTrue(facts.pubsub_topic_customer_managed_encryption)
        self.assertEqual(
            facts.pubsub_topic_kms_key_name,
            "projects/tfstride-demo/locations/global/keyRings/app/cryptoKeys/pubsub",
        )
        self.assertEqual(facts.pubsub_topic_message_retention_duration, "604800s")
        self.assertEqual(facts.pubsub_topic_message_retention_seconds, 604800)
        self.assertEqual(facts.pubsub_topic_message_retention_state, STATE_CONFIGURED)
        self.assertEqual(
            facts.pubsub_topic_message_storage_policy,
            [{"allowed_persistence_regions": ["us-central1"]}],
        )
        self.assertEqual(
            facts.pubsub_topic_schema_settings,
            [{"schema": "projects/tfstride-demo/schemas/events"}],
        )
        self.assertEqual(facts.pubsub_posture_uncertainties, [])

    def test_pubsub_subscription_normalizes_retention_and_dead_letter_posture(self) -> None:
        normalized = normalize_pubsub_subscription(
            _terraform_resource(
                "google_pubsub_subscription.events",
                "google_pubsub_subscription",
                {
                    "name": "events",
                    "project": "tfstride-demo",
                    "topic": "google_pubsub_topic.events.id",
                    "ack_deadline_seconds": 20,
                    "message_retention_duration": "86400s",
                    "dead_letter_policy": [
                        {
                            "dead_letter_topic": "projects/tfstride-demo/topics/events-dead-letter",
                            "max_delivery_attempts": 5,
                        }
                    ],
                    "expiration_policy": [{"ttl": "2592000s"}],
                    "filter": 'attributes.type = "event"',
                    "push_config": [{"push_endpoint": "https://worker.example.test/events"}],
                    "retain_acked_messages": True,
                    "retry_policy": [{"minimum_backoff": "10s", "maximum_backoff": "600s"}],
                },
            )
        )

        facts = gcp_facts(normalized)

        self.assertEqual(facts.pubsub_subscription_ack_deadline_seconds, 20)
        self.assertEqual(facts.pubsub_subscription_message_retention_duration, "86400s")
        self.assertEqual(facts.pubsub_subscription_message_retention_seconds, 86400)
        self.assertEqual(facts.pubsub_subscription_message_retention_state, STATE_CONFIGURED)
        self.assertEqual(facts.pubsub_subscription_dead_letter_policy_state, STATE_CONFIGURED)
        self.assertEqual(
            facts.pubsub_subscription_dead_letter_topic,
            "projects/tfstride-demo/topics/events-dead-letter",
        )
        self.assertEqual(facts.pubsub_subscription_dead_letter_max_delivery_attempts, 5)
        self.assertEqual(
            facts.pubsub_subscription_dead_letter_policy,
            [
                {
                    "dead_letter_topic": "projects/tfstride-demo/topics/events-dead-letter",
                    "max_delivery_attempts": 5,
                }
            ],
        )
        self.assertEqual(facts.pubsub_subscription_expiration_policy, [{"ttl": "2592000s"}])
        self.assertEqual(facts.pubsub_subscription_filter, 'attributes.type = "event"')
        self.assertEqual(
            facts.pubsub_subscription_push_config,
            [{"push_endpoint": "https://worker.example.test/events"}],
        )
        self.assertTrue(facts.pubsub_subscription_retain_acked_messages)
        self.assertEqual(
            facts.pubsub_subscription_retry_policy,
            [{"minimum_backoff": "10s", "maximum_backoff": "600s"}],
        )
        self.assertEqual(facts.pubsub_posture_uncertainties, [])

    def test_pubsub_missing_optional_posture_is_not_configured(self) -> None:
        topic = normalize_pubsub_topic(
            _terraform_resource(
                "google_pubsub_topic.events",
                "google_pubsub_topic",
                {"name": "events"},
            )
        )
        subscription = normalize_pubsub_subscription(
            _terraform_resource(
                "google_pubsub_subscription.events",
                "google_pubsub_subscription",
                {"name": "events", "topic": "google_pubsub_topic.events.id"},
            )
        )

        topic_facts = gcp_facts(topic)
        subscription_facts = gcp_facts(subscription)

        self.assertEqual(topic_facts.pubsub_topic_cmek_state, STATE_NOT_CONFIGURED)
        self.assertFalse(topic_facts.pubsub_topic_customer_managed_encryption)
        self.assertEqual(topic_facts.pubsub_topic_message_retention_state, STATE_NOT_CONFIGURED)
        self.assertIsNone(topic_facts.pubsub_topic_message_retention_duration)
        self.assertIsNone(topic_facts.pubsub_topic_message_retention_seconds)
        self.assertEqual(subscription_facts.pubsub_subscription_message_retention_state, STATE_NOT_CONFIGURED)
        self.assertEqual(subscription_facts.pubsub_subscription_dead_letter_policy_state, STATE_NOT_CONFIGURED)
        self.assertIsNone(subscription_facts.pubsub_subscription_dead_letter_topic)
        self.assertIsNone(subscription_facts.pubsub_subscription_dead_letter_max_delivery_attempts)
        self.assertEqual(topic_facts.pubsub_posture_uncertainties, [])
        self.assertEqual(subscription_facts.pubsub_posture_uncertainties, [])

    def test_pubsub_unknown_posture_is_preserved_as_uncertainty(self) -> None:
        topic = normalize_pubsub_topic(
            _terraform_resource(
                "google_pubsub_topic.events",
                "google_pubsub_topic",
                {
                    "name": "events",
                    "kms_key_name": "projects/tfstride-demo/locations/global/keyRings/app/cryptoKeys/pubsub",
                    "message_retention_duration": "604800s",
                },
                unknown_values={"kms_key_name": True, "message_retention_duration": True},
            )
        )
        subscription = normalize_pubsub_subscription(
            _terraform_resource(
                "google_pubsub_subscription.events",
                "google_pubsub_subscription",
                {
                    "name": "events",
                    "topic": "google_pubsub_topic.events.id",
                    "message_retention_duration": "86400s",
                    "dead_letter_policy": [
                        {
                            "dead_letter_topic": "projects/tfstride-demo/topics/events-dead-letter",
                            "max_delivery_attempts": 5,
                        }
                    ],
                },
                unknown_values={
                    "message_retention_duration": True,
                    "dead_letter_policy": [{"dead_letter_topic": True, "max_delivery_attempts": True}],
                },
            )
        )

        topic_facts = gcp_facts(topic)
        subscription_facts = gcp_facts(subscription)

        self.assertEqual(topic_facts.pubsub_topic_cmek_state, STATE_UNKNOWN)
        self.assertIsNone(topic_facts.pubsub_topic_customer_managed_encryption)
        self.assertEqual(topic_facts.pubsub_topic_message_retention_state, STATE_UNKNOWN)
        self.assertEqual(
            topic_facts.pubsub_posture_uncertainties,
            [
                "kms_key_name is unknown after planning",
                "message_retention_duration is unknown after planning",
            ],
        )
        self.assertEqual(subscription_facts.pubsub_subscription_message_retention_state, STATE_UNKNOWN)
        self.assertEqual(subscription_facts.pubsub_subscription_dead_letter_policy_state, STATE_UNKNOWN)
        self.assertEqual(
            subscription_facts.pubsub_posture_uncertainties,
            [
                "message_retention_duration is unknown after planning",
                "dead_letter_policy.dead_letter_topic is unknown after planning",
                "dead_letter_policy.max_delivery_attempts is unknown after planning",
            ],
        )
