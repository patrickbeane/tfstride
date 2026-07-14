from __future__ import annotations

from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.coercion import STATE_CONFIGURED, STATE_NOT_CONFIGURED
from tfstride.providers.gcp.resource_facts import GcpResourceFacts, gcp_facts

_PUBSUB_TOPIC_RESOURCE_TYPE = "google_pubsub_topic"
_PUBSUB_SUBSCRIPTION_RESOURCE_TYPE = "google_pubsub_subscription"
_PUBSUB_MIN_MESSAGE_RETENTION_DAYS = 7
_PUBSUB_MIN_MESSAGE_RETENTION_SECONDS = _PUBSUB_MIN_MESSAGE_RETENTION_DAYS * 24 * 60 * 60


class GcpPubSubPostureRuleDetectors:
    def detect_pubsub_topic_customer_managed_encryption_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for topic in context.inventory.by_type(_PUBSUB_TOPIC_RESOURCE_TYPE):
            topic_facts = gcp_facts(topic)
            if topic_facts.pubsub_topic_cmek_state != STATE_NOT_CONFIGURED:
                continue
            severity_reasoning = _pubsub_posture_severity()
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[topic.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{topic.display_name} relies on Google-managed Pub/Sub encryption rather than a "
                        "customer-managed Cloud KMS key. Google-managed encryption still protects message "
                        "data; this finding concerns key ownership, rotation, audit separation, and compliance "
                        "posture."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(topic)),
                        evidence_item("encryption_ownership", _cmek_evidence(topic_facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_pubsub_message_retention_insufficient(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for resource in context.inventory.by_type(
            _PUBSUB_TOPIC_RESOURCE_TYPE,
            _PUBSUB_SUBSCRIPTION_RESOURCE_TYPE,
        ):
            retention = _message_retention_posture(resource, gcp_facts(resource))
            if retention is None or retention.seconds >= _PUBSUB_MIN_MESSAGE_RETENTION_SECONDS:
                continue
            severity_reasoning = _pubsub_posture_severity()
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[resource.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{resource.display_name} retains Pub/Sub messages for only {retention.seconds} seconds, "
                        f"below the {_PUBSUB_MIN_MESSAGE_RETENTION_DAYS}-day recovery baseline. Short retention "
                        "can reduce the time available to replay messages after subscriber failures or "
                        "destructive changes."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(resource)),
                        evidence_item(
                            "message_retention_posture",
                            [
                                f"message_retention_duration={retention.duration}",
                                f"message_retention_seconds={retention.seconds}",
                                f"minimum_message_retention_days={_PUBSUB_MIN_MESSAGE_RETENTION_DAYS}",
                                (f"minimum_message_retention_seconds={_PUBSUB_MIN_MESSAGE_RETENTION_SECONDS}"),
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_pubsub_subscription_dead_letter_policy_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for subscription in context.inventory.by_type(_PUBSUB_SUBSCRIPTION_RESOURCE_TYPE):
            subscription_facts = gcp_facts(subscription)
            if subscription_facts.pubsub_subscription_dead_letter_policy_state != STATE_NOT_CONFIGURED:
                continue
            severity_reasoning = _pubsub_posture_severity()
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[subscription.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{subscription.display_name} does not configure a Pub/Sub dead-letter policy. "
                        "Poison messages or repeated delivery failures can consume subscriber capacity and "
                        "reduce recovery options for failed processing."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(subscription)),
                        evidence_item(
                            "dead_letter_posture",
                            [
                                (
                                    "dead_letter_policy_state="
                                    f"{subscription_facts.pubsub_subscription_dead_letter_policy_state}"
                                ),
                                "dead_letter_topic=unset",
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


class _MessageRetentionPosture:
    def __init__(self, duration: str, seconds: int) -> None:
        self.duration = duration
        self.seconds = seconds


def _message_retention_posture(
    resource: NormalizedResource,
    facts: GcpResourceFacts,
) -> _MessageRetentionPosture | None:
    if resource.resource_type == _PUBSUB_TOPIC_RESOURCE_TYPE:
        state = facts.pubsub_topic_message_retention_state
        duration = facts.pubsub_topic_message_retention_duration
        seconds = facts.pubsub_topic_message_retention_seconds
    else:
        state = facts.pubsub_subscription_message_retention_state
        duration = facts.pubsub_subscription_message_retention_duration
        seconds = facts.pubsub_subscription_message_retention_seconds

    if state != STATE_CONFIGURED or duration is None or seconds is None:
        return None
    return _MessageRetentionPosture(duration, seconds)


def _pubsub_posture_severity():
    return build_severity_reasoning(
        internet_exposure=False,
        privilege_breadth=0,
        data_sensitivity=2,
        lateral_movement=0,
        blast_radius=1,
    )


def _target_resource_evidence(resource: NormalizedResource) -> list[str]:
    return [f"address={resource.address}", f"resource_type={resource.resource_type}"]


def _cmek_evidence(facts: GcpResourceFacts) -> list[str]:
    return [
        f"cmek_state={facts.pubsub_topic_cmek_state}",
        f"kms_key_name={facts.pubsub_topic_kms_key_name or 'unset'}",
    ]
