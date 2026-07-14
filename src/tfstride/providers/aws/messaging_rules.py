from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.aws.resource_facts import AwsResourceFacts, aws_facts
from tfstride.providers.coercion import STATE_NOT_CONFIGURED

_AWS_SNS_TOPIC = "aws_sns_topic"
_AWS_SQS_QUEUE = "aws_sqs_queue"
_MIN_SQS_MESSAGE_RETENTION_DAYS = 4
_MIN_SQS_MESSAGE_RETENTION_SECONDS = _MIN_SQS_MESSAGE_RETENTION_DAYS * 24 * 60 * 60
_NON_CUSTOMER_MANAGED_ENCRYPTION_STATES = frozenset({"service_managed", "absent"})


class AwsMessagingPostureRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_sns_customer_managed_encryption_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for topic in context.inventory.by_type(_AWS_SNS_TOPIC):
            facts = aws_facts(topic)
            if facts.sns_encryption_ownership_state not in _NON_CUSTOMER_MANAGED_ENCRYPTION_STATES:
                continue
            severity_reasoning = _messaging_posture_severity()
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[topic.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{topic.display_name} does not configure a customer-managed KMS key for SNS message "
                        "encryption. This is an encryption ownership and key-control posture finding; it does not "
                        "claim that the topic is unencrypted."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(topic)),
                        evidence_item("encryption_ownership", _sns_encryption_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_sqs_customer_managed_encryption_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for queue in context.inventory.by_type(_AWS_SQS_QUEUE):
            facts = aws_facts(queue)
            if facts.sqs_encryption_ownership_state not in _NON_CUSTOMER_MANAGED_ENCRYPTION_STATES:
                continue
            severity_reasoning = _messaging_posture_severity()
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[queue.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{queue.display_name} does not configure a customer-managed KMS key for SQS message "
                        "encryption. This is an encryption ownership and key-control posture finding; it does not "
                        "claim that the queue is unencrypted."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(queue)),
                        evidence_item("encryption_ownership", _sqs_encryption_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_sqs_message_retention_insufficient(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for queue in context.inventory.by_type(_AWS_SQS_QUEUE):
            facts = aws_facts(queue)
            retention_seconds = facts.sqs_message_retention_seconds
            if retention_seconds is None or retention_seconds >= _MIN_SQS_MESSAGE_RETENTION_SECONDS:
                continue
            severity_reasoning = _messaging_posture_severity()
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[queue.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{queue.display_name} retains SQS messages for only {retention_seconds} seconds, below "
                        f"the {_MIN_SQS_MESSAGE_RETENTION_DAYS}-day recovery baseline. Short retention can reduce "
                        "the time available to replay messages after subscriber failures or destructive changes."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(queue)),
                        evidence_item(
                            "message_retention_posture",
                            [
                                f"message_retention_seconds={retention_seconds}",
                                f"minimum_message_retention_days={_MIN_SQS_MESSAGE_RETENTION_DAYS}",
                                f"minimum_message_retention_seconds={_MIN_SQS_MESSAGE_RETENTION_SECONDS}",
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_sqs_dead_letter_queue_not_configured(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for queue in context.inventory.by_type(_AWS_SQS_QUEUE):
            facts = aws_facts(queue)
            if facts.sqs_redrive_state != STATE_NOT_CONFIGURED:
                continue
            severity_reasoning = _messaging_posture_severity()
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[queue.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{queue.display_name} does not configure an SQS dead-letter queue. Poison messages or "
                        "repeated delivery failures can consume subscriber capacity and reduce recovery options "
                        "for failed processing."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(queue)),
                        evidence_item("dead_letter_posture", _dead_letter_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _messaging_posture_severity():
    return build_severity_reasoning(
        internet_exposure=False,
        privilege_breadth=0,
        data_sensitivity=2,
        lateral_movement=0,
        blast_radius=1,
    )


def _target_resource_evidence(resource: NormalizedResource) -> list[str]:
    values = [f"address={resource.address}", f"resource_type={resource.resource_type}"]
    if resource.identifier:
        values.append(f"identifier={resource.identifier}")
    if resource.arn:
        values.append(f"arn={resource.arn}")
    return values


def _sns_encryption_evidence(facts: AwsResourceFacts) -> list[str]:
    return [
        f"encryption_ownership_state={facts.sns_encryption_ownership_state}",
        f"kms_master_key_id={facts.sns_kms_master_key_id or 'unset'}",
        "finding_scope=customer-managed key ownership and control posture",
    ]


def _sqs_encryption_evidence(facts: AwsResourceFacts) -> list[str]:
    return [
        f"encryption_ownership_state={facts.sqs_encryption_ownership_state}",
        f"kms_master_key_id={facts.sqs_kms_master_key_id or 'unset'}",
        f"sqs_managed_sse_enabled_state={facts.sqs_managed_sse_enabled_state or 'unset'}",
        "finding_scope=customer-managed key ownership and control posture",
    ]


def _dead_letter_evidence(facts: AwsResourceFacts) -> list[str]:
    return [
        f"redrive_state={facts.sqs_redrive_state}",
        f"dead_letter_target_arn={facts.sqs_redrive_target_arn or 'unset'}",
        f"max_receive_count={facts.sqs_redrive_max_receive_count if facts.sqs_redrive_max_receive_count is not None else 'unset'}",
        f"redrive_source_address={facts.sqs_redrive_source_address or 'unset'}",
    ]
