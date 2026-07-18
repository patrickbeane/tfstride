from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.secret_settings import (
    SensitiveSettingCategory,
    SensitiveSettingClassification,
    redacted_sensitive_setting_evidence,
)

_AWS_ECS_TASK_DEFINITION = "aws_ecs_task_definition"


class AwsEcsSecretDeliveryRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_inline_sensitive_environment_value(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for task_definition in context.inventory.by_type(_AWS_ECS_TASK_DEFINITION):
            for record in aws_facts(task_definition).ecs_secret_references:
                classification = _literal_sensitive_setting(record)
                if classification is None:
                    continue

                severity_reasoning = build_severity_reasoning(
                    internet_exposure=False,
                    privilege_breadth=0,
                    data_sensitivity=2,
                    lateral_movement=0,
                    blast_radius=1,
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=[task_definition.address],
                        trust_boundary_id=None,
                        rationale=(
                            f"{task_definition.display_name} materializes the sensitive-classified setting "
                            f"{classification.normalized_name} as a literal ECS environment value. Literal "
                            "configuration can place credential material in Terraform plan/state and ECS task "
                            "definition surfaces; use ECS secret injection backed by Secrets Manager or Systems "
                            "Manager Parameter Store. The literal value is intentionally excluded from this finding."
                        ),
                        evidence=collect_evidence(
                            evidence_item("target_resource", _target_resource_evidence(task_definition)),
                            evidence_item(
                                "sensitive_setting",
                                [
                                    redacted_sensitive_setting_evidence(
                                        classification,
                                        path=_setting_path(record),
                                    )
                                ],
                            ),
                            evidence_item("delivery_posture", _delivery_posture_evidence(record)),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings


def _literal_sensitive_setting(record: Mapping[str, Any]) -> SensitiveSettingClassification | None:
    if record.get("state") != "literal":
        return None
    normalized_name = record.get("normalized_setting_name")
    category = record.get("sensitive_category")
    if not isinstance(normalized_name, str) or not normalized_name or not isinstance(category, str):
        return None
    try:
        sensitive_category = SensitiveSettingCategory(category)
    except ValueError:
        return None
    return SensitiveSettingClassification(
        normalized_name=normalized_name,
        category=sensitive_category,
    )


def _setting_path(record: Mapping[str, Any]) -> str | None:
    value_path = record.get("value_path")
    if isinstance(value_path, str) and value_path:
        return value_path
    path = record.get("path")
    return path if isinstance(path, str) and path else None


def _target_resource_evidence(resource: NormalizedResource) -> list[str]:
    values = [f"address={resource.address}", f"type={resource.resource_type}"]
    if resource.identifier:
        values.append(f"identifier={resource.identifier}")
    if resource.arn:
        values.append(f"arn={resource.arn}")
    return values


def _delivery_posture_evidence(record: Mapping[str, Any]) -> list[str]:
    return [
        f"source={record.get('source') or 'unknown'}",
        f"container_name={record.get('container_name') or 'unknown'}",
        f"state={record.get('state') or 'unknown'}",
    ]
