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

    def detect_secret_access_blast_radius(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for task_definition in context.inventory.by_type(_AWS_ECS_TASK_DEFINITION):
            facts = aws_facts(task_definition)
            if facts.ecs_secret_access_path_uncertainties:
                continue

            consumed_secret_arns = _consumed_secret_arns(facts.ecs_secret_access_paths)
            if not consumed_secret_arns:
                continue

            paths_by_role = _access_paths_by_role(facts.ecs_secret_access_paths)
            for role_address, access_paths in paths_by_role.items():
                broad_grants = _broad_secret_grants(access_paths, consumed_secret_arns)
                if not broad_grants:
                    continue

                role_arn = _first_string(access_paths, "role_arn")
                severity_reasoning = build_severity_reasoning(
                    internet_exposure=False,
                    privilege_breadth=2,
                    data_sensitivity=2,
                    lateral_movement=0,
                    blast_radius=2,
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=[task_definition.address, role_address],
                        trust_boundary_id=None,
                        rationale=(
                            f"{task_definition.display_name} consumes {len(consumed_secret_arns)} exact Secrets "
                            f"Manager secret reference(s), but its ECS task execution role {role_address} has "
                            "modeled identity-policy grants with materially broader Secrets Manager action or "
                            "resource scope. ECS uses the execution role for agent-side secret delivery; the task "
                            "role remains the separate application runtime identity. Narrow the execution role to "
                            "`secretsmanager:GetSecretValue` on only the secret ARNs required by this task."
                        ),
                        evidence=collect_evidence(
                            evidence_item("target_resource", _target_resource_evidence(task_definition)),
                            evidence_item(
                                "execution_role",
                                _execution_role_evidence(role_address, role_arn),
                            ),
                            evidence_item(
                                "consumed_secrets",
                                _consumed_secret_evidence(access_paths, consumed_secret_arns),
                            ),
                            evidence_item("broader_policy_grants", broad_grants),
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


def _consumed_secret_arns(access_paths: list[dict[str, Any]]) -> set[str]:
    return {
        secret_arn for path in access_paths if isinstance((secret_arn := path.get("secret_arn")), str) and secret_arn
    }


def _access_paths_by_role(access_paths: list[dict[str, Any]]) -> dict[str, list[Mapping[str, Any]]]:
    paths_by_role: dict[str, list[Mapping[str, Any]]] = {}
    for path in access_paths:
        role_address = path.get("role_address")
        if not isinstance(role_address, str) or not role_address:
            continue
        paths_by_role.setdefault(role_address, []).append(path)
    return paths_by_role


def _broad_secret_grants(
    access_paths: list[Mapping[str, Any]],
    consumed_secret_arns: set[str],
) -> list[str]:
    if any(
        path.get("access_state") != "allowed"
        or path.get("role_policy_complete") is not True
        or path.get("explicit_deny") is True
        or path.get("conditional_evaluation_required") is True
        for path in access_paths
    ):
        return []

    grants: list[str] = []
    seen_statements: set[tuple[tuple[str, ...], tuple[str, ...]]] = set()
    for path in access_paths:
        policy_statements = path.get("policy_statements")
        if not isinstance(policy_statements, list):
            continue
        for statement in policy_statements:
            if not isinstance(statement, Mapping):
                continue
            if statement.get("effect") != "allow" or statement.get("conditional") is not False:
                continue
            actions = _string_values(statement.get("actions"))
            resources = _string_values(statement.get("resources"))
            fingerprint = (tuple(actions), tuple(resources))
            if fingerprint in seen_statements:
                continue
            seen_statements.add(fingerprint)

            reasons = _grant_breadth_reasons(actions, resources, consumed_secret_arns)
            if not reasons:
                continue
            grants.append(f"reasons={','.join(reasons)}; actions={','.join(actions)}; resources={','.join(resources)}")
    return grants


def _grant_breadth_reasons(
    actions: list[str],
    resources: list[str],
    consumed_secret_arns: set[str],
) -> list[str]:
    reasons: list[str] = []
    if any(_is_broad_secret_action(action) for action in actions):
        reasons.append("broad_action_scope")
    if any(_has_wildcard(resource) for resource in resources):
        reasons.append("wildcard_resource_scope")
    if any(_is_secret_arn(resource) and resource not in consumed_secret_arns for resource in resources):
        reasons.append("unconsumed_secret_scope")
    return reasons


def _is_broad_secret_action(action: str) -> bool:
    normalized = action.strip().lower()
    return normalized != "secretsmanager:getsecretvalue" and any(character in normalized for character in "*?")


def _has_wildcard(value: str) -> bool:
    return "*" in value or "?" in value


def _is_secret_arn(value: str) -> bool:
    parts = value.split(":", 6)
    return len(parts) == 7 and parts[0] == "arn" and parts[2] == "secretsmanager" and parts[5] == "secret"


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({item for item in value if isinstance(item, str) and item}, key=str.lower)


def _first_string(records: list[Mapping[str, Any]], key: str) -> str | None:
    return next(
        (value for record in records if isinstance((value := record.get(key)), str) and value),
        None,
    )


def _execution_role_evidence(role_address: str, role_arn: str | None) -> list[str]:
    values = [
        f"address={role_address}",
        "role_kind=ecs_task_execution_role",
        "credential_context=ecs_agent_secret_delivery",
        "role_policy_complete=true",
    ]
    if role_arn:
        values.append(f"arn={role_arn}")
    return values


def _consumed_secret_evidence(
    access_paths: list[Mapping[str, Any]],
    consumed_secret_arns: set[str],
) -> list[str]:
    values = [f"secret_arn={secret_arn}" for secret_arn in sorted(consumed_secret_arns)]
    paths = sorted(
        {
            reference_path
            for path in access_paths
            if isinstance((reference_path := path.get("secret_reference_path")), str) and reference_path
        }
    )
    values.extend(f"reference_path={path}" for path in paths)
    return values
