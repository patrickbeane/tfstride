from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    describe_policy_statement,
    evidence_item,
)
from tfstride.analysis.resource_concepts import IAM_POLICY_RESOURCE_TYPES, WORKLOAD_RESOURCE_TYPES
from tfstride.analysis.role_helpers import resolve_workload_role
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import (
    BoundaryType,
    Finding,
    IAMPolicyStatement,
)

SENSITIVE_ACTION_PREFIXES = {
    "kms:Decrypt",
    "secretsmanager:GetSecretValue",
    "ssm:GetParameter",
    "ssm:GetParameters",
    "iam:PassRole",
    "sts:AssumeRole",
    "s3:*",
    "*",
}


class IAMRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_wildcard_permissions(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for policy_resource in context.inventory.by_type(*IAM_POLICY_RESOURCE_TYPES):
            wildcard_statements = [
                statement
                for statement in policy_resource.policy_statements
                if statement.effect == "Allow"
                and (statement.has_wildcard_action() or statement.has_wildcard_resource())
            ]
            if not wildcard_statements:
                continue
            wildcard_actions = sorted(
                {
                    action
                    for statement in wildcard_statements
                    for action in statement.actions
                    if action == "*" or action.endswith(":*")
                }
            )
            wildcard_resources = sorted(
                {resource for statement in wildcard_statements for resource in statement.resources if resource == "*"}
            )
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=(
                    2 if any(statement.has_wildcard_action() for statement in wildcard_statements) else 1
                ),
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=2,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[policy_resource.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{policy_resource.display_name} contains allow statements with wildcard actions or "
                        "resources. That makes the resulting access difficult to reason about and expands blast radius."
                    ),
                    evidence=collect_evidence(
                        evidence_item("iam_actions", wildcard_actions),
                        evidence_item("iam_resources", wildcard_resources),
                        evidence_item(
                            "policy_statements",
                            [describe_policy_statement(statement) for statement in wildcard_statements],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_workload_role_sensitive_permissions(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        indexes = context.analysis_indexes
        assert indexes is not None
        for workload in context.inventory.by_type(*WORKLOAD_RESOURCE_TYPES):
            role = resolve_workload_role(workload, indexes.role_index)
            if role is None:
                continue
            sensitive_actions = _sensitive_actions(role.policy_statements)
            if not sensitive_actions:
                continue
            boundary = context.boundary_index.get((BoundaryType.CONTROL_TO_WORKLOAD, role.address, workload.address))
            severity_reasoning = build_severity_reasoning(
                internet_exposure=workload.public_exposure,
                privilege_breadth=2 if "*" in sensitive_actions or "s3:*" in sensitive_actions else 1,
                data_sensitivity=1,
                lateral_movement=1,
                blast_radius=2,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[workload.address, role.address],
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{workload.display_name} inherits sensitive privileges from {role.display_name}, including "
                        f"{', '.join(sorted(sensitive_actions))}. If the workload is compromised, those credentials "
                        "can be reused for privilege escalation, data access, or role chaining."
                    ),
                    evidence=collect_evidence(
                        evidence_item("iam_actions", sorted(sensitive_actions)),
                        evidence_item(
                            "policy_statements",
                            [
                                describe_policy_statement(statement)
                                for statement in role.policy_statements
                                if statement.effect == "Allow"
                                and _statement_matches_sensitive_actions(statement, sensitive_actions)
                            ],
                        ),
                        evidence_item("public_exposure_reasons", workload.public_exposure_reasons),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _sensitive_actions(statements: list[IAMPolicyStatement]) -> set[str]:
    sensitive: set[str] = set()
    for statement in statements:
        if statement.effect != "Allow":
            continue
        for action in statement.actions:
            if action in SENSITIVE_ACTION_PREFIXES:
                sensitive.add(action)
                continue
            if action.startswith("ssm:GetParameter"):
                sensitive.add("ssm:GetParameter*")
    return sensitive


def _statement_matches_sensitive_actions(
    statement: IAMPolicyStatement,
    sensitive_actions: set[str],
) -> bool:
    for action in statement.actions:
        if action in sensitive_actions:
            return True
        if action.startswith("ssm:GetParameter") and "ssm:GetParameter*" in sensitive_actions:
            return True
    return False
