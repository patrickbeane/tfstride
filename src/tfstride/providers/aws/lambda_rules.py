from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    describe_policy_statement,
    evidence_item,
)
from tfstride.analysis.policy_conditions import (
    policy_statement_principal_assessments,
    resource_policy_statement_has_effective_narrowing,
)
from tfstride.analysis.resource_facts import analysis_facts
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, IAMPolicyStatement, NormalizedResource
from tfstride.providers.aws.resource_facts import AwsResourceFacts, aws_facts

_AWS_LAMBDA_FUNCTION = "aws_lambda_function"
_AWS_LAMBDA_FUNCTION_URL = "aws_lambda_function_url"
_AUTHORIZATION_NONE = "none"
_LAMBDA_PUBLIC_INVOKE_ACTIONS = frozenset({"*", "lambda:*", "lambda:invokefunction", "lambda:invokefunctionurl"})


class AwsLambdaRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_invocation(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        findings.extend(self._detect_public_function_urls(context, rule_id))
        findings.extend(self._detect_public_lambda_permissions(context, rule_id))
        return findings

    def _detect_public_function_urls(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for function_url in context.inventory.by_type(_AWS_LAMBDA_FUNCTION_URL):
            facts = aws_facts(function_url)
            if _normalized_authorization_type(facts) != _AUTHORIZATION_NONE:
                continue

            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[function_url.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{function_url.display_name} configures a Lambda Function URL with "
                        "`authorization_type` set to `NONE`. Unauthenticated internet clients can invoke "
                        "the function URL unless another control outside the Terraform plan blocks access."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _function_url_target_evidence(function_url, facts)),
                        evidence_item("function_url_posture", _function_url_posture_evidence(facts)),
                        evidence_item("cors_evidence", _function_url_cors_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def _detect_public_lambda_permissions(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        primary_account_id = context.inventory.primary_account_id
        seen: set[tuple[str, str]] = set()

        for function in context.inventory.by_type(_AWS_LAMBDA_FUNCTION):
            resource_policy_sources = analysis_facts(function).iam.resource_policy_source_addresses
            for statement in function.policy_statements:
                if not _is_public_invocation_statement(statement, primary_account_id):
                    continue
                finding_key = (function.address, describe_policy_statement(statement))
                if finding_key in seen:
                    continue
                seen.add(finding_key)

                severity_reasoning = build_severity_reasoning(
                    internet_exposure=True,
                    privilege_breadth=2,
                    data_sensitivity=0,
                    lateral_movement=1,
                    blast_radius=1,
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=_dedupe_addresses([function.address, *resource_policy_sources]),
                        trust_boundary_id=None,
                        rationale=(
                            f"{function.display_name} has a Lambda resource policy statement that allows "
                            "wildcard principals to invoke the function without a deterministic source ARN or "
                            "source account narrowing condition."
                        ),
                        evidence=collect_evidence(
                            evidence_item("target_resource", _lambda_function_target_evidence(function)),
                            evidence_item("public_invocation_policy", _lambda_permission_evidence(statement)),
                            evidence_item("resource_policy_sources", resource_policy_sources),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings


def _normalized_authorization_type(facts: AwsResourceFacts) -> str | None:
    value = facts.lambda_function_url_authorization_type
    return value.strip().lower() if value else None


def _is_public_invocation_statement(
    statement: IAMPolicyStatement,
    primary_account_id: str | None,
) -> bool:
    if statement.effect != "Allow":
        return False
    if resource_policy_statement_has_effective_narrowing(statement):
        return False
    if not any(_allows_lambda_invocation_action(action) for action in statement.actions):
        return False
    return any(
        assessment.is_wildcard for assessment in policy_statement_principal_assessments(statement, primary_account_id)
    )


def _allows_lambda_invocation_action(action: str) -> bool:
    normalized = action.strip().lower()
    return normalized in _LAMBDA_PUBLIC_INVOKE_ACTIONS or normalized == "lambda:invoke*"


def _function_url_target_evidence(function_url: NormalizedResource, facts: AwsResourceFacts) -> list[str]:
    values = [f"address={function_url.address}", f"type={function_url.resource_type}"]
    if facts.lambda_function_url_function_reference:
        values.append(f"function_name={facts.lambda_function_url_function_reference}")
    if facts.lambda_function_url:
        values.append(f"function_url={facts.lambda_function_url}")
    return values


def _function_url_posture_evidence(facts: AwsResourceFacts) -> list[str]:
    values = [f"authorization_type={facts.lambda_function_url_authorization_type or 'unknown'}"]
    if facts.lambda_function_url_invoke_mode:
        values.append(f"invoke_mode={facts.lambda_function_url_invoke_mode}")
    if facts.lambda_function_url_qualifier:
        values.append(f"qualifier={facts.lambda_function_url_qualifier}")
    values.append("authorization_type NONE permits unauthenticated function URL invocation")
    return values


def _function_url_cors_evidence(facts: AwsResourceFacts) -> list[str]:
    values: list[str] = []
    if facts.lambda_function_url_cors_allow_origins:
        values.append("allow_origins=" + ", ".join(facts.lambda_function_url_cors_allow_origins))
    if facts.lambda_function_url_cors_allow_methods:
        values.append("allow_methods=" + ", ".join(facts.lambda_function_url_cors_allow_methods))
    if facts.lambda_function_url_cors_allow_credentials_state:
        values.append(f"allow_credentials_state={facts.lambda_function_url_cors_allow_credentials_state}")
    return values


def _lambda_function_target_evidence(function: NormalizedResource) -> list[str]:
    values = [f"address={function.address}", f"type={function.resource_type}"]
    if function.identifier:
        values.append(f"function_name={function.identifier}")
    if function.arn:
        values.append(f"arn={function.arn}")
    return values


def _lambda_permission_evidence(statement: IAMPolicyStatement) -> list[str]:
    return [
        "principal=*",
        "narrowing_condition=none",
        "actions=" + ", ".join(sorted(statement.actions)),
        describe_policy_statement(statement),
    ]


def _dedupe_addresses(addresses: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for address in addresses:
        if not address or address in seen:
            continue
        seen.add(address)
        deduped.append(address)
    return deduped
