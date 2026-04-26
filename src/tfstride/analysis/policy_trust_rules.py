from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    describe_policy_statement,
    evidence_item,
)
from tfstride.analysis.policy_conditions import (
    assess_principal,
    describe_trust_narrowing,
    resource_policy_statement_has_effective_narrowing,
    trust_statement_has_effective_narrowing,
    trust_statement_has_supported_narrowing,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, Finding


SENSITIVE_RESOURCE_POLICY_TYPES = {"aws_s3_bucket", "aws_kms_key", "aws_secretsmanager_secret"}
SERVICE_RESOURCE_POLICY_TYPES = {"aws_lambda_function", "aws_sqs_queue", "aws_sns_topic"}


class PolicyTrustRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_sensitive_resource_policy_exposure(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_resource_policy_exposure(
            context,
            rule_id=rule_id,
            resource_types=SENSITIVE_RESOURCE_POLICY_TYPES,
            sensitive_resource=True,
        )
	
    def detect_service_resource_policy_exposure(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_resource_policy_exposure(
            context,
            rule_id=rule_id,
            resource_types=SERVICE_RESOURCE_POLICY_TYPES,
            sensitive_resource=False,
        )

    def _detect_resource_policy_exposure(
        self,
        context: RuleEvaluationContext,
        *,
        rule_id: str,
        resource_types: set[str],
        sensitive_resource: bool,
	) -> list[Finding]:
        findings: list[Finding] = []
        primary_account_id = context.inventory.primary_account_id
        seen: set[tuple[str, str]] = set()

        for resource in context.inventory.resources:
            if resource.resource_type not in resource_types:
                continue
            for statement in resource.policy_statements:
                if statement.effect != "Allow" or not statement.principals:
                    continue
                if resource_policy_statement_has_effective_narrowing(statement):
                    continue
                for principal in statement.principals:
                    assessment = assess_principal(principal, primary_account_id)
                    if assessment.is_service:
                        continue
                    if assessment.scope_description is None:
                        continue
                    if resource.resource_type == "aws_s3_bucket":
                        if assessment.is_wildcard and not resource.public_exposure:
                            continue
                        if assessment.is_wildcard and resource.public_exposure:
                            # Public S3 exposure is already covered by the dedicated object-storage rule.
                            continue
                    finding_key = (resource.address, principal)
                    if finding_key in seen:
                        continue
                    seen.add(finding_key)

                    same_account_kms_root = (
                        resource.resource_type == "aws_kms_key"
                        and assessment.is_root_like
                        and not assessment.is_foreign_account
                        and assessment.account_id is not None
                        and assessment.account_id == primary_account_id
                    )
                    if same_account_kms_root:
                        severity_reasoning = build_severity_reasoning(
                            internet_exposure=False,
                            privilege_breadth=1,
                            data_sensitivity=2,
                            lateral_movement=1,
                            blast_radius=0,
                        )
                        rationale = (
                            f"{resource.display_name} allows same-account root through its key policy. "
                            "That is a common default KMS posture, but it still keeps key control broader than "
                            "a role-scoped grant and can make delegation or decryption authority harder to constrain."
                        )
                    else:
                        severity_reasoning = build_severity_reasoning(
                            internet_exposure=assessment.is_wildcard,
                            privilege_breadth=2 if assessment.is_wildcard or assessment.is_root_like else 1,
                            data_sensitivity=2 if sensitive_resource else 0,
                            lateral_movement=1,
                            blast_radius=2 if assessment.is_wildcard or assessment.is_foreign_account else 1,
                        )
                        rationale = (
                            f"{resource.display_name} allows {principal} through a resource policy. "
                            "Broad principals, account-root grants, or foreign-account principals expand who can "
                            "invoke, read, decrypt, or consume this resource."
                        )

                    boundary = context.boundary_index.get(
                        (BoundaryType.CROSS_ACCOUNT_OR_ROLE, principal, resource.address)
                    )
                    findings.append(
                        self._finding_factory.build(
                            rule_id=rule_id,
                            severity=severity_reasoning.severity,
                            affected_resources=[
                                resource.address,
                                *resource.resource_policy_source_addresses,
                            ],
                            trust_boundary_id=boundary.identifier if boundary else None,
                            rationale=rationale,
                            evidence=collect_evidence(
                                evidence_item("trust_principals", [principal]),
                                evidence_item("trust_scope", [assessment.scope_description]),
                                evidence_item("policy_actions", sorted(statement.actions)),
                                evidence_item(
                                    "policy_statements",
                                    [describe_policy_statement(statement)],
                                ),
                                evidence_item(
                                    "resource_policy_sources",
                                    resource.resource_policy_source_addresses,
                                ),
                            ),
                            severity_reasoning=severity_reasoning,
                        )
                    )
        return findings

    def detect_trust_expansion(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
	) -> list[Finding]:
        findings: list[Finding] = []
        primary_account_id = context.inventory.primary_account_id
        seen: set[tuple[str, str]] = set()

        for role in context.inventory.by_type("aws_iam_role"):
            for trust_statement in role.trust_statements:
                if trust_statement_has_effective_narrowing(trust_statement):
                    continue
                for principal in trust_statement.get("principals", []):
                    assessment = assess_principal(principal, primary_account_id)
                    if assessment.is_service:
                        continue
                    if assessment.scope_description is None:
                        continue
                    finding_key = (role.address, principal)
                    if finding_key in seen:
                        continue
                    seen.add(finding_key)

                    severity_reasoning = build_severity_reasoning(
                        internet_exposure=False,
                        privilege_breadth=2 if assessment.is_wildcard else 1,
                        data_sensitivity=0,
                        lateral_movement=2,
                        blast_radius=2 if assessment.is_wildcard or assessment.is_foreign_account else 1,
                    )
                    boundary = context.boundary_index.get(
                        (BoundaryType.CROSS_ACCOUNT_OR_ROLE, principal, role.address)
                    )
                    findings.append(
                        self._finding_factory.build(
                            rule_id=rule_id,
                            severity=severity_reasoning.severity,
                            affected_resources=[role.address],
                            trust_boundary_id=boundary.identifier if boundary else None,
                            rationale=(
                                f"{role.display_name} can be assumed by {principal}. Broad or foreign-account trust "
                                "relationships increase the chance that compromise in one identity domain spills into "
                                "another."
                            ),
                            evidence=collect_evidence(
                                evidence_item("trust_principals", [principal]),
                                evidence_item(
                                    "trust_path",
                                    [assessment.trust_path_description],
                                ),
                            ),
                            severity_reasoning=severity_reasoning,
                        )
                    )
        return findings

    def detect_unconstrained_trust(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        primary_account_id = context.inventory.primary_account_id
        seen: set[tuple[str, str]] = set()

        for role in context.inventory.by_type("aws_iam_role"):
            for trust_statement in role.trust_statements:
                if trust_statement_has_supported_narrowing(trust_statement):
                    continue
                for principal in trust_statement.get("principals", []):
                    assessment = assess_principal(principal, primary_account_id)
                    if assessment.is_service:
                        continue
                    if assessment.scope_description is None:
                        continue
                    finding_key = (role.address, principal)
                    if finding_key in seen:
                        continue
                    seen.add(finding_key)

                    severity_reasoning = build_severity_reasoning(
                        internet_exposure=False,
                        privilege_breadth=2 if assessment.is_wildcard or assessment.is_root_like else 1,
                        data_sensitivity=0,
                        lateral_movement=1,
                        blast_radius=2 if assessment.is_wildcard or assessment.is_foreign_account else 1,
                    )
                    boundary = context.boundary_index.get(
                        (BoundaryType.CROSS_ACCOUNT_OR_ROLE, principal, role.address)
                    )
                    findings.append(
                        self._finding_factory.build(
                            rule_id=rule_id,
                            severity=severity_reasoning.severity,
                            affected_resources=[role.address],
                            trust_boundary_id=boundary.identifier if boundary else None,
                            rationale=(
                                f"{role.display_name} trusts {principal} without supported narrowing conditions such as "
                                "`sts:ExternalId`, `aws:SourceArn`, or `aws:SourceAccount`. That leaves the "
                                "assume-role path dependent on a broad or external principal match alone."
                            ),
                            evidence=collect_evidence(
                                evidence_item("trust_principals", [principal]),
                                evidence_item("trust_scope", [assessment.scope_description]),
                                evidence_item("trust_narrowing", describe_trust_narrowing(trust_statement)),
                            ),
                            severity_reasoning=severity_reasoning,
                        )
                    )
        return findings