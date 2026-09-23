from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    describe_policy_statement,
    evidence_item,
)
from tfstride.analysis.resource_concepts import (
    IDENTITY_ROLE_RESOURCE_TYPES,
    SENSITIVE_RESOURCE_POLICY_RESOURCE_TYPES,
    SERVICE_RESOURCE_POLICY_RESOURCE_TYPES,
    is_key_management_resource,
    is_object_storage_resource,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, Finding
from tfstride.providers.aws.account_identity import describe_account_resolution
from tfstride.providers.aws.analysis_indexes import aws_analysis_indexes
from tfstride.providers.aws.policy_conditions import (
    PrincipalAssessment,
    describe_trust_narrowing_for_principal,
    policy_statement_principal_assessments,
    resource_policy_statement_has_effective_narrowing,
    trust_statement_has_effective_narrowing_for_principal,
    trust_statement_has_supported_narrowing_for_principal,
    trust_statement_principal_assessments,
    trust_statement_resolved_oidc_provider_addresses,
)
from tfstride.providers.aws.resource_facts import aws_facts


class AwsPolicyTrustRuleDetectors:
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
            resource_types=SENSITIVE_RESOURCE_POLICY_RESOURCE_TYPES,
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
            resource_types=SERVICE_RESOURCE_POLICY_RESOURCE_TYPES,
            sensitive_resource=False,
        )

    def _detect_resource_policy_exposure(
        self,
        context: RuleEvaluationContext,
        *,
        rule_id: str,
        resource_types: frozenset[str],
        sensitive_resource: bool,
    ) -> list[Finding]:
        findings: list[Finding] = []
        indexes = context.analysis_indexes
        assert indexes is not None
        account_identities = aws_analysis_indexes(indexes, context.inventory).account_identities
        seen: set[tuple[str, str]] = set()

        for resource in context.inventory.resources:
            if resource.resource_type not in resource_types:
                continue
            target_account = account_identities.resolve(resource)
            for statement in resource.policy_statements:
                if statement.effect != "Allow":
                    continue
                if resource_policy_statement_has_effective_narrowing(statement):
                    continue
                for assessment in policy_statement_principal_assessments(
                    statement,
                    target_account.account_id,
                    target_partition=target_account.partition,
                ):
                    principal = assessment.principal
                    if assessment.is_service:
                        continue
                    if assessment.scope_description is None:
                        continue
                    if is_object_storage_resource(resource):
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
                        is_key_management_resource(resource)
                        and assessment.is_root_like
                        and not assessment.is_foreign_account
                        and assessment.account_id is not None
                        and assessment.account_id == target_account.account_id
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
                            f"{resource.display_name} delegates its key-policy permissions to its own AWS account "
                            "through the account-root principal. This common KMS default enables IAM policies in "
                            "that account to delegate the permitted actions; it does not itself grant every "
                            "identity access. The delegation scope is broader than named roles."
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
                    resource_policy_sources = aws_facts(resource).resource_policy_source_addresses
                    findings.append(
                        self._finding_factory.build(
                            rule_id=rule_id,
                            severity=severity_reasoning.severity,
                            affected_resources=[
                                resource.address,
                                *resource_policy_sources,
                            ],
                            trust_boundary_id=boundary.identifier if boundary else None,
                            rationale=rationale,
                            evidence=collect_evidence(
                                evidence_item("trust_principals", [principal]),
                                evidence_item("trust_scope", [assessment.scope_description]),
                                evidence_item("target_account_resolution", describe_account_resolution(target_account)),
                                evidence_item("policy_actions", sorted(statement.actions)),
                                evidence_item(
                                    "policy_statements",
                                    [describe_policy_statement(statement)],
                                ),
                                evidence_item(
                                    "resource_policy_sources",
                                    resource_policy_sources,
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
        indexes = context.analysis_indexes
        assert indexes is not None
        account_identities = aws_analysis_indexes(indexes, context.inventory).account_identities
        seen: set[tuple[str, str]] = set()

        for role in context.inventory.by_type(*IDENTITY_ROLE_RESOURCE_TYPES):
            target_account = account_identities.resolve(role)
            for trust_statement in aws_facts(role).trust_statements:
                for assessment in trust_statement_principal_assessments(
                    trust_statement,
                    target_account.account_id,
                    target_partition=target_account.partition,
                ):
                    if trust_statement_has_effective_narrowing_for_principal(trust_statement, assessment):
                        continue
                    principal = assessment.principal
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
                    boundary = context.boundary_index.get((BoundaryType.CROSS_ACCOUNT_OR_ROLE, principal, role.address))
                    provider_addresses = trust_statement_resolved_oidc_provider_addresses(
                        trust_statement,
                        principal,
                    )
                    findings.append(
                        self._finding_factory.build(
                            rule_id=rule_id,
                            severity=severity_reasoning.severity,
                            affected_resources=[role.address, *provider_addresses],
                            trust_boundary_id=boundary.identifier if boundary else None,
                            rationale=_trust_expansion_rationale(role.display_name, principal, assessment),
                            evidence=collect_evidence(
                                evidence_item("trust_principals", [principal]),
                                evidence_item("target_account_resolution", describe_account_resolution(target_account)),
                                evidence_item(
                                    "trust_path",
                                    [assessment.trust_path_description],
                                ),
                                evidence_item("trust_provider_resources", provider_addresses),
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
        indexes = context.analysis_indexes
        assert indexes is not None
        account_identities = aws_analysis_indexes(indexes, context.inventory).account_identities
        seen: set[tuple[str, str]] = set()

        for role in context.inventory.by_type(*IDENTITY_ROLE_RESOURCE_TYPES):
            target_account = account_identities.resolve(role)
            for trust_statement in aws_facts(role).trust_statements:
                for assessment in trust_statement_principal_assessments(
                    trust_statement,
                    target_account.account_id,
                    target_partition=target_account.partition,
                ):
                    if trust_statement_has_supported_narrowing_for_principal(trust_statement, assessment):
                        continue
                    principal = assessment.principal
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
                    boundary = context.boundary_index.get((BoundaryType.CROSS_ACCOUNT_OR_ROLE, principal, role.address))
                    provider_addresses = trust_statement_resolved_oidc_provider_addresses(
                        trust_statement,
                        principal,
                    )
                    findings.append(
                        self._finding_factory.build(
                            rule_id=rule_id,
                            severity=severity_reasoning.severity,
                            affected_resources=[role.address, *provider_addresses],
                            trust_boundary_id=boundary.identifier if boundary else None,
                            rationale=_missing_narrowing_rationale(role.display_name, principal, assessment),
                            evidence=collect_evidence(
                                evidence_item("trust_principals", [principal]),
                                evidence_item("trust_scope", [assessment.scope_description]),
                                evidence_item("target_account_resolution", describe_account_resolution(target_account)),
                                evidence_item(
                                    "trust_narrowing",
                                    describe_trust_narrowing_for_principal(trust_statement, assessment),
                                ),
                                evidence_item("trust_provider_resources", provider_addresses),
                            ),
                            severity_reasoning=severity_reasoning,
                        )
                    )
        return findings


def _trust_expansion_rationale(
    role_display_name: str,
    principal: str,
    assessment: PrincipalAssessment,
) -> str:
    if assessment.is_federated:
        return (
            f"{role_display_name} can be assumed through {principal}. Federated trust relationships without "
            "effective audience or subject conditions increase the chance that assertions or web identity tokens "
            "from the provider are accepted more broadly than intended."
        )
    return (
        f"{role_display_name} can be assumed by {principal}. Broad or foreign-account trust "
        "relationships increase the chance that compromise in one identity domain spills into another."
    )


def _missing_narrowing_rationale(
    role_display_name: str,
    principal: str,
    assessment: PrincipalAssessment,
) -> str:
    examples = "`sts:ExternalId`, `aws:SourceArn`, or `aws:SourceAccount`"
    if assessment.federated_provider_type == "saml":
        examples = "`SAML:aud`"
    elif assessment.federated_provider_type == "oidc":
        examples = "provider-specific `:aud` and `:sub` conditions"
    elif assessment.federated_provider_type == "cognito":
        examples = "`cognito-identity.amazonaws.com:aud`"

    return (
        f"{role_display_name} trusts {principal} without supported narrowing conditions such as {examples}. "
        "That leaves the assume-role path dependent on the trusted principal match alone."
    )
