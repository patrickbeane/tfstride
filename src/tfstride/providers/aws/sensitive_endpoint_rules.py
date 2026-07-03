from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from fnmatch import fnmatchcase

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    describe_policy_statement,
    evidence_item,
)
from tfstride.analysis.resource_concepts import WORKLOAD_RESOURCE_TYPES
from tfstride.analysis.role_helpers import resolve_workload_role
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, IAMPolicyStatement, NormalizedResource
from tfstride.providers.aws.policy_documents import parse_policy_statements
from tfstride.providers.aws.resource_facts import AwsResourceFacts, aws_facts
from tfstride.providers.aws.vpc_endpoint_index import AwsVpcEndpointIndex, build_aws_vpc_endpoint_index


@dataclass(frozen=True, slots=True)
class _SensitiveEndpointService:
    key: str
    display_name: str
    expected_endpoint: str
    action_patterns: tuple[str, ...]
    has_endpoint: Callable[[AwsVpcEndpointIndex, str | None], bool]
    posture_description: str


_SERVICE_BY_RULE_ID = {
    "aws-workload-secretsmanager-vpc-endpoint-missing": _SensitiveEndpointService(
        key="secretsmanager",
        display_name="Secrets Manager",
        expected_endpoint="interface",
        action_patterns=(
            "secretsmanager:GetSecretValue",
            "secretsmanager:BatchGetSecretValue",
            "secretsmanager:Get*",
            "secretsmanager:*",
        ),
        has_endpoint=lambda index, vpc_id: index.has_secrets_manager_interface_endpoint(vpc_id),
        posture_description="Secrets Manager secret retrieval",
    ),
    "aws-workload-kms-vpc-endpoint-missing": _SensitiveEndpointService(
        key="kms",
        display_name="KMS",
        expected_endpoint="interface",
        action_patterns=(
            "kms:Decrypt",
            "kms:GenerateDataKey",
            "kms:GenerateDataKey*",
            "kms:Encrypt",
            "kms:ReEncrypt*",
            "kms:*",
        ),
        has_endpoint=lambda index, vpc_id: index.has_kms_endpoint(vpc_id),
        posture_description="KMS cryptographic key access",
    ),
    "aws-workload-s3-vpc-endpoint-missing": _SensitiveEndpointService(
        key="s3",
        display_name="S3",
        expected_endpoint="gateway_or_interface",
        action_patterns=("s3:*",),
        has_endpoint=lambda index, vpc_id: index.has_s3_endpoint(vpc_id),
        posture_description="S3 data-plane access",
    ),
}

_SUPPORTED_ENDPOINT_POLICY_SERVICE_NAMES = {
    "s3": "S3",
    "secretsmanager": "Secrets Manager",
    "kms": "KMS",
}
_ENDPOINT_POLICY_UNKNOWN_MARKER = "policy is unknown after planning"


class AwsSensitiveEndpointRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_missing_secretsmanager_endpoint(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_missing_service_endpoint(context, rule_id)

    def detect_missing_kms_endpoint(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_missing_service_endpoint(context, rule_id)

    def detect_missing_s3_endpoint(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_missing_service_endpoint(context, rule_id)

    def detect_broad_vpc_endpoint_policy(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for endpoint in context.inventory.by_type("aws_vpc_endpoint"):
            facts = aws_facts(endpoint)
            service_family = facts.vpc_endpoint_service_family
            if service_family not in _SUPPORTED_ENDPOINT_POLICY_SERVICE_NAMES:
                continue
            if _endpoint_policy_unknown(facts):
                continue

            posture = _broad_endpoint_policy_posture(facts, service_family)
            if posture is None:
                continue

            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=2,
                data_sensitivity=1,
                lateral_movement=0,
                blast_radius=1,
            )
            service_name = _SUPPORTED_ENDPOINT_POLICY_SERVICE_NAMES[service_family]
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[endpoint.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{endpoint.display_name} is a {service_name} VPC endpoint with a broad or default "
                        "endpoint policy. VPC endpoint policies do not grant service permissions by themselves, "
                        "but broad principals, actions, or resources weaken the endpoint-level guardrail for "
                        "workloads that already have identity permissions. This finding does not imply any S3 "
                        "bucket, secret, or key is public."
                    ),
                    evidence=collect_evidence(
                        evidence_item("vpc_endpoint", _endpoint_policy_target_evidence(endpoint, facts)),
                        evidence_item("policy_posture", list(posture.reasons)),
                        evidence_item(
                            "policy_statements",
                            [describe_policy_statement(statement) for statement in posture.statements],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def _detect_missing_service_endpoint(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        service = _SERVICE_BY_RULE_ID[rule_id]
        endpoint_index = build_aws_vpc_endpoint_index(context.inventory)
        indexes = context.analysis_indexes
        assert indexes is not None

        findings: list[Finding] = []
        for workload in context.inventory.by_type(*WORKLOAD_RESOURCE_TYPES):
            if not workload.vpc_id:
                continue
            role = resolve_workload_role(workload, indexes.role_index)
            if role is None:
                continue
            dependency = _service_dependency(role, service)
            if dependency is None:
                continue
            if service.has_endpoint(endpoint_index, workload.vpc_id):
                continue
            if _has_unresolved_service_endpoint(endpoint_index, workload.vpc_id):
                continue

            severity_reasoning = build_severity_reasoning(
                internet_exposure=workload.public_exposure,
                privilege_breadth=1,
                data_sensitivity=1,
                lateral_movement=1,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[workload.address, role.address],
                    trust_boundary_id=None,
                    rationale=_rationale(workload, role, service),
                    evidence=collect_evidence(
                        evidence_item("target_workload", _workload_evidence(workload)),
                        evidence_item("sensitive_service_dependency", _dependency_evidence(role, service, dependency)),
                        evidence_item(
                            "vpc_endpoint_coverage",
                            _endpoint_coverage_evidence(endpoint_index, workload.vpc_id, service),
                        ),
                        evidence_item(
                            "policy_statements",
                            [describe_policy_statement(statement) for statement in dependency.statements],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


@dataclass(frozen=True, slots=True)
class _ServiceDependency:
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    statements: tuple[IAMPolicyStatement, ...]


@dataclass(frozen=True, slots=True)
class _EndpointPolicyPosture:
    reasons: tuple[str, ...]
    statements: tuple[IAMPolicyStatement, ...]


def _endpoint_policy_unknown(facts: AwsResourceFacts) -> bool:
    return _ENDPOINT_POLICY_UNKNOWN_MARKER in facts.vpc_endpoint_posture_uncertainties


def _broad_endpoint_policy_posture(
    facts: AwsResourceFacts,
    service_family: str,
) -> _EndpointPolicyPosture | None:
    policy_document = facts.vpc_endpoint_policy_document
    if not policy_document:
        return _EndpointPolicyPosture(
            reasons=(
                "policy_document=absent_or_default",
                "default endpoint policy allows all principals, actions, and resources for the service",
            ),
            statements=(),
        )

    reasons: list[str] = []
    statements: list[IAMPolicyStatement] = []
    for statement in parse_policy_statements(policy_document):
        if statement.effect.lower() != "allow":
            continue
        statement_reasons = _broad_endpoint_policy_statement_reasons(statement, service_family)
        if not statement_reasons:
            continue
        reasons.extend(statement_reasons)
        statements.append(statement)

    if not reasons:
        return None
    return _EndpointPolicyPosture(
        reasons=_dedupe(reasons),
        statements=tuple(statements),
    )


def _broad_endpoint_policy_statement_reasons(
    statement: IAMPolicyStatement,
    service_family: str,
) -> list[str]:
    reasons: list[str] = []
    for principal in statement.principals:
        if principal == "*":
            reasons.append("principal=*")
    for action in statement.actions:
        if _is_broad_endpoint_policy_action(action, service_family):
            reasons.append(f"action={action}")
    for resource in statement.resources:
        if _is_broad_endpoint_policy_resource(resource, service_family):
            reasons.append(f"resource={resource}")
    return reasons


def _is_broad_endpoint_policy_action(action: str, service_family: str) -> bool:
    normalized_action = action.strip().lower()
    return normalized_action in {"*", f"{service_family}:*"}


def _is_broad_endpoint_policy_resource(resource: str, service_family: str) -> bool:
    normalized_resource = resource.strip().lower()
    if normalized_resource == "*":
        return True
    if service_family == "s3":
        return normalized_resource in {"arn:aws:s3:::*", "arn:aws:s3:::*/*"} or normalized_resource.startswith(
            "arn:aws:s3:::*"
        )
    arn_parts = normalized_resource.split(":", 5)
    if len(arn_parts) != 6:
        return False
    arn_marker, _, arn_service, region, account, resource_path = arn_parts
    if arn_marker != "arn" or arn_service != service_family:
        return False
    if region == "*" or account == "*":
        return True
    if service_family == "secretsmanager":
        return resource_path in {"*", "secret:*"}
    if service_family == "kms":
        return resource_path in {"*", "key/*", "alias/*"}
    return False


def _service_dependency(role: NormalizedResource, service: _SensitiveEndpointService) -> _ServiceDependency | None:
    actions: list[str] = []
    resources: list[str] = []
    statements: list[IAMPolicyStatement] = []
    for statement in role.policy_statements:
        if statement.effect != "Allow":
            continue
        matched_actions = [action for action in statement.actions if _action_matches_service(action, service)]
        if not matched_actions:
            continue
        actions.extend(matched_actions)
        resources.extend(statement.resources)
        statements.append(statement)
    if not actions:
        return None
    return _ServiceDependency(
        actions=_dedupe(actions),
        resources=_dedupe(resources),
        statements=tuple(statements),
    )


def _action_matches_service(action: str, service: _SensitiveEndpointService) -> bool:
    normalized_action = action.strip().lower()
    if not normalized_action.startswith(f"{service.key}:"):
        return False
    if service.key == "s3":
        return True
    return any(
        fnmatchcase(normalized_action, pattern.lower()) or fnmatchcase(pattern.lower(), normalized_action)
        for pattern in service.action_patterns
    )


def _has_unresolved_service_endpoint(endpoint_index: AwsVpcEndpointIndex, vpc_id: str | None) -> bool:
    if not vpc_id:
        return False
    return any(endpoint.vpc_id == vpc_id for endpoint in endpoint_index.unresolved_service_name_endpoints)


def _rationale(
    workload: NormalizedResource,
    role: NormalizedResource,
    service: _SensitiveEndpointService,
) -> str:
    if service.key == "s3":
        return (
            f"{workload.display_name} runs in VPC `{workload.vpc_id}` and inherits S3 data-plane permissions from "
            f"{role.display_name}, but the Terraform plan does not show an S3 VPC endpoint for that VPC. "
            "S3 access may therefore depend on public AWS service endpoints, NAT, or another egress path; "
            "this does not imply the bucket itself is public."
        )
    return (
        f"{workload.display_name} runs in VPC `{workload.vpc_id}` and inherits {service.posture_description} "
        f"from {role.display_name}, but the Terraform plan does not show a {service.display_name} "
        f"{service.expected_endpoint} VPC endpoint for that VPC. Calls to the sensitive service may therefore "
        "depend on public AWS service endpoints, NAT, or another egress path."
    )


def _workload_evidence(workload: NormalizedResource) -> list[str]:
    values = [
        f"address={workload.address}",
        f"type={workload.resource_type}",
        f"vpc_id={workload.vpc_id}",
    ]
    if workload.subnet_ids:
        values.append(f"subnet_ids=[{', '.join(workload.subnet_ids)}]")
    if workload.security_group_ids:
        values.append(f"security_group_ids=[{', '.join(workload.security_group_ids)}]")
    if workload.public_exposure:
        values.append("public_exposure=true")
        values.extend(workload.public_exposure_reasons)
    return values


def _endpoint_policy_target_evidence(endpoint: NormalizedResource, facts: AwsResourceFacts) -> list[str]:
    values = [
        f"address={endpoint.address}",
        f"service_family={facts.vpc_endpoint_service_family}",
    ]
    if facts.vpc_endpoint_service_name:
        values.append(f"service_name={facts.vpc_endpoint_service_name}")
    if facts.vpc_endpoint_type:
        values.append(f"endpoint_type={facts.vpc_endpoint_type}")
    if facts.vpc_endpoint_vpc_id:
        values.append(f"vpc_id={facts.vpc_endpoint_vpc_id}")
    if facts.vpc_endpoint_id:
        values.append(f"endpoint_id={facts.vpc_endpoint_id}")
    return values


def _dependency_evidence(
    role: NormalizedResource,
    service: _SensitiveEndpointService,
    dependency: _ServiceDependency,
) -> list[str]:
    values = [
        f"service={service.key}",
        f"role={role.address}",
        f"actions=[{', '.join(dependency.actions)}]",
    ]
    if dependency.resources:
        values.append(f"resources=[{', '.join(dependency.resources)}]")
    return values


def _endpoint_coverage_evidence(
    endpoint_index: AwsVpcEndpointIndex,
    vpc_id: str | None,
    service: _SensitiveEndpointService,
) -> list[str]:
    existing_endpoint_addresses = tuple(
        endpoint.endpoint_address for endpoint in endpoint_index.endpoints_for_vpc(vpc_id)
    )
    values = [
        f"vpc_id={vpc_id}",
        f"service={service.key}",
        f"expected_endpoint_type={service.expected_endpoint}",
        "vpc_endpoint_coverage=missing",
    ]
    if existing_endpoint_addresses:
        values.append(f"existing_vpc_endpoint_addresses=[{', '.join(existing_endpoint_addresses)}]")
    return values


def _dedupe(values: Iterable[str | None]) -> tuple[str, ...]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value or value in seen:
            continue
        deduped.append(value)
        seen.add(value)
    return tuple(deduped)
