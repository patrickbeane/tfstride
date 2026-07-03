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
