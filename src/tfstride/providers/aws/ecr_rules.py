from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.aws.resource_facts import AwsResourceFacts, aws_facts
from tfstride.providers.coercion import STATE_DISABLED

_AWS_ECR_REPOSITORY = "aws_ecr_repository"
_MUTABLE_TAG_POLICIES = frozenset({"MUTABLE", "MUTABLE_WITH_EXCLUSION"})
_NON_CUSTOMER_MANAGED_ENCRYPTION_STATES = frozenset({"service_managed", "not_configured"})


class AwsEcrRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_mutable_image_tags(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for repository in context.inventory.by_type(_AWS_ECR_REPOSITORY):
            facts = aws_facts(repository)
            mutability = _normalized_upper(facts.ecr_image_tag_mutability)
            if mutability not in _MUTABLE_TAG_POLICIES:
                continue

            severity_reasoning = _ecr_posture_severity()
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[repository.address],
                    trust_boundary_id=None,
                    rationale=_mutable_tag_rationale(repository.display_name, mutability),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(repository)),
                        evidence_item("tag_mutability", _tag_mutability_evidence(facts, mutability)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_customer_managed_encryption_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for repository in context.inventory.by_type(_AWS_ECR_REPOSITORY):
            facts = aws_facts(repository)
            state = facts.ecr_encryption_ownership_state
            if state not in _NON_CUSTOMER_MANAGED_ENCRYPTION_STATES:
                continue

            severity_reasoning = _ecr_posture_severity()
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[repository.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{repository.display_name} does not configure a customer-managed KMS key for ECR image "
                        "encryption. This is an encryption ownership and key-control posture finding; it does not "
                        "claim that the repository is unencrypted."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(repository)),
                        evidence_item("encryption_ownership", _encryption_ownership_evidence(facts)),
                        evidence_item(
                            "posture_uncertainty",
                            _uncertainty_evidence(facts, ("encryption_configuration",)),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_repository_scanning_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for repository in context.inventory.by_type(_AWS_ECR_REPOSITORY):
            facts = aws_facts(repository)
            if facts.ecr_repository_scan_on_push_state != STATE_DISABLED:
                continue

            severity_reasoning = _ecr_posture_severity()
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[repository.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{repository.display_name} explicitly disables ECR repository scan-on-push. Image scanning "
                        "coverage should be enabled through repository or registry controls appropriate to the "
                        "account; this finding does not infer that registry-level scanning is absent."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(repository)),
                        evidence_item("repository_scanning", _repository_scanning_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _ecr_posture_severity():
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


def _tag_mutability_evidence(facts: AwsResourceFacts, mutability: str) -> list[str]:
    values = [f"image_tag_mutability={mutability}"]
    if mutability == "MUTABLE_WITH_EXCLUSION":
        filters = facts.ecr_image_tag_mutability_exclusion_filters
        values.append(f"mutable_tag_exclusion_filters={_format_records(filters)}")
        values.append("mutable_tag_scope=tags outside the exclusion filters")
    else:
        values.append("mutable_tag_scope=all repository tags")
    return values


def _encryption_ownership_evidence(facts: AwsResourceFacts) -> list[str]:
    return [
        f"encryption_ownership_state={facts.ecr_encryption_ownership_state}",
        f"encryption_type={facts.ecr_encryption_type or 'unset'}",
        f"kms_key={facts.ecr_kms_key or 'unset'}",
        "finding_scope=customer-managed key ownership and control posture",
    ]


def _repository_scanning_evidence(facts: AwsResourceFacts) -> list[str]:
    return [
        f"repository_scan_on_push_state={facts.ecr_repository_scan_on_push_state}",
        "scanning_scope=repository scan-on-push configuration",
        "registry_level_scanning_absence=not_inferred",
    ]


def _uncertainty_evidence(facts: AwsResourceFacts, field_paths: tuple[str, ...]) -> list[str]:
    return [
        uncertainty
        for uncertainty in facts.ecr_posture_uncertainties
        if any(field_path in uncertainty for field_path in field_paths)
    ]


def _format_records(records: list[dict[str, object]]) -> str:
    if not records:
        return "[]"
    return (
        "["
        + ", ".join(", ".join(f"{key}={value}" for key, value in sorted(record.items())) for record in records)
        + "]"
    )


def _mutable_tag_rationale(display_name: str, mutability: str) -> str:
    if mutability == "MUTABLE_WITH_EXCLUSION":
        return (
            f"{display_name} permits mutable ECR image tags outside its configured exclusion filters. Mutable tags "
            "can allow a later image push to change the artifact selected by a deployment; use immutable tags or "
            "narrow, intentional exceptions."
        )
    return (
        f"{display_name} permits mutable ECR image tags. A later image push can change the artifact selected by a "
        "deployment; use immutable tags or a narrowly justified exception policy."
    )


def _normalized_upper(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().upper()
    return normalized or None
