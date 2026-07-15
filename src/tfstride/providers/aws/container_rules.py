from __future__ import annotations

from collections.abc import Mapping
from fnmatch import fnmatchcase
from typing import Any

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.aws.resource_facts import AwsResourceFacts, aws_facts

_AWS_ECR_REPOSITORY = "aws_ecr_repository"
_AWS_WORKLOAD_RESOURCE_TYPES = ("aws_ecs_task_definition", "aws_lambda_function")
_MUTABLE_TAG_POLICIES = frozenset({"MUTABLE", "MUTABLE_WITH_EXCLUSION"})
_IMMUTABLE_TAG_POLICIES_WITH_EXCLUSIONS = frozenset({"IMMUTABLE_WITH_EXCLUSION"})
_EXCLUSION_FILTER_UNCERTAINTY = "image_tag_mutability_exclusion_filter"


class AwsContainerDeploymentRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_image_not_digest_pinned(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for workload in context.inventory.by_type(*_AWS_WORKLOAD_RESOURCE_TYPES):
            facts = aws_facts(workload)
            for image_reference in facts.container_image_references:
                if not _is_resolved_unpinned_reference(image_reference):
                    continue

                severity_reasoning = build_severity_reasoning(
                    internet_exposure=False,
                    privilege_breadth=0,
                    data_sensitivity=0,
                    lateral_movement=0,
                    blast_radius=1,
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=[workload.address],
                        trust_boundary_id=None,
                        rationale=(
                            f"{workload.display_name} deploys container image "
                            f"{image_reference.get('raw') or 'with an unresolved image value'} without a digest pin. "
                            "A tag or registry resolution can change the artifact selected by a future deployment; "
                            "pin deployment images to immutable digests for reproducible workload integrity."
                        ),
                        evidence=collect_evidence(
                            evidence_item("target_resource", _target_resource_evidence(workload)),
                            evidence_item("image_reference", _image_reference_evidence(image_reference)),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings

    def detect_mutable_ecr_tag(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        repositories_by_url = _ecr_repositories_by_url(context)
        findings: list[Finding] = []
        for workload in context.inventory.by_type(*_AWS_WORKLOAD_RESOURCE_TYPES):
            facts = aws_facts(workload)
            for image_reference in facts.container_image_references:
                if not _is_resolved_tagged_ecr_reference(image_reference):
                    continue
                repository_url = image_reference["ecr_repository_url"]
                for repository in repositories_by_url.get(repository_url, ()):  # exact URL match only
                    repository_facts = aws_facts(repository)
                    if _ecr_tag_is_mutable(repository_facts, image_reference["tag"]) is not True:
                        continue

                    severity_reasoning = build_severity_reasoning(
                        internet_exposure=False,
                        privilege_breadth=0,
                        data_sensitivity=1,
                        lateral_movement=1,
                        blast_radius=1,
                    )
                    findings.append(
                        self._finding_factory.build(
                            rule_id=rule_id,
                            severity=severity_reasoning.severity,
                            affected_resources=[workload.address, repository.address],
                            trust_boundary_id=None,
                            rationale=(
                                f"{workload.display_name} deploys the ECR image "
                                f"{image_reference.get('raw')} from {repository.display_name}, and the exact "
                                "repository policy permits this tag to be mutable. A later image push can change "
                                "the artifact selected by a future deployment; use an immutable tag policy or a "
                                "digest-pinned reference."
                            ),
                            evidence=collect_evidence(
                                evidence_item("target_resource", _target_resource_evidence(workload)),
                                evidence_item("image_reference", _image_reference_evidence(image_reference)),
                                evidence_item("ecr_repository", _ecr_repository_evidence(repository, repository_facts)),
                            ),
                            severity_reasoning=severity_reasoning,
                        )
                    )
        return findings


def _ecr_repositories_by_url(context: RuleEvaluationContext) -> dict[str, list[NormalizedResource]]:
    repositories_by_url: dict[str, list[NormalizedResource]] = {}
    for repository in context.inventory.by_type(_AWS_ECR_REPOSITORY):
        repository_url = aws_facts(repository).ecr_repository_url
        if repository_url:
            repositories_by_url.setdefault(repository_url, []).append(repository)
    return repositories_by_url


def _is_resolved_unpinned_reference(reference: Mapping[str, Any]) -> bool:
    return reference.get("is_resolved") is True and reference.get("digest_pinned") is False


def _is_resolved_tagged_ecr_reference(reference: Mapping[str, Any]) -> bool:
    return (
        _is_resolved_unpinned_reference(reference)
        and isinstance(reference.get("tag"), str)
        and bool(reference.get("tag"))
        and isinstance(reference.get("ecr_repository_url"), str)
        and bool(reference.get("ecr_repository_url"))
    )


def _ecr_tag_is_mutable(facts: AwsResourceFacts, tag: object) -> bool | None:
    if not isinstance(tag, str) or not tag:
        return None

    mutability = _normalized_upper(facts.ecr_image_tag_mutability)
    if mutability == "MUTABLE":
        return True
    if mutability == "IMMUTABLE":
        return False
    if mutability not in _MUTABLE_TAG_POLICIES | _IMMUTABLE_TAG_POLICIES_WITH_EXCLUSIONS:
        return None
    if any(_EXCLUSION_FILTER_UNCERTAINTY in uncertainty for uncertainty in facts.ecr_posture_uncertainties):
        return None

    filters = facts.ecr_image_tag_mutability_exclusion_filters
    if not filters:
        return mutability == "MUTABLE_WITH_EXCLUSION"

    matches: list[bool] = []
    for exclusion_filter in filters:
        pattern = exclusion_filter.get("filter")
        filter_type = _normalized_upper(exclusion_filter.get("filter_type"))
        if not isinstance(pattern, str) or not pattern or filter_type != "WILDCARD":
            return None
        matches.append(fnmatchcase(tag, pattern))

    matches_exclusion = any(matches)
    if mutability == "MUTABLE_WITH_EXCLUSION":
        return not matches_exclusion
    return matches_exclusion


def _target_resource_evidence(resource: NormalizedResource) -> list[str]:
    values = [f"address={resource.address}", f"type={resource.resource_type}"]
    if resource.identifier:
        values.append(f"identifier={resource.identifier}")
    if resource.arn:
        values.append(f"arn={resource.arn}")
    return values


def _image_reference_evidence(reference: Mapping[str, Any]) -> list[str]:
    return [
        f"source={reference.get('source') or 'unknown'}",
        f"path={reference.get('path') or 'unknown'}",
        f"raw={reference.get('raw') or 'unknown'}",
        f"registry_host={reference.get('registry_host') or 'implicit'}",
        f"repository={reference.get('repository') or 'unknown'}",
        f"tag={reference.get('tag') or 'unset'}",
        f"digest={reference.get('digest') or 'unset'}",
        f"digest_pinned={reference.get('digest_pinned')}",
    ]


def _ecr_repository_evidence(
    repository: NormalizedResource,
    facts: AwsResourceFacts,
) -> list[str]:
    return [
        f"address={repository.address}",
        f"repository_url={facts.ecr_repository_url}",
        f"image_tag_mutability={facts.ecr_image_tag_mutability}",
        f"exclusion_filters={facts.ecr_image_tag_mutability_exclusion_filters or '[]'}",
    ]


def _normalized_upper(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().upper()
    return normalized or None
