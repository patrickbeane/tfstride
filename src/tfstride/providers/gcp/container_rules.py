from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.coercion import STATE_DISABLED
from tfstride.providers.gcp.resource_facts import GcpResourceFacts, gcp_facts
from tfstride.providers.gcp.resource_types import GCP_CLOUD_RUN_RESOURCE_TYPES


class GcpContainerDeploymentRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_cloud_run_image_not_digest_pinned(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for workload in context.inventory.by_type(*GCP_CLOUD_RUN_RESOURCE_TYPES):
            facts = gcp_facts(workload)
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
                            f"{workload.display_name} deploys Cloud Run image "
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

    def detect_cloud_run_artifact_registry_mutable_tag(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        repositories_by_path = _artifact_registry_repositories_by_path(context)
        findings: list[Finding] = []
        for workload in context.inventory.by_type(*GCP_CLOUD_RUN_RESOURCE_TYPES):
            facts = gcp_facts(workload)
            for image_reference in facts.container_image_references:
                if not _is_resolved_tagged_artifact_registry_reference(image_reference):
                    continue

                repository_path = image_reference["artifact_registry_repository_path"]
                for repository in repositories_by_path.get(repository_path, ()):
                    repository_facts = gcp_facts(repository)
                    if not _artifact_registry_repository_allows_mutable_tags(repository_facts):
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
                                f"{workload.display_name} deploys the Artifact Registry image "
                                f"{image_reference.get('raw')} from {repository.display_name}, and the exact "
                                "Docker repository permits this tag to be mutable. A later image push can change "
                                "the artifact selected by a future deployment; use immutable tags or a "
                                "digest-pinned reference."
                            ),
                            evidence=collect_evidence(
                                evidence_item("target_resource", _target_resource_evidence(workload)),
                                evidence_item("image_reference", _image_reference_evidence(image_reference)),
                                evidence_item(
                                    "artifact_registry_repository",
                                    _artifact_registry_repository_evidence(repository, repository_facts),
                                ),
                            ),
                            severity_reasoning=severity_reasoning,
                        )
                    )
        return findings


def _artifact_registry_repositories_by_path(
    context: RuleEvaluationContext,
) -> dict[str, list[NormalizedResource]]:
    repositories_by_path: dict[str, list[NormalizedResource]] = {}
    for repository in context.inventory.by_type("google_artifact_registry_repository"):
        repository_path = gcp_facts(repository).artifact_registry_repository_path
        if repository_path:
            repositories_by_path.setdefault(repository_path, []).append(repository)
    return repositories_by_path


def _is_resolved_unpinned_reference(reference: Mapping[str, Any]) -> bool:
    return reference.get("is_resolved") is True and reference.get("digest_pinned") is False


def _is_resolved_tagged_artifact_registry_reference(reference: Mapping[str, Any]) -> bool:
    return (
        _is_resolved_unpinned_reference(reference)
        and isinstance(reference.get("tag"), str)
        and bool(reference.get("tag"))
        and isinstance(reference.get("artifact_registry_repository_path"), str)
        and bool(reference.get("artifact_registry_repository_path"))
    )


def _artifact_registry_repository_allows_mutable_tags(facts: GcpResourceFacts) -> bool:
    return (
        _normalized_upper(facts.artifact_registry_format) == "DOCKER"
        and facts.artifact_registry_docker_immutable_tags_state == STATE_DISABLED
    )


def _target_resource_evidence(resource: NormalizedResource) -> list[str]:
    values = [f"address={resource.address}", f"type={resource.resource_type}"]
    if resource.identifier:
        values.append(f"identifier={resource.identifier}")
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
        f"artifact_registry_repository_path={reference.get('artifact_registry_repository_path') or 'unset'}",
    ]


def _artifact_registry_repository_evidence(
    repository: NormalizedResource,
    facts: GcpResourceFacts,
) -> list[str]:
    return [
        f"address={repository.address}",
        f"repository_path={facts.artifact_registry_repository_path}",
        f"format={facts.artifact_registry_format or 'unknown'}",
        f"docker_immutable_tags_state={facts.artifact_registry_docker_immutable_tags_state or 'unknown'}",
        f"docker_immutable_tags={_bool_status(facts.artifact_registry_docker_immutable_tags)}",
    ]


def _bool_status(value: bool | None) -> str:
    if value is None:
        return "unknown"
    return str(value).lower()


def _normalized_upper(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().upper()
    return normalized or None
