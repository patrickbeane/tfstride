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

    def detect_cloud_run_artifact_registry_self_modification_path(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for workload in context.inventory.by_type(*GCP_CLOUD_RUN_RESOURCE_TYPES):
            for write_path in gcp_facts(workload).artifact_registry_write_paths:
                if not _is_reportable_self_modification_path(write_path):
                    continue

                repository = _resource_by_address(
                    context,
                    write_path.get("artifact_registry_repository_address"),
                    expected_type="google_artifact_registry_repository",
                )
                iam_resource = _resource_by_address(
                    context,
                    write_path.get("iam_resource_address"),
                    expected_types=(
                        "google_artifact_registry_repository_iam_member",
                        "google_artifact_registry_repository_iam_binding",
                        "google_artifact_registry_repository_iam_policy",
                    ),
                )
                if repository is None or iam_resource is None:
                    continue
                repository_facts = gcp_facts(repository)
                if not _artifact_registry_repository_allows_mutable_tags(repository_facts):
                    continue

                severity_reasoning = build_severity_reasoning(
                    internet_exposure=False,
                    privilege_breadth=1,
                    data_sensitivity=1,
                    lateral_movement=2,
                    blast_radius=1,
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=[workload.address, repository.address, iam_resource.address],
                        trust_boundary_id=None,
                        rationale=(
                            f"{workload.display_name} deploys the unpinned Artifact Registry image "
                            f"{write_path.get('image_reference')} from {repository.display_name}, and its runtime "
                            f"service account has the modeled {write_path.get('role') or 'writer/admin role'} on "
                            "that exact repository. Because Docker tags are mutable, a compromised workload can "
                            "publish a replacement artifact selected by a future deployment, creating a "
                            "self-modification and persistence path."
                        ),
                        evidence=collect_evidence(
                            evidence_item("target_resource", _target_resource_evidence(workload)),
                            evidence_item("image_reference", _write_path_image_evidence(write_path)),
                            evidence_item("runtime_identity", _write_path_identity_evidence(write_path)),
                            evidence_item(
                                "artifact_registry_write_path",
                                _artifact_registry_write_path_evidence(write_path),
                            ),
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


def _resource_by_address(
    context: RuleEvaluationContext,
    address: object,
    *,
    expected_type: str | None = None,
    expected_types: tuple[str, ...] = (),
) -> NormalizedResource | None:
    if not isinstance(address, str) or not address:
        return None
    resource = context.inventory.get_by_address(address)
    if resource is None:
        return None
    allowed_types = expected_types or ((expected_type,) if expected_type is not None else ())
    if allowed_types and resource.resource_type not in allowed_types:
        return None
    return resource


def _is_reportable_self_modification_path(path: Mapping[str, Any]) -> bool:
    return (
        path.get("grant_basis") == "artifact_registry_repository_iam"
        and path.get("repository_scope") == "exact_repository_path"
        and path.get("role_kind") in {"writer", "admin"}
        and isinstance(path.get("service_account_member"), str)
        and bool(path.get("service_account_member"))
        and path.get("image_digest_pinned") is False
    )


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


def _write_path_image_evidence(path: Mapping[str, Any]) -> list[str]:
    return [
        f"raw={path.get('image_reference') or 'unknown'}",
        f"path={path.get('image_reference_path') or 'unknown'}",
        f"tag={path.get('image_tag') or 'unset'}",
        f"digest={path.get('image_digest') or 'unset'}",
        f"digest_pinned={path.get('image_digest_pinned')}",
    ]


def _write_path_identity_evidence(path: Mapping[str, Any]) -> list[str]:
    return [
        f"service_account_email={path.get('service_account_email') or 'unknown'}",
        f"service_account_member={path.get('service_account_member') or 'unknown'}",
        f"role={path.get('role') or 'unknown'}",
        f"role_kind={path.get('role_kind') or 'unknown'}",
    ]


def _artifact_registry_write_path_evidence(path: Mapping[str, Any]) -> list[str]:
    return [
        f"repository_address={path.get('artifact_registry_repository_address') or 'unknown'}",
        f"repository_path={path.get('artifact_registry_repository_path') or 'unknown'}",
        f"iam_resource_address={path.get('iam_resource_address') or 'unknown'}",
        f"grant_basis={path.get('grant_basis') or 'unknown'}",
        f"repository_scope={path.get('repository_scope') or 'unknown'}",
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
