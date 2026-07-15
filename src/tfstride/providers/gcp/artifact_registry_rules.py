from __future__ import annotations

from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.coercion import STATE_DISABLED, STATE_NOT_CONFIGURED
from tfstride.providers.gcp.resource_facts import GcpResourceFacts, gcp_facts

_ARTIFACT_REGISTRY_REPOSITORY = "google_artifact_registry_repository"


class GcpArtifactRegistryRuleDetectors:
    def detect_artifact_registry_docker_tags_mutable(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for repository in context.inventory.by_type(_ARTIFACT_REGISTRY_REPOSITORY):
            facts = gcp_facts(repository)
            if _normalized_upper(facts.artifact_registry_format) != "DOCKER":
                continue
            if facts.artifact_registry_docker_immutable_tags_state != STATE_DISABLED:
                continue

            severity_reasoning = _artifact_registry_posture_severity()
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[repository.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{repository.display_name} permits mutable Artifact Registry Docker image tags. A later "
                        "push can change the artifact selected by a deployment; use immutable tags or a narrowly "
                        "justified exception policy."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(repository)),
                        evidence_item("tag_mutability", _tag_mutability_evidence(facts)),
                        evidence_item(
                            "posture_uncertainty",
                            _uncertainty_evidence(facts, ("docker_config", "immutable_tags")),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_artifact_registry_customer_managed_encryption_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for repository in context.inventory.by_type(_ARTIFACT_REGISTRY_REPOSITORY):
            facts = gcp_facts(repository)
            if facts.artifact_registry_encryption_state != STATE_NOT_CONFIGURED:
                continue

            severity_reasoning = _artifact_registry_posture_severity()
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[repository.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{repository.display_name} relies on Google-managed Artifact Registry encryption rather "
                        "than a customer-managed Cloud KMS key. Google-managed encryption still protects stored "
                        "artifacts; this finding does not claim that the repository is unencrypted. It concerns "
                        "customer key ownership, rotation, audit separation, "
                        "and compliance posture."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(repository)),
                        evidence_item("encryption_ownership", _encryption_ownership_evidence(facts)),
                        evidence_item(
                            "posture_uncertainty",
                            _uncertainty_evidence(facts, ("kms_key_name",)),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_artifact_registry_vulnerability_scanning_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for repository in context.inventory.by_type(_ARTIFACT_REGISTRY_REPOSITORY):
            facts = gcp_facts(repository)
            if facts.artifact_registry_vulnerability_scanning_state != STATE_DISABLED:
                continue

            severity_reasoning = _artifact_registry_posture_severity()
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[repository.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{repository.display_name} explicitly disables Artifact Registry vulnerability scanning. "
                        "Enable repository scanning or an explicit registry scanning control that covers this "
                        "repository; this finding does not infer that scanning is absent when the plan omits "
                        "registry-level configuration."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(repository)),
                        evidence_item("vulnerability_scanning", _vulnerability_scanning_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _artifact_registry_posture_severity():
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
    return values


def _tag_mutability_evidence(facts: GcpResourceFacts) -> list[str]:
    values = [
        f"format={facts.artifact_registry_format or 'unknown'}",
        f"docker_immutable_tags_state={facts.artifact_registry_docker_immutable_tags_state or 'unknown'}",
        f"docker_immutable_tags={_bool_status(facts.artifact_registry_docker_immutable_tags)}",
    ]
    if facts.artifact_registry_docker_config:
        values.append(
            f"docker_config.immutable_tags={facts.artifact_registry_docker_config.get('immutable_tags', 'unset')}"
        )
    return values


def _encryption_ownership_evidence(facts: GcpResourceFacts) -> list[str]:
    return [
        f"encryption_ownership_state={facts.artifact_registry_encryption_state or 'unknown'}",
        f"kms_key_name={facts.artifact_registry_kms_key_name or 'unset'}",
        "finding_scope=customer-managed key ownership and control posture",
    ]


def _vulnerability_scanning_evidence(facts: GcpResourceFacts) -> list[str]:
    return [
        f"vulnerability_scanning_state={facts.artifact_registry_vulnerability_scanning_state or 'unknown'}",
        (
            "vulnerability_scanning_config.enablement_config="
            f"{facts.artifact_registry_vulnerability_scanning_enablement_config or 'unset'}"
        ),
        (
            "vulnerability_scanning_config.enablement_state="
            f"{facts.artifact_registry_vulnerability_scanning_enablement_state or 'unset'}"
        ),
        (
            "vulnerability_scanning_config.enablement_state_reason="
            f"{facts.artifact_registry_vulnerability_scanning_state_reason or 'unset'}"
        ),
        "scanning_scope=repository vulnerability scanning configuration",
        "registry_level_scanning_absence=not_inferred",
    ]


def _uncertainty_evidence(facts: GcpResourceFacts, field_paths: tuple[str, ...]) -> list[str]:
    return [
        uncertainty
        for uncertainty in facts.artifact_registry_posture_uncertainties
        if any(field_path in uncertainty for field_path in field_paths)
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
