from __future__ import annotations

from collections.abc import Mapping

from tfstride.analysis.control_observations import observe_controls as collect_control_observations
from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.iam_rules import IAMRuleDetectors
from tfstride.analysis.network_data_rules import NetworkDataRuleDetectors
from tfstride.analysis.path_chain_rules import PathChainRuleDetectors
from tfstride.analysis.policy_trust_rules import PolicyTrustRuleDetectors
from tfstride.analysis.posture_rules import PostureRuleDetectors
from tfstride.analysis.rule_definitions import (
    BoundaryIndex,
    ExecutableRule,
    RuleDefinition,
    RuleDetector,
    RuleEvaluationContext,
)
from tfstride.analysis.rule_registry import (
    RulePolicy,
    RuleRegistry,
    default_rule_metadata,
)
from tfstride.models import Finding, Observation, ResourceInventory, TrustBoundary


_RULE_GROUP_IDS = (
    (
        "aws-public-compute-broad-ingress",
        "aws-rds-storage-encryption-disabled",
        "aws-s3-public-access",
    ),
    (
        "aws-database-permissive-ingress",
        "aws-missing-tier-segmentation",
    ),
    (
        "aws-sensitive-resource-policy-external-access",
        "aws-service-resource-policy-external-access",
    ),
    (
        "aws-iam-wildcard-permissions",
        "aws-workload-role-sensitive-permissions",
    ),
    (
        "aws-private-data-transitive-exposure",
        "aws-control-plane-sensitive-workload-chain",
    ),
    (
        "aws-role-trust-expansion",
        "aws-role-trust-missing-narrowing",
    ),
)


def _rule_definition(rule_id: str, detector: RuleDetector) -> RuleDefinition:
    return RuleDefinition(metadata=default_rule_metadata(rule_id), detector=detector)


def _default_rule_registry() -> RuleRegistry:
    return RuleRegistry([
        default_rule_metadata(rule_id)
        for rule_group in _RULE_GROUP_IDS
        for rule_id in rule_group
    ])


def _build_rule_groups(
    detectors_by_rule_id: Mapping[str, RuleDetector],
) -> tuple[tuple[RuleDefinition, ...], ...]:
    return tuple(
        tuple(
            _rule_definition(rule_id, detectors_by_rule_id[rule_id])
            for rule_id in rule_group
        )
        for rule_group in _RULE_GROUP_IDS
    )


class StrideRuleEngine:
    def __init__(self, rule_registry: RuleRegistry | None = None) -> None:
        self._rule_registry = (
            rule_registry
            if rule_registry is not None
            else _default_rule_registry()
        )
        self._finding_factory = FindingFactory(self._rule_registry)
        posture_detectors = PostureRuleDetectors(self._finding_factory)
        network_data_detectors = NetworkDataRuleDetectors(self._finding_factory)
        path_chain_detectors = PathChainRuleDetectors(self._finding_factory)
        iam_detectors = IAMRuleDetectors(self._finding_factory)
        policy_trust_detectors = PolicyTrustRuleDetectors(self._finding_factory)
        detectors_by_rule_id: Mapping[str, RuleDetector] = {
            "aws-public-compute-broad-ingress": posture_detectors.detect_public_compute_exposure,
            "aws-rds-storage-encryption-disabled": posture_detectors.detect_unencrypted_databases,
            "aws-s3-public-access": posture_detectors.detect_public_object_storage,
            "aws-database-permissive-ingress": network_data_detectors.detect_database_exposure,
            "aws-missing-tier-segmentation": network_data_detectors.detect_missing_segmentation,
            "aws-sensitive-resource-policy-external-access": (
                policy_trust_detectors.detect_sensitive_resource_policy_exposure
            ),
            "aws-service-resource-policy-external-access": (
                policy_trust_detectors.detect_service_resource_policy_exposure
            ),
            "aws-iam-wildcard-permissions": iam_detectors.detect_wildcard_permissions,
            "aws-workload-role-sensitive-permissions": iam_detectors.detect_workload_role_sensitive_permissions,
            "aws-private-data-transitive-exposure": path_chain_detectors.detect_transitive_private_data_exposure,
            "aws-control-plane-sensitive-workload-chain": (
                path_chain_detectors.detect_control_plane_sensitive_workload_chain
            ),
            "aws-role-trust-expansion": policy_trust_detectors.detect_trust_expansion,
            "aws-role-trust-missing-narrowing": policy_trust_detectors.detect_unconstrained_trust,
        }
        self._rule_groups_by_stage = _build_rule_groups(detectors_by_rule_id)
        (
            self._posture_rules,
            self._network_data_rules,
            self._resource_policy_rules,
            self._iam_rules,
            self._path_chain_rules,
            self._trust_rules,
        ) = self._rule_groups_by_stage

    def configured_rule_ids(self) -> set[str]:
        return {
            rule.metadata.rule_id
            for rule_group in self._rule_groups()
            for rule in rule_group
        }

    def evaluate(
        self,
        inventory: ResourceInventory,
        boundaries: list[TrustBoundary],
        *,
        rule_policy: RulePolicy | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        boundary_index: BoundaryIndex = {
            (boundary.boundary_type, boundary.source, boundary.target): boundary for boundary in boundaries
        }
        context = RuleEvaluationContext(
            inventory=inventory,
            boundary_index=boundary_index,
            rule_registry=self._rule_registry,
            rule_policy=rule_policy,
        )

        for rules in self._rule_groups():
            findings.extend(self._evaluate_rules(rules, context))

        return findings

    def _evaluate_rules(
        self,
        rules: tuple[RuleDefinition, ...],
        context: RuleEvaluationContext,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for definition in rules:
            executable_rule = ExecutableRule(definition.metadata.rule_id, definition.detector)
            findings.extend(executable_rule.evaluate(context))
        return findings

    def _rule_groups(self) -> tuple[tuple[RuleDefinition, ...], ...]:
        return self._rule_groups_by_stage

    def observe_controls(self, inventory: ResourceInventory) -> list[Observation]:
        return collect_control_observations(inventory)