from __future__ import annotations

from collections.abc import Mapping

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.iam_rules import IAMRuleDetectors
from tfstride.analysis.network_data_rules import NetworkDataRuleDetectors
from tfstride.analysis.path_chain_rules import PathChainRuleDetectors
from tfstride.analysis.policy_trust_rules import PolicyTrustRuleDetectors
from tfstride.analysis.posture_rules import PostureRuleDetectors
from tfstride.analysis.rule_definitions import RuleContribution, RuleDetector, build_rule_contribution
from tfstride.analysis.rule_registry import RuleRegistry, default_rule_registry

AWS_RULE_GROUP_IDS: tuple[tuple[str, ...], ...] = (
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


def build_aws_rule_contribution(
    finding_factory: FindingFactory,
    metadata_registry: RuleRegistry | None = None,
) -> RuleContribution:
    posture_detectors = PostureRuleDetectors(finding_factory)
    network_data_detectors = NetworkDataRuleDetectors(finding_factory)
    path_chain_detectors = PathChainRuleDetectors(finding_factory)
    iam_detectors = IAMRuleDetectors(finding_factory)
    policy_trust_detectors = PolicyTrustRuleDetectors(finding_factory)
    detectors_by_rule_id: Mapping[str, RuleDetector] = {
        "aws-public-compute-broad-ingress": posture_detectors.detect_public_compute_exposure,
        "aws-rds-storage-encryption-disabled": posture_detectors.detect_unencrypted_databases,
        "aws-s3-public-access": posture_detectors.detect_public_object_storage,
        "aws-database-permissive-ingress": network_data_detectors.detect_database_exposure,
        "aws-missing-tier-segmentation": network_data_detectors.detect_missing_segmentation,
        "aws-sensitive-resource-policy-external-access": (
            policy_trust_detectors.detect_sensitive_resource_policy_exposure
        ),
        "aws-service-resource-policy-external-access": policy_trust_detectors.detect_service_resource_policy_exposure,
        "aws-iam-wildcard-permissions": iam_detectors.detect_wildcard_permissions,
        "aws-workload-role-sensitive-permissions": iam_detectors.detect_workload_role_sensitive_permissions,
        "aws-private-data-transitive-exposure": path_chain_detectors.detect_transitive_private_data_exposure,
        "aws-control-plane-sensitive-workload-chain": (
            path_chain_detectors.detect_control_plane_sensitive_workload_chain
        ),
        "aws-role-trust-expansion": policy_trust_detectors.detect_trust_expansion,
        "aws-role-trust-missing-narrowing": policy_trust_detectors.detect_unconstrained_trust,
    }
    resolved_metadata_registry = metadata_registry if metadata_registry is not None else default_rule_registry()
    return build_rule_contribution(
        (
            tuple((rule_id, detectors_by_rule_id[rule_id]) for rule_id in rule_group)
            for rule_group in AWS_RULE_GROUP_IDS
        ),
        resolved_metadata_registry,
    )
