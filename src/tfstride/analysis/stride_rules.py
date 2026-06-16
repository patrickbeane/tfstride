from __future__ import annotations

from collections.abc import Mapping

from tfstride.analysis.control_observations import observe_controls as collect_control_observations
from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.gcp.rules import GcpRuleDetectors
from tfstride.analysis.iam_rules import IAMRuleDetectors
from tfstride.analysis.indexes import AnalysisIndexes, build_analysis_indexes
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
        "gcp-sensitive-resource-iam-external-access",
        "gcp-pubsub-public-access",
        "gcp-bigquery-public-access",
        "gcp-cloud-sql-public-authorized-network",
        "gcp-cloud-sql-backup-disabled",
        "gcp-cloud-sql-public-ip-without-private-network",
        "gcp-cloud-sql-ssl-not-required",
        "gcp-cloud-sql-point-in-time-recovery-disabled",
        "gcp-cloud-sql-deletion-protection-disabled",
        "gcp-gcs-public-access",
        "gcp-gcs-uniform-bucket-level-access-disabled",
        "gcp-gcs-public-access-prevention-not-enforced",
        "gcp-gcs-versioning-disabled",
        "gcp-gcs-customer-managed-encryption-missing",
        "gcp-public-compute-broad-ingress",
        "gcp-public-load-balanced-workload",
        "gcp-compute-os-login-disabled",
        "gcp-gke-public-control-plane",
        "gcp-gke-broad-authorized-networks",
        "gcp-gke-workload-identity-disabled",
        "gcp-gke-legacy-metadata-endpoints-enabled",
        "gcp-gke-broad-node-service-account",
        "gcp-cloud-run-public-invoker",
        "gcp-cloud-functions-public-invoker",
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
        "gcp-service-account-iam-broad-principal",
        "gcp-service-account-iam-privileged-role",
        "gcp-service-account-key-hygiene",
        "gcp-service-account-key-effective-access",
        "gcp-org-folder-iam-broad-principal",
        "gcp-org-folder-iam-privileged-role",
        "gcp-project-iam-broad-principal",
        "gcp-project-iam-privileged-role",
        "gcp-inherited-iam-sensitive-resource-access",
        "gcp-inherited-iam-blast-radius",
    ),
    (
        "aws-private-data-transitive-exposure",
        "aws-control-plane-sensitive-workload-chain",
        "gcp-public-workload-sensitive-data-access",
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
        self._rule_registry = rule_registry if rule_registry is not None else _default_rule_registry()
        self._finding_factory = FindingFactory(self._rule_registry)
        posture_detectors = PostureRuleDetectors(self._finding_factory)
        gcp_detectors = GcpRuleDetectors(self._finding_factory)
        network_data_detectors = NetworkDataRuleDetectors(self._finding_factory)
        path_chain_detectors = PathChainRuleDetectors(self._finding_factory)
        iam_detectors = IAMRuleDetectors(self._finding_factory)
        policy_trust_detectors = PolicyTrustRuleDetectors(self._finding_factory)
        detectors_by_rule_id: Mapping[str, RuleDetector] = {
            "aws-public-compute-broad-ingress": posture_detectors.detect_public_compute_exposure,
            "aws-rds-storage-encryption-disabled": posture_detectors.detect_unencrypted_databases,
            "aws-s3-public-access": posture_detectors.detect_public_object_storage,
            "gcp-sensitive-resource-iam-external-access": gcp_detectors.detect_sensitive_iam_external_access,
            "gcp-pubsub-public-access": gcp_detectors.detect_pubsub_public_access,
            "gcp-bigquery-public-access": gcp_detectors.detect_bigquery_public_access,
            "gcp-cloud-sql-public-authorized-network": gcp_detectors.detect_cloud_sql_public_authorized_network,
            "gcp-cloud-sql-backup-disabled": gcp_detectors.detect_cloud_sql_backup_disabled,
            "gcp-cloud-sql-public-ip-without-private-network": (
                gcp_detectors.detect_cloud_sql_public_ip_without_private_network
            ),
            "gcp-cloud-sql-ssl-not-required": gcp_detectors.detect_cloud_sql_ssl_not_required,
            "gcp-cloud-sql-point-in-time-recovery-disabled": (
                gcp_detectors.detect_cloud_sql_point_in_time_recovery_disabled
            ),
            "gcp-cloud-sql-deletion-protection-disabled": (
                gcp_detectors.detect_cloud_sql_deletion_protection_disabled
            ),
            "gcp-gcs-public-access": gcp_detectors.detect_gcs_public_access,
            "gcp-gcs-uniform-bucket-level-access-disabled": (
                gcp_detectors.detect_gcs_uniform_bucket_level_access_disabled
            ),
            "gcp-gcs-public-access-prevention-not-enforced": (
                gcp_detectors.detect_gcs_public_access_prevention_not_enforced
            ),
            "gcp-gcs-versioning-disabled": gcp_detectors.detect_gcs_versioning_disabled,
            "gcp-gcs-customer-managed-encryption-missing": (
                gcp_detectors.detect_gcs_customer_managed_encryption_missing
            ),
            "gcp-public-compute-broad-ingress": gcp_detectors.detect_public_compute_broad_ingress,
            "gcp-public-load-balanced-workload": gcp_detectors.detect_public_load_balanced_workload,
            "gcp-compute-os-login-disabled": gcp_detectors.detect_compute_os_login_disabled,
            "gcp-gke-public-control-plane": gcp_detectors.detect_gke_public_control_plane,
            "gcp-gke-broad-authorized-networks": gcp_detectors.detect_gke_broad_authorized_networks,
            "gcp-gke-workload-identity-disabled": gcp_detectors.detect_gke_workload_identity_disabled,
            "gcp-gke-legacy-metadata-endpoints-enabled": (
                gcp_detectors.detect_gke_legacy_metadata_endpoints_enabled
            ),
            "gcp-gke-broad-node-service-account": gcp_detectors.detect_gke_broad_node_service_account,
            "gcp-cloud-run-public-invoker": gcp_detectors.detect_cloud_run_public_invoker,
            "gcp-cloud-functions-public-invoker": gcp_detectors.detect_cloud_function_public_invoker,
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
            "gcp-service-account-iam-broad-principal": (
                gcp_detectors.detect_service_account_iam_broad_principal
            ),
            "gcp-service-account-iam-privileged-role": (
                gcp_detectors.detect_service_account_iam_privileged_role
            ),
            "gcp-service-account-key-hygiene": gcp_detectors.detect_service_account_key_hygiene,
            "gcp-service-account-key-effective-access": (
                gcp_detectors.detect_service_account_key_effective_access
            ),
            "gcp-org-folder-iam-broad-principal": gcp_detectors.detect_org_folder_iam_broad_principal,
            "gcp-org-folder-iam-privileged-role": gcp_detectors.detect_org_folder_iam_privileged_role,
            "gcp-project-iam-broad-principal": gcp_detectors.detect_project_iam_broad_principal,
            "gcp-project-iam-privileged-role": gcp_detectors.detect_project_iam_privileged_role,
            "gcp-inherited-iam-sensitive-resource-access": (
                gcp_detectors.detect_inherited_iam_sensitive_resource_access
            ),
            "gcp-inherited-iam-blast-radius": gcp_detectors.detect_inherited_iam_blast_radius,
            "aws-private-data-transitive-exposure": path_chain_detectors.detect_transitive_private_data_exposure,
            "aws-control-plane-sensitive-workload-chain": (
                path_chain_detectors.detect_control_plane_sensitive_workload_chain
            ),
            "gcp-public-workload-sensitive-data-access": (
                path_chain_detectors.detect_public_workload_sensitive_data_access
            ),
            "aws-role-trust-expansion": policy_trust_detectors.detect_trust_expansion,
            "aws-role-trust-missing-narrowing": policy_trust_detectors.detect_unconstrained_trust,
        }
        self._rule_groups_by_stage = _build_rule_groups(detectors_by_rule_id)

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
        analysis_indexes: AnalysisIndexes | None = None,
        rule_policy: RulePolicy | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        resolved_indexes = (
            analysis_indexes
            if analysis_indexes is not None
            else build_analysis_indexes(inventory)
        )
        boundary_index: BoundaryIndex = {
            (boundary.boundary_type, boundary.source, boundary.target): boundary for boundary in boundaries
        }
        context = RuleEvaluationContext(
            inventory=inventory,
            boundary_index=boundary_index,
            rule_registry=self._rule_registry,
            analysis_indexes=resolved_indexes,
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