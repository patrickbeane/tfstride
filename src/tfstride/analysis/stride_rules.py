from __future__ import annotations

from collections.abc import Mapping

from tfstride.analysis.control_observations import observe_controls as collect_control_observations
from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.gcp.rules import GcpRuleDetectors
from tfstride.analysis.indexes import AnalysisIndexes, build_analysis_indexes
from tfstride.analysis.path_chain_rules import PathChainRuleDetectors
from tfstride.analysis.rule_definitions import (
    BoundaryIndex,
    ExecutableRule,
    RuleContribution,
    RuleDefinition,
    RuleDetector,
    RuleEvaluationContext,
    build_rule_contribution,
    build_rule_registry_from_contribution,
    merge_rule_contributions_by_stage,
)
from tfstride.analysis.rule_registry import (
    RulePolicy,
    RuleRegistry,
    default_rule_registry,
)
from tfstride.models import Finding, Observation, ResourceInventory, TrustBoundary
from tfstride.providers.aws.rules import build_aws_rule_contribution

RuleGroupIds = tuple[tuple[str, ...], ...]

_GCP_RULE_GROUP_IDS: RuleGroupIds = (
    (
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
    (),
    (),
    (
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
    ("gcp-public-workload-sensitive-data-access",),
    (),
)


def _default_rule_metadata_registry() -> RuleRegistry:
    return default_rule_registry()


def _build_rule_contribution(
    rule_group_ids: RuleGroupIds,
    detectors_by_rule_id: Mapping[str, RuleDetector],
    metadata_registry: RuleRegistry,
) -> RuleContribution:
    return build_rule_contribution(
        (tuple((rule_id, detectors_by_rule_id[rule_id]) for rule_id in rule_group) for rule_group in rule_group_ids),
        metadata_registry,
    )


def _build_gcp_rule_contribution(
    finding_factory: FindingFactory,
    metadata_registry: RuleRegistry,
) -> RuleContribution:
    gcp_detectors = GcpRuleDetectors(finding_factory)
    path_chain_detectors = PathChainRuleDetectors(finding_factory)
    detectors_by_rule_id: Mapping[str, RuleDetector] = {
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
        "gcp-cloud-sql-deletion-protection-disabled": gcp_detectors.detect_cloud_sql_deletion_protection_disabled,
        "gcp-gcs-public-access": gcp_detectors.detect_gcs_public_access,
        "gcp-gcs-uniform-bucket-level-access-disabled": gcp_detectors.detect_gcs_uniform_bucket_level_access_disabled,
        "gcp-gcs-public-access-prevention-not-enforced": (
            gcp_detectors.detect_gcs_public_access_prevention_not_enforced
        ),
        "gcp-gcs-versioning-disabled": gcp_detectors.detect_gcs_versioning_disabled,
        "gcp-gcs-customer-managed-encryption-missing": gcp_detectors.detect_gcs_customer_managed_encryption_missing,
        "gcp-public-compute-broad-ingress": gcp_detectors.detect_public_compute_broad_ingress,
        "gcp-public-load-balanced-workload": gcp_detectors.detect_public_load_balanced_workload,
        "gcp-compute-os-login-disabled": gcp_detectors.detect_compute_os_login_disabled,
        "gcp-gke-public-control-plane": gcp_detectors.detect_gke_public_control_plane,
        "gcp-gke-broad-authorized-networks": gcp_detectors.detect_gke_broad_authorized_networks,
        "gcp-gke-workload-identity-disabled": gcp_detectors.detect_gke_workload_identity_disabled,
        "gcp-gke-legacy-metadata-endpoints-enabled": gcp_detectors.detect_gke_legacy_metadata_endpoints_enabled,
        "gcp-gke-broad-node-service-account": gcp_detectors.detect_gke_broad_node_service_account,
        "gcp-cloud-run-public-invoker": gcp_detectors.detect_cloud_run_public_invoker,
        "gcp-cloud-functions-public-invoker": gcp_detectors.detect_cloud_function_public_invoker,
        "gcp-service-account-iam-broad-principal": gcp_detectors.detect_service_account_iam_broad_principal,
        "gcp-service-account-iam-privileged-role": gcp_detectors.detect_service_account_iam_privileged_role,
        "gcp-service-account-key-hygiene": gcp_detectors.detect_service_account_key_hygiene,
        "gcp-service-account-key-effective-access": gcp_detectors.detect_service_account_key_effective_access,
        "gcp-org-folder-iam-broad-principal": gcp_detectors.detect_org_folder_iam_broad_principal,
        "gcp-org-folder-iam-privileged-role": gcp_detectors.detect_org_folder_iam_privileged_role,
        "gcp-project-iam-broad-principal": gcp_detectors.detect_project_iam_broad_principal,
        "gcp-project-iam-privileged-role": gcp_detectors.detect_project_iam_privileged_role,
        "gcp-inherited-iam-sensitive-resource-access": gcp_detectors.detect_inherited_iam_sensitive_resource_access,
        "gcp-inherited-iam-blast-radius": gcp_detectors.detect_inherited_iam_blast_radius,
        "gcp-public-workload-sensitive-data-access": (
            path_chain_detectors.detect_public_workload_sensitive_data_access
        ),
    }
    return _build_rule_contribution(_GCP_RULE_GROUP_IDS, detectors_by_rule_id, metadata_registry)


def _build_default_rule_contribution(
    finding_factory: FindingFactory,
    metadata_registry: RuleRegistry,
) -> RuleContribution:
    return merge_rule_contributions_by_stage(
        build_aws_rule_contribution(finding_factory, metadata_registry),
        _build_gcp_rule_contribution(finding_factory, metadata_registry),
    )


class StrideRuleEngine:
    def __init__(
        self,
        rule_registry: RuleRegistry | None = None,
        rule_contribution: RuleContribution | None = None,
    ) -> None:
        if rule_contribution is None:
            metadata_registry = _default_rule_metadata_registry()
            finding_registry = rule_registry if rule_registry is not None else metadata_registry
            rule_contribution = _build_default_rule_contribution(
                FindingFactory(finding_registry),
                metadata_registry,
            )

        self._rule_contribution = rule_contribution
        self._rule_registry = (
            rule_registry if rule_registry is not None else build_rule_registry_from_contribution(rule_contribution)
        )

    def configured_rule_ids(self) -> set[str]:
        return {rule.metadata.rule_id for rule_group in self._rule_groups() for rule in rule_group}

    def evaluate(
        self,
        inventory: ResourceInventory,
        boundaries: list[TrustBoundary],
        *,
        analysis_indexes: AnalysisIndexes | None = None,
        rule_policy: RulePolicy | None = None,
    ) -> list[Finding]:
        resolved_indexes = analysis_indexes if analysis_indexes is not None else build_analysis_indexes(inventory)
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

        return self._evaluate_contribution(context)

    def _evaluate_contribution(self, context: RuleEvaluationContext) -> list[Finding]:
        findings: list[Finding] = []
        for rules in self._rule_contribution.rule_groups:
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
        return self._rule_contribution.rule_groups

    def observe_controls(self, inventory: ResourceInventory) -> list[Observation]:
        return collect_control_observations(inventory)
