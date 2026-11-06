from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import cast

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, Finding, NormalizedResource
from tfstride.providers.gcp.analysis_indexes import gcp_gcs_grant_context
from tfstride.providers.gcp.cloud_run_public_invocation import (
    cloud_run_public_exposure_configuration,
    cloud_run_public_invoker_evidence,
    current_cloud_run_public_exposure_reasons,
    current_cloud_run_public_invokers,
)
from tfstride.providers.gcp.gcs_grant_evaluation import GcsGrantConstraintContext
from tfstride.providers.gcp.object_storage_topology_destruction_evidence import (
    GcpCloudRunGcsBucketTopologyDestructionPath,
)
from tfstride.providers.gcp.resource_decoration.cloud_run_gcs_bucket_topology_destruction_paths import (
    current_cloud_run_gcs_bucket_topology_destruction_paths,
)
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext
from tfstride.providers.gcp.resource_types import GCP_CLOUD_RUN_RESOURCE_TYPES, GcpResourceType

_DELETE_BUCKET = "storage.buckets.delete"
_BUCKET_TOPOLOGY_DESTRUCTION_OPERATION = _DELETE_BUCKET
_AUTHORIZATION_RELATIONSHIP_FIELDS = (
    "workload_address",
    "workload_type",
    "service_account_email",
    "service_account_member",
    "identity_kind",
    "credential_context",
    "bucket_address",
    "bucket_resource_type",
    "operation",
    "operation_class",
    "internal_operation",
    "management_effect",
    "target_granularity",
    "target_scope",
    "target_model_evidence_addresses",
    "iam_resource_address",
    "iam_resource_type",
    "iam_source_addresses",
    "role",
    "scope_type",
    "scope",
    "resource_scope",
    "grant_basis",
)


class GcpCloudRunGcsBucketTopologyDisruptionRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_cloud_run_gcs_bucket_topology_disruption(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []
        grant_context = gcp_gcs_grant_context(context.analysis_indexes, context.inventory)
        if grant_context is None:
            return []

        resources = list(context.inventory.resources)
        decoration_context = GcpDecorationContext(grant_context.index)
        findings: list[Finding] = []
        for workload in context.inventory.by_type(*GCP_CLOUD_RUN_RESOURCE_TYPES):
            public_invokers = current_cloud_run_public_invokers(
                workload,
                resources,
            )
            invoker_iam_check_disabled = gcp_facts(workload).cloud_run_invoker_iam_disabled is True
            if not workload.public_access_configured or (not public_invokers and not invoker_iam_check_disabled):
                continue

            paths: list[GcpCloudRunGcsBucketTopologyDestructionPath] = []
            for cached_path in gcp_facts(workload).cloud_run_gcs_bucket_topology_destruction_paths:
                current_path = _current_topology_path(
                    cached_path,
                    workload,
                    context,
                    decoration_context,
                    grant_context,
                )
                if current_path is not None:
                    paths.append(current_path)
            if not paths:
                continue

            bucket_addresses = _path_string_values(paths, "bucket_address")
            iam_source_addresses = _path_string_values(paths, "iam_source_addresses")
            public_source_addresses = sorted({binding["source"] for binding in public_invokers})
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=2 if len(bucket_addresses) > 1 else 1,
            )
            boundary = context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", workload.address))
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            workload.address,
                            *public_source_addresses,
                            *bucket_addresses,
                            *iam_source_addresses,
                        ]
                    ),
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=_rationale(workload, len(bucket_addresses)),
                    evidence=collect_evidence(
                        evidence_item(
                            "public_invoker_bindings",
                            cloud_run_public_invoker_evidence(public_invokers),
                        ),
                        evidence_item(
                            "public_exposure_reasons",
                            current_cloud_run_public_exposure_reasons(
                                workload,
                                public_invokers,
                                invoker_iam_check_disabled=invoker_iam_check_disabled,
                            ),
                        ),
                        evidence_item(
                            "public_exposure_configuration",
                            cloud_run_public_exposure_configuration(workload),
                        ),
                        evidence_item(
                            "runtime_identity",
                            _runtime_identity_evidence(paths),
                        ),
                        evidence_item(
                            "gcs_bucket_topology_destruction_paths",
                            _topology_path_evidence(paths),
                        ),
                        evidence_item(
                            "bucket_deletion_recovery_evidence",
                            _recovery_evidence(paths),
                        ),
                        evidence_item(
                            "bucket_topology_destruction_path_uncertainties",
                            _current_path_uncertainties(paths),
                        ),
                        evidence_item("assessment_scope", _assessment_scope()),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _current_topology_path(
    cached_path: Mapping[str, object],
    workload: NormalizedResource,
    context: RuleEvaluationContext,
    decoration_context: GcpDecorationContext,
    grant_context: GcsGrantConstraintContext,
) -> GcpCloudRunGcsBucketTopologyDestructionPath | None:
    if (
        cached_path.get("workload_address") != workload.address
        or cached_path.get("workload_type") != workload.resource_type
        or cached_path.get("operation") != _BUCKET_TOPOLOGY_DESTRUCTION_OPERATION
        or cached_path.get("operation_class") != "bucket_deletion"
        or cached_path.get("internal_operation") != "delete_bucket"
        or cached_path.get("management_effect") != "disruption"
        or cached_path.get("target_granularity") != "bucket_topology"
        or cached_path.get("target_scope") != "exact_gcs_bucket"
        or cached_path.get("authorization_state") != "granted"
        or cached_path.get("policy_complete") is not True
        or cached_path.get("iam_manager_ambiguity_state") != "not_detected"
        or cached_path.get("condition") is not None
        or cached_path.get("condition_state") != "not_configured"
        or cached_path.get("matched_permissions") != [_DELETE_BUCKET]
        or cached_path.get("lifecycle_compatibility_state") != "bucket_emptiness_not_established"
    ):
        return None

    bucket_address = _known_string(cached_path.get("bucket_address"))
    if bucket_address is None:
        return None
    bucket = context.inventory.get_by_address(bucket_address)
    if bucket is None or bucket.provider != "gcp" or bucket.resource_type != GcpResourceType.STORAGE_BUCKET:
        return None

    current_paths = current_cloud_run_gcs_bucket_topology_destruction_paths(
        workload,
        bucket,
        list(context.inventory.resources),
        decoration_context,
        grant_context=grant_context,
    )
    return next(
        (
            current_path
            for current_path in current_paths
            if _authorization_relationship_matches(cached_path, current_path)
        ),
        None,
    )


def _authorization_relationship_matches(
    cached_path: Mapping[str, object],
    current_path: Mapping[str, object],
) -> bool:
    return all(cached_path.get(field) == current_path.get(field) for field in _AUTHORIZATION_RELATIONSHIP_FIELDS)


def _current_path_uncertainties(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted({uncertainty for path in paths for uncertainty in _string_values(path.get("posture_uncertainties"))})


def _path_string_values(paths: Sequence[Mapping[str, object]], key: str) -> list[str]:
    values: set[str] = set()
    for path in paths:
        value = path.get(key)
        if key == "iam_source_addresses":
            if isinstance(value, list):
                values.update(item for item in value if isinstance(item, str) and item)
        elif isinstance(value, str) and value:
            values.add(value)
    return sorted(values)


def _runtime_identity_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"service_account={path.get('service_account_email')}",
                    f"member={path.get('service_account_member')}",
                    "identity_kind=cloud_run_service_account",
                    "credential_context=workload_runtime",
                )
            )
            for path in paths
        }
    )


def _topology_path_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"bucket_address={path.get('bucket_address')}",
                    f"bucket_name={path.get('bucket_name')}",
                    f"bucket_project={path.get('bucket_project')}",
                    f"bucket_reference={path.get('bucket_reference')}",
                    f"operation={path.get('operation')}",
                    f"operation_class={path.get('operation_class')}",
                    f"target_granularity={path.get('target_granularity')}",
                    f"target_scope={path.get('target_scope')}",
                    f"scope_type={path.get('scope_type')}",
                    f"scope={path.get('scope')}",
                    f"iam_resource={path.get('iam_resource_address')}",
                    f"iam_sources={','.join(_string_values(path.get('iam_source_addresses'))) or 'none'}",
                    f"role={path.get('role')}",
                    f"role_kind={_role_kind(path.get('role_evidence'))}",
                    (
                        "custom_role_permissions="
                        f"{','.join(_custom_role_permissions(path.get('role_evidence'))) or 'none'}"
                    ),
                    f"matched_permissions={','.join(_string_values(path.get('matched_permissions')))}",
                    "authorization_state=granted",
                    "operation_evaluation=deterministic_allowed",
                )
            )
            for path in paths
        }
    )


def _recovery_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        evidence = path.get("recovery_evidence")
        if not isinstance(evidence, Mapping):
            continue
        evidence_map = cast(Mapping[str, object], evidence)
        values.add(
            "; ".join(
                (
                    f"bucket_address={path.get('bucket_address')}",
                    f"recovery_evidence_scope={evidence_map.get('recovery_evidence_scope')}",
                    f"bucket_emptiness_required={_display(evidence_map.get('bucket_emptiness_required'))}",
                    f"bucket_emptiness_state={_display(evidence_map.get('bucket_emptiness_state'))}",
                    f"soft_delete_state={_display(evidence_map.get('soft_delete_state'))}",
                    f"soft_delete_retention_duration_seconds={_display(evidence_map.get('soft_delete_retention_duration_seconds'))}",
                    f"versioning_enabled={_display(evidence_map.get('versioning_enabled'))}",
                    f"retention_period_seconds={_display(evidence_map.get('retention_period_seconds'))}",
                    f"retention_policy_locked={_display(evidence_map.get('retention_policy_locked'))}",
                    f"bucket_recovery_state={_display(evidence_map.get('bucket_recovery_state'))}",
                    f"out_of_plan_object_inventory_evaluated={_display(evidence_map.get('out_of_plan_object_inventory_evaluated'))}",
                    f"successful_deletion_observed={_display(evidence_map.get('successful_deletion_observed'))}",
                    f"restoration_observed={_display(evidence_map.get('restoration_observed'))}",
                )
            )
        )
    return sorted(values)


def _assessment_scope() -> list[str]:
    return [
        (
            "establishes=deterministic storage.buckets.delete authority over exact modeled "
            "GCS bucket topology with Denial of Service effect"
        ),
        ("does_not_establish=bucket emptiness, successful deletion, recovery, or authority over out-of-plan objects"),
    ]


def _rationale(workload: NormalizedResource, bucket_count: int) -> str:
    bucket_text = "bucket" if bucket_count == 1 else "buckets"
    return (
        f"{workload.display_name} is publicly invokable and its Cloud Run runtime service account has "
        f"deterministic GCS bucket-topology deletion authority (storage.buckets.delete) across {bucket_count} "
        f"exact modeled GCS {bucket_text}. A compromise of the public workload could request deletion of those "
        "bucket topologies, subject to provider-side bucket deletion prerequisites. This plan-local evidence does "
        "not establish bucket emptiness, successful deletion, recovery, or out-of-plan objects."
    )


def _role_kind(value: object) -> str:
    if isinstance(value, Mapping):
        role_kind = cast(Mapping[str, object], value).get("role_kind")
        if isinstance(role_kind, str):
            return role_kind
    return "unknown"


def _custom_role_permissions(value: object) -> list[str]:
    if not isinstance(value, Mapping):
        return []
    return _string_values(cast(Mapping[str, object], value).get("custom_role_permissions"))


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in cast(list[object], value) if isinstance(item, str) and item]


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _display(value: object) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)
