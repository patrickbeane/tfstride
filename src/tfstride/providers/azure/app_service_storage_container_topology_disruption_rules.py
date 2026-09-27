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
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.azure.app_service_ingress_helpers import app_service_ingress
from tfstride.providers.azure.object_storage_topology_destruction_evidence import (
    AzureAppServiceStorageContainerTopologyDestructionPath,
)
from tfstride.providers.azure.resource_decoration.app_service_storage_container_topology_destruction_paths import (
    current_app_service_storage_container_topology_destruction_paths,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext, AzureResourceIndexBuilder
from tfstride.providers.azure.resource_types import AZURE_APP_SERVICE_RESOURCE_TYPES, AzureResourceType

_DELETE_CONTAINER = "Microsoft.Storage/storageAccounts/blobServices/containers/delete"
_AUTHORIZATION_RELATIONSHIP_FIELDS = (
    "workload_address",
    "workload_type",
    "identity_address",
    "identity_kind",
    "principal_id",
    "credential_context",
    "storage_account_address",
    "storage_account_id",
    "container_address",
    "container_resource_manager_id",
    "operation",
    "operation_class",
    "internal_operation",
    "management_effect",
    "authorization_evidence_kind",
    "target_granularity",
    "target_scope",
    "target_model_evidence_addresses",
    "role_assignment_address",
    "authorization_source_addresses",
    "authorization_state",
    "modeled_allow_evidence_complete",
    "condition",
    "condition_state",
)


class AzureAppServiceStorageContainerTopologyDisruptionRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_app_service_storage_container_topology_disruption(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        resources = list(context.inventory.resources)
        decoration_context = AzureDecorationContext(AzureResourceIndexBuilder().build(resources))
        findings: list[Finding] = []
        for workload in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            workload_facts = azure_facts(workload)
            ingress = app_service_ingress(workload, context)
            if not ingress.is_public:
                continue

            paths: list[AzureAppServiceStorageContainerTopologyDestructionPath] = []
            for cached_path in workload_facts.app_service_storage_container_topology_destruction_paths:
                current_path = _current_topology_path(
                    cached_path,
                    workload,
                    context,
                    decoration_context,
                )
                if current_path is not None:
                    paths.append(current_path)
            if not paths:
                continue

            container_addresses = _path_string_values(paths, "container_address")
            account_addresses = _path_string_values(paths, "storage_account_address")
            identity_addresses = _path_string_values(paths, "identity_address")
            authorization_sources = _path_string_values(paths, "authorization_source_addresses")
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=2 if len(container_addresses) > 1 or len(account_addresses) > 1 else 1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            workload.address,
                            *(address for address in identity_addresses if address != workload.address),
                            *account_addresses,
                            *container_addresses,
                            *authorization_sources,
                        ]
                    ),
                    trust_boundary_id=None,
                    rationale=_rationale(workload, len(container_addresses)),
                    evidence=collect_evidence(
                        *ingress.evidence,
                        evidence_item("runtime_identity", _runtime_identity_evidence(paths)),
                        evidence_item(
                            "storage_container_topology_destruction_paths",
                            _topology_path_evidence(paths),
                        ),
                        evidence_item(
                            "container_authorization_evidence",
                            _authorization_evidence(paths),
                        ),
                        evidence_item(
                            "container_deletion_prerequisite_evidence",
                            _prerequisite_evidence(paths),
                        ),
                        evidence_item(
                            "container_soft_delete_recovery_evidence",
                            _recovery_evidence(paths),
                        ),
                        evidence_item(
                            "storage_container_topology_destruction_path_uncertainties",
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
    decoration_context: AzureDecorationContext,
) -> AzureAppServiceStorageContainerTopologyDestructionPath | None:
    if (
        cached_path.get("workload_address") != workload.address
        or cached_path.get("workload_type") != workload.resource_type
        or cached_path.get("operation") != _DELETE_CONTAINER
        or cached_path.get("operation_class") != "container_deletion"
        or cached_path.get("internal_operation") != "delete_container"
        or cached_path.get("management_effect") != "disruption"
        or cached_path.get("authorization_evidence_kind") != "azure_rbac_action"
        or cached_path.get("target_granularity") != "container_topology"
        or cached_path.get("target_scope") != "exact_storage_container"
        or cached_path.get("authorization_state") != "granted"
        or cached_path.get("modeled_allow_evidence_complete") is not True
        or cached_path.get("condition") is not None
        or cached_path.get("condition_state") != "not_configured"
        or cached_path.get("lifecycle_compatibility_state") not in {"compatible", "unknown"}
    ):
        return None

    container_address = _known_string(cached_path.get("container_address"))
    if container_address is None:
        return None
    container = context.inventory.get_by_address(container_address)
    if (
        container is None
        or container.provider != "azure"
        or container.resource_type != AzureResourceType.STORAGE_CONTAINER
    ):
        return None

    current_paths = current_app_service_storage_container_topology_destruction_paths(
        workload,
        container,
        list(context.inventory.resources),
        decoration_context,
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


def _path_string_values(paths: Sequence[Mapping[str, object]], key: str) -> list[str]:
    values: set[str] = set()
    for path in paths:
        value = path.get(key)
        if key in {"authorization_source_addresses", "target_model_evidence_addresses"}:
            if isinstance(value, list):
                values.update(item for item in value if isinstance(item, str) and item)
        elif isinstance(value, str) and value:
            values.add(value)
    return sorted(values)


def _current_path_uncertainties(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted({uncertainty for path in paths for uncertainty in _string_values(path.get("posture_uncertainties"))})


def _runtime_identity_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"identity_address={path.get('identity_address')}",
                    f"identity_kind={path.get('identity_kind')}",
                    f"principal_id={path.get('principal_id')}",
                    "credential_context=workload_runtime",
                    "authorization_state=granted",
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
                    f"storage_account_address={path.get('storage_account_address')}",
                    f"container_address={path.get('container_address')}",
                    f"container_name={path.get('container_name')}",
                    f"operation={path.get('operation')}",
                    f"operation_class={path.get('operation_class')}",
                    f"target_granularity={path.get('target_granularity')}",
                    f"target_scope={path.get('target_scope')}",
                    f"target_model_evidence_addresses={','.join(_string_values(path.get('target_model_evidence_addresses'))) or 'none'}",
                    f"role_assignment_address={path.get('role_assignment_address')}",
                    f"authorization_sources={','.join(_string_values(path.get('authorization_source_addresses'))) or 'none'}",
                    f"authorization_state={path.get('authorization_state')}",
                    "operation_evaluation=deterministic_allowed",
                )
            )
            for path in paths
        }
    )


def _authorization_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        grant = path.get("authorization_grant")
        if not isinstance(grant, Mapping):
            continue
        grant_map = cast(Mapping[str, object], grant)
        role_evidence = grant_map.get("role_evidence")
        role_map: Mapping[str, object] = (
            cast(Mapping[str, object], role_evidence) if isinstance(role_evidence, Mapping) else {}
        )
        values.add(
            "; ".join(
                (
                    f"container_address={path.get('container_address')}",
                    f"assignment_scope_type={grant_map.get('assignment_scope_type')}",
                    f"assignment_scope_arm_id={grant_map.get('assignment_scope_arm_id')}",
                    f"role_kind={role_map.get('role_kind', 'unknown')}",
                    f"role_definition_address={role_map.get('role_definition_address') or 'none'}",
                    f"role_definition_name={grant_map.get('role_definition_name') or 'unknown'}",
                    f"role_actions={','.join(_string_values(grant_map.get('role_actions'))) or 'none'}",
                    f"role_not_actions={','.join(_string_values(grant_map.get('role_not_actions'))) or 'none'}",
                    f"requested_actions={','.join(_string_values(grant_map.get('requested_actions')))}",
                    f"matched_actions={','.join(_string_values(grant_map.get('matched_actions')))}",
                    "condition_state=not_configured",
                    "authorization_state=granted",
                )
            )
        )
    return sorted(values)


def _prerequisite_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        constraints = path.get("deletion_constraint_evidence")
        if not isinstance(constraints, Mapping):
            continue
        constraints_map = cast(Mapping[str, object], constraints)
        values.add(
            "; ".join(
                (
                    f"container_address={path.get('container_address')}",
                    f"has_immutability_policy={_display(constraints_map.get('has_immutability_policy'))}",
                    f"has_legal_hold={_display(constraints_map.get('has_legal_hold'))}",
                    f"protected_content_emptiness_required={_display(constraints_map.get('protected_content_emptiness_required'))}",
                    f"protected_content_emptiness_state={_display(constraints_map.get('protected_content_emptiness_state'))}",
                    f"constraint_state={constraints_map.get('constraint_state')}",
                    f"uncertainties={','.join(_string_values(constraints_map.get('uncertainties'))) or 'none'}",
                )
            )
        )
    return sorted(values)


def _recovery_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        recovery = path.get("recovery_evidence")
        if not isinstance(recovery, Mapping):
            continue
        recovery_map = cast(Mapping[str, object], recovery)
        values.add(
            "; ".join(
                (
                    f"container_address={path.get('container_address')}",
                    f"container_soft_delete_state={_display(recovery_map.get('container_soft_delete_state'))}",
                    f"container_delete_retention_days={_display(recovery_map.get('container_delete_retention_days'))}",
                    f"container_recovery_state={_display(recovery_map.get('container_recovery_state'))}",
                    f"successful_deletion_observed={_display(recovery_map.get('successful_deletion_observed'))}",
                    f"restoration_observed={_display(recovery_map.get('restoration_observed'))}",
                    f"storage_account_deletion_evaluated={_display(recovery_map.get('storage_account_deletion_evaluated'))}",
                    f"out_of_plan_blob_inventory_evaluated={_display(recovery_map.get('out_of_plan_blob_inventory_evaluated'))}",
                    f"uncertainties={','.join(_string_values(recovery_map.get('uncertainties'))) or 'none'}",
                )
            )
        )
    return sorted(values)


def _assessment_scope() -> list[str]:
    return [
        (
            "establishes=deterministic Azure RBAC container-delete authority over exact modeled "
            "Blob container topology with Denial of Service effect"
        ),
        (
            "does_not_establish=protected-content emptiness, successful deletion, storage-account deletion, "
            "restoration, or out-of-plan blob inventory"
        ),
    ]


def _rationale(workload: NormalizedResource, container_count: int) -> str:
    container_text = "container" if container_count == 1 else "containers"
    return (
        f"{workload.display_name} is publicly reachable and its App Service runtime identity has deterministic "
        f"Azure RBAC authority to delete exact modeled Blob {container_text} ({_DELETE_CONTAINER}). A compromise "
        f"could request deletion of those container topologies across {container_count} exact modeled Blob "
        f"{container_text}. Protection posture may require protected-content emptiness, but this plan-local evidence "
        "does not establish that prerequisite, successful deletion, restoration, storage-account deletion, or "
        "out-of-plan blob inventory."
    )


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
