from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Literal, cast

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, Finding, NormalizedResource
from tfstride.providers.gcp.cloud_run_public_invocation import (
    cloud_run_public_exposure_configuration,
    cloud_run_public_invoker_evidence,
    current_cloud_run_public_exposure_reasons,
    current_cloud_run_public_invokers,
)
from tfstride.providers.gcp.custom_role_index import GcpCustomRoleIndex, build_gcp_custom_role_index
from tfstride.providers.gcp.messaging_topology_destruction_evidence import (
    GcpPubsubTopologyDestructionOperation,
)
from tfstride.providers.gcp.resource_decoration.cloud_run_pubsub_topology_destruction_paths import (
    _iam_manager_ambiguities,
    _iam_resource_types,
    _iam_scope,
    _project_organizations,
    _role_evidence,
    _role_reconciliation_key,
    _topology_targets,
    _TopologyTarget,
)
from tfstride.providers.gcp.resource_decoration.iam import iam_bindings
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext, GcpResourceIndexBuilder
from tfstride.providers.gcp.resource_types import (
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.gcp.resource_utils import binding_members

_TargetKind = Literal["topic", "subscription"]
_DELETE_TOPIC: GcpPubsubTopologyDestructionOperation = "pubsub.topics.delete"
_DELETE_SUBSCRIPTION: GcpPubsubTopologyDestructionOperation = "pubsub.subscriptions.delete"
_OPERATION_ORDER: tuple[GcpPubsubTopologyDestructionOperation, ...] = (
    _DELETE_TOPIC,
    _DELETE_SUBSCRIPTION,
)
_EXPECTED_OPERATIONS: dict[
    _TargetKind,
    tuple[GcpPubsubTopologyDestructionOperation, str, str, str, str, str],
] = {
    "topic": (
        _DELETE_TOPIC,
        "topic_deletion",
        "delete_topic",
        "topic_topology",
        "exact_pubsub_topic",
        GcpResourceType.PUBSUB_TOPIC,
    ),
    "subscription": (
        _DELETE_SUBSCRIPTION,
        "subscription_deletion",
        "delete_subscription",
        "subscription_topology",
        "exact_pubsub_subscription",
        GcpResourceType.PUBSUB_SUBSCRIPTION,
    ),
}
_EXPECTED_OUTCOME_EVIDENCE = {
    "outcome_evidence_scope": "plan_local_pubsub_topology_deletion_authority",
    "successful_deletion_observed": False,
    "recovery_state": "not_established_by_modeled_gcp_messaging_topology_evidence",
    "descendant_impact_evaluated": False,
    "out_of_plan_topology_evaluated": False,
    "uncertainties": [],
}


class GcpCloudRunPubsubTopologyDisruptionRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_cloud_run_pubsub_topology_disruption(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        resources = list(context.inventory.resources)
        decoration_context = GcpDecorationContext(GcpResourceIndexBuilder().build(resources))
        targets, _target_uncertainties = _topology_targets(resources, decoration_context)
        custom_roles = build_gcp_custom_role_index(resources)
        project_organizations = _project_organizations(resources)
        findings: list[Finding] = []

        for workload in context.inventory.by_type(*GCP_CLOUD_RUN_RESOURCE_TYPES):
            public_invokers = current_cloud_run_public_invokers(
                workload,
                resources,
            )
            invoker_iam_check_disabled = gcp_facts(workload).cloud_run_invoker_iam_disabled is True
            if not workload.public_access_configured or (not public_invokers and not invoker_iam_check_disabled):
                continue

            paths = [
                path
                for path in gcp_facts(workload).cloud_run_pubsub_topology_destruction_paths
                if _is_current_topology_path(
                    path,
                    workload,
                    resources,
                    targets,
                    decoration_context,
                    custom_roles,
                    project_organizations,
                )
            ]
            if not paths:
                continue

            target_addresses = _path_string_values(paths, "messaging_resource_address")
            iam_source_addresses = sorted(
                {source for path in paths for source in _string_values(path.get("iam_source_addresses"))}
            )
            public_source_addresses = sorted({binding["source"] for binding in public_invokers})
            operations = _operations(paths)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2,
                data_sensitivity=1,
                lateral_movement=1,
                blast_radius=2 if len(target_addresses) > 1 else 1,
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
                            *target_addresses,
                            *iam_source_addresses,
                        ]
                    ),
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=_rationale(workload, operations, len(target_addresses)),
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
                            "pubsub_topology_destruction_paths",
                            _topology_path_evidence(paths),
                        ),
                        evidence_item(
                            "topology_deletion_outcome_evidence",
                            _outcome_evidence(paths),
                        ),
                        evidence_item(
                            "topology_destruction_path_uncertainties",
                            gcp_facts(workload).cloud_run_pubsub_topology_destruction_path_uncertainties,
                        ),
                        evidence_item("assessment_scope", _assessment_scope(operations)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _is_current_topology_path(
    path: Mapping[str, object],
    workload: NormalizedResource,
    resources: Sequence[NormalizedResource],
    targets: Sequence[_TopologyTarget],
    decoration_context: GcpDecorationContext,
    custom_roles: GcpCustomRoleIndex,
    project_organizations: Mapping[str, str],
) -> bool:
    raw_kind = _known_string(path.get("messaging_resource_kind"))
    if raw_kind not in {"topic", "subscription"}:
        return False
    kind = cast(_TargetKind, raw_kind)
    expected = _EXPECTED_OPERATIONS[kind]
    operation, operation_class, internal_operation, granularity, target_scope, target_type = expected
    target_address = _known_string(path.get("messaging_resource_address"))
    target = next(
        (
            candidate
            for candidate in targets
            if candidate.kind == kind and target_address is not None and candidate.resource.address == target_address
        ),
        None,
    )
    if target is None:
        return False

    workload_facts = gcp_facts(workload)
    service_account_email = _known_string(workload_facts.service_account_email)
    service_account_member = _known_string(workload_facts.service_account_member)
    if (
        service_account_email is None
        or service_account_member is None
        or service_account_member != f"serviceAccount:{service_account_email}"
        or path.get("workload_address") != workload.address
        or path.get("workload_type") != workload.resource_type
        or path.get("service_account_email") != service_account_email
        or path.get("service_account_member") != service_account_member
        or path.get("identity_kind") != "cloud_run_service_account"
        or path.get("credential_context") != "workload_runtime"
    ):
        return False

    expected_target_fields = _target_fields(target)
    if any(path.get(field) != value for field, value in expected_target_fields.items()):
        return False
    if (
        path.get("messaging_resource_type") != target_type
        or path.get("operation") != operation
        or path.get("operation_class") != operation_class
        or path.get("internal_operation") != internal_operation
        or path.get("target_granularity") != granularity
        or path.get("target_scope") != target_scope
        or path.get("management_effect") != "disruption"
        or path.get("matched_permissions") != [operation]
        or path.get("authorization_state") != "granted"
        or path.get("policy_complete") is not True
        or path.get("iam_manager_ambiguity_state") != "not_detected"
        or path.get("condition") is not None
        or path.get("condition_state") != "not_configured"
        or path.get("lifecycle_compatibility_state") != "not_applicable"
        or path.get("posture_uncertainties") != []
        or path.get("outcome_evidence") != _EXPECTED_OUTCOME_EVIDENCE
    ):
        return False

    iam_resource_address = _known_string(path.get("iam_resource_address"))
    role = _known_string(path.get("role"))
    source_addresses = path.get("iam_source_addresses")
    if (
        iam_resource_address is None
        or role is None
        or not isinstance(source_addresses, list)
        or not source_addresses
        or not all(isinstance(address, str) and address for address in source_addresses)
    ):
        return False
    iam_resource = next(
        (resource for resource in resources if resource.address == iam_resource_address),
        None,
    )
    if (
        iam_resource is None
        or iam_resource.resource_type not in _iam_resource_types(kind)
        or path.get("iam_resource_type") != iam_resource.resource_type
    ):
        return False

    scope_type, scope, scope_uncertainty = _iam_scope(iam_resource, target, decoration_context)
    if (
        scope_uncertainty is not None
        or scope_type is None
        or scope is None
        or path.get("scope_type") != scope_type
        or path.get("scope") != scope
        or path.get("grant_basis") != ("pubsub_project_iam" if scope_type == "project" else f"pubsub_{kind}_iam")
        or path.get("resource_scope") != ("pubsub_project" if scope_type == "project" else f"exact_pubsub_{kind}")
    ):
        return False

    current_binding_source = _current_grant_source(
        path,
        iam_resource,
        service_account_member,
    )
    if current_binding_source is None:
        return False

    role_access, role_uncertainty = _role_evidence(
        role,
        operation,
        target.project,
        scope_type,
        custom_roles,
        project_organizations,
    )
    if role_access is None or role_uncertainty is not None:
        return False
    expected_source_addresses = [current_binding_source]
    role_definition_address = role_access["role_definition_address"]
    if role_definition_address is not None:
        expected_source_addresses.append(role_definition_address)
    if source_addresses != expected_source_addresses or path.get("role_evidence") != role_access:
        return False

    relevant_iam_resources = tuple(
        resource for resource in resources if resource.resource_type in _iam_resource_types(kind)
    )
    ambiguous_scopes, ambiguous_roles, _ = _iam_manager_ambiguities(
        target,
        relevant_iam_resources,
        decoration_context,
        custom_roles,
    )
    role_key = _role_reconciliation_key(role, custom_roles)
    return (scope_type, scope) not in ambiguous_scopes and (
        scope_type,
        scope,
        role_key,
    ) not in ambiguous_roles


def _target_fields(target: _TopologyTarget) -> dict[str, object]:
    return {
        "messaging_resource_address": target.resource.address,
        "messaging_resource_name": target.name,
        "messaging_resource_project": target.project,
        "messaging_resource_reference": target.reference,
        "target_model_evidence_addresses": (
            [target.topic.address] if target.kind == "topic" else [target.topic.address, target.resource.address]
        ),
        "topic_address": target.topic.address,
        "topic_resource_type": target.topic.resource_type,
        "topic_name": target.topic_name,
        "topic_project": target.topic_project,
        "topic_reference": target.topic_reference,
        "subscription_address": None if target.kind == "topic" else target.resource.address,
        "subscription_resource_type": None if target.kind == "topic" else target.resource.resource_type,
        "subscription_name": None if target.kind == "topic" else target.name,
        "subscription_project": None if target.kind == "topic" else target.project,
        "subscription_reference": None if target.kind == "topic" else target.reference,
    }


def _current_grant_source(
    path: Mapping[str, object],
    iam_resource: NormalizedResource,
    service_account_member: str,
) -> str | None:
    source_addresses = path.get("iam_source_addresses")
    role = _known_string(path.get("role"))
    if (
        not isinstance(source_addresses, list)
        or not source_addresses
        or not isinstance(source_addresses[0], str)
        or role is None
    ):
        return None
    facts = gcp_facts(iam_resource)
    if facts.iam_policy_data_state in {"unknown", "invalid", "not_configured"}:
        return None
    expected_source = source_addresses[0]
    for binding in iam_bindings(iam_resource):
        source = _known_string(binding.get("source")) or iam_resource.address
        if (
            source != expected_source
            or _known_string(binding.get("role")) != role
            or service_account_member not in binding_members(binding)
            or binding.get("role_state") == "unknown"
            or binding.get("members_state") == "unknown"
            or binding.get("condition") is not None
            or binding.get("condition_state") not in {None, "not_configured"}
        ):
            continue
        return source
    return None


def _operations(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return [operation for operation in _OPERATION_ORDER if any(path.get("operation") == operation for path in paths)]


def _path_string_values(paths: Sequence[Mapping[str, object]], key: str) -> list[str]:
    return sorted({value for path in paths if (value := _known_string(path.get(key))) is not None})


def _runtime_identity_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"service_account={path.get('service_account_email')}",
                    f"member={path.get('service_account_member')}",
                    f"identity_kind={path.get('identity_kind')}",
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
                    f"target_address={path.get('messaging_resource_address')}",
                    f"target_type={path.get('messaging_resource_type')}",
                    f"target_name={path.get('messaging_resource_name')}",
                    f"target_project={path.get('messaging_resource_project')}",
                    f"target_reference={path.get('messaging_resource_reference')}",
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
                    f"matched_permissions={','.join(_string_values(path.get('matched_permissions')))}",
                    "authorization_state=granted",
                    "operation_evaluation=deterministic_allowed",
                )
            )
            for path in paths
        }
    )


def _outcome_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        outcome_value = path.get("outcome_evidence")
        if not isinstance(outcome_value, Mapping):
            continue
        outcome = cast(Mapping[str, object], outcome_value)
        values.add(
            "; ".join(
                (
                    f"target_address={path.get('messaging_resource_address')}",
                    f"operation={path.get('operation')}",
                    f"outcome_evidence_scope={outcome.get('outcome_evidence_scope')}",
                    f"successful_deletion_observed={outcome.get('successful_deletion_observed')}",
                    f"recovery_state={outcome.get('recovery_state')}",
                    f"descendant_impact_evaluated={outcome.get('descendant_impact_evaluated')}",
                    f"out_of_plan_topology_evaluated={outcome.get('out_of_plan_topology_evaluated')}",
                )
            )
        )
    return sorted(values)


def _assessment_scope(operations: Sequence[str]) -> list[str]:
    return [
        (
            f"establishes=deterministic {_operation_text(operations)} authority over exact modeled "
            "Pub/Sub topic or subscription topology with Denial of Service effect"
        ),
        (
            "does_not_establish=successful topology deletion, subscription impact from topic deletion, recovery, "
            "or out-of-plan Pub/Sub topology"
        ),
    ]


def _rationale(
    workload: NormalizedResource,
    operations: Sequence[str],
    target_count: int,
) -> str:
    if operations == [_DELETE_TOPIC]:
        impact = "delete exact modeled Pub/Sub topics"
    elif operations == [_DELETE_SUBSCRIPTION]:
        impact = "delete exact modeled Pub/Sub subscriptions"
    else:
        impact = "delete exact modeled Pub/Sub topics or subscriptions"
    return (
        f"{workload.display_name} is publicly invokable and its Cloud Run runtime service account has deterministic "
        f"Pub/Sub topology-deletion authority ({_operation_text(operations)}) across {target_count} exact modeled "
        f"Pub/Sub topology target(s). A compromise of the public workload could {impact} within the modeled grants, "
        "disrupting messaging topology and availability. This is plan-local authorization evidence; it does not "
        "establish successful deletion, subscription impact from topic deletion, recovery, or out-of-plan topology."
    )


def _operation_text(operations: Sequence[str]) -> str:
    return ", ".join(operations)


def _role_kind(value: object) -> str:
    if isinstance(value, Mapping):
        role_kind = cast(Mapping[str, object], value).get("role_kind")
        if isinstance(role_kind, str):
            return role_kind
    return "unknown"


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None
