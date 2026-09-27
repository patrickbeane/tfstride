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
from tfstride.providers.azure.arm_control_plane_authorization import (
    model_arm_control_plane_action_authority,
)
from tfstride.providers.azure.arm_control_plane_evidence import (
    AzureArmControlPlaneGrant,
)
from tfstride.providers.azure.messaging_topology_destruction_evidence import (
    AzureServiceBusTopologyDestructionOperation,
)
from tfstride.providers.azure.resource_decoration.app_service_service_bus_topology_destruction_paths import (
    _management_lock_evaluation,
    _topology_targets,
    _TopologyTarget,
)
from tfstride.providers.azure.resource_decoration.workload_identities import (
    workload_managed_identities,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import (
    AzureDecorationContext,
    AzureResourceIndexBuilder,
)
from tfstride.providers.azure.resource_types import (
    AZURE_APP_SERVICE_RESOURCE_TYPES,
    AzureResourceType,
)
from tfstride.providers.coercion import dedupe

_RULE_OPERATION_NAMESPACE: AzureServiceBusTopologyDestructionOperation = "Microsoft.ServiceBus/namespaces/delete"
_RULE_OPERATION_QUEUE: AzureServiceBusTopologyDestructionOperation = "Microsoft.ServiceBus/namespaces/queues/delete"
_RULE_OPERATION_TOPIC: AzureServiceBusTopologyDestructionOperation = "Microsoft.ServiceBus/namespaces/topics/delete"
_RULE_OPERATION_SUBSCRIPTION: AzureServiceBusTopologyDestructionOperation = (
    "Microsoft.ServiceBus/namespaces/topics/subscriptions/delete"
)
_OPERATION_ORDER = (
    _RULE_OPERATION_NAMESPACE,
    _RULE_OPERATION_QUEUE,
    _RULE_OPERATION_TOPIC,
    _RULE_OPERATION_SUBSCRIPTION,
)

_EXPECTED_TARGETS: dict[
    str,
    tuple[
        AzureServiceBusTopologyDestructionOperation,
        str,
        str,
        str,
    ],
] = {
    "namespace": (
        _RULE_OPERATION_NAMESPACE,
        "namespace_deletion",
        "service_bus_namespace_topology",
        "exact_service_bus_namespace",
    ),
    "queue": (
        _RULE_OPERATION_QUEUE,
        "queue_deletion",
        "queue_topology",
        "exact_service_bus_queue",
    ),
    "topic": (
        _RULE_OPERATION_TOPIC,
        "topic_deletion",
        "topic_topology",
        "exact_service_bus_topic",
    ),
    "subscription": (
        _RULE_OPERATION_SUBSCRIPTION,
        "subscription_deletion",
        "subscription_topology",
        "exact_service_bus_subscription",
    ),
}

_EXPECTED_LOCK_EVIDENCE = {
    "lock_evidence_scope": "plan_local_service_bus_ancestry",
    "modeled_management_lock_state": "not_observed",
    "applicable_lock_addresses": [],
    "applicable_lock_levels": [],
    "external_management_locks_evaluated": False,
    "deletion_compatibility_state": "compatible",
    "uncertainties": [],
}
_EXPECTED_OUTCOME_EVIDENCE = {
    "outcome_evidence_scope": "plan_local_service_bus_topology_deletion_authority",
    "successful_deletion_observed": False,
    "recovery_state": "not_established_by_modeled_azure_messaging_topology_evidence",
    "out_of_plan_topology_evaluated": False,
    "uncertainties": [],
}


class AzureAppServiceServiceBusTopologyDisruptionRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_app_service_service_bus_topology_disruption(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        resources = list(context.inventory.resources)
        decoration_context = AzureDecorationContext(AzureResourceIndexBuilder().build(resources))
        targets, _target_uncertainties = _topology_targets(resources, decoration_context)
        locks = tuple(resource for resource in resources if resource.resource_type == AzureResourceType.MANAGEMENT_LOCK)
        findings: list[Finding] = []

        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            app_facts = azure_facts(app)
            ingress = app_service_ingress(app, context)
            if not ingress.is_public:
                continue

            paths = [
                path
                for path in app_facts.app_service_service_bus_topology_destruction_paths
                if _is_current_topology_path(
                    path,
                    app,
                    resources,
                    targets,
                    locks,
                    decoration_context,
                    context,
                )
            ]
            if not paths:
                continue

            target_addresses = _path_string_values(paths, "service_bus_resource_address")
            namespace_addresses = _path_string_values(paths, "service_bus_namespace_address")
            topic_addresses = _path_string_values(paths, "topic_address")
            identity_addresses = _path_string_values(paths, "identity_address")
            assignment_addresses = _path_string_values(paths, "role_assignment_address")
            role_definition_addresses = _role_definition_addresses(paths)
            operations = _operations(paths)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2,
                data_sensitivity=1,
                lateral_movement=1,
                blast_radius=2 if len(target_addresses) > 1 or _RULE_OPERATION_NAMESPACE in operations else 1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            app.address,
                            *(address for address in identity_addresses if address != app.address),
                            *namespace_addresses,
                            *topic_addresses,
                            *target_addresses,
                            *assignment_addresses,
                            *role_definition_addresses,
                        ]
                    ),
                    trust_boundary_id=None,
                    rationale=_rationale(app, operations, len(target_addresses)),
                    evidence=collect_evidence(
                        *ingress.evidence,
                        evidence_item(
                            "runtime_identity",
                            _runtime_identity_evidence(paths),
                        ),
                        evidence_item(
                            "service_bus_topology_destruction_paths",
                            _topology_path_evidence(paths),
                        ),
                        evidence_item(
                            "management_lock_evidence",
                            _lock_evidence(paths),
                        ),
                        evidence_item(
                            "topology_deletion_outcome_evidence",
                            _outcome_evidence(paths),
                        ),
                        evidence_item(
                            "assessment_scope",
                            _assessment_scope(operations),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _is_current_topology_path(
    path: Mapping[str, object],
    app: NormalizedResource,
    resources: Sequence[NormalizedResource],
    targets: Sequence[_TopologyTarget],
    locks: Sequence[NormalizedResource],
    decoration_context: AzureDecorationContext,
    context: RuleEvaluationContext,
) -> bool:
    kind = _known_string(path.get("service_bus_resource_kind"))
    expected = _EXPECTED_TARGETS.get(kind or "")
    if expected is None:
        return False
    operation, operation_class, granularity, target_scope = expected
    target = next(
        (
            candidate
            for candidate in targets
            if candidate.kind == kind and candidate.resource.address == path.get("service_bus_resource_address")
        ),
        None,
    )
    if target is None:
        return False

    if (
        path.get("workload_address") != app.address
        or path.get("workload_type") != app.resource_type
        or path.get("identity_kind") not in {"system_assigned", "user_assigned"}
        or path.get("credential_context") != "workload_runtime"
        or path.get("service_bus_namespace_address") != target.namespace.address
        or path.get("service_bus_namespace_id") != target.namespace_id
        or path.get("service_bus_resource_type") != target.resource.resource_type
        or path.get("service_bus_resource_id") != target.resource_id
        or path.get("target_model_evidence_addresses") != _target_evidence_addresses(target)
        or path.get("management_effect") != "disruption"
        or path.get("operation") != operation
        or path.get("operation_class") != operation_class
        or path.get("target_granularity") != granularity
        or path.get("target_scope") != target_scope
        or path.get("authorization_state") != "granted"
        or path.get("modeled_allow_evidence_complete") is not True
        or path.get("condition") is not None
        or path.get("condition_state") != "not_configured"
        or path.get("lifecycle_compatibility_state") != "compatible"
        or path.get("management_lock_evidence") != _EXPECTED_LOCK_EVIDENCE
        or path.get("outcome_evidence") != _EXPECTED_OUTCOME_EVIDENCE
        or path.get("posture_uncertainties") != []
    ):
        return False

    if not _target_variant_is_current(path, target):
        return False
    if not _runtime_identity_is_current(path, app, decoration_context):
        return False

    lock_evaluation = _management_lock_evaluation(target, locks, decoration_context)
    if lock_evaluation.state != "not_observed":
        return False

    assignment_address = _known_string(path.get("role_assignment_address"))
    assignment = context.inventory.get_by_address(assignment_address) if assignment_address is not None else None
    if assignment is None or assignment.resource_type != AzureResourceType.ROLE_ASSIGNMENT:
        return False

    principal_id = _known_string(path.get("principal_id"))
    if principal_id is None:
        return False
    result = model_arm_control_plane_action_authority(
        assignment,
        decoration_context,
        principal_id=principal_id,
        target_arm_id=target.resource_id,
        requested_actions=(operation,),
    )
    grant = result.grant
    return (
        result.state == "granted"
        and grant is not None
        and _authorization_grant_is_current(path, grant, operation)
        and path.get("role_assignment_address") == grant["source_address"]
        and path.get("authorization_source_addresses") == _authorization_source_addresses(grant)
    )


def _target_variant_is_current(
    path: Mapping[str, object],
    target: _TopologyTarget,
) -> bool:
    expected_by_kind: dict[str, dict[str, object]] = {
        "namespace": {
            "queue_address": None,
            "queue_id": None,
            "topic_address": None,
            "topic_id": None,
            "subscription_address": None,
            "subscription_id": None,
        },
        "queue": {
            "queue_address": target.resource.address,
            "queue_id": target.resource_id,
            "topic_address": None,
            "topic_id": None,
            "subscription_address": None,
            "subscription_id": None,
        },
        "topic": {
            "queue_address": None,
            "queue_id": None,
            "topic_address": target.resource.address,
            "topic_id": target.resource_id,
            "subscription_address": None,
            "subscription_id": None,
        },
        "subscription": {
            "queue_address": None,
            "queue_id": None,
            "topic_address": target.topic.address if target.topic else None,
            "topic_id": (_known_string(azure_facts(target.topic).service_bus_entity_id) if target.topic else None),
            "subscription_address": target.resource.address,
            "subscription_id": target.resource_id,
        },
    }
    expected = expected_by_kind.get(target.kind)
    if expected is None:
        return False
    return all(path.get(key) == value for key, value in expected.items())


def _runtime_identity_is_current(
    path: Mapping[str, object],
    app: NormalizedResource,
    decoration_context: AzureDecorationContext,
) -> bool:
    identity_address = _known_string(path.get("identity_address"))
    principal_id = _known_string(path.get("principal_id"))
    if identity_address is None or principal_id is None:
        return False
    identities, _uncertainties = workload_managed_identities(app, decoration_context)
    for identity, identity_kind in identities:
        if identity.address != identity_address or identity_kind != path.get("identity_kind"):
            continue
        current_principal_id = _known_string(azure_facts(identity).principal_id)
        if current_principal_id != principal_id:
            return False
        return True
    return False


def _authorization_source_addresses(
    grant: Mapping[str, object],
) -> list[str]:
    role_definition_address = _known_string(grant.get("role_definition_address"))
    return dedupe(
        [
            value
            for value in (
                _known_string(grant.get("source_address")),
                role_definition_address,
            )
            if value is not None
        ]
    )


def _authorization_grant_is_current(
    path: Mapping[str, object],
    grant: AzureArmControlPlaneGrant,
    operation: AzureServiceBusTopologyDestructionOperation,
) -> bool:
    authorization = path.get("authorization_grant")
    if not isinstance(authorization, Mapping):
        return False
    authorization_map = cast(Mapping[str, object], authorization)
    role_definition_address = _known_string(grant["role_definition_address"])
    if (
        grant["requested_actions"] != [operation]
        or grant["matched_actions"] != [operation]
        or grant["excluded_actions"]
        or grant["principal_state"] != "resolved"
        or grant["assignment_scope_state"] != "resolved"
        or grant["assignment_condition"] is not None
        or grant["assignment_condition_version"] is not None
        or grant["assignment_condition_state"] != "not_configured"
        or grant["role_definition_condition_state"] != "not_configured"
        or grant["delegation_constraint_kind"] != "none"
        or grant["allowed_role_definition_ids"]
        or grant["authorization_state"] != "granted"
        or grant["deny_assignments_evaluated"] is not False
        or grant["evaluation_basis"] != "modeled_arm_control_plane_authority"
    ):
        return False

    if (
        grant["role_kind"] == "built_in"
        and grant["role_resolution_state"] == "modeled_subset"
        and role_definition_address is None
        and grant["assignable_scope_compatibility_state"] == "not_applicable"
    ):
        role_evidence: object = {
            "role_kind": "built_in",
            "role_resolution_state": "modeled_subset",
            "role_definition_address": None,
            "assignable_scope_compatibility_state": "not_applicable",
        }
    elif (
        grant["role_kind"] == "custom"
        and grant["role_resolution_state"] == "resolved"
        and role_definition_address is not None
        and grant["assignable_scope_compatibility_state"] == "resolved"
    ):
        role_evidence = {
            "role_kind": "custom",
            "role_resolution_state": "resolved",
            "role_definition_address": role_definition_address,
            "assignable_scope_compatibility_state": "resolved",
        }
    else:
        return False

    expected = {
        "source_address": grant["source_address"],
        "principal_id": grant["principal_id"],
        "principal_type": grant["principal_type"],
        "principal_state": "resolved",
        "assignment_scope_type": grant["assignment_scope_type"],
        "assignment_scope": grant["assignment_scope"],
        "assignment_scope_arm_id": grant["assignment_scope_arm_id"],
        "assignment_scope_state": "resolved",
        "target_arm_id": grant["target_arm_id"],
        "role_definition_name": grant["role_definition_name"],
        "role_definition_id": grant["role_definition_id"],
        "requested_actions": [operation],
        "matched_actions": [operation],
        "role_evidence": role_evidence,
        "role_actions": list(grant["role_actions"]),
        "role_not_actions": list(grant["role_not_actions"]),
        "excluded_actions": [],
        "assignment_condition": None,
        "assignment_condition_version": None,
        "assignment_condition_state": "not_configured",
        "role_definition_condition_state": "not_configured",
        "delegation_constraint_kind": "none",
        "allowed_role_definition_ids": [],
        "authorization_state": "granted",
        "deny_assignments_evaluated": False,
        "evaluation_basis": "modeled_arm_control_plane_authority",
    }
    return all(authorization_map.get(key) == value for key, value in expected.items())


def _target_evidence_addresses(target: _TopologyTarget) -> list[str]:
    if target.kind == "namespace":
        return [target.namespace.address]
    if target.kind in {"queue", "topic"}:
        return [target.namespace.address, target.resource.address]
    if target.topic is None:
        return []
    return [target.namespace.address, target.topic.address, target.resource.address]


def _operations(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return [operation for operation in _OPERATION_ORDER if any(path.get("operation") == operation for path in paths)]


def _path_string_values(
    paths: Sequence[Mapping[str, object]],
    key: str,
) -> list[str]:
    return sorted({value for path in paths if (value := _known_string(path.get(key))) is not None})


def _role_definition_addresses(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        grant = path.get("authorization_grant")
        if isinstance(grant, Mapping):
            grant_map = cast(Mapping[str, object], grant)
            value = _known_string(grant_map.get("role_definition_address"))
            if value is not None:
                values.add(value)
    return sorted(values)


def _runtime_identity_evidence(
    paths: Sequence[Mapping[str, object]],
) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"identity_address={path.get('identity_address')}",
                    f"identity_kind={path.get('identity_kind')}",
                    f"principal_id={path.get('principal_id')}",
                    "credential_context=workload_runtime",
                )
            )
            for path in paths
        }
    )


def _topology_path_evidence(
    paths: Sequence[Mapping[str, object]],
) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"target_address={path.get('service_bus_resource_address')}",
                    f"target_type={path.get('service_bus_resource_type')}",
                    f"namespace={path.get('service_bus_namespace_address')}",
                    f"topic={path.get('topic_address') or 'not_applicable'}",
                    f"subscription={path.get('subscription_address') or 'not_applicable'}",
                    f"operation={path.get('operation')}",
                    f"operation_class={path.get('operation_class')}",
                    f"target_granularity={path.get('target_granularity')}",
                    f"target_scope={path.get('target_scope')}",
                    f"identity={path.get('identity_address')}",
                    f"role_assignment={path.get('role_assignment_address')}",
                    f"authorization_sources={','.join(_string_values(path.get('authorization_source_addresses'))) or 'none'}",
                    "authorization_state=granted",
                    "operation_evaluation=deterministic_allowed",
                )
            )
            for path in paths
        }
    )


def _lock_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"target_address={path.get('service_bus_resource_address')}",
                    f"modeled_management_lock_state={_mapping_value(path.get('management_lock_evidence'), 'modeled_management_lock_state') or 'unknown'}",
                    f"deletion_compatibility_state={_mapping_value(path.get('management_lock_evidence'), 'deletion_compatibility_state') or 'unknown'}",
                    "external_management_locks_evaluated=False",
                )
            )
            for path in paths
        }
    )


def _outcome_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        outcome = path.get("outcome_evidence")
        if not isinstance(outcome, Mapping):
            continue
        outcome_map = cast(Mapping[str, object], outcome)
        values.add(
            "; ".join(
                (
                    f"target_address={path.get('service_bus_resource_address')}",
                    f"operation={path.get('operation')}",
                    f"successful_deletion_observed={outcome_map.get('successful_deletion_observed')}",
                    f"recovery_state={outcome_map.get('recovery_state')}",
                    f"out_of_plan_topology_evaluated={outcome_map.get('out_of_plan_topology_evaluated')}",
                )
            )
        )
    return sorted(values)


def _assessment_scope(operations: Sequence[str]) -> list[str]:
    return [
        (
            f"establishes=deterministic {_operation_text(operations)} authority for an App Service runtime "
            "identity over exact modeled Azure Service Bus topology targets with Denial of Service effect"
        ),
        (
            "does_not_establish=successful topology deletion, descendant-resource impact, recovery, or out-of-plan "
            "Service Bus topology"
        ),
    ]


def _rationale(
    app: NormalizedResource,
    operations: Sequence[str],
    target_count: int,
) -> str:
    target_text = _operation_target_text(operations)
    return (
        f"{app.display_name} permits external ingress within the evidenced scope and its runtime managed identity has deterministic "
        f"Service Bus topology-deletion authority ({_operation_text(operations)}) across {target_count} exact "
        f"modeled {target_text}. A compromise through the public application path could delete those "
        "Service Bus topology resources, disrupting messaging availability. This is plan-local control-plane "
        "authorization evidence; it does not establish successful deletion, descendant-resource impact, recovery, "
        "or out-of-plan topology."
    )


def _operation_target_text(operations: Sequence[str]) -> str:
    targets = {
        _RULE_OPERATION_NAMESPACE: "namespace(s)",
        _RULE_OPERATION_QUEUE: "queue(s)",
        _RULE_OPERATION_TOPIC: "topic(s)",
        _RULE_OPERATION_SUBSCRIPTION: "subscription(s)",
    }
    values = [targets[operation] for operation in operations if operation in targets]
    if len(values) == 1:
        return values[0]
    if len(values) == 2:
        return f"{values[0]} or {values[1]}"
    if values:
        return ", ".join(values[:-1]) + f", or {values[-1]}"
    return "topology target(s)"


def _operation_text(operations: Sequence[str]) -> str:
    values = [operation for operation in _OPERATION_ORDER if operation in operations]
    if len(values) == 1:
        return values[0]
    if len(values) == 2:
        return f"{values[0]} and {values[1]}"
    if values:
        return ", ".join(values[:-1]) + f", and {values[-1]}"
    return "Service Bus topology deletion"


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({item for item in value if isinstance(item, str)})


def _mapping_value(value: object, key: str) -> object | None:
    if not isinstance(value, Mapping):
        return None
    return cast(Mapping[str, object], value).get(key)
