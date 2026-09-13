from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from tfstride.models import NormalizedResource
from tfstride.providers.azure.arm_control_plane_authorization import (
    AzureArmControlPlaneAuthorityResult,
    azure_arm_scope_contains,
    model_arm_control_plane_action_authority,
)
from tfstride.providers.azure.arm_control_plane_evidence import (
    AzureArmControlPlaneGrant,
)
from tfstride.providers.azure.key_vault_evidence import (
    AzureKeyVaultRuntimeIdentityKind,
)
from tfstride.providers.azure.messaging_topology_destruction_evidence import (
    AzureAppServiceServiceBusNamespaceDeletionPath,
    AzureAppServiceServiceBusQueueDeletionPath,
    AzureAppServiceServiceBusSubscriptionDeletionPath,
    AzureAppServiceServiceBusTopicDeletionPath,
    AzureAppServiceServiceBusTopologyDestructionPath,
    AzureAppServiceServiceBusTopologyDestructionPathCommon,
    AzureServiceBusNamespaceDeletionAuthorizationGrant,
    AzureServiceBusQueueDeletionAuthorizationGrant,
    AzureServiceBusSubscriptionDeletionAuthorizationGrant,
    AzureServiceBusTopicDeletionAuthorizationGrant,
    AzureServiceBusTopologyBuiltInRoleEvidence,
    AzureServiceBusTopologyCustomRoleEvidence,
    AzureServiceBusTopologyDestructionAuthorizationGrantCommon,
    AzureServiceBusTopologyDestructionLockEvidence,
    AzureServiceBusTopologyDestructionOperation,
    AzureServiceBusTopologyDestructionOutcomeEvidence,
    AzureServiceBusTopologyRoleEvidence,
)
from tfstride.providers.azure.resource_decoration.workload_identities import (
    workload_managed_identities,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import (
    AZURE_APP_SERVICE_RESOURCE_TYPES,
    AzureResourceType,
)
from tfstride.providers.coercion import dedupe, dedupe_strings

_DELETE_NAMESPACE: Literal["Microsoft.ServiceBus/namespaces/delete"] = "Microsoft.ServiceBus/namespaces/delete"
_DELETE_QUEUE: Literal["Microsoft.ServiceBus/namespaces/queues/delete"] = (
    "Microsoft.ServiceBus/namespaces/queues/delete"
)
_DELETE_TOPIC: Literal["Microsoft.ServiceBus/namespaces/topics/delete"] = (
    "Microsoft.ServiceBus/namespaces/topics/delete"
)
_DELETE_SUBSCRIPTION: Literal["Microsoft.ServiceBus/namespaces/topics/subscriptions/delete"] = (
    "Microsoft.ServiceBus/namespaces/topics/subscriptions/delete"
)

_SERVICE_BUS_TARGET_TYPES = frozenset(
    {
        AzureResourceType.SERVICE_BUS_NAMESPACE,
        AzureResourceType.SERVICE_BUS_QUEUE,
        AzureResourceType.SERVICE_BUS_TOPIC,
        AzureResourceType.SERVICE_BUS_SUBSCRIPTION,
    }
)
_NAMESPACE_ID_PATTERN = re.compile(
    r"^/subscriptions/[^/]+/resourcegroups/[^/]+/providers/"
    r"microsoft\.servicebus/namespaces/[^/]+$",
    re.IGNORECASE,
)

_TargetKind = Literal["namespace", "queue", "topic", "subscription"]
_LockEvaluationState = Literal["not_observed", "blocking", "unknown"]
_LockCompatibilityState = Literal["compatible", "blocked", "unknown"]


@dataclass(frozen=True, slots=True)
class _RuntimeIdentity:
    resource: NormalizedResource
    kind: AzureKeyVaultRuntimeIdentityKind
    principal_id: str


@dataclass(frozen=True, slots=True)
class _TopologyTarget:
    resource: NormalizedResource
    kind: _TargetKind
    resource_id: str
    namespace: NormalizedResource
    namespace_id: str
    topic: NormalizedResource | None = None


@dataclass(frozen=True, slots=True)
class _LockEvaluation:
    state: _LockEvaluationState
    compatibility_state: _LockCompatibilityState
    applicable_lock_addresses: tuple[str, ...] = ()
    applicable_lock_levels: tuple[str, ...] = ()
    uncertainties: tuple[str, ...] = ()


class ModelAppServiceServiceBusTopologyDestructionPathsStage:
    """Project exact Service Bus control-plane deletion authority onto App Services."""

    name = "model_app_service_service_bus_topology_destruction_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AzureDecorationContext,
    ) -> None:
        targets, target_uncertainties = _topology_targets(resources, context)
        locks = tuple(resource for resource in resources if resource.resource_type == AzureResourceType.MANAGEMENT_LOCK)
        lock_evaluations = {
            target.resource.address: _management_lock_evaluation(target, locks, context) for target in targets
        }
        assignments = tuple(
            resource for resource in resources if resource.resource_type == AzureResourceType.ROLE_ASSIGNMENT
        )
        for workload in resources:
            if workload.resource_type not in AZURE_APP_SERVICE_RESOURCE_TYPES:
                continue
            paths, uncertainties = _app_service_service_bus_topology_destruction_paths(
                workload,
                targets,
                target_uncertainties,
                lock_evaluations,
                assignments,
                context,
            )
            facts = azure_facts(workload)
            facts.set_app_service_service_bus_topology_destruction_paths(paths)
            facts.extend_app_service_service_bus_topology_destruction_path_uncertainties(
                uncertainties,
            )


def _app_service_service_bus_topology_destruction_paths(
    workload: NormalizedResource,
    targets: Sequence[_TopologyTarget],
    target_uncertainties: Sequence[str],
    lock_evaluations: Mapping[str, _LockEvaluation],
    assignments: Sequence[NormalizedResource],
    context: AzureDecorationContext,
) -> tuple[list[AzureAppServiceServiceBusTopologyDestructionPath], list[str]]:
    identities, identity_uncertainties = workload_managed_identities(workload, context)
    uncertainties = [
        *identity_uncertainties,
        *(f"{workload.address}: {uncertainty}" for uncertainty in azure_facts(workload).managed_identity_uncertainties),
    ]
    runtime_identities = tuple(
        _RuntimeIdentity(identity, kind, principal_id)
        for identity, kind in identities
        if (principal_id := _known_string(azure_facts(identity).principal_id)) is not None
    )
    if not runtime_identities:
        return [], dedupe(uncertainties)

    uncertainties.extend(f"{workload.address}: {uncertainty}" for uncertainty in target_uncertainties)
    paths: list[AzureAppServiceServiceBusTopologyDestructionPath] = []
    for target in targets:
        lock_evaluation = lock_evaluations[target.resource.address]
        if lock_evaluation.state == "blocking":
            continue
        if lock_evaluation.state == "unknown":
            uncertainties.extend(
                f"{workload.address}: {target.resource.address}: {uncertainty}"
                for uncertainty in lock_evaluation.uncertainties
            )
            continue
        operation = _operation(target.kind)
        for identity in runtime_identities:
            for assignment in assignments:
                result = model_arm_control_plane_action_authority(
                    assignment,
                    context,
                    principal_id=identity.principal_id,
                    target_arm_id=target.resource_id,
                    requested_actions=(operation,),
                )
                _record_result_uncertainties(
                    workload,
                    target,
                    result,
                    uncertainties,
                )
                if result.grant is None:
                    continue
                path = _topology_path(workload, identity, target, result.grant)
                if path is None:
                    uncertainties.append(
                        f"{workload.address}: {assignment.address} returned "
                        f"incoherent Service Bus topology-deletion evidence for "
                        f"{target.resource.address}"
                    )
                    continue
                paths.append(path)

    paths.sort(
        key=lambda path: (
            path["service_bus_resource_address"],
            path["operation"],
            path["identity_address"],
            path["role_assignment_address"],
        )
    )
    return _dedupe_paths(paths), dedupe(uncertainties)


def _record_result_uncertainties(
    workload: NormalizedResource,
    target: _TopologyTarget,
    result: AzureArmControlPlaneAuthorityResult,
    uncertainties: list[str],
) -> None:
    if result.state != "unknown":
        return
    uncertainties.extend(
        f"{workload.address}: {target.resource.address}: {uncertainty}" for uncertainty in result.uncertainties
    )


def _topology_targets(
    resources: Sequence[NormalizedResource],
    context: AzureDecorationContext,
) -> tuple[list[_TopologyTarget], list[str]]:
    targets: list[_TopologyTarget] = []
    uncertainties: list[str] = []
    for resource in resources:
        if resource.resource_type not in _SERVICE_BUS_TARGET_TYPES:
            continue
        target, uncertainty = _topology_target(resource, context)
        if target is not None:
            targets.append(target)
        elif uncertainty is not None:
            uncertainties.append(uncertainty)
    targets.sort(key=lambda target: target.resource.address)
    return targets, dedupe(uncertainties)


def _management_lock_evaluation(
    target: _TopologyTarget,
    locks: Sequence[NormalizedResource],
    context: AzureDecorationContext,
) -> _LockEvaluation:
    blocking_addresses: list[str] = []
    blocking_levels: list[str] = []
    uncertainties: list[str] = []
    for lock in locks:
        scope_state = _management_lock_scope_state(lock, target, context)
        if scope_state == "unrelated":
            continue
        lock_facts = azure_facts(lock)
        if scope_state == "unknown":
            uncertainties.extend(
                f"{lock.address}: {uncertainty}"
                for uncertainty in (
                    lock_facts.management_lock_uncertainties or ["management-lock scope applicability is unresolved"]
                )
            )
            continue

        lock_level = _blocking_lock_level(lock_facts.management_lock_level)
        if lock_level is None:
            uncertainties.extend(
                f"{lock.address}: {uncertainty}"
                for uncertainty in (
                    lock_facts.management_lock_uncertainties or ["management-lock level is unsupported or unresolved"]
                )
            )
            continue
        blocking_addresses.append(lock.address)
        blocking_levels.append(lock_level)

    if blocking_addresses:
        return _LockEvaluation(
            state="blocking",
            compatibility_state="blocked",
            applicable_lock_addresses=tuple(dedupe(blocking_addresses)),
            applicable_lock_levels=tuple(dedupe(blocking_levels)),
        )
    if uncertainties:
        return _LockEvaluation(
            state="unknown",
            compatibility_state="unknown",
            uncertainties=tuple(dedupe(uncertainties)),
        )
    return _LockEvaluation(
        state="not_observed",
        compatibility_state="compatible",
    )


def _management_lock_scope_state(
    lock: NormalizedResource,
    target: _TopologyTarget,
    context: AzureDecorationContext,
) -> Literal["applicable", "unrelated", "unknown"]:
    scope = _known_string(azure_facts(lock).management_lock_scope)
    if scope is None:
        return "unknown"

    if scope.startswith("/"):
        normalized_scope = _known_arm_id(scope)
        if normalized_scope is None:
            return "unknown"
        if normalized_scope.casefold().startswith("/providers/microsoft.management/managementgroups/"):
            return "unknown"
        return "applicable" if azure_arm_scope_contains(normalized_scope, target.resource_id) else "unrelated"

    scope_resource = context.index.resolve(scope, source=lock)
    if scope_resource is None:
        return "unknown"
    scope_arm_id = _service_bus_resource_arm_id(scope_resource)
    if scope_arm_id is None:
        return "unknown"
    return "applicable" if azure_arm_scope_contains(scope_arm_id, target.resource_id) else "unrelated"


def _blocking_lock_level(value: object) -> Literal["CanNotDelete", "ReadOnly"] | None:
    normalized = _known_string(value)
    if normalized is None:
        return None
    key = normalized.casefold().replace("_", "").replace("-", "").replace(" ", "")
    if key == "cannotdelete":
        return "CanNotDelete"
    if key == "readonly":
        return "ReadOnly"
    return None


def _service_bus_resource_arm_id(resource: NormalizedResource) -> str | None:
    facts = azure_facts(resource)
    if resource.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE:
        return _exact_namespace_id(facts.service_bus_namespace_id)
    if resource.resource_type in {
        AzureResourceType.SERVICE_BUS_QUEUE,
        AzureResourceType.SERVICE_BUS_TOPIC,
        AzureResourceType.SERVICE_BUS_SUBSCRIPTION,
    }:
        return _known_arm_id(facts.service_bus_entity_id)
    return None


def _topology_target(
    resource: NormalizedResource,
    context: AzureDecorationContext,
) -> tuple[_TopologyTarget | None, str | None]:
    if resource.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE:
        namespace_id = _exact_namespace_id(
            azure_facts(resource).service_bus_namespace_id,
        )
        if namespace_id is None:
            return None, f"{resource.address}: exact Service Bus namespace ARM identity is unresolved"
        return (
            _TopologyTarget(
                resource=resource,
                kind="namespace",
                resource_id=namespace_id,
                namespace=resource,
                namespace_id=namespace_id,
            ),
            None,
        )

    facts = azure_facts(resource)
    resource_id = _known_arm_id(facts.service_bus_entity_id)
    if resource_id is None:
        return None, f"{resource.address}: exact Service Bus entity ARM identity is unresolved"

    if resource.resource_type == AzureResourceType.SERVICE_BUS_SUBSCRIPTION:
        return _subscription_target(resource, resource_id, context)
    return _queue_or_topic_target(resource, resource_id, context)


def _queue_or_topic_target(
    resource: NormalizedResource,
    resource_id: str,
    context: AzureDecorationContext,
) -> tuple[_TopologyTarget | None, str | None]:
    expected_kind: Literal["queue", "topic"] = (
        "queue" if resource.resource_type == AzureResourceType.SERVICE_BUS_QUEUE else "topic"
    )
    facts = azure_facts(resource)
    namespace = context.index.resources_by_address.get(
        facts.resolved_service_bus_namespace_address or "",
    )
    namespace_id = (
        _exact_namespace_id(azure_facts(namespace).service_bus_namespace_id)
        if namespace is not None and namespace.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE
        else None
    )
    if namespace is None or namespace_id is None:
        return None, f"{resource.address}: exact Service Bus namespace ancestry is unresolved"
    if facts.service_bus_entity_kind != expected_kind or not _is_direct_child_id(
        namespace_id,
        resource_id,
        f"{expected_kind}s",
    ):
        return None, f"{resource.address}: Service Bus {expected_kind} identity and ancestry are incoherent"
    return (
        _TopologyTarget(
            resource=resource,
            kind=expected_kind,
            resource_id=resource_id,
            namespace=namespace,
            namespace_id=namespace_id,
        ),
        None,
    )


def _subscription_target(
    resource: NormalizedResource,
    resource_id: str,
    context: AzureDecorationContext,
) -> tuple[_TopologyTarget | None, str | None]:
    facts = azure_facts(resource)
    topic = context.index.resources_by_address.get(
        facts.resolved_service_bus_topic_address or "",
    )
    namespace = context.index.resources_by_address.get(
        facts.resolved_service_bus_namespace_address or "",
    )
    if (
        topic is None
        or topic.resource_type != AzureResourceType.SERVICE_BUS_TOPIC
        or namespace is None
        or namespace.resource_type != AzureResourceType.SERVICE_BUS_NAMESPACE
        or facts.service_bus_entity_kind != "subscription"
        or azure_facts(topic).resolved_service_bus_namespace_address != namespace.address
    ):
        return None, f"{resource.address}: exact Service Bus topic ancestry is unresolved"

    namespace_id = _exact_namespace_id(
        azure_facts(namespace).service_bus_namespace_id,
    )
    topic_id = _known_arm_id(azure_facts(topic).service_bus_entity_id)
    if (
        namespace_id is None
        or topic_id is None
        or not _is_direct_child_id(namespace_id, topic_id, "topics")
        or not _is_direct_child_id(topic_id, resource_id, "subscriptions")
    ):
        return None, f"{resource.address}: Service Bus subscription identity and ancestry are incoherent"
    return (
        _TopologyTarget(
            resource=resource,
            kind="subscription",
            resource_id=resource_id,
            namespace=namespace,
            namespace_id=namespace_id,
            topic=topic,
        ),
        None,
    )


def _topology_path(
    workload: NormalizedResource,
    identity: _RuntimeIdentity,
    target: _TopologyTarget,
    grant: AzureArmControlPlaneGrant,
) -> AzureAppServiceServiceBusTopologyDestructionPath | None:
    operation = _operation(target.kind)
    grant_common = _authorization_grant_common(
        grant,
        identity,
        target,
        operation,
    )
    if grant_common is None:
        return None

    common = _path_common(workload, identity, target, grant)
    if target.kind == "namespace":
        authorization = AzureServiceBusNamespaceDeletionAuthorizationGrant(
            **grant_common,
            requested_actions=[_DELETE_NAMESPACE],
            matched_actions=[_DELETE_NAMESPACE],
        )
        return AzureAppServiceServiceBusNamespaceDeletionPath(
            **common,
            service_bus_resource_kind="namespace",
            operation=_DELETE_NAMESPACE,
            operation_class="namespace_deletion",
            internal_operation="delete_namespace",
            target_granularity="service_bus_namespace_topology",
            target_scope="exact_service_bus_namespace",
            queue_address=None,
            queue_id=None,
            topic_address=None,
            topic_id=None,
            subscription_address=None,
            subscription_id=None,
            authorization_grant=authorization,
        )
    if target.kind == "queue":
        authorization = AzureServiceBusQueueDeletionAuthorizationGrant(
            **grant_common,
            requested_actions=[_DELETE_QUEUE],
            matched_actions=[_DELETE_QUEUE],
        )
        return AzureAppServiceServiceBusQueueDeletionPath(
            **common,
            service_bus_resource_kind="queue",
            operation=_DELETE_QUEUE,
            operation_class="queue_deletion",
            internal_operation="delete_queue",
            target_granularity="queue_topology",
            target_scope="exact_service_bus_queue",
            queue_address=target.resource.address,
            queue_id=target.resource_id,
            topic_address=None,
            topic_id=None,
            subscription_address=None,
            subscription_id=None,
            authorization_grant=authorization,
        )
    if target.kind == "topic":
        authorization = AzureServiceBusTopicDeletionAuthorizationGrant(
            **grant_common,
            requested_actions=[_DELETE_TOPIC],
            matched_actions=[_DELETE_TOPIC],
        )
        return AzureAppServiceServiceBusTopicDeletionPath(
            **common,
            service_bus_resource_kind="topic",
            operation=_DELETE_TOPIC,
            operation_class="topic_deletion",
            internal_operation="delete_topic",
            target_granularity="topic_topology",
            target_scope="exact_service_bus_topic",
            queue_address=None,
            queue_id=None,
            topic_address=target.resource.address,
            topic_id=target.resource_id,
            subscription_address=None,
            subscription_id=None,
            authorization_grant=authorization,
        )

    topic = target.topic
    if topic is None:
        return None
    topic_id = _known_arm_id(azure_facts(topic).service_bus_entity_id)
    if topic_id is None:
        return None
    authorization = AzureServiceBusSubscriptionDeletionAuthorizationGrant(
        **grant_common,
        requested_actions=[_DELETE_SUBSCRIPTION],
        matched_actions=[_DELETE_SUBSCRIPTION],
    )
    return AzureAppServiceServiceBusSubscriptionDeletionPath(
        **common,
        service_bus_resource_kind="subscription",
        operation=_DELETE_SUBSCRIPTION,
        operation_class="subscription_deletion",
        internal_operation="delete_subscription",
        target_granularity="subscription_topology",
        target_scope="exact_service_bus_subscription",
        queue_address=None,
        queue_id=None,
        topic_address=topic.address,
        topic_id=topic_id,
        subscription_address=target.resource.address,
        subscription_id=target.resource_id,
        authorization_grant=authorization,
    )


def _path_common(
    workload: NormalizedResource,
    identity: _RuntimeIdentity,
    target: _TopologyTarget,
    grant: AzureArmControlPlaneGrant,
) -> AzureAppServiceServiceBusTopologyDestructionPathCommon:
    role_definition_address = _known_string(grant["role_definition_address"])
    lock_evidence: AzureServiceBusTopologyDestructionLockEvidence = {
        "lock_evidence_scope": "plan_local_service_bus_ancestry",
        "modeled_management_lock_state": "not_observed",
        "applicable_lock_addresses": [],
        "applicable_lock_levels": [],
        "external_management_locks_evaluated": False,
        "deletion_compatibility_state": "compatible",
        "uncertainties": [],
    }
    outcome_evidence: AzureServiceBusTopologyDestructionOutcomeEvidence = {
        "outcome_evidence_scope": "plan_local_service_bus_topology_deletion_authority",
        "successful_deletion_observed": False,
        "recovery_state": "not_established_by_modeled_azure_messaging_topology_evidence",
        "out_of_plan_topology_evaluated": False,
        "uncertainties": [],
    }
    return {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "identity_address": identity.resource.address,
        "identity_kind": identity.kind,
        "principal_id": identity.principal_id,
        "credential_context": "workload_runtime",
        "service_bus_namespace_address": target.namespace.address,
        "service_bus_namespace_id": target.namespace_id,
        "service_bus_resource_address": target.resource.address,
        "service_bus_resource_type": target.resource.resource_type,
        "service_bus_resource_id": target.resource_id,
        "target_model_evidence_addresses": _target_evidence_addresses(target),
        "management_effect": "disruption",
        "role_assignment_address": grant["source_address"],
        "authorization_source_addresses": dedupe_strings(
            [grant["source_address"], role_definition_address],
        ),
        "authorization_state": "granted",
        "modeled_allow_evidence_complete": True,
        "condition": None,
        "condition_state": "not_configured",
        "lifecycle_compatibility_state": "compatible",
        "management_lock_evidence": lock_evidence,
        "outcome_evidence": outcome_evidence,
        "posture_uncertainties": [],
    }


def _authorization_grant_common(
    grant: AzureArmControlPlaneGrant,
    identity: _RuntimeIdentity,
    target: _TopologyTarget,
    operation: AzureServiceBusTopologyDestructionOperation,
) -> AzureServiceBusTopologyDestructionAuthorizationGrantCommon | None:
    principal_id = _known_string(grant["principal_id"])
    role_evidence = _role_evidence(grant)
    if (
        principal_id is None
        or not _same_identifier(principal_id, identity.principal_id)
        or not _same_identifier(grant["target_arm_id"], target.resource_id)
        or grant["requested_actions"] != [operation]
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
        or role_evidence is None
    ):
        return None
    return {
        "source_address": grant["source_address"],
        "principal_id": principal_id,
        "principal_type": grant["principal_type"],
        "principal_state": "resolved",
        "assignment_scope_type": grant["assignment_scope_type"],
        "assignment_scope": grant["assignment_scope"],
        "assignment_scope_arm_id": grant["assignment_scope_arm_id"],
        "assignment_scope_state": "resolved",
        "target_arm_id": target.resource_id,
        "role_definition_name": grant["role_definition_name"],
        "role_definition_id": grant["role_definition_id"],
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


def _role_evidence(
    grant: AzureArmControlPlaneGrant,
) -> AzureServiceBusTopologyRoleEvidence | None:
    role_definition_address = _known_string(grant["role_definition_address"])
    if (
        grant["role_kind"] == "built_in"
        and grant["role_resolution_state"] == "modeled_subset"
        and role_definition_address is None
        and grant["assignable_scope_compatibility_state"] == "not_applicable"
    ):
        return AzureServiceBusTopologyBuiltInRoleEvidence(
            role_kind="built_in",
            role_resolution_state="modeled_subset",
            role_definition_address=None,
            assignable_scope_compatibility_state="not_applicable",
        )
    if (
        grant["role_kind"] == "custom"
        and grant["role_resolution_state"] == "resolved"
        and role_definition_address is not None
        and grant["assignable_scope_compatibility_state"] == "resolved"
    ):
        return AzureServiceBusTopologyCustomRoleEvidence(
            role_kind="custom",
            role_resolution_state="resolved",
            role_definition_address=role_definition_address,
            assignable_scope_compatibility_state="resolved",
        )
    return None


def _target_evidence_addresses(target: _TopologyTarget) -> list[str]:
    if target.kind == "namespace":
        return [target.namespace.address]
    if target.kind in {"queue", "topic"}:
        return [target.namespace.address, target.resource.address]
    assert target.topic is not None
    return [
        target.namespace.address,
        target.topic.address,
        target.resource.address,
    ]


def _operation(
    kind: _TargetKind,
) -> AzureServiceBusTopologyDestructionOperation:
    if kind == "namespace":
        return _DELETE_NAMESPACE
    if kind == "queue":
        return _DELETE_QUEUE
    if kind == "topic":
        return _DELETE_TOPIC
    return _DELETE_SUBSCRIPTION


def _exact_namespace_id(value: object) -> str | None:
    normalized = _known_arm_id(value)
    if normalized is None or _NAMESPACE_ID_PATTERN.fullmatch(normalized) is None:
        return None
    return normalized


def _known_arm_id(value: object) -> str | None:
    normalized = _known_string(value)
    if normalized is None or not normalized.startswith("/"):
        return None
    return normalized.rstrip("/")


def _is_direct_child_id(parent_id: str, child_id: str, collection: str) -> bool:
    prefix = f"{parent_id.rstrip('/')}/{collection}/"
    if not child_id.casefold().startswith(prefix.casefold()):
        return False
    child_name = child_id[len(prefix) :]
    return bool(child_name) and "/" not in child_name


def _same_identifier(left: str | None, right: str | None) -> bool:
    return bool(left and right and left.strip().rstrip("/").casefold() == right.strip().rstrip("/").casefold())


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _dedupe_paths(
    paths: Sequence[AzureAppServiceServiceBusTopologyDestructionPath],
) -> list[AzureAppServiceServiceBusTopologyDestructionPath]:
    result: list[AzureAppServiceServiceBusTopologyDestructionPath] = []
    for path in paths:
        if path not in result:
            result.append(path)
    return result
