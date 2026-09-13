from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal, cast

from tfstride.models import NormalizedResource
from tfstride.providers.azure.arm_control_plane_authorization import (
    assignment_condition_state,
    azure_arm_scope_contains,
)
from tfstride.providers.azure.key_vault_evidence import (
    AzureKeyVaultRuntimeIdentityKind,
)
from tfstride.providers.azure.message_removal_evidence import (
    AzureAppServiceServiceBusMessageRemovalPath,
    AzureAppServiceServiceBusMessageRemovalPathCommon,
    AzureAppServiceServiceBusQueueMessageRemovalPath,
    AzureAppServiceServiceBusSubscriptionMessageRemovalPath,
    AzureServiceBusMessageRemovalDeliveryEvidence,
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

_RECEIVE: Literal["microsoft.servicebus/namespaces/messages/receive/action"] = (
    "microsoft.servicebus/namespaces/messages/receive/action"
)
_RECEIVE_CASEFOLDED = _RECEIVE.casefold()
_BUILT_IN_RECEIVE_ROLE_KINDS = frozenset(
    {
        "service_bus_data_receiver",
        "service_bus_data_owner",
    }
)
_SETTLEMENT_TARGET_TYPES = frozenset(
    {
        AzureResourceType.SERVICE_BUS_QUEUE,
        AzureResourceType.SERVICE_BUS_SUBSCRIPTION,
    }
)


class ModelAppServiceServiceBusMessageRemovalPathsStage:
    """Project deterministic Service Bus receive-and-settle authority onto App Services."""

    name = "model_app_service_service_bus_message_removal_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AzureDecorationContext,
    ) -> None:
        for workload in resources:
            if workload.resource_type not in AZURE_APP_SERVICE_RESOURCE_TYPES:
                continue
            paths, uncertainties = _app_service_service_bus_message_removal_paths(
                workload,
                context,
            )
            facts = azure_facts(workload)
            facts.set_app_service_service_bus_message_removal_paths(paths)
            facts.extend_app_service_service_bus_message_removal_path_uncertainties(
                uncertainties,
            )


def _app_service_service_bus_message_removal_paths(
    workload: NormalizedResource,
    context: AzureDecorationContext,
) -> tuple[list[AzureAppServiceServiceBusMessageRemovalPath], list[str]]:
    facts = azure_facts(workload)
    identities = _current_workload_identities(workload, context)
    paths: list[AzureAppServiceServiceBusMessageRemovalPath] = []
    uncertainties = list(facts.app_service_service_bus_access_path_uncertainties)

    for access_path in facts.app_service_service_bus_access_paths:
        if not _access_path_allows_settlement(access_path):
            continue
        target_access_paths, target_uncertainties = _settlement_access_targets(
            access_path,
            context,
        )
        uncertainties.extend(target_uncertainties)
        for target_access_path in target_access_paths:
            path, uncertainty = _message_removal_path(
                workload,
                target_access_path,
                identities,
                context,
            )
            if uncertainty is not None:
                uncertainties.append(f"{workload.address}: {uncertainty}")
            if path is not None:
                paths.append(path)

    paths.sort(
        key=lambda path: (
            path["service_bus_namespace_address"],
            path["service_bus_resource_address"],
            path["identity_address"],
            path["role_assignment_address"],
        )
    )
    return _dedupe_paths(paths), dedupe(uncertainties)


def _settlement_access_targets(
    access_path: Mapping[str, Any],
    context: AzureDecorationContext,
) -> tuple[list[Mapping[str, Any]], list[str]]:
    resource_type = access_path.get("service_bus_resource_type")
    if resource_type != AzureResourceType.SERVICE_BUS_NAMESPACE:
        return [access_path], []

    namespace_address = _known_string(
        access_path.get("service_bus_resource_address"),
    )
    namespace = context.index.resolve(
        namespace_address,
        resource_types={AzureResourceType.SERVICE_BUS_NAMESPACE},
    )
    if namespace is None or namespace.resource_type != AzureResourceType.SERVICE_BUS_NAMESPACE:
        return [], ["Service Bus namespace authorization scope is unresolved"]

    targets: list[Mapping[str, Any]] = []
    uncertainties: list[str] = []
    namespace_id = _known_string(azure_facts(namespace).service_bus_namespace_id)
    for resource in context.index.resources_by_address.values():
        if resource.resource_type not in {
            AzureResourceType.SERVICE_BUS_QUEUE,
            AzureResourceType.SERVICE_BUS_SUBSCRIPTION,
        }:
            continue

        resource_facts = azure_facts(resource)
        resolved_namespace_address = resource_facts.resolved_service_bus_namespace_address
        if resolved_namespace_address is not None:
            if resolved_namespace_address != namespace.address:
                continue
        else:
            namespace_reference = _known_string(
                resource_facts.service_bus_namespace_reference,
            )
            referenced_namespace = context.index.resolve(
                namespace_reference,
                source=resource,
                resource_types={AzureResourceType.SERVICE_BUS_NAMESPACE},
            )
            if referenced_namespace is not None and referenced_namespace.address != namespace.address:
                continue
            if (
                namespace_reference is not None
                and namespace_id is not None
                and namespace_reference.startswith("/")
                and not _same_identifier(namespace_reference, namespace_id)
            ):
                continue
            uncertainties.append(
                f"{resource.address}: Service Bus namespace ancestry is unresolved",
            )
            continue

        resource_id = _service_bus_resource_id(resource)
        if resource_id is None:
            uncertainties.append(
                f"{resource.address}: Service Bus entity identity is unresolved",
            )
            continue

        candidate = dict(access_path)
        candidate.update(
            {
                "service_bus_resource_address": resource.address,
                "service_bus_resource_type": resource.resource_type,
                "service_bus_resource_id": resource_id,
                "service_bus_entity_kind": resource_facts.service_bus_entity_kind,
                "resource_scope": (
                    "exact_service_bus_queue"
                    if resource.resource_type == AzureResourceType.SERVICE_BUS_QUEUE
                    else "exact_service_bus_subscription"
                ),
                "queue_address": (
                    resource.address if resource.resource_type == AzureResourceType.SERVICE_BUS_QUEUE else None
                ),
                "topic_address": None,
                "subscription_address": (
                    resource.address if resource.resource_type == AzureResourceType.SERVICE_BUS_SUBSCRIPTION else None
                ),
            }
        )

        candidate["_source_assignment_scope_kind"] = access_path.get(
            "assignment_scope_kind",
        )
        candidate["assignment_scope_kind"] = "namespace"
        candidate["_authorization_scope_address"] = namespace.address
        candidate["_authorization_scope_type"] = namespace.resource_type

        if resource.resource_type == AzureResourceType.SERVICE_BUS_SUBSCRIPTION:
            topic_address = resource_facts.resolved_service_bus_topic_address
            topic = context.index.resolve(
                topic_address,
                source=resource,
                resource_types={AzureResourceType.SERVICE_BUS_TOPIC},
            )
            if (
                topic is None
                or topic.resource_type != AzureResourceType.SERVICE_BUS_TOPIC
                or azure_facts(topic).resolved_service_bus_namespace_address != namespace.address
            ):
                uncertainties.append(
                    f"{resource.address}: Service Bus topic ancestry is unresolved",
                )
                continue
            candidate["topic_address"] = topic.address

        targets.append(candidate)

    return targets, uncertainties


def _current_workload_identities(
    workload: NormalizedResource,
    context: AzureDecorationContext,
) -> dict[str, tuple[AzureKeyVaultRuntimeIdentityKind, str]]:
    identities, _uncertainties = workload_managed_identities(workload, context)
    result: dict[str, tuple[AzureKeyVaultRuntimeIdentityKind, str]] = {}
    for identity, identity_kind in identities:
        principal_id = _known_string(azure_facts(identity).principal_id)
        typed_kind = _identity_kind(identity_kind)
        if principal_id is not None and typed_kind is not None:
            result[identity.address] = (typed_kind, principal_id)
    return result


def _access_path_allows_settlement(access_path: Mapping[str, Any]) -> bool:
    if "receive" not in _string_values(access_path.get("access_classes")):
        return False
    role_kind = _known_string(access_path.get("role_kind"))
    if role_kind == "custom":
        return _RECEIVE_CASEFOLDED in {
            action.casefold() for action in _string_values(access_path.get("matched_data_actions"))
        }
    return role_kind in _BUILT_IN_RECEIVE_ROLE_KINDS


def _settlement_status(
    target: NormalizedResource,
) -> tuple[str | None, str | None]:
    status = _known_string(azure_facts(target).service_bus_entity_status)
    if status is None:
        return None, f"{target.address}: Service Bus entity status is unresolved"

    normalized = status.casefold().replace("_", "").replace("-", "").replace(" ", "")
    if normalized == "active":
        return status, None
    if normalized == "senddisabled" and target.resource_type == AzureResourceType.SERVICE_BUS_QUEUE:
        return status, None
    if normalized in {"receivedisabled", "disabled"}:
        return None, None
    return None, f"{target.address}: Service Bus entity status {status!r} is unsupported or transitional"


def _message_removal_path(
    workload: NormalizedResource,
    access_path: Mapping[str, Any],
    identities: Mapping[str, tuple[AzureKeyVaultRuntimeIdentityKind, str]],
    context: AzureDecorationContext,
) -> tuple[AzureAppServiceServiceBusMessageRemovalPath | None, str | None]:
    if (
        access_path.get("workload_address") != workload.address
        or access_path.get("workload_type") != workload.resource_type
        or access_path.get("credential_context") != "workload_runtime"
        or access_path.get("evaluation_basis") != "modeled_rbac_assignment"
        or access_path.get("access_state") != "granted"
        or access_path.get("condition") is not None
        or access_path.get("condition_state") != "not_configured"
    ):
        return None, "Service Bus settlement access path is not deterministic"

    identity_address = _known_string(access_path.get("identity_address"))
    principal_id = _known_string(access_path.get("principal_id"))
    identity_kind = _identity_kind(access_path.get("identity_kind"))
    current_identity = identities.get(identity_address or "")
    if (
        identity_address is None
        or principal_id is None
        or identity_kind is None
        or current_identity is None
        or current_identity[0] != identity_kind
        or not _same_identifier(current_identity[1], principal_id)
    ):
        return None, "Service Bus settlement access path has no exact current runtime identity"

    target, namespace, topic, target_uncertainty = _current_target(
        access_path,
        context,
    )
    if target is None or namespace is None:
        return None, target_uncertainty

    entity_status, status_uncertainty = _settlement_status(target)
    if entity_status is None:
        return None, status_uncertainty

    service_bus_facts = azure_facts(target)
    auto_forwarding_state = service_bus_facts.service_bus_auto_forwarding_state
    forward_to = service_bus_facts.service_bus_forward_to
    if auto_forwarding_state == "configured":
        return None, None
    if auto_forwarding_state != "not_configured":
        return None, f"{target.address}: Service Bus auto-forwarding state is unresolved"
    if forward_to is not None:
        return None, f"{target.address}: Service Bus auto-forwarding evidence is incoherent"

    role_assignment_address = _known_string(access_path.get("role_assignment_address"))
    role_definition_name = _known_string(access_path.get("role_definition_name"))
    assignment_scope = _known_string(access_path.get("assignment_scope"))
    assignment_scope_kind = _known_string(access_path.get("assignment_scope_kind"))
    if assignment_scope_kind == "namespace" and (
        access_path.get("_authorization_scope_address") != namespace.address
        or access_path.get("_authorization_scope_type") != AzureResourceType.SERVICE_BUS_NAMESPACE
    ):
        return None, "Service Bus namespace authorization scope is incoherent"
    grant_basis = _known_string(access_path.get("grant_basis"))
    role_kind = _known_string(access_path.get("role_kind"))
    if (
        role_assignment_address is None
        or role_definition_name is None
        or assignment_scope is None
        or assignment_scope_kind is None
        or grant_basis
        not in {
            "azure_service_bus_scoped_rbac",
            "azure_custom_role_service_bus_scoped_rbac",
        }
        or role_kind is None
    ):
        return None, "Service Bus settlement authorization evidence is incomplete"

    assignment = context.index.resolve(
        role_assignment_address,
        source=workload,
        resource_types={AzureResourceType.ROLE_ASSIGNMENT},
    )
    if assignment is None or assignment.resource_type != AzureResourceType.ROLE_ASSIGNMENT:
        return None, "Service Bus settlement role assignment is unavailable"
    assignment_facts = azure_facts(assignment)
    source_assignment_scope_kind = _known_string(
        access_path.get(
            "_source_assignment_scope_kind",
            assignment_scope_kind,
        )
    )
    if (
        not _same_identifier(assignment_facts.principal_id, principal_id)
        or not _same_identifier(
            assignment_facts.role_assignment_scope,
            assignment_scope,
        )
        or assignment_facts.role_assignment_scope_kind != source_assignment_scope_kind
        or assignment_condition_state(assignment) != "not_configured"
    ):
        return None, "Service Bus settlement role assignment is no longer exact"

    role_definition_address = _known_string(access_path.get("role_definition_address"))
    custom_role_assignable_scope_compatibility_state = "not_applicable"
    if role_kind == "custom":
        role_definition = context.index.resolve(
            role_definition_address,
            source=assignment,
            resource_types={AzureResourceType.ROLE_DEFINITION},
        )
        if (
            role_definition is None
            or role_definition.resource_type != AzureResourceType.ROLE_DEFINITION
            or azure_facts(assignment).resolved_role_definition_address != role_definition.address
            or azure_facts(role_definition).role_definition_data_actions
            != _string_values(access_path.get("custom_role_data_actions"))
            or azure_facts(role_definition).role_definition_not_data_actions
            != _string_values(access_path.get("custom_role_not_data_actions"))
        ):
            return None, "custom Service Bus settlement role definition is unavailable or stale"
        custom_role_assignable_scope_compatibility_state = _custom_role_assignable_scope_compatibility(
            role_definition,
            target,
            namespace,
            access_path,
            context,
        )
        if custom_role_assignable_scope_compatibility_state == "outside_assignable_scope":
            return None, None
        if custom_role_assignable_scope_compatibility_state != "compatible":
            return (
                None,
                "custom Service Bus settlement role assignable-scope compatibility is unresolved",
            )
    elif role_definition_address is not None:
        return None, "built-in Service Bus settlement evidence names a custom role definition"

    namespace_id = _known_string(azure_facts(namespace).service_bus_namespace_id)
    service_bus_resource_id = _service_bus_resource_id(target)
    if namespace_id is None or service_bus_resource_id is None:
        return None, "Service Bus settlement target identity is unresolved"

    delivery_evidence = _delivery_evidence(target)
    common: AzureAppServiceServiceBusMessageRemovalPathCommon = {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "identity_address": identity_address,
        "identity_kind": identity_kind,
        "principal_id": principal_id,
        "credential_context": "workload_runtime",
        "service_bus_resource_address": target.address,
        "service_bus_resource_type": target.resource_type,
        "service_bus_resource_id": service_bus_resource_id,
        "service_bus_entity_status": entity_status,
        "service_bus_auto_forwarding_state": "not_configured",
        "service_bus_forward_to": None,
        "service_bus_namespace_address": namespace.address,
        "service_bus_namespace_id": namespace_id,
        "operation": _RECEIVE,
        "operation_class": "destructive_message_receive",
        "management_effect": "disruption",
        "target_model_evidence_addresses": _target_evidence_addresses(
            target,
            namespace,
            topic,
        ),
        "receive_and_delete_capability": True,
        "peek_lock_complete_capability": True,
        "runtime_receive_mode_selection": "not_plan_visible",
        "complete_lock_token_source": "runtime_peek_lock_receive",
        "complete_lock_token_value": None,
        "role_assignment_address": role_assignment_address,
        "role_definition_name": role_definition_name,
        "role_definition_id": _known_string(access_path.get("role_definition_id")),
        "role_definition_address": role_definition_address,
        "role_kind": role_kind,
        "custom_role_assignable_scope_compatibility_state": (custom_role_assignable_scope_compatibility_state),
        "grant_basis": grant_basis,
        "evaluation_basis": "modeled_rbac_assignment",
        "assignment_scope": assignment_scope,
        "assignment_scope_kind": assignment_scope_kind,
        "authorization_source_addresses": dedupe_strings([role_assignment_address, role_definition_address]),
        "custom_role_data_actions": _string_values(access_path.get("custom_role_data_actions")),
        "custom_role_not_data_actions": _string_values(access_path.get("custom_role_not_data_actions")),
        "matched_data_actions": [_RECEIVE],
        "excluded_data_actions": _string_values(access_path.get("excluded_data_actions")),
        "condition": None,
        "condition_state": "not_configured",
        "authorization_state": "granted",
        "policy_complete": True,
        "lifecycle_compatibility_state": "not_applicable",
        "delivery_evidence": delivery_evidence,
        "posture_uncertainties": list(delivery_evidence["uncertainties"]),
    }
    return _scoped_path(common, target, topic), None


def _custom_role_assignable_scope_compatibility(
    role_definition: NormalizedResource,
    target: NormalizedResource,
    namespace: NormalizedResource,
    access_path: Mapping[str, Any],
    context: AzureDecorationContext,
) -> str:
    role_facts = azure_facts(role_definition)
    if any("assignable_scopes" in uncertainty for uncertainty in role_facts.role_definition_uncertainties):
        return "unknown"

    assignable_scopes = role_facts.role_definition_assignable_scopes
    if not assignable_scopes:
        return "unknown"

    scope_address = _known_string(
        access_path.get("_authorization_scope_address"),
    )
    scope_resource = (
        namespace
        if scope_address == namespace.address
        else target
        if scope_address is None or scope_address == target.address
        else context.index.resolve(scope_address, source=role_definition)
    )
    assignment_arm_id = _resource_arm_id(scope_resource)
    if assignment_arm_id is None:
        return "unknown"

    resolved_scopes: list[str] = []
    for raw_scope in assignable_scopes:
        scope = _known_string(raw_scope)
        if scope is None:
            return "unknown"
        if scope.startswith("/"):
            resolved_scopes.append(scope)
            continue
        referenced_resource = context.index.resolve(scope, source=role_definition)
        referenced_id = _resource_arm_id(referenced_resource)
        if referenced_id is None:
            return "unknown"
        resolved_scopes.append(referenced_id)

    if any(azure_arm_scope_contains(scope, assignment_arm_id) for scope in resolved_scopes):
        return "compatible"
    return "outside_assignable_scope"


def _resource_arm_id(resource: NormalizedResource | None) -> str | None:
    if resource is None:
        return None
    facts = azure_facts(resource)
    if resource.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE:
        value = facts.service_bus_namespace_id
    elif resource.resource_type in {
        AzureResourceType.SERVICE_BUS_QUEUE,
        AzureResourceType.SERVICE_BUS_TOPIC,
        AzureResourceType.SERVICE_BUS_SUBSCRIPTION,
    }:
        value = facts.service_bus_entity_id
    else:
        value = resource.identifier
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized if normalized.startswith("/") else None


def _current_target(
    access_path: Mapping[str, Any],
    context: AzureDecorationContext,
) -> tuple[
    NormalizedResource | None,
    NormalizedResource | None,
    NormalizedResource | None,
    str | None,
]:
    target_address = _known_string(access_path.get("service_bus_resource_address"))
    namespace_address = _known_string(access_path.get("service_bus_namespace_address"))
    target = context.index.resolve(
        target_address,
        resource_types=_SETTLEMENT_TARGET_TYPES,
    )
    namespace = context.index.resolve(
        namespace_address,
        source=target,
        resource_types={AzureResourceType.SERVICE_BUS_NAMESPACE},
    )
    if (
        target is None
        or target.resource_type not in _SETTLEMENT_TARGET_TYPES
        or namespace is None
        or namespace.resource_type != AzureResourceType.SERVICE_BUS_NAMESPACE
        or access_path.get("service_bus_resource_type") != target.resource_type
        or not _same_identifier(
            _service_bus_resource_id(target),
            _known_string(access_path.get("service_bus_resource_id")),
        )
        or not _same_identifier(
            azure_facts(namespace).service_bus_namespace_id,
            _known_string(access_path.get("service_bus_namespace_id")),
        )
    ):
        return None, None, None, "Service Bus settlement target identity is unresolved"

    target_facts = azure_facts(target)
    topic: NormalizedResource | None = None
    if target.resource_type == AzureResourceType.SERVICE_BUS_QUEUE:
        if (
            target_facts.resolved_service_bus_namespace_address != namespace.address
            or access_path.get("resource_scope") != "exact_service_bus_queue"
            or access_path.get("queue_address") != target.address
            or access_path.get("topic_address") is not None
            or access_path.get("subscription_address") is not None
        ):
            return None, None, None, "Service Bus queue settlement ancestry is unresolved"
    else:
        topic_address = _known_string(access_path.get("topic_address"))
        topic = context.index.resolve(
            topic_address,
            source=target,
            resource_types={AzureResourceType.SERVICE_BUS_TOPIC},
        )
        if (
            topic is None
            or topic.resource_type != AzureResourceType.SERVICE_BUS_TOPIC
            or target_facts.resolved_service_bus_namespace_address != namespace.address
            or target_facts.resolved_service_bus_topic_address != topic.address
            or azure_facts(topic).resolved_service_bus_namespace_address != namespace.address
            or access_path.get("resource_scope") != "exact_service_bus_subscription"
            or access_path.get("queue_address") is not None
            or access_path.get("subscription_address") != target.address
        ):
            return None, None, None, "Service Bus subscription settlement ancestry is unresolved"
    return target, namespace, topic, None


def _scoped_path(
    common: AzureAppServiceServiceBusMessageRemovalPathCommon,
    target: NormalizedResource,
    topic: NormalizedResource | None,
) -> AzureAppServiceServiceBusMessageRemovalPath:
    if target.resource_type == AzureResourceType.SERVICE_BUS_QUEUE:
        queue_path = AzureAppServiceServiceBusQueueMessageRemovalPath(
            **common,
            scope_type="queue",
            target_granularity="queue_message_namespace",
            target_scope="exact_service_bus_queue_message_namespace",
            service_bus_entity_kind="queue",
            queue_address=target.address,
            topic_address=None,
            subscription_address=None,
        )
        return queue_path
    assert topic is not None
    subscription_path = AzureAppServiceServiceBusSubscriptionMessageRemovalPath(
        **common,
        scope_type="subscription",
        target_granularity="subscription_message_namespace",
        target_scope="exact_service_bus_subscription_message_namespace",
        service_bus_entity_kind="subscription",
        queue_address=None,
        topic_address=topic.address,
        subscription_address=target.address,
    )
    return subscription_path


def _target_evidence_addresses(
    target: NormalizedResource,
    namespace: NormalizedResource,
    topic: NormalizedResource | None,
) -> list[str]:
    if target.resource_type == AzureResourceType.SERVICE_BUS_QUEUE:
        return [namespace.address, target.address]
    assert topic is not None
    return [namespace.address, topic.address, target.address]


def _delivery_evidence(
    target: NormalizedResource,
) -> AzureServiceBusMessageRemovalDeliveryEvidence:
    facts = azure_facts(target)
    uncertainties = [f"{target.address}: {uncertainty}" for uncertainty in facts.service_bus_posture_uncertainties]
    default_message_time_to_live = facts.service_bus_default_message_time_to_live
    lock_duration = facts.service_bus_lock_duration
    max_delivery_count = facts.service_bus_max_delivery_count
    dead_lettering_on_message_expiration = facts.service_bus_dead_lettering_on_message_expiration
    return {
        "delivery_evidence_scope": "service_bus_message_delivery_posture",
        "default_message_time_to_live": default_message_time_to_live,
        "lock_duration": lock_duration,
        "max_delivery_count": max_delivery_count,
        "dead_lettering_on_message_expiration": (dead_lettering_on_message_expiration),
        "removed_message_recovery_state": ("not_established_by_modeled_service_bus_delivery_controls"),
        "uncertainties": dedupe(uncertainties),
    }


def _service_bus_resource_id(resource: NormalizedResource) -> str | None:
    facts = azure_facts(resource)
    if resource.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE:
        return _known_string(facts.service_bus_namespace_id)
    return _known_string(facts.service_bus_entity_id)


def _identity_kind(value: object) -> AzureKeyVaultRuntimeIdentityKind | None:
    if value not in {"system_assigned", "user_assigned"}:
        return None
    return cast(AzureKeyVaultRuntimeIdentityKind, value)


def _same_identifier(left: str | None, right: str | None) -> bool:
    return bool(left and right and left.strip().casefold() == right.strip().casefold())


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            continue
        normalized = item.strip()
        if not normalized or normalized in seen:
            continue
        result.append(normalized)
        seen.add(normalized)
    return result


def _dedupe_paths(
    paths: list[AzureAppServiceServiceBusMessageRemovalPath],
) -> list[AzureAppServiceServiceBusMessageRemovalPath]:
    result: list[AzureAppServiceServiceBusMessageRemovalPath] = []
    for path in paths:
        if path not in result:
            result.append(path)
    return result
