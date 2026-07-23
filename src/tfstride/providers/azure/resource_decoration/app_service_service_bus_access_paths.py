from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.azure.resource_decoration.workload_identities import workload_managed_identities
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import AZURE_APP_SERVICE_RESOURCE_TYPES, AzureResourceType
from tfstride.providers.coercion import dedupe

_ACCESS_CLASS_ORDER = ("send", "receive", "administrative")
_BUILT_IN_SERVICE_BUS_DATA_ROLES: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "azure service bus data sender": (
        "Azure Service Bus Data Sender",
        "service_bus_data_sender",
        ("send",),
    ),
    "azure service bus data receiver": (
        "Azure Service Bus Data Receiver",
        "service_bus_data_receiver",
        ("receive",),
    ),
    "azure service bus data owner": (
        "Azure Service Bus Data Owner",
        "service_bus_data_owner",
        _ACCESS_CLASS_ORDER,
    ),
}
_BUILT_IN_SERVICE_BUS_DATA_ROLE_IDS: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "69a216fc-b8fb-44d8-bc22-1f3c2cd27a39": _BUILT_IN_SERVICE_BUS_DATA_ROLES["azure service bus data sender"],
    "4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0": _BUILT_IN_SERVICE_BUS_DATA_ROLES["azure service bus data receiver"],
    "090c5cfd-751d-490a-894a-3ce6f1109419": _BUILT_IN_SERVICE_BUS_DATA_ROLES["azure service bus data owner"],
}
_SERVICE_BUS_DATA_ACTIONS: tuple[tuple[str, str], ...] = (
    ("microsoft.servicebus/namespaces/messages/send/action", "send"),
    ("microsoft.servicebus/namespaces/messages/receive/action", "receive"),
    (
        "microsoft.servicebus/namespaces/generateuserdelegationkey/action",
        "administrative",
    ),
    (
        "microsoft.servicebus/namespaces/revokeuserdelegationkeys/action",
        "administrative",
    ),
)
_SERVICE_BUS_TARGET_TYPES = frozenset(
    {
        AzureResourceType.SERVICE_BUS_NAMESPACE,
        AzureResourceType.SERVICE_BUS_QUEUE,
        AzureResourceType.SERVICE_BUS_TOPIC,
        AzureResourceType.SERVICE_BUS_SUBSCRIPTION,
    }
)
_TARGET_ACCESS_CLASSES: dict[str, frozenset[str]] = {
    AzureResourceType.SERVICE_BUS_NAMESPACE: frozenset({"send", "receive", "administrative"}),
    AzureResourceType.SERVICE_BUS_QUEUE: frozenset({"send", "receive"}),
    AzureResourceType.SERVICE_BUS_TOPIC: frozenset({"send"}),
    AzureResourceType.SERVICE_BUS_SUBSCRIPTION: frozenset({"receive"}),
}


@dataclass(frozen=True, slots=True)
class _ServiceBusDataGrant:
    role_name: str
    role_kind: str
    access_classes: tuple[str, ...]
    grant_basis: str
    role_definition_address: str | None = None
    permission_patterns: tuple[str, ...] = ()
    not_permission_patterns: tuple[str, ...] = ()
    matched_data_actions: tuple[str, ...] = ()
    excluded_data_actions: tuple[str, ...] = ()


class ModelAppServiceServiceBusAccessPathsStage:
    name = "model_app_service_service_bus_access_paths"

    def apply(self, resources: list[NormalizedResource], context: AzureDecorationContext) -> None:
        for workload in resources:
            if workload.resource_type not in AZURE_APP_SERVICE_RESOURCE_TYPES:
                continue
            paths, uncertainties = _app_service_service_bus_access_paths(workload, context)
            facts = azure_facts(workload)
            facts.set_app_service_service_bus_access_paths(paths)
            facts.extend_app_service_service_bus_access_path_uncertainties(uncertainties)


def _app_service_service_bus_access_paths(
    workload: NormalizedResource,
    context: AzureDecorationContext,
) -> tuple[list[dict[str, Any]], list[str]]:
    workload_facts = azure_facts(workload)
    identities, identity_uncertainties = workload_managed_identities(workload, context)
    uncertainties = [
        *identity_uncertainties,
        *[f"{workload.address}: {value}" for value in workload_facts.managed_identity_uncertainties],
    ]
    paths: list[dict[str, Any]] = []

    for identity, identity_kind in identities:
        identity_facts = azure_facts(identity)
        for assignment in identity_facts.managed_identity_role_assignments:
            assignment_resource = _assignment_resource(assignment, context)
            if assignment_resource is None:
                source = _string_value(assignment.get("source")) or "unknown role assignment"
                uncertainties.append(f"{workload.address}: {source} is not modeled")
                continue
            assignment_facts = azure_facts(assignment_resource)
            if not _same_identifier(assignment_facts.principal_id, identity_facts.principal_id):
                continue
            if _condition_is_unknown(assignment_resource):
                uncertainties.append(f"{workload.address}: {assignment_resource.address} condition is unresolved")
                continue

            target, target_uncertainty = _exact_service_bus_target(
                assignment,
                assignment_resource,
                context,
            )
            if target_uncertainty:
                uncertainties.append(f"{workload.address}: {assignment_resource.address} {target_uncertainty}")
            if target is None:
                continue

            grant, grant_uncertainty = _service_bus_data_grant(
                assignment,
                assignment_resource,
                context,
                target.resource_type,
            )
            if grant_uncertainty:
                uncertainties.append(f"{workload.address}: {assignment_resource.address} {grant_uncertainty}")
            if grant is None:
                continue
            paths.append(
                _access_path_record(
                    workload,
                    identity,
                    identity_kind,
                    assignment_resource,
                    target,
                    grant,
                    context,
                )
            )

    return _dedupe_dicts(paths), dedupe(uncertainties)


def _assignment_resource(
    assignment: Mapping[str, Any],
    context: AzureDecorationContext,
) -> NormalizedResource | None:
    resource = context.index.resolve(_string_value(assignment.get("source")))
    if resource is None or resource.resource_type != AzureResourceType.ROLE_ASSIGNMENT:
        return None
    return resource


def _exact_service_bus_target(
    assignment: Mapping[str, Any],
    assignment_resource: NormalizedResource,
    context: AzureDecorationContext,
) -> tuple[NormalizedResource | None, str | None]:
    target_address = _string_value(assignment.get("target_resource_address"))
    target_type = _string_value(assignment.get("target_resource_type"))
    scope_kind = _string_value(assignment.get("scope_kind"))
    if scope_kind != "resource" or target_address is None or target_type not in _SERVICE_BUS_TARGET_TYPES:
        scope = azure_facts(assignment_resource).role_assignment_scope or "unknown"
        return (
            None,
            f"scope {scope} does not resolve to an exact Service Bus namespace, queue, topic, or subscription",
        )

    target = context.index.resolve(target_address)
    if target is None or target.address != target_address or target.resource_type != target_type:
        return (
            None,
            f"target {target_address} is not an exact modeled Service Bus namespace, queue, topic, or subscription",
        )
    return target, None


def _service_bus_data_grant(
    assignment: Mapping[str, Any],
    assignment_resource: NormalizedResource,
    context: AzureDecorationContext,
    target_type: str,
) -> tuple[_ServiceBusDataGrant | None, str | None]:
    role_name = _string_value(assignment.get("role_definition_name"))
    role_definition_id = _string_value(assignment.get("role_definition_id"))
    built_in = _built_in_role(role_name, role_definition_id)
    if built_in is not None:
        default_role_name, role_kind, access_classes = built_in
        access_classes = _applicable_access_classes(access_classes, target_type)
        if not access_classes:
            return None, None
        return (
            _ServiceBusDataGrant(
                role_name=default_role_name,
                role_kind=role_kind,
                access_classes=access_classes,
                grant_basis="azure_service_bus_scoped_rbac",
            ),
            None,
        )

    assignment_facts = azure_facts(assignment_resource)
    role_definition = context.index.resolve(assignment_facts.resolved_role_definition_address)
    if role_definition is None or role_definition.resource_type != AzureResourceType.ROLE_DEFINITION:
        if role_name is None:
            return None, "role is unresolved"
        return None, None

    role_facts = azure_facts(role_definition)
    if any(
        "data_actions" in value or "not_data_actions" in value for value in role_facts.role_definition_uncertainties
    ):
        return None, f"custom role {role_definition.address} data actions are unresolved"

    permission_patterns = tuple(value for value in role_facts.role_definition_data_actions if value.strip())
    not_permission_patterns = tuple(value for value in role_facts.role_definition_not_data_actions if value.strip())
    matched, excluded = _matched_data_actions(
        permission_patterns,
        not_permission_patterns,
        target_type,
    )
    if not matched:
        return None, None
    return (
        _ServiceBusDataGrant(
            role_name=role_name or role_facts.name or role_definition.address,
            role_kind="custom",
            access_classes=_access_classes(matched),
            grant_basis="azure_custom_role_service_bus_scoped_rbac",
            role_definition_address=role_definition.address,
            permission_patterns=permission_patterns,
            not_permission_patterns=not_permission_patterns,
            matched_data_actions=matched,
            excluded_data_actions=excluded,
        ),
        None,
    )


def _built_in_role(
    role_name: str | None,
    role_definition_id: str | None,
) -> tuple[str, str, tuple[str, ...]] | None:
    if role_definition_id:
        role_id = role_definition_id.strip().lower().rstrip("/").rsplit("/", 1)[-1]
        return _BUILT_IN_SERVICE_BUS_DATA_ROLE_IDS.get(role_id)
    if role_name:
        return _BUILT_IN_SERVICE_BUS_DATA_ROLES.get(role_name.strip().lower())
    return None


def _matched_data_actions(
    permission_patterns: tuple[str, ...],
    not_permission_patterns: tuple[str, ...],
    target_type: str,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    applicable_classes = _TARGET_ACCESS_CLASSES.get(target_type, frozenset())
    matched: list[str] = []
    excluded: list[str] = []
    for action, access_class in _SERVICE_BUS_DATA_ACTIONS:
        if access_class not in applicable_classes:
            continue
        if not _matches_any(action, permission_patterns):
            continue
        if _matches_any(action, not_permission_patterns):
            excluded.append(action)
        else:
            matched.append(action)
    return tuple(matched), tuple(excluded)


def _access_classes(actions: tuple[str, ...]) -> tuple[str, ...]:
    classes = {access_class for action, access_class in _SERVICE_BUS_DATA_ACTIONS if action in actions}
    return tuple(access_class for access_class in _ACCESS_CLASS_ORDER if access_class in classes)


def _applicable_access_classes(
    access_classes: tuple[str, ...],
    target_type: str,
) -> tuple[str, ...]:
    applicable = _TARGET_ACCESS_CLASSES.get(target_type, frozenset())
    return tuple(
        access_class
        for access_class in _ACCESS_CLASS_ORDER
        if access_class in access_classes and access_class in applicable
    )


def _matches_any(action: str, patterns: tuple[str, ...]) -> bool:
    normalized_action = action.strip().lower()
    return any(fnmatchcase(normalized_action, pattern.strip().lower()) for pattern in patterns)


def _access_path_record(
    workload: NormalizedResource,
    identity: NormalizedResource,
    identity_kind: str,
    assignment: NormalizedResource,
    target: NormalizedResource,
    grant: _ServiceBusDataGrant,
    context: AzureDecorationContext,
) -> dict[str, Any]:
    identity_facts = azure_facts(identity)
    assignment_facts = azure_facts(assignment)
    target_facts = azure_facts(target)
    namespace = _service_bus_namespace_for_target(target, context)
    topic = _service_bus_topic_for_target(target, context)
    condition = assignment_facts.role_assignment_condition
    return {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "identity_address": identity.address,
        "identity_kind": identity_kind,
        "principal_id": identity_facts.principal_id,
        "credential_context": "workload_runtime",
        "service_bus_resource_address": target.address,
        "service_bus_resource_type": target.resource_type,
        "service_bus_resource_id": _service_bus_resource_id(target),
        "service_bus_entity_kind": (
            "namespace"
            if target.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE
            else target_facts.service_bus_entity_kind
        ),
        "service_bus_namespace_address": namespace.address if namespace else None,
        "service_bus_namespace_id": (azure_facts(namespace).service_bus_namespace_id if namespace else None),
        "queue_address": (target.address if target.resource_type == AzureResourceType.SERVICE_BUS_QUEUE else None),
        "topic_address": topic.address if topic else None,
        "subscription_address": (
            target.address if target.resource_type == AzureResourceType.SERVICE_BUS_SUBSCRIPTION else None
        ),
        "role_assignment_address": assignment.address,
        "role_definition_name": grant.role_name,
        "role_definition_id": assignment_facts.role_definition_id,
        "role_kind": grant.role_kind,
        "access_classes": list(grant.access_classes),
        "grant_basis": grant.grant_basis,
        "evaluation_basis": "modeled_rbac_assignment",
        "resource_scope": _resource_scope(target),
        "assignment_scope": assignment_facts.role_assignment_scope,
        "assignment_scope_kind": assignment_facts.role_assignment_scope_kind,
        "condition": condition,
        "condition_state": "configured" if condition else "not_configured",
        "access_state": "conditional" if condition else "granted",
        "role_definition_address": grant.role_definition_address,
        "custom_role_data_actions": list(grant.permission_patterns),
        "custom_role_not_data_actions": list(grant.not_permission_patterns),
        "matched_data_actions": list(grant.matched_data_actions),
        "excluded_data_actions": list(grant.excluded_data_actions),
    }


def _service_bus_resource_id(target: NormalizedResource) -> str | None:
    facts = azure_facts(target)
    if target.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE:
        return facts.service_bus_namespace_id
    return facts.service_bus_entity_id


def _service_bus_namespace_for_target(
    target: NormalizedResource,
    context: AzureDecorationContext,
) -> NormalizedResource | None:
    if target.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE:
        return target
    namespace = context.index.resolve(azure_facts(target).resolved_service_bus_namespace_address)
    if namespace is None or namespace.resource_type != AzureResourceType.SERVICE_BUS_NAMESPACE:
        return None
    return namespace


def _service_bus_topic_for_target(
    target: NormalizedResource,
    context: AzureDecorationContext,
) -> NormalizedResource | None:
    if target.resource_type == AzureResourceType.SERVICE_BUS_TOPIC:
        return target
    if target.resource_type != AzureResourceType.SERVICE_BUS_SUBSCRIPTION:
        return None
    topic = context.index.resolve(azure_facts(target).resolved_service_bus_topic_address)
    if topic is None or topic.resource_type != AzureResourceType.SERVICE_BUS_TOPIC:
        return None
    return topic


def _resource_scope(target: NormalizedResource) -> str:
    if target.resource_type == AzureResourceType.SERVICE_BUS_QUEUE:
        return "exact_service_bus_queue"
    if target.resource_type == AzureResourceType.SERVICE_BUS_TOPIC:
        return "exact_service_bus_topic"
    if target.resource_type == AzureResourceType.SERVICE_BUS_SUBSCRIPTION:
        return "exact_service_bus_subscription"
    return "exact_service_bus_namespace"


def _condition_is_unknown(assignment: NormalizedResource) -> bool:
    return any(
        "condition is unknown" in uncertainty
        for uncertainty in azure_facts(assignment).key_vault_authorization_uncertainties
    )


def _same_identifier(left: str | None, right: str | None) -> bool:
    return bool(left and right and left.strip().lower() == right.strip().lower())


def _string_value(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _dedupe_dicts(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result
