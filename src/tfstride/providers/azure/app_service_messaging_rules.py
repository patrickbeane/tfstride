from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, cast

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
    assignment_condition_state,
    azure_arm_scope_contains,
)
from tfstride.providers.azure.resource_decoration.app_service_service_bus_access_paths import (
    service_bus_built_in_data_role,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import (
    AZURE_APP_SERVICE_RESOURCE_TYPES,
    AzureResourceType,
)
from tfstride.providers.azure.resource_utils import azure_reference_key, azure_resource_references
from tfstride.providers.coercion import dedupe

_MUTATION_ACCESS_CLASSES = frozenset({"send", "administrative"})
_RECEIVE_ACCESS_CLASS = "receive"
_SERVICE_BUS_RECEIVE_DATA_ACTION = "microsoft.servicebus/namespaces/messages/receive/action"
_MUTATING_ROLE_KINDS = frozenset(
    {
        "service_bus_data_sender",
        "service_bus_data_owner",
        "custom",
    }
)
_RECEIVING_ROLE_KINDS = frozenset(
    {
        "service_bus_data_receiver",
        "service_bus_data_owner",
        "custom",
    }
)
_SERVICE_BUS_TARGET_TYPES = (
    AzureResourceType.SERVICE_BUS_NAMESPACE,
    AzureResourceType.SERVICE_BUS_QUEUE,
    AzureResourceType.SERVICE_BUS_TOPIC,
    AzureResourceType.SERVICE_BUS_SUBSCRIPTION,
)
_SERVICE_BUS_RECEIVE_TARGET_TYPES = frozenset(
    {
        AzureResourceType.SERVICE_BUS_NAMESPACE,
        AzureResourceType.SERVICE_BUS_QUEUE,
        AzureResourceType.SERVICE_BUS_SUBSCRIPTION,
    }
)
_SERVICE_BUS_GRANT_BASES = frozenset(
    {
        "azure_service_bus_scoped_rbac",
        "azure_custom_role_service_bus_scoped_rbac",
    }
)
_SERVICE_BUS_MESSAGE_REMOVAL_RULE_OPERATION = "microsoft.servicebus/namespaces/messages/receive/action"
_SERVICE_BUS_MESSAGE_REMOVAL_TARGET_TYPES = frozenset(
    {
        AzureResourceType.SERVICE_BUS_QUEUE,
        AzureResourceType.SERVICE_BUS_SUBSCRIPTION,
    }
)
_SERVICE_BUS_MESSAGE_REMOVAL_GRANT_BASES = frozenset(
    {
        "azure_service_bus_scoped_rbac",
        "azure_custom_role_service_bus_scoped_rbac",
    }
)
_SERVICE_BUS_RESOURCE_SCOPES = frozenset(
    {
        "exact_service_bus_namespace",
        "exact_service_bus_queue",
        "exact_service_bus_topic",
        "exact_service_bus_subscription",
    }
)


class AzureAppServiceMessagingRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_app_service_service_bus_mutation_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            facts = azure_facts(app)
            ingress = app_service_ingress(app, context)
            if not ingress.is_public:
                continue

            mutation_paths = [
                path
                for path in facts.app_service_service_bus_access_paths
                if _is_deterministic_mutation_path(path, app, context)
            ]
            if not mutation_paths:
                continue

            target_addresses = _path_string_values(
                mutation_paths,
                "service_bus_resource_address",
            )
            namespace_addresses = _path_string_values(
                mutation_paths,
                "service_bus_namespace_address",
            )
            topic_addresses = _path_string_values(mutation_paths, "topic_address")
            identity_addresses = _path_string_values(mutation_paths, "identity_address")
            assignment_addresses = _path_string_values(
                mutation_paths,
                "role_assignment_address",
            )
            role_definition_addresses = _path_string_values(
                mutation_paths,
                "role_definition_address",
            )
            mutation_classes = _mutation_classes(mutation_paths)
            has_receive_access = _has_receive_access(mutation_paths)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2 if "administrative" in mutation_classes else 1,
                data_sensitivity=1,
                lateral_movement=1,
                blast_radius=2 if len(target_addresses) > 1 else 1,
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
                    rationale=_mutation_rationale(
                        app,
                        mutation_classes,
                        target_addresses,
                        has_receive_access=has_receive_access,
                    ),
                    evidence=collect_evidence(
                        *ingress.evidence,
                        evidence_item(
                            "runtime_identity",
                            _runtime_identity_evidence(mutation_paths),
                        ),
                        evidence_item(
                            "service_bus_mutation_paths",
                            _mutation_path_evidence(mutation_paths),
                        ),
                        evidence_item(
                            "custom_role_permissions",
                            _custom_role_permission_evidence(mutation_paths),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_public_app_service_service_bus_receive_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            facts = azure_facts(app)
            ingress = app_service_ingress(app, context)
            if not ingress.is_public:
                continue

            receive_paths = [
                path
                for path in facts.app_service_service_bus_access_paths
                if _is_deterministic_receive_path(path, app, context)
            ]
            if not receive_paths:
                continue

            target_addresses = _path_string_values(
                receive_paths,
                "service_bus_resource_address",
            )
            namespace_addresses = _path_string_values(
                receive_paths,
                "service_bus_namespace_address",
            )
            topic_addresses = _path_string_values(receive_paths, "topic_address")
            identity_addresses = _path_string_values(receive_paths, "identity_address")
            assignment_addresses = _path_string_values(
                receive_paths,
                "role_assignment_address",
            )
            role_definition_addresses = _path_string_values(
                receive_paths,
                "role_definition_address",
            )
            has_namespace_scope = any(
                path.get("resource_scope") == "exact_service_bus_namespace" for path in receive_paths
            )
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=1,
                data_sensitivity=1,
                lateral_movement=1,
                blast_radius=(2 if has_namespace_scope or len(target_addresses) > 1 else 1),
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
                    rationale=(
                        f"{app.display_name} permits external ingress within the evidenced scope and its runtime managed "
                        "identity has an unconditional modeled RBAC allow assignment containing Azure Service Bus "
                        f"receive permission on {len(target_addresses)} exact modeled target(s). A compromise "
                        "through an allowed public application path could attempt message-receive operations with "
                        "the workload identity. This establishes a modeled RBAC receive grant, not guaranteed "
                        "effective message retrieval; Azure deny assignments and Service Bus network controls are "
                        "independent controls not evaluated by this path. The Service Bus target itself is not "
                        "public. The ingress evidence identifies the allowed source and request scope."
                    ),
                    evidence=collect_evidence(
                        *ingress.evidence,
                        evidence_item(
                            "runtime_identity",
                            _runtime_identity_evidence(receive_paths),
                        ),
                        evidence_item(
                            "service_bus_receive_paths",
                            _receive_path_evidence(receive_paths),
                        ),
                        evidence_item(
                            "custom_role_permissions",
                            _custom_role_permission_evidence(receive_paths),
                        ),
                        evidence_item(
                            "assessment_scope",
                            [
                                (
                                    "establishes=unconditional modeled RBAC allow assignment with Azure Service "
                                    "Bus receive permission"
                                ),
                                (
                                    "does_not_establish=effective access after Azure deny assignment or Service "
                                    "Bus network evaluation"
                                ),
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_public_app_service_service_bus_message_disruption(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            app_facts = azure_facts(app)
            ingress = app_service_ingress(app, context)
            if not ingress.is_public:
                continue

            paths = [
                path
                for path in app_facts.app_service_service_bus_message_removal_paths
                if _is_current_message_removal_path(path, app, context)
            ]
            if not paths:
                continue

            target_addresses = _path_string_values(paths, "service_bus_resource_address")
            namespace_addresses = _path_string_values(paths, "service_bus_namespace_address")
            topic_addresses = _path_string_values(paths, "topic_address")
            identity_addresses = _path_string_values(paths, "identity_address")
            assignment_addresses = _path_string_values(paths, "role_assignment_address")
            role_definition_addresses = _path_string_values(paths, "role_definition_address")
            has_namespace_scope = any(path.get("assignment_scope_kind") == "namespace" for path in paths)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=1,
                data_sensitivity=1,
                lateral_movement=1,
                blast_radius=2 if has_namespace_scope or len(target_addresses) > 1 else 1,
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
                    rationale=_message_disruption_rationale(
                        app,
                        len(target_addresses),
                    ),
                    evidence=collect_evidence(
                        *ingress.evidence,
                        evidence_item(
                            "runtime_identity",
                            _runtime_identity_evidence(paths),
                        ),
                        evidence_item(
                            "service_bus_message_removal_paths",
                            _message_removal_path_evidence(paths),
                        ),
                        evidence_item(
                            "delivery_and_recovery_evidence",
                            _message_delivery_evidence(paths),
                        ),
                        evidence_item(
                            "custom_role_permissions",
                            _custom_role_permission_evidence(paths),
                        ),
                        evidence_item(
                            "service_bus_message_removal_path_uncertainties",
                            app_facts.app_service_service_bus_message_removal_path_uncertainties,
                        ),
                        evidence_item(
                            "assessment_scope",
                            [
                                (
                                    "establishes=deterministic Service Bus receive-and-settle authority "
                                    "over exact modeled queue or subscription message namespaces"
                                ),
                                (
                                    "delivery_evidence=plan-local Service Bus delivery posture; successful "
                                    "message removal, concrete lock tokens, and immediate restoration are not established"
                                ),
                                (
                                    "does_not_establish=Service Bus network reachability or that the "
                                    "Service Bus target itself is public"
                                ),
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _is_current_message_removal_path(
    path: Mapping[str, Any],
    app: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    if not _message_removal_contract_is_current(path, app):
        return False

    target, namespace, topic = _current_message_target(path, context)
    if target is None or namespace is None:
        return False
    if not _message_runtime_identity_is_current(path, app, context):
        return False
    source_access_path = _current_message_access_path(path, target, namespace, app, context)
    if source_access_path is None:
        return False
    if not _message_role_assignment_is_current(
        path,
        source_access_path,
        target,
        namespace,
        app,
        context,
    ):
        return False
    return _message_delivery_evidence_is_current(path, target, namespace, topic)


def _message_removal_contract_is_current(
    path: Mapping[str, Any],
    app: NormalizedResource,
) -> bool:
    if (
        path.get("workload_address") != app.address
        or path.get("workload_type") != app.resource_type
        or path.get("identity_kind") not in {"system_assigned", "user_assigned"}
        or path.get("credential_context") != "workload_runtime"
        or path.get("operation") != _SERVICE_BUS_MESSAGE_REMOVAL_RULE_OPERATION
        or path.get("operation_class") != "destructive_message_receive"
        or path.get("management_effect") != "disruption"
        or path.get("receive_and_delete_capability") is not True
        or path.get("peek_lock_complete_capability") is not True
        or path.get("runtime_receive_mode_selection") != "not_plan_visible"
        or path.get("complete_lock_token_source") != "runtime_peek_lock_receive"
        or path.get("complete_lock_token_value") is not None
        or path.get("authorization_state") != "granted"
        or path.get("policy_complete") is not True
        or path.get("condition") is not None
        or path.get("condition_state") != "not_configured"
        or path.get("evaluation_basis") != "modeled_rbac_assignment"
        or path.get("grant_basis") not in _SERVICE_BUS_MESSAGE_REMOVAL_GRANT_BASES
        or path.get("assignment_scope_kind") not in {"resource", "namespace"}
        or path.get("lifecycle_compatibility_state") != "not_applicable"
        or path.get("service_bus_auto_forwarding_state") != "not_configured"
        or path.get("service_bus_forward_to") is not None
        or path.get("matched_data_actions") != [_SERVICE_BUS_MESSAGE_REMOVAL_RULE_OPERATION]
    ):
        return False

    target_type = path.get("service_bus_resource_type")
    if target_type not in _SERVICE_BUS_MESSAGE_REMOVAL_TARGET_TYPES:
        return False
    if target_type == AzureResourceType.SERVICE_BUS_QUEUE:
        return (
            path.get("scope_type") == "queue"
            and path.get("target_granularity") == "queue_message_namespace"
            and path.get("target_scope") == "exact_service_bus_queue_message_namespace"
            and path.get("service_bus_entity_kind") == "queue"
            and path.get("queue_address") == path.get("service_bus_resource_address")
            and path.get("topic_address") is None
            and path.get("subscription_address") is None
        )
    return (
        path.get("scope_type") == "subscription"
        and path.get("target_granularity") == "subscription_message_namespace"
        and path.get("target_scope") == "exact_service_bus_subscription_message_namespace"
        and path.get("service_bus_entity_kind") == "subscription"
        and path.get("queue_address") is None
        and _known_string(path.get("topic_address")) is not None
        and path.get("subscription_address") == path.get("service_bus_resource_address")
    )


def _current_message_target(
    path: Mapping[str, Any],
    context: RuleEvaluationContext,
) -> tuple[NormalizedResource | None, NormalizedResource | None, NormalizedResource | None]:
    target_address = _known_string(path.get("service_bus_resource_address"))
    namespace_address = _known_string(path.get("service_bus_namespace_address"))
    target = _resource_by_address(
        context,
        target_address,
        expected_types=tuple(_SERVICE_BUS_MESSAGE_REMOVAL_TARGET_TYPES),
    )
    namespace = _resource_by_address(
        context,
        namespace_address,
        expected_type=AzureResourceType.SERVICE_BUS_NAMESPACE,
    )
    if target is None or namespace is None:
        return None, None, None
    target_facts = azure_facts(target)
    namespace_facts = azure_facts(namespace)
    if (
        path.get("service_bus_resource_type") != target.resource_type
        or not _same_identifier(path.get("service_bus_resource_id"), _service_bus_entity_id(target))
        or not _same_identifier(path.get("service_bus_namespace_id"), namespace_facts.service_bus_namespace_id)
        or target_facts.resolved_service_bus_namespace_address != namespace.address
        or not _message_entity_status_is_current(path, target)
        or target_facts.service_bus_auto_forwarding_state != "not_configured"
        or target_facts.service_bus_forward_to is not None
    ):
        return None, None, None

    topic: NormalizedResource | None = None
    if target.resource_type == AzureResourceType.SERVICE_BUS_QUEUE:
        if path.get("target_model_evidence_addresses") != [namespace.address, target.address]:
            return None, None, None
    else:
        topic = _resource_by_address(
            context,
            path.get("topic_address"),
            expected_type=AzureResourceType.SERVICE_BUS_TOPIC,
        )
        if (
            topic is None
            or target_facts.resolved_service_bus_topic_address != topic.address
            or azure_facts(topic).resolved_service_bus_namespace_address != namespace.address
            or path.get("target_model_evidence_addresses") != [namespace.address, topic.address, target.address]
        ):
            return None, None, None
    return target, namespace, topic


def _service_bus_entity_id(resource: NormalizedResource) -> str | None:
    facts = azure_facts(resource)
    if resource.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE:
        return _known_string(facts.service_bus_namespace_id)
    return _known_string(facts.service_bus_entity_id)


def _message_entity_status_is_current(
    path: Mapping[str, Any],
    target: NormalizedResource,
) -> bool:
    status = _known_string(azure_facts(target).service_bus_entity_status)
    if status is None or not _same_identifier(path.get("service_bus_entity_status"), status):
        return False
    normalized = status.casefold().replace("_", "").replace("-", "").replace(" ", "")
    if target.resource_type == AzureResourceType.SERVICE_BUS_QUEUE:
        return normalized in {"active", "senddisabled"}
    return normalized == "active"


def _message_runtime_identity_is_current(
    path: Mapping[str, Any],
    app: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    identity_address = _known_string(path.get("identity_address"))
    principal_id = _known_string(path.get("principal_id"))
    if identity_address is None or principal_id is None:
        return False
    identity = _resource_by_address(
        context,
        identity_address,
        expected_types=(*AZURE_APP_SERVICE_RESOURCE_TYPES, AzureResourceType.USER_ASSIGNED_IDENTITY),
    )
    if identity is None or not _same_identifier(azure_facts(identity).principal_id, principal_id):
        return False
    app_facts = azure_facts(app)
    if path.get("identity_kind") == "system_assigned":
        return identity.address == app.address and app_facts.has_system_assigned_identity
    if path.get("identity_kind") == "user_assigned":
        return (
            identity.resource_type == AzureResourceType.USER_ASSIGNED_IDENTITY
            and app_facts.has_user_assigned_identity
            and _user_identity_is_attached(app_facts, identity.address)
        )
    return False


def _user_identity_is_attached(facts: Any, address: str) -> bool:
    resolved = facts.resolved_attached_identity_addresses
    references = facts.attached_identity_references
    return address in resolved or any(
        isinstance(reference, str) and (reference == address or reference.startswith(f"{address}."))
        for reference in references
    )


def _current_message_access_path(
    path: Mapping[str, Any],
    target: NormalizedResource,
    namespace: NormalizedResource,
    app: NormalizedResource,
    context: RuleEvaluationContext,
) -> Mapping[str, Any] | None:
    source_target = namespace if path.get("assignment_scope_kind") == "namespace" else target
    source_target_scope = (
        "exact_service_bus_namespace"
        if source_target.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE
        else "exact_service_bus_queue"
        if source_target.resource_type == AzureResourceType.SERVICE_BUS_QUEUE
        else "exact_service_bus_subscription"
        if source_target.resource_type == AzureResourceType.SERVICE_BUS_SUBSCRIPTION
        else "exact_service_bus_topic"
    )
    for source in azure_facts(app).app_service_service_bus_access_paths:
        if (
            source.get("workload_address") != app.address
            or source.get("workload_type") != app.resource_type
            or source.get("identity_address") != path.get("identity_address")
            or source.get("identity_kind") != path.get("identity_kind")
            or source.get("principal_id") != path.get("principal_id")
            or source.get("service_bus_resource_address") != source_target.address
            or source.get("service_bus_resource_type") != source_target.resource_type
            or source.get("service_bus_resource_id") != _service_bus_entity_id(source_target)
            or source.get("resource_scope") != source_target_scope
            or source.get("service_bus_namespace_address") != namespace.address
            or source.get("role_assignment_address") != path.get("role_assignment_address")
            or source.get("role_definition_name") != path.get("role_definition_name")
            or source.get("role_definition_id") != path.get("role_definition_id")
            or source.get("role_definition_address") != path.get("role_definition_address")
            or source.get("role_kind") != path.get("role_kind")
            or source.get("grant_basis") != path.get("grant_basis")
            or source.get("assignment_scope") != path.get("assignment_scope")
            or source.get("condition") is not None
            or source.get("condition_state") != "not_configured"
            or source.get("access_state") != "granted"
            or "receive" not in _string_values(source.get("access_classes"))
            or source.get("custom_role_data_actions") != path.get("custom_role_data_actions")
            or source.get("custom_role_not_data_actions") != path.get("custom_role_not_data_actions")
            or source.get("excluded_data_actions") != path.get("excluded_data_actions")
        ):
            continue
        if path.get("role_kind") == "custom" and _SERVICE_BUS_MESSAGE_REMOVAL_RULE_OPERATION not in {
            action.casefold() for action in _string_values(source.get("matched_data_actions"))
        }:
            continue
        if path.get("role_kind") != "custom" and path.get("role_definition_address") is not None:
            continue
        return source
    return None


def _message_role_assignment_is_current(
    path: Mapping[str, Any],
    source: Mapping[str, Any],
    target: NormalizedResource,
    namespace: NormalizedResource,
    app: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    assignment = _resource_by_address(
        context,
        path.get("role_assignment_address"),
        expected_type=AzureResourceType.ROLE_ASSIGNMENT,
    )
    if assignment is None:
        return False
    assignment_facts = azure_facts(assignment)
    source_target = namespace if path.get("assignment_scope_kind") == "namespace" else target
    if (
        assignment_facts.principal_id != path.get("principal_id")
        or not _same_identifier(assignment_facts.role_assignment_scope, path.get("assignment_scope"))
        or assignment_facts.role_assignment_scope_kind != "resource"
        or assignment_facts.role_assignment_target_resource_address != source_target.address
        or assignment_facts.role_assignment_target_resource_type != source_target.resource_type
        or assignment_facts.role_definition_id != path.get("role_definition_id")
        or assignment_condition_state(assignment) != "not_configured"
        or (path.get("role_kind") != "custom" and not _built_in_service_bus_role_is_current(path, assignment))
    ):
        return False

    role_definition_address = _known_string(path.get("role_definition_address"))
    if path.get("role_kind") == "custom":
        if path.get("custom_role_assignable_scope_compatibility_state") != "compatible":
            return False
        role_definition = _resource_by_address(
            context,
            role_definition_address,
            expected_type=AzureResourceType.ROLE_DEFINITION,
        )
        if role_definition is None:
            return False
        role_facts = azure_facts(role_definition)
        if (
            assignment_facts.resolved_role_definition_address != role_definition.address
            or role_facts.name != path.get("role_definition_name")
            or role_facts.role_definition_data_actions != _string_values(path.get("custom_role_data_actions"))
            or role_facts.role_definition_not_data_actions != _string_values(path.get("custom_role_not_data_actions"))
            or role_facts.role_definition_uncertainties
            or not _custom_role_scope_is_current(role_definition, source_target, context)
        ):
            return False
    elif (
        role_definition_address is not None
        or path.get("custom_role_assignable_scope_compatibility_state") != "not_applicable"
    ):
        return False
    expected_sources = [path.get("role_assignment_address")]
    if role_definition_address is not None:
        expected_sources.append(role_definition_address)
    return _string_values(path.get("authorization_source_addresses")) == expected_sources


def _custom_role_scope_is_current(
    role_definition: NormalizedResource,
    assignment_target: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    role_facts = azure_facts(role_definition)
    if any("assignable_scopes" in uncertainty for uncertainty in role_facts.role_definition_uncertainties):
        return False
    target_id = _resource_arm_id(assignment_target)
    if target_id is None or not role_facts.role_definition_assignable_scopes:
        return False
    for raw_scope in role_facts.role_definition_assignable_scopes:
        if not isinstance(raw_scope, str) or not raw_scope.strip():
            return False
        scope = raw_scope.strip()
        resolved_scope = _current_arm_scope(scope, context)
        if resolved_scope is None:
            return False
        if azure_arm_scope_contains(resolved_scope, target_id):
            return True
    return False


def _current_arm_scope(
    value: str,
    context: RuleEvaluationContext,
) -> str | None:
    if value.startswith("/"):
        return value
    key = azure_reference_key(value)
    matches = [
        _resource_arm_id(resource)
        for resource in context.inventory.resources
        if key in azure_resource_references(resource)
    ]
    resolved = {match for match in matches if match is not None}
    return next(iter(resolved)) if len(resolved) == 1 else None


def _resource_arm_id(resource: NormalizedResource | None) -> str | None:
    if resource is None:
        return None
    facts = azure_facts(resource)
    if resource.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE:
        value = facts.service_bus_namespace_id
    else:
        value = facts.service_bus_entity_id
    return _known_string(value)


def _message_delivery_evidence_is_current(
    path: Mapping[str, Any],
    target: NormalizedResource,
    namespace: NormalizedResource,
    topic: NormalizedResource | None,
) -> bool:
    expected = _current_message_delivery_evidence(target)
    return path.get("delivery_evidence") == expected and path.get("posture_uncertainties") == expected["uncertainties"]


def _current_message_delivery_evidence(
    target: NormalizedResource,
) -> dict[str, object]:
    facts = azure_facts(target)
    uncertainties = dedupe(
        f"{target.address}: {uncertainty}" for uncertainty in facts.service_bus_posture_uncertainties
    )
    return {
        "delivery_evidence_scope": "service_bus_message_delivery_posture",
        "default_message_time_to_live": facts.service_bus_default_message_time_to_live,
        "lock_duration": facts.service_bus_lock_duration,
        "max_delivery_count": facts.service_bus_max_delivery_count,
        "dead_lettering_on_message_expiration": facts.service_bus_dead_lettering_on_message_expiration,
        "removed_message_recovery_state": "not_established_by_modeled_service_bus_delivery_controls",
        "uncertainties": uncertainties,
    }


def _message_removal_path_evidence(
    paths: Sequence[Mapping[str, Any]],
) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"service_bus_resource_address={path.get('service_bus_resource_address')}",
                    f"service_bus_resource_type={path.get('service_bus_resource_type')}",
                    f"service_bus_entity_kind={path.get('service_bus_entity_kind')}",
                    f"service_bus_entity_status={path.get('service_bus_entity_status')}",
                    f"service_bus_auto_forwarding_state={path.get('service_bus_auto_forwarding_state')}",
                    f"service_bus_namespace_address={path.get('service_bus_namespace_address')}",
                    f"queue_address={path.get('queue_address') or 'not_applicable'}",
                    f"topic_address={path.get('topic_address') or 'not_applicable'}",
                    f"subscription_address={path.get('subscription_address') or 'not_applicable'}",
                    f"operation={path.get('operation')}",
                    f"operation_class={path.get('operation_class')}",
                    f"target_granularity={path.get('target_granularity')}",
                    f"target_scope={path.get('target_scope')}",
                    f"role_assignment_address={path.get('role_assignment_address')}",
                    f"role_definition_name={path.get('role_definition_name')}",
                    f"role_kind={path.get('role_kind')}",
                    f"assignment_scope={path.get('assignment_scope') or 'unknown'}",
                    f"assignment_scope_kind={path.get('assignment_scope_kind') or 'unknown'}",
                    f"matched_data_actions={','.join(_string_values(path.get('matched_data_actions')))}",
                    "receive_and_delete_capability=true",
                    "peek_lock_complete_capability=true",
                    "authorization_state=granted",
                )
            )
            for path in paths
        }
    )


def _message_delivery_evidence(
    paths: Sequence[Mapping[str, Any]],
) -> list[str]:
    result: set[str] = set()
    for path in paths:
        delivery = path.get("delivery_evidence")
        if not isinstance(delivery, Mapping):
            continue
        delivery = cast(Mapping[str, object], delivery)
        result.add(
            "; ".join(
                (
                    f"service_bus_resource_address={path.get('service_bus_resource_address')}",
                    f"delivery_evidence_scope={delivery.get('delivery_evidence_scope')}",
                    f"default_message_time_to_live={delivery.get('default_message_time_to_live') or 'unknown'}",
                    f"lock_duration={delivery.get('lock_duration') or 'unknown'}",
                    f"max_delivery_count={delivery.get('max_delivery_count') if delivery.get('max_delivery_count') is not None else 'unknown'}",
                    f"dead_lettering_on_message_expiration={delivery.get('dead_lettering_on_message_expiration') if delivery.get('dead_lettering_on_message_expiration') is not None else 'unknown'}",
                    f"removed_message_recovery_state={delivery.get('removed_message_recovery_state')}",
                    f"uncertainties={','.join(_string_values(delivery.get('uncertainties'))) or 'none'}",
                )
            )
        )
    return sorted(result)


def _message_disruption_rationale(
    app: NormalizedResource,
    target_count: int,
) -> str:
    return (
        f"{app.display_name} permits external ingress within the evidenced scope and its runtime managed identity has deterministic "
        f"Service Bus receive-and-settle authority over {target_count} exact modeled queue or subscription target(s). "
        "A compromise through an allowed public application path could receive messages and complete receive-and-delete "
        "or PeekLock settlement, causing message disruption within the modeled target scopes. Delivery evidence is "
        "plan-local and does not establish successful removal, concrete lock tokens, immediate restoration, or that "
        "the Service Bus target itself is public."
    )


def _is_deterministic_mutation_path(
    path: Mapping[str, Any],
    app: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    return (
        _is_deterministic_service_bus_path(path, app, context)
        and path.get("role_kind") in _MUTATING_ROLE_KINDS
        and bool(_path_mutation_classes(path))
    )


def _is_deterministic_receive_path(
    path: Mapping[str, Any],
    app: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    if (
        not _is_deterministic_service_bus_path(path, app, context)
        or path.get("service_bus_resource_type") not in _SERVICE_BUS_RECEIVE_TARGET_TYPES
        or path.get("role_kind") not in _RECEIVING_ROLE_KINDS
        or _RECEIVE_ACCESS_CLASS not in _string_values(path.get("access_classes"))
    ):
        return False
    if path.get("role_kind") == "custom":
        return _SERVICE_BUS_RECEIVE_DATA_ACTION in _string_values(path.get("matched_data_actions"))
    return True


def _is_deterministic_service_bus_path(
    path: Mapping[str, Any],
    app: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    if (
        path.get("workload_address") != app.address
        or path.get("workload_type") != app.resource_type
        or path.get("identity_kind") not in {"system_assigned", "user_assigned"}
        or path.get("credential_context") != "workload_runtime"
        or path.get("grant_basis") not in _SERVICE_BUS_GRANT_BASES
        or path.get("evaluation_basis") != "modeled_rbac_assignment"
        or path.get("resource_scope") not in _SERVICE_BUS_RESOURCE_SCOPES
        or path.get("assignment_scope_kind") != "resource"
        or path.get("access_state") != "granted"
        or path.get("condition_state") != "not_configured"
        or path.get("condition") is not None
    ):
        return False

    identity_address = _known_string(path.get("identity_address"))
    principal_id = _known_string(path.get("principal_id"))
    target_address = _known_string(path.get("service_bus_resource_address"))
    assignment_address = _known_string(path.get("role_assignment_address"))
    role_name = _known_string(path.get("role_definition_name"))
    if not all((identity_address, principal_id, target_address, assignment_address, role_name)):
        return False

    identity = _resource_by_address(
        context,
        identity_address,
        expected_types=(
            *AZURE_APP_SERVICE_RESOURCE_TYPES,
            AzureResourceType.USER_ASSIGNED_IDENTITY,
        ),
    )
    target = _resource_by_address(
        context,
        target_address,
        expected_types=_SERVICE_BUS_TARGET_TYPES,
    )
    role_assignment = _resource_by_address(
        context,
        assignment_address,
        expected_type=AzureResourceType.ROLE_ASSIGNMENT,
    )
    if identity is None or target is None or role_assignment is None:
        return False
    if assignment_condition_state(role_assignment) != "not_configured":
        return False
    if path.get("role_kind") != "custom" and (
        azure_facts(role_assignment).role_definition_id != path.get("role_definition_id")
        or not _built_in_service_bus_role_is_current(path, role_assignment)
    ):
        return False
    if path.get("identity_kind") == "system_assigned" and identity.address != app.address:
        return False
    if (
        path.get("identity_kind") == "user_assigned"
        and identity.resource_type != AzureResourceType.USER_ASSIGNED_IDENTITY
    ):
        return False
    if path.get("service_bus_resource_type") != target.resource_type:
        return False
    if not _target_relationship_is_exact(path, target, context):
        return False

    role_definition_address = _known_string(path.get("role_definition_address"))
    if (
        role_definition_address is not None
        and _resource_by_address(
            context,
            role_definition_address,
            expected_type=AzureResourceType.ROLE_DEFINITION,
        )
        is None
    ):
        return False
    if path.get("role_kind") == "custom" and (
        role_definition_address is None or not _string_values(path.get("matched_data_actions"))
    ):
        return False
    return True


def _built_in_service_bus_role_is_current(
    path: Mapping[str, Any],
    assignment: NormalizedResource,
) -> bool:
    assignment_facts = azure_facts(assignment)
    role = service_bus_built_in_data_role(
        assignment_facts.role_definition_name,
        assignment_facts.role_definition_id,
    )
    return bool(role is not None and role[0] == path.get("role_definition_name") and role[1] == path.get("role_kind"))


def _target_relationship_is_exact(
    path: Mapping[str, Any],
    target: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    relationship_key_by_type = {
        AzureResourceType.SERVICE_BUS_NAMESPACE: "service_bus_namespace_address",
        AzureResourceType.SERVICE_BUS_QUEUE: "queue_address",
        AzureResourceType.SERVICE_BUS_TOPIC: "topic_address",
        AzureResourceType.SERVICE_BUS_SUBSCRIPTION: "subscription_address",
    }
    relationship_key = relationship_key_by_type.get(target.resource_type)
    if relationship_key is None or path.get(relationship_key) != target.address:
        return False

    namespace_address = _known_string(path.get("service_bus_namespace_address"))
    if (
        namespace_address is None
        or _resource_by_address(
            context,
            namespace_address,
            expected_type=AzureResourceType.SERVICE_BUS_NAMESPACE,
        )
        is None
    ):
        return False

    if target.resource_type == AzureResourceType.SERVICE_BUS_SUBSCRIPTION:
        topic_address = _known_string(path.get("topic_address"))
        if (
            topic_address is None
            or _resource_by_address(
                context,
                topic_address,
                expected_type=AzureResourceType.SERVICE_BUS_TOPIC,
            )
            is None
        ):
            return False
    return True


def _resource_by_address(
    context: RuleEvaluationContext,
    address: object,
    *,
    expected_type: str | None = None,
    expected_types: tuple[str, ...] = (),
) -> NormalizedResource | None:
    if not isinstance(address, str) or not address:
        return None
    resource = context.inventory.get_by_address(address)
    if resource is None:
        return None
    allowed_types = expected_types or ((expected_type,) if expected_type is not None else ())
    if allowed_types and resource.resource_type not in allowed_types:
        return None
    return resource


def _mutation_rationale(
    app: NormalizedResource,
    mutation_classes: list[str],
    target_addresses: list[str],
    *,
    has_receive_access: bool,
) -> str:
    rationale = (
        f"{app.display_name} permits external ingress within the evidenced scope and its runtime managed identity has deterministic "
        f"{', '.join(mutation_classes)} access to {len(target_addresses)} exact modeled Azure Service Bus "
        "target(s). A compromise through an allowed public application path could tamper with messaging by "
        f"{_mutation_impact(mutation_classes)} within the modeled grants. This path does not mean that the "
        "Service Bus target itself is public. The ingress evidence identifies the allowed source and request scope."
    )
    if not has_receive_access:
        rationale += (
            " The mutation paths included in this finding do not establish message receive access; "
            "receiver-only grants do not independently trigger this Tampering rule."
        )
    return rationale


def _mutation_impact(mutation_classes: list[str]) -> str:
    impacts = {
        "send": "injecting messages",
        "administrative": "issuing or revoking namespace user-delegation keys",
    }
    values = [impacts[access_class] for access_class in mutation_classes]
    if len(values) == 1:
        return values[0]
    return " and ".join(values)


def _has_receive_access(paths: Sequence[Mapping[str, Any]]) -> bool:
    return any("receive" in _string_values(path.get("access_classes")) for path in paths)


def _mutation_classes(paths: Sequence[Mapping[str, Any]]) -> list[str]:
    classes = {access_class for path in paths for access_class in _path_mutation_classes(path)}
    return [access_class for access_class in ("send", "administrative") if access_class in classes]


def _path_mutation_classes(path: Mapping[str, Any]) -> list[str]:
    return [
        access_class
        for access_class in _string_values(path.get("access_classes"))
        if access_class in _MUTATION_ACCESS_CLASSES
    ]


def _path_string_values(paths: Sequence[Mapping[str, Any]], key: str) -> list[str]:
    return sorted({value for path in paths if (value := _known_string(path.get(key))) is not None})


def _runtime_identity_evidence(paths: Sequence[Mapping[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"identity_address={path['identity_address']}",
                    f"identity_kind={path['identity_kind']}",
                    f"principal_id={path['principal_id']}",
                    f"role_definition_name={path['role_definition_name']}",
                    f"role_kind={path['role_kind']}",
                    "credential_context=workload_runtime",
                )
            )
            for path in paths
        }
    )


def _mutation_path_evidence(paths: Sequence[Mapping[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"service_bus_resource_address={path['service_bus_resource_address']}",
                    f"service_bus_resource_type={path['service_bus_resource_type']}",
                    f"service_bus_resource_id={path.get('service_bus_resource_id') or 'unknown'}",
                    f"service_bus_entity_kind={path.get('service_bus_entity_kind') or 'unknown'}",
                    f"service_bus_namespace_address={path['service_bus_namespace_address']}",
                    f"queue_address={path.get('queue_address') or 'not_applicable'}",
                    f"topic_address={path.get('topic_address') or 'not_applicable'}",
                    f"subscription_address={path.get('subscription_address') or 'not_applicable'}",
                    f"role_assignment_address={path['role_assignment_address']}",
                    f"role_definition_name={path['role_definition_name']}",
                    f"role_kind={path['role_kind']}",
                    f"mutation_classes={','.join(_path_mutation_classes(path))}",
                    f"access_classes={','.join(_string_values(path.get('access_classes')))}",
                    f"assignment_scope={path.get('assignment_scope') or 'unknown'}",
                    f"resource_scope={path['resource_scope']}",
                    f"grant_basis={path['grant_basis']}",
                    "access_state=granted",
                    "condition_state=not_configured",
                )
            )
            for path in paths
        }
    )


def _receive_path_evidence(paths: Sequence[Mapping[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"service_bus_resource_address={path['service_bus_resource_address']}",
                    f"service_bus_resource_type={path['service_bus_resource_type']}",
                    f"service_bus_resource_id={path.get('service_bus_resource_id') or 'unknown'}",
                    f"service_bus_entity_kind={path.get('service_bus_entity_kind') or 'unknown'}",
                    f"service_bus_namespace_address={path['service_bus_namespace_address']}",
                    f"queue_address={path.get('queue_address') or 'not_applicable'}",
                    f"topic_address={path.get('topic_address') or 'not_applicable'}",
                    f"subscription_address={path.get('subscription_address') or 'not_applicable'}",
                    f"role_assignment_address={path['role_assignment_address']}",
                    f"role_definition_name={path['role_definition_name']}",
                    f"role_kind={path['role_kind']}",
                    f"receive_permission={_SERVICE_BUS_RECEIVE_DATA_ACTION}",
                    f"matched_data_actions={','.join(_string_values(path.get('matched_data_actions'))) or 'built-in-role'}",
                    f"access_classes={','.join(_string_values(path.get('access_classes')))}",
                    f"assignment_scope={path.get('assignment_scope') or 'unknown'}",
                    f"resource_scope={path['resource_scope']}",
                    f"grant_basis={path['grant_basis']}",
                    "access_state=granted",
                    "condition_state=not_configured",
                    "receive_evaluation=unconditional_modeled_rbac_allow_assignment",
                )
            )
            for path in paths
        }
    )


def _custom_role_permission_evidence(paths: Sequence[Mapping[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"role_definition_address={path['role_definition_address']}",
                    f"data_actions={','.join(_string_values(path.get('custom_role_data_actions')))}",
                    f"not_data_actions={','.join(_string_values(path.get('custom_role_not_data_actions'))) or 'none'}",
                    f"matched_data_actions={','.join(_string_values(path.get('matched_data_actions')))}",
                    f"excluded_data_actions={','.join(_string_values(path.get('excluded_data_actions'))) or 'none'}",
                )
            )
            for path in paths
            if path.get("role_kind") == "custom" and path.get("role_definition_address")
        }
    )


def _same_identifier(left: object, right: object) -> bool:
    return (
        isinstance(left, str)
        and isinstance(right, str)
        and left.strip().rstrip("/").casefold() == right.strip().rstrip("/").casefold()
    )


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None
