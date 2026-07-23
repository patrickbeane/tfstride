from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import (
    AZURE_APP_SERVICE_RESOURCE_TYPES,
    AzureResourceType,
)

_MUTATION_ACCESS_CLASSES = frozenset({"send", "administrative"})
_MUTATING_ROLE_KINDS = frozenset(
    {
        "service_bus_data_sender",
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
_SERVICE_BUS_GRANT_BASES = frozenset(
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
            if facts.public_network_access_enabled is not True:
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
                        evidence_item("public_endpoint", _public_endpoint_evidence(app)),
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


def _is_deterministic_mutation_path(
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
        or path.get("role_kind") not in _MUTATING_ROLE_KINDS
        or not _path_mutation_classes(path)
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
        f"{app.display_name} has public network access enabled and its runtime managed identity has deterministic "
        f"{', '.join(mutation_classes)} access to {len(target_addresses)} exact modeled Azure Service Bus "
        "target(s). A compromise through an allowed public application path could tamper with messaging by "
        f"{_mutation_impact(mutation_classes)} within the modeled grants. This path does not mean that the "
        "Service Bus target itself is public; configured App Service access restrictions may still narrow which "
        "clients can reach the endpoint."
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


def _has_receive_access(paths: list[dict[str, Any]]) -> bool:
    return any("receive" in _string_values(path.get("access_classes")) for path in paths)


def _mutation_classes(paths: list[dict[str, Any]]) -> list[str]:
    classes = {access_class for path in paths for access_class in _path_mutation_classes(path)}
    return [access_class for access_class in ("send", "administrative") if access_class in classes]


def _path_mutation_classes(path: Mapping[str, Any]) -> list[str]:
    return [
        access_class
        for access_class in _string_values(path.get("access_classes"))
        if access_class in _MUTATION_ACCESS_CLASSES
    ]


def _path_string_values(paths: list[dict[str, Any]], key: str) -> list[str]:
    return sorted({value for path in paths if (value := _known_string(path.get(key))) is not None})


def _public_endpoint_evidence(app: NormalizedResource) -> list[str]:
    facts = azure_facts(app)
    return [
        f"address={app.address}",
        f"type={app.resource_type}",
        "public_network_access_enabled=true",
        f"public_network_fallback_state={facts.public_network_fallback_state or 'unknown'}",
        f"ip_restriction_default_action={facts.app_service_ip_restriction_default_action or 'not_configured'}",
        f"ip_restriction_count={len(facts.app_service_access_restrictions)}",
    ]


def _runtime_identity_evidence(paths: list[dict[str, Any]]) -> list[str]:
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


def _mutation_path_evidence(paths: list[dict[str, Any]]) -> list[str]:
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


def _custom_role_permission_evidence(paths: list[dict[str, Any]]) -> list[str]:
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


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None
