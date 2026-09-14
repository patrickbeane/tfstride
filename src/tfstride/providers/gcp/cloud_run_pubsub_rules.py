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
from tfstride.models import BoundaryType, Finding, NormalizedResource
from tfstride.providers.gcp.cloud_run_public_invocation import (
    cloud_run_public_exposure_configuration,
    cloud_run_public_invoker_evidence,
    current_cloud_run_public_exposure_reasons,
    current_cloud_run_public_invokers,
)
from tfstride.providers.gcp.custom_role_index import build_gcp_custom_role_index
from tfstride.providers.gcp.iam_reference_utils import custom_role_reference_keys
from tfstride.providers.gcp.resource_decoration.cloud_run_pubsub_message_removal_paths import (
    _delivery_evidence,
    _iam_manager_ambiguities,
    _iam_scope,
    _normalize_project,
    _project_organizations,
    _role_access,
    _role_reconciliation_key,
    _RoleAccess,
    _subscription_reference,
    _topic_reference,
)
from tfstride.providers.gcp.resource_decoration.iam import iam_bindings
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import (
    GcpDecorationContext,
    GcpResourceIndexBuilder,
)
from tfstride.providers.gcp.resource_types import (
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    GCP_CUSTOM_ROLE_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GCP_PUBSUB_SUBSCRIPTION_IAM_RESOURCE_TYPES,
    GCP_PUBSUB_TOPIC_IAM_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.gcp.resource_utils import (
    GCP_ROLE_REFERENCE_SUFFIXES,
    binding_members,
    gcp_reference_key,
)

_MUTATION_ACCESS_CLASSES = frozenset({"publish", "administrative"})
_SUBSCRIPTION_CONSUMER_ROLES = frozenset(
    {
        "roles/pubsub.subscriber",
        "roles/pubsub.editor",
        "roles/pubsub.admin",
    }
)
_BUILT_IN_SUBSCRIPTION_ROLE_KINDS = {
    "roles/pubsub.subscriber": "subscriber",
    "roles/pubsub.editor": "editor",
    "roles/pubsub.admin": "admin",
}
_SUBSCRIPTION_CONSUME_PERMISSION = "pubsub.subscriptions.consume"
_CUSTOM_ROLE_ACK_PERMISSIONS = frozenset(
    {
        "*",
        "pubsub.*",
        "pubsub.subscriptions.*",
        _SUBSCRIPTION_CONSUME_PERMISSION,
    }
)
_MESSAGE_DISRUPTION_OPERATION = _SUBSCRIPTION_CONSUME_PERMISSION
_PUBSUB_TARGET_TYPES = frozenset(
    {
        GcpResourceType.PUBSUB_TOPIC,
        GcpResourceType.PUBSUB_SUBSCRIPTION,
    }
)
_PUBSUB_IAM_RESOURCE_TYPES = GCP_PUBSUB_TOPIC_IAM_RESOURCE_TYPES | GCP_PUBSUB_SUBSCRIPTION_IAM_RESOURCE_TYPES


class GcpCloudRunPubsubAccessRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_cloud_run_pubsub_mutation_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        current_resources = list(context.inventory.resources)
        findings: list[Finding] = []
        for workload in context.inventory.by_type(*GCP_CLOUD_RUN_RESOURCE_TYPES):
            public_invokers = current_cloud_run_public_invokers(
                workload,
                current_resources,
            )
            invoker_iam_check_disabled = gcp_facts(workload).cloud_run_invoker_iam_disabled is True
            if not workload.public_access_configured or (not public_invokers and not invoker_iam_check_disabled):
                continue

            mutation_paths = [
                path
                for path in gcp_facts(workload).cloud_run_pubsub_access_paths
                if _is_deterministic_mutation_path(path, workload, context)
            ]
            if not mutation_paths:
                continue

            target_addresses = _path_string_values(mutation_paths, "messaging_resource_address")
            iam_resource_addresses = _path_string_values(mutation_paths, "iam_resource_address")
            public_source_addresses = sorted({binding["source"] for binding in public_invokers})
            mutation_classes = _mutation_classes(mutation_paths)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=(2 if "administrative" in mutation_classes else 1),
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
                            *iam_resource_addresses,
                        ]
                    ),
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=_mutation_rationale(workload, mutation_classes, target_addresses),
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
                            _runtime_identity_evidence(mutation_paths),
                        ),
                        evidence_item(
                            "pubsub_mutation_paths",
                            _mutation_path_evidence(mutation_paths),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_public_cloud_run_pubsub_consume_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        current_resources = list(context.inventory.resources)
        findings: list[Finding] = []
        for workload in context.inventory.by_type(*GCP_CLOUD_RUN_RESOURCE_TYPES):
            public_invokers = current_cloud_run_public_invokers(
                workload,
                current_resources,
            )
            invoker_iam_check_disabled = gcp_facts(workload).cloud_run_invoker_iam_disabled is True
            if not workload.public_access_configured or (not public_invokers and not invoker_iam_check_disabled):
                continue

            consume_paths = [
                path
                for path in gcp_facts(workload).cloud_run_pubsub_access_paths
                if _is_deterministic_consume_path(path, workload, context)
            ]
            if not consume_paths:
                continue

            subscription_addresses = _path_string_values(consume_paths, "messaging_resource_address")
            iam_resource_addresses = _path_string_values(consume_paths, "iam_resource_address")
            public_source_addresses = sorted({binding["source"] for binding in public_invokers})
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=1,
                data_sensitivity=1,
                lateral_movement=1,
                blast_radius=2 if len(subscription_addresses) > 1 else 1,
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
                            *subscription_addresses,
                            *iam_resource_addresses,
                        ]
                    ),
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{workload.display_name} is publicly invokable and its Cloud Run runtime service account "
                        f"has an unconditional IAM allow grant containing `{_SUBSCRIPTION_CONSUME_PERMISSION}` on "
                        f"{len(subscription_addresses)} exact modeled Pub/Sub subscription(s). A compromise of "
                        "the public workload could attempt message-consumption operations with its runtime identity. "
                        "This establishes a modeled subscription-level allow grant, not guaranteed effective message "
                        "retrieval; IAM deny and principal access boundary policies are independent controls not "
                        "evaluated by this path. The Pub/Sub subscription itself is not public."
                    ),
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
                            _runtime_identity_evidence(consume_paths),
                        ),
                        evidence_item(
                            "pubsub_consume_paths",
                            _consume_path_evidence(consume_paths),
                        ),
                        evidence_item(
                            "assessment_scope",
                            [
                                ("establishes=unconditional IAM allow grant containing pubsub.subscriptions.consume"),
                                (
                                    "does_not_establish=effective access after IAM deny or principal access "
                                    "boundary evaluation"
                                ),
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_public_cloud_run_pubsub_message_disruption(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        current_resources = list(context.inventory.resources)
        findings: list[Finding] = []
        for workload in context.inventory.by_type(*GCP_CLOUD_RUN_RESOURCE_TYPES):
            public_invokers = current_cloud_run_public_invokers(
                workload,
                current_resources,
            )
            invoker_iam_check_disabled = gcp_facts(workload).cloud_run_invoker_iam_disabled is True
            if not workload.public_access_configured or (not public_invokers and not invoker_iam_check_disabled):
                continue

            removal_paths = [
                path
                for path in gcp_facts(workload).cloud_run_pubsub_message_removal_paths
                if _is_current_message_removal_path(path, workload, context)
            ]
            if not removal_paths:
                continue

            subscription_addresses = _path_string_values(removal_paths, "subscription_address")
            iam_source_addresses = sorted(
                {source for path in removal_paths for source in _string_values(path.get("iam_source_addresses"))}
            )
            public_source_addresses = sorted({binding["source"] for binding in public_invokers})
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=1,
                data_sensitivity=1,
                lateral_movement=1,
                blast_radius=2 if len(subscription_addresses) > 1 else 1,
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
                            *subscription_addresses,
                            *iam_source_addresses,
                        ]
                    ),
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=_message_disruption_rationale(workload, subscription_addresses, removal_paths),
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
                            _runtime_identity_evidence(removal_paths),
                        ),
                        evidence_item(
                            "pubsub_message_removal_paths",
                            _message_removal_path_evidence(removal_paths),
                        ),
                        evidence_item(
                            "delivery_and_recovery_evidence",
                            _delivery_and_recovery_evidence(removal_paths),
                        ),
                        evidence_item(
                            "pubsub_message_removal_path_uncertainties",
                            _message_path_uncertainties(
                                removal_paths,
                                gcp_facts(workload).cloud_run_pubsub_message_removal_path_uncertainties,
                            ),
                        ),
                        evidence_item(
                            "assessment_scope",
                            _message_disruption_assessment_scope(),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _is_deterministic_mutation_path(
    path: Mapping[str, Any],
    workload: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    if (
        path.get("workload_address") != workload.address
        or path.get("workload_type") != workload.resource_type
        or path.get("identity_kind") != "cloud_run_service_account"
        or path.get("credential_context") != "workload_runtime"
        or path.get("messaging_service") != "pubsub"
        or path.get("grant_basis") not in {"pubsub_topic_iam", "pubsub_subscription_iam"}
        or path.get("resource_scope") not in {"exact_topic", "exact_subscription"}
        or path.get("access_state") != "granted"
        or path.get("condition_state") != "not_configured"
        or path.get("condition") is not None
        or not _path_mutation_classes(path)
    ):
        return False

    service_account_member = _known_string(path.get("service_account_member"))
    role = _known_string(path.get("role"))
    target_address = _known_string(path.get("messaging_resource_address"))
    iam_resource_address = _known_string(path.get("iam_resource_address"))
    if not all((service_account_member, role, target_address, iam_resource_address)):
        return False

    assert target_address is not None
    assert iam_resource_address is not None
    target = context.inventory.get_by_address(target_address)
    iam_resource = context.inventory.get_by_address(iam_resource_address)
    if (
        target is None
        or target.resource_type not in _PUBSUB_TARGET_TYPES
        or iam_resource is None
        or iam_resource.resource_type not in _PUBSUB_IAM_RESOURCE_TYPES
    ):
        return False

    if path.get("role_kind") == "custom" and not _string_values(path.get("matched_permissions")):
        return False
    return True


def _is_deterministic_consume_path(
    path: Mapping[str, Any],
    workload: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    if (
        path.get("workload_address") != workload.address
        or path.get("workload_type") != workload.resource_type
        or path.get("identity_kind") != "cloud_run_service_account"
        or path.get("credential_context") != "workload_runtime"
        or path.get("messaging_service") != "pubsub"
        or path.get("messaging_resource_kind") != "subscription"
        or path.get("messaging_resource_type") != GcpResourceType.PUBSUB_SUBSCRIPTION
        or path.get("grant_basis") != "pubsub_subscription_iam"
        or path.get("resource_scope") != "exact_subscription"
        or path.get("access_state") != "granted"
        or path.get("condition_state") != "not_configured"
        or path.get("condition") is not None
        or "consume" not in _string_values(path.get("access_classes"))
    ):
        return False

    service_account_member = _known_string(path.get("service_account_member"))
    role = _known_string(path.get("role"))
    target_address = _known_string(path.get("messaging_resource_address"))
    iam_resource_address = _known_string(path.get("iam_resource_address"))
    if not all((service_account_member, role, target_address, iam_resource_address)):
        return False

    assert target_address is not None
    assert iam_resource_address is not None
    target = context.inventory.get_by_address(target_address)
    iam_resource = context.inventory.get_by_address(iam_resource_address)
    if (
        target is None
        or target.resource_type != GcpResourceType.PUBSUB_SUBSCRIPTION
        or iam_resource is None
        or iam_resource.resource_type not in GCP_PUBSUB_SUBSCRIPTION_IAM_RESOURCE_TYPES
    ):
        return False

    if path.get("role_kind") == "custom":
        return _SUBSCRIPTION_CONSUME_PERMISSION in _string_values(path.get("matched_permissions"))
    return role in _SUBSCRIPTION_CONSUMER_ROLES


def _is_current_message_removal_path(
    path: Mapping[str, Any],
    workload: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    if (
        path.get("operation") != _MESSAGE_DISRUPTION_OPERATION
        or path.get("workload_address") != workload.address
        or path.get("workload_type") != workload.resource_type
        or path.get("identity_kind") != "cloud_run_service_account"
        or path.get("credential_context") != "workload_runtime"
        or path.get("operation_class") != "message_acknowledgement"
        or path.get("internal_operation") != "acknowledge_messages"
        or path.get("management_effect") != "disruption"
        or path.get("target_granularity") != "subscription_message_namespace"
        or path.get("target_scope") != "exact_subscription_message_namespace"
        or path.get("resource_scope") not in {"pubsub_project", "exact_pubsub_subscription"}
        or path.get("acknowledgement_id_source") != "runtime_message_delivery"
        or path.get("acknowledgement_id_value") is not None
        or path.get("matched_permissions") != [_MESSAGE_DISRUPTION_OPERATION]
        or path.get("authorization_state") != "granted"
        or path.get("policy_complete") is not True
        or path.get("condition") is not None
        or path.get("condition_state") != "not_configured"
        or path.get("lifecycle_compatibility_state") != "not_applicable"
    ):
        return False

    workload_facts = gcp_facts(workload)
    service_account_email = _known_string(workload_facts.service_account_email)
    service_account_member = _known_string(workload_facts.service_account_member)
    if (
        service_account_email is None
        or service_account_member is None
        or path.get("service_account_email") != service_account_email
        or path.get("service_account_member") != service_account_member
        or service_account_member != f"serviceAccount:{service_account_email}"
    ):
        return False

    topic_address = _known_string(path.get("topic_address"))
    subscription_address = _known_string(path.get("subscription_address"))
    if topic_address is None or subscription_address is None:
        return False
    topic = context.inventory.get_by_address(topic_address)
    subscription = context.inventory.get_by_address(subscription_address)
    if (
        topic is None
        or topic.resource_type != GcpResourceType.PUBSUB_TOPIC
        or subscription is None
        or subscription.resource_type != GcpResourceType.PUBSUB_SUBSCRIPTION
        or path.get("topic_resource_type") != topic.resource_type
        or path.get("subscription_resource_type") != subscription.resource_type
        or path.get("target_model_evidence_addresses") != [topic.address, subscription.address]
    ):
        return False

    topic_facts = gcp_facts(topic)
    subscription_facts = gcp_facts(subscription)
    topic_project = _normalize_project(topic_facts.project)
    subscription_project = _normalize_project(subscription_facts.project)
    expected_topic_name = _known_string(topic_facts.resource_name) or topic.name
    expected_subscription_name = _known_string(subscription_facts.resource_name) or subscription.name
    if (
        topic_project is None
        or subscription_project is None
        or path.get("topic_name") != expected_topic_name
        or path.get("topic_project") != topic_project
        or path.get("topic_reference") != _topic_reference(topic)
        or path.get("subscription_name") != expected_subscription_name
        or path.get("subscription_project") != subscription_project
        or path.get("subscription_reference") != _subscription_reference(subscription)
        or path.get("resource_scope")
        != ("pubsub_project" if path.get("scope_type") == "project" else "exact_pubsub_subscription")
        or subscription_facts.pubsub_subscription_delivery_mode != "pull"
        or not _subscription_targets_topic(subscription_facts.pubsub_topic_reference, topic)
    ):
        return False

    iam_resource_address = _known_string(path.get("iam_resource_address"))
    role = _known_string(path.get("role"))
    source_addresses = path.get("iam_source_addresses")
    if (
        iam_resource_address is None
        or role is None
        or not isinstance(source_addresses, list)
        or not all(isinstance(address, str) and address for address in source_addresses)
    ):
        return False
    iam_resource = context.inventory.get_by_address(iam_resource_address)
    if (
        iam_resource is None
        or iam_resource.resource_type
        not in (GCP_PROJECT_IAM_RESOURCE_TYPES | GCP_PUBSUB_SUBSCRIPTION_IAM_RESOURCE_TYPES)
        or path.get("iam_resource_type") != iam_resource.resource_type
    ):
        return False

    current_resources = list(context.inventory.resources)
    decoration_context = GcpDecorationContext(GcpResourceIndexBuilder().build(current_resources))
    lifecycles = build_gcp_custom_role_index(current_resources)
    project_organizations = _project_organizations(current_resources)
    current_role_access, role_scope_compatibility = _role_access(
        role,
        lifecycles,
        subscription_project,
        project_organizations,
    )
    if current_role_access is None or role_scope_compatibility is not None:
        return False
    iam_scope_type, iam_scope, scope_uncertainty = _iam_scope(
        iam_resource,
        subscription,
        subscription_project,
        decoration_context,
    )
    if scope_uncertainty is not None or iam_scope_type != path.get("scope_type") or iam_scope != path.get("scope"):
        return False
    if path.get("grant_basis") != ("project_iam" if iam_scope_type == "project" else "subscription_iam"):
        return False
    if _current_pubsub_iam_manager_is_ambiguous(
        path,
        subscription,
        subscription_project,
        current_resources,
        decoration_context,
    ):
        return False
    current_binding_source = _current_pubsub_grant_source(
        path,
        iam_resource,
        service_account_member,
    )
    if current_binding_source is None:
        return False
    if not _current_pubsub_role_evidence(
        path,
        current_binding_source,
        current_role_access,
        context,
    ):
        return False

    expected_delivery = _delivery_evidence(topic, subscription)
    actual_delivery = path.get("delivery_evidence")
    return (
        isinstance(actual_delivery, Mapping)
        and dict(actual_delivery) == expected_delivery
        and path.get("posture_uncertainties") == expected_delivery["uncertainties"]
    )


def _subscription_targets_topic(reference: object, topic: NormalizedResource) -> bool:
    value = _known_string(reference)
    if value is None:
        return False
    return gcp_reference_key(value) in {
        gcp_reference_key(topic.address),
        gcp_reference_key(_topic_reference(topic)),
    }


def _current_pubsub_iam_manager_is_ambiguous(
    path: Mapping[str, Any],
    subscription: NormalizedResource,
    subscription_project: str,
    resources: Sequence[NormalizedResource],
    decoration_context: GcpDecorationContext,
) -> bool:
    iam_resources = tuple(
        resource
        for resource in resources
        if resource.resource_type in (GCP_PROJECT_IAM_RESOURCE_TYPES | GCP_PUBSUB_SUBSCRIPTION_IAM_RESOURCE_TYPES)
    )
    lifecycles = build_gcp_custom_role_index(resources)
    ambiguous_scopes, ambiguous_roles, _ = _iam_manager_ambiguities(
        subscription,
        subscription_project,
        iam_resources,
        decoration_context,
        lifecycles,
    )
    role = _known_string(path.get("role"))
    scope_type = path.get("scope_type")
    scope = _known_string(path.get("scope"))
    if role is None or scope_type not in {"project", "subscription"} or scope is None:
        return True
    role_key = _role_reconciliation_key(role, lifecycles)
    return (scope_type, scope) in ambiguous_scopes or (scope_type, scope, role_key) in ambiguous_roles


def _current_pubsub_grant_source(
    path: Mapping[str, Any],
    iam_resource: NormalizedResource,
    service_account_member: str,
) -> str | None:
    source_addresses = path.get("iam_source_addresses")
    if not isinstance(source_addresses, list) or not source_addresses:
        return None
    expected_source = source_addresses[0]
    source_facts = gcp_facts(iam_resource)
    if source_facts.iam_policy_data_state in {"unknown", "invalid", "not_configured"}:
        return None
    for binding in iam_bindings(iam_resource):
        source = _known_string(binding.get("source")) or iam_resource.address
        if (
            source != expected_source
            or _known_string(binding.get("role")) != _known_string(path.get("role"))
            or service_account_member not in binding_members(binding)
            or binding.get("role_state") == "unknown"
            or binding.get("members_state") == "unknown"
            or binding.get("condition") is not None
            or binding.get("condition_state") not in {None, "not_configured"}
        ):
            continue
        return source
    return None


def _current_pubsub_role_evidence(
    path: Mapping[str, Any],
    current_binding_source: str,
    current_role_access: _RoleAccess,
    context: RuleEvaluationContext,
) -> bool:
    role_kind = _known_string(path.get("role_kind"))
    role = _known_string(path.get("role"))
    source_addresses = path.get("iam_source_addresses")
    if (
        role is None
        or role_kind is None
        or not isinstance(source_addresses, list)
        or not all(isinstance(address, str) for address in source_addresses)
        or not source_addresses
        or source_addresses[0] != current_binding_source
    ):
        return False

    if (
        role_kind != current_role_access.role_kind
        or path.get("role_definition_address") != current_role_access.role_definition_address
        or path.get("custom_role_permissions") != list(current_role_access.custom_role_permissions)
        or path.get("custom_role_stage") != current_role_access.custom_role_stage
        or path.get("custom_role_deleted") != current_role_access.custom_role_deleted
        or path.get("custom_role_grant_scope_compatibility_state")
        != current_role_access.custom_role_grant_scope_compatibility_state
    ):
        return False

    if role_kind != "custom":
        return (
            _BUILT_IN_SUBSCRIPTION_ROLE_KINDS.get(role) == role_kind
            and len(source_addresses) == 1
            and path.get("role_definition_address") is None
            and path.get("custom_role_permissions") == []
            and path.get("custom_role_stage") is None
            and path.get("custom_role_deleted") is None
            and path.get("custom_role_grant_scope_compatibility_state") == "not_applicable"
        )

    if len(source_addresses) != 2 or path.get("role_definition_address") != source_addresses[1]:
        return False
    role_definition = context.inventory.get_by_address(source_addresses[1])
    if (
        role_definition is None
        or role_definition.resource_type not in GCP_CUSTOM_ROLE_RESOURCE_TYPES
        or gcp_reference_key(role, GCP_ROLE_REFERENCE_SUFFIXES) not in custom_role_reference_keys(role_definition)
    ):
        return False
    role_facts = gcp_facts(role_definition)
    stage = role_facts.custom_role_stage
    return (
        role_facts.custom_role_deleted is False
        and stage is not None
        and stage.upper() in {"ALPHA", "BETA", "DEPRECATED", "EAP", "GA"}
        and role_facts.custom_role_permissions_state == "configured"
        and path.get("custom_role_stage") == stage.upper()
        and path.get("custom_role_deleted") is False
        and path.get("custom_role_permissions") == sorted(set(role_facts.custom_role_permissions))
        and any(
            permission.strip().casefold() in _CUSTOM_ROLE_ACK_PERMISSIONS
            for permission in role_facts.custom_role_permissions
        )
        and path.get("custom_role_grant_scope_compatibility_state") == "compatible"
    )


def _message_disruption_rationale(
    workload: NormalizedResource,
    subscription_addresses: Sequence[str],
    paths: Sequence[Mapping[str, Any]],
) -> str:
    rationale = (
        f"{workload.display_name} is publicly invokable and its Cloud Run runtime service account has "
        f"deterministic Pub/Sub acknowledgement authority across {len(subscription_addresses)} exact modeled "
        "pull subscription message namespace(s). A compromise of the public workload could acknowledge "
        "delivered messages and remove them from normal unacknowledged delivery within the modeled grants. "
    )
    replay_states: set[object] = set()
    for path in paths:
        delivery_value = path.get("delivery_evidence")
        if isinstance(delivery_value, Mapping):
            delivery = cast(Mapping[str, object], delivery_value)
            replay_states.add(delivery.get("acknowledged_message_replay_state"))
    if "unknown" in replay_states:
        rationale += "Replay posture is partly unknown, so recovery impact cannot be characterized completely. "
    elif replay_states == {"not_established"}:
        rationale += "The modeled delivery controls do not establish replay of acknowledged messages. "
    else:
        rationale += "The delivery evidence records modeled replay-retention posture without proving restoration. "
    return rationale + (
        "This finding does not establish a concrete acknowledgement ID, successful acknowledgement, message "
        "payload access, successful replay, or successful recovery. The Pub/Sub topic or subscription itself "
        "is not public."
    )


def _message_removal_path_evidence(paths: Sequence[Mapping[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"topic_address={path.get('topic_address')}",
                    f"subscription_address={path.get('subscription_address')}",
                    f"operation={path.get('operation')}",
                    f"operation_class={path.get('operation_class')}",
                    f"internal_operation={path.get('internal_operation')}",
                    f"target_granularity={path.get('target_granularity')}",
                    f"target_scope={path.get('target_scope')}",
                    f"scope_type={path.get('scope_type')}",
                    f"scope={path.get('scope')}",
                    f"iam_resource={path.get('iam_resource_address')}",
                    f"iam_sources={','.join(_string_values(path.get('iam_source_addresses'))) or 'none'}",
                    f"role={path.get('role')}",
                    f"role_kind={path.get('role_kind')}",
                    f"matched_permissions={','.join(_string_values(path.get('matched_permissions')))}",
                    "authorization_state=granted",
                    "condition_state=not_configured",
                )
            )
            for path in paths
        }
    )


def _delivery_and_recovery_evidence(paths: Sequence[Mapping[str, Any]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        delivery_value = path.get("delivery_evidence")
        if not isinstance(delivery_value, Mapping):
            continue
        delivery = cast(Mapping[str, object], delivery_value)
        values.add(
            "; ".join(
                (
                    f"topic_address={path.get('topic_address')}",
                    f"subscription_address={path.get('subscription_address')}",
                    f"subscription_message_retention_state={delivery.get('subscription_message_retention_state')}",
                    f"subscription_message_retention_seconds={_display_value(delivery.get('subscription_message_retention_seconds'))}",
                    f"subscription_retain_acked_messages={_display_value(delivery.get('subscription_retain_acked_messages'))}",
                    f"topic_message_retention_state={delivery.get('topic_message_retention_state')}",
                    f"topic_message_retention_seconds={_display_value(delivery.get('topic_message_retention_seconds'))}",
                    f"acknowledged_message_replay_state={delivery.get('acknowledged_message_replay_state')}",
                    f"dead_letter_policy_state={delivery.get('dead_letter_policy_state')}",
                    f"dead_letter_max_delivery_attempts={_display_value(delivery.get('dead_letter_max_delivery_attempts'))}",
                    f"uncertainties={','.join(_string_values(delivery.get('uncertainties'))) or 'none'}",
                    "successful_acknowledgement_not_established=true",
                    "successful_recovery_not_established=true",
                )
            )
        )
    return sorted(values)


def _message_path_uncertainties(
    paths: Sequence[Mapping[str, Any]],
    aggregate_uncertainties: Sequence[str],
) -> list[str]:
    return sorted(
        {
            uncertainty
            for uncertainty in (
                *aggregate_uncertainties,
                *(uncertainty for path in paths for uncertainty in _string_values(path.get("posture_uncertainties"))),
            )
            if uncertainty
        }
    )


def _message_disruption_assessment_scope() -> list[str]:
    return [
        (
            "establishes=deterministic pubsub.subscriptions.consume acknowledgement authority over exact "
            "modeled pull subscription message namespaces with Denial of Service effect"
        ),
        (
            "does_not_establish=a concrete acknowledgement ID, message payload access, successful acknowledgement, "
            "successful replay, or successful recovery"
        ),
    ]


def _display_value(value: object) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)


def _mutation_rationale(
    workload: NormalizedResource,
    mutation_classes: list[str],
    target_addresses: list[str],
) -> str:
    rationale = (
        f"{workload.display_name} is publicly invokable and its Cloud Run runtime service account has "
        f"deterministic {', '.join(mutation_classes)} access to {len(target_addresses)} exact modeled "
        f"Pub/Sub target(s). A compromise of the public workload could {_mutation_impact(mutation_classes)} "
        "within the modeled grants."
    )
    if "administrative" in mutation_classes:
        rationale += (
            " Some administrative operations require companion permissions that this path does not claim are present."
        )
    return rationale + " This path does not mean that the Pub/Sub topic or subscription itself is public."


def _mutation_impact(mutation_classes: list[str]) -> str:
    impacts = {
        "publish": "inject messages into a topic",
        "delete": "delete Pub/Sub topics or subscriptions",
        "administrative": "exercise administrative Pub/Sub permissions",
    }
    values = [impacts[access_class] for access_class in mutation_classes]
    if len(values) == 1:
        return values[0]
    return " or ".join(values)


def _mutation_classes(paths: list[dict[str, Any]]) -> list[str]:
    classes = {access_class for path in paths for access_class in _path_mutation_classes(path)}
    return [access_class for access_class in ("publish", "administrative") if access_class in classes]


def _path_mutation_classes(path: Mapping[str, Any]) -> list[str]:
    return [
        access_class
        for access_class in _string_values(path.get("access_classes"))
        if access_class in _MUTATION_ACCESS_CLASSES
    ]


def _mutation_matched_permissions(path: Mapping[str, Any]) -> list[str]:
    return [
        permission
        for permission in _string_values(path.get("matched_permissions"))
        if permission.casefold() not in {"pubsub.topics.delete", "pubsub.subscriptions.delete"}
    ]


def _path_string_values(paths: Sequence[Mapping[str, Any]], key: str) -> list[str]:
    return sorted({value for path in paths if (value := _known_string(path.get(key))) is not None})


def _runtime_identity_evidence(paths: Sequence[Mapping[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"service_account={path.get('service_account_email') or 'unknown'}",
                    f"member={path['service_account_member']}",
                    f"role={path['role']}",
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
                    f"target_address={path['messaging_resource_address']}",
                    f"target_kind={path['messaging_resource_kind']}",
                    f"target_name={path.get('messaging_resource_name') or 'unknown'}",
                    f"iam_resource={path['iam_resource_address']}",
                    f"role={path['role']}",
                    f"role_kind={path['role_kind']}",
                    f"mutation_classes={','.join(_path_mutation_classes(path))}",
                    f"access_classes={','.join(_path_mutation_classes(path))}",
                    f"matched_permissions={','.join(_mutation_matched_permissions(path)) or 'built-in-role'}",
                    f"resource_scope={path['resource_scope']}",
                    "access_state=granted",
                    "condition_state=not_configured",
                )
            )
            for path in paths
        }
    )


def _consume_path_evidence(paths: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"subscription_address={path['messaging_resource_address']}",
                    f"subscription_name={path.get('messaging_resource_name') or 'unknown'}",
                    f"iam_resource={path['iam_resource_address']}",
                    f"role={path['role']}",
                    f"role_kind={path['role_kind']}",
                    f"permission={_SUBSCRIPTION_CONSUME_PERMISSION}",
                    f"matched_permissions={','.join(_string_values(path.get('matched_permissions'))) or 'built-in-role'}",
                    "resource_scope=exact_subscription",
                    "access_state=granted",
                    "condition_state=not_configured",
                )
            )
            for path in paths
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
