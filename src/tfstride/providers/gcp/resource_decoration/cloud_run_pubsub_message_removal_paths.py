from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, cast

from tfstride.models import NormalizedResource
from tfstride.providers.coercion import (
    STATE_CONFIGURED,
    STATE_NOT_CONFIGURED,
    STATE_UNKNOWN,
    dedupe,
)
from tfstride.providers.gcp.iam_reference_utils import custom_role_reference_keys
from tfstride.providers.gcp.message_removal_evidence import (
    GcpCloudRunPubsubMessageRemovalPath,
    GcpPubsubAcknowledgedMessageReplayState,
    GcpPubsubMessageRemovalDeliveryEvidence,
)
from tfstride.providers.gcp.resource_decoration.iam import iam_bindings
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext
from tfstride.providers.gcp.resource_types import (
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GCP_PUBSUB_SUBSCRIPTION_IAM_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.gcp.resource_utils import (
    GCP_ROLE_REFERENCE_SUFFIXES,
    binding_members,
    gcp_reference_key,
)

_ACKNOWLEDGE = "pubsub.subscriptions.consume"
_ACTIVE_CUSTOM_ROLE_STAGES = frozenset({"ALPHA", "BETA", "DEPRECATED", "EAP", "GA"})
_BUILT_IN_SUBSCRIPTION_ROLES: dict[str, str] = {
    "roles/pubsub.subscriber": "subscriber",
    "roles/pubsub.editor": "editor",
    "roles/pubsub.admin": "admin",
}
_CUSTOM_ROLE_ACK_PERMISSIONS = frozenset(
    {
        "*",
        "pubsub.*",
        "pubsub.subscriptions.*",
        _ACKNOWLEDGE,
    }
)


@dataclass(frozen=True, slots=True)
class _CustomRoleLifecycle:
    resource_address: str
    project: str | None
    organization_id: str | None
    stage: str | None
    deleted: bool | None
    permissions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _RoleAccess:
    role_kind: str
    custom_role_permissions: tuple[str, ...]
    role_definition_address: str | None
    custom_role_stage: str | None
    custom_role_deleted: Literal[False] | None
    custom_role_grant_scope_compatibility_state: Literal["compatible", "not_applicable"]


@dataclass(frozen=True, slots=True)
class _IamManager:
    source_address: str
    scope_type: Literal["project", "subscription"]
    scope: str
    management_mode: Literal["authoritative_policy", "authoritative_role_binding", "additive_member"]
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _UnresolvedIamManager:
    source_address: str
    scope_type: Literal["project", "subscription"]
    scope: str
    management_mode: Literal["authoritative_policy", "authoritative_role_binding", "additive_member"]
    roles: tuple[str, ...]


class ModelCloudRunPubsubMessageRemovalPathsStage:
    """Project deterministic Pub/Sub acknowledgement authority onto subscriptions."""

    name = "model_cloud_run_pubsub_message_removal_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: GcpDecorationContext,
    ) -> None:
        custom_role_lifecycles = _custom_role_lifecycles_by_reference(resources)
        project_organizations = _project_organizations(resources)
        subscriptions = tuple(
            resource for resource in resources if resource.resource_type == GcpResourceType.PUBSUB_SUBSCRIPTION
        )
        iam_resources = tuple(
            resource
            for resource in resources
            if resource.resource_type in (GCP_PROJECT_IAM_RESOURCE_TYPES | GCP_PUBSUB_SUBSCRIPTION_IAM_RESOURCE_TYPES)
        )
        for workload in resources:
            if workload.resource_type not in GCP_CLOUD_RUN_RESOURCE_TYPES:
                continue
            paths, uncertainties = _cloud_run_pubsub_message_removal_paths(
                workload,
                subscriptions,
                iam_resources,
                context,
                custom_role_lifecycles,
                project_organizations,
            )
            facts = gcp_facts(workload)
            facts.set_cloud_run_pubsub_message_removal_paths(paths)
            facts.extend_cloud_run_pubsub_message_removal_path_uncertainties(uncertainties)


def _cloud_run_pubsub_message_removal_paths(
    workload: NormalizedResource,
    subscriptions: Sequence[NormalizedResource],
    iam_resources: Sequence[NormalizedResource],
    context: GcpDecorationContext,
    custom_role_lifecycles: Mapping[str, _CustomRoleLifecycle],
    project_organizations: Mapping[str, str],
) -> tuple[list[GcpCloudRunPubsubMessageRemovalPath], list[str]]:
    workload_facts = gcp_facts(workload)
    service_account_email = _known_string(workload_facts.service_account_email)
    service_account_member = _known_string(workload_facts.service_account_member)
    if service_account_email is None or service_account_member is None:
        return [], [f"{workload.address}: Cloud Run service account is unresolved for Pub/Sub acknowledgement modeling"]

    paths: list[GcpCloudRunPubsubMessageRemovalPath] = []
    uncertainties: list[str] = []
    seen: set[tuple[str, str, str, str, str, str]] = set()
    for subscription in subscriptions:
        subscription_facts = gcp_facts(subscription)
        delivery_mode = subscription_facts.pubsub_subscription_delivery_mode
        if delivery_mode == STATE_UNKNOWN or delivery_mode is None:
            uncertainties.append(
                f"{workload.address}: Pub/Sub subscription {subscription.address} delivery mode is unresolved"
            )
            continue
        if delivery_mode != "pull":
            continue
        topic = _subscription_topic(subscription, context)
        if topic is None:
            uncertainties.append(
                f"{workload.address}: Pub/Sub subscription {subscription.address} has unresolved topic ancestry"
            )
            continue
        subscription_project = _normalize_project(subscription_facts.project)
        topic_project = _normalize_project(gcp_facts(topic).project)
        if subscription_project is None or topic_project is None:
            uncertainties.append(
                f"{workload.address}: Pub/Sub subscription {subscription.address} has unresolved project ancestry"
            )
            continue

        ambiguous_scopes, ambiguous_roles, manager_uncertainties = _iam_manager_ambiguities(
            subscription,
            subscription_project,
            iam_resources,
            context,
            custom_role_lifecycles,
        )
        uncertainties.extend(
            f"{workload.address}: {message} for {subscription.address}" for message in manager_uncertainties
        )

        for iam_resource in iam_resources:
            scope_type, scope, scope_uncertainty = _iam_scope(
                iam_resource,
                subscription,
                subscription_project,
                context,
            )
            if scope_type is None or scope is None:
                if scope_uncertainty is not None:
                    for binding in iam_bindings(iam_resource):
                        if _binding_member_applies(binding, service_account_member):
                            uncertainties.append(
                                f"{workload.address}: {iam_resource.address} Pub/Sub IAM scope is unresolved "
                                f"for {subscription.address}"
                            )
                continue
            source_facts = gcp_facts(iam_resource)
            policy_state = source_facts.iam_policy_data_state
            if policy_state in {"unknown", "invalid", "not_configured"}:
                uncertainties.append(
                    f"{workload.address}: {iam_resource.address} IAM policy_data is {policy_state} "
                    f"for {subscription.address}"
                )
                continue
            bindings = iam_bindings(iam_resource)
            if not bindings:
                continue
            for binding in bindings:
                source = _known_string(binding.get("source")) or iam_resource.address
                if binding.get("role_state") == "unknown" or binding.get("members_state") == "unknown":
                    uncertainties.append(f"{workload.address}: {source} Pub/Sub IAM role or members are unresolved")
                    continue
                if not _binding_member_applies(binding, service_account_member):
                    continue
                role = _known_string(binding.get("role"))
                if role is None:
                    uncertainties.append(f"{workload.address}: {source} Pub/Sub IAM role is unresolved")
                    continue
                condition = _condition(binding.get("condition"))
                condition_state = _known_string(binding.get("condition_state"))
                if condition is not None or condition_state not in {None, "not_configured"}:
                    uncertainties.append(
                        f"{workload.address}: {source} Pub/Sub acknowledgement condition is not deterministic"
                    )
                    continue
                role_access, compatibility_state = _role_access(
                    role,
                    custom_role_lifecycles,
                    subscription_project,
                    project_organizations,
                )
                if role_access is None:
                    if compatibility_state == "incompatible":
                        uncertainties.append(
                            f"{workload.address}: {source} custom IAM role {role} is not grantable "
                            f"in consumer project {subscription_project}"
                        )
                    elif compatibility_state == "unknown":
                        uncertainties.append(
                            f"{workload.address}: {source} custom IAM role {role} grant scope "
                            f"compatibility is unresolved for consumer project {subscription_project}"
                        )
                    elif _looks_like_custom_role(role):
                        uncertainties.append(
                            f"{workload.address}: {source} custom IAM role {role} does not resolve to "
                            "an active Pub/Sub acknowledgement permission"
                        )
                    continue
                role_key = _role_reconciliation_key(role, custom_role_lifecycles)
                if (scope_type, scope) in ambiguous_scopes or (scope_type, scope, role_key) in ambiguous_roles:
                    continue
                fingerprint = (
                    subscription.address,
                    source,
                    role,
                    scope_type,
                    scope,
                    json.dumps(condition, sort_keys=True, default=str),
                )
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                paths.append(
                    _acknowledgement_path(
                        workload,
                        topic,
                        subscription,
                        service_account_email,
                        service_account_member,
                        iam_resource,
                        source,
                        role,
                        role_access,
                        scope_type,
                        scope,
                    )
                )

    paths.sort(
        key=lambda path: (
            path["subscription_address"],
            path["scope_type"],
            path["iam_resource_address"],
            path["role"],
        )
    )
    return paths, dedupe(uncertainties)


def _subscription_topic(
    subscription: NormalizedResource,
    context: GcpDecorationContext,
) -> NormalizedResource | None:
    reference = _known_string(gcp_facts(subscription).pubsub_topic_reference)
    if reference is None:
        return None
    return context.index.resources_by_reference.get(
        gcp_reference_key(reference),
        source=subscription,
        resource_types={GcpResourceType.PUBSUB_TOPIC},
    )


def _iam_manager_ambiguities(
    subscription: NormalizedResource,
    project: str,
    iam_resources: Sequence[NormalizedResource],
    context: GcpDecorationContext,
    custom_role_lifecycles: Mapping[str, _CustomRoleLifecycle],
) -> tuple[
    set[tuple[Literal["project", "subscription"], str]],
    set[tuple[Literal["project", "subscription"], str, str]],
    list[str],
]:
    managers: list[_IamManager] = []
    unresolved_managers: list[_UnresolvedIamManager] = []
    for iam_resource in iam_resources:
        scope_type, scope, scope_uncertainty = _iam_scope(
            iam_resource,
            subscription,
            project,
            context,
        )
        management_mode = _management_mode(iam_resource)
        bindings = iam_bindings(iam_resource)
        roles = _manager_role_keys(bindings, custom_role_lifecycles)
        if scope_type is None or scope is None:
            potential_scope = _potential_unresolved_manager_scope(
                iam_resource,
                subscription,
                project,
                scope_uncertainty,
            )
            if potential_scope is not None and management_mode != "additive_member":
                unresolved_managers.append(
                    _UnresolvedIamManager(
                        iam_resource.address,
                        potential_scope[0],
                        potential_scope[1],
                        management_mode,
                        roles,
                    )
                )
            continue

        managers.append(
            _IamManager(
                source_address=iam_resource.address,
                scope_type=scope_type,
                scope=scope,
                management_mode=management_mode,
                roles=roles,
            )
        )
        if management_mode != "additive_member" and _manager_has_unresolved_role(bindings):
            unresolved_managers.append(
                _UnresolvedIamManager(
                    iam_resource.address,
                    scope_type,
                    scope,
                    management_mode,
                    roles,
                )
            )

    ambiguous_scopes: set[tuple[Literal["project", "subscription"], str]] = set()
    ambiguous_roles: set[tuple[Literal["project", "subscription"], str, str]] = set()
    uncertainties: list[str] = []
    scope_keys: set[tuple[Literal["project", "subscription"], str]] = {
        (manager.scope_type, manager.scope) for manager in managers
    }
    for scope_type, scope in sorted(scope_keys):
        scoped = [manager for manager in managers if manager.scope_type == scope_type and manager.scope == scope]
        policy_sources = {
            manager.source_address for manager in scoped if manager.management_mode == "authoritative_policy"
        }
        other_sources = {
            manager.source_address for manager in scoped if manager.management_mode != "authoritative_policy"
        }
        if len(policy_sources) > 1 or (policy_sources and other_sources):
            ambiguous_scopes.add((scope_type, scope))
            uncertainties.append(
                f"effective Pub/Sub IAM at {scope_type} scope {scope} is ambiguous because "
                "authoritative policy and other Terraform IAM managers overlap"
            )
            continue

        roles_at_scope = sorted({role for manager in scoped for role in manager.roles})
        for role in roles_at_scope:
            binding_sources = {
                manager.source_address
                for manager in scoped
                if manager.management_mode == "authoritative_role_binding" and role in manager.roles
            }
            member_sources = {
                manager.source_address
                for manager in scoped
                if manager.management_mode == "additive_member" and role in manager.roles
            }
            if len(binding_sources) > 1 or (binding_sources and member_sources):
                ambiguous_roles.add((scope_type, scope, role))
                uncertainties.append(
                    f"effective Pub/Sub IAM membership for role {role} at {scope_type} scope {scope} "
                    "is ambiguous because authoritative role bindings overlap with another Terraform IAM manager"
                )

    for manager in unresolved_managers:
        if manager.management_mode == "authoritative_policy" or not manager.roles:
            ambiguous_scopes.add((manager.scope_type, manager.scope))
            uncertainties.append(
                f"effective Pub/Sub IAM at {manager.scope_type} scope {manager.scope} is unresolved "
                f"because {manager.source_address} may be an overlapping authoritative IAM manager"
            )
            continue
        for role in manager.roles:
            ambiguous_roles.add((manager.scope_type, manager.scope, role))
            uncertainties.append(
                f"effective Pub/Sub IAM membership for role {role} at {manager.scope_type} scope "
                f"{manager.scope} is unresolved because {manager.source_address} may be an overlapping "
                "authoritative IAM manager"
            )

    return ambiguous_scopes, ambiguous_roles, uncertainties


def _manager_role_keys(
    bindings: Sequence[Mapping[str, Any]],
    custom_role_lifecycles: Mapping[str, _CustomRoleLifecycle],
) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                _role_reconciliation_key(role, custom_role_lifecycles)
                for binding in bindings
                if binding.get("role_state") != "unknown" and (role := _known_string(binding.get("role"))) is not None
            }
        )
    )


def _manager_has_unresolved_role(bindings: Sequence[Mapping[str, Any]]) -> bool:
    return any(
        binding.get("role_state") == "unknown" or _known_string(binding.get("role")) is None for binding in bindings
    )


def _potential_unresolved_manager_scope(
    iam_resource: NormalizedResource,
    subscription: NormalizedResource,
    project: str,
    scope_uncertainty: str | None,
) -> tuple[Literal["project", "subscription"], str] | None:
    if scope_uncertainty is None:
        return None
    if iam_resource.resource_type in GCP_PROJECT_IAM_RESOURCE_TYPES:
        return "project", project
    if iam_resource.resource_type in GCP_PUBSUB_SUBSCRIPTION_IAM_RESOURCE_TYPES:
        return "subscription", _subscription_reference(subscription)
    return None


def _role_reconciliation_key(
    role: str,
    custom_role_lifecycles: Mapping[str, _CustomRoleLifecycle],
) -> str:
    normalized = gcp_reference_key(role, GCP_ROLE_REFERENCE_SUFFIXES)
    lifecycle = custom_role_lifecycles.get(normalized)
    if lifecycle is not None:
        return f"custom:{lifecycle.resource_address}"
    return f"role:{normalized}"


def _management_mode(
    resource: NormalizedResource,
) -> Literal["authoritative_policy", "authoritative_role_binding", "additive_member"]:
    if resource.resource_type.endswith("_iam_policy"):
        return "authoritative_policy"
    if resource.resource_type.endswith("_iam_binding"):
        return "authoritative_role_binding"
    return "additive_member"


def _iam_scope(
    iam_resource: NormalizedResource,
    subscription: NormalizedResource,
    project: str,
    context: GcpDecorationContext,
) -> tuple[Literal["project", "subscription"] | None, str | None, str | None]:
    facts = gcp_facts(iam_resource)
    scope_state = facts.iam_scope_reference_state
    if scope_state in {"unknown", "not_configured"}:
        return None, None, "scope reference is unresolved"
    if iam_resource.resource_type in GCP_PROJECT_IAM_RESOURCE_TYPES:
        if _normalize_project(facts.project) != project:
            return None, None, None
        return "project", project, None
    if iam_resource.resource_type not in GCP_PUBSUB_SUBSCRIPTION_IAM_RESOURCE_TYPES:
        return None, None, None
    target_reference = _known_string(facts.target_reference)
    if target_reference is None:
        return None, None, "subscription target is unresolved"
    target = context.index.resources_by_reference.get(
        gcp_reference_key(target_reference),
        source=iam_resource,
        resource_types={GcpResourceType.PUBSUB_SUBSCRIPTION},
    )
    if target is None:
        return None, None, "subscription target is unresolved"
    if target.address != subscription.address:
        return None, None, None
    return "subscription", _subscription_reference(subscription), None


def _binding_member_applies(binding: Mapping[str, Any], member: str) -> bool:
    return member in binding_members(binding)


def _role_access(
    role: str,
    lifecycles: Mapping[str, _CustomRoleLifecycle],
    consumer_project: str,
    project_organizations: Mapping[str, str],
) -> tuple[_RoleAccess | None, Literal["incompatible", "unknown"] | None]:
    built_in_kind = _BUILT_IN_SUBSCRIPTION_ROLES.get(role)
    if built_in_kind is not None:
        return _RoleAccess(built_in_kind, (), None, None, None, "not_applicable"), None
    if not _looks_like_custom_role(role):
        return None, None
    lifecycle = lifecycles.get(gcp_reference_key(role, GCP_ROLE_REFERENCE_SUFFIXES))
    if lifecycle is None or lifecycle.deleted is not False or lifecycle.stage is None:
        return None, None
    stage = lifecycle.stage.upper()
    if stage not in _ACTIVE_CUSTOM_ROLE_STAGES:
        return None, None
    permissions = lifecycle.permissions
    if not any(permission.strip().casefold() in _CUSTOM_ROLE_ACK_PERMISSIONS for permission in permissions):
        return None, None
    compatibility = _custom_role_grant_scope_compatibility(
        lifecycle,
        consumer_project,
        project_organizations,
    )
    if compatibility != "compatible":
        return None, compatibility
    return (
        _RoleAccess(
            "custom",
            permissions,
            lifecycle.resource_address,
            stage,
            False,
            "compatible",
        ),
        None,
    )


def _custom_role_grant_scope_compatibility(
    lifecycle: _CustomRoleLifecycle,
    consumer_project: str,
    project_organizations: Mapping[str, str],
) -> Literal["compatible", "incompatible", "unknown"]:
    if lifecycle.project is not None:
        return "compatible" if lifecycle.project == consumer_project else "incompatible"
    if lifecycle.organization_id is None:
        return "unknown"
    consumer_organization = project_organizations.get(consumer_project)
    if consumer_organization is None:
        return "unknown"
    return "compatible" if consumer_organization == lifecycle.organization_id else "incompatible"


def _acknowledgement_path(
    workload: NormalizedResource,
    topic: NormalizedResource,
    subscription: NormalizedResource,
    service_account_email: str,
    service_account_member: str,
    iam_resource: NormalizedResource,
    source: str,
    role: str,
    role_access: _RoleAccess,
    scope_type: Literal["project", "subscription"],
    scope: str,
) -> GcpCloudRunPubsubMessageRemovalPath:
    topic_facts = gcp_facts(topic)
    subscription_facts = gcp_facts(subscription)
    topic_reference = _topic_reference(topic)
    subscription_reference = _subscription_reference(subscription)
    delivery = _delivery_evidence(topic, subscription)
    iam_source_addresses = [source]
    if role_access.role_definition_address is not None:
        iam_source_addresses.append(role_access.role_definition_address)
    record: dict[str, Any] = {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "service_account_email": service_account_email,
        "service_account_member": service_account_member,
        "identity_kind": "cloud_run_service_account",
        "credential_context": "workload_runtime",
        "topic_address": topic.address,
        "topic_resource_type": topic.resource_type,
        "topic_name": _known_string(topic_facts.resource_name) or topic.name,
        "topic_project": _normalize_project(topic_facts.project) or "",
        "topic_reference": topic_reference,
        "subscription_address": subscription.address,
        "subscription_resource_type": subscription.resource_type,
        "subscription_name": _known_string(subscription_facts.resource_name) or subscription.name,
        "subscription_project": _normalize_project(subscription_facts.project) or "",
        "subscription_reference": subscription_reference,
        "operation": _ACKNOWLEDGE,
        "operation_class": "message_acknowledgement",
        "internal_operation": "acknowledge_messages",
        "management_effect": "disruption",
        "target_granularity": "subscription_message_namespace",
        "target_scope": "exact_subscription_message_namespace",
        "target_model_evidence_addresses": [topic.address, subscription.address],
        "acknowledgement_id_source": "runtime_message_delivery",
        "acknowledgement_id_value": None,
        "iam_resource_address": iam_resource.address,
        "iam_resource_type": iam_resource.resource_type,
        "iam_source_addresses": iam_source_addresses,
        "role": role,
        "role_kind": role_access.role_kind,
        "role_definition_address": role_access.role_definition_address,
        "custom_role_permissions": list(role_access.custom_role_permissions),
        "custom_role_stage": role_access.custom_role_stage,
        "custom_role_deleted": role_access.custom_role_deleted,
        "custom_role_grant_scope_compatibility_state": (role_access.custom_role_grant_scope_compatibility_state),
        "matched_permissions": [_ACKNOWLEDGE],
        "grant_basis": "project_iam" if scope_type == "project" else "subscription_iam",
        "authorization_state": "granted",
        "policy_complete": True,
        "condition": None,
        "condition_state": "not_configured",
        "lifecycle_compatibility_state": "not_applicable",
        "delivery_evidence": delivery,
        "posture_uncertainties": list(delivery["uncertainties"]),
        "scope_type": scope_type,
        "scope": scope,
        "resource_scope": "pubsub_project" if scope_type == "project" else "exact_pubsub_subscription",
    }
    return cast(GcpCloudRunPubsubMessageRemovalPath, record)


def _delivery_evidence(
    topic: NormalizedResource,
    subscription: NormalizedResource,
) -> GcpPubsubMessageRemovalDeliveryEvidence:
    topic_facts = gcp_facts(topic)
    subscription_facts = gcp_facts(subscription)
    uncertainties = dedupe(
        [
            *topic_facts.pubsub_posture_uncertainties,
            *subscription_facts.pubsub_posture_uncertainties,
        ]
    )
    topic_state = _posture_state(topic_facts.pubsub_topic_message_retention_state)
    subscription_state = _posture_state(subscription_facts.pubsub_subscription_message_retention_state)
    dead_letter_state = _posture_state(subscription_facts.pubsub_subscription_dead_letter_policy_state)
    replay_state = _replay_state(
        subscription_state,
        subscription_facts.pubsub_subscription_retain_acked_messages,
        topic_state,
    )
    return {
        "delivery_evidence_scope": "pubsub_acknowledged_message_retention_posture",
        "subscription_message_retention_state": subscription_state,
        "subscription_message_retention_duration": subscription_facts.pubsub_subscription_message_retention_duration,
        "subscription_message_retention_seconds": subscription_facts.pubsub_subscription_message_retention_seconds,
        "subscription_retain_acked_messages": subscription_facts.pubsub_subscription_retain_acked_messages,
        "topic_message_retention_state": topic_state,
        "topic_message_retention_duration": topic_facts.pubsub_topic_message_retention_duration,
        "topic_message_retention_seconds": topic_facts.pubsub_topic_message_retention_seconds,
        "acknowledged_message_replay_state": replay_state,
        "replay_authority_evaluated": False,
        "dead_letter_policy_state": dead_letter_state,
        "dead_letter_topic": subscription_facts.pubsub_subscription_dead_letter_topic,
        "dead_letter_max_delivery_attempts": subscription_facts.pubsub_subscription_dead_letter_max_delivery_attempts,
        "dead_letter_policy_is_acknowledgement_recovery": False,
        "uncertainties": uncertainties,
    }


def _replay_state(
    subscription_state: Literal["configured", "not_configured", "unknown"],
    retain_acked_messages: bool | None,
    topic_state: Literal["configured", "not_configured", "unknown"],
) -> GcpPubsubAcknowledgedMessageReplayState:
    if (
        subscription_state == "unknown"
        or topic_state == "unknown"
        or (subscription_state == STATE_CONFIGURED and retain_acked_messages is None)
    ):
        return "unknown"
    retained_by_subscription = subscription_state == STATE_CONFIGURED and retain_acked_messages is True
    retained_by_topic = topic_state == STATE_CONFIGURED
    if retained_by_subscription and retained_by_topic:
        return "retained_by_subscription_and_topic"
    if retained_by_subscription:
        return "retained_by_subscription"
    if retained_by_topic:
        return "retained_by_topic"
    return "not_established"


def _posture_state(value: str | None) -> Literal["configured", "not_configured", "unknown"]:
    if value in {STATE_CONFIGURED, STATE_NOT_CONFIGURED, STATE_UNKNOWN}:
        return cast(Literal["configured", "not_configured", "unknown"], value)
    return "unknown"


def _project_organizations(resources: Sequence[NormalizedResource]) -> Mapping[str, str]:
    organizations: dict[str, str] = {}
    for resource in resources:
        if resource.resource_type != GcpResourceType.PROJECT:
            continue
        facts = gcp_facts(resource)
        project = _normalize_project(facts.project)
        organization_id = _normalize_organization(facts.organization_id)
        if project is not None and organization_id is not None:
            organizations.setdefault(project, organization_id)
    return organizations


def _custom_role_lifecycles_by_reference(
    resources: Sequence[NormalizedResource],
) -> Mapping[str, _CustomRoleLifecycle]:
    lifecycles: dict[str, _CustomRoleLifecycle] = {}
    for resource in resources:
        if resource.resource_type not in {
            GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
            GcpResourceType.ORGANIZATION_IAM_CUSTOM_ROLE,
        }:
            continue
        facts = gcp_facts(resource)
        lifecycle = _CustomRoleLifecycle(
            resource.address,
            _normalize_project(facts.project),
            _normalize_organization(facts.organization_id),
            facts.custom_role_stage,
            facts.custom_role_deleted,
            tuple(sorted(set(facts.custom_role_permissions))),
        )
        for reference in custom_role_reference_keys(resource):
            lifecycles.setdefault(reference, lifecycle)
    return lifecycles


def _topic_reference(topic: NormalizedResource) -> str:
    facts = gcp_facts(topic)
    identifier = _known_string(topic.identifier)
    if identifier and identifier.startswith("projects/") and "/topics/" in identifier:
        return identifier
    project = _normalize_project(facts.project)
    name = _known_string(facts.resource_name) or topic.name
    return f"projects/{project}/topics/{name}" if project and name else topic.address


def _subscription_reference(subscription: NormalizedResource) -> str:
    facts = gcp_facts(subscription)
    identifier = _known_string(subscription.identifier)
    if identifier and identifier.startswith("projects/") and "/subscriptions/" in identifier:
        return identifier
    project = _normalize_project(facts.project)
    name = _known_string(facts.resource_name) or subscription.name
    return f"projects/{project}/subscriptions/{name}" if project and name else subscription.address


def _normalize_project(value: object) -> str | None:
    text = _known_string(value)
    if text is None:
        return None
    if text.startswith("projects/"):
        return text.removeprefix("projects/").split("/", 1)[0] or None
    return text


def _normalize_organization(value: object) -> str | None:
    text = _known_string(value)
    if text is None:
        return None
    if text.startswith("organizations/"):
        return text.removeprefix("organizations/") or None
    return text


def _condition(value: object) -> dict[str, Any] | None:
    if isinstance(value, Mapping):
        return {str(key): item for key, item in value.items()}
    return None


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _looks_like_custom_role(role: str) -> bool:
    return role.startswith(("projects/", "organizations/")) or "iam_custom_role." in role
