from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, cast

from tfstride.models import NormalizedResource
from tfstride.providers.coercion import dedupe
from tfstride.providers.gcp.iam_reference_utils import (
    custom_role_reference_keys,
    normalize_gcp_project,
)
from tfstride.providers.gcp.messaging_topology_destruction_evidence import (
    GcpCloudRunPubsubTopologyDestructionPath,
    GcpPubsubTopologyActiveCustomRoleStage,
    GcpPubsubTopologyBuiltInRoleEvidence,
    GcpPubsubTopologyCustomRoleEvidence,
    GcpPubsubTopologyDestructionOperation,
    GcpPubsubTopologyRoleEvidence,
)
from tfstride.providers.gcp.resource_decoration.iam import iam_bindings
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext
from tfstride.providers.gcp.resource_types import (
    GCP_CLOUD_RUN_RESOURCE_TYPES,
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

_ACTIVE_CUSTOM_ROLE_STAGES = frozenset({"ALPHA", "BETA", "DEPRECATED", "EAP", "GA"})
_BUILT_IN_DELETE_ROLES: dict[str, Literal["owner", "editor", "admin"]] = {
    "roles/pubsub.editor": "editor",
    "roles/pubsub.admin": "admin",
}
_BASIC_PROJECT_DELETE_ROLES: dict[str, Literal["owner", "editor", "admin"]] = {
    "roles/editor": "editor",
    "roles/owner": "owner",
}
_DELETE_TOPIC: GcpPubsubTopologyDestructionOperation = "pubsub.topics.delete"
_DELETE_SUBSCRIPTION: GcpPubsubTopologyDestructionOperation = "pubsub.subscriptions.delete"
_PUBSUB_RESOURCE_REFERENCE_SUFFIXES = (".id", ".name")

_TargetKind = Literal["topic", "subscription"]
_ScopeType = Literal["project", "topic", "subscription"]
_ManagementMode = Literal[
    "authoritative_policy",
    "authoritative_role_binding",
    "additive_member",
]


@dataclass(frozen=True, slots=True)
class _CustomRoleLifecycle:
    resource_address: str
    project: str | None
    organization_id: str | None
    stage: str | None
    deleted: bool | None
    permissions: tuple[str, ...]
    permissions_state: str | None


@dataclass(frozen=True, slots=True)
class _TopologyTarget:
    resource: NormalizedResource
    kind: _TargetKind
    name: str
    project: str
    reference: str
    topic: NormalizedResource
    topic_name: str
    topic_project: str
    topic_reference: str


@dataclass(frozen=True, slots=True)
class _IamManager:
    source_address: str
    scope_type: _ScopeType
    scope: str
    management_mode: _ManagementMode
    roles: tuple[str, ...]


class ModelCloudRunPubsubTopologyDestructionPathsStage:
    """Project deterministic Pub/Sub topic and subscription deletion authority."""

    name = "model_cloud_run_pubsub_topology_destruction_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: GcpDecorationContext,
    ) -> None:
        targets, target_uncertainties = _topology_targets(resources, context)
        custom_roles = _custom_role_lifecycles_by_reference(resources)
        project_organizations = _project_organizations(resources)
        iam_resources = tuple(
            resource
            for resource in resources
            if resource.resource_type
            in (
                GCP_PROJECT_IAM_RESOURCE_TYPES
                | GCP_PUBSUB_TOPIC_IAM_RESOURCE_TYPES
                | GCP_PUBSUB_SUBSCRIPTION_IAM_RESOURCE_TYPES
            )
        )

        for workload in resources:
            if workload.resource_type not in GCP_CLOUD_RUN_RESOURCE_TYPES:
                continue
            paths, uncertainties = _cloud_run_pubsub_topology_destruction_paths(
                workload,
                targets,
                iam_resources,
                context,
                custom_roles,
                project_organizations,
            )
            uncertainties.extend(f"{workload.address}: {message}" for message in target_uncertainties)
            facts = gcp_facts(workload)
            facts.set_cloud_run_pubsub_topology_destruction_paths(paths)
            facts.extend_cloud_run_pubsub_topology_destruction_path_uncertainties(dedupe(uncertainties))


def _cloud_run_pubsub_topology_destruction_paths(
    workload: NormalizedResource,
    targets: Sequence[_TopologyTarget],
    iam_resources: Sequence[NormalizedResource],
    context: GcpDecorationContext,
    custom_roles: Mapping[str, _CustomRoleLifecycle],
    project_organizations: Mapping[str, str],
) -> tuple[list[GcpCloudRunPubsubTopologyDestructionPath], list[str]]:
    workload_facts = gcp_facts(workload)
    service_account_email = _known_string(workload_facts.service_account_email)
    service_account_member = _known_string(workload_facts.service_account_member)
    if (
        service_account_email is None
        or service_account_member is None
        or service_account_member != f"serviceAccount:{service_account_email}"
    ):
        return [], [
            f"{workload.address}: Cloud Run service account is unresolved for Pub/Sub topology-deletion modeling"
        ]

    paths: list[GcpCloudRunPubsubTopologyDestructionPath] = []
    uncertainties: list[str] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for target in targets:
        relevant_iam_resources = tuple(
            resource for resource in iam_resources if resource.resource_type in _iam_resource_types(target.kind)
        )
        ambiguous_scopes, ambiguous_roles, manager_uncertainties = _iam_manager_ambiguities(
            target,
            relevant_iam_resources,
            context,
            custom_roles,
        )
        uncertainties.extend(
            f"{workload.address}: {message} for {target.resource.address}" for message in manager_uncertainties
        )

        operation = _operation(target.kind)
        for iam_resource in relevant_iam_resources:
            scope_type, scope, scope_uncertainty = _iam_scope(
                iam_resource,
                target,
                context,
            )
            if scope_type is None or scope is None:
                if scope_uncertainty is not None and any(
                    _binding_member_applies(binding, service_account_member) for binding in iam_bindings(iam_resource)
                ):
                    uncertainties.append(
                        f"{workload.address}: {iam_resource.address} Pub/Sub IAM scope is unresolved "
                        f"for {target.resource.address}"
                    )
                continue

            source_facts = gcp_facts(iam_resource)
            policy_state = source_facts.iam_policy_data_state
            if policy_state in {"unknown", "invalid", "not_configured"}:
                uncertainties.append(
                    f"{workload.address}: {iam_resource.address} IAM policy_data is {policy_state} "
                    f"for {target.resource.address}"
                )
                continue

            for binding in iam_bindings(iam_resource):
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
                        f"{workload.address}: {source} Pub/Sub topology-deletion condition is not deterministic"
                    )
                    continue

                role_evidence, role_uncertainty = _role_evidence(
                    role,
                    operation,
                    target.project,
                    scope_type,
                    custom_roles,
                    project_organizations,
                )
                if role_evidence is None:
                    if role_uncertainty is not None:
                        uncertainties.append(f"{workload.address}: {source} {role_uncertainty}")
                    continue

                role_key = _role_reconciliation_key(role, custom_roles)
                if (scope_type, scope) in ambiguous_scopes or (scope_type, scope, role_key) in ambiguous_roles:
                    continue
                fingerprint = (
                    target.resource.address,
                    source,
                    role_key,
                    scope_type,
                    scope,
                )
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                paths.append(
                    _topology_destruction_path(
                        workload,
                        target,
                        service_account_email,
                        service_account_member,
                        iam_resource,
                        source,
                        role,
                        role_evidence,
                        scope_type,
                        scope,
                    )
                )

    paths.sort(
        key=lambda path: (
            path["messaging_resource_address"],
            path["operation"],
            path["scope_type"],
            path["iam_resource_address"],
            path["role"],
        )
    )
    return paths, dedupe(uncertainties)


def _topology_targets(
    resources: Sequence[NormalizedResource],
    context: GcpDecorationContext,
) -> tuple[list[_TopologyTarget], list[str]]:
    targets: list[_TopologyTarget] = []
    uncertainties: list[str] = []
    for resource in resources:
        if resource.resource_type == GcpResourceType.PUBSUB_TOPIC:
            identity = _target_identity(resource, "topic")
            if identity is None:
                uncertainties.append(f"Pub/Sub topic {resource.address} has unresolved native identity")
                continue
            name, project, reference = identity
            targets.append(
                _TopologyTarget(
                    resource,
                    "topic",
                    name,
                    project,
                    reference,
                    resource,
                    name,
                    project,
                    reference,
                )
            )
            continue
        if resource.resource_type != GcpResourceType.PUBSUB_SUBSCRIPTION:
            continue
        identity = _target_identity(resource, "subscription")
        topic = _subscription_topic(resource, context)
        if identity is None:
            uncertainties.append(f"Pub/Sub subscription {resource.address} has unresolved native identity")
            continue
        if topic is None:
            uncertainties.append(f"Pub/Sub subscription {resource.address} has unresolved topic ancestry")
            continue
        topic_identity = _target_identity(topic, "topic")
        if topic_identity is None:
            uncertainties.append(f"Pub/Sub subscription {resource.address} has unresolved topic identity")
            continue
        name, project, reference = identity
        topic_name, topic_project, topic_reference = topic_identity
        targets.append(
            _TopologyTarget(
                resource,
                "subscription",
                name,
                project,
                reference,
                topic,
                topic_name,
                topic_project,
                topic_reference,
            )
        )
    return targets, uncertainties


def _target_identity(
    resource: NormalizedResource,
    kind: _TargetKind,
) -> tuple[str, str, str] | None:
    facts = gcp_facts(resource)
    if any(
        uncertainty in {"name is unknown after planning", "project is unknown after planning"}
        for uncertainty in facts.pubsub_posture_uncertainties
    ):
        return None
    name = _known_string(facts.resource_name)
    project = normalize_gcp_project(facts.project)
    if name is None or project is None:
        return None
    expected = f"projects/{project}/{'topics' if kind == 'topic' else 'subscriptions'}/{name}"
    identifier = _known_string(resource.identifier)
    if identifier is not None and identifier.startswith("projects/") and identifier != expected:
        return None
    return name, project, expected


def _subscription_topic(
    subscription: NormalizedResource,
    context: GcpDecorationContext,
) -> NormalizedResource | None:
    reference = _known_string(gcp_facts(subscription).pubsub_topic_reference)
    if reference is None:
        return None
    return context.index.resources_by_reference.get(
        gcp_reference_key(reference, _PUBSUB_RESOURCE_REFERENCE_SUFFIXES),
        source=subscription,
        resource_types={GcpResourceType.PUBSUB_TOPIC},
    )


def _iam_manager_ambiguities(
    target: _TopologyTarget,
    iam_resources: Sequence[NormalizedResource],
    context: GcpDecorationContext,
    custom_roles: Mapping[str, _CustomRoleLifecycle],
) -> tuple[
    set[tuple[_ScopeType, str]],
    set[tuple[_ScopeType, str, str]],
    list[str],
]:
    managers: list[_IamManager] = []
    unresolved_managers: list[_IamManager] = []
    for iam_resource in iam_resources:
        scope_type, scope, scope_uncertainty = _iam_scope(
            iam_resource,
            target,
            context,
        )
        management_mode = _management_mode(iam_resource)
        bindings = iam_bindings(iam_resource)
        roles = _manager_role_keys(bindings, custom_roles)
        if scope_type is None or scope is None:
            potential_scope = _potential_unresolved_manager_scope(
                iam_resource,
                target,
                scope_uncertainty,
            )
            if potential_scope is not None and management_mode != "additive_member":
                unresolved_managers.append(
                    _IamManager(
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
                iam_resource.address,
                scope_type,
                scope,
                management_mode,
                roles,
            )
        )
        if management_mode != "additive_member" and _manager_has_unresolved_role(bindings):
            unresolved_managers.append(
                _IamManager(
                    iam_resource.address,
                    scope_type,
                    scope,
                    management_mode,
                    roles,
                )
            )

    ambiguous_scopes: set[tuple[_ScopeType, str]] = set()
    ambiguous_roles: set[tuple[_ScopeType, str, str]] = set()
    uncertainties: list[str] = []
    scope_keys: set[tuple[_ScopeType, str]] = {(manager.scope_type, manager.scope) for manager in managers}
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


def _iam_scope(
    iam_resource: NormalizedResource,
    target: _TopologyTarget,
    context: GcpDecorationContext,
) -> tuple[_ScopeType | None, str | None, str | None]:
    facts = gcp_facts(iam_resource)
    if facts.iam_scope_reference_state in {"unknown", "not_configured"}:
        return None, None, "scope reference is unresolved"
    if iam_resource.resource_type in GCP_PROJECT_IAM_RESOURCE_TYPES:
        project = normalize_gcp_project(facts.project)
        if project != target.project:
            return None, None, None
        return "project", project, None

    target_types = (
        GCP_PUBSUB_TOPIC_IAM_RESOURCE_TYPES if target.kind == "topic" else GCP_PUBSUB_SUBSCRIPTION_IAM_RESOURCE_TYPES
    )
    if iam_resource.resource_type not in target_types:
        return None, None, None
    target_reference = _known_string(facts.target_reference)
    if target_reference is None:
        return None, None, f"{target.kind} target is unresolved"
    resolved = context.index.resources_by_reference.get(
        gcp_reference_key(target_reference, _PUBSUB_RESOURCE_REFERENCE_SUFFIXES),
        source=iam_resource,
        resource_types=(
            {GcpResourceType.PUBSUB_TOPIC} if target.kind == "topic" else {GcpResourceType.PUBSUB_SUBSCRIPTION}
        ),
    )
    if resolved is None:
        return None, None, f"{target.kind} target is unresolved"
    if resolved.address != target.resource.address:
        return None, None, None
    return target.kind, target.reference, None


def _potential_unresolved_manager_scope(
    iam_resource: NormalizedResource,
    target: _TopologyTarget,
    scope_uncertainty: str | None,
) -> tuple[_ScopeType, str] | None:
    if scope_uncertainty is None:
        return None
    if iam_resource.resource_type in GCP_PROJECT_IAM_RESOURCE_TYPES:
        return "project", target.project
    target_types = (
        GCP_PUBSUB_TOPIC_IAM_RESOURCE_TYPES if target.kind == "topic" else GCP_PUBSUB_SUBSCRIPTION_IAM_RESOURCE_TYPES
    )
    if iam_resource.resource_type in target_types:
        return target.kind, target.reference
    return None


def _role_evidence(
    role: str,
    operation: GcpPubsubTopologyDestructionOperation,
    target_project: str,
    scope_type: _ScopeType,
    custom_roles: Mapping[str, _CustomRoleLifecycle],
    project_organizations: Mapping[str, str],
) -> tuple[GcpPubsubTopologyRoleEvidence | None, str | None]:
    built_in_kind = _BUILT_IN_DELETE_ROLES.get(role)
    if built_in_kind is None and scope_type == "project":
        built_in_kind = _BASIC_PROJECT_DELETE_ROLES.get(role)
    if built_in_kind is not None:
        evidence: GcpPubsubTopologyBuiltInRoleEvidence = {
            "role_kind": built_in_kind,
            "role_definition_address": None,
            "custom_role_permissions": [],
            "custom_role_stage": None,
            "custom_role_deleted": None,
            "custom_role_grant_scope_compatibility_state": "not_applicable",
        }
        return evidence, None
    if not _looks_like_custom_role(role):
        return None, None
    lifecycle = custom_roles.get(gcp_reference_key(role, GCP_ROLE_REFERENCE_SUFFIXES))
    if lifecycle is None:
        return None, f"custom IAM role {role} is unresolved"
    if lifecycle.deleted is True:
        return None, None
    if lifecycle.deleted is None:
        return None, f"custom IAM role {role} deletion state is unresolved"
    if lifecycle.stage is None:
        return None, f"custom IAM role {role} lifecycle stage is unresolved"
    stage = lifecycle.stage.upper()
    if stage not in _ACTIVE_CUSTOM_ROLE_STAGES:
        return None, None
    if lifecycle.permissions_state in {None, "unknown"}:
        return None, f"custom IAM role {role} permissions are unresolved"
    wildcard_permissions = tuple(permission for permission in lifecycle.permissions if "*" in permission)
    if wildcard_permissions:
        return None, (
            f"custom IAM role {role} contains unsupported wildcard permission(s): {', '.join(wildcard_permissions)}"
        )
    if not _permissions_allow(lifecycle.permissions, operation):
        return None, None
    compatibility = _custom_role_grant_scope_compatibility(
        lifecycle,
        target_project,
        project_organizations,
    )
    if compatibility == "incompatible":
        return None, f"custom IAM role {role} is not grantable in target project {target_project}"
    if compatibility == "unknown":
        return None, (
            f"custom IAM role {role} grant scope compatibility is unresolved for target project {target_project}"
        )
    custom_evidence = GcpPubsubTopologyCustomRoleEvidence(
        role_kind="custom",
        role_definition_address=lifecycle.resource_address,
        custom_role_permissions=list(lifecycle.permissions),
        custom_role_stage=cast(GcpPubsubTopologyActiveCustomRoleStage, stage),
        custom_role_deleted=False,
        custom_role_grant_scope_compatibility_state="compatible",
    )
    return custom_evidence, None


def _permissions_allow(
    permissions: Sequence[str],
    operation: GcpPubsubTopologyDestructionOperation,
) -> bool:
    operation_key = operation.casefold()
    return any(permission.strip().casefold() == operation_key for permission in permissions)


def _custom_role_grant_scope_compatibility(
    lifecycle: _CustomRoleLifecycle,
    target_project: str,
    project_organizations: Mapping[str, str],
) -> Literal["compatible", "incompatible", "unknown"]:
    if lifecycle.project is not None:
        return "compatible" if lifecycle.project == target_project else "incompatible"
    if lifecycle.organization_id is None:
        return "unknown"
    target_organization = project_organizations.get(target_project)
    if target_organization is None:
        return "unknown"
    return "compatible" if target_organization == lifecycle.organization_id else "incompatible"


def _topology_destruction_path(
    workload: NormalizedResource,
    target: _TopologyTarget,
    service_account_email: str,
    service_account_member: str,
    iam_resource: NormalizedResource,
    source: str,
    role: str,
    role_evidence: GcpPubsubTopologyRoleEvidence,
    scope_type: _ScopeType,
    scope: str,
) -> GcpCloudRunPubsubTopologyDestructionPath:
    operation = _operation(target.kind)
    iam_source_addresses = [source]
    role_definition_address = role_evidence["role_definition_address"]
    if role_definition_address is not None:
        iam_source_addresses.append(role_definition_address)
    common: dict[str, Any] = {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "service_account_email": service_account_email,
        "service_account_member": service_account_member,
        "identity_kind": "cloud_run_service_account",
        "credential_context": "workload_runtime",
        "messaging_resource_address": target.resource.address,
        "messaging_resource_type": target.resource.resource_type,
        "messaging_resource_name": target.name,
        "messaging_resource_project": target.project,
        "messaging_resource_reference": target.reference,
        "target_model_evidence_addresses": (
            [target.topic.address] if target.kind == "topic" else [target.topic.address, target.resource.address]
        ),
        "management_effect": "disruption",
        "iam_resource_address": iam_resource.address,
        "iam_resource_type": iam_resource.resource_type,
        "iam_source_addresses": iam_source_addresses,
        "role": role,
        "role_evidence": role_evidence,
        "authorization_state": "granted",
        "policy_complete": True,
        "iam_manager_ambiguity_state": "not_detected",
        "condition": None,
        "condition_state": "not_configured",
        "lifecycle_compatibility_state": "not_applicable",
        "outcome_evidence": {
            "outcome_evidence_scope": "plan_local_pubsub_topology_deletion_authority",
            "successful_deletion_observed": False,
            "recovery_state": "not_established_by_modeled_gcp_messaging_topology_evidence",
            "descendant_impact_evaluated": False,
            "out_of_plan_topology_evaluated": False,
            "uncertainties": [],
        },
        "posture_uncertainties": [],
        "scope_type": scope_type,
        "scope": scope,
        "grant_basis": ("pubsub_project_iam" if scope_type == "project" else f"pubsub_{target.kind}_iam"),
        "resource_scope": ("pubsub_project" if scope_type == "project" else f"exact_pubsub_{target.kind}"),
        "messaging_resource_kind": target.kind,
        "operation": operation,
        "operation_class": ("topic_deletion" if target.kind == "topic" else "subscription_deletion"),
        "internal_operation": ("delete_topic" if target.kind == "topic" else "delete_subscription"),
        "target_granularity": ("topic_topology" if target.kind == "topic" else "subscription_topology"),
        "target_scope": ("exact_pubsub_topic" if target.kind == "topic" else "exact_pubsub_subscription"),
        "topic_address": target.topic.address,
        "topic_resource_type": target.topic.resource_type,
        "topic_name": target.topic_name,
        "topic_project": target.topic_project,
        "topic_reference": target.topic_reference,
        "subscription_address": (None if target.kind == "topic" else target.resource.address),
        "subscription_resource_type": (None if target.kind == "topic" else target.resource.resource_type),
        "subscription_name": None if target.kind == "topic" else target.name,
        "subscription_project": None if target.kind == "topic" else target.project,
        "subscription_reference": None if target.kind == "topic" else target.reference,
        "matched_permissions": [operation],
    }
    return cast(GcpCloudRunPubsubTopologyDestructionPath, common)


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
            normalize_gcp_project(facts.project),
            _normalize_organization(facts.organization_id),
            facts.custom_role_stage,
            facts.custom_role_deleted,
            tuple(sorted(set(facts.custom_role_permissions))),
            facts.custom_role_permissions_state,
        )
        for reference in custom_role_reference_keys(resource):
            lifecycles.setdefault(reference, lifecycle)
    return lifecycles


def _project_organizations(
    resources: Sequence[NormalizedResource],
) -> Mapping[str, str]:
    organizations: dict[str, str] = {}
    for resource in resources:
        if resource.resource_type != GcpResourceType.PROJECT:
            continue
        facts = gcp_facts(resource)
        project = normalize_gcp_project(facts.project)
        organization = _normalize_organization(facts.organization_id)
        if project is not None and organization is not None:
            organizations.setdefault(project, organization)
    return organizations


def _role_reconciliation_key(
    role: str,
    custom_roles: Mapping[str, _CustomRoleLifecycle],
) -> str:
    normalized = gcp_reference_key(role, GCP_ROLE_REFERENCE_SUFFIXES)
    lifecycle = custom_roles.get(normalized)
    if lifecycle is not None:
        return f"custom:{lifecycle.resource_address}"
    return f"role:{normalized}"


def _manager_role_keys(
    bindings: Sequence[Mapping[str, Any]],
    custom_roles: Mapping[str, _CustomRoleLifecycle],
) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                _role_reconciliation_key(role, custom_roles)
                for binding in bindings
                if binding.get("role_state") != "unknown" and (role := _known_string(binding.get("role"))) is not None
            }
        )
    )


def _manager_has_unresolved_role(bindings: Sequence[Mapping[str, Any]]) -> bool:
    return any(
        binding.get("role_state") == "unknown" or _known_string(binding.get("role")) is None for binding in bindings
    )


def _management_mode(resource: NormalizedResource) -> _ManagementMode:
    if resource.resource_type.endswith("_iam_policy"):
        return "authoritative_policy"
    if resource.resource_type.endswith("_iam_binding"):
        return "authoritative_role_binding"
    return "additive_member"


def _binding_member_applies(binding: Mapping[str, Any], member: str) -> bool:
    return member in binding_members(binding)


def _iam_resource_types(target_kind: _TargetKind) -> frozenset[str]:
    return GCP_PROJECT_IAM_RESOURCE_TYPES | (
        GCP_PUBSUB_TOPIC_IAM_RESOURCE_TYPES if target_kind == "topic" else GCP_PUBSUB_SUBSCRIPTION_IAM_RESOURCE_TYPES
    )


def _operation(target_kind: _TargetKind) -> GcpPubsubTopologyDestructionOperation:
    return _DELETE_TOPIC if target_kind == "topic" else _DELETE_SUBSCRIPTION


def _condition(value: object) -> dict[str, Any] | None:
    if isinstance(value, Mapping):
        return {str(key): item for key, item in value.items()}
    return None


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _normalize_organization(value: object) -> str | None:
    text = _known_string(value)
    if text is None:
        return None
    if text.startswith("organizations/"):
        return text.removeprefix("organizations/") or None
    return text


def _looks_like_custom_role(role: str) -> bool:
    return role.startswith(("projects/", "organizations/")) or "iam_custom_role." in role
