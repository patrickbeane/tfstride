from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from tfstride.models import NormalizedResource, TerraformReferenceProvenance, TerraformReferenceResolutionState
from tfstride.providers.azure.arm_control_plane_evidence import AzureArmScopeType
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import AZURE_APP_SERVICE_RESOURCE_TYPES, AzureResourceType

_SUBSCRIPTION_SCOPE_PATTERN = re.compile(r"^/subscriptions/[^/]+$", re.IGNORECASE)

_RESOURCE_GROUP_SCOPE_PATTERN = re.compile(
    r"^/subscriptions/[^/]+/resourcegroups/[^/]+$",
    re.IGNORECASE,
)

_MANAGEMENT_GROUP_SCOPE_PATTERN = re.compile(
    r"^/providers/microsoft\.management/managementgroups/[^/]+$",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class AzureAssignmentScope:
    state: Literal["resolved", "unknown", "unrelated", "invalid"]
    scope_type: AzureArmScopeType | None = None
    arm_scope: str | None = None


def azure_arm_scope_contains(parent: str, child: str) -> bool:
    normalized_parent = parent.strip().casefold().rstrip("/")
    normalized_child = child.strip().casefold().rstrip("/")
    if normalized_parent == "":
        normalized_parent = "/"
    if normalized_parent == "/":
        return True
    if not normalized_parent.startswith("/") or not normalized_child.startswith("/"):
        return False
    return normalized_child == normalized_parent or normalized_child.startswith(f"{normalized_parent}/")


def resolve_assignment_scope(
    assignment: NormalizedResource,
    context: AzureDecorationContext,
    target_arm_id: str | None,
) -> AzureAssignmentScope:
    facts = azure_facts(assignment)
    raw_scope = _known_string(facts.role_assignment_scope)
    if raw_scope is None:
        if assignment_field_unknown(assignment, "scope"):
            return AzureAssignmentScope("unknown")
        target_address = _known_string(facts.role_assignment_target_resource_address)
        target = context.index.resources_by_address.get(target_address or "")
        arm_scope = resource_arm_id(target) if target is not None else None
    else:
        arm_scope = normalize_arm_id(raw_scope)
        if arm_scope is None:
            target = proven_symbolic_assignment_scope_target(
                assignment,
                context,
            )
            arm_scope = resource_arm_id(target) if target is not None else None

    if arm_scope is None:
        return AzureAssignmentScope("unknown")
    scope_type = _scope_type(arm_scope)
    if scope_type is None:
        return AzureAssignmentScope("invalid")
    if target_arm_id is None:
        return AzureAssignmentScope("unknown", scope_type, arm_scope)
    if scope_type == "management_group" and not azure_arm_scope_contains(
        arm_scope,
        target_arm_id,
    ):
        return AzureAssignmentScope("unknown", scope_type, arm_scope)
    if not azure_arm_scope_contains(arm_scope, target_arm_id):
        return AzureAssignmentScope("unrelated", scope_type, arm_scope)
    return AzureAssignmentScope("resolved", scope_type, arm_scope)


def proven_symbolic_assignment_scope_target(
    assignment: NormalizedResource,
    context: AzureDecorationContext,
) -> NormalizedResource | None:
    facts = azure_facts(assignment)
    target_address = _known_string(facts.role_assignment_target_resource_address)
    if target_address is None:
        return None

    resolution = assignment.reference_resolution("scope")
    if (
        resolution.state != TerraformReferenceResolutionState.SYMBOLIC
        or resolution.provenance != TerraformReferenceProvenance.CONFIGURATION_REFERENCE
        or len(resolution.targets) != 1
    ):
        return None

    resolved_target = resolution.targets[0]
    if resolved_target.address != target_address:
        return None
    target = context.index.resources_by_address.get(target_address)
    if target is None or not _valid_symbolic_assignment_scope_reference(
        target,
        resolved_target.reference,
    ):
        return None
    return target


def _valid_symbolic_assignment_scope_reference(
    target: NormalizedResource,
    reference: str,
) -> bool:
    normalized = reference.casefold()
    if target.resource_type in {
        AzureResourceType.KEY_VAULT_KEY,
        AzureResourceType.KEY_VAULT_SECRET,
    }:
        return normalized.endswith(".resource_versionless_id")
    if target.resource_type == AzureResourceType.STORAGE_CONTAINER:
        return normalized.endswith(".resource_manager_id")
    return normalized.endswith(".id")


def role_assignable_scope_state(
    role_definition: NormalizedResource,
    assignment_arm_scope: str | None,
) -> str:
    facts = azure_facts(role_definition)
    if any("assignable_scopes" in value for value in facts.role_definition_uncertainties):
        return "unknown"
    scopes = facts.role_definition_assignable_scopes
    if not scopes or assignment_arm_scope is None:
        return "unknown"
    return (
        "resolved"
        if any(azure_arm_scope_contains(scope, assignment_arm_scope) for scope in scopes)
        else "outside_assignable_scope"
    )


def assignment_condition_state(assignment: NormalizedResource) -> str:
    facts = azure_facts(assignment)
    if assignment_field_unknown(assignment, "condition") or assignment_field_unknown(
        assignment,
        "condition_version",
    ):
        return "unknown"
    if facts.role_assignment_condition:
        return "configured"
    if facts.role_assignment_condition_version:
        return "unknown"
    return "not_configured"


def assignment_field_unknown(assignment: NormalizedResource, field: str) -> bool:
    prefix = f"{field} is unknown"
    return any(value.startswith(prefix) for value in azure_facts(assignment).key_vault_authorization_uncertainties)


def _scope_type(value: str) -> AzureArmScopeType | None:
    if _MANAGEMENT_GROUP_SCOPE_PATTERN.fullmatch(value):
        return "management_group"
    if _SUBSCRIPTION_SCOPE_PATTERN.fullmatch(value):
        return "subscription"
    if _RESOURCE_GROUP_SCOPE_PATTERN.fullmatch(value):
        return "resource_group"
    if normalize_arm_id(value) is not None:
        return "resource"
    return None


def resource_arm_id(resource: NormalizedResource) -> str | None:
    facts = azure_facts(resource)
    if resource.resource_type in AZURE_APP_SERVICE_RESOURCE_TYPES:
        value = facts.app_service_id
    elif resource.resource_type == AzureResourceType.STORAGE_ACCOUNT:
        value = facts.storage_account_id
    elif resource.resource_type == AzureResourceType.STORAGE_CONTAINER:
        value = facts.storage_container_resource_manager_id
    elif resource.resource_type == AzureResourceType.KEY_VAULT:
        value = facts.key_vault_id
    elif resource.resource_type == AzureResourceType.KEY_VAULT_KEY:
        value = facts.key_vault_key_versionless_resource_id
    elif resource.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE:
        value = facts.service_bus_namespace_id
    elif resource.resource_type in {
        AzureResourceType.SERVICE_BUS_QUEUE,
        AzureResourceType.SERVICE_BUS_TOPIC,
        AzureResourceType.SERVICE_BUS_SUBSCRIPTION,
    }:
        value = facts.service_bus_entity_id
    elif resource.resource_type == AzureResourceType.COSMOSDB_ACCOUNT:
        value = facts.cosmosdb_account_id
    elif resource.resource_type == AzureResourceType.COSMOSDB_SQL_DATABASE:
        value = facts.cosmosdb_sql_database_id
    elif resource.resource_type == AzureResourceType.COSMOSDB_SQL_CONTAINER:
        value = facts.cosmosdb_sql_container_id
    elif resource.resource_type == AzureResourceType.COSMOSDB_SQL_ROLE_DEFINITION:
        value = facts.cosmosdb_sql_role_definition_resource_id
    else:
        value = resource.identifier
    return normalize_arm_id(value) or normalize_arm_id(resource.identifier)


def normalize_arm_id(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().rstrip("/")
    if "|" in normalized:
        return None
    lowered = normalized.casefold()
    if lowered == "/" or lowered.startswith("/subscriptions/") or lowered.startswith("/providers/"):
        return normalized
    return None


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None
