from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence

from tfstride.identity import (
    AssignmentScopeKind,
    PrincipalType,
    PrivilegeCategory,
    PrivilegeConfidence,
    PrivilegedAccessGrant,
    PrivilegedAccessPosture,
    PrivilegedAssignmentScope,
    PrivilegedPrincipal,
)
from tfstride.models import NormalizedResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.rbac_breadth import (
    AUTHORIZATION_MANAGEMENT,
    COMPUTE_MANAGEMENT,
    KEY_VAULT_DATA_PLANE,
    NETWORK_MANAGEMENT,
    OWNER_LIKE_OR_WILDCARD,
    RESOURCE_GROUP_SUBSCRIPTION_WIDE_MANAGEMENT,
    ROLE_ASSIGNMENT_CAPABLE,
    STORAGE_DATA_PLANE,
    UNKNOWN_CUSTOM_WILDCARD,
)
from tfstride.providers.azure.resource_types import AzureResourceType

_AZURE_PROVIDER = "azure"

_BUILTIN_ROLE_CATEGORIES: dict[str, tuple[PrivilegeCategory, ...]] = {
    "contributor": (
        PrivilegeCategory.COMPUTE_ADMIN,
        PrivilegeCategory.NETWORK_ADMIN,
        PrivilegeCategory.DATA_ADMIN,
    ),
    "key vault administrator": (
        PrivilegeCategory.KEY_ADMIN,
        PrivilegeCategory.SECRETS_ADMIN,
    ),
    "key vault certificates officer": (PrivilegeCategory.SECRETS_ADMIN,),
    "key vault crypto officer": (PrivilegeCategory.KEY_ADMIN,),
    "key vault data access administrator": (
        PrivilegeCategory.KEY_ADMIN,
        PrivilegeCategory.SECRETS_ADMIN,
        PrivilegeCategory.ROLE_ASSIGNMENT,
    ),
    "key vault secrets officer": (PrivilegeCategory.SECRETS_ADMIN,),
    "owner": (
        PrivilegeCategory.FULL_ADMIN,
        PrivilegeCategory.IAM_ADMIN,
        PrivilegeCategory.POLICY_ADMIN,
    ),
    "storage account contributor": (PrivilegeCategory.DATA_ADMIN,),
    "storage blob data contributor": (PrivilegeCategory.DATA_ADMIN,),
    "storage blob data owner": (PrivilegeCategory.DATA_ADMIN,),
    "user access administrator": (
        PrivilegeCategory.IAM_ADMIN,
        PrivilegeCategory.ROLE_ASSIGNMENT,
    ),
}

_BREADTH_SIGNAL_CATEGORIES: dict[str, tuple[PrivilegeCategory, ...]] = {
    OWNER_LIKE_OR_WILDCARD: (PrivilegeCategory.FULL_ADMIN,),
    AUTHORIZATION_MANAGEMENT: (
        PrivilegeCategory.IAM_ADMIN,
        PrivilegeCategory.POLICY_ADMIN,
    ),
    ROLE_ASSIGNMENT_CAPABLE: (PrivilegeCategory.ROLE_ASSIGNMENT,),
    COMPUTE_MANAGEMENT: (PrivilegeCategory.COMPUTE_ADMIN,),
    NETWORK_MANAGEMENT: (PrivilegeCategory.NETWORK_ADMIN,),
    STORAGE_DATA_PLANE: (PrivilegeCategory.DATA_ADMIN,),
    KEY_VAULT_DATA_PLANE: (
        PrivilegeCategory.KEY_ADMIN,
        PrivilegeCategory.SECRETS_ADMIN,
    ),
    RESOURCE_GROUP_SUBSCRIPTION_WIDE_MANAGEMENT: (PrivilegeCategory.COMPUTE_ADMIN,),
    UNKNOWN_CUSTOM_WILDCARD: (PrivilegeCategory.UNKNOWN,),
}


def build_azure_privileged_access_posture(
    role_assignment: NormalizedResource,
    *,
    scope_kind: str | None,
    breadth_signals: Sequence[str],
    target_resource: NormalizedResource | None = None,
    role_definition: NormalizedResource | None = None,
    principal: NormalizedResource | None = None,
) -> PrivilegedAccessPosture:
    if (
        role_assignment.provider != _AZURE_PROVIDER
        or role_assignment.resource_type != AzureResourceType.ROLE_ASSIGNMENT
    ):
        return PrivilegedAccessPosture(provider=_AZURE_PROVIDER)

    unresolved: list[str] = []
    principal_id = _get_string(role_assignment, AzureResourceMetadata.PRINCIPAL_ID)
    role_name = _get_string(role_assignment, AzureResourceMetadata.ROLE_DEFINITION_NAME)
    role_id = _get_string(role_assignment, AzureResourceMetadata.ROLE_DEFINITION_ID)
    if not principal_id:
        unresolved.append(f"{role_assignment.address}: principal_id was not resolved")
    if not role_name and not role_id:
        unresolved.append(f"{role_assignment.address}: role definition was not resolved")
    elif role_definition is None and _looks_like_role_definition_reference(role_id):
        unresolved.append(f"{role_assignment.address}: custom role {role_id} was not resolved")

    categories = _privilege_categories(
        role_name=role_name,
        breadth_signals=breadth_signals,
        role_definition=role_definition,
    )
    if not principal_id or not categories:
        return PrivilegedAccessPosture(provider=_AZURE_PROVIDER, unresolved_assignments=tuple(unresolved))

    return PrivilegedAccessPosture(
        provider=_AZURE_PROVIDER,
        grants=(
            PrivilegedAccessGrant(
                provider=_AZURE_PROVIDER,
                principal=_principal(role_assignment, principal, principal_id),
                assignment_scope=_assignment_scope(role_assignment, scope_kind, target_resource),
                privilege_categories=categories,
                confidence=_confidence(role_name=role_name, role_definition=role_definition),
                assignment_source_address=role_assignment.address,
                role_name=role_name,
                role_id=role_id,
                permission_patterns=tuple(_permission_patterns(role_assignment, role_definition, role_name, role_id)),
                evidence=tuple(_grant_evidence(role_assignment, breadth_signals, target_resource, role_definition)),
                uncertainties=tuple(unresolved),
            ),
        ),
        unresolved_assignments=tuple(unresolved),
    )


def serialize_privileged_access_posture(posture: PrivilegedAccessPosture) -> list[dict[str, object]]:
    return [_serialize_grant(grant) for grant in posture.grants]


def deserialize_privileged_access_grants(records: Iterable[dict[str, object]]) -> tuple[PrivilegedAccessGrant, ...]:
    grants: list[PrivilegedAccessGrant] = []
    for record in records:
        grants.append(
            PrivilegedAccessGrant(
                provider=_record_string(record, "provider") or _AZURE_PROVIDER,
                principal=PrivilegedPrincipal(
                    principal_type=_record_string(record, "principal_type") or PrincipalType.UNKNOWN,
                    identifier=_record_string(record, "principal_identifier"),
                    display_name=_record_string(record, "principal_display_name"),
                    source_address=_record_string(record, "principal_source_address"),
                ),
                assignment_scope=PrivilegedAssignmentScope(
                    scope_kind=_record_string(record, "scope_kind") or AssignmentScopeKind.UNKNOWN,
                    value=_record_string(record, "scope_value"),
                    source_address=_record_string(record, "scope_source_address"),
                ),
                privilege_categories=tuple(_record_string_list(record, "privilege_categories")),
                confidence=_record_string(record, "confidence") or PrivilegeConfidence.HIGH,
                assignment_source_address=_record_string(record, "assignment_source_address"),
                role_name=_record_string(record, "role_name"),
                role_id=_record_string(record, "role_id"),
                permission_patterns=tuple(_record_string_list(record, "permission_patterns")),
                evidence=tuple(_record_string_list(record, "evidence")),
                uncertainties=tuple(_record_string_list(record, "uncertainties")),
            )
        )
    return tuple(grants)


def _principal(
    role_assignment: NormalizedResource,
    principal: NormalizedResource | None,
    principal_id: str,
) -> PrivilegedPrincipal:
    if principal is not None:
        return PrivilegedPrincipal(
            principal_type=PrincipalType.MANAGED_IDENTITY,
            identifier=principal_id,
            display_name=principal.display_name,
            source_address=principal.address,
        )
    return PrivilegedPrincipal(
        principal_type=_principal_type(_get_string(role_assignment, AzureResourceMetadata.PRINCIPAL_TYPE)),
        identifier=principal_id,
        display_name=principal_id,
        source_address=role_assignment.address,
    )


def _principal_type(principal_type: str | None) -> PrincipalType:
    normalized = (principal_type or "").replace("_", "").replace(" ", "").lower()
    if normalized == "user":
        return PrincipalType.HUMAN_USER
    if normalized in {"group", "foreigngroup"}:
        return PrincipalType.GROUP
    if normalized in {"serviceprincipal", "application"}:
        return PrincipalType.SERVICE_PRINCIPAL
    if normalized == "managedidentity":
        return PrincipalType.MANAGED_IDENTITY
    return PrincipalType.UNKNOWN


def _assignment_scope(
    role_assignment: NormalizedResource,
    scope_kind: str | None,
    target_resource: NormalizedResource | None,
) -> PrivilegedAssignmentScope:
    scope = _get_string(role_assignment, AzureResourceMetadata.ROLE_ASSIGNMENT_SCOPE)
    source_address = target_resource.address if target_resource is not None else role_assignment.address
    return PrivilegedAssignmentScope(_scope_kind(scope_kind), value=scope, source_address=source_address)


def _scope_kind(scope_kind: str | None) -> AssignmentScopeKind:
    normalized = (scope_kind or "").strip().lower()
    if normalized == "subscription":
        return AssignmentScopeKind.SUBSCRIPTION
    if normalized == "resource_group":
        return AssignmentScopeKind.RESOURCE_GROUP
    if normalized == "resource":
        return AssignmentScopeKind.RESOURCE
    return AssignmentScopeKind.UNKNOWN


def _privilege_categories(
    *,
    role_name: str | None,
    breadth_signals: Sequence[str],
    role_definition: NormalizedResource | None,
) -> tuple[PrivilegeCategory, ...]:
    categories: list[PrivilegeCategory] = []
    for category in _BUILTIN_ROLE_CATEGORIES.get((role_name or "").strip().lower(), ()):
        _append_unique(categories, category)
    for signal in breadth_signals:
        for category in _BREADTH_SIGNAL_CATEGORIES.get(str(signal), ()):
            _append_unique(categories, category)
    if role_definition is not None:
        for signal in _get_list(role_definition, AzureResourceMetadata.ROLE_DEFINITION_BREADTH_SIGNALS):
            for category in _BREADTH_SIGNAL_CATEGORIES.get(signal, ()):
                _append_unique(categories, category)
    return tuple(categories)


def _confidence(
    *,
    role_name: str | None,
    role_definition: NormalizedResource | None,
) -> PrivilegeConfidence:
    if role_definition is not None or (role_name or "").strip().lower() in _BUILTIN_ROLE_CATEGORIES:
        return PrivilegeConfidence.HIGH
    return PrivilegeConfidence.MEDIUM


def _permission_patterns(
    role_assignment: NormalizedResource,
    role_definition: NormalizedResource | None,
    role_name: str | None,
    role_id: str | None,
) -> list[str]:
    if role_definition is not None:
        return _dedupe(
            [
                *_get_list(role_definition, AzureResourceMetadata.ROLE_DEFINITION_ACTIONS),
                *_get_list(role_definition, AzureResourceMetadata.ROLE_DEFINITION_DATA_ACTIONS),
            ]
        )
    return _dedupe([role_name, role_id, _get_string(role_assignment, AzureResourceMetadata.ROLE_DEFINITION_ID)])


def _grant_evidence(
    role_assignment: NormalizedResource,
    breadth_signals: Sequence[str],
    target_resource: NormalizedResource | None,
    role_definition: NormalizedResource | None,
) -> list[str]:
    values = [
        f"source={role_assignment.address}",
        f"role={_get_string(role_assignment, AzureResourceMetadata.ROLE_DEFINITION_NAME)}",
        f"role_definition_id={_get_string(role_assignment, AzureResourceMetadata.ROLE_DEFINITION_ID)}",
        f"principal_id={_get_string(role_assignment, AzureResourceMetadata.PRINCIPAL_ID)}",
        f"principal_type={_get_string(role_assignment, AzureResourceMetadata.PRINCIPAL_TYPE)}",
        f"scope={_get_string(role_assignment, AzureResourceMetadata.ROLE_ASSIGNMENT_SCOPE)}",
        f"scope_kind={_get_string(role_assignment, AzureResourceMetadata.ROLE_ASSIGNMENT_SCOPE_KIND)}",
        f"target_resource={target_resource.address}" if target_resource is not None else None,
        f"resolved_role_definition={role_definition.address}" if role_definition is not None else None,
    ]
    values.extend(f"breadth_signal={signal}" for signal in breadth_signals if signal)
    return _dedupe(values)


def _serialize_grant(grant: PrivilegedAccessGrant) -> dict[str, object]:
    return {
        "provider": grant.provider,
        "principal_type": grant.principal.principal_type.value,
        "principal_identifier": grant.principal.identifier,
        "principal_display_name": grant.principal.display_name,
        "principal_source_address": grant.principal.source_address,
        "scope_kind": grant.assignment_scope.scope_kind.value,
        "scope_value": grant.assignment_scope.value,
        "scope_source_address": grant.assignment_scope.source_address,
        "privilege_categories": [category.value for category in grant.privilege_categories],
        "confidence": grant.confidence.value,
        "assignment_source_address": grant.assignment_source_address,
        "role_name": grant.role_name,
        "role_id": grant.role_id,
        "permission_patterns": list(grant.permission_patterns),
        "evidence": list(grant.evidence),
        "uncertainties": list(grant.uncertainties),
    }


def _record_string(record: Mapping[str, object], key: str) -> str | None:
    value = record.get(key)
    return _known_string(value)


def _record_string_list(record: Mapping[str, object], key: str) -> list[str]:
    value = record.get(key)
    if not isinstance(value, list | tuple):
        return []
    return [normalized for item in value if (normalized := _known_string(item))]


def _looks_like_role_definition_reference(reference: str | None) -> bool:
    return bool(reference and reference.strip().lower().startswith("azurerm_role_definition."))


def _get_string(resource: NormalizedResource, field: object) -> str | None:
    return _known_string(resource.get_metadata_field(field))


def _get_list(resource: NormalizedResource, field: object) -> tuple[str, ...]:
    value = resource.get_metadata_field(field)
    if not isinstance(value, list | tuple):
        return ()
    return tuple(normalized for item in value if (normalized := _known_string(item)))


def _known_string(value: object) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _dedupe(values: Iterable[str | None]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if value is None:
            continue
        normalized = str(value).strip()
        if not normalized or normalized in seen or normalized.endswith("=None"):
            continue
        seen.add(normalized)
        deduped.append(normalized)
    return deduped


def _append_unique(values: list[PrivilegeCategory], value: PrivilegeCategory) -> None:
    if value not in values:
        values.append(value)
