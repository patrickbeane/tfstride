from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from tfstride.analysis.resource_facts import analysis_facts
from tfstride.models import NormalizedResource
from tfstride.providers.gcp.constants import GCP_ORGANIZATION_POLICY_RESOURCE_TYPES
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.resource_metadata import MetadataField


GCP_ORG_POLICY_SCOPE_ORGANIZATION = "organization"
GCP_ORG_POLICY_SCOPE_FOLDER = "folder"
GCP_ORG_POLICY_SCOPE_PROJECT = "project"


@dataclass(frozen=True, slots=True)
class GcpOrgPolicyScopeKey:
    scope_type: str
    identifier: str

    @property
    def label(self) -> str:
        return f"{self.scope_type}:{self.identifier}"


@dataclass(frozen=True, slots=True)
class GcpOrgPolicyGuardrail:
    resource: NormalizedResource
    scope: GcpOrgPolicyScopeKey
    constraint: str
    rules: tuple[Mapping[str, Any], ...]
    allowed_values: tuple[str, ...]
    denied_values: tuple[str, ...]
    enforced: bool | None
    inherit_from_parent: bool | None
    restore_default: bool


@dataclass(frozen=True, slots=True)
class GcpOrgPolicyGuardrailIndex:
    guardrails_by_scope: Mapping[GcpOrgPolicyScopeKey, tuple[GcpOrgPolicyGuardrail, ...]]
    guardrails_by_constraint: Mapping[str, tuple[GcpOrgPolicyGuardrail, ...]]
    guardrails_by_scope_and_constraint: Mapping[
        tuple[GcpOrgPolicyScopeKey, str],
        tuple[GcpOrgPolicyGuardrail, ...],
    ]
    unresolved_policy_resources: tuple[NormalizedResource, ...]

    def direct_guardrails_for_scope(
        self,
        scope: GcpOrgPolicyScopeKey,
    ) -> tuple[GcpOrgPolicyGuardrail, ...]:
        return self.guardrails_by_scope.get(scope, ())

    def direct_guardrails_for_constraint(
        self,
        scope: GcpOrgPolicyScopeKey,
        constraint: str,
    ) -> tuple[GcpOrgPolicyGuardrail, ...]:
        return self.guardrails_by_scope_and_constraint.get((scope, constraint), ())

    def effective_guardrails_for_resource(
        self,
        resource: NormalizedResource,
        *,
        constraint: str | None = None,
    ) -> tuple[GcpOrgPolicyGuardrail, ...]:
        return _effective_guardrails_for_scope_chain(
            self,
            _resource_scope_chain(resource),
            constraint=constraint,
        )

    def effective_guardrails_for_scope_chain(
        self,
        scopes: Iterable[GcpOrgPolicyScopeKey],
        *,
        constraint: str | None = None,
    ) -> tuple[GcpOrgPolicyGuardrail, ...]:
        return _effective_guardrails_for_scope_chain(self, tuple(scopes), constraint=constraint)


_EMPTY_GCP_ORG_POLICY_GUARDRAIL_INDEX = GcpOrgPolicyGuardrailIndex(
    guardrails_by_scope=MappingProxyType({}),
    guardrails_by_constraint=MappingProxyType({}),
    guardrails_by_scope_and_constraint=MappingProxyType({}),
    unresolved_policy_resources=(),
)


def empty_gcp_org_policy_guardrail_index() -> GcpOrgPolicyGuardrailIndex:
    return _EMPTY_GCP_ORG_POLICY_GUARDRAIL_INDEX


def build_gcp_org_policy_guardrail_index(
    resources: Iterable[NormalizedResource],
) -> GcpOrgPolicyGuardrailIndex:
    resource_tuple = tuple(resources)
    if not any(resource.provider == "gcp" for resource in resource_tuple):
        return empty_gcp_org_policy_guardrail_index()

    guardrails_by_scope: dict[GcpOrgPolicyScopeKey, list[GcpOrgPolicyGuardrail]] = {}
    guardrails_by_constraint: dict[str, list[GcpOrgPolicyGuardrail]] = {}
    guardrails_by_scope_and_constraint: dict[
        tuple[GcpOrgPolicyScopeKey, str],
        list[GcpOrgPolicyGuardrail],
    ] = {}
    unresolved_policy_resources: list[NormalizedResource] = []

    for resource in resource_tuple:
        if resource.resource_type not in GCP_ORGANIZATION_POLICY_RESOURCE_TYPES:
            continue
        guardrail = _guardrail_from_resource(resource)
        if guardrail is None:
            unresolved_policy_resources.append(resource)
            continue
        guardrails_by_scope.setdefault(guardrail.scope, []).append(guardrail)
        guardrails_by_constraint.setdefault(guardrail.constraint, []).append(guardrail)
        guardrails_by_scope_and_constraint.setdefault(
            (guardrail.scope, guardrail.constraint),
            [],
        ).append(guardrail)

    return GcpOrgPolicyGuardrailIndex(
        guardrails_by_scope=_freeze_guardrail_groups(guardrails_by_scope),
        guardrails_by_constraint=MappingProxyType(
            {constraint: tuple(guardrails) for constraint, guardrails in guardrails_by_constraint.items()}
        ),
        guardrails_by_scope_and_constraint=MappingProxyType(
            {key: tuple(guardrails) for key, guardrails in guardrails_by_scope_and_constraint.items()}
        ),
        unresolved_policy_resources=tuple(unresolved_policy_resources),
    )


def _guardrail_from_resource(resource: NormalizedResource) -> GcpOrgPolicyGuardrail | None:
    constraint = resource.get_metadata_field(GcpResourceMetadata.ORG_POLICY_CONSTRAINT)
    scope = _policy_scope(resource)
    if constraint is None or scope is None:
        return None
    return GcpOrgPolicyGuardrail(
        resource=resource,
        scope=scope,
        constraint=constraint,
        rules=tuple(resource.get_metadata_field(GcpResourceMetadata.ORG_POLICY_RULES)),
        allowed_values=tuple(resource.get_metadata_field(GcpResourceMetadata.ORG_POLICY_ALLOWED_VALUES)),
        denied_values=tuple(resource.get_metadata_field(GcpResourceMetadata.ORG_POLICY_DENIED_VALUES)),
        enforced=_optional_bool_metadata(resource, GcpResourceMetadata.ORG_POLICY_ENFORCED),
        inherit_from_parent=_optional_bool_metadata(
            resource,
            GcpResourceMetadata.ORG_POLICY_INHERIT_FROM_PARENT,
        ),
        restore_default=resource.get_metadata_field(GcpResourceMetadata.ORG_POLICY_RESTORE_DEFAULT),
    )


def _policy_scope(resource: NormalizedResource) -> GcpOrgPolicyScopeKey | None:
    scope_type = resource.get_metadata_field(GcpResourceMetadata.ORG_POLICY_SCOPE_TYPE)
    scope = resource.get_metadata_field(GcpResourceMetadata.ORG_POLICY_SCOPE)
    if scope_type == GCP_ORG_POLICY_SCOPE_PROJECT:
        identifier = _normalize_project_id(
            resource.get_metadata_field(GcpResourceMetadata.PROJECT)
            or _path_segment(scope, "projects")
            or scope
        )
    elif scope_type == GCP_ORG_POLICY_SCOPE_FOLDER:
        identifier = _normalize_hierarchy_id(
            resource.get_metadata_field(GcpResourceMetadata.FOLDER_ID)
            or _path_segment(scope, "folders")
            or scope,
            "folders",
        )
    elif scope_type == GCP_ORG_POLICY_SCOPE_ORGANIZATION:
        identifier = _normalize_hierarchy_id(
            resource.get_metadata_field(GcpResourceMetadata.ORGANIZATION_ID)
            or _path_segment(scope, "organizations")
            or scope,
            "organizations",
        )
    else:
        return None
    if not identifier:
        return None
    return GcpOrgPolicyScopeKey(scope_type, identifier)


def _resource_scope_chain(resource: NormalizedResource) -> tuple[GcpOrgPolicyScopeKey, ...]:
    facts = analysis_facts(resource)
    scopes: list[GcpOrgPolicyScopeKey] = []
    organization_id = _resource_organization_id(resource)
    folder_id = _resource_folder_id(resource)
    project = _normalize_project_id(facts.iam.project) or _project_from_resource(resource)
    if organization_id:
        scopes.append(GcpOrgPolicyScopeKey(GCP_ORG_POLICY_SCOPE_ORGANIZATION, organization_id))
    if folder_id:
        scopes.append(GcpOrgPolicyScopeKey(GCP_ORG_POLICY_SCOPE_FOLDER, folder_id))
    if project:
        scopes.append(GcpOrgPolicyScopeKey(GCP_ORG_POLICY_SCOPE_PROJECT, project))
    return tuple(scopes)


def _effective_guardrails_for_scope_chain(
    index: GcpOrgPolicyGuardrailIndex,
    scopes: tuple[GcpOrgPolicyScopeKey, ...],
    *,
    constraint: str | None,
) -> tuple[GcpOrgPolicyGuardrail, ...]:
    effective_by_constraint: dict[str, list[GcpOrgPolicyGuardrail]] = {}
    constraint_order: list[str] = []
    for scope in scopes:
        for guardrail in index.direct_guardrails_for_scope(scope):
            if constraint is not None and guardrail.constraint != constraint:
                continue
            if guardrail.constraint not in effective_by_constraint:
                constraint_order.append(guardrail.constraint)
            existing = effective_by_constraint.get(guardrail.constraint, [])
            if guardrail.restore_default or guardrail.inherit_from_parent is False:
                existing = []
            existing.append(guardrail)
            effective_by_constraint[guardrail.constraint] = existing

    effective: list[GcpOrgPolicyGuardrail] = []
    for constraint_key in constraint_order:
        effective.extend(effective_by_constraint[constraint_key])
    return tuple(effective)


def _resource_organization_id(resource: NormalizedResource) -> str | None:
    facts = analysis_facts(resource)
    organization_id = _normalize_hierarchy_id(facts.iam.organization_id, "organizations")
    if organization_id:
        return organization_id
    for value in _scope_candidate_values(resource):
        organization_id = _path_segment(value, "organizations")
        if organization_id:
            return organization_id
    return None


def _resource_folder_id(resource: NormalizedResource) -> str | None:
    facts = analysis_facts(resource)
    folder_id = _normalize_hierarchy_id(facts.iam.folder_id, "folders")
    if folder_id:
        return folder_id
    for value in _scope_candidate_values(resource):
        folder_id = _path_segment(value, "folders")
        if folder_id:
            return folder_id
    return None


def _project_from_resource(resource: NormalizedResource) -> str | None:
    for value in _scope_candidate_values(resource):
        project = _path_segment(value, "projects")
        if project:
            return project
    return None


def _scope_candidate_values(resource: NormalizedResource) -> tuple[str, ...]:
    facts = analysis_facts(resource)
    values: list[str] = []
    for value in (resource.identifier, facts.iam.resource_name):
        if value:
            values.append(str(value))
    values.extend(facts.iam.reference_values)
    return tuple(values)


def _normalize_project_id(value: object) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    if not text:
        return None
    return _path_segment(text, "projects") or text


def _normalize_hierarchy_id(value: object, marker: str) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    if not text:
        return None
    return _path_segment(text, marker) or text


def _path_segment(value: object, marker: str) -> str | None:
    if value in (None, ""):
        return None
    parts = [part for part in str(value).strip().split("/") if part]
    try:
        marker_index = parts.index(marker)
    except ValueError:
        return None
    value_index = marker_index + 1
    if value_index >= len(parts):
        return None
    return parts[value_index] or None


def _optional_bool_metadata(resource: NormalizedResource, field: MetadataField[bool]) -> bool | None:
    if not resource.has_metadata_field(field):
        return None
    if resource.metadata_snapshot().get(field.key) is None:
        return None
    return resource.get_metadata_field(field)


def _freeze_guardrail_groups(
    groups: dict[GcpOrgPolicyScopeKey, list[GcpOrgPolicyGuardrail]],
) -> Mapping[GcpOrgPolicyScopeKey, tuple[GcpOrgPolicyGuardrail, ...]]:
    return MappingProxyType({scope: tuple(guardrails) for scope, guardrails in groups.items()})