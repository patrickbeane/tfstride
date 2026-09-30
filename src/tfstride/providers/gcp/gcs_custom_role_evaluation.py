"""Custom-role grantability for inherited GCS authority over modeled buckets.

Role resolution alone is insufficient: role ownership, the grant attachment,
permissions, and lifecycle must all be established. Bucket-local evaluation
retains its existing contract during this bounded migration.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.custom_role_index import GcpCustomRoleIndex
from tfstride.providers.gcp.gcs_grant_ancestry import ancestor_scope, bucket_hierarchy
from tfstride.providers.gcp.gcs_project_grants import project_identity, project_scope_matches
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.protected_data_evidence import GcsInheritedCustomRoleEvidence
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpResourceIndex
from tfstride.providers.gcp.resource_types import GCP_PROJECT_IAM_RESOURCE_TYPES, GcpResourceType
from tfstride.providers.gcp.resource_utils import gcp_reference_key
from tfstride.providers.resource_reference_index import ResourceReferenceIndex

_ACTIVE_STAGES = {"ALPHA", "BETA", "DEPRECATED", "EAP", "GA"}
_NATIVE_ROLE = re.compile(r"(projects|organizations)/([^/]+)/roles/([^/]+)")


@dataclass(frozen=True, slots=True)
class GcsInheritedCustomRoleAssessment:
    state: Literal["compatible", "incompatible", "inactive", "unknown"]
    reason: str
    permissions: tuple[str, ...] = ()
    evidence: GcsInheritedCustomRoleEvidence | None = None


def assess_inherited_gcs_custom_role(
    role: str,
    source: NormalizedResource,
    bucket: NormalizedResource,
    custom_roles: GcpCustomRoleIndex,
    index: GcpResourceIndex,
    projects: ResourceReferenceIndex,
) -> GcsInheritedCustomRoleAssessment:
    """Assess a role only after the caller establishes grant-to-bucket applicability."""
    resolution = custom_roles.resolve(role)
    definition = resolution.selected_candidate
    if definition is None:
        return GcsInheritedCustomRoleAssessment("unknown", f"custom role resolution is {resolution.state}")
    reference = gcp_reference_key(role, suffixes=(".id", ".name"))
    if reference != definition.address and not _NATIVE_ROLE.fullmatch(reference):
        return GcsInheritedCustomRoleAssessment("unknown", "custom role reference does not establish a scoped identity")
    facts = gcp_facts(definition)
    is_project = definition.resource_type == GcpResourceType.PROJECT_IAM_CUSTOM_ROLE
    kind = "projects" if is_project else "organizations"
    owner = project_identity(facts.project, projects) if is_project else facts.organization_id
    if not is_project:
        organization = ancestor_scope(owner, "organizations", index)
        owner = organization.key.removeprefix("organizations/") if organization else None
    if owner is None:
        return GcsInheritedCustomRoleAssessment("unknown", "custom role ownership is unresolved")
    # Conflicting planned name/id and owner fields must not manufacture a role
    # in whichever namespace would make the binding applicable.
    for value in (reference, definition.identifier, definition.get_metadata_field(GcpResourceMetadata.NAME)):
        match = _NATIVE_ROLE.fullmatch(value or "")
        if match is None:
            continue
        native_owner = project_identity(match[2], projects) if is_project else match[2]
        same_owner = project_scope_matches(owner, native_owner) if is_project else owner == native_owner
        if match[1] != kind or same_owner is not True or (facts.custom_role_id and match[3] != facts.custom_role_id):
            return GcsInheritedCustomRoleAssessment("unknown", "custom role identity and ownership conflict")
    if is_project:
        if source.resource_type not in GCP_PROJECT_IAM_RESOURCE_TYPES:
            return GcsInheritedCustomRoleAssessment(
                "incompatible", "project custom roles cannot be granted at folder or organization scope"
            )
        compatible = project_scope_matches(owner, project_identity(gcp_facts(source).project, projects))
    else:
        compatible = bucket_hierarchy(bucket, index).contains(ancestor_scope(owner, "organizations", index))
    if compatible is not True:
        return GcsInheritedCustomRoleAssessment(
            "incompatible" if compatible is False else "unknown",
            "custom role is not established as grantable at the inherited scope",
        )
    stage = facts.custom_role_stage.upper() if facts.custom_role_stage else None
    if facts.custom_role_deleted is True or stage == "DISABLED":
        return GcsInheritedCustomRoleAssessment("inactive", "custom role is deleted or disabled")
    if facts.custom_role_deleted is not False or stage not in _ACTIVE_STAGES:
        return GcsInheritedCustomRoleAssessment("unknown", "custom role lifecycle is unresolved or unsupported")
    permissions = tuple(sorted(set(facts.custom_role_permissions)))
    if facts.custom_role_permissions_state != "configured" or not permissions:
        return GcsInheritedCustomRoleAssessment("unknown", "custom role permissions are unresolved")
    if any(
        not re.fullmatch(r"[a-z][a-z0-9]*\.[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)+", permission) for permission in permissions
    ):
        return GcsInheritedCustomRoleAssessment("unknown", "custom role contains unsupported permission syntax")
    assert stage is not None
    return GcsInheritedCustomRoleAssessment(
        "compatible",
        "active custom role with compatible inherited scope",
        permissions,
        GcsInheritedCustomRoleEvidence(
            role_definition_address=definition.address,
            role_scope=f"{kind}/{owner}",
            grant_scope_compatibility="compatible",
            stage=stage,
            deleted=False,
        ),
    )
