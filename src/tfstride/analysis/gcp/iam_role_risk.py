from __future__ import annotations

from tfstride.analysis.gcp.custom_roles import GcpCustomRoleIndex, custom_role_privilege_risk

_PRIVILEGED_GCP_PROJECT_ROLES: dict[str, str] = {
    "roles/owner": "full project administration",
    "roles/editor": "broad write access across most project services",
    "roles/iam.serviceAccountTokenCreator": "service account token minting and impersonation",
    "roles/iam.serviceAccountUser": "service account attachment and impersonation paths",
    "roles/iam.serviceAccountAdmin": "service account administration",
    "roles/iam.securityAdmin": "IAM policy and security-control administration",
    "roles/resourcemanager.iam.projectIamAdmin": "project IAM policy administration",
}

_PRIVILEGED_GCP_ORG_FOLDER_ROLES: dict[str, str] = {
    **_PRIVILEGED_GCP_PROJECT_ROLES,
    "roles/accesscontextmanager.policyAdmin": "access policy administration across protected resources",
    "roles/billing.admin": "billing account administration and project billing linkage control",
    "roles/iam.organizationRoleAdmin": "custom role administration at organization scope",
    "roles/orgpolicy.policyAdmin": "organization policy administration",
    "roles/resourcemanager.folderAdmin": "folder hierarchy administration",
    "roles/resourcemanager.organizationAdmin": "organization-level resource administration",
    "roles/resourcemanager.iam.projectCreator": "project creation under the organization or folder",
    "roles/resourcemanager.iam.projectDeleter": "project deletion under the organization or folder",
}


def privileged_project_role_risk(
    role: str | None,
    custom_roles: GcpCustomRoleIndex | None = None,
) -> str | None:
    return _privileged_gcp_role_risk(
        role,
        predefined_roles=_PRIVILEGED_GCP_PROJECT_ROLES,
        admin_risk="admin-level control over a GCP service or project security surface",
        custom_roles=custom_roles,
    )


def privileged_org_folder_role_risk(
    role: str | None,
    custom_roles: GcpCustomRoleIndex | None = None,
) -> str | None:
    return _privileged_gcp_role_risk(
        role,
        predefined_roles=_PRIVILEGED_GCP_ORG_FOLDER_ROLES,
        admin_risk="admin-level control over a GCP organization, folder, or descendant project surface",
        custom_roles=custom_roles,
    )


def _privileged_gcp_role_risk(
    role: str | None,
    *,
    predefined_roles: dict[str, str],
    admin_risk: str,
    custom_roles: GcpCustomRoleIndex | None = None,
) -> str | None:
    if not role:
        return None
    normalized_role = role.strip()
    if normalized_role in predefined_roles:
        return predefined_roles[normalized_role]
    role_name = normalized_role.rsplit("/", 1)[-1].lower()
    if normalized_role.startswith("roles/") and "admin" in role_name:
        return admin_risk
    if custom_roles is not None:
        return custom_role_privilege_risk(normalized_role, custom_roles)
    return None
