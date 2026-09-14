from __future__ import annotations

from tfstride.analysis.resource_concepts import (
    is_database_resource,
    is_key_management_resource,
    is_object_storage_resource,
    is_secret_store_resource,
)
from tfstride.models import NormalizedResource
from tfstride.providers.gcp.custom_role_index import (
    GcpCustomRoleIndex,
    custom_role_permissions,
)
from tfstride.providers.gcp.custom_role_index import (
    build_gcp_custom_role_index as build_gcp_custom_role_index,
)

_PRIVILEGE_ESCALATION_PERMISSIONS = frozenset(
    {
        "cloudbuild.builds.create",
        "cloudfunctions.functions.update",
        "compute.instances.setMetadata",
        "compute.instances.setServiceAccount",
        "iam.roles.create",
        "iam.roles.delete",
        "iam.roles.update",
        "iam.serviceAccounts.actAs",
        "iam.serviceAccounts.getAccessToken",
        "iam.serviceAccounts.getOpenIdToken",
        "iam.serviceAccounts.implicitDelegation",
        "iam.serviceAccounts.setIamPolicy",
        "iam.serviceAccounts.signBlob",
        "iam.serviceAccounts.signJwt",
        "resourcemanager.iam.projects.setIamPolicy",
        "run.services.update",
    }
)


def custom_role_privilege_risk(role: str | None, custom_roles: GcpCustomRoleIndex) -> str | None:
    permissions = custom_role_permissions(role, custom_roles)
    risky_permissions = _privileged_permissions(permissions)
    if not risky_permissions:
        return None
    permission_text = ", ".join(risky_permissions[:4])
    if len(risky_permissions) > 4:
        permission_text = f"{permission_text}, and {len(risky_permissions) - 4} more"
    return f"custom role includes high-impact permissions: {permission_text}"


def custom_role_allows_data_store_access(
    resource: NormalizedResource,
    role: str | None,
    custom_roles: GcpCustomRoleIndex,
) -> bool:
    permissions = custom_role_permissions(role, custom_roles)
    if not permissions:
        return False
    if _permission_matches_any(permissions, {"*"}):
        return True
    if is_object_storage_resource(resource):
        return _permission_matches_any(
            permissions,
            {
                "storage.*",
                "storage.objects.*",
                "storage.objects.create",
                "storage.objects.delete",
                "storage.objects.get",
                "storage.objects.list",
                "storage.objects.update",
            },
        )
    if is_secret_store_resource(resource):
        return _permission_matches_any(
            permissions,
            {
                "secretmanager.*",
                "secretmanager.secrets.*",
                "secretmanager.versions.*",
                "secretmanager.versions.access",
            },
        )
    if is_key_management_resource(resource):
        return _permission_matches_any(
            permissions,
            {
                "cloudkms.*",
                "cloudkms.cryptoKeyVersions.*",
                "cloudkms.cryptoKeyVersions.useToDecrypt",
                "cloudkms.cryptoKeyVersions.useToEncrypt",
                "cloudkms.cryptoKeys.*",
            },
        )
    if is_database_resource(resource):
        return _permission_matches_any(
            permissions,
            {
                "cloudsql.*",
                "cloudsql.instances.*",
                "cloudsql.instances.connect",
                "cloudsql.instances.get",
            },
        )
    if resource.resource_type in {"google_bigquery_dataset", "google_bigquery_table"}:
        return _permission_matches_any(
            permissions,
            {
                "bigquery.*",
                "bigquery.datasets.*",
                "bigquery.datasets.get",
                "bigquery.jobs.create",
                "bigquery.tables.*",
                "bigquery.tables.get",
                "bigquery.tables.getData",
                "bigquery.tables.list",
                "bigquery.tables.update",
            },
        )
    if resource.resource_type in {"google_pubsub_subscription", "google_pubsub_topic"}:
        return _permission_matches_any(
            permissions,
            {
                "pubsub.*",
                "pubsub.subscriptions.*",
                "pubsub.subscriptions.consume",
                "pubsub.subscriptions.get",
                "pubsub.topics.*",
                "pubsub.topics.get",
                "pubsub.topics.publish",
            },
        )
    return False


def _privileged_permissions(permissions: tuple[str, ...]) -> tuple[str, ...]:
    risky: list[str] = []
    for permission in permissions:
        normalized = permission.strip()
        if not normalized:
            continue
        if normalized == "*" or normalized.endswith(".*"):
            risky.append(normalized)
            continue
        if normalized in _PRIVILEGE_ESCALATION_PERMISSIONS or normalized.endswith(".setIamPolicy"):
            risky.append(normalized)
    return tuple(risky)


def _permission_matches_any(permissions: tuple[str, ...], candidates: set[str]) -> bool:
    for permission in permissions:
        normalized = permission.strip()
        if not normalized:
            continue
        if normalized in candidates:
            return True
        if normalized.endswith(".*"):
            prefix = normalized[:-1]
            if any(candidate.startswith(prefix) for candidate in candidates):
                return True
    return False
