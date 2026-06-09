from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from tfstride.analysis.resource_concepts import (
    is_database_resource,
    is_key_management_resource,
    is_object_storage_resource,
    is_secret_store_resource,
)
from tfstride.analysis.resource_facts import analysis_facts
from tfstride.models import NormalizedResource
from tfstride.providers.gcp.resource_utils import GCP_ROLE_REFERENCE_SUFFIXES, gcp_reference_key


GCP_CUSTOM_ROLE_RESOURCE_TYPES = frozenset(
    {"google_project_iam_custom_role", "google_organization_iam_custom_role"}
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


@dataclass(frozen=True, slots=True)
class GcpCustomRoleIndex:
    permissions_by_reference: Mapping[str, tuple[str, ...]]


def build_gcp_custom_role_index(resources: Iterable[NormalizedResource]) -> GcpCustomRoleIndex:
    permissions_by_reference: dict[str, tuple[str, ...]] = {}
    for resource in resources:
        if resource.resource_type not in GCP_CUSTOM_ROLE_RESOURCE_TYPES:
            continue
        permissions = tuple(sorted(set(analysis_facts(resource).iam.custom_role_permissions)))
        if not permissions:
            continue
        for reference in _custom_role_references(resource):
            permissions_by_reference.setdefault(gcp_reference_key(reference, GCP_ROLE_REFERENCE_SUFFIXES), permissions)
    return GcpCustomRoleIndex(MappingProxyType(permissions_by_reference))


def custom_role_permissions(role: str | None, custom_roles: GcpCustomRoleIndex) -> tuple[str, ...]:
    if not role:
        return ()
    return custom_roles.permissions_by_reference.get(gcp_reference_key(role, GCP_ROLE_REFERENCE_SUFFIXES), ())


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


def _custom_role_references(resource: NormalizedResource) -> set[str]:
    facts = analysis_facts(resource)
    references = {
        resource.address,
        f"{resource.address}.id",
        f"{resource.address}.name",
        f"{resource.address}.role_id",
        resource.identifier,
        resource.name,
        facts.iam.resource_name,
        facts.iam.custom_role_id,
    }
    if facts.iam.project and facts.iam.custom_role_id:
        references.add(f"projects/{facts.iam.project}/roles/{facts.iam.custom_role_id}")
    return {str(reference).strip() for reference in references if reference not in (None, "")}


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