from __future__ import annotations

from collections.abc import Collection
from typing import Any

from tfstride.models import (
    NormalizedResource,
    TerraformReferenceProvenance,
    TerraformReferenceResolutionState,
)
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext
from tfstride.providers.gcp.resource_types import (
    GCP_ARTIFACT_REGISTRY_REPOSITORY_IAM_RESOURCE_TYPES,
    GCP_BIGQUERY_DATASET_IAM_RESOURCE_TYPES,
    GCP_BIGQUERY_TABLE_IAM_RESOURCE_TYPES,
    GCP_CLOUD_FUNCTION_IAM_RESOURCE_TYPES,
    GCP_CLOUD_FUNCTION_RESOURCE_TYPES,
    GCP_CLOUD_RUN_IAM_RESOURCE_TYPES,
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    GCP_KMS_CRYPTO_KEY_IAM_RESOURCE_TYPES,
    GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GCP_PUBSUB_SUBSCRIPTION_IAM_RESOURCE_TYPES,
    GCP_PUBSUB_TOPIC_IAM_RESOURCE_TYPES,
    GCP_SECRET_MANAGER_SECRET_IAM_RESOURCE_TYPES,
    GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES,
    GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.gcp.resource_utils import gcp_reference_key, service_account_member
from tfstride.resource_metadata import OptionalStringMetadataField

_GENERIC_REFERENCE_SUFFIXES = (".id", ".name", ".self_link")
_PROJECT_REFERENCE_SUFFIXES = (".id", ".name", ".project_id")
_SERVICE_ACCOUNT_REFERENCE_SUFFIXES = (".email", ".id", ".member", ".name")
_CLOUD_RUN_SERVICE_ACCOUNT_REFERENCE_SUFFIXES = (".email",)
_IAM_MEMBER_REFERENCE_SUFFIXES = (".email", ".member")
_SECRET_IAM_REFERENCE_SUFFIXES = (".secret_id",)
_SECRET_VERSION_PARENT_SUFFIXES = (".id",)
_KMS_VERSION_KEY_SUFFIXES = (".id",)
_KMS_KEY_RING_PARENT_SUFFIXES = (".id",)
_KMS_CRYPTO_KEY_IAM_SUFFIXES = (".id",)
_KMS_KEY_RING_IAM_SUFFIXES = (".id",)
_CLOUD_RUN_SERVICE_ACCOUNT_PATHS = {
    ("template", 0, "service_account"),
    ("template", 0, "spec", 0, "service_account_name"),
}


def _relationship(
    resource_types: Collection[str],
    field: OptionalStringMetadataField,
    target_types: Collection[str],
    source_paths: Collection[tuple[str | int, ...]],
    suffixes: Collection[str],
) -> tuple[set[str], OptionalStringMetadataField, set[str], set[tuple[str | int, ...]], tuple[str, ...]]:
    return (
        set(resource_types),
        field,
        set(target_types),
        set(source_paths),
        tuple(suffixes),
    )


_IAM_TARGET_RELATIONSHIPS = (
    _relationship(
        GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES,
        GcpResourceMetadata.SERVICE_ACCOUNT_REFERENCE,
        {GcpResourceType.SERVICE_ACCOUNT},
        {("service_account",), ("service_account_id",)},
        _SERVICE_ACCOUNT_REFERENCE_SUFFIXES,
    ),
    _relationship(
        GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES,
        GcpResourceMetadata.BUCKET_NAME,
        {GcpResourceType.STORAGE_BUCKET},
        {("bucket",)},
        _GENERIC_REFERENCE_SUFFIXES,
    ),
    _relationship(
        GCP_SECRET_MANAGER_SECRET_IAM_RESOURCE_TYPES,
        GcpResourceMetadata.SECRET_REFERENCE,
        {GcpResourceType.SECRET_MANAGER_SECRET},
        {("secret_id",)},
        _SECRET_IAM_REFERENCE_SUFFIXES,
    ),
    _relationship(
        GCP_PUBSUB_TOPIC_IAM_RESOURCE_TYPES,
        GcpResourceMetadata.PUBSUB_TOPIC_REFERENCE,
        {GcpResourceType.PUBSUB_TOPIC},
        {("topic",), ("topic_id",)},
        _GENERIC_REFERENCE_SUFFIXES,
    ),
    _relationship(
        GCP_PUBSUB_SUBSCRIPTION_IAM_RESOURCE_TYPES,
        GcpResourceMetadata.PUBSUB_SUBSCRIPTION_REFERENCE,
        {GcpResourceType.PUBSUB_SUBSCRIPTION},
        {("subscription",), ("subscription_id",)},
        _GENERIC_REFERENCE_SUFFIXES,
    ),
    _relationship(
        GCP_BIGQUERY_DATASET_IAM_RESOURCE_TYPES,
        GcpResourceMetadata.BIGQUERY_DATASET_REFERENCE,
        {GcpResourceType.BIGQUERY_DATASET},
        {("dataset_id",), ("dataset",)},
        (".dataset_id", ".id", ".name", ".self_link"),
    ),
    _relationship(
        GCP_BIGQUERY_TABLE_IAM_RESOURCE_TYPES,
        GcpResourceMetadata.BIGQUERY_TABLE_REFERENCE,
        {GcpResourceType.BIGQUERY_TABLE},
        {("table_id",), ("table",)},
        (".table_id", ".id", ".name", ".self_link"),
    ),
    _relationship(
        GCP_KMS_CRYPTO_KEY_IAM_RESOURCE_TYPES,
        GcpResourceMetadata.KMS_CRYPTO_KEY_REFERENCE,
        {GcpResourceType.KMS_CRYPTO_KEY},
        {("crypto_key_id",), ("crypto_key",)},
        _KMS_CRYPTO_KEY_IAM_SUFFIXES,
    ),
    _relationship(
        GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES,
        GcpResourceMetadata.KMS_KEY_RING,
        {GcpResourceType.KMS_KEY_RING},
        {("key_ring_id",), ("key_ring",)},
        _KMS_KEY_RING_IAM_SUFFIXES,
    ),
    _relationship(
        GCP_CLOUD_RUN_IAM_RESOURCE_TYPES,
        GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE,
        set(GCP_CLOUD_RUN_RESOURCE_TYPES),
        {("service",), ("name",)},
        _GENERIC_REFERENCE_SUFFIXES,
    ),
    _relationship(
        GCP_CLOUD_FUNCTION_IAM_RESOURCE_TYPES,
        GcpResourceMetadata.CLOUD_FUNCTION_REFERENCE,
        set(GCP_CLOUD_FUNCTION_RESOURCE_TYPES),
        {("cloud_function",), ("function",), ("name",)},
        _GENERIC_REFERENCE_SUFFIXES,
    ),
    _relationship(
        GCP_ARTIFACT_REGISTRY_REPOSITORY_IAM_RESOURCE_TYPES,
        GcpResourceMetadata.ARTIFACT_REGISTRY_REPOSITORY_REFERENCE,
        {GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY},
        {("repository",), ("repository_id",)},
        _GENERIC_REFERENCE_SUFFIXES,
    ),
)


class ResolveGcpSymbolicRelationshipsStage:
    """Adopt exact, provider-approved symbolic Terraform relationships."""

    name = "resolve_gcp_symbolic_relationships"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: GcpDecorationContext,
    ) -> None:
        for resource in resources:
            if resource.resource_type in GCP_CLOUD_RUN_RESOURCE_TYPES:
                self._resolve_cloud_run_service_account(resource, context)
            elif resource.resource_type == GcpResourceType.PUBSUB_SUBSCRIPTION:
                self._resolve_pubsub_topic(resource, context)
            elif resource.resource_type == GcpResourceType.SECRET_MANAGER_SECRET_VERSION:
                self._resolve_secret_version_parent(resource, context)
            elif resource.resource_type == GcpResourceType.KMS_CRYPTO_KEY_VERSION:
                self._resolve_kms_version_key(resource, context)
            elif resource.resource_type == GcpResourceType.KMS_CRYPTO_KEY:
                self._resolve_kms_key_ring(resource, context)

            self._resolve_iam_member(resource, context)
            self._resolve_iam_target(resource, context)

    def _resolve_cloud_run_service_account(
        self,
        resource: NormalizedResource,
        context: GcpDecorationContext,
    ) -> None:
        facts = gcp_facts(resource)
        if facts.service_account_email:
            return
        target = _symbolic_target(
            resource,
            context,
            allowed_paths=_CLOUD_RUN_SERVICE_ACCOUNT_PATHS,
            expected_resource_types={GcpResourceType.SERVICE_ACCOUNT},
            expected_reference_suffixes=_CLOUD_RUN_SERVICE_ACCOUNT_REFERENCE_SUFFIXES,
        )
        if target is None:
            return
        email = _service_account_email(target)
        if email is None:
            return
        facts.set(GcpResourceMetadata.SERVICE_ACCOUNT_EMAIL, email)
        facts.set(GcpResourceMetadata.SERVICE_ACCOUNT_MEMBER, service_account_member(email))
        facts.set(GcpResourceMetadata.SERVICE_ACCOUNTS, [{"email": email}])
        facts.set(GcpResourceMetadata.SERVICE_ACCOUNT_REFERENCE, target.address)

    def _resolve_pubsub_topic(
        self,
        resource: NormalizedResource,
        context: GcpDecorationContext,
    ) -> None:
        facts = gcp_facts(resource)
        if facts.pubsub_topic_reference:
            return
        target = _symbolic_target(
            resource,
            context,
            allowed_paths={("topic",)},
            expected_resource_types={GcpResourceType.PUBSUB_TOPIC},
            expected_reference_suffixes=_GENERIC_REFERENCE_SUFFIXES,
        )
        if target is not None:
            facts.set(
                GcpResourceMetadata.PUBSUB_TOPIC_REFERENCE,
                _canonical_reference(target),
            )

    def _resolve_secret_version_parent(
        self,
        resource: NormalizedResource,
        context: GcpDecorationContext,
    ) -> None:
        facts = gcp_facts(resource)
        if facts.secret_manager_version_resolved_secret_address:
            return
        target = _symbolic_target(
            resource,
            context,
            allowed_paths={("secret",)},
            expected_resource_types={GcpResourceType.SECRET_MANAGER_SECRET},
            expected_reference_suffixes=_SECRET_VERSION_PARENT_SUFFIXES,
        )
        if target is not None:
            facts.set(
                GcpResourceMetadata.SECRET_MANAGER_VERSION_RESOLVED_SECRET_ADDRESS,
                target.address,
            )

    def _resolve_kms_version_key(
        self,
        resource: NormalizedResource,
        context: GcpDecorationContext,
    ) -> None:
        facts = gcp_facts(resource)
        if facts.kms_crypto_key_version_crypto_key_reference or facts.kms_crypto_key_version_crypto_key_path:
            return
        target = _symbolic_target(
            resource,
            context,
            allowed_paths={("crypto_key",)},
            expected_resource_types={GcpResourceType.KMS_CRYPTO_KEY},
            expected_reference_suffixes=_KMS_VERSION_KEY_SUFFIXES,
        )
        if target is None:
            return
        key_reference = _canonical_reference(target)
        if not facts.kms_crypto_key_version_crypto_key_reference:
            facts.set(
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_CRYPTO_KEY_REFERENCE,
                key_reference,
            )
        key_path = _canonical_kms_key_path(target)
        if key_path and not facts.kms_crypto_key_version_crypto_key_path:
            facts.set(
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_CRYPTO_KEY_PATH,
                key_path,
            )
        target_facts = gcp_facts(target)
        if target_facts.project and not facts.project:
            facts.set(GcpResourceMetadata.PROJECT, target_facts.project)
        if target_facts.kms_key_ring and not facts.kms_crypto_key_version_key_ring:
            facts.set(
                GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_KEY_RING,
                target_facts.kms_key_ring,
            )

    def _resolve_kms_key_ring(
        self,
        resource: NormalizedResource,
        context: GcpDecorationContext,
    ) -> None:
        facts = gcp_facts(resource)
        if facts.kms_key_ring:
            return
        target = _symbolic_target(
            resource,
            context,
            allowed_paths={("key_ring",)},
            expected_resource_types={GcpResourceType.KMS_KEY_RING},
            expected_reference_suffixes=_KMS_KEY_RING_PARENT_SUFFIXES,
        )
        if target is not None:
            facts.set(GcpResourceMetadata.KMS_KEY_RING, _canonical_reference(target))

    def _resolve_iam_member(
        self,
        resource: NormalizedResource,
        context: GcpDecorationContext,
    ) -> None:
        if not resource.resource_type.endswith("_iam_member"):
            return
        facts = gcp_facts(resource)
        if facts.get(GcpResourceMetadata.IAM_MEMBER) or facts.get(GcpResourceMetadata.IAM_MEMBERS):
            return
        target = _symbolic_target(
            resource,
            context,
            allowed_paths={("member",)},
            expected_resource_types={GcpResourceType.SERVICE_ACCOUNT},
            expected_reference_suffixes=_IAM_MEMBER_REFERENCE_SUFFIXES,
        )
        if target is None:
            return
        email = _service_account_email(target)
        if email is None:
            return
        member = service_account_member(email)
        if member is None:
            return
        facts.set(GcpResourceMetadata.IAM_MEMBER, member)
        facts.set(GcpResourceMetadata.IAM_MEMBERS, [member])
        bindings = facts.bindings
        if bindings:
            normalized_bindings: list[dict[str, Any]] = []
            for binding in bindings:
                updated = dict(binding)
                updated["members"] = [member]
                normalized_bindings.append(updated)
            facts.set(GcpResourceMetadata.IAM_BINDINGS, normalized_bindings)
        else:
            role = facts.get(GcpResourceMetadata.IAM_ROLE)
            if role:
                facts.set(
                    GcpResourceMetadata.IAM_BINDINGS,
                    [{"role": role, "members": [member]}],
                )

    def _resolve_iam_target(
        self,
        resource: NormalizedResource,
        context: GcpDecorationContext,
    ) -> None:
        relationship = next(
            (item for item in _IAM_TARGET_RELATIONSHIPS if resource.resource_type in item[0]),
            None,
        )
        if relationship is None:
            if resource.resource_type in GCP_PROJECT_IAM_RESOURCE_TYPES:
                self._resolve_project_target(resource, context)
            return

        _, field, expected_types, allowed_paths, suffixes = relationship
        facts = gcp_facts(resource)
        if facts.get(field):
            return
        target = _symbolic_target(
            resource,
            context,
            allowed_paths=allowed_paths,
            expected_resource_types=expected_types,
            expected_reference_suffixes=suffixes,
        )
        if target is None:
            return
        facts.set(field, _canonical_reference(target))
        if resource.has_metadata_field(GcpResourceMetadata.IAM_SCOPE_REFERENCE_STATE):
            facts.set(GcpResourceMetadata.IAM_SCOPE_REFERENCE_STATE, "configured")

    def _resolve_project_target(
        self,
        resource: NormalizedResource,
        context: GcpDecorationContext,
    ) -> None:
        facts = gcp_facts(resource)
        if facts.project:
            return
        target = _symbolic_target(
            resource,
            context,
            allowed_paths={("project",)},
            expected_resource_types={GcpResourceType.PROJECT},
            expected_reference_suffixes=_PROJECT_REFERENCE_SUFFIXES,
        )
        if target is None:
            return
        project = _project_id(target)
        if project is None:
            return
        facts.set(GcpResourceMetadata.PROJECT, project)
        if resource.has_metadata_field(GcpResourceMetadata.IAM_SCOPE_REFERENCE_STATE):
            facts.set(GcpResourceMetadata.IAM_SCOPE_REFERENCE_STATE, "configured")


def _symbolic_target(
    resource: NormalizedResource,
    context: GcpDecorationContext,
    *,
    allowed_paths: Collection[tuple[str | int, ...]],
    expected_resource_types: Collection[str],
    expected_reference_suffixes: Collection[str],
) -> NormalizedResource | None:
    matches: dict[str, NormalizedResource] = {}
    expected_types = set(expected_resource_types)
    suffixes = tuple(expected_reference_suffixes)
    for resolution in resource.reference_resolutions:
        if resolution.state != TerraformReferenceResolutionState.SYMBOLIC:
            continue
        if resolution.provenance != TerraformReferenceProvenance.CONFIGURATION_REFERENCE:
            continue
        if resolution.path not in allowed_paths:
            continue
        if len(resolution.targets) != 1:
            continue
        target = resolution.targets[0]
        if not any(target.reference.endswith(suffix) for suffix in suffixes):
            continue
        candidate = context.index.resources_by_reference.get(
            gcp_reference_key(target.address),
            source=resource,
            resource_types=expected_types,
        )
        if candidate is None or candidate.address != target.address:
            continue
        matches[candidate.address] = candidate
    return next(iter(matches.values())) if len(matches) == 1 else None


def _canonical_reference(resource: NormalizedResource) -> str:
    resource_type = resource.resource_type
    facts = gcp_facts(resource)
    if resource_type == GcpResourceType.SERVICE_ACCOUNT:
        return _service_account_email(resource) or resource.address
    if resource_type == GcpResourceType.PUBSUB_TOPIC:
        return _project_child_reference(facts.project, facts.resource_name, "topics") or resource.address
    if resource_type == GcpResourceType.PUBSUB_SUBSCRIPTION:
        return _project_child_reference(facts.project, facts.resource_name, "subscriptions") or resource.address
    if resource_type == GcpResourceType.FIRESTORE_DATABASE:
        project = _project_id_from_value(facts.project)
        name = facts.firestore_database_name or facts.resource_name
        if project and name:
            return f"projects/{project}/databases/{name}"
        return resource.address
    if resource_type == GcpResourceType.KMS_CRYPTO_KEY:
        return _canonical_kms_key_path(resource) or resource.address
    if resource_type == GcpResourceType.KMS_KEY_RING:
        for value in (resource.identifier, facts.kms_key_ring):
            if isinstance(value, str) and "/keyRings/" in value:
                return value.strip("/")
        return resource.address
    if resource_type == GcpResourceType.PROJECT:
        return _project_id(resource) or resource.address
    return resource.address


def _canonical_kms_key_path(resource: NormalizedResource) -> str | None:
    facts = gcp_facts(resource)
    for value in (facts.kms_crypto_key_reference, resource.identifier):
        if isinstance(value, str) and value.startswith("projects/") and "/cryptoKeys/" in value:
            return value.strip("/")
    key_ring = facts.kms_key_ring
    name = facts.resource_name
    if isinstance(key_ring, str) and "/keyRings/" in key_ring and isinstance(name, str) and "/" not in name:
        return f"{key_ring.rstrip('/')}/cryptoKeys/{name}"
    return None


def _service_account_email(resource: NormalizedResource) -> str | None:
    facts = gcp_facts(resource)
    email = facts.service_account_email
    if isinstance(email, str) and "@" in email:
        return email
    account_id = resource.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_ACCOUNT_ID)
    project = _project_id_from_value(facts.project)
    if isinstance(account_id, str) and account_id and project:
        return f"{account_id}@{project}.iam.gserviceaccount.com"
    for value in (resource.identifier, facts.resource_name):
        if isinstance(value, str) and "@" in value:
            return value
    return None


def _project_id(resource: NormalizedResource) -> str | None:
    facts = gcp_facts(resource)
    for value in (facts.project, resource.identifier, facts.resource_name):
        project = _project_id_from_value(value)
        if project:
            return project
    return None


def _project_id_from_value(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    text = value.strip("/")
    if text.startswith("projects/"):
        parts = text.split("/")
        return parts[1] if len(parts) > 1 and parts[1] else None
    return text if "/" not in text else None


def _project_child_reference(project: object, name: object, child: str) -> str | None:
    project_id = _project_id_from_value(project)
    if not project_id or not isinstance(name, str) or not name or "/" in name:
        return None
    return f"projects/{project_id}/{child}/{name}"
