from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, TypeVar

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_utils import dedupe, service_account_member
from tfstride.providers.metadata_ownership import ProviderMetadataWriteValidator
from tfstride.providers.resource_facts import NeutralProviderResourceFacts, ProviderResourceFactDomains
from tfstride.resource_metadata import MetadataField, StringListMetadataField

_MetadataValue = TypeVar("_MetadataValue")
_GCP_METADATA_WRITE_VALIDATOR = ProviderMetadataWriteValidator.build(
    provider="gcp",
    namespace=GcpResourceMetadata,
)


_REFERENCE_VALUE_FIELDS = (
    GcpResourceMetadata.NAME,
    GcpResourceMetadata.SELF_LINK,
    GcpResourceMetadata.BUCKET_NAME,
    GcpResourceMetadata.SECRET_ID,
    GcpResourceMetadata.SECRET_REFERENCE,
    GcpResourceMetadata.PUBSUB_TOPIC_REFERENCE,
    GcpResourceMetadata.PUBSUB_SUBSCRIPTION_REFERENCE,
    GcpResourceMetadata.BIGQUERY_DATASET_ID,
    GcpResourceMetadata.BIGQUERY_DATASET_REFERENCE,
    GcpResourceMetadata.BIGQUERY_TABLE_ID,
    GcpResourceMetadata.BIGQUERY_TABLE_REFERENCE,
    GcpResourceMetadata.KMS_CRYPTO_KEY_REFERENCE,
    GcpResourceMetadata.KMS_KEY_RING,
    GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE,
    GcpResourceMetadata.CLOUD_FUNCTION_REFERENCE,
    GcpResourceMetadata.SERVICE_ACCOUNT_EMAIL,
    GcpResourceMetadata.SERVICE_ACCOUNT_MEMBER,
    GcpResourceMetadata.SERVICE_ACCOUNT_REFERENCE,
)
_IAM_TARGET_REFERENCE_FIELDS = (
    GcpResourceMetadata.SERVICE_ACCOUNT_REFERENCE,
    GcpResourceMetadata.BUCKET_NAME,
    GcpResourceMetadata.SECRET_REFERENCE,
    GcpResourceMetadata.PUBSUB_TOPIC_REFERENCE,
    GcpResourceMetadata.PUBSUB_SUBSCRIPTION_REFERENCE,
    GcpResourceMetadata.BIGQUERY_TABLE_REFERENCE,
    GcpResourceMetadata.BIGQUERY_DATASET_REFERENCE,
    GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE,
    GcpResourceMetadata.CLOUD_FUNCTION_REFERENCE,
    GcpResourceMetadata.KMS_CRYPTO_KEY_REFERENCE,
    GcpResourceMetadata.KMS_KEY_RING,
)


@dataclass(frozen=True, slots=True)
class GcpResourceFacts(NeutralProviderResourceFacts):
    """GCP-owned view over provider-specific resource metadata."""

    def get(self, field: MetadataField[_MetadataValue]) -> _MetadataValue:
        return self.resource.get_metadata_field(field)

    def set(self, field: MetadataField[_MetadataValue], value: _MetadataValue) -> None:
        _GCP_METADATA_WRITE_VALIDATOR.validate(field)
        self.resource.set_metadata_field(field, value)

    def optional_bool(self, field: MetadataField[bool]) -> bool | None:
        if not self.resource.has_metadata_field(field):
            return None
        if self.resource.metadata_snapshot().get(field.key) is None:
            return None
        return self.get(field)

    def append(self, field: StringListMetadataField, value: str | None) -> None:
        _GCP_METADATA_WRITE_VALIDATOR.validate(field)
        self.resource.append_metadata_field(field, value)

    def extend(self, field: StringListMetadataField, values: Sequence[str | None]) -> None:
        _GCP_METADATA_WRITE_VALIDATOR.validate(field)
        self.resource.extend_metadata_field(field, values)

    @property
    def bucket_name(self) -> str | None:
        return self.get(GcpResourceMetadata.BUCKET_NAME)

    @property
    def policy_document(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.POLICY_DOCUMENT)

    @property
    def gcs_uniform_bucket_level_access(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.UNIFORM_BUCKET_LEVEL_ACCESS)

    @property
    def gcs_public_access_prevention(self) -> str | None:
        return self.get(GcpResourceMetadata.PUBLIC_ACCESS_PREVENTION)

    @property
    def gcs_versioning_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.GCS_VERSIONING_ENABLED)

    @property
    def gcs_default_kms_key_name(self) -> str | None:
        return self.get(GcpResourceMetadata.GCS_DEFAULT_KMS_KEY_NAME)

    @property
    def customer_managed_encryption(self) -> bool | None:
        value = self.optional_bool(GcpResourceMetadata.CUSTOMER_MANAGED_ENCRYPTION)
        if value is not None:
            return value
        if self.gcs_default_kms_key_name:
            return True
        return None

    @property
    def resource_policy_source_addresses(self) -> list[str]:
        return self.get(GcpResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES)

    @property
    def project(self) -> str | None:
        return self.get(GcpResourceMetadata.PROJECT)

    @property
    def resource_name(self) -> str | None:
        return self.get(GcpResourceMetadata.NAME)

    @property
    def reference_values(self) -> list[str]:
        values: list[str] = []
        for field in _REFERENCE_VALUE_FIELDS:
            value = self.get(field)
            if value in (None, ""):
                continue
            values.append(str(value))
        return dedupe(values)

    @property
    def iam_target_reference(self) -> str | None:
        for field in _IAM_TARGET_REFERENCE_FIELDS:
            value = self.get(field)
            if value:
                return value
        return None

    @property
    def iam_bindings(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.IAM_BINDINGS)

    @property
    def custom_role_id(self) -> str | None:
        return self.get(GcpResourceMetadata.CUSTOM_ROLE_ID)

    @property
    def custom_role_permissions(self) -> list[str]:
        return self.get(GcpResourceMetadata.CUSTOM_ROLE_PERMISSIONS)

    @property
    def organization_id(self) -> str | None:
        return self.get(GcpResourceMetadata.ORGANIZATION_ID)

    @property
    def folder_id(self) -> str | None:
        return self.get(GcpResourceMetadata.FOLDER_ID)

    @property
    def engine(self) -> str | None:
        return self.get(GcpResourceMetadata.DATABASE_VERSION)

    @property
    def cloud_sql_authorized_networks(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.CLOUD_SQL_AUTHORIZED_NETWORKS)

    @property
    def cloud_sql_backup_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.CLOUD_SQL_BACKUP_ENABLED)

    @property
    def cloud_sql_point_in_time_recovery_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.CLOUD_SQL_POINT_IN_TIME_RECOVERY_ENABLED)

    @property
    def cloud_sql_ipv4_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.CLOUD_SQL_IPV4_ENABLED)

    @property
    def cloud_sql_private_network(self) -> str | None:
        return self.get(GcpResourceMetadata.CLOUD_SQL_PRIVATE_NETWORK)

    @property
    def cloud_sql_require_ssl(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.CLOUD_SQL_REQUIRE_SSL)

    @property
    def cloud_sql_ssl_mode(self) -> str | None:
        return self.get(GcpResourceMetadata.CLOUD_SQL_SSL_MODE)

    @property
    def deletion_protection(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.DELETION_PROTECTION)

    @property
    def os_login_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.OS_LOGIN_ENABLED)

    @property
    def gke_endpoint(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_ENDPOINT)

    @property
    def gke_private_endpoint_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.GKE_PRIVATE_ENDPOINT_ENABLED)

    @property
    def gke_private_nodes_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.GKE_PRIVATE_NODES_ENABLED)

    @property
    def gke_master_authorized_networks(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.GKE_MASTER_AUTHORIZED_NETWORKS)

    @property
    def gke_workload_identity_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.GKE_WORKLOAD_IDENTITY_ENABLED)

    @property
    def gke_workload_identity_pool(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_WORKLOAD_IDENTITY_POOL)

    @property
    def gke_node_service_account(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_NODE_SERVICE_ACCOUNT)

    @property
    def gke_node_oauth_scopes(self) -> list[str]:
        return self.get(GcpResourceMetadata.GKE_NODE_OAUTH_SCOPES)

    @property
    def gke_node_metadata_mode(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_NODE_METADATA_MODE)

    @property
    def gke_legacy_metadata_endpoints_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.GKE_LEGACY_METADATA_ENDPOINTS_ENABLED)

    @property
    def service_account_email(self) -> str | None:
        return self.get(GcpResourceMetadata.SERVICE_ACCOUNT_EMAIL)

    @property
    def service_account_member(self) -> str | None:
        return self.get(GcpResourceMetadata.SERVICE_ACCOUNT_MEMBER)

    @property
    def service_account_reference(self) -> str | None:
        return self.get(GcpResourceMetadata.SERVICE_ACCOUNT_REFERENCE)

    @property
    def workload_identity_members(self) -> list[str]:
        members: list[str] = []
        for account in self.get(GcpResourceMetadata.SERVICE_ACCOUNTS):
            email = _service_account_email(account)
            if email is None:
                continue
            member = service_account_member(email)
            if member is not None:
                members.append(member)
        return dedupe(members)

    @property
    def workload_identity_scopes(self) -> list[str]:
        scopes: list[str] = []
        for account in self.get(GcpResourceMetadata.SERVICE_ACCOUNTS):
            if not isinstance(account, dict):
                continue
            account_scopes = account.get("scopes")
            if isinstance(account_scopes, list):
                scopes.extend(
                    str(scope) for scope in account_scopes if scope not in (None, "")
                )
            elif account_scopes not in (None, ""):
                scopes.append(str(account_scopes))
        return dedupe(scopes)

    @property
    def network_tags(self) -> list[str]:
        return self.get(GcpResourceMetadata.NETWORK_TAGS)

    @property
    def internet_ingress_firewalls(self) -> list[str]:
        return self.get(GcpResourceMetadata.INTERNET_INGRESS_FIREWALLS)

    @property
    def fronted_by_internet_facing_load_balancer(self) -> bool:
        return self.get(GcpResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER)

    @property
    def internet_facing_load_balancer_addresses(self) -> list[str]:
        return self.get(GcpResourceMetadata.INTERNET_FACING_LOAD_BALANCER_ADDRESSES)

    @property
    def load_balancer_frontends(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.LOAD_BALANCER_FRONTENDS)

    @property
    def load_balancer_reachable_backends(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.LOAD_BALANCER_REACHABLE_BACKENDS)

    @property
    def iam_role(self) -> str | None:
        return self.get(GcpResourceMetadata.IAM_ROLE)

    @property
    def iam_member(self) -> str | None:
        return self.get(GcpResourceMetadata.IAM_MEMBER)


def gcp_facts(resource: NormalizedResource) -> GcpResourceFacts:
    return GcpResourceFacts(resource)


def gcp_fact_domains(resource: NormalizedResource) -> ProviderResourceFactDomains:
    facts = gcp_facts(resource)
    return ProviderResourceFactDomains(
        storage=facts,
        iam=facts,
        sql=facts,
        gke=facts,
        compute=facts,
        workload=facts,
    )


def _service_account_email(value: Any) -> str | None:
    if isinstance(value, dict):
        email = value.get("email")
    else:
        email = value
    if email in (None, "", "default"):
        return None
    text = str(email).strip()
    if not text or text == "default":
        return None
    if text.startswith("serviceAccount:"):
        return text.removeprefix("serviceAccount:")
    return text