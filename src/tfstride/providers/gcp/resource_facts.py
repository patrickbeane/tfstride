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
        if not self.resource.has_metadata_value(field):
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
    def uniform_bucket_level_access(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.UNIFORM_BUCKET_LEVEL_ACCESS)

    @property
    def public_access_prevention(self) -> str | None:
        return self.get(GcpResourceMetadata.PUBLIC_ACCESS_PREVENTION)

    @property
    def versioning_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.GCS_VERSIONING_ENABLED)

    @property
    def gcs_retention_period_seconds(self) -> int | None:
        return self.get(GcpResourceMetadata.GCS_RETENTION_PERIOD_SECONDS)

    @property
    def gcs_retention_policy_locked(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.GCS_RETENTION_POLICY_LOCKED)

    @property
    def gcs_retention_policy_configuration(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.GCS_RETENTION_POLICY_CONFIGURATION)

    @property
    def gcs_retention_policy_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.GCS_RETENTION_POLICY_UNCERTAINTIES)

    @property
    def secret_manager_replication_mode(self) -> str | None:
        return self.get(GcpResourceMetadata.SECRET_MANAGER_REPLICATION_MODE)

    @property
    def secret_manager_kms_key_names(self) -> list[str]:
        return self.get(GcpResourceMetadata.SECRET_MANAGER_KMS_KEY_NAMES)

    @property
    def secret_manager_replication(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.SECRET_MANAGER_REPLICATION)

    @property
    def secret_manager_ttl(self) -> str | None:
        return self.get(GcpResourceMetadata.SECRET_MANAGER_TTL)

    @property
    def secret_manager_expire_time(self) -> str | None:
        return self.get(GcpResourceMetadata.SECRET_MANAGER_EXPIRE_TIME)

    @property
    def secret_manager_version_destroy_ttl(self) -> str | None:
        return self.get(GcpResourceMetadata.SECRET_MANAGER_VERSION_DESTROY_TTL)

    @property
    def secret_manager_posture_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.SECRET_MANAGER_POSTURE_UNCERTAINTIES)

    @property
    def kms_purpose(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_PURPOSE)

    @property
    def kms_rotation_period(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_ROTATION_PERIOD)

    @property
    def kms_destroy_scheduled_duration(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_DESTROY_SCHEDULED_DURATION)

    @property
    def kms_posture_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.KMS_POSTURE_UNCERTAINTIES)

    @property
    def default_kms_key_name(self) -> str | None:
        return self.get(GcpResourceMetadata.GCS_DEFAULT_KMS_KEY_NAME)

    @property
    def customer_managed_encryption(self) -> bool | None:
        value = self.optional_bool(GcpResourceMetadata.CUSTOMER_MANAGED_ENCRYPTION)
        if value is not None:
            return value
        if self.default_kms_key_name:
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
    def org_policy_constraint(self) -> str | None:
        return self.get(GcpResourceMetadata.ORG_POLICY_CONSTRAINT)

    @property
    def org_policy_rules(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.ORG_POLICY_RULES)

    @property
    def org_policy_allowed_values(self) -> list[str]:
        return self.get(GcpResourceMetadata.ORG_POLICY_ALLOWED_VALUES)

    @property
    def org_policy_denied_values(self) -> list[str]:
        return self.get(GcpResourceMetadata.ORG_POLICY_DENIED_VALUES)

    @property
    def org_policy_enforced(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.ORG_POLICY_ENFORCED)

    @property
    def org_policy_inherit_from_parent(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.ORG_POLICY_INHERIT_FROM_PARENT)

    @property
    def org_policy_restore_default(self) -> bool:
        return self.get(GcpResourceMetadata.ORG_POLICY_RESTORE_DEFAULT)

    @property
    def org_policy_scope_type(self) -> str | None:
        return self.get(GcpResourceMetadata.ORG_POLICY_SCOPE_TYPE)

    @property
    def org_policy_scope(self) -> str | None:
        return self.get(GcpResourceMetadata.ORG_POLICY_SCOPE)

    @property
    def service_account_key_keepers(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.SERVICE_ACCOUNT_KEY_KEEPERS)

    @property
    def service_account_key_algorithm(self) -> str | None:
        return self.get(GcpResourceMetadata.SERVICE_ACCOUNT_KEY_ALGORITHM)

    @property
    def service_account_public_key_type(self) -> str | None:
        return self.get(GcpResourceMetadata.SERVICE_ACCOUNT_PUBLIC_KEY_TYPE)

    @property
    def service_account_id(self) -> str | None:
        return self.get(GcpResourceMetadata.SERVICE_ACCOUNT_ID)

    @property
    def service_account_key_valid_after(self) -> str | None:
        return self.get(GcpResourceMetadata.SERVICE_ACCOUNT_KEY_VALID_AFTER)

    @property
    def service_account_key_valid_before(self) -> str | None:
        return self.get(GcpResourceMetadata.SERVICE_ACCOUNT_KEY_VALID_BEFORE)

    @property
    def private_connectivity_purpose(self) -> str | None:
        return self.get(GcpResourceMetadata.PRIVATE_CONNECTIVITY_PURPOSE)

    @property
    def private_connectivity_address_type(self) -> str | None:
        return self.get(GcpResourceMetadata.PRIVATE_CONNECTIVITY_ADDRESS_TYPE)

    @property
    def private_connectivity_address(self) -> str | None:
        return self.get(GcpResourceMetadata.PRIVATE_CONNECTIVITY_ADDRESS)

    @property
    def private_connectivity_prefix_length(self) -> int | None:
        return self.get(GcpResourceMetadata.PRIVATE_CONNECTIVITY_PREFIX_LENGTH)

    @property
    def private_connectivity_service(self) -> str | None:
        return self.get(GcpResourceMetadata.PRIVATE_CONNECTIVITY_SERVICE)

    @property
    def private_connectivity_reserved_ranges(self) -> list[str]:
        return self.get(GcpResourceMetadata.PRIVATE_CONNECTIVITY_RESERVED_RANGES)

    @property
    def private_connectivity_peering(self) -> str | None:
        return self.get(GcpResourceMetadata.PRIVATE_CONNECTIVITY_PEERING)

    @property
    def private_connectivity_target_service(self) -> str | None:
        return self.get(GcpResourceMetadata.PRIVATE_CONNECTIVITY_TARGET_SERVICE)

    @property
    def private_connectivity_nat_subnets(self) -> list[str]:
        return self.get(GcpResourceMetadata.PRIVATE_CONNECTIVITY_NAT_SUBNETS)

    @property
    def private_connectivity_subnetworks(self) -> list[str]:
        return self.get(GcpResourceMetadata.PRIVATE_CONNECTIVITY_SUBNETWORKS)

    @property
    def private_connectivity_domain_names(self) -> list[str]:
        return self.get(GcpResourceMetadata.PRIVATE_CONNECTIVITY_DOMAIN_NAMES)

    @property
    def private_connectivity_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.PRIVATE_CONNECTIVITY_UNCERTAINTIES)

    @property
    def private_ip_google_access(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.PRIVATE_IP_GOOGLE_ACCESS)

    @property
    def psc_connection_id(self) -> str | None:
        return self.get(GcpResourceMetadata.PSC_CONNECTION_ID)

    @property
    def psc_connection_status(self) -> str | None:
        return self.get(GcpResourceMetadata.PSC_CONNECTION_STATUS)

    @property
    def psc_connection_preference(self) -> str | None:
        return self.get(GcpResourceMetadata.PSC_CONNECTION_PREFERENCE)

    @property
    def psc_service_label(self) -> str | None:
        return self.get(GcpResourceMetadata.PSC_SERVICE_LABEL)

    @property
    def psc_service_name(self) -> str | None:
        return self.get(GcpResourceMetadata.PSC_SERVICE_NAME)

    @property
    def psc_service_class(self) -> str | None:
        return self.get(GcpResourceMetadata.PSC_SERVICE_CLASS)

    @property
    def psc_config(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.PSC_CONFIG)

    @property
    def psc_consumer_accept_list(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.PSC_CONSUMER_ACCEPT_LIST)

    @property
    def psc_consumer_reject_list(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.PSC_CONSUMER_REJECT_LIST)

    @property
    def engine(self) -> str | None:
        return self.get(GcpResourceMetadata.DATABASE_VERSION)

    @property
    def authorized_networks(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.CLOUD_SQL_AUTHORIZED_NETWORKS)

    @property
    def backup_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.CLOUD_SQL_BACKUP_ENABLED)

    @property
    def point_in_time_recovery_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.CLOUD_SQL_POINT_IN_TIME_RECOVERY_ENABLED)

    @property
    def ipv4_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.CLOUD_SQL_IPV4_ENABLED)

    @property
    def private_network(self) -> str | None:
        return self.get(GcpResourceMetadata.CLOUD_SQL_PRIVATE_NETWORK)

    @property
    def require_ssl(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.CLOUD_SQL_REQUIRE_SSL)

    @property
    def ssl_mode(self) -> str | None:
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
    def gke_logging_service(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_LOGGING_SERVICE)

    @property
    def gke_logging_components(self) -> list[str]:
        return self.get(GcpResourceMetadata.GKE_LOGGING_COMPONENTS)

    @property
    def gke_control_plane_logging_state(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_CONTROL_PLANE_LOGGING_STATE)

    @property
    def gke_logging_config(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.GKE_LOGGING_CONFIG)

    @property
    def gke_network_policy_state(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_NETWORK_POLICY_STATE)

    @property
    def gke_network_policy_provider(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_NETWORK_POLICY_PROVIDER)

    @property
    def gke_network_policy(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.GKE_NETWORK_POLICY)

    @property
    def gke_database_encryption_state(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_DATABASE_ENCRYPTION_STATE)

    @property
    def gke_database_encryption_key_name(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_DATABASE_ENCRYPTION_KEY_NAME)

    @property
    def gke_secrets_encryption_state(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_SECRETS_ENCRYPTION_STATE)

    @property
    def gke_database_encryption(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.GKE_DATABASE_ENCRYPTION)

    @property
    def gke_legacy_abac_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.GKE_LEGACY_ABAC_ENABLED)

    @property
    def gke_legacy_abac_state(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_LEGACY_ABAC_STATE)

    @property
    def gke_client_certificate_auth_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.GKE_CLIENT_CERTIFICATE_AUTH_ENABLED)

    @property
    def gke_client_certificate_auth_state(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_CLIENT_CERTIFICATE_AUTH_STATE)

    @property
    def gke_basic_auth_state(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_BASIC_AUTH_STATE)

    @property
    def gke_basic_auth_username(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_BASIC_AUTH_USERNAME)

    @property
    def gke_basic_auth_password_configured(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.GKE_BASIC_AUTH_PASSWORD_CONFIGURED)

    @property
    def gke_master_auth(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.GKE_MASTER_AUTH)

    @property
    def gke_client_certificate_config(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.GKE_CLIENT_CERTIFICATE_CONFIG)

    @property
    def gke_release_channel(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_RELEASE_CHANNEL)

    @property
    def gke_release_channel_config(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.GKE_RELEASE_CHANNEL_CONFIG)

    @property
    def gke_shielded_nodes_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.GKE_SHIELDED_NODES_ENABLED)

    @property
    def gke_shielded_nodes_state(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_SHIELDED_NODES_STATE)

    @property
    def gke_shielded_nodes_config(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.GKE_SHIELDED_NODES_CONFIG)

    @property
    def gke_binary_authorization_evaluation_mode(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_BINARY_AUTHORIZATION_EVALUATION_MODE)

    @property
    def gke_binary_authorization_state(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_BINARY_AUTHORIZATION_STATE)

    @property
    def gke_binary_authorization(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.GKE_BINARY_AUTHORIZATION)

    @property
    def gke_posture_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.GKE_POSTURE_UNCERTAINTIES)

    @property
    def audit_security_posture_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.AUDIT_SECURITY_POSTURE_UNCERTAINTIES)

    @property
    def logging_sink_name(self) -> str | None:
        return self.get(GcpResourceMetadata.LOGGING_SINK_NAME)

    @property
    def logging_sink_destination(self) -> str | None:
        return self.get(GcpResourceMetadata.LOGGING_SINK_DESTINATION)

    @property
    def logging_sink_filter(self) -> str | None:
        return self.get(GcpResourceMetadata.LOGGING_SINK_FILTER)

    @property
    def logging_sink_writer_identity(self) -> str | None:
        return self.get(GcpResourceMetadata.LOGGING_SINK_WRITER_IDENTITY)

    @property
    def logging_sink_scope_type(self) -> str | None:
        return self.get(GcpResourceMetadata.LOGGING_SINK_SCOPE_TYPE)

    @property
    def logging_sink_scope(self) -> str | None:
        return self.get(GcpResourceMetadata.LOGGING_SINK_SCOPE)

    @property
    def logging_sink_include_children(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.LOGGING_SINK_INCLUDE_CHILDREN)

    @property
    def logging_sink_unique_writer_identity(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.LOGGING_SINK_UNIQUE_WRITER_IDENTITY)

    @property
    def logging_exclusion_name(self) -> str | None:
        return self.get(GcpResourceMetadata.LOGGING_EXCLUSION_NAME)

    @property
    def logging_exclusion_description(self) -> str | None:
        return self.get(GcpResourceMetadata.LOGGING_EXCLUSION_DESCRIPTION)

    @property
    def logging_exclusion_filter(self) -> str | None:
        return self.get(GcpResourceMetadata.LOGGING_EXCLUSION_FILTER)

    @property
    def logging_exclusion_scope_type(self) -> str | None:
        return self.get(GcpResourceMetadata.LOGGING_EXCLUSION_SCOPE_TYPE)

    @property
    def logging_exclusion_scope(self) -> str | None:
        return self.get(GcpResourceMetadata.LOGGING_EXCLUSION_SCOPE)

    @property
    def logging_exclusion_disabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.LOGGING_EXCLUSION_DISABLED)

    @property
    def scc_organization(self) -> str | None:
        return self.get(GcpResourceMetadata.SCC_ORGANIZATION)

    @property
    def scc_enable_asset_discovery(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.SCC_ENABLE_ASSET_DISCOVERY)

    @property
    def scc_asset_discovery_state(self) -> str | None:
        return self.get(GcpResourceMetadata.SCC_ASSET_DISCOVERY_STATE)

    @property
    def scc_asset_discovery_inclusion_mode(self) -> str | None:
        return self.get(GcpResourceMetadata.SCC_ASSET_DISCOVERY_INCLUSION_MODE)

    @property
    def scc_asset_discovery_project_ids(self) -> list[str]:
        return self.get(GcpResourceMetadata.SCC_ASSET_DISCOVERY_PROJECT_IDS)

    @property
    def scc_asset_discovery_folder_ids(self) -> list[str]:
        return self.get(GcpResourceMetadata.SCC_ASSET_DISCOVERY_FOLDER_IDS)

    @property
    def scc_asset_discovery_config(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.SCC_ASSET_DISCOVERY_CONFIG)

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
                scopes.extend(str(scope) for scope in account_scopes if scope not in (None, ""))
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
    def forwarding_rule_target(self) -> str | None:
        return self.get(GcpResourceMetadata.FORWARDING_RULE_TARGET)

    @property
    def forwarding_rule_load_balancing_scheme(self) -> str | None:
        return self.get(GcpResourceMetadata.FORWARDING_RULE_LOAD_BALANCING_SCHEME)

    @property
    def forwarding_rule_ip_address(self) -> str | None:
        return self.get(GcpResourceMetadata.FORWARDING_RULE_IP_ADDRESS)

    @property
    def forwarding_rule_ports(self) -> list[str]:
        return self.get(GcpResourceMetadata.FORWARDING_RULE_PORTS)

    @property
    def load_balancer_ssl_certificates(self) -> list[str]:
        return self.get(GcpResourceMetadata.LOAD_BALANCER_SSL_CERTIFICATES)

    @property
    def load_balancer_ssl_policy(self) -> str | None:
        return self.get(GcpResourceMetadata.LOAD_BALANCER_SSL_POLICY)

    @property
    def load_balancer_certificate_map(self) -> str | None:
        return self.get(GcpResourceMetadata.LOAD_BALANCER_CERTIFICATE_MAP)

    @property
    def ssl_policy_min_tls_version(self) -> str | None:
        return self.get(GcpResourceMetadata.SSL_POLICY_MIN_TLS_VERSION)

    @property
    def ssl_policy_profile(self) -> str | None:
        return self.get(GcpResourceMetadata.SSL_POLICY_PROFILE)

    @property
    def ssl_policy_custom_features(self) -> list[str]:
        return self.get(GcpResourceMetadata.SSL_POLICY_CUSTOM_FEATURES)

    @property
    def ssl_policy_enabled_features(self) -> list[str]:
        return self.get(GcpResourceMetadata.SSL_POLICY_ENABLED_FEATURES)

    @property
    def managed_ssl_certificate_domains(self) -> list[str]:
        return self.get(GcpResourceMetadata.MANAGED_SSL_CERTIFICATE_DOMAINS)

    @property
    def managed_ssl_certificate_status(self) -> str | None:
        return self.get(GcpResourceMetadata.MANAGED_SSL_CERTIFICATE_STATUS)

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
