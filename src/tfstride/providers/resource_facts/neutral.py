from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.resource_facts.contracts import ProviderResourceFactDomains


class NeutralProviderStorageFacts:
    """Neutral storage facts for providers without storage posture signals."""

    __slots__ = ()

    @property
    def bucket_name(self) -> str | None:
        return None

    @property
    def bucket_acl(self) -> str:
        return ""

    @property
    def public_access_block(self) -> dict[str, bool] | None:
        return None

    @property
    def uniform_bucket_level_access(self) -> bool | None:
        return None

    @property
    def public_access_prevention(self) -> str | None:
        return None

    @property
    def versioning_enabled(self) -> bool | None:
        return None

    @property
    def default_kms_key_name(self) -> str | None:
        return None

    @property
    def customer_managed_encryption(self) -> bool | None:
        return None

    @property
    def gcs_retention_period_seconds(self) -> int | None:
        return None

    @property
    def gcs_retention_policy_locked(self) -> bool | None:
        return None

    @property
    def gcs_retention_policy_configuration(self) -> dict[str, Any]:
        return {}

    @property
    def gcs_retention_policy_uncertainties(self) -> list[str]:
        return []


class NeutralProviderIamFacts:
    """Neutral IAM facts for providers without IAM hierarchy signals."""

    __slots__ = ()

    @property
    def policy_document(self) -> dict[str, Any]:
        return {}

    @property
    def trust_statements(self) -> list[dict[str, Any]]:
        return []

    @property
    def resource_policy_source_addresses(self) -> list[str]:
        return []

    @property
    def project(self) -> str | None:
        return None

    @property
    def resource_name(self) -> str | None:
        return None

    @property
    def reference_values(self) -> list[str]:
        return []

    @property
    def iam_target_reference(self) -> str | None:
        return None

    @property
    def iam_bindings(self) -> list[dict[str, Any]]:
        return []

    @property
    def custom_role_id(self) -> str | None:
        return None

    @property
    def custom_role_permissions(self) -> list[str]:
        return []

    @property
    def organization_id(self) -> str | None:
        return None

    @property
    def folder_id(self) -> str | None:
        return None

    @property
    def service_account_email(self) -> str | None:
        return None

    @property
    def service_account_member(self) -> str | None:
        return None

    @property
    def service_account_reference(self) -> str | None:
        return None

    @property
    def iam_role(self) -> str | None:
        return None

    @property
    def iam_member(self) -> str | None:
        return None

    @property
    def org_policy_constraint(self) -> str | None:
        return None

    @property
    def org_policy_rules(self) -> list[dict[str, Any]]:
        return []

    @property
    def org_policy_allowed_values(self) -> list[str]:
        return []

    @property
    def org_policy_denied_values(self) -> list[str]:
        return []

    @property
    def org_policy_enforced(self) -> bool | None:
        return None

    @property
    def org_policy_inherit_from_parent(self) -> bool | None:
        return None

    @property
    def org_policy_restore_default(self) -> bool:
        return False

    @property
    def org_policy_scope_type(self) -> str | None:
        return None

    @property
    def org_policy_scope(self) -> str | None:
        return None

    @property
    def service_account_key_keepers(self) -> dict[str, Any]:
        return {}

    @property
    def service_account_key_algorithm(self) -> str | None:
        return None

    @property
    def service_account_public_key_type(self) -> str | None:
        return None

    @property
    def service_account_id(self) -> str | None:
        return None

    @property
    def service_account_key_valid_after(self) -> str | None:
        return None

    @property
    def service_account_key_valid_before(self) -> str | None:
        return None


class NeutralProviderSqlFacts:
    """Neutral SQL facts for providers without managed SQL signals."""

    __slots__ = ()

    @property
    def engine(self) -> str | None:
        return None

    @property
    def authorized_networks(self) -> list[dict[str, Any]]:
        return []

    @property
    def backup_enabled(self) -> bool | None:
        return None

    @property
    def point_in_time_recovery_enabled(self) -> bool | None:
        return None

    @property
    def ipv4_enabled(self) -> bool | None:
        return None

    @property
    def private_network(self) -> str | None:
        return None

    @property
    def require_ssl(self) -> bool | None:
        return None

    @property
    def ssl_mode(self) -> str | None:
        return None

    @property
    def deletion_protection(self) -> bool | None:
        return None


class NeutralProviderComputeFacts:
    """Neutral compute facts for providers without compute posture signals."""

    __slots__ = ()

    @property
    def os_login_enabled(self) -> bool | None:
        return None

    @property
    def network_tags(self) -> list[str]:
        return []

    @property
    def internet_ingress_firewalls(self) -> list[str]:
        return []

    @property
    def fronted_by_internet_facing_load_balancer(self) -> bool:
        return False

    @property
    def internet_facing_load_balancer_addresses(self) -> list[str]:
        return []

    @property
    def load_balancer_frontends(self) -> list[dict[str, Any]]:
        return []

    @property
    def load_balancer_reachable_backends(self) -> list[dict[str, Any]]:
        return []

    @property
    def gke_endpoint(self) -> str | None:
        return None

    @property
    def gke_private_endpoint_enabled(self) -> bool | None:
        return None

    @property
    def gke_private_nodes_enabled(self) -> bool | None:
        return None

    @property
    def gke_master_authorized_networks(self) -> list[dict[str, Any]]:
        return []

    @property
    def gke_workload_identity_enabled(self) -> bool | None:
        return None

    @property
    def gke_workload_identity_pool(self) -> str | None:
        return None

    @property
    def gke_node_service_account(self) -> str | None:
        return None

    @property
    def gke_node_oauth_scopes(self) -> list[str]:
        return []

    @property
    def gke_node_metadata_mode(self) -> str | None:
        return None

    @property
    def gke_legacy_metadata_endpoints_enabled(self) -> bool | None:
        return None

    @property
    def gke_logging_service(self) -> str | None:
        return None

    @property
    def gke_logging_components(self) -> list[str]:
        return []

    @property
    def gke_control_plane_logging_state(self) -> str | None:
        return None

    @property
    def gke_logging_config(self) -> dict[str, Any]:
        return {}

    @property
    def gke_network_policy_state(self) -> str | None:
        return None

    @property
    def gke_network_policy_provider(self) -> str | None:
        return None

    @property
    def gke_network_policy(self) -> dict[str, Any]:
        return {}

    @property
    def gke_database_encryption_state(self) -> str | None:
        return None

    @property
    def gke_database_encryption_key_name(self) -> str | None:
        return None

    @property
    def gke_secrets_encryption_state(self) -> str | None:
        return None

    @property
    def gke_database_encryption(self) -> dict[str, Any]:
        return {}

    @property
    def gke_legacy_abac_enabled(self) -> bool | None:
        return None

    @property
    def gke_legacy_abac_state(self) -> str | None:
        return None

    @property
    def gke_client_certificate_auth_enabled(self) -> bool | None:
        return None

    @property
    def gke_client_certificate_auth_state(self) -> str | None:
        return None

    @property
    def gke_basic_auth_state(self) -> str | None:
        return None

    @property
    def gke_basic_auth_username(self) -> str | None:
        return None

    @property
    def gke_basic_auth_password_configured(self) -> bool | None:
        return None

    @property
    def gke_master_auth(self) -> dict[str, Any]:
        return {}

    @property
    def gke_client_certificate_config(self) -> dict[str, Any]:
        return {}

    @property
    def gke_release_channel(self) -> str | None:
        return None

    @property
    def gke_release_channel_config(self) -> dict[str, Any]:
        return {}

    @property
    def gke_shielded_nodes_enabled(self) -> bool | None:
        return None

    @property
    def gke_shielded_nodes_state(self) -> str | None:
        return None

    @property
    def gke_shielded_nodes_config(self) -> dict[str, Any]:
        return {}

    @property
    def gke_binary_authorization_evaluation_mode(self) -> str | None:
        return None

    @property
    def gke_binary_authorization_state(self) -> str | None:
        return None

    @property
    def gke_binary_authorization(self) -> dict[str, Any]:
        return {}

    @property
    def gke_posture_uncertainties(self) -> list[str]:
        return []


class NeutralProviderWorkloadFacts:
    """Neutral workload facts for providers without workload identity signals."""

    __slots__ = ()

    @property
    def workload_identity_members(self) -> list[str]:
        return []

    @property
    def workload_identity_scopes(self) -> list[str]:
        return []


@dataclass(frozen=True, slots=True)
class NeutralProviderResourceFacts(
    NeutralProviderStorageFacts,
    NeutralProviderIamFacts,
    NeutralProviderSqlFacts,
    NeutralProviderComputeFacts,
    NeutralProviderWorkloadFacts,
):
    """Neutral facts for providers without a shared-analysis facts adapter yet."""

    resource: NormalizedResource


def neutral_provider_resource_fact_domains(resource: NormalizedResource) -> ProviderResourceFactDomains:
    """Build a neutral domain facts bundle for providers without facts adapters."""

    neutral = NeutralProviderResourceFacts(resource)
    return ProviderResourceFactDomains(
        storage=neutral,
        iam=neutral,
        sql=neutral,
        compute=neutral,
        workload=neutral,
    )
