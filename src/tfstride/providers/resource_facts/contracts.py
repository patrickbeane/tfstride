from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from tfstride.models import NormalizedResource


class ProviderStorageFacts(Protocol):
    """Storage facts exposed by provider-owned resource adapters."""

    @property
    def bucket_name(self) -> str | None:
        raise NotImplementedError

    @property
    def bucket_acl(self) -> str:
        raise NotImplementedError

    @property
    def public_access_block(self) -> dict[str, bool] | None:
        raise NotImplementedError

    @property
    def uniform_bucket_level_access(self) -> bool | None:
        raise NotImplementedError

    @property
    def public_access_prevention(self) -> str | None:
        raise NotImplementedError

    @property
    def versioning_enabled(self) -> bool | None:
        raise NotImplementedError

    @property
    def default_kms_key_name(self) -> str | None:
        raise NotImplementedError

    @property
    def customer_managed_encryption(self) -> bool | None:
        raise NotImplementedError

    @property
    def gcs_retention_period_seconds(self) -> int | None:
        raise NotImplementedError

    @property
    def gcs_retention_policy_locked(self) -> bool | None:
        raise NotImplementedError

    @property
    def gcs_retention_policy_configuration(self) -> dict[str, Any]:
        raise NotImplementedError

    @property
    def gcs_retention_policy_uncertainties(self) -> list[str]:
        raise NotImplementedError


class ProviderIamFacts(Protocol):
    """IAM, policy, hierarchy, and identity facts from provider adapters."""

    @property
    def policy_document(self) -> dict[str, Any]:
        raise NotImplementedError

    @property
    def trust_statements(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    @property
    def resource_policy_source_addresses(self) -> list[str]:
        raise NotImplementedError

    @property
    def project(self) -> str | None:
        raise NotImplementedError

    @property
    def resource_name(self) -> str | None:
        raise NotImplementedError

    @property
    def reference_values(self) -> list[str]:
        raise NotImplementedError

    @property
    def iam_target_reference(self) -> str | None:
        raise NotImplementedError

    @property
    def iam_bindings(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    @property
    def custom_role_id(self) -> str | None:
        raise NotImplementedError

    @property
    def custom_role_permissions(self) -> list[str]:
        raise NotImplementedError

    @property
    def organization_id(self) -> str | None:
        raise NotImplementedError

    @property
    def folder_id(self) -> str | None:
        raise NotImplementedError

    @property
    def service_account_email(self) -> str | None:
        raise NotImplementedError

    @property
    def service_account_member(self) -> str | None:
        raise NotImplementedError

    @property
    def service_account_reference(self) -> str | None:
        raise NotImplementedError

    @property
    def iam_role(self) -> str | None:
        raise NotImplementedError

    @property
    def iam_member(self) -> str | None:
        raise NotImplementedError

    @property
    def org_policy_constraint(self) -> str | None:
        raise NotImplementedError

    @property
    def org_policy_rules(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    @property
    def org_policy_allowed_values(self) -> list[str]:
        raise NotImplementedError

    @property
    def org_policy_denied_values(self) -> list[str]:
        raise NotImplementedError

    @property
    def org_policy_enforced(self) -> bool | None:
        raise NotImplementedError

    @property
    def org_policy_inherit_from_parent(self) -> bool | None:
        raise NotImplementedError

    @property
    def org_policy_restore_default(self) -> bool:
        raise NotImplementedError

    @property
    def org_policy_scope_type(self) -> str | None:
        raise NotImplementedError

    @property
    def org_policy_scope(self) -> str | None:
        raise NotImplementedError

    @property
    def service_account_key_keepers(self) -> dict[str, Any]:
        raise NotImplementedError

    @property
    def service_account_key_algorithm(self) -> str | None:
        raise NotImplementedError

    @property
    def service_account_public_key_type(self) -> str | None:
        raise NotImplementedError

    @property
    def service_account_id(self) -> str | None:
        raise NotImplementedError

    @property
    def service_account_key_valid_after(self) -> str | None:
        raise NotImplementedError

    @property
    def service_account_key_valid_before(self) -> str | None:
        raise NotImplementedError


class ProviderSqlFacts(Protocol):
    """Managed SQL and database posture facts from provider adapters."""

    @property
    def engine(self) -> str | None:
        raise NotImplementedError

    @property
    def authorized_networks(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    @property
    def backup_enabled(self) -> bool | None:
        raise NotImplementedError

    @property
    def point_in_time_recovery_enabled(self) -> bool | None:
        raise NotImplementedError

    @property
    def ipv4_enabled(self) -> bool | None:
        raise NotImplementedError

    @property
    def private_network(self) -> str | None:
        raise NotImplementedError

    @property
    def require_ssl(self) -> bool | None:
        raise NotImplementedError

    @property
    def ssl_mode(self) -> str | None:
        raise NotImplementedError

    @property
    def deletion_protection(self) -> bool | None:
        raise NotImplementedError


class ProviderComputeFacts(Protocol):
    """Compute and network posture facts from provider adapters."""

    @property
    def os_login_enabled(self) -> bool | None:
        raise NotImplementedError

    @property
    def network_tags(self) -> list[str]:
        raise NotImplementedError

    @property
    def internet_ingress_firewalls(self) -> list[str]:
        raise NotImplementedError

    @property
    def fronted_by_internet_facing_load_balancer(self) -> bool:
        raise NotImplementedError

    @property
    def internet_facing_load_balancer_addresses(self) -> list[str]:
        raise NotImplementedError

    @property
    def load_balancer_frontends(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    @property
    def load_balancer_reachable_backends(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    @property
    def forwarding_rule_target(self) -> str | None:
        raise NotImplementedError

    @property
    def forwarding_rule_load_balancing_scheme(self) -> str | None:
        raise NotImplementedError

    @property
    def forwarding_rule_ip_address(self) -> str | None:
        raise NotImplementedError

    @property
    def forwarding_rule_ports(self) -> list[str]:
        raise NotImplementedError

    @property
    def load_balancer_ssl_policy(self) -> str | None:
        raise NotImplementedError

    @property
    def load_balancer_certificate_map(self) -> str | None:
        raise NotImplementedError

    @property
    def ssl_policy_min_tls_version(self) -> str | None:
        raise NotImplementedError

    @property
    def ssl_policy_profile(self) -> str | None:
        raise NotImplementedError

    @property
    def ssl_policy_custom_features(self) -> list[str]:
        raise NotImplementedError

    @property
    def ssl_policy_enabled_features(self) -> list[str]:
        raise NotImplementedError

    @property
    def gke_endpoint(self) -> str | None:
        raise NotImplementedError

    @property
    def gke_private_endpoint_enabled(self) -> bool | None:
        raise NotImplementedError

    @property
    def gke_private_nodes_enabled(self) -> bool | None:
        raise NotImplementedError

    @property
    def gke_master_authorized_networks(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    @property
    def gke_workload_identity_enabled(self) -> bool | None:
        raise NotImplementedError

    @property
    def gke_workload_identity_pool(self) -> str | None:
        raise NotImplementedError

    @property
    def gke_node_service_account(self) -> str | None:
        raise NotImplementedError

    @property
    def gke_node_oauth_scopes(self) -> list[str]:
        raise NotImplementedError

    @property
    def gke_node_metadata_mode(self) -> str | None:
        raise NotImplementedError

    @property
    def gke_legacy_metadata_endpoints_enabled(self) -> bool | None:
        raise NotImplementedError

    @property
    def gke_logging_service(self) -> str | None:
        raise NotImplementedError

    @property
    def gke_logging_components(self) -> list[str]:
        raise NotImplementedError

    @property
    def gke_control_plane_logging_state(self) -> str | None:
        raise NotImplementedError

    @property
    def gke_logging_config(self) -> dict[str, Any]:
        raise NotImplementedError

    @property
    def gke_network_policy_state(self) -> str | None:
        raise NotImplementedError

    @property
    def gke_network_policy_provider(self) -> str | None:
        raise NotImplementedError

    @property
    def gke_network_policy(self) -> dict[str, Any]:
        raise NotImplementedError

    @property
    def gke_database_encryption_state(self) -> str | None:
        raise NotImplementedError

    @property
    def gke_database_encryption_key_name(self) -> str | None:
        raise NotImplementedError

    @property
    def gke_secrets_encryption_state(self) -> str | None:
        raise NotImplementedError

    @property
    def gke_database_encryption(self) -> dict[str, Any]:
        raise NotImplementedError

    @property
    def gke_legacy_abac_enabled(self) -> bool | None:
        raise NotImplementedError

    @property
    def gke_legacy_abac_state(self) -> str | None:
        raise NotImplementedError

    @property
    def gke_client_certificate_auth_enabled(self) -> bool | None:
        raise NotImplementedError

    @property
    def gke_client_certificate_auth_state(self) -> str | None:
        raise NotImplementedError

    @property
    def gke_basic_auth_state(self) -> str | None:
        raise NotImplementedError

    @property
    def gke_basic_auth_username(self) -> str | None:
        raise NotImplementedError

    @property
    def gke_basic_auth_password_configured(self) -> bool | None:
        raise NotImplementedError

    @property
    def gke_master_auth(self) -> dict[str, Any]:
        raise NotImplementedError

    @property
    def gke_client_certificate_config(self) -> dict[str, Any]:
        raise NotImplementedError

    @property
    def gke_release_channel(self) -> str | None:
        raise NotImplementedError

    @property
    def gke_release_channel_config(self) -> dict[str, Any]:
        raise NotImplementedError

    @property
    def gke_shielded_nodes_enabled(self) -> bool | None:
        raise NotImplementedError

    @property
    def gke_shielded_nodes_state(self) -> str | None:
        raise NotImplementedError

    @property
    def gke_shielded_nodes_config(self) -> dict[str, Any]:
        raise NotImplementedError

    @property
    def gke_binary_authorization_evaluation_mode(self) -> str | None:
        raise NotImplementedError

    @property
    def gke_binary_authorization_state(self) -> str | None:
        raise NotImplementedError

    @property
    def gke_binary_authorization(self) -> dict[str, Any]:
        raise NotImplementedError

    @property
    def gke_posture_uncertainties(self) -> list[str]:
        raise NotImplementedError


class ProviderWorkloadFacts(Protocol):
    """Workload identity facts from provider adapters."""

    @property
    def workload_identity_members(self) -> list[str]:
        raise NotImplementedError

    @property
    def workload_identity_scopes(self) -> list[str]:
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class ProviderResourceFactDomains:
    """Provider-owned facts grouped by shared analysis domain."""

    storage: ProviderStorageFacts
    iam: ProviderIamFacts
    sql: ProviderSqlFacts
    compute: ProviderComputeFacts
    workload: ProviderWorkloadFacts


ProviderResourceFactsFactory = Callable[[NormalizedResource], ProviderResourceFactDomains]
