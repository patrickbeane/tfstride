from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.catalog import default_resource_facts_registry
from tfstride.providers.resource_facts import (
    ProviderComputeFacts,
    ProviderIamFacts,
    ProviderResourceFactDomains,
    ProviderResourceFactsRegistry,
    ProviderSqlFacts,
    ProviderStorageFacts,
    ProviderWorkloadFacts,
)

_DEFAULT_RESOURCE_FACTS_REGISTRY = default_resource_facts_registry()


@dataclass(frozen=True, slots=True)
class AnalysisStorageFacts:
    _facts: ProviderStorageFacts

    @property
    def bucket_name(self) -> str | None:
        return self._facts.bucket_name

    @property
    def bucket_acl(self) -> str:
        return self._facts.bucket_acl

    @property
    def public_access_block(self) -> dict[str, bool] | None:
        return self._facts.public_access_block

    @property
    def uniform_bucket_level_access(self) -> bool | None:
        return self._facts.uniform_bucket_level_access

    @property
    def public_access_prevention(self) -> str | None:
        return self._facts.public_access_prevention

    @property
    def versioning_enabled(self) -> bool | None:
        return self._facts.versioning_enabled

    @property
    def default_kms_key_name(self) -> str | None:
        return self._facts.default_kms_key_name

    @property
    def customer_managed_encryption(self) -> bool | None:
        return self._facts.customer_managed_encryption

    @property
    def gcs_retention_period_seconds(self) -> int | None:
        return self._facts.gcs_retention_period_seconds

    @property
    def gcs_retention_policy_locked(self) -> bool | None:
        return self._facts.gcs_retention_policy_locked

    @property
    def gcs_retention_policy_configuration(self) -> dict[str, Any]:
        return self._facts.gcs_retention_policy_configuration

    @property
    def gcs_retention_policy_uncertainties(self) -> list[str]:
        return self._facts.gcs_retention_policy_uncertainties

    @property
    def secret_manager_replication_mode(self) -> str | None:
        return self._facts.secret_manager_replication_mode

    @property
    def secret_manager_kms_key_names(self) -> list[str]:
        return self._facts.secret_manager_kms_key_names

    @property
    def secret_manager_replication(self) -> dict[str, Any]:
        return self._facts.secret_manager_replication

    @property
    def secret_manager_ttl(self) -> str | None:
        return self._facts.secret_manager_ttl

    @property
    def secret_manager_expire_time(self) -> str | None:
        return self._facts.secret_manager_expire_time

    @property
    def secret_manager_version_destroy_ttl(self) -> str | None:
        return self._facts.secret_manager_version_destroy_ttl

    @property
    def secret_manager_posture_uncertainties(self) -> list[str]:
        return self._facts.secret_manager_posture_uncertainties

    @property
    def kms_purpose(self) -> str | None:
        return self._facts.kms_purpose

    @property
    def kms_rotation_period(self) -> str | None:
        return self._facts.kms_rotation_period

    @property
    def kms_posture_uncertainties(self) -> list[str]:
        return self._facts.kms_posture_uncertainties


@dataclass(frozen=True, slots=True)
class AnalysisIamFacts:
    _facts: ProviderIamFacts

    @property
    def policy_document(self) -> dict[str, Any]:
        return self._facts.policy_document

    @property
    def trust_statements(self) -> list[dict[str, Any]]:
        return self._facts.trust_statements

    @property
    def resource_policy_source_addresses(self) -> list[str]:
        return self._facts.resource_policy_source_addresses

    @property
    def project(self) -> str | None:
        return self._facts.project

    @property
    def resource_name(self) -> str | None:
        return self._facts.resource_name

    @property
    def reference_values(self) -> list[str]:
        return self._facts.reference_values

    @property
    def target_reference(self) -> str | None:
        return self._facts.iam_target_reference

    @property
    def bindings(self) -> list[dict[str, Any]]:
        return self._facts.iam_bindings

    @property
    def custom_role_id(self) -> str | None:
        return self._facts.custom_role_id

    @property
    def custom_role_permissions(self) -> list[str]:
        return self._facts.custom_role_permissions

    @property
    def organization_id(self) -> str | None:
        return self._facts.organization_id

    @property
    def folder_id(self) -> str | None:
        return self._facts.folder_id

    @property
    def service_account_email(self) -> str | None:
        return self._facts.service_account_email

    @property
    def service_account_member(self) -> str | None:
        return self._facts.service_account_member

    @property
    def service_account_reference(self) -> str | None:
        return self._facts.service_account_reference

    @property
    def role(self) -> str | None:
        return self._facts.iam_role

    @property
    def member(self) -> str | None:
        return self._facts.iam_member

    @property
    def org_policy_constraint(self) -> str | None:
        return self._facts.org_policy_constraint

    @property
    def org_policy_rules(self) -> list[dict[str, Any]]:
        return self._facts.org_policy_rules

    @property
    def org_policy_allowed_values(self) -> list[str]:
        return self._facts.org_policy_allowed_values

    @property
    def org_policy_denied_values(self) -> list[str]:
        return self._facts.org_policy_denied_values

    @property
    def org_policy_enforced(self) -> bool | None:
        return self._facts.org_policy_enforced

    @property
    def org_policy_inherit_from_parent(self) -> bool | None:
        return self._facts.org_policy_inherit_from_parent

    @property
    def org_policy_restore_default(self) -> bool:
        return self._facts.org_policy_restore_default

    @property
    def org_policy_scope_type(self) -> str | None:
        return self._facts.org_policy_scope_type

    @property
    def org_policy_scope(self) -> str | None:
        return self._facts.org_policy_scope

    @property
    def service_account_key_keepers(self) -> dict[str, Any]:
        return self._facts.service_account_key_keepers

    @property
    def service_account_key_algorithm(self) -> str | None:
        return self._facts.service_account_key_algorithm

    @property
    def service_account_public_key_type(self) -> str | None:
        return self._facts.service_account_public_key_type

    @property
    def service_account_id(self) -> str | None:
        return self._facts.service_account_id

    @property
    def service_account_key_valid_after(self) -> str | None:
        return self._facts.service_account_key_valid_after

    @property
    def service_account_key_valid_before(self) -> str | None:
        return self._facts.service_account_key_valid_before


@dataclass(frozen=True, slots=True)
class AnalysisSqlFacts:
    _facts: ProviderSqlFacts

    @property
    def engine(self) -> str | None:
        return self._facts.engine

    @property
    def authorized_networks(self) -> list[dict[str, Any]]:
        return self._facts.authorized_networks

    @property
    def backup_enabled(self) -> bool | None:
        return self._facts.backup_enabled

    @property
    def point_in_time_recovery_enabled(self) -> bool | None:
        return self._facts.point_in_time_recovery_enabled

    @property
    def ipv4_enabled(self) -> bool | None:
        return self._facts.ipv4_enabled

    @property
    def private_network(self) -> str | None:
        return self._facts.private_network

    @property
    def require_ssl(self) -> bool | None:
        return self._facts.require_ssl

    @property
    def ssl_mode(self) -> str | None:
        return self._facts.ssl_mode

    @property
    def deletion_protection(self) -> bool | None:
        return self._facts.deletion_protection


@dataclass(frozen=True, slots=True)
class AnalysisComputeFacts:
    _facts: ProviderComputeFacts

    @property
    def os_login_enabled(self) -> bool | None:
        return self._facts.os_login_enabled

    @property
    def network_tags(self) -> list[str]:
        return self._facts.network_tags

    @property
    def internet_ingress_firewalls(self) -> list[str]:
        return self._facts.internet_ingress_firewalls

    @property
    def fronted_by_internet_facing_load_balancer(self) -> bool:
        return self._facts.fronted_by_internet_facing_load_balancer

    @property
    def internet_facing_load_balancer_addresses(self) -> list[str]:
        return self._facts.internet_facing_load_balancer_addresses

    @property
    def load_balancer_frontends(self) -> list[dict[str, Any]]:
        return self._facts.load_balancer_frontends

    @property
    def load_balancer_reachable_backends(self) -> list[dict[str, Any]]:
        return self._facts.load_balancer_reachable_backends

    @property
    def forwarding_rule_target(self) -> str | None:
        return self._facts.forwarding_rule_target

    @property
    def forwarding_rule_load_balancing_scheme(self) -> str | None:
        return self._facts.forwarding_rule_load_balancing_scheme

    @property
    def forwarding_rule_ip_address(self) -> str | None:
        return self._facts.forwarding_rule_ip_address

    @property
    def forwarding_rule_ports(self) -> list[str]:
        return self._facts.forwarding_rule_ports

    @property
    def load_balancer_ssl_policy(self) -> str | None:
        return self._facts.load_balancer_ssl_policy

    @property
    def load_balancer_certificate_map(self) -> str | None:
        return self._facts.load_balancer_certificate_map

    @property
    def ssl_policy_min_tls_version(self) -> str | None:
        return self._facts.ssl_policy_min_tls_version

    @property
    def ssl_policy_profile(self) -> str | None:
        return self._facts.ssl_policy_profile

    @property
    def ssl_policy_custom_features(self) -> list[str]:
        return self._facts.ssl_policy_custom_features

    @property
    def ssl_policy_enabled_features(self) -> list[str]:
        return self._facts.ssl_policy_enabled_features

    @property
    def gke_endpoint(self) -> str | None:
        return self._facts.gke_endpoint

    @property
    def gke_private_endpoint_enabled(self) -> bool | None:
        return self._facts.gke_private_endpoint_enabled

    @property
    def gke_private_nodes_enabled(self) -> bool | None:
        return self._facts.gke_private_nodes_enabled

    @property
    def gke_master_authorized_networks(self) -> list[dict[str, Any]]:
        return self._facts.gke_master_authorized_networks

    @property
    def gke_workload_identity_enabled(self) -> bool | None:
        return self._facts.gke_workload_identity_enabled

    @property
    def gke_workload_identity_pool(self) -> str | None:
        return self._facts.gke_workload_identity_pool

    @property
    def gke_node_service_account(self) -> str | None:
        return self._facts.gke_node_service_account

    @property
    def gke_node_oauth_scopes(self) -> list[str]:
        return self._facts.gke_node_oauth_scopes

    @property
    def gke_node_metadata_mode(self) -> str | None:
        return self._facts.gke_node_metadata_mode

    @property
    def gke_legacy_metadata_endpoints_enabled(self) -> bool | None:
        return self._facts.gke_legacy_metadata_endpoints_enabled

    @property
    def gke_logging_service(self) -> str | None:
        return self._facts.gke_logging_service

    @property
    def gke_logging_components(self) -> list[str]:
        return self._facts.gke_logging_components

    @property
    def gke_control_plane_logging_state(self) -> str | None:
        return self._facts.gke_control_plane_logging_state

    @property
    def gke_logging_config(self) -> dict[str, Any]:
        return self._facts.gke_logging_config

    @property
    def gke_network_policy_state(self) -> str | None:
        return self._facts.gke_network_policy_state

    @property
    def gke_network_policy_provider(self) -> str | None:
        return self._facts.gke_network_policy_provider

    @property
    def gke_network_policy(self) -> dict[str, Any]:
        return self._facts.gke_network_policy

    @property
    def gke_database_encryption_state(self) -> str | None:
        return self._facts.gke_database_encryption_state

    @property
    def gke_database_encryption_key_name(self) -> str | None:
        return self._facts.gke_database_encryption_key_name

    @property
    def gke_secrets_encryption_state(self) -> str | None:
        return self._facts.gke_secrets_encryption_state

    @property
    def gke_database_encryption(self) -> dict[str, Any]:
        return self._facts.gke_database_encryption

    @property
    def gke_legacy_abac_enabled(self) -> bool | None:
        return self._facts.gke_legacy_abac_enabled

    @property
    def gke_legacy_abac_state(self) -> str | None:
        return self._facts.gke_legacy_abac_state

    @property
    def gke_client_certificate_auth_enabled(self) -> bool | None:
        return self._facts.gke_client_certificate_auth_enabled

    @property
    def gke_client_certificate_auth_state(self) -> str | None:
        return self._facts.gke_client_certificate_auth_state

    @property
    def gke_basic_auth_state(self) -> str | None:
        return self._facts.gke_basic_auth_state

    @property
    def gke_basic_auth_username(self) -> str | None:
        return self._facts.gke_basic_auth_username

    @property
    def gke_basic_auth_password_configured(self) -> bool | None:
        return self._facts.gke_basic_auth_password_configured

    @property
    def gke_master_auth(self) -> dict[str, Any]:
        return self._facts.gke_master_auth

    @property
    def gke_client_certificate_config(self) -> dict[str, Any]:
        return self._facts.gke_client_certificate_config

    @property
    def gke_release_channel(self) -> str | None:
        return self._facts.gke_release_channel

    @property
    def gke_release_channel_config(self) -> dict[str, Any]:
        return self._facts.gke_release_channel_config

    @property
    def gke_shielded_nodes_enabled(self) -> bool | None:
        return self._facts.gke_shielded_nodes_enabled

    @property
    def gke_shielded_nodes_state(self) -> str | None:
        return self._facts.gke_shielded_nodes_state

    @property
    def gke_shielded_nodes_config(self) -> dict[str, Any]:
        return self._facts.gke_shielded_nodes_config

    @property
    def gke_binary_authorization_evaluation_mode(self) -> str | None:
        return self._facts.gke_binary_authorization_evaluation_mode

    @property
    def gke_binary_authorization_state(self) -> str | None:
        return self._facts.gke_binary_authorization_state

    @property
    def gke_binary_authorization(self) -> dict[str, Any]:
        return self._facts.gke_binary_authorization

    @property
    def gke_posture_uncertainties(self) -> list[str]:
        return self._facts.gke_posture_uncertainties


@dataclass(frozen=True, slots=True)
class AnalysisWorkloadFacts:
    _facts: ProviderWorkloadFacts

    @property
    def identity_members(self) -> list[str]:
        return self._facts.workload_identity_members

    @property
    def identity_scopes(self) -> list[str]:
        return self._facts.workload_identity_scopes


@dataclass(frozen=True, slots=True)
class AnalysisResourceFacts:
    """Domain facades for provider-backed facts used by shared analysis."""

    resource: NormalizedResource
    _provider_facts: ProviderResourceFactDomains | None = None

    def __post_init__(self) -> None:
        if self._provider_facts is None:
            object.__setattr__(
                self,
                "_provider_facts",
                _DEFAULT_RESOURCE_FACTS_REGISTRY.facts_for(self.resource),
            )

    @property
    def _facts(self) -> ProviderResourceFactDomains:
        if self._provider_facts is None:
            raise RuntimeError("AnalysisResourceFacts was initialized without provider facts.")
        return self._provider_facts

    @property
    def storage(self) -> AnalysisStorageFacts:
        return AnalysisStorageFacts(self._facts.storage)

    @property
    def iam(self) -> AnalysisIamFacts:
        return AnalysisIamFacts(self._facts.iam)

    @property
    def sql(self) -> AnalysisSqlFacts:
        return AnalysisSqlFacts(self._facts.sql)

    @property
    def compute(self) -> AnalysisComputeFacts:
        return AnalysisComputeFacts(self._facts.compute)

    @property
    def workload(self) -> AnalysisWorkloadFacts:
        return AnalysisWorkloadFacts(self._facts.workload)


def analysis_facts(
    resource: NormalizedResource,
    *,
    facts_registry: ProviderResourceFactsRegistry | None = None,
) -> AnalysisResourceFacts:
    registry = facts_registry or _DEFAULT_RESOURCE_FACTS_REGISTRY
    return AnalysisResourceFacts(resource, registry.facts_for(resource))
