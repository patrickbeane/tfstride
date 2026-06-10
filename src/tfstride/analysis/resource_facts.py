from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.catalog import default_resource_facts_registry
from tfstride.providers.resource_facts import (
    ProviderResourceFacts,
    ProviderResourceFactsRegistry,
)


_DEFAULT_RESOURCE_FACTS_REGISTRY = default_resource_facts_registry()


@dataclass(frozen=True, slots=True)
class AnalysisStorageFacts:
    _facts: ProviderResourceFacts

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
        return self._facts.gcs_uniform_bucket_level_access

    @property
    def public_access_prevention(self) -> str | None:
        return self._facts.gcs_public_access_prevention

    @property
    def versioning_enabled(self) -> bool | None:
        return self._facts.gcs_versioning_enabled

    @property
    def default_kms_key_name(self) -> str | None:
        return self._facts.gcs_default_kms_key_name


@dataclass(frozen=True, slots=True)
class AnalysisIamFacts:
    _facts: ProviderResourceFacts

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


@dataclass(frozen=True, slots=True)
class AnalysisSqlFacts:
    _facts: ProviderResourceFacts

    @property
    def engine(self) -> str | None:
        return self._facts.engine

    @property
    def authorized_networks(self) -> list[dict[str, Any]]:
        return self._facts.cloud_sql_authorized_networks

    @property
    def backup_enabled(self) -> bool | None:
        return self._facts.cloud_sql_backup_enabled

    @property
    def point_in_time_recovery_enabled(self) -> bool | None:
        return self._facts.cloud_sql_point_in_time_recovery_enabled

    @property
    def ipv4_enabled(self) -> bool | None:
        return self._facts.cloud_sql_ipv4_enabled

    @property
    def private_network(self) -> str | None:
        return self._facts.cloud_sql_private_network

    @property
    def require_ssl(self) -> bool | None:
        return self._facts.cloud_sql_require_ssl

    @property
    def ssl_mode(self) -> str | None:
        return self._facts.cloud_sql_ssl_mode

    @property
    def deletion_protection(self) -> bool | None:
        return self._facts.deletion_protection


@dataclass(frozen=True, slots=True)
class AnalysisGkeFacts:
    _facts: ProviderResourceFacts

    @property
    def endpoint(self) -> str | None:
        return self._facts.gke_endpoint

    @property
    def private_endpoint_enabled(self) -> bool | None:
        return self._facts.gke_private_endpoint_enabled

    @property
    def private_nodes_enabled(self) -> bool | None:
        return self._facts.gke_private_nodes_enabled

    @property
    def master_authorized_networks(self) -> list[dict[str, Any]]:
        return self._facts.gke_master_authorized_networks

    @property
    def workload_identity_enabled(self) -> bool | None:
        return self._facts.gke_workload_identity_enabled

    @property
    def workload_identity_pool(self) -> str | None:
        return self._facts.gke_workload_identity_pool

    @property
    def node_service_account(self) -> str | None:
        return self._facts.gke_node_service_account

    @property
    def node_oauth_scopes(self) -> list[str]:
        return self._facts.gke_node_oauth_scopes

    @property
    def node_metadata_mode(self) -> str | None:
        return self._facts.gke_node_metadata_mode

    @property
    def legacy_metadata_endpoints_enabled(self) -> bool | None:
        return self._facts.gke_legacy_metadata_endpoints_enabled


@dataclass(frozen=True, slots=True)
class AnalysisComputeFacts:
    _facts: ProviderResourceFacts

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


@dataclass(frozen=True, slots=True)
class AnalysisWorkloadFacts:
    _facts: ProviderResourceFacts

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
    _provider_facts: ProviderResourceFacts | None = None

    def __post_init__(self) -> None:
        if self._provider_facts is None:
            object.__setattr__(
                self,
                "_provider_facts",
                _DEFAULT_RESOURCE_FACTS_REGISTRY.facts_for(self.resource),
            )

    @property
    def _facts(self) -> ProviderResourceFacts:
        if self._provider_facts is None:
            raise RuntimeError("AnalysisResourceFacts was initialized without provider facts.")
        return self._provider_facts

    @property
    def storage(self) -> AnalysisStorageFacts:
        return AnalysisStorageFacts(self._facts)

    @property
    def iam(self) -> AnalysisIamFacts:
        return AnalysisIamFacts(self._facts)

    @property
    def sql(self) -> AnalysisSqlFacts:
        return AnalysisSqlFacts(self._facts)

    @property
    def gke(self) -> AnalysisGkeFacts:
        return AnalysisGkeFacts(self._facts)

    @property
    def compute(self) -> AnalysisComputeFacts:
        return AnalysisComputeFacts(self._facts)

    @property
    def workload(self) -> AnalysisWorkloadFacts:
        return AnalysisWorkloadFacts(self._facts)


def analysis_facts(
    resource: NormalizedResource,
    *,
    facts_registry: ProviderResourceFactsRegistry | None = None,
) -> AnalysisResourceFacts:
    registry = facts_registry or _DEFAULT_RESOURCE_FACTS_REGISTRY
    return AnalysisResourceFacts(resource, registry.facts_for(resource))