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
class AnalysisResourceFacts:
    """Read facade for provider-backed facts used by shared analysis."""

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
    def bucket_name(self) -> str | None:
        return self._facts.bucket_name

    @property
    def bucket_acl(self) -> str:
        return self._facts.bucket_acl

    @property
    def public_access_block(self) -> dict[str, bool] | None:
        return self._facts.public_access_block

    @property
    def gcs_uniform_bucket_level_access(self) -> bool | None:
        return self._facts.gcs_uniform_bucket_level_access

    @property
    def gcs_public_access_prevention(self) -> str | None:
        return self._facts.gcs_public_access_prevention

    @property
    def gcs_versioning_enabled(self) -> bool | None:
        return self._facts.gcs_versioning_enabled

    @property
    def gcs_default_kms_key_name(self) -> str | None:
        return self._facts.gcs_default_kms_key_name

    @property
    def policy_document(self) -> dict[str, Any]:
        return self._facts.policy_document

    @property
    def trust_statements(self) -> list[dict[str, Any]]:
        return self._facts.trust_statements

    @property
    def database_engine(self) -> str | None:
        return self._facts.engine

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
    def iam_bindings(self) -> list[dict[str, Any]]:
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
    def cloud_sql_authorized_networks(self) -> list[dict[str, Any]]:
        return self._facts.cloud_sql_authorized_networks

    @property
    def cloud_sql_backup_enabled(self) -> bool | None:
        return self._facts.cloud_sql_backup_enabled

    @property
    def cloud_sql_point_in_time_recovery_enabled(self) -> bool | None:
        return self._facts.cloud_sql_point_in_time_recovery_enabled

    @property
    def cloud_sql_ipv4_enabled(self) -> bool | None:
        return self._facts.cloud_sql_ipv4_enabled

    @property
    def cloud_sql_private_network(self) -> str | None:
        return self._facts.cloud_sql_private_network

    @property
    def cloud_sql_require_ssl(self) -> bool | None:
        return self._facts.cloud_sql_require_ssl

    @property
    def cloud_sql_ssl_mode(self) -> str | None:
        return self._facts.cloud_sql_ssl_mode

    @property
    def deletion_protection(self) -> bool | None:
        return self._facts.deletion_protection

    @property
    def os_login_enabled(self) -> bool | None:
        return self._facts.os_login_enabled

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
    def service_account_email(self) -> str | None:
        return self._facts.service_account_email

    @property
    def service_account_member(self) -> str | None:
        return self._facts.service_account_member

    @property
    def service_account_reference(self) -> str | None:
        return self._facts.service_account_reference

    @property
    def workload_identity_members(self) -> list[str]:
        return self._facts.workload_identity_members

    @property
    def workload_identity_scopes(self) -> list[str]:
        return self._facts.workload_identity_scopes

    @property
    def network_tags(self) -> list[str]:
        return self._facts.network_tags

    @property
    def internet_ingress_firewalls(self) -> list[str]:
        return self._facts.internet_ingress_firewalls

    @property
    def iam_role(self) -> str | None:
        return self._facts.iam_role

    @property
    def iam_member(self) -> str | None:
        return self._facts.iam_member


def analysis_facts(
    resource: NormalizedResource,
    *,
    facts_registry: ProviderResourceFactsRegistry | None = None,
) -> AnalysisResourceFacts:
    registry = facts_registry or _DEFAULT_RESOURCE_FACTS_REGISTRY
    return AnalysisResourceFacts(resource, registry.facts_for(resource))