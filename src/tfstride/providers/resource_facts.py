from __future__ import annotations

from collections.abc import Callable, Iterable
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
    def gcs_uniform_bucket_level_access(self) -> bool | None:
        raise NotImplementedError

    @property
    def gcs_public_access_prevention(self) -> str | None:
        raise NotImplementedError

    @property
    def gcs_versioning_enabled(self) -> bool | None:
        raise NotImplementedError

    @property
    def gcs_default_kms_key_name(self) -> str | None:
        raise NotImplementedError

    @property
    def customer_managed_encryption(self) -> bool | None:
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


class ProviderSqlFacts(Protocol):
    """Managed SQL and database posture facts from provider adapters."""

    @property
    def engine(self) -> str | None:
        raise NotImplementedError

    @property
    def cloud_sql_authorized_networks(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    @property
    def cloud_sql_backup_enabled(self) -> bool | None:
        raise NotImplementedError

    @property
    def cloud_sql_point_in_time_recovery_enabled(self) -> bool | None:
        raise NotImplementedError

    @property
    def cloud_sql_ipv4_enabled(self) -> bool | None:
        raise NotImplementedError

    @property
    def cloud_sql_private_network(self) -> str | None:
        raise NotImplementedError

    @property
    def cloud_sql_require_ssl(self) -> bool | None:
        raise NotImplementedError

    @property
    def cloud_sql_ssl_mode(self) -> str | None:
        raise NotImplementedError

    @property
    def deletion_protection(self) -> bool | None:
        raise NotImplementedError


class ProviderGkeFacts(Protocol):
    """GKE cluster and node posture facts from provider adapters."""

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


class ProviderWorkloadFacts(Protocol):
    """Workload identity facts from provider adapters."""

    @property
    def workload_identity_members(self) -> list[str]:
        raise NotImplementedError

    @property
    def workload_identity_scopes(self) -> list[str]:
        raise NotImplementedError


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
    def gcs_uniform_bucket_level_access(self) -> bool | None:
        return None

    @property
    def gcs_public_access_prevention(self) -> str | None:
        return None

    @property
    def gcs_versioning_enabled(self) -> bool | None:
        return None

    @property
    def gcs_default_kms_key_name(self) -> str | None:
        return None

    @property
    def customer_managed_encryption(self) -> bool | None:
        return None


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


class NeutralProviderSqlFacts:
    """Neutral SQL facts for providers without managed SQL signals."""

    __slots__ = ()

    @property
    def engine(self) -> str | None:
        return None

    @property
    def cloud_sql_authorized_networks(self) -> list[dict[str, Any]]:
        return []

    @property
    def cloud_sql_backup_enabled(self) -> bool | None:
        return None

    @property
    def cloud_sql_point_in_time_recovery_enabled(self) -> bool | None:
        return None

    @property
    def cloud_sql_ipv4_enabled(self) -> bool | None:
        return None

    @property
    def cloud_sql_private_network(self) -> str | None:
        return None

    @property
    def cloud_sql_require_ssl(self) -> bool | None:
        return None

    @property
    def cloud_sql_ssl_mode(self) -> str | None:
        return None

    @property
    def deletion_protection(self) -> bool | None:
        return None


class NeutralProviderGkeFacts:
    """Neutral GKE facts for providers without GKE cluster signals."""

    __slots__ = ()

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
class ProviderResourceFactDomains:
    """Provider-owned facts grouped by shared analysis domain."""

    storage: ProviderStorageFacts
    iam: ProviderIamFacts
    sql: ProviderSqlFacts
    gke: ProviderGkeFacts
    compute: ProviderComputeFacts
    workload: ProviderWorkloadFacts


ProviderResourceFactsFactory = Callable[[NormalizedResource], ProviderResourceFactDomains]


def neutral_provider_resource_fact_domains(resource: NormalizedResource) -> ProviderResourceFactDomains:
    """Build a neutral domain facts bundle for providers without facts adapters."""

    neutral = NeutralProviderResourceFacts(resource)
    return ProviderResourceFactDomains(
        storage=neutral,
        iam=neutral,
        sql=neutral,
        gke=neutral,
        compute=neutral,
        workload=neutral,
    )


class ProviderResourceFactsRegistryError(ValueError):
    """Raised when provider facts registry configuration or lookup fails."""


class ProviderResourceFactsNotRegisteredError(ProviderResourceFactsRegistryError):
    """Raised when a requested provider has no registered facts factory."""


@dataclass(frozen=True, slots=True)
class NeutralProviderResourceFacts(
    NeutralProviderStorageFacts,
    NeutralProviderIamFacts,
    NeutralProviderSqlFacts,
    NeutralProviderGkeFacts,
    NeutralProviderComputeFacts,
    NeutralProviderWorkloadFacts,
):
    """Neutral facts for providers without a shared-analysis facts adapter yet."""

    resource: NormalizedResource


class ProviderResourceFactsRegistry:
    def __init__(
        self,
        factories: Iterable[tuple[str, ProviderResourceFactsFactory]] = (),
    ) -> None:
        self._factories: dict[str, ProviderResourceFactsFactory] = {}
        for provider, factory in factories:
            self.register(provider, factory)

    def register(self, provider: str, factory: ProviderResourceFactsFactory) -> None:
        provider_name = _normalize_provider_name(provider)
        if not provider_name:
            raise ProviderResourceFactsRegistryError("Provider facts factories must define a non-empty provider name.")
        if provider_name in self._factories:
            raise ProviderResourceFactsRegistryError(
                f"Provider facts factory already registered for `{provider_name}`."
            )
        if not callable(factory):
            raise ProviderResourceFactsRegistryError(f"Provider facts factory for `{provider_name}` must be callable.")
        self._factories[provider_name] = factory

    def get(self, provider: str) -> ProviderResourceFactsFactory:
        provider_name = _normalize_provider_name(provider)
        try:
            return self._factories[provider_name]
        except KeyError as exc:
            raise ProviderResourceFactsNotRegisteredError(
                f"No provider facts factory registered for `{provider_name}`."
            ) from exc

    def facts_for(self, resource: NormalizedResource) -> ProviderResourceFactDomains:
        provider_name = _normalize_provider_name(resource.provider)
        factory = self._factories.get(provider_name)
        if factory is None:
            return neutral_provider_resource_fact_domains(resource)
        return factory(resource)

    def providers(self) -> tuple[str, ...]:
        return tuple(self._factories)


def _normalize_provider_name(provider: str) -> str:
    return str(provider).strip().lower()
