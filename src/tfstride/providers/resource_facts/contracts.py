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
