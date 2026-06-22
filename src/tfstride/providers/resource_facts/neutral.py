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
