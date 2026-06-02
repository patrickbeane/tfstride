from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, TypeVar

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.resource_facts import NeutralProviderResourceFacts
from tfstride.resource_metadata import MetadataField, StringListMetadataField


_MetadataValue = TypeVar("_MetadataValue")


@dataclass(frozen=True, slots=True)
class GcpResourceFacts(NeutralProviderResourceFacts):
    """GCP-owned view over provider-specific resource metadata."""

    def get(self, field: MetadataField[_MetadataValue]) -> _MetadataValue:
        return self.resource.get_metadata_field(field)

    def set(self, field: MetadataField[_MetadataValue], value: _MetadataValue) -> None:
        self.resource.set_metadata_field(field, value)

    def optional_bool(self, field: MetadataField[bool]) -> bool | None:
        if not self.resource.has_metadata_field(field):
            return None
        return self.get(field)

    def append(self, field: StringListMetadataField, value: str | None) -> None:
        self.resource.append_metadata_field(field, value)

    def extend(self, field: StringListMetadataField, values: Sequence[str | None]) -> None:
        self.resource.extend_metadata_field(field, values)

    @property
    def bucket_name(self) -> str | None:
        return self.get(GcpResourceMetadata.BUCKET_NAME)

    @property
    def resource_policy_source_addresses(self) -> list[str]:
        return self.get(GcpResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES)

    @property
    def project(self) -> str | None:
        return self.get(GcpResourceMetadata.PROJECT)

    @property
    def iam_bindings(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.IAM_BINDINGS)

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
            members.append(_service_account_member(email))
        return _dedupe(members)

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
        return _dedupe(scopes)

    @property
    def network_tags(self) -> list[str]:
        return self.get(GcpResourceMetadata.NETWORK_TAGS)

    @property
    def internet_ingress_firewalls(self) -> list[str]:
        return self.get(GcpResourceMetadata.INTERNET_INGRESS_FIREWALLS)

    @property
    def iam_role(self) -> str | None:
        return self.get(GcpResourceMetadata.IAM_ROLE)

    @property
    def iam_member(self) -> str | None:
        return self.get(GcpResourceMetadata.IAM_MEMBER)


def gcp_facts(resource: NormalizedResource) -> GcpResourceFacts:
    return GcpResourceFacts(resource)


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


def _service_account_member(email: str) -> str:
    if email.startswith("serviceAccount:"):
        return email
    return f"serviceAccount:{email}"


def _dedupe(values: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        deduped.append(value)
        seen.add(value)
    return deduped