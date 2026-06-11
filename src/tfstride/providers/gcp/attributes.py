from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

from tfstride.providers.gcp.coercion import as_bool, as_list, as_optional_int, compact


T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class GcpAttribute(Generic[T]):
    """Typed Terraform Google provider attribute reader."""

    key: str

    def get(self, values: Mapping[str, Any]) -> T:
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class RawAttribute(GcpAttribute[Any]):
    default: Any = None

    def get(self, values: Mapping[str, Any]) -> Any:
        return values.get(self.key, self.default)


@dataclass(frozen=True, slots=True)
class OptionalStringAttribute(GcpAttribute[str | None]):
    def get(self, values: Mapping[str, Any]) -> str | None:
        value = values.get(self.key)
        if value is None:
            return None
        text = str(value).strip()
        return text or None


@dataclass(frozen=True, slots=True)
class BoolAttribute(GcpAttribute[bool]):
    default: bool = False

    def get(self, values: Mapping[str, Any]) -> bool:
        return as_bool(values.get(self.key, self.default))


@dataclass(frozen=True, slots=True)
class OptionalIntAttribute(GcpAttribute[int | None]):
    def get(self, values: Mapping[str, Any]) -> int | None:
        return as_optional_int(values.get(self.key))


@dataclass(frozen=True, slots=True)
class StringListAttribute(GcpAttribute[list[str]]):
    def get(self, values: Mapping[str, Any]) -> list[str]:
        return compact(as_list(values.get(self.key)))


@dataclass(frozen=True, slots=True)
class DictAttribute(GcpAttribute[dict[str, Any]]):
    def get(self, values: Mapping[str, Any]) -> dict[str, Any]:
        value = values.get(self.key)
        if not isinstance(value, dict):
            return {}
        return deepcopy(value)


@dataclass(frozen=True, slots=True)
class DictListAttribute(GcpAttribute[list[dict[str, Any]]]):
    def get(self, values: Mapping[str, Any]) -> list[dict[str, Any]]:
        return [deepcopy(item) for item in as_list(values.get(self.key)) if isinstance(item, dict)]


@dataclass(frozen=True, slots=True)
class GcpValues:
    """Provider-local facade over raw Terraform resource values."""

    values: Mapping[str, Any]

    def get(self, attribute: GcpAttribute[T]) -> T:
        return attribute.get(self.values)

    def raw(self, attribute: GcpAttribute[Any]) -> Any:
        return self.values.get(attribute.key)

    def has(self, attribute: GcpAttribute[Any]) -> bool:
        return attribute.key in self.values


class GcpAttr:
    """Common Terraform Google provider input attributes."""

    ACCOUNT_ID = OptionalStringAttribute("account_id")
    ACTION = OptionalStringAttribute("action")
    ALLOW = DictListAttribute("allow")
    ATTACHMENT_TARGET = OptionalStringAttribute("attachment_target")
    BACKEND = DictListAttribute("backend")
    BACKEND_SERVICE = OptionalStringAttribute("backend_service")
    BUCKET = OptionalStringAttribute("bucket")
    BUCKET_NAME = OptionalStringAttribute("bucket_name")
    CONDITION = DictListAttribute("condition")
    CRYPTO_KEY = OptionalStringAttribute("crypto_key")
    CRYPTO_KEY_ID = OptionalStringAttribute("crypto_key_id")
    DATASET = OptionalStringAttribute("dataset")
    DATASET_ID = OptionalStringAttribute("dataset_id")
    DELETED = BoolAttribute("deleted")
    DENY = DictListAttribute("deny")
    DESCRIPTION = OptionalStringAttribute("description")
    DESTINATION_RANGES = StringListAttribute("destination_ranges")
    DIRECTION = OptionalStringAttribute("direction")
    DISABLED = BoolAttribute("disabled")
    DISPLAY_NAME = OptionalStringAttribute("display_name")
    EMAIL = OptionalStringAttribute("email")
    ENABLE_LOGGING = BoolAttribute("enable_logging")
    ENCRYPTION = DictListAttribute("encryption")
    FIREWALL_POLICY = OptionalStringAttribute("firewall_policy")
    FOLDER = OptionalStringAttribute("folder")
    FOLDER_ID = OptionalStringAttribute("folder_id")
    ID = OptionalStringAttribute("id")
    KEEPERS = DictAttribute("keepers")
    KEY_ALGORITHM = OptionalStringAttribute("key_algorithm")
    KEY_RING = OptionalStringAttribute("key_ring")
    KEY_RING_ID = OptionalStringAttribute("key_ring_id")
    LABELS = DictAttribute("labels")
    MATCH = DictListAttribute("match")
    MEMBER = OptionalStringAttribute("member")
    MEMBERS = StringListAttribute("members")
    METADATA = DictAttribute("metadata")
    NAME = OptionalStringAttribute("name")
    NETWORK = OptionalStringAttribute("network")
    NETWORK_INTERFACE = DictListAttribute("network_interface")
    ORG_ID = OptionalStringAttribute("org_id")
    ORGANIZATION = OptionalStringAttribute("organization")
    ORGANIZATION_ID = OptionalStringAttribute("organization_id")
    PERMISSIONS = StringListAttribute("permissions")
    POLICY_DATA = RawAttribute("policy_data")
    PRIORITY = OptionalIntAttribute("priority")
    PROJECT = OptionalStringAttribute("project")
    PUBLIC_KEY_TYPE = OptionalStringAttribute("public_key_type")
    REGION = OptionalStringAttribute("region")
    ROLE = OptionalStringAttribute("role")
    ROLE_ID = OptionalStringAttribute("role_id")
    SELF_LINK = OptionalStringAttribute("self_link")
    SECRET = OptionalStringAttribute("secret")
    SECRET_ID = OptionalStringAttribute("secret_id")
    SERVICE_ACCOUNT = OptionalStringAttribute("service_account")
    SERVICE_ACCOUNT_BLOCKS = DictListAttribute("service_account")
    SERVICE_ACCOUNT_ID = OptionalStringAttribute("service_account_id")
    SOURCE_RANGES = StringListAttribute("source_ranges")
    SOURCE_SERVICE_ACCOUNTS = StringListAttribute("source_service_accounts")
    SOURCE_TAGS = StringListAttribute("source_tags")
    STAGE = OptionalStringAttribute("stage")
    SUBNETWORK = OptionalStringAttribute("subnetwork")
    SUBSCRIPTION = OptionalStringAttribute("subscription")
    SUBSCRIPTION_ID = OptionalStringAttribute("subscription_id")
    TABLE = OptionalStringAttribute("table")
    TABLE_ID = OptionalStringAttribute("table_id")
    TAGS = StringListAttribute("tags")
    TARGET = OptionalStringAttribute("target")
    TARGET_RESOURCES = StringListAttribute("target_resources")
    TARGET_SERVICE_ACCOUNTS = StringListAttribute("target_service_accounts")
    TARGET_TAGS = StringListAttribute("target_tags")
    TITLE = OptionalStringAttribute("title")
    TOPIC = OptionalStringAttribute("topic")
    TOPIC_ID = OptionalStringAttribute("topic_id")
    UNIQUE_ID = OptionalStringAttribute("unique_id")
    VALID_AFTER = OptionalStringAttribute("valid_after")
    VALID_BEFORE = OptionalStringAttribute("valid_before")
    ZONE = OptionalStringAttribute("zone")