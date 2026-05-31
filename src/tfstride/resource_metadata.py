from __future__ import annotations

from collections.abc import Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Generic, TypeVar


T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class MetadataField(Generic[T]):
    key: str

    def get(self, metadata: Mapping[str, Any]) -> T:
        raise NotImplementedError

    def set(self, metadata: dict[str, Any], value: T) -> None:
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class BoolMetadataField(MetadataField[bool]):
    default: bool = False

    def get(self, metadata: Mapping[str, Any]) -> bool:
        return bool(metadata.get(self.key, self.default))

    def set(self, metadata: dict[str, Any], value: bool) -> None:
        metadata[self.key] = bool(value)


@dataclass(frozen=True, slots=True)
class StringListMetadataField(MetadataField[list[str]]):
    def get(self, metadata: Mapping[str, Any]) -> list[str]:
        values = metadata.get(self.key)
        if not isinstance(values, list):
            return []
        return [str(value) for value in values if value not in (None, "")]

    def set(self, metadata: dict[str, Any], value: list[str]) -> None:
        metadata[self.key] = [str(item) for item in value if item not in (None, "")]

    def append_unique(self, metadata: dict[str, Any], value: str | None) -> None:
        self.extend_unique(metadata, [value])

    def extend_unique(self, metadata: dict[str, Any], values: Iterable[str | None]) -> None:
        pending_values: list[str] = []
        pending_seen: set[str] = set()
        for value in values:
            if not value:
                continue
            item = str(value)
            if item in pending_seen:
                continue
            pending_values.append(item)
            pending_seen.add(item)
        if not pending_values:
            return

        existing_values = self.get(metadata)
        existing_seen = set(existing_values)
        for item in pending_values:
            if item in existing_seen:
                continue
            existing_values.append(item)
            existing_seen.add(item)
        self.set(metadata, existing_values)


@dataclass(frozen=True, slots=True)
class OptionalStringMetadataField(MetadataField[str | None]):
    def get(self, metadata: Mapping[str, Any]) -> str | None:
        value = metadata.get(self.key)
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    def set(self, metadata: dict[str, Any], value: str | None) -> None:
        if value is None or not str(value).strip():
            metadata.pop(self.key, None)
            return
        metadata[self.key] = str(value).strip()


@dataclass(frozen=True, slots=True)
class OptionalIntMetadataField(MetadataField[int | None]):
    def get(self, metadata: Mapping[str, Any]) -> int | None:
        value = metadata.get(self.key)
        if value is None or value == "":
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def set(self, metadata: dict[str, Any], value: int | None) -> None:
        if value is None:
            metadata.pop(self.key, None)
            return
        metadata[self.key] = int(value)


@dataclass(frozen=True, slots=True)
class DictMetadataField(MetadataField[dict[str, Any]]):
    def get(self, metadata: Mapping[str, Any]) -> dict[str, Any]:
        value = metadata.get(self.key)
        if not isinstance(value, dict):
            return {}
        return deepcopy(value)

    def set(self, metadata: dict[str, Any], value: dict[str, Any] | None) -> None:
        if value is None:
            metadata.pop(self.key, None)
            return
        metadata[self.key] = deepcopy(value)


@dataclass(frozen=True, slots=True)
class DictListMetadataField(MetadataField[list[dict[str, Any]]]):
    def get(self, metadata: Mapping[str, Any]) -> list[dict[str, Any]]:
        values = metadata.get(self.key)
        if not isinstance(values, list):
            return []
        return [deepcopy(value) for value in values if isinstance(value, dict)]

    def set(self, metadata: dict[str, Any], value: list[dict[str, Any]]) -> None:
        metadata[self.key] = [deepcopy(item) for item in value if isinstance(item, dict)]


@dataclass(frozen=True, slots=True)
class BoolDictMetadataField(MetadataField[dict[str, bool] | None]):
    def get(self, metadata: Mapping[str, Any]) -> dict[str, bool] | None:
        value = metadata.get(self.key)
        if not isinstance(value, dict):
            return None
        return {str(item_key): bool(item) for item_key, item in value.items()}

    def set(self, metadata: dict[str, Any], value: dict[str, bool] | None) -> None:
        if value is None:
            metadata.pop(self.key, None)
            return
        metadata[self.key] = {str(item_key): bool(item) for item_key, item in value.items()}


@dataclass(frozen=True, slots=True)
class IntMapMetadataField(MetadataField[dict[str, int]]):
    def get(self, metadata: Mapping[str, Any]) -> dict[str, int]:
        value = metadata.get(self.key)
        if not isinstance(value, dict):
            return {}

        parsed: dict[str, int] = {}
        for item_key, item_value in value.items():
            try:
                parsed[str(item_key)] = int(item_value)
            except (TypeError, ValueError):
                continue
        return dict(sorted(parsed.items()))

    def set(self, metadata: dict[str, Any], value: dict[str, int] | None) -> None:
        if value is None:
            metadata.pop(self.key, None)
            return
        metadata[self.key] = self.get({self.key: value})


class ResourceMetadata:
    DIRECT_INTERNET_REACHABLE = BoolMetadataField("direct_internet_reachable")
    INTERNET_INGRESS_CAPABLE = BoolMetadataField("internet_ingress_capable")
    IN_PUBLIC_SUBNET = BoolMetadataField("in_public_subnet")
    HAS_NAT_GATEWAY_EGRESS = BoolMetadataField("has_nat_gateway_egress")
    IS_PUBLIC_SUBNET = BoolMetadataField("is_public_subnet")
    HAS_PUBLIC_ROUTE = BoolMetadataField("has_public_route")
    VPC_ENABLED = BoolMetadataField("vpc_enabled", default=True)
    STORAGE_ENCRYPTED = BoolMetadataField("storage_encrypted")
    PUBLICLY_ACCESSIBLE = BoolMetadataField("publicly_accessible")
    PUBLIC_ACCESS_CONFIGURED = BoolMetadataField("public_access_configured")
    INTERNET_INGRESS = BoolMetadataField("internet_ingress")
    FRONTED_BY_INTERNET_FACING_LOAD_BALANCER = BoolMetadataField(
        "fronted_by_internet_facing_load_balancer"
    )
    MAP_PUBLIC_IP_ON_LAUNCH = BoolMetadataField("map_public_ip_on_launch")
    BLOCK_PUBLIC_ACLS = BoolMetadataField("block_public_acls")
    BLOCK_PUBLIC_POLICY = BoolMetadataField("block_public_policy")
    IGNORE_PUBLIC_ACLS = BoolMetadataField("ignore_public_acls")
    RESTRICT_PUBLIC_BUCKETS = BoolMetadataField("restrict_public_buckets")

    PUBLIC_ACCESS_REASONS = StringListMetadataField("public_access_reasons")
    PUBLIC_EXPOSURE_REASONS = StringListMetadataField("public_exposure_reasons")
    INTERNET_INGRESS_REASONS = StringListMetadataField("internet_ingress_reasons")
    ROUTE_TABLE_IDS = StringListMetadataField("route_table_ids")
    INTERNET_FACING_LOAD_BALANCER_ADDRESSES = StringListMetadataField(
        "internet_facing_load_balancer_addresses"
    )
    ROLE_REFERENCES = StringListMetadataField("role_references")
    RESOLVED_ROLE_REFERENCES = StringListMetadataField("resolved_role_references")
    RESOLVED_ROLE_ADDRESSES = StringListMetadataField("resolved_role_addresses")
    STANDALONE_RULE_ADDRESSES = StringListMetadataField("standalone_rule_addresses")
    INLINE_POLICY_RESOURCE_ADDRESSES = StringListMetadataField("inline_policy_resource_addresses")
    INLINE_POLICY_NAMES = StringListMetadataField("inline_policy_names")
    UNRESOLVED_ATTACHED_POLICY_ARNS = StringListMetadataField("unresolved_attached_policy_arns")
    ATTACHED_POLICY_ARNS = StringListMetadataField("attached_policy_arns")
    ATTACHED_POLICY_ADDRESSES = StringListMetadataField("attached_policy_addresses")
    UNRESOLVED_ROLE_REFERENCES = StringListMetadataField("unresolved_role_references")
    UNRESOLVED_INSTANCE_PROFILES = StringListMetadataField("unresolved_instance_profiles")
    RESOLVED_INSTANCE_PROFILE_ADDRESSES = StringListMetadataField(
        "resolved_instance_profile_addresses"
    )
    UNRESOLVED_CLUSTER_REFERENCES = StringListMetadataField("unresolved_cluster_references")
    RESOLVED_CLUSTER_ADDRESSES = StringListMetadataField("resolved_cluster_addresses")
    UNRESOLVED_TASK_DEFINITION_REFERENCES = StringListMetadataField(
        "unresolved_task_definition_references"
    )
    RESOLVED_TASK_DEFINITION_ADDRESSES = StringListMetadataField(
        "resolved_task_definition_addresses"
    )
    RESOLVED_TASK_ROLE_ADDRESSES = StringListMetadataField("resolved_task_role_addresses")
    UNRESOLVED_TASK_ROLE_ARNS = StringListMetadataField("unresolved_task_role_arns")
    RESOLVED_EXECUTION_ROLE_ADDRESSES = StringListMetadataField(
        "resolved_execution_role_addresses"
    )
    UNRESOLVED_EXECUTION_ROLE_ARNS = StringListMetadataField("unresolved_execution_role_arns")
    UNRESOLVED_BUCKET_REFERENCES = StringListMetadataField("unresolved_bucket_references")
    UNRESOLVED_SECRET_ARNS = StringListMetadataField("unresolved_secret_arns")
    UNRESOLVED_FUNCTION_REFERENCES = StringListMetadataField("unresolved_function_references")
    REQUIRES_COMPATIBILITIES = StringListMetadataField("requires_compatibilities")
    TRUST_PRINCIPALS = StringListMetadataField("trust_principals")
    RESOURCE_POLICY_SOURCE_ADDRESSES = StringListMetadataField("resource_policy_source_addresses")

    SECURITY_GROUP_ID = OptionalStringMetadataField("security_group_id")
    ROLE_REFERENCE = OptionalStringMetadataField("role")
    IAM_INSTANCE_PROFILE = OptionalStringMetadataField("iam_instance_profile")
    POLICY_ARN = OptionalStringMetadataField("policy_arn")
    POLICY_NAME = OptionalStringMetadataField("policy_name")
    CLUSTER_REFERENCE = OptionalStringMetadataField("cluster")
    NAME = OptionalStringMetadataField("name")
    TASK_DEFINITION_REFERENCE = OptionalStringMetadataField("task_definition")
    TASK_DEFINITION_FAMILY = OptionalStringMetadataField("family")
    NETWORK_MODE = OptionalStringMetadataField("network_mode")
    TASK_ROLE_ARN = OptionalStringMetadataField("task_role_arn")
    EXECUTION_ROLE_ARN = OptionalStringMetadataField("execution_role_arn")
    SECRET_ARN = OptionalStringMetadataField("secret_arn")
    FUNCTION_NAME = OptionalStringMetadataField("function_name")
    ROUTE_TABLE_ID = OptionalStringMetadataField("route_table_id")
    SUBNET_ID = OptionalStringMetadataField("subnet_id")
    BUCKET_NAME = OptionalStringMetadataField("bucket")
    BUCKET_ACL = OptionalStringMetadataField("acl")
    ENGINE = OptionalStringMetadataField("engine")

    TASK_DEFINITION_REVISION = OptionalIntMetadataField("revision")

    POLICY_DOCUMENT = DictMetadataField("policy_document")
    ROUTES = DictListMetadataField("routes")
    TRUST_STATEMENTS = DictListMetadataField("trust_statements")
    PUBLIC_ACCESS_BLOCK = BoolDictMetadataField("public_access_block")


class InventoryMetadata:
    PRIMARY_ACCOUNT_ID = OptionalStringMetadataField("primary_account_id")
    SUPPORTED_RESOURCE_TYPES = StringListMetadataField("supported_resource_types")
    TOTAL_INPUT_RESOURCES = OptionalIntMetadataField("total_input_resources")
    PROVIDER_RESOURCE_COUNT = OptionalIntMetadataField("provider_resource_count")
    NORMALIZED_RESOURCE_COUNT = OptionalIntMetadataField("normalized_resource_count")
    UNSUPPORTED_RESOURCE_TYPES = IntMapMetadataField("unsupported_resource_types")