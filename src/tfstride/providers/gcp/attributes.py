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
class ListAttribute(GcpAttribute[list[Any]]):
    def get(self, values: Mapping[str, Any]) -> list[Any]:
        return deepcopy(as_list(values.get(self.key)))


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
    ACK_DEADLINE_SECONDS = RawAttribute("ack_deadline_seconds")
    AUTHORIZED_NETWORKS = DictListAttribute("authorized_networks")
    AVAILABILITY_TYPE = OptionalStringAttribute("availability_type")
    BUILD_CONFIG = DictListAttribute("build_config")
    CAN_IP_FORWARD = BoolAttribute("can_ip_forward")
    CIDR_BLOCK = OptionalStringAttribute("cidr_block")
    CIDR_BLOCKS = DictListAttribute("cidr_blocks")
    CLOUD_FUNCTION = OptionalStringAttribute("cloud_function")
    CLUSTER = OptionalStringAttribute("cluster")
    CONNECTOR = OptionalStringAttribute("connector")
    ANNOTATIONS = DictAttribute("annotations")
    ALLOW = DictListAttribute("allow")
    ATTACHMENT_TARGET = OptionalStringAttribute("attachment_target")
    BACKEND = DictListAttribute("backend")
    BACKUP_CONFIGURATION = DictListAttribute("backup_configuration")
    BACKEND_SERVICE = OptionalStringAttribute("backend_service")
    BUCKET = OptionalStringAttribute("bucket")
    BUCKET_NAME = OptionalStringAttribute("bucket_name")
    CONDITION = DictListAttribute("condition")
    CRYPTO_KEY = OptionalStringAttribute("crypto_key")
    CLUSTERING = ListAttribute("clustering")
    CRYPTO_KEY_ID = OptionalStringAttribute("crypto_key_id")
    DATASET = OptionalStringAttribute("dataset")
    DATABASE_VERSION = OptionalStringAttribute("database_version")
    DEAD_LETTER_POLICY = ListAttribute("dead_letter_policy")
    DEFAULT_ENCRYPTION_CONFIGURATION = DictListAttribute("default_encryption_configuration")
    DEFAULT_TABLE_EXPIRATION_MS = RawAttribute("default_table_expiration_ms")
    DEFAULT_KMS_KEY_NAME = OptionalStringAttribute("default_kms_key_name")
    DELETE_CONTENTS_ON_DESTROY = BoolAttribute("delete_contents_on_destroy")
    DELETION_PROTECTION = BoolAttribute("deletion_protection")
    DATASET_ID = OptionalStringAttribute("dataset_id")
    DELETED = BoolAttribute("deleted")
    DENY = DictListAttribute("deny")
    DISABLE_LEGACY_ENDPOINTS = BoolAttribute("disable-legacy-endpoints")
    DISPLAY_NAME = OptionalStringAttribute("display_name")
    DESCRIPTION = OptionalStringAttribute("description")
    DESTINATION_RANGES = StringListAttribute("destination_ranges")
    DESTROY_SCHEDULED_DURATION = RawAttribute("destroy_scheduled_duration")
    DISK_SIZE = RawAttribute("disk_size")
    DISK_TYPE = OptionalStringAttribute("disk_type")
    DIRECTION = OptionalStringAttribute("direction")
    DISABLED = BoolAttribute("disabled")
    EMAIL = OptionalStringAttribute("email")
    ENABLE_LOGGING = BoolAttribute("enable_logging")
    ENABLE_OSLOGIN = BoolAttribute("enable-oslogin")
    ENABLE_PRIVATE_ENDPOINT = BoolAttribute("enable_private_endpoint")
    ENABLE_PRIVATE_NODES = BoolAttribute("enable_private_nodes")
    ENDPOINT = OptionalStringAttribute("endpoint")
    ENABLED = BoolAttribute("enabled")
    ENCRYPTION_CONFIGURATION = DictListAttribute("encryption_configuration")
    EXPIRATION_POLICY = ListAttribute("expiration_policy")
    EXPIRE_TIME = OptionalStringAttribute("expire_time")
    FILTER = OptionalStringAttribute("filter")
    FUNCTION = OptionalStringAttribute("function")
    FORCE_DESTROY = BoolAttribute("force_destroy")
    FRIENDLY_NAME = OptionalStringAttribute("friendly_name")
    ENCRYPTION = DictListAttribute("encryption")
    FIREWALL_POLICY = OptionalStringAttribute("firewall_policy")
    FOLDER = OptionalStringAttribute("folder")
    FOLDER_ID = OptionalStringAttribute("folder_id")
    IMPORT_ONLY = BoolAttribute("import_only")
    IP_CONFIGURATION = DictListAttribute("ip_configuration")
    IPV4_ENABLED = BoolAttribute("ipv4_enabled")
    ID = OptionalStringAttribute("id")
    KEEPERS = DictAttribute("keepers")
    KEY_ALGORITHM = OptionalStringAttribute("key_algorithm")
    KEY_RING = OptionalStringAttribute("key_ring")
    HTTPS_TRIGGER_URL = OptionalStringAttribute("https_trigger_url")
    INGRESS = OptionalStringAttribute("ingress")
    INGRESS_SETTINGS = OptionalStringAttribute("ingress_settings")
    INITIAL_NODE_COUNT = RawAttribute("initial_node_count")
    KEY_RING_ID = OptionalStringAttribute("key_ring_id")
    KMS_KEY_NAME = OptionalStringAttribute("kms_key_name")
    LOCATION = OptionalStringAttribute("location")
    MAX_TIME_TRAVEL_HOURS = RawAttribute("max_time_travel_hours")
    MACHINE_TYPE = OptionalStringAttribute("machine_type")
    MESSAGE_RETENTION_DURATION = OptionalStringAttribute("message_retention_duration")
    MESSAGE_STORAGE_POLICY = ListAttribute("message_storage_policy")
    LABELS = DictAttribute("labels")
    MATCH = DictListAttribute("match")
    MEMBER = OptionalStringAttribute("member")
    MEMBERS = StringListAttribute("members")
    MASTER_AUTHORIZED_NETWORKS_CONFIG = DictListAttribute("master_authorized_networks_config")
    METADATA_BLOCKS = DictListAttribute("metadata")
    MODE = OptionalStringAttribute("mode")
    METADATA = DictAttribute("metadata")
    NAME = OptionalStringAttribute("name")
    NETWORK_INTERFACES = ListAttribute("network_interfaces")
    NODE_CONFIG = DictListAttribute("node_config")
    NODE_LOCATIONS = StringListAttribute("node_locations")
    NODE_METADATA = OptionalStringAttribute("node_metadata")
    OAUTH_SCOPES = StringListAttribute("oauth_scopes")
    NETWORK = OptionalStringAttribute("network")
    NETWORK_INTERFACE = DictListAttribute("network_interface")
    ORG_ID = OptionalStringAttribute("org_id")
    ORGANIZATION = OptionalStringAttribute("organization")
    ORGANIZATION_ID = OptionalStringAttribute("organization_id")
    PERMISSIONS = StringListAttribute("permissions")
    POLICY_DATA = RawAttribute("policy_data")
    POINT_IN_TIME_RECOVERY_ENABLED = BoolAttribute("point_in_time_recovery_enabled")
    PRIVATE_CLUSTER_CONFIG = DictListAttribute("private_cluster_config")
    PRIVATE_NETWORK = OptionalStringAttribute("private_network")
    PRIORITY = OptionalIntAttribute("priority")
    PROJECT = OptionalStringAttribute("project")
    PUBLIC_ACCESS_PREVENTION = OptionalStringAttribute("public_access_prevention")
    PURPOSE = OptionalStringAttribute("purpose")
    PUSH_CONFIG = ListAttribute("push_config")
    PUBLIC_KEY_TYPE = OptionalStringAttribute("public_key_type")
    REPLICATION = ListAttribute("replication")
    RETAIN_ACKED_MESSAGES = BoolAttribute("retain_acked_messages")
    REQUIRE_SSL = BoolAttribute("require_ssl")
    RETRY_POLICY = ListAttribute("retry_policy")
    ROTATION_PERIOD = OptionalStringAttribute("rotation_period")
    REMOVE_DEFAULT_NODE_POOL = BoolAttribute("remove_default_node_pool")
    RUNTIME = OptionalStringAttribute("runtime")
    RESOURCE_LABELS = DictAttribute("resource_labels")
    RUN_INGRESS_ANNOTATION = OptionalStringAttribute("run.googleapis.com/ingress")
    REGION = OptionalStringAttribute("region")
    ROLE = OptionalStringAttribute("role")
    ROLE_ID = OptionalStringAttribute("role_id")
    SERVICE = OptionalStringAttribute("service")
    SERVICE_ACCOUNT_EMAIL = OptionalStringAttribute("service_account_email")
    SERVICE_ACCOUNT_NAME = OptionalStringAttribute("service_account_name")
    SERVICE_CONFIG = DictListAttribute("service_config")
    SELF_LINK = OptionalStringAttribute("self_link")
    SECRET = OptionalStringAttribute("secret")
    SCHEMA = RawAttribute("schema")
    SCHEMA_SETTINGS = ListAttribute("schema_settings")
    SETTINGS = DictListAttribute("settings")
    SECRET_ID = OptionalStringAttribute("secret_id")
    SERVICE_ACCOUNT = OptionalStringAttribute("service_account")
    SERVICE_ACCOUNT_BLOCKS = DictListAttribute("service_account")
    SERVICE_ACCOUNT_ID = OptionalStringAttribute("service_account_id")
    SOURCE_RANGES = StringListAttribute("source_ranges")
    SOURCE_SERVICE_ACCOUNTS = StringListAttribute("source_service_accounts")
    SKIP_INITIAL_VERSION_CREATION = BoolAttribute("skip_initial_version_creation")
    STORAGE_BILLING_MODEL = OptionalStringAttribute("storage_billing_model")
    STORAGE_CLASS = OptionalStringAttribute("storage_class")
    SSL_MODE = OptionalStringAttribute("ssl_mode")
    SOURCE_TAGS = StringListAttribute("source_tags")
    STAGE = OptionalStringAttribute("stage")
    SUBNET = OptionalStringAttribute("subnet")
    SUBNETWORK = OptionalStringAttribute("subnetwork")
    SUBSCRIPTION = OptionalStringAttribute("subscription")
    SUBSCRIPTION_ID = OptionalStringAttribute("subscription_id")
    TABLE = OptionalStringAttribute("table")
    SPEC = DictListAttribute("spec")
    STATUS = DictListAttribute("status")
    TEMPLATE = DictListAttribute("template")
    TABLE_ID = OptionalStringAttribute("table_id")
    TAGS = StringListAttribute("tags")
    TARGET = OptionalStringAttribute("target")
    TARGET_RESOURCES = StringListAttribute("target_resources")
    TARGET_SERVICE_ACCOUNTS = StringListAttribute("target_service_accounts")
    TARGET_TAGS = StringListAttribute("target_tags")
    TITLE = OptionalStringAttribute("title")
    TIER = OptionalStringAttribute("tier")
    TIME_PARTITIONING = ListAttribute("time_partitioning")
    TOPIC = OptionalStringAttribute("topic")
    TOPICS = ListAttribute("topics")
    TTL = OptionalStringAttribute("ttl")
    URI = OptionalStringAttribute("uri")
    URL = OptionalStringAttribute("url")
    UNIFORM_BUCKET_LEVEL_ACCESS = BoolAttribute("uniform_bucket_level_access")
    TRIGGER_HTTP = BoolAttribute("trigger_http")
    TOPIC_ID = OptionalStringAttribute("topic_id")
    UNIQUE_ID = OptionalStringAttribute("unique_id")
    VALID_AFTER = OptionalStringAttribute("valid_after")
    VERSION_DESTROY_TTL = OptionalStringAttribute("version_destroy_ttl")
    VPC_ACCESS = ListAttribute("vpc_access")
    VPC_CONNECTOR = OptionalStringAttribute("vpc_connector")
    WORKLOAD_IDENTITY_CONFIG = DictListAttribute("workload_identity_config")
    WORKLOAD_METADATA_CONFIG = DictListAttribute("workload_metadata_config")
    WORKLOAD_POOL = OptionalStringAttribute("workload_pool")
    VERSIONING = DictListAttribute("versioning")
    VIEW = ListAttribute("view")
    VALID_BEFORE = OptionalStringAttribute("valid_before")
    VALUE = OptionalStringAttribute("value")
    ZONE = OptionalStringAttribute("zone")