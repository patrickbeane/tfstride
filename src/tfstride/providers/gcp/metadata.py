from __future__ import annotations

from tfstride.resource_metadata import (
    BoolMetadataField,
    DictListMetadataField,
    DictMetadataField,
    OptionalStringMetadataField,
    StringListMetadataField,
)


class GcpResourceMetadata:
    """GCP-owned metadata fields preserved by the provider normalizers."""

    NAME = OptionalStringMetadataField("name")
    SELF_LINK = OptionalStringMetadataField("self_link")
    PROJECT = OptionalStringMetadataField("project")
    REGION = OptionalStringMetadataField("region")
    ZONE = OptionalStringMetadataField("zone")
    NETWORK = OptionalStringMetadataField("network")
    SUBNETWORK = OptionalStringMetadataField("subnetwork")
    CIDR_RANGE = OptionalStringMetadataField("cidr_range")
    MACHINE_TYPE = OptionalStringMetadataField("machine_type")
    DATABASE_VERSION = OptionalStringMetadataField("database_version")
    CLOUD_SQL_PRIVATE_NETWORK = OptionalStringMetadataField("cloud_sql_private_network")
    CLOUD_SQL_SSL_MODE = OptionalStringMetadataField("cloud_sql_ssl_mode")
    IAM_ROLE = OptionalStringMetadataField("iam_role")
    IAM_MEMBER = OptionalStringMetadataField("iam_member")
    BUCKET_NAME = OptionalStringMetadataField("bucket")
    SERVICE_ACCOUNT_ACCOUNT_ID = OptionalStringMetadataField("service_account_account_id")
    SERVICE_ACCOUNT_EMAIL = OptionalStringMetadataField("service_account_email")
    SERVICE_ACCOUNT_MEMBER = OptionalStringMetadataField("service_account_member")
    SERVICE_ACCOUNT_REFERENCE = OptionalStringMetadataField("service_account_reference")
    SERVICE_ACCOUNT_UNIQUE_ID = OptionalStringMetadataField("service_account_unique_id")
    SERVICE_ACCOUNT_KEY_ALGORITHM = OptionalStringMetadataField("service_account_key_algorithm")
    SERVICE_ACCOUNT_PUBLIC_KEY_TYPE = OptionalStringMetadataField("service_account_public_key_type")
    SECRET_ID = OptionalStringMetadataField("secret_id")
    SECRET_REFERENCE = OptionalStringMetadataField("secret_reference")
    KMS_CRYPTO_KEY_REFERENCE = OptionalStringMetadataField("kms_crypto_key_reference")
    KMS_KEY_RING = OptionalStringMetadataField("kms_key_ring")
    KMS_PURPOSE = OptionalStringMetadataField("kms_purpose")
    KMS_ROTATION_PERIOD = OptionalStringMetadataField("kms_rotation_period")
    PUBLIC_ACCESS_PREVENTION = OptionalStringMetadataField("public_access_prevention")

    AUTO_CREATE_SUBNETWORKS = BoolMetadataField("auto_create_subnetworks")
    PRIVATE_IP_GOOGLE_ACCESS = BoolMetadataField("private_ip_google_access")
    UNIFORM_BUCKET_LEVEL_ACCESS = BoolMetadataField("uniform_bucket_level_access")
    SERVICE_ACCOUNT_DISABLED = BoolMetadataField("service_account_disabled")
    CLOUD_SQL_IPV4_ENABLED = BoolMetadataField("cloud_sql_ipv4_enabled")
    CLOUD_SQL_BACKUP_ENABLED = BoolMetadataField("cloud_sql_backup_enabled")
    CLOUD_SQL_POINT_IN_TIME_RECOVERY_ENABLED = BoolMetadataField("cloud_sql_point_in_time_recovery_enabled")
    CLOUD_SQL_REQUIRE_SSL = BoolMetadataField("cloud_sql_require_ssl")
    DELETION_PROTECTION = BoolMetadataField("deletion_protection")

    NETWORK_TAGS = StringListMetadataField("network_tags")
    IAM_MEMBERS = StringListMetadataField("iam_members")
    RESOURCE_POLICY_SOURCE_ADDRESSES = StringListMetadataField("gcp_resource_policy_source_addresses")
    INTERNET_INGRESS_FIREWALLS = StringListMetadataField("internet_ingress_firewalls")
    FIREWALL_SOURCE_RANGES = StringListMetadataField("source_ranges")
    FIREWALL_DESTINATION_RANGES = StringListMetadataField("destination_ranges")
    FIREWALL_TARGET_TAGS = StringListMetadataField("target_tags")
    FIREWALL_SOURCE_TAGS = StringListMetadataField("source_tags")

    FIREWALL_ALLOW = DictListMetadataField("allow")
    FIREWALL_DENY = DictListMetadataField("deny")
    IAM_BINDINGS = DictListMetadataField("iam_bindings")
    CLOUD_SQL_AUTHORIZED_NETWORKS = DictListMetadataField("cloud_sql_authorized_networks")
    CLOUD_SQL_BACKUP_CONFIGURATION = DictMetadataField("cloud_sql_backup_configuration")
    CLOUD_SQL_IP_CONFIGURATION = DictMetadataField("cloud_sql_ip_configuration")
    NETWORK_INTERFACES = DictListMetadataField("network_interfaces")
    SERVICE_ACCOUNTS = DictListMetadataField("service_accounts")
    LABELS = DictMetadataField("labels")