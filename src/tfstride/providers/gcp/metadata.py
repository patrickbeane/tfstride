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
    PUBLIC_ACCESS_PREVENTION = OptionalStringMetadataField("public_access_prevention")

    AUTO_CREATE_SUBNETWORKS = BoolMetadataField("auto_create_subnetworks")
    PRIVATE_IP_GOOGLE_ACCESS = BoolMetadataField("private_ip_google_access")
    UNIFORM_BUCKET_LEVEL_ACCESS = BoolMetadataField("uniform_bucket_level_access")
    SERVICE_ACCOUNT_DISABLED = BoolMetadataField("service_account_disabled")

    NETWORK_TAGS = StringListMetadataField("network_tags")
    IAM_MEMBERS = StringListMetadataField("iam_members")
    INTERNET_INGRESS_FIREWALLS = StringListMetadataField("internet_ingress_firewalls")
    FIREWALL_SOURCE_RANGES = StringListMetadataField("source_ranges")
    FIREWALL_DESTINATION_RANGES = StringListMetadataField("destination_ranges")
    FIREWALL_TARGET_TAGS = StringListMetadataField("target_tags")
    FIREWALL_SOURCE_TAGS = StringListMetadataField("source_tags")

    FIREWALL_ALLOW = DictListMetadataField("allow")
    FIREWALL_DENY = DictListMetadataField("deny")
    IAM_BINDINGS = DictListMetadataField("iam_bindings")
    NETWORK_INTERFACES = DictListMetadataField("network_interfaces")
    SERVICE_ACCOUNTS = DictListMetadataField("service_accounts")
    LABELS = DictMetadataField("labels")