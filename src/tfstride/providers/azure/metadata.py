from __future__ import annotations

from tfstride.resource_metadata import (
    BoolMetadataField,
    OptionalStringMetadataField,
    StringListMetadataField,
)


class AzureResourceMetadata:
    """Azure-owned metadata fields preserved by provider normalizers."""

    NAME = OptionalStringMetadataField("name")
    STORAGE_ACCOUNT_ID = OptionalStringMetadataField("storage_account_id")
    STORAGE_ACCOUNT_REFERENCE = OptionalStringMetadataField("storage_account_reference")
    RESOLVED_STORAGE_ACCOUNT_ADDRESS = OptionalStringMetadataField("resolved_storage_account_address")
    CONTAINER_ACCESS_TYPE = OptionalStringMetadataField("container_access_type")
    MIN_TLS_VERSION = OptionalStringMetadataField("min_tls_version")
    NETWORK_DEFAULT_ACTION = OptionalStringMetadataField("network_default_action")
    NETWORK_RULE_SOURCE_ADDRESS = OptionalStringMetadataField("network_rule_source_address")

    ALLOW_NESTED_ITEMS_TO_BE_PUBLIC = BoolMetadataField("allow_nested_items_to_be_public")
    SHARED_ACCESS_KEY_ENABLED = BoolMetadataField("shared_access_key_enabled")
    PUBLIC_NETWORK_ACCESS_ENABLED = BoolMetadataField("public_network_access_enabled")

    PUBLIC_CONTAINER_ADDRESSES = StringListMetadataField("public_container_addresses")
    UNRESOLVED_STORAGE_ACCOUNT_REFERENCES = StringListMetadataField("unresolved_storage_account_references")
