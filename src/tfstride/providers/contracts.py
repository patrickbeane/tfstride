from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True, slots=True)
class ProviderEncapsulationContract:
    """Declarative boundary between core models and provider-owned details."""

    provider_neutral_resource_fields: frozenset[str]
    provider_neutral_resource_accessors: frozenset[str]
    legacy_provider_metadata_accessors: frozenset[str]
    guidelines: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ResourceMetadataOwnershipContract:
    """Ownership map for shared and provider-owned metadata namespaces."""

    shared_core_fields: frozenset[str]
    provider_owned_fields: Mapping[str, frozenset[str]]
    guidelines: tuple[str, ...]


PROVIDER_ENCAPSULATION_GUIDELINES = (
    "Core models expose normalized, provider-neutral facts used by shared analysis and reporting.",
    "Provider packages own provider-specific facts, metadata keys, indexes, decorators, boundary contributors, and relationship resolution.",
    "Shared boundary orchestration should accept provider contributors through the provider plugin contract rather than importing provider packages directly.",
    "Shared analysis should prefer normalized fields or capability helpers over raw provider metadata keys.",
    "Do not add new provider-specific convenience accessors to NormalizedResource; put them behind a provider facts facade.",
)

RESOURCE_METADATA_OWNERSHIP_GUIDELINES = (
    "Shared-core metadata backs provider-neutral NormalizedResource posture and reporting fields.",
    "Provider-owned metadata belongs behind provider facts, mutation facades, or provider metadata namespaces.",
    "Provider-shaped data used by shared analysis must be exposed through provider facts before adding another provider.",
    "Do not add new ResourceMetadata fields without classifying their ownership here.",
)

PROVIDER_NEUTRAL_NORMALIZED_RESOURCE_FIELDS = frozenset(
    {
        "address",
        "provider",
        "resource_type",
        "name",
        "category",
        "identifier",
        "arn",
        "vpc_id",
        "subnet_ids",
        "security_group_ids",
        "attached_role_arns",
        "network_rules",
        "policy_statements",
        "public_access_configured",
        "public_exposure",
        "data_sensitivity",
    }
)

PROVIDER_NEUTRAL_NORMALIZED_RESOURCE_ACCESSORS = frozenset(
    {
        "display_name",
        "metadata",
        "direct_internet_reachable",
        "internet_ingress_capable",
        "in_public_subnet",
        "has_nat_gateway_egress",
        "is_public_subnet",
        "has_public_route",
        "vpc_enabled",
        "storage_encrypted",
        "publicly_accessible",
        "public_access_reasons",
        "public_exposure_reasons",
        "internet_ingress_reasons",
    }
)

# Provider-specific convenience accessors have moved out of the core model.
LEGACY_NORMALIZED_RESOURCE_PROVIDER_METADATA_ACCESSORS = frozenset()


SHARED_CORE_RESOURCE_METADATA_FIELDS = frozenset(
    {
        "DIRECT_INTERNET_REACHABLE",
        "INTERNET_INGRESS_CAPABLE",
        "IN_PUBLIC_SUBNET",
        "HAS_NAT_GATEWAY_EGRESS",
        "IS_PUBLIC_SUBNET",
        "HAS_PUBLIC_ROUTE",
        "VPC_ENABLED",
        "STORAGE_ENCRYPTED",
        "PUBLICLY_ACCESSIBLE",
        "PUBLIC_ACCESS_CONFIGURED",
        "PUBLIC_ACCESS_REASONS",
        "PUBLIC_EXPOSURE_REASONS",
        "INTERNET_INGRESS_REASONS",
    }
)

AWS_OWNED_RESOURCE_METADATA_FIELDS = frozenset(
    {
        "INTERNET_INGRESS",
        "FRONTED_BY_INTERNET_FACING_LOAD_BALANCER",
        "MAP_PUBLIC_IP_ON_LAUNCH",
        "BLOCK_PUBLIC_ACLS",
        "BLOCK_PUBLIC_POLICY",
        "IGNORE_PUBLIC_ACLS",
        "RESTRICT_PUBLIC_BUCKETS",
        "ROUTE_TABLE_IDS",
        "INTERNET_FACING_LOAD_BALANCER_ADDRESSES",
        "ROLE_REFERENCES",
        "RESOLVED_ROLE_REFERENCES",
        "RESOLVED_ROLE_ADDRESSES",
        "STANDALONE_RULE_ADDRESSES",
        "INLINE_POLICY_RESOURCE_ADDRESSES",
        "INLINE_POLICY_NAMES",
        "UNRESOLVED_ATTACHED_POLICY_ARNS",
        "ATTACHED_POLICY_ARNS",
        "ATTACHED_POLICY_ADDRESSES",
        "UNRESOLVED_ROLE_REFERENCES",
        "UNRESOLVED_INSTANCE_PROFILES",
        "RESOLVED_INSTANCE_PROFILE_ADDRESSES",
        "UNRESOLVED_CLUSTER_REFERENCES",
        "RESOLVED_CLUSTER_ADDRESSES",
        "UNRESOLVED_TASK_DEFINITION_REFERENCES",
        "RESOLVED_TASK_DEFINITION_ADDRESSES",
        "RESOLVED_TASK_ROLE_ADDRESSES",
        "UNRESOLVED_TASK_ROLE_ARNS",
        "RESOLVED_EXECUTION_ROLE_ADDRESSES",
        "UNRESOLVED_EXECUTION_ROLE_ARNS",
        "UNRESOLVED_BUCKET_REFERENCES",
        "UNRESOLVED_SECRET_ARNS",
        "UNRESOLVED_FUNCTION_REFERENCES",
        "REQUIRES_COMPATIBILITIES",
        "TRUST_PRINCIPALS",
        "SECURITY_GROUP_ID",
        "ROLE_REFERENCE",
        "IAM_INSTANCE_PROFILE",
        "POLICY_ARN",
        "POLICY_NAME",
        "POLICY_DOCUMENT",
        "TRUST_STATEMENTS",
        "RESOURCE_POLICY_SOURCE_ADDRESSES",
        "CLUSTER_REFERENCE",
        "NAME",
        "BUCKET_NAME",
        "BUCKET_ACL",
        "ENGINE",
        "TASK_DEFINITION_REFERENCE",
        "TASK_DEFINITION_FAMILY",
        "NETWORK_MODE",
        "TASK_ROLE_ARN",
        "EXECUTION_ROLE_ARN",
        "SECRET_ARN",
        "FUNCTION_NAME",
        "ROUTE_TABLE_ID",
        "SUBNET_ID",
        "TASK_DEFINITION_REVISION",
        "ROUTES",
        "PUBLIC_ACCESS_BLOCK",
    }
)

GCP_OWNED_RESOURCE_METADATA_FIELDS = frozenset(
    {
        "NAME",
        "SELF_LINK",
        "PROJECT",
        "REGION",
        "ZONE",
        "NETWORK",
        "SUBNETWORK",
        "CIDR_RANGE",
        "MACHINE_TYPE",
        "BUCKET_NAME",
        "DATABASE_VERSION",
        "CLOUD_SQL_PRIVATE_NETWORK",
        "CLOUD_SQL_SSL_MODE",
        "IAM_ROLE",
        "IAM_MEMBER",
        "IAM_CONDITION",
        "POLICY_DOCUMENT",
        "RESOURCE_POLICY_SOURCE_ADDRESSES",
        "CUSTOM_ROLE_ID",
        "CUSTOM_ROLE_STAGE",
        "ORGANIZATION_ID",
        "FOLDER_ID",
        "ORG_POLICY_CONSTRAINT",
        "ORG_POLICY_SCOPE",
        "ORG_POLICY_SCOPE_TYPE",
        "SERVICE_ACCOUNT_ACCOUNT_ID",
        "SERVICE_ACCOUNT_EMAIL",
        "SERVICE_ACCOUNT_MEMBER",
        "SERVICE_ACCOUNT_ID",
        "SERVICE_ACCOUNT_REFERENCE",
        "CLOUD_RUN_SERVICE_REFERENCE",
        "CLOUD_FUNCTION_REFERENCE",
        "SERVERLESS_INGRESS",
        "SERVICE_ACCOUNT_UNIQUE_ID",
        "SERVICE_ACCOUNT_KEY_ALGORITHM",
        "SERVICE_ACCOUNT_PUBLIC_KEY_TYPE",
        "SERVICE_ACCOUNT_KEY_VALID_AFTER",
        "SERVICE_ACCOUNT_KEY_VALID_BEFORE",
        "SECRET_ID",
        "SECRET_REFERENCE",
        "PUBSUB_TOPIC_REFERENCE",
        "PUBSUB_SUBSCRIPTION_REFERENCE",
        "BIGQUERY_DATASET_ID",
        "BIGQUERY_DATASET_REFERENCE",
        "BIGQUERY_TABLE_ID",
        "BIGQUERY_TABLE_REFERENCE",
        "BIGQUERY_DEFAULT_KMS_KEY_NAME",
        "KMS_CRYPTO_KEY_REFERENCE",
        "KMS_KEY_RING",
        "KMS_PURPOSE",
        "KMS_ROTATION_PERIOD",
        "PUBLIC_ACCESS_PREVENTION",
        "GCS_DEFAULT_KMS_KEY_NAME",
        "ROUTE_DEST_RANGE",
        "ROUTE_NEXT_HOP_GATEWAY",
        "ROUTE_NEXT_HOP_INSTANCE",
        "ROUTE_NEXT_HOP_IP",
        "ROUTE_NEXT_HOP_ILB",
        "ROUTE_NEXT_HOP_VPN_TUNNEL",
        "ROUTER_REFERENCE",
        "ROUTE_PRIORITY",
        "FIREWALL_POLICY_REFERENCE",
        "FIREWALL_POLICY_PARENT",
        "FIREWALL_POLICY_ATTACHMENT_TARGET",
        "FIREWALL_POLICY_ACTION",
        "FIREWALL_POLICY_DIRECTION",
        "FIREWALL_DIRECTION",
        "FIREWALL_PRIORITY",
        "FIREWALL_POLICY_PRIORITY",
        "FORWARDING_RULE_IP_ADDRESS",
        "FORWARDING_RULE_LOAD_BALANCING_SCHEME",
        "FORWARDING_RULE_TARGET",
        "FORWARDING_RULE_BACKEND_SERVICE",
        "LOAD_BALANCER_URL_MAP",
        "LOAD_BALANCER_DEFAULT_SERVICE",
        "LOAD_BALANCER_BACKEND_BUCKET_NAME",
        "LOAD_BALANCER_BACKEND_SERVICE_PROTOCOL",
        "LOAD_BALANCER_BACKEND_SERVICE_LOAD_BALANCING_SCHEME",
        "LOAD_BALANCER_NETWORK_ENDPOINT_TYPE",
        "GKE_ENDPOINT",
        "GKE_WORKLOAD_IDENTITY_POOL",
        "GKE_NODE_SERVICE_ACCOUNT",
        "GKE_NODE_METADATA_MODE",
        "AUTO_CREATE_SUBNETWORKS",
        "PRIVATE_IP_GOOGLE_ACCESS",
        "UNIFORM_BUCKET_LEVEL_ACCESS",
        "GCS_VERSIONING_ENABLED",
        "SERVICE_ACCOUNT_DISABLED",
        "OS_LOGIN_ENABLED",
        "CLOUD_SQL_IPV4_ENABLED",
        "CLOUD_SQL_BACKUP_ENABLED",
        "CLOUD_SQL_POINT_IN_TIME_RECOVERY_ENABLED",
        "CLOUD_SQL_REQUIRE_SSL",
        "DELETION_PROTECTION",
        "GKE_PRIVATE_ENDPOINT_ENABLED",
        "GKE_PRIVATE_NODES_ENABLED",
        "GKE_WORKLOAD_IDENTITY_ENABLED",
        "GKE_LEGACY_METADATA_ENDPOINTS_ENABLED",
        "CUSTOMER_MANAGED_ENCRYPTION",
        "FIREWALL_DISABLED",
        "FIREWALL_POLICY_DISABLED",
        "FIREWALL_POLICY_ENABLE_LOGGING",
        "FRONTED_BY_INTERNET_FACING_LOAD_BALANCER",
        "ORG_POLICY_ENFORCED",
        "ORG_POLICY_INHERIT_FROM_PARENT",
        "ORG_POLICY_RESTORE_DEFAULT",
        "NETWORK_TAGS",
        "IAM_MEMBERS",
        "CUSTOM_ROLE_PERMISSIONS",
        "INTERNET_INGRESS_FIREWALLS",
        "FIREWALL_SOURCE_RANGES",
        "FIREWALL_DESTINATION_RANGES",
        "FIREWALL_TARGET_TAGS",
        "FIREWALL_SOURCE_TAGS",
        "FIREWALL_TARGET_SERVICE_ACCOUNTS",
        "FIREWALL_POLICY_TARGET_RESOURCES",
        "FIREWALL_POLICY_TARGET_SERVICE_ACCOUNTS",
        "FIREWALL_SOURCE_SERVICE_ACCOUNTS",
        "ROUTE_TAGS",
        "FORWARDING_RULE_PORTS",
        "FORWARDING_RULE_SOURCE_IP_RANGES",
        "LOAD_BALANCER_SSL_CERTIFICATES",
        "INTERNET_FACING_LOAD_BALANCER_ADDRESSES",
        "GKE_NODE_OAUTH_SCOPES",
        "ORG_POLICY_ALLOWED_VALUES",
        "ORG_POLICY_DENIED_VALUES",
        "FIREWALL_ALLOW",
        "FIREWALL_DENY",
        "FIREWALL_POLICY_MATCH",
        "IAM_BINDINGS",
        "LOAD_BALANCER_BACKENDS",
        "LOAD_BALANCER_HOST_RULES",
        "LOAD_BALANCER_PATH_MATCHERS",
        "LOAD_BALANCER_SERVERLESS_ENDPOINTS",
        "LOAD_BALANCER_NETWORK_ENDPOINTS",
        "LOAD_BALANCER_FRONTENDS",
        "LOAD_BALANCER_REACHABLE_BACKENDS",
        "ORG_POLICY_RULES",
        "GKE_MASTER_AUTHORIZED_NETWORKS",
        "CLOUD_SQL_AUTHORIZED_NETWORKS",
        "CLOUD_SQL_BACKUP_CONFIGURATION",
        "CLOUD_SQL_IP_CONFIGURATION",
        "GCS_VERSIONING_CONFIGURATION",
        "GCS_ENCRYPTION_CONFIGURATION",
        "SERVICE_ACCOUNT_KEY_KEEPERS",
        "NETWORK_INTERFACES",
        "SERVICE_ACCOUNTS",
        "NAT_SUBNETWORKS",
        "LABELS",
    }
)

AZURE_OWNED_RESOURCE_METADATA_FIELDS = frozenset(
    {
        "NAME",
        "STORAGE_ACCOUNT_ID",
        "STORAGE_ACCOUNT_REFERENCE",
        "RESOLVED_STORAGE_ACCOUNT_ADDRESS",
        "CONTAINER_ACCESS_TYPE",
        "MIN_TLS_VERSION",
        "NETWORK_DEFAULT_ACTION",
        "NETWORK_RULE_SOURCE_ADDRESS",
        "ALLOW_NESTED_ITEMS_TO_BE_PUBLIC",
        "SHARED_ACCESS_KEY_ENABLED",
        "PUBLIC_NETWORK_ACCESS_ENABLED",
        "PUBLIC_CONTAINER_ADDRESSES",
        "UNRESOLVED_STORAGE_ACCOUNT_REFERENCES",
        "LOCATION",
        "VIRTUAL_NETWORK_REFERENCE",
        "RESOLVED_VIRTUAL_NETWORK_ADDRESS",
        "NETWORK_SECURITY_GROUP_REFERENCE",
        "SUBNET_REFERENCE",
        "NETWORK_INTERFACE_REFERENCE",
        "PUBLIC_IP_ADDRESS",
        "VM_SIZE",
        "OS_TYPE",
        "DEFAULT_OUTBOUND_ACCESS_ENABLED",
        "IP_FORWARDING_ENABLED",
        "ADDRESS_SPACE",
        "ADDRESS_PREFIXES",
        "NETWORK_INTERFACE_REFERENCES",
        "PUBLIC_IP_REFERENCES",
        "RESOLVED_SUBNET_ADDRESSES",
        "RESOLVED_NETWORK_SECURITY_GROUP_ADDRESSES",
        "RESOLVED_NETWORK_INTERFACE_ADDRESSES",
        "RESOLVED_PUBLIC_IP_ADDRESSES",
        "ASSOCIATED_RESOURCE_ADDRESSES",
        "STANDALONE_RULE_ADDRESSES",
        "UNRESOLVED_RESOURCE_REFERENCES",
        "IP_CONFIGURATIONS",
        "NETWORK_SECURITY_RULES",
    }
)

PROVIDER_OWNED_RESOURCE_METADATA_FIELDS = MappingProxyType(
    {
        "aws": AWS_OWNED_RESOURCE_METADATA_FIELDS,
        "gcp": GCP_OWNED_RESOURCE_METADATA_FIELDS,
        "azure": AZURE_OWNED_RESOURCE_METADATA_FIELDS,
    }
)


DEFAULT_PROVIDER_ENCAPSULATION_CONTRACT = ProviderEncapsulationContract(
    provider_neutral_resource_fields=PROVIDER_NEUTRAL_NORMALIZED_RESOURCE_FIELDS,
    provider_neutral_resource_accessors=PROVIDER_NEUTRAL_NORMALIZED_RESOURCE_ACCESSORS,
    legacy_provider_metadata_accessors=LEGACY_NORMALIZED_RESOURCE_PROVIDER_METADATA_ACCESSORS,
    guidelines=PROVIDER_ENCAPSULATION_GUIDELINES,
)

DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT = ResourceMetadataOwnershipContract(
    shared_core_fields=SHARED_CORE_RESOURCE_METADATA_FIELDS,
    provider_owned_fields=PROVIDER_OWNED_RESOURCE_METADATA_FIELDS,
    guidelines=RESOURCE_METADATA_OWNERSHIP_GUIDELINES,
)
