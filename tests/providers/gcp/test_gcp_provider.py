from __future__ import annotations

import unittest

from tests.helpers.paths import SOURCE_ROOT
from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.gcp.constants import (
    GCP_ARTIFACT_REGISTRY_REPOSITORY_IAM_RESOURCE_TYPES,
    GCP_BIGQUERY_DATASET_IAM_RESOURCE_TYPES,
    GCP_BIGQUERY_TABLE_IAM_RESOURCE_TYPES,
    GCP_CLOUD_FUNCTION_IAM_RESOURCE_TYPES,
    GCP_CLOUD_FUNCTION_RESOURCE_TYPES,
    GCP_CLOUD_RUN_IAM_RESOURCE_TYPES,
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    GCP_CUSTOM_ROLE_RESOURCE_TYPES,
    GCP_FOLDER_IAM_RESOURCE_TYPES,
    GCP_IAM_GRANT_RESOURCE_TYPES,
    GCP_IAM_POLICY_RESOURCE_TYPES,
    GCP_KMS_CRYPTO_KEY_IAM_RESOURCE_TYPES,
    GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES,
    GCP_ORG_FOLDER_IAM_RESOURCE_TYPES,
    GCP_ORGANIZATION_IAM_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GCP_PUBSUB_SUBSCRIPTION_IAM_RESOURCE_TYPES,
    GCP_PUBSUB_TOPIC_IAM_RESOURCE_TYPES,
    GCP_RESOURCE_IAM_RESOURCE_TYPES,
    GCP_SECRET_MANAGER_SECRET_IAM_RESOURCE_TYPES,
    GCP_SERVERLESS_WORKLOAD_RESOURCE_TYPES,
    GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES,
    GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES,
    PUBLIC_GCP_IAM_MEMBERS,
)
from tfstride.providers.gcp.limitations import GCP_LIMITATIONS
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import SUPPORTED_GCP_TYPES, GcpNormalizer
from tfstride.providers.gcp.plugin import gcp_provider_plugin
from tfstride.providers.gcp.resource_capabilities import GCP_RESOURCE_CAPABILITIES
from tfstride.providers.gcp.resource_decorator import GcpResourceDecorator
from tfstride.providers.gcp.resource_facts import GcpResourceFacts, gcp_facts
from tfstride.providers.gcp.resource_types import (
    GCP_EDGE_PROTECTION_RESOURCE_TYPES,
    GCP_NORMALIZED_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.resource_capabilities import ResourceCapability
from tfstride.resource_metadata import InventoryMetadata, MetadataField


def _terraform_resource(
    *,
    address: str,
    resource_type: str,
    provider_name: str = "registry.terraform.io/hashicorp/google",
) -> TerraformResource:
    return TerraformResource(
        address=address,
        mode="managed",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        provider_name=provider_name,
        values={},
    )


def _normalized_resource(provider: str = "gcp") -> NormalizedResource:
    return NormalizedResource(
        address="google_storage_bucket.logs",
        provider=provider,
        resource_type=GcpResourceType.STORAGE_BUCKET,
        name="logs",
        category=ResourceCategory.DATA,
    )


def _metadata_field_names(namespace: type) -> set[str]:
    return {name for name, value in vars(namespace).items() if isinstance(value, MetadataField)}


class GcpProviderTests(unittest.TestCase):
    def test_plugin_describes_gcp_provider_contract(self) -> None:
        plugin = gcp_provider_plugin()

        self.assertEqual(plugin.provider, "gcp")
        self.assertIs(plugin.metadata_namespace, GcpResourceMetadata)
        self.assertEqual(plugin.supported_resource_types, SUPPORTED_GCP_TYPES)
        self.assertEqual(dict(plugin.resource_capabilities), dict(GCP_RESOURCE_CAPABILITIES))
        self.assertEqual(plugin.limitations, GCP_LIMITATIONS)
        self.assertIsInstance(plugin.create_normalizer(), GcpNormalizer)
        self.assertIsInstance(plugin.create_resource_decorator(), GcpResourceDecorator)
        self.assertEqual(
            plugin.resource_types_for_capability(ResourceCapability.WORKLOAD),
            frozenset(
                {
                    GcpResourceType.CLOUD_RUN_SERVICE,
                    GcpResourceType.CLOUD_RUN_V2_SERVICE,
                    GcpResourceType.CLOUDFUNCTIONS_FUNCTION,
                    GcpResourceType.CLOUDFUNCTIONS2_FUNCTION,
                    GcpResourceType.COMPUTE_INSTANCE,
                }
            ),
        )
        for resource_type in sorted(GCP_NORMALIZED_RESOURCE_TYPES):
            self.assertTrue(plugin.supports_resource_type(resource_type), resource_type)
        self.assertFalse(plugin.supports_resource_type("google_project_service"))

    def test_shared_gcp_constants_match_supported_resource_contract(self) -> None:
        self.assertEqual(PUBLIC_GCP_IAM_MEMBERS, frozenset({"allUsers", "allAuthenticatedUsers"}))
        self.assertEqual(
            GCP_SERVERLESS_WORKLOAD_RESOURCE_TYPES,
            GCP_CLOUD_RUN_RESOURCE_TYPES | GCP_CLOUD_FUNCTION_RESOURCE_TYPES,
        )
        self.assertEqual(
            GCP_ORG_FOLDER_IAM_RESOURCE_TYPES,
            GCP_ORGANIZATION_IAM_RESOURCE_TYPES | GCP_FOLDER_IAM_RESOURCE_TYPES,
        )
        self.assertEqual(
            GCP_RESOURCE_IAM_RESOURCE_TYPES,
            GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES
            | GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES
            | GCP_SECRET_MANAGER_SECRET_IAM_RESOURCE_TYPES
            | GCP_PUBSUB_TOPIC_IAM_RESOURCE_TYPES
            | GCP_PUBSUB_SUBSCRIPTION_IAM_RESOURCE_TYPES
            | GCP_BIGQUERY_DATASET_IAM_RESOURCE_TYPES
            | GCP_BIGQUERY_TABLE_IAM_RESOURCE_TYPES
            | GCP_KMS_CRYPTO_KEY_IAM_RESOURCE_TYPES
            | GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES
            | GCP_CLOUD_RUN_IAM_RESOURCE_TYPES
            | GCP_CLOUD_FUNCTION_IAM_RESOURCE_TYPES
            | GCP_ARTIFACT_REGISTRY_REPOSITORY_IAM_RESOURCE_TYPES,
        )
        self.assertEqual(
            GCP_IAM_GRANT_RESOURCE_TYPES,
            GCP_PROJECT_IAM_RESOURCE_TYPES
            | GCP_ORGANIZATION_IAM_RESOURCE_TYPES
            | GCP_FOLDER_IAM_RESOURCE_TYPES
            | GCP_RESOURCE_IAM_RESOURCE_TYPES,
        )
        self.assertEqual(
            GCP_IAM_POLICY_RESOURCE_TYPES,
            GCP_IAM_GRANT_RESOURCE_TYPES | GCP_CUSTOM_ROLE_RESOURCE_TYPES,
        )
        self.assertEqual(SUPPORTED_GCP_TYPES, GCP_NORMALIZED_RESOURCE_TYPES)
        self.assertEqual(
            GCP_EDGE_PROTECTION_RESOURCE_TYPES,
            frozenset(
                {
                    GcpResourceType.COMPUTE_SECURITY_POLICY,
                    GcpResourceType.COMPUTE_REGION_SECURITY_POLICY,
                }
            ),
        )
        self.assertLessEqual(GCP_EDGE_PROTECTION_RESOURCE_TYPES, SUPPORTED_GCP_TYPES)
        self.assertLessEqual(GCP_SERVERLESS_WORKLOAD_RESOURCE_TYPES, SUPPORTED_GCP_TYPES)
        self.assertLessEqual(GCP_IAM_GRANT_RESOURCE_TYPES, SUPPORTED_GCP_TYPES)
        self.assertLessEqual(GCP_IAM_POLICY_RESOURCE_TYPES, SUPPORTED_GCP_TYPES)

    def test_metadata_namespace_exposes_gcp_owned_fields(self) -> None:
        self.assertGreaterEqual(
            _metadata_field_names(GcpResourceMetadata),
            {
                "NAME",
                "SELF_LINK",
                "PROJECT",
                "REGION",
                "ZONE",
                "NETWORK",
                "NETWORK_TAGS",
                "PRIVATE_CONNECTIVITY_PURPOSE",
                "PRIVATE_CONNECTIVITY_ADDRESS_TYPE",
                "PRIVATE_CONNECTIVITY_ADDRESS",
                "PRIVATE_CONNECTIVITY_PREFIX_LENGTH",
                "PRIVATE_CONNECTIVITY_SERVICE",
                "PRIVATE_CONNECTIVITY_RESERVED_RANGES",
                "PRIVATE_CONNECTIVITY_PEERING",
                "PRIVATE_CONNECTIVITY_TARGET_SERVICE",
                "PRIVATE_CONNECTIVITY_NAT_SUBNETS",
                "PRIVATE_CONNECTIVITY_SUBNETWORKS",
                "PRIVATE_CONNECTIVITY_DOMAIN_NAMES",
                "PRIVATE_CONNECTIVITY_UNCERTAINTIES",
                "PSC_CONNECTION_ID",
                "PSC_CONNECTION_STATUS",
                "PSC_CONNECTION_PREFERENCE",
                "PSC_SERVICE_LABEL",
                "PSC_SERVICE_NAME",
                "PSC_SERVICE_CLASS",
                "PSC_CONFIG",
                "PSC_CONSUMER_ACCEPT_LIST",
                "PSC_CONSUMER_REJECT_LIST",
                "FIREWALL_ALLOW",
                "FIREWALL_TARGET_SERVICE_ACCOUNTS",
                "FIREWALL_POLICY_REFERENCE",
                "FIREWALL_POLICY_PARENT",
                "FIREWALL_POLICY_ATTACHMENT_TARGET",
                "FIREWALL_POLICY_ACTION",
                "FIREWALL_POLICY_DIRECTION",
                "FIREWALL_DIRECTION",
                "ROUTE_PRIORITY",
                "FIREWALL_PRIORITY",
                "FIREWALL_POLICY_PRIORITY",
                "FIREWALL_DISABLED",
                "FIREWALL_POLICY_DISABLED",
                "FIREWALL_POLICY_ENABLE_LOGGING",
                "FIREWALL_POLICY_TARGET_RESOURCES",
                "FIREWALL_POLICY_TARGET_SERVICE_ACCOUNTS",
                "FIREWALL_POLICY_MATCH",
                "FIREWALL_SOURCE_SERVICE_ACCOUNTS",
                "ROUTE_DEST_RANGE",
                "ROUTE_NEXT_HOP_GATEWAY",
                "ROUTE_NEXT_HOP_INSTANCE",
                "ROUTE_NEXT_HOP_IP",
                "ROUTE_NEXT_HOP_ILB",
                "ROUTE_NEXT_HOP_VPN_TUNNEL",
                "ROUTE_TAGS",
                "ROUTER_REFERENCE",
                "NAT_SUBNETWORKS",
                "FORWARDING_RULE_IP_ADDRESS",
                "FORWARDING_RULE_LOAD_BALANCING_SCHEME",
                "FORWARDING_RULE_TARGET",
                "FORWARDING_RULE_BACKEND_SERVICE",
                "FORWARDING_RULE_PORTS",
                "FORWARDING_RULE_SOURCE_IP_RANGES",
                "LOAD_BALANCER_URL_MAP",
                "LOAD_BALANCER_DEFAULT_SERVICE",
                "LOAD_BALANCER_BACKEND_BUCKET_NAME",
                "LOAD_BALANCER_BACKEND_SERVICE_PROTOCOL",
                "LOAD_BALANCER_BACKEND_SERVICE_LOAD_BALANCING_SCHEME",
                "LOAD_BALANCER_NETWORK_ENDPOINT_TYPE",
                "LOAD_BALANCER_SSL_CERTIFICATES",
                "LOAD_BALANCER_SSL_POLICY",
                "LOAD_BALANCER_CERTIFICATE_MAP",
                "SSL_POLICY_NAME",
                "SSL_POLICY_MIN_TLS_VERSION",
                "SSL_POLICY_PROFILE",
                "SSL_POLICY_CUSTOM_FEATURES",
                "SSL_POLICY_ENABLED_FEATURES",
                "MANAGED_SSL_CERTIFICATE_NAME",
                "MANAGED_SSL_CERTIFICATE_DOMAINS",
                "MANAGED_SSL_CERTIFICATE_STATUS",
                "FRONTED_BY_INTERNET_FACING_LOAD_BALANCER",
                "INTERNET_FACING_LOAD_BALANCER_ADDRESSES",
                "LOAD_BALANCER_BACKENDS",
                "LOAD_BALANCER_HOST_RULES",
                "LOAD_BALANCER_PATH_MATCHERS",
                "LOAD_BALANCER_SERVERLESS_ENDPOINTS",
                "LOAD_BALANCER_NETWORK_ENDPOINTS",
                "LOAD_BALANCER_FRONTENDS",
                "LOAD_BALANCER_REACHABLE_BACKENDS",
                "NETWORK_INTERFACES",
                "SERVICE_ACCOUNTS",
                "CONTAINER_IMAGE_REFERENCES",
                "INTERNET_INGRESS_FIREWALLS",
                "IAM_ROLE",
                "IAM_MEMBER",
                "IAM_CONDITION",
                "IAM_MEMBERS",
                "IAM_ASSIGNMENT_POSTURE_UNCERTAINTIES",
                "WORKLOAD_IDENTITY_FEDERATION_TRUST_PATHS",
                "WORKLOAD_IDENTITY_FEDERATION_TRUST_PATH_UNCERTAINTIES",
                "CUSTOM_ROLE_ID",
                "CUSTOM_ROLE_PERMISSIONS",
                "CUSTOM_ROLE_STAGE",
                "ORGANIZATION_ID",
                "FOLDER_ID",
                "ORG_POLICY_CONSTRAINT",
                "ORG_POLICY_SCOPE",
                "ORG_POLICY_SCOPE_TYPE",
                "IAM_BINDINGS",
                "PRIVILEGED_ACCESS_GRANTS",
                "ORG_POLICY_ENFORCED",
                "ORG_POLICY_INHERIT_FROM_PARENT",
                "ORG_POLICY_RESTORE_DEFAULT",
                "ORG_POLICY_ALLOWED_VALUES",
                "ORG_POLICY_DENIED_VALUES",
                "ORG_POLICY_RULES",
                "BUCKET_NAME",
                "ARTIFACT_REGISTRY_REPOSITORY_ID",
                "ARTIFACT_REGISTRY_REPOSITORY_REFERENCE",
                "ARTIFACT_REGISTRY_REPOSITORY_PATH",
                "ARTIFACT_REGISTRY_WRITE_PATHS",
                "ARTIFACT_REGISTRY_FORMAT",
                "ARTIFACT_REGISTRY_MODE",
                "ARTIFACT_REGISTRY_KMS_KEY_NAME",
                "ARTIFACT_REGISTRY_ENCRYPTION_STATE",
                "ARTIFACT_REGISTRY_DOCKER_IMMUTABLE_TAGS_STATE",
                "ARTIFACT_REGISTRY_DOCKER_CONFIG",
                "ARTIFACT_REGISTRY_VULNERABILITY_SCANNING_ENABLEMENT_CONFIG",
                "ARTIFACT_REGISTRY_VULNERABILITY_SCANNING_ENABLEMENT_STATE",
                "ARTIFACT_REGISTRY_VULNERABILITY_SCANNING_STATE",
                "ARTIFACT_REGISTRY_VULNERABILITY_SCANNING_STATE_REASON",
                "ARTIFACT_REGISTRY_VULNERABILITY_SCANNING_CONFIG",
                "ARTIFACT_REGISTRY_CLEANUP_POLICIES",
                "ARTIFACT_REGISTRY_CLEANUP_POLICY_STATE",
                "ARTIFACT_REGISTRY_CLEANUP_POLICY_DRY_RUN_STATE",
                "ARTIFACT_REGISTRY_DELETION_POLICY",
                "ARTIFACT_REGISTRY_DELETION_POLICY_STATE",
                "ARTIFACT_REGISTRY_POSTURE_UNCERTAINTIES",
                "ARTIFACT_REGISTRY_IAM_POSTURE_UNCERTAINTIES",
                "GCS_DEFAULT_KMS_KEY_NAME",
                "CUSTOMER_MANAGED_ENCRYPTION",
                "GCS_VERSIONING_ENABLED",
                "GCS_RETENTION_PERIOD_SECONDS",
                "GCS_RETENTION_POLICY_LOCKED",
                "GCS_RETENTION_POLICY_CONFIGURATION",
                "GCS_RETENTION_POLICY_UNCERTAINTIES",
                "GCS_VERSIONING_CONFIGURATION",
                "GCS_ENCRYPTION_CONFIGURATION",
                "DATABASE_VERSION",
                "CLOUD_SQL_PRIVATE_NETWORK",
                "CLOUD_SQL_SSL_MODE",
                "CLOUD_SQL_AVAILABILITY_TYPE",
                "CLOUD_SQL_CONNECTOR_ENFORCEMENT",
                "CLOUD_SQL_QUERY_INSIGHTS_ENABLED",
                "CLOUD_SQL_QUERY_INSIGHTS_STATE",
                "CLOUD_SQL_INSIGHTS_CONFIG",
                "CLOUD_SQL_DELETION_PROTECTION_ENABLED",
                "CLOUD_SQL_DELETION_PROTECTION_STATE",
                "CLOUD_SQL_POSTURE_UNCERTAINTIES",
                "CLOUD_SQL_IPV4_ENABLED",
                "CLOUD_SQL_BACKUP_ENABLED",
                "CLOUD_SQL_POINT_IN_TIME_RECOVERY_ENABLED",
                "CLOUD_SQL_REQUIRE_SSL",
                "CLOUD_SQL_AUTHORIZED_NETWORKS",
                "CLOUD_SQL_BACKUP_CONFIGURATION",
                "CLOUD_SQL_IP_CONFIGURATION",
                "DELETION_PROTECTION",
                "SECRET_ID",
                "SECRET_REFERENCE",
                "SECRET_MANAGER_TTL",
                "SECRET_MANAGER_EXPIRE_TIME",
                "SECRET_MANAGER_VERSION_DESTROY_TTL",
                "KMS_CRYPTO_KEY_REFERENCE",
                "KMS_KEY_RING",
                "KMS_PURPOSE",
                "KMS_ROTATION_PERIOD",
                "KMS_DESTROY_SCHEDULED_DURATION",
                "KMS_POSTURE_UNCERTAINTIES",
                "RESOURCE_POLICY_SOURCE_ADDRESSES",
                "SERVICE_ACCOUNT_ACCOUNT_ID",
                "SERVICE_ACCOUNT_EMAIL",
                "SERVICE_ACCOUNT_MEMBER",
                "SERVICE_ACCOUNT_REFERENCE",
                "CLOUD_RUN_SERVICE_REFERENCE",
                "CONTAINER_IMAGE_POSTURE_UNCERTAINTIES",
                "CLOUD_FUNCTION_REFERENCE",
                "SERVERLESS_INGRESS",
                "SERVICE_ACCOUNT_UNIQUE_ID",
                "SERVICE_ACCOUNT_KEY_ALGORITHM",
                "SERVICE_ACCOUNT_PUBLIC_KEY_TYPE",
                "SERVICE_ACCOUNT_DISABLED",
                "OS_LOGIN_ENABLED",
                "GKE_ENDPOINT",
                "GKE_PRIVATE_ENDPOINT_ENABLED",
                "GKE_PRIVATE_NODES_ENABLED",
                "GKE_MASTER_AUTHORIZED_NETWORKS",
                "GKE_WORKLOAD_IDENTITY_ENABLED",
                "GKE_WORKLOAD_IDENTITY_POOL",
                "WORKLOAD_IDENTITY_POOL_ID",
                "WORKLOAD_IDENTITY_POOL_MODE",
                "WORKLOAD_IDENTITY_POOL_STATE",
                "WORKLOAD_IDENTITY_POOL_PROVIDER_ID",
                "WORKLOAD_IDENTITY_POOL_PROVIDER_TYPE",
                "WORKLOAD_IDENTITY_POOL_PROVIDER_STATE",
                "WORKLOAD_IDENTITY_POOL_PROVIDER_ISSUER_URI",
                "WORKLOAD_IDENTITY_POOL_PROVIDER_ALLOWED_AUDIENCES",
                "WORKLOAD_IDENTITY_POOL_PROVIDER_ATTRIBUTE_MAPPINGS",
                "WORKLOAD_IDENTITY_POOL_PROVIDER_ATTRIBUTE_CONDITION",
                "WORKLOAD_IDENTITY_POOL_PROVIDER_AWS_ACCOUNT_ID",
                "WORKLOAD_IDENTITY_POOL_POSTURE_UNCERTAINTIES",
                "GKE_NODE_SERVICE_ACCOUNT",
                "GKE_NODE_OAUTH_SCOPES",
                "GKE_NODE_METADATA_MODE",
                "GKE_LEGACY_METADATA_ENDPOINTS_ENABLED",
                "GKE_LOGGING_SERVICE",
                "GKE_LOGGING_COMPONENTS",
                "GKE_CONTROL_PLANE_LOGGING_STATE",
                "GKE_LOGGING_CONFIG",
                "GKE_NETWORK_POLICY_STATE",
                "GKE_NETWORK_POLICY_PROVIDER",
                "GKE_NETWORK_POLICY",
                "GKE_DATABASE_ENCRYPTION_STATE",
                "GKE_DATABASE_ENCRYPTION_KEY_NAME",
                "GKE_SECRETS_ENCRYPTION_STATE",
                "GKE_DATABASE_ENCRYPTION",
                "GKE_LEGACY_ABAC_ENABLED",
                "GKE_LEGACY_ABAC_STATE",
                "GKE_CLIENT_CERTIFICATE_AUTH_ENABLED",
                "GKE_CLIENT_CERTIFICATE_AUTH_STATE",
                "GKE_BASIC_AUTH_STATE",
                "GKE_BASIC_AUTH_USERNAME",
                "GKE_BASIC_AUTH_PASSWORD_CONFIGURED",
                "GKE_MASTER_AUTH",
                "GKE_CLIENT_CERTIFICATE_CONFIG",
                "GKE_RELEASE_CHANNEL",
                "GKE_RELEASE_CHANNEL_CONFIG",
                "GKE_SHIELDED_NODES_ENABLED",
                "GKE_SHIELDED_NODES_STATE",
                "GKE_SHIELDED_NODES_CONFIG",
                "GKE_BINARY_AUTHORIZATION_EVALUATION_MODE",
                "GKE_BINARY_AUTHORIZATION_STATE",
                "GKE_BINARY_AUTHORIZATION",
                "GKE_POSTURE_UNCERTAINTIES",
                "LOGGING_SINK_NAME",
                "LOGGING_SINK_DESTINATION",
                "LOGGING_SINK_FILTER",
                "LOGGING_SINK_WRITER_IDENTITY",
                "LOGGING_SINK_SCOPE_TYPE",
                "LOGGING_SINK_SCOPE",
                "LOGGING_SINK_INCLUDE_CHILDREN",
                "LOGGING_SINK_UNIQUE_WRITER_IDENTITY",
                "LOGGING_EXCLUSION_NAME",
                "LOGGING_EXCLUSION_DESCRIPTION",
                "LOGGING_EXCLUSION_FILTER",
                "LOGGING_EXCLUSION_SCOPE_TYPE",
                "LOGGING_EXCLUSION_SCOPE",
                "LOGGING_EXCLUSION_DISABLED",
                "SCC_ORGANIZATION",
                "SCC_ENABLE_ASSET_DISCOVERY",
                "SCC_ASSET_DISCOVERY_STATE",
                "SCC_ASSET_DISCOVERY_INCLUSION_MODE",
                "SUBNETWORK_FLOW_LOG_STATE",
                "SUBNETWORK_FLOW_LOG_CONFIG",
                "SUBNETWORK_FLOW_LOG_AGGREGATION_INTERVAL",
                "SUBNETWORK_FLOW_LOG_SAMPLING",
                "SUBNETWORK_FLOW_LOG_METADATA",
                "SUBNETWORK_FLOW_LOG_METADATA_FIELDS",
                "SUBNETWORK_FLOW_LOG_FILTER_EXPR",
                "NETWORK_TELEMETRY_POSTURE_UNCERTAINTIES",
                "SCC_ASSET_DISCOVERY_PROJECT_IDS",
                "SCC_ASSET_DISCOVERY_FOLDER_IDS",
                "SCC_ASSET_DISCOVERY_CONFIG",
                "AUDIT_SECURITY_POSTURE_UNCERTAINTIES",
            },
        )

    def test_resource_facts_are_provider_local(self) -> None:
        facts = gcp_facts(_normalized_resource())

        self.assertIsInstance(facts, GcpResourceFacts)
        self.assertIsNone(facts.bucket_name)
        self.assertEqual(facts.policy_document, {})
        self.assertFalse(hasattr(facts, "bucket_acl"))
        self.assertFalse(hasattr(facts, "public_access_block"))
        self.assertFalse(hasattr(facts, "trust_statements"))
        self.assertFalse(hasattr(facts, "rds_backup_retention_period"))
        self.assertFalse(hasattr(facts, "s3_versioning_enabled"))

    def test_gcp_resource_facts_are_composed_by_domain(self) -> None:
        gcp_provider_root = SOURCE_ROOT / "providers" / "gcp"
        facts_package = gcp_provider_root / "resource_facts"
        required_fact_modules = {
            "artifact_registry",
            "base",
            "storage",
            "secret_manager",
            "kms",
            "iam",
            "identity",
            "network",
            "cloud_sql",
            "compute",
            "gke",
            "audit",
            "edge",
        }

        self.assertFalse((gcp_provider_root / "resource_facts.py").exists())
        self.assertTrue(facts_package.is_dir())
        self.assertTrue(
            required_fact_modules <= {path.stem for path in facts_package.glob("*.py")},
        )

    def test_optional_boolean_facts_preserve_none_and_false(self) -> None:
        resource = NormalizedResource(
            address="google_sql_database_instance.app",
            provider="gcp",
            resource_type=GcpResourceType.SQL_DATABASE_INSTANCE,
            name="app",
            category=ResourceCategory.DATA,
            metadata={
                GcpResourceMetadata.CLOUD_SQL_BACKUP_ENABLED.key: None,
                GcpResourceMetadata.CLOUD_SQL_POINT_IN_TIME_RECOVERY_ENABLED: False,
            },
        )

        facts = gcp_facts(resource)

        self.assertIsNone(facts.backup_enabled)
        self.assertFalse(facts.point_in_time_recovery_enabled)

    def test_gke_facts_read_provider_owned_cluster_metadata(self) -> None:
        resource = NormalizedResource(
            address="google_container_cluster.app",
            provider="gcp",
            resource_type=GcpResourceType.CONTAINER_CLUSTER,
            name="app",
            category=ResourceCategory.COMPUTE,
            metadata={
                GcpResourceMetadata.GKE_ENDPOINT: "35.1.2.3",
                GcpResourceMetadata.GKE_PRIVATE_ENDPOINT_ENABLED: False,
                GcpResourceMetadata.GKE_PRIVATE_NODES_ENABLED: False,
                GcpResourceMetadata.GKE_MASTER_AUTHORIZED_NETWORKS: [
                    {"display_name": "anywhere", "cidr_block": "0.0.0.0/0"}
                ],
                GcpResourceMetadata.GKE_WORKLOAD_IDENTITY_ENABLED: False,
                GcpResourceMetadata.GKE_WORKLOAD_IDENTITY_POOL: None,
                GcpResourceMetadata.GKE_NODE_SERVICE_ACCOUNT: ("123456789-compute@developer.gserviceaccount.com"),
                GcpResourceMetadata.GKE_NODE_OAUTH_SCOPES: ["https://www.googleapis.com/auth/cloud-platform"],
                GcpResourceMetadata.GKE_NODE_METADATA_MODE: "GCE_METADATA",
                GcpResourceMetadata.GKE_LEGACY_METADATA_ENDPOINTS_ENABLED: True,
                GcpResourceMetadata.GKE_LOGGING_SERVICE: "logging.googleapis.com/kubernetes",
                GcpResourceMetadata.GKE_LOGGING_COMPONENTS: ["APISERVER", "SCHEDULER"],
                GcpResourceMetadata.GKE_CONTROL_PLANE_LOGGING_STATE: "configured",
                GcpResourceMetadata.GKE_LOGGING_CONFIG: {"enable_components": ["APISERVER", "SCHEDULER"]},
                GcpResourceMetadata.GKE_NETWORK_POLICY_STATE: "enabled",
                GcpResourceMetadata.GKE_NETWORK_POLICY_PROVIDER: "CALICO",
                GcpResourceMetadata.GKE_NETWORK_POLICY: {"enabled": True, "provider": "CALICO"},
                GcpResourceMetadata.GKE_DATABASE_ENCRYPTION_STATE: "ENCRYPTED",
                GcpResourceMetadata.GKE_DATABASE_ENCRYPTION_KEY_NAME: "projects/demo/locations/global/keyRings/gke/cryptoKeys/secrets",
                GcpResourceMetadata.GKE_SECRETS_ENCRYPTION_STATE: "enabled",
                GcpResourceMetadata.GKE_DATABASE_ENCRYPTION: {
                    "state": "ENCRYPTED",
                    "key_name": "projects/demo/locations/global/keyRings/gke/cryptoKeys/secrets",
                },
                GcpResourceMetadata.GKE_LEGACY_ABAC_ENABLED: False,
                GcpResourceMetadata.GKE_LEGACY_ABAC_STATE: "disabled",
                GcpResourceMetadata.GKE_CLIENT_CERTIFICATE_AUTH_ENABLED: False,
                GcpResourceMetadata.GKE_CLIENT_CERTIFICATE_AUTH_STATE: "disabled",
                GcpResourceMetadata.GKE_BASIC_AUTH_STATE: "disabled",
                GcpResourceMetadata.GKE_BASIC_AUTH_USERNAME: None,
                GcpResourceMetadata.GKE_BASIC_AUTH_PASSWORD_CONFIGURED: False,
                GcpResourceMetadata.GKE_MASTER_AUTH: {
                    "password_configured": False,
                    "client_certificate_config": {"issue_client_certificate": False},
                },
                GcpResourceMetadata.GKE_CLIENT_CERTIFICATE_CONFIG: {"issue_client_certificate": False},
                GcpResourceMetadata.GKE_RELEASE_CHANNEL: "REGULAR",
                GcpResourceMetadata.GKE_RELEASE_CHANNEL_CONFIG: {"channel": "REGULAR"},
                GcpResourceMetadata.GKE_SHIELDED_NODES_ENABLED: True,
                GcpResourceMetadata.GKE_SHIELDED_NODES_STATE: "enabled",
                GcpResourceMetadata.GKE_SHIELDED_NODES_CONFIG: {},
                GcpResourceMetadata.GKE_BINARY_AUTHORIZATION_EVALUATION_MODE: "PROJECT_SINGLETON_POLICY_ENFORCE",
                GcpResourceMetadata.GKE_BINARY_AUTHORIZATION_STATE: "enabled",
                GcpResourceMetadata.GKE_BINARY_AUTHORIZATION: {"evaluation_mode": "PROJECT_SINGLETON_POLICY_ENFORCE"},
                GcpResourceMetadata.GKE_POSTURE_UNCERTAINTIES: [],
            },
        )

        facts = gcp_facts(resource)

        self.assertEqual(facts.gke_endpoint, "35.1.2.3")
        self.assertFalse(facts.gke_private_endpoint_enabled)
        self.assertFalse(facts.gke_private_nodes_enabled)
        self.assertEqual(
            facts.gke_master_authorized_networks,
            [{"display_name": "anywhere", "cidr_block": "0.0.0.0/0"}],
        )
        self.assertFalse(facts.gke_workload_identity_enabled)
        self.assertIsNone(facts.gke_workload_identity_pool)
        self.assertEqual(
            facts.gke_node_service_account,
            "123456789-compute@developer.gserviceaccount.com",
        )
        self.assertEqual(
            facts.gke_node_oauth_scopes,
            ["https://www.googleapis.com/auth/cloud-platform"],
        )
        self.assertEqual(facts.gke_node_metadata_mode, "GCE_METADATA")
        self.assertTrue(facts.gke_legacy_metadata_endpoints_enabled)
        self.assertEqual(facts.gke_logging_service, "logging.googleapis.com/kubernetes")
        self.assertEqual(facts.gke_logging_components, ["APISERVER", "SCHEDULER"])
        self.assertEqual(facts.gke_control_plane_logging_state, "configured")
        self.assertEqual(facts.gke_logging_config, {"enable_components": ["APISERVER", "SCHEDULER"]})
        self.assertEqual(facts.gke_network_policy_state, "enabled")
        self.assertEqual(facts.gke_network_policy_provider, "CALICO")
        self.assertEqual(facts.gke_network_policy, {"enabled": True, "provider": "CALICO"})
        self.assertEqual(facts.gke_database_encryption_state, "ENCRYPTED")
        self.assertEqual(
            facts.gke_database_encryption_key_name,
            "projects/demo/locations/global/keyRings/gke/cryptoKeys/secrets",
        )
        self.assertEqual(facts.gke_secrets_encryption_state, "enabled")
        self.assertEqual(
            facts.gke_database_encryption,
            {"state": "ENCRYPTED", "key_name": "projects/demo/locations/global/keyRings/gke/cryptoKeys/secrets"},
        )
        self.assertFalse(facts.gke_legacy_abac_enabled)
        self.assertEqual(facts.gke_legacy_abac_state, "disabled")
        self.assertFalse(facts.gke_client_certificate_auth_enabled)
        self.assertEqual(facts.gke_client_certificate_auth_state, "disabled")
        self.assertEqual(facts.gke_basic_auth_state, "disabled")
        self.assertIsNone(facts.gke_basic_auth_username)
        self.assertFalse(facts.gke_basic_auth_password_configured)
        self.assertEqual(
            facts.gke_master_auth,
            {"password_configured": False, "client_certificate_config": {"issue_client_certificate": False}},
        )
        self.assertEqual(facts.gke_client_certificate_config, {"issue_client_certificate": False})
        self.assertEqual(facts.gke_release_channel, "REGULAR")
        self.assertEqual(facts.gke_release_channel_config, {"channel": "REGULAR"})
        self.assertTrue(facts.gke_shielded_nodes_enabled)
        self.assertEqual(facts.gke_shielded_nodes_state, "enabled")
        self.assertEqual(facts.gke_shielded_nodes_config, {})
        self.assertEqual(facts.gke_binary_authorization_evaluation_mode, "PROJECT_SINGLETON_POLICY_ENFORCE")
        self.assertEqual(facts.gke_binary_authorization_state, "enabled")
        self.assertEqual(facts.gke_binary_authorization, {"evaluation_mode": "PROJECT_SINGLETON_POLICY_ENFORCE"})
        self.assertEqual(facts.gke_posture_uncertainties, [])

    def test_normalizer_reports_resource_ownership(self) -> None:
        normalizer = GcpNormalizer()

        self.assertTrue(
            normalizer.owns_resource(
                _terraform_resource(
                    address="google_storage_bucket.logs",
                    resource_type=GcpResourceType.STORAGE_BUCKET,
                )
            )
        )
        self.assertTrue(
            normalizer.owns_resource(
                _terraform_resource(
                    address="google_compute_instance.web",
                    resource_type=GcpResourceType.COMPUTE_INSTANCE,
                    provider_name="registry.terraform.io/hashicorp/google-beta",
                )
            )
        )
        self.assertFalse(
            normalizer.owns_resource(
                _terraform_resource(
                    address="aws_s3_bucket.logs",
                    resource_type="aws_s3_bucket",
                    provider_name="registry.terraform.io/hashicorp/aws",
                )
            )
        )

    def test_normalizer_normalizes_supported_gcp_resources_and_tracks_unsupported(self) -> None:
        resources = [
            _terraform_resource(
                address="google_storage_bucket.logs",
                resource_type=GcpResourceType.STORAGE_BUCKET,
            ),
            _terraform_resource(
                address="google_compute_instance.web",
                resource_type=GcpResourceType.COMPUTE_INSTANCE,
                provider_name="registry.terraform.io/hashicorp/google-beta",
            ),
            _terraform_resource(
                address="google_service_account.web",
                resource_type=GcpResourceType.SERVICE_ACCOUNT,
            ),
            _terraform_resource(
                address="google_project_service.compute",
                resource_type="google_project_service",
            ),
            _terraform_resource(
                address="aws_s3_bucket.logs",
                resource_type="aws_s3_bucket",
                provider_name="registry.terraform.io/hashicorp/aws",
            ),
        ]

        inventory = GcpNormalizer().normalize(resources)

        self.assertEqual(inventory.provider, "gcp")
        self.assertEqual(
            [resource.address for resource in inventory.resources],
            ["google_storage_bucket.logs", "google_compute_instance.web", "google_service_account.web"],
        )
        self.assertEqual(inventory.unsupported_resources, ["google_project_service.compute"])
        self.assertEqual(
            InventoryMetadata.SUPPORTED_RESOURCE_TYPES.get(inventory.metadata),
            sorted(SUPPORTED_GCP_TYPES),
        )
        self.assertEqual(InventoryMetadata.TOTAL_INPUT_RESOURCES.get(inventory.metadata), 5)
        self.assertEqual(InventoryMetadata.PROVIDER_RESOURCE_COUNT.get(inventory.metadata), 4)
        self.assertEqual(InventoryMetadata.NORMALIZED_RESOURCE_COUNT.get(inventory.metadata), 3)
        self.assertEqual(
            InventoryMetadata.UNSUPPORTED_RESOURCE_TYPES.get(inventory.metadata),
            {"google_project_service": 1},
        )

    def test_normalizer_recognizes_google_resource_type_prefix_without_provider_suffix(self) -> None:
        resource = _terraform_resource(
            address="google_project_service.compute",
            resource_type="google_project_service",
            provider_name="registry.example.com/custom/provider",
        )

        inventory = GcpNormalizer().normalize([resource])

        self.assertEqual(inventory.unsupported_resources, ["google_project_service.compute"])
        self.assertEqual(InventoryMetadata.PROVIDER_RESOURCE_COUNT.get(inventory.metadata), 1)


if __name__ == "__main__":
    unittest.main()
