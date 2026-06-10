from __future__ import annotations

import unittest

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import NormalizedResource, ResourceCategory, ResourceInventory, TerraformResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer



def _compute_network() -> TerraformResource:
    return TerraformResource(
        address="google_compute_network.main",
        mode="managed",
        resource_type="google_compute_network",
        name="main",
        provider_name="registry.terraform.io/hashicorp/google",
        values={"name": "tfstride-main", "id": "google_compute_network.main"},
    )


def _compute_subnetwork() -> TerraformResource:
    return TerraformResource(
        address="google_compute_subnetwork.app",
        mode="managed",
        resource_type="google_compute_subnetwork",
        name="app",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "name": "tfstride-app",
            "id": "google_compute_subnetwork.app",
            "network": "google_compute_network.main.id",
            "ip_cidr_range": "10.10.0.0/24",
        },
    )


def _public_compute_firewall() -> TerraformResource:
    return TerraformResource(
        address="google_compute_firewall.web",
        mode="managed",
        resource_type="google_compute_firewall",
        name="web",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "name": "tfstride-web",
            "network": "google_compute_network.main.id",
            "direction": "INGRESS",
            "source_ranges": ["0.0.0.0/0"],
            "target_tags": ["web"],
            "allow": [{"protocol": "tcp", "ports": ["443"]}],
        },
    )


def _compute_instance(
    *,
    public: bool = True,
    service_account_email: str = "tfstride-web@tfstride-demo.iam.gserviceaccount.com",
    scopes: list[str] | None = None,
) -> TerraformResource:
    network_interface: dict[str, object] = {"subnetwork": "google_compute_subnetwork.app.id"}
    if public:
        network_interface["access_config"] = [{}]
    return TerraformResource(
        address="google_compute_instance.web",
        mode="managed",
        resource_type="google_compute_instance",
        name="web",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "name": "tfstride-web",
            "machine_type": "e2-medium",
            "zone": "us-central1-a",
            "tags": ["web"],
            "network_interface": [network_interface],
            "service_account": [
                {
                    "email": service_account_email,
                    "scopes": scopes or ["https://www.googleapis.com/auth/cloud-platform"],
                }
            ],
        },
    )


def _gke_cluster(
    *,
    endpoint: str | None = "35.1.2.3",
    private_endpoint: bool = False,
    authorized_networks: list[dict[str, object]] | None = None,
    authorized_networks_configured: bool = True,
    workload_identity_pool: str | None = None,
    node_service_account: str | None = "123456789-compute@developer.gserviceaccount.com",
    oauth_scopes: list[str] | None = None,
    disable_legacy_endpoints: str = "false",
    metadata_mode: str | None = None,
) -> TerraformResource:
    node_config: dict[str, object] = {
        "metadata": {"disable-legacy-endpoints": disable_legacy_endpoints},
        "oauth_scopes": oauth_scopes or ["https://www.googleapis.com/auth/cloud-platform"],
    }
    if node_service_account is not None:
        node_config["service_account"] = node_service_account
    if metadata_mode is not None:
        node_config["workload_metadata_config"] = [{"mode": metadata_mode}]
    values: dict[str, object] = {
        "name": "tfstride-gke",
        "project": "tfstride-demo",
        "location": "us-central1",
        "network": "google_compute_network.main.id",
        "subnetwork": "google_compute_subnetwork.app.id",
        "private_cluster_config": [{"enable_private_endpoint": private_endpoint, "enable_private_nodes": private_endpoint}],
        "node_config": [node_config],
    }
    if endpoint is not None:
        values["endpoint"] = endpoint
    if authorized_networks_configured:
        values["master_authorized_networks_config"] = [
            {"cidr_blocks": authorized_networks if authorized_networks is not None else []}
        ]
    if workload_identity_pool is not None:
        values["workload_identity_config"] = [{"workload_pool": workload_identity_pool}]
    return TerraformResource(
        address="google_container_cluster.app",
        mode="managed",
        resource_type="google_container_cluster",
        name="app",
        provider_name="registry.terraform.io/hashicorp/google",
        values=values,
    )


def _gke_node_pool(
    *,
    node_service_account: str | None = "123456789-compute@developer.gserviceaccount.com",
    oauth_scopes: list[str] | None = None,
    disable_legacy_endpoints: str = "false",
    metadata_mode: str | None = None,
) -> TerraformResource:
    node_config: dict[str, object] = {
        "metadata": {"disable-legacy-endpoints": disable_legacy_endpoints},
        "oauth_scopes": oauth_scopes or ["https://www.googleapis.com/auth/cloud-platform"],
    }
    if node_service_account is not None:
        node_config["service_account"] = node_service_account
    if metadata_mode is not None:
        node_config["workload_metadata_config"] = [{"mode": metadata_mode}]
    return TerraformResource(
        address="google_container_node_pool.app",
        mode="managed",
        resource_type="google_container_node_pool",
        name="app",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "name": "app-pool",
            "project": "tfstride-demo",
            "location": "us-central1",
            "cluster": "google_container_cluster.app.name",
            "node_config": [node_config],
        },
    )


def _cloud_run_service(
    *,
    public_ingress: bool = True,
    service_account_email: str = "tfstride-run@tfstride-demo.iam.gserviceaccount.com",
) -> TerraformResource:
    return TerraformResource(
        address="google_cloud_run_v2_service.api",
        mode="managed",
        resource_type="google_cloud_run_v2_service",
        name="api",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "name": "tfstride-api",
            "project": "tfstride-demo",
            "location": "us-central1",
            "ingress": "INGRESS_TRAFFIC_ALL" if public_ingress else "INGRESS_TRAFFIC_INTERNAL_ONLY",
            "template": [{"service_account": service_account_email}],
        },
    )


def _cloud_run_service_iam_member(
    member: str = "allUsers",
    role: str = "roles/run.invoker",
    condition: dict[str, object] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address="google_cloud_run_v2_service_iam_member.public_invoker",
        mode="managed",
        resource_type="google_cloud_run_v2_service_iam_member",
        name="public_invoker",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "name": "tfstride-api",
            "location": "us-central1",
            "role": role,
            "member": member,
            **({"condition": [condition]} if condition else {}),
        },
    )


def _cloudfunctions_function(
    *,
    public: bool = True,
    service_account_email: str = "tfstride-fn@tfstride-demo.iam.gserviceaccount.com",
) -> TerraformResource:
    return TerraformResource(
        address="google_cloudfunctions_function.fn",
        mode="managed",
        resource_type="google_cloudfunctions_function",
        name="fn",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "name": "tfstride-fn",
            "project": "tfstride-demo",
            "region": "us-central1",
            "runtime": "python312",
            "trigger_http": public,
            "service_account_email": service_account_email,
        },
    )


def _cloudfunctions_function_iam_member(
    member: str = "allUsers",
    role: str = "roles/cloudfunctions.invoker",
) -> TerraformResource:
    return TerraformResource(
        address="google_cloudfunctions_function_iam_member.public_invoker",
        mode="managed",
        resource_type="google_cloudfunctions_function_iam_member",
        name="public_invoker",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "cloud_function": "tfstride-fn",
            "region": "us-central1",
            "role": role,
            "member": member,
        },
    )


def _cloudfunctions2_function(public: bool = True) -> TerraformResource:
    service_config: dict[str, object] = {
        "service_account_email": "tfstride-fn2@tfstride-demo.iam.gserviceaccount.com",
    }
    if public:
        service_config["uri"] = "https://tfstride-fn2-uc.a.run.app"
    return TerraformResource(
        address="google_cloudfunctions2_function.fn2",
        mode="managed",
        resource_type="google_cloudfunctions2_function",
        name="fn2",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "name": "tfstride-fn2",
            "project": "tfstride-demo",
            "location": "us-central1",
            "service_config": [service_config],
        },
    )


def _cloudfunctions2_function_iam_binding(
    members: list[str] | None = None,
    role: str = "roles/cloudfunctions.invoker",
) -> TerraformResource:
    return TerraformResource(
        address="google_cloudfunctions2_function_iam_binding.public_invokers",
        mode="managed",
        resource_type="google_cloudfunctions2_function_iam_binding",
        name="public_invokers",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "cloud_function": "tfstride-fn2",
            "location": "us-central1",
            "role": role,
            "members": members or ["allAuthenticatedUsers"],
        },
    )


def _service_account() -> TerraformResource:
    email = "tfstride-deploy@tfstride-demo.iam.gserviceaccount.com"
    return TerraformResource(
        address="google_service_account.deploy",
        mode="managed",
        resource_type="google_service_account",
        name="deploy",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "account_id": "tfstride-deploy",
            "email": email,
            "name": f"projects/tfstride-demo/serviceAccounts/{email}",
            "project": "tfstride-demo",
        },
    )


def _service_account_key(
    *,
    valid_after: str = "2026-01-01T00:00:00Z",
    valid_before: str = "2027-01-01T00:00:00Z",
    keepers: dict[str, object] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address="google_service_account_key.deploy",
        mode="managed",
        resource_type="google_service_account_key",
        name="deploy",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "name": "projects/tfstride-demo/serviceAccounts/tfstride-deploy@tfstride-demo.iam.gserviceaccount.com/keys/key-id",
            "service_account_id": "google_service_account.deploy.name",
            "key_algorithm": "KEY_ALG_RSA_2048",
            "public_key_type": "TYPE_X509_PEM_FILE",
            "valid_after": valid_after,
            "valid_before": valid_before,
            "keepers": keepers or {},
            "private_key": "redacted-test-secret-material",
        },
    )


def _service_account_iam_member(
    role: str = "roles/iam.serviceAccountTokenCreator",
    member: str = "group:deploy@example.com",
) -> TerraformResource:
    return TerraformResource(
        address="google_service_account_iam_member.deploy_token_creator",
        mode="managed",
        resource_type="google_service_account_iam_member",
        name="deploy_token_creator",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "service_account_id": "google_service_account.deploy.name",
            "role": role,
            "member": member,
        },
    )


def _service_account_iam_binding(
    role: str = "roles/iam.serviceAccountUser",
    members: list[str] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address="google_service_account_iam_binding.deploy_users",
        mode="managed",
        resource_type="google_service_account_iam_binding",
        name="deploy_users",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "service_account_id": "google_service_account.deploy.name",
            "role": role,
            "members": members or ["allUsers"],
        },
    )


def _service_account_iam_policy(bindings: list[dict[str, object]]) -> TerraformResource:
    return TerraformResource(
        address="google_service_account_iam_policy.deploy_policy",
        mode="managed",
        resource_type="google_service_account_iam_policy",
        name="deploy_policy",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "service_account_id": "google_service_account.deploy.name",
            "policy_data": {"bindings": bindings},
        },
    )


def _project_iam_member(role: str, member: str = "serviceAccount:deploy@example.iam.gserviceaccount.com") -> TerraformResource:
    return TerraformResource(
        address="google_project_iam_member.binding",
        mode="managed",
        resource_type="google_project_iam_member",
        name="binding",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "project": "tfstride-demo",
            "role": role,
            "member": member,
        },
    )


def _project_iam_binding(
    role: str,
    members: list[str] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address="google_project_iam_binding.binding",
        mode="managed",
        resource_type="google_project_iam_binding",
        name="binding",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "project": "tfstride-demo",
            "role": role,
            "members": members or ["serviceAccount:deploy@example.iam.gserviceaccount.com"],
        },
    )


def _project_iam_policy(bindings: list[dict[str, object]]) -> TerraformResource:
    return TerraformResource(
        address="google_project_iam_policy.policy",
        mode="managed",
        resource_type="google_project_iam_policy",
        name="policy",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "project": "tfstride-demo",
            "policy_data": {"bindings": bindings},
        },
    )


def _organization_iam_member(
    role: str,
    member: str = "group:platform-admins@example.com",
) -> TerraformResource:
    return TerraformResource(
        address="google_organization_iam_member.binding",
        mode="managed",
        resource_type="google_organization_iam_member",
        name="binding",
        provider_name="registry.terraform.io/hashicorp/google",
        values={"org_id": "1234567890", "role": role, "member": member},
    )


def _organization_iam_binding(
    role: str,
    members: list[str] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address="google_organization_iam_binding.binding",
        mode="managed",
        resource_type="google_organization_iam_binding",
        name="binding",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "org_id": "1234567890",
            "role": role,
            "members": members or ["group:platform-admins@example.com"],
        },
    )


def _organization_iam_policy(bindings: list[dict[str, object]]) -> TerraformResource:
    return TerraformResource(
        address="google_organization_iam_policy.policy",
        mode="managed",
        resource_type="google_organization_iam_policy",
        name="policy",
        provider_name="registry.terraform.io/hashicorp/google",
        values={"org_id": "1234567890", "policy_data": {"bindings": bindings}},
    )


def _folder_iam_member(
    role: str,
    member: str = "group:folder-admins@example.com",
) -> TerraformResource:
    return TerraformResource(
        address="google_folder_iam_member.binding",
        mode="managed",
        resource_type="google_folder_iam_member",
        name="binding",
        provider_name="registry.terraform.io/hashicorp/google",
        values={"folder": "folders/12345", "role": role, "member": member},
    )


def _organization_iam_custom_role(
    role_id: str = "orgAdmin",
    permissions: list[str] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address="google_organization_iam_custom_role.custom",
        mode="managed",
        resource_type="google_organization_iam_custom_role",
        name="custom",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "org_id": "1234567890",
            "role_id": role_id,
            "title": "Org Custom Role",
            "permissions": permissions or ["resourcemanager.projects.setIamPolicy"],
            "stage": "GA",
        },
    )


def _project_iam_custom_role(
    role_id: str = "deployAdmin",
    permissions: list[str] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address="google_project_iam_custom_role.custom",
        mode="managed",
        resource_type="google_project_iam_custom_role",
        name="custom",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "project": "tfstride-demo",
            "role_id": role_id,
            "title": "Custom Role",
            "permissions": permissions or ["iam.serviceAccounts.actAs"],
            "stage": "GA",
        },
    )


def _storage_bucket(
    public_access_prevention: str | None = None,
    *,
    uniform_bucket_level_access: bool = True,
    versioning_enabled: bool = True,
    default_kms_key_name: str | None = "projects/tfstride-demo/locations/global/keyRings/app/cryptoKeys/gcs",
) -> TerraformResource:
    values = {
        "name": "tfstride-logs",
        "location": "US",
        "uniform_bucket_level_access": uniform_bucket_level_access,
        "versioning": [{"enabled": versioning_enabled}],
    }
    if public_access_prevention is not None:
        values["public_access_prevention"] = public_access_prevention
    if default_kms_key_name is not None:
        values["encryption"] = [{"default_kms_key_name": default_kms_key_name}]
    return TerraformResource(
        address="google_storage_bucket.logs",
        mode="managed",
        resource_type="google_storage_bucket",
        name="logs",
        provider_name="registry.terraform.io/hashicorp/google",
        values=values,
    )


def _storage_bucket_iam_member(
    member: str = "allUsers",
    role: str = "roles/storage.objectViewer",
    *,
    bucket: str = "google_storage_bucket.logs.name",
) -> TerraformResource:
    return TerraformResource(
        address="google_storage_bucket_iam_member.public_logs_reader",
        mode="managed",
        resource_type="google_storage_bucket_iam_member",
        name="public_logs_reader",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "bucket": bucket,
            "role": role,
            "member": member,
        },
    )


def _cloud_sql_instance(
    *,
    ipv4_enabled: bool = True,
    authorized_networks: list[dict[str, object]] | None = None,
    backup_enabled: bool = True,
    pitr_enabled: bool = True,
    private_network: str | None = None,
    require_ssl: bool = True,
    ssl_mode: str | None = None,
    deletion_protection: bool = True,
) -> TerraformResource:
    ip_configuration: dict[str, object] = {
        "ipv4_enabled": ipv4_enabled,
        "require_ssl": require_ssl,
        "authorized_networks": authorized_networks if authorized_networks is not None else [],
    }
    if private_network is not None:
        ip_configuration["private_network"] = private_network
    if ssl_mode is not None:
        ip_configuration["ssl_mode"] = ssl_mode
    return TerraformResource(
        address="google_sql_database_instance.app",
        mode="managed",
        resource_type="google_sql_database_instance",
        name="app",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "name": "tfstride-app-db",
            "database_version": "POSTGRES_15",
            "settings": [
                {
                    "backup_configuration": [
                        {
                            "enabled": backup_enabled,
                            "point_in_time_recovery_enabled": pitr_enabled,
                        }
                    ],
                    "ip_configuration": [ip_configuration],
                }
            ],
            "deletion_protection": deletion_protection,
        },
    )


def _secret_manager_secret(project: str = "tfstride-demo") -> TerraformResource:
    return TerraformResource(
        address="google_secret_manager_secret.api_key",
        mode="managed",
        resource_type="google_secret_manager_secret",
        name="api_key",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "secret_id": "tfstride-api-key",
            "id": "projects/tfstride-demo/secrets/tfstride-api-key",
            "project": project,
            "replication": [{"auto": [{}]}],
        },
    )


def _secret_manager_secret_iam_member(
    member: str = "allAuthenticatedUsers",
    role: str = "roles/secretmanager.secretAccessor",
) -> TerraformResource:
    return TerraformResource(
        address="google_secret_manager_secret_iam_member.public_accessor",
        mode="managed",
        resource_type="google_secret_manager_secret_iam_member",
        name="public_accessor",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "secret_id": "google_secret_manager_secret.api_key.id",
            "role": role,
            "member": member,
        },
    )


def _kms_crypto_key() -> TerraformResource:
    return TerraformResource(
        address="google_kms_crypto_key.customer",
        mode="managed",
        resource_type="google_kms_crypto_key",
        name="customer",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "name": "tfstride-customer-key",
            "id": "projects/tfstride-demo/locations/global/keyRings/tfstride-app/cryptoKeys/tfstride-customer-key",
            "key_ring": "projects/tfstride-demo/locations/global/keyRings/tfstride-app",
            "purpose": "ENCRYPT_DECRYPT",
        },
    )


def _kms_crypto_key_iam_member(
    member: str = "serviceAccount:decryptor@partner-project.iam.gserviceaccount.com",
    role: str = "roles/cloudkms.cryptoKeyDecrypter",
) -> TerraformResource:
    return TerraformResource(
        address="google_kms_crypto_key_iam_member.partner_decrypter",
        mode="managed",
        resource_type="google_kms_crypto_key_iam_member",
        name="partner_decrypter",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "crypto_key_id": "google_kms_crypto_key.customer.id",
            "role": role,
            "member": member,
        },
    )


def _kms_key_ring_iam_member(
    member: str = "serviceAccount:decryptor@partner-project.iam.gserviceaccount.com",
    role: str = "roles/cloudkms.cryptoKeyDecrypter",
) -> TerraformResource:
    return TerraformResource(
        address="google_kms_key_ring_iam_member.partner_decrypter",
        mode="managed",
        resource_type="google_kms_key_ring_iam_member",
        name="partner_decrypter",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "key_ring_id": "projects/tfstride-demo/locations/global/keyRings/tfstride-app",
            "role": role,
            "member": member,
        },
    )


def _pubsub_topic() -> TerraformResource:
    return TerraformResource(
        address="google_pubsub_topic.events",
        mode="managed",
        resource_type="google_pubsub_topic",
        name="events",
        provider_name="registry.terraform.io/hashicorp/google",
        values={"name": "tfstride-events", "project": "tfstride-demo"},
    )


def _pubsub_subscription() -> TerraformResource:
    return TerraformResource(
        address="google_pubsub_subscription.events",
        mode="managed",
        resource_type="google_pubsub_subscription",
        name="events",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "name": "tfstride-events-sub",
            "topic": "google_pubsub_topic.events.id",
            "project": "tfstride-demo",
        },
    )


def _pubsub_topic_iam_member(
    member: str = "allUsers",
    role: str = "roles/pubsub.publisher",
) -> TerraformResource:
    return TerraformResource(
        address="google_pubsub_topic_iam_member.public_publisher",
        mode="managed",
        resource_type="google_pubsub_topic_iam_member",
        name="public_publisher",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "topic": "google_pubsub_topic.events.name",
            "role": role,
            "member": member,
        },
    )


def _pubsub_subscription_iam_binding(
    members: list[str] | None = None,
    role: str = "roles/pubsub.subscriber",
) -> TerraformResource:
    return TerraformResource(
        address="google_pubsub_subscription_iam_binding.public_subscribers",
        mode="managed",
        resource_type="google_pubsub_subscription_iam_binding",
        name="public_subscribers",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "subscription": "google_pubsub_subscription.events.name",
            "role": role,
            "members": members or ["domain:example.com"],
        },
    )


def _bigquery_dataset() -> TerraformResource:
    return TerraformResource(
        address="google_bigquery_dataset.analytics",
        mode="managed",
        resource_type="google_bigquery_dataset",
        name="analytics",
        provider_name="registry.terraform.io/hashicorp/google",
        values={"dataset_id": "tfstride_analytics", "project": "tfstride-demo", "location": "US"},
    )


def _bigquery_table() -> TerraformResource:
    return TerraformResource(
        address="google_bigquery_table.events",
        mode="managed",
        resource_type="google_bigquery_table",
        name="events",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "dataset_id": "google_bigquery_dataset.analytics.dataset_id",
            "table_id": "events",
            "project": "tfstride-demo",
        },
    )


def _bigquery_dataset_iam_member(
    member: str = "allUsers",
    role: str = "roles/bigquery.dataViewer",
) -> TerraformResource:
    return TerraformResource(
        address="google_bigquery_dataset_iam_member.public_viewer",
        mode="managed",
        resource_type="google_bigquery_dataset_iam_member",
        name="public_viewer",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "dataset_id": "google_bigquery_dataset.analytics.dataset_id",
            "role": role,
            "member": member,
        },
    )


def _bigquery_table_iam_binding(
    members: list[str] | None = None,
    role: str = "roles/bigquery.dataOwner",
) -> TerraformResource:
    return TerraformResource(
        address="google_bigquery_table_iam_binding.domain_owner",
        mode="managed",
        resource_type="google_bigquery_table_iam_binding",
        name="domain_owner",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "table_id": "google_bigquery_table.events.table_id",
            "role": role,
            "members": members or ["domain:example.com"],
        },
    )


def _normalized_gcp_resource(
    address: str,
    resource_type: str,
    category: ResourceCategory,
    *,
    identifier: str | None = None,
    data_sensitivity: str = "standard",
    metadata: dict[str, object] | None = None,
) -> NormalizedResource:
    return NormalizedResource(
        address=address,
        provider="gcp",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        category=category,
        identifier=identifier,
        data_sensitivity=data_sensitivity,
        metadata=metadata,
    )


class GcpRuleTests(unittest.TestCase):
    def test_public_compute_ssh_and_rdp_broad_ingress_is_detected_for_each_target(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _compute_network(),
                _compute_subnetwork(),
                TerraformResource(
                    address="google_compute_firewall.admin",
                    mode="managed",
                    resource_type="google_compute_firewall",
                    name="admin",
                    provider_name="registry.terraform.io/hashicorp/google",
                    values={
                        "name": "tfstride-admin",
                        "network": "google_compute_network.main.name",
                        "direction": "INGRESS",
                        "source_ranges": ["0.0.0.0/0"],
                        "allow": [{"protocol": "tcp", "ports": ["22", "3389"]}],
                    },
                ),
                _compute_instance(),
                TerraformResource(
                    address="google_compute_instance.worker",
                    mode="managed",
                    resource_type="google_compute_instance",
                    name="worker",
                    provider_name="registry.terraform.io/hashicorp/google",
                    values={
                        "name": "tfstride-worker",
                        "machine_type": "e2-medium",
                        "zone": "us-central1-a",
                        "network_interface": [
                            {
                                "subnetwork": "google_compute_subnetwork.app.id",
                                "access_config": [{}],
                            }
                        ],
                    },
                ),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-compute-broad-ingress"})),
        )

        self.assertEqual(
            [finding.affected_resources for finding in findings],
            [
                ["google_compute_instance.web", "google_compute_firewall.admin"],
                ["google_compute_instance.worker", "google_compute_firewall.admin"],
            ],
        )
        for finding in findings:
            evidence = {item.key: item.values for item in finding.evidence}
            self.assertEqual(
                evidence["firewall_rules"],
                [
                    "google_compute_firewall.admin ingress tcp 22 from 0.0.0.0/0",
                    "google_compute_firewall.admin ingress tcp 3389 from 0.0.0.0/0",
                ],
            )

    def test_direct_network_compute_firewall_produces_public_compute_finding(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _compute_network(),
                TerraformResource(
                    address="google_compute_firewall.admin",
                    mode="managed",
                    resource_type="google_compute_firewall",
                    name="admin",
                    provider_name="registry.terraform.io/hashicorp/google",
                    values={
                        "name": "tfstride-admin",
                        "network": "google_compute_network.main.name",
                        "direction": "INGRESS",
                        "source_ranges": ["0.0.0.0/0"],
                        "target_tags": ["web"],
                        "allow": [{"protocol": "tcp", "ports": ["22"]}],
                    },
                ),
                TerraformResource(
                    address="google_compute_instance.web",
                    mode="managed",
                    resource_type="google_compute_instance",
                    name="web",
                    provider_name="registry.terraform.io/hashicorp/google",
                    values={
                        "name": "tfstride-web",
                        "tags": ["web"],
                        "network_interface": [
                            {
                                "network": "google_compute_network.main.id",
                                "access_config": [{}],
                            }
                        ],
                    },
                ),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-compute-broad-ingress"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(
            finding.affected_resources,
            ["google_compute_instance.web", "google_compute_firewall.admin"],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            "internet-to-service:internet->google_compute_instance.web",
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["internet_ingress_reasons"],
            ["google_compute_firewall.admin ingress tcp 22 from 0.0.0.0/0"],
        )
        self.assertEqual(
            evidence["public_exposure_reasons"],
            [
                "compute instance has an external access config and matching firewall rules allow internet ingress"
            ],
        )

    def test_private_compute_broad_admin_firewall_is_still_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _compute_network(),
                _compute_subnetwork(),
                TerraformResource(
                    address="google_compute_firewall.admin",
                    mode="managed",
                    resource_type="google_compute_firewall",
                    name="admin",
                    provider_name="registry.terraform.io/hashicorp/google",
                    values={
                        "name": "tfstride-admin",
                        "network": "projects/tfstride-demo/global/networks/tfstride-main",
                        "direction": "INGRESS",
                        "source_ranges": ["0.0.0.0/0"],
                        "allow": [{"protocol": "tcp", "ports": ["22"]}],
                    },
                ),
                _compute_instance(public=False),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-compute-broad-ingress"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(
            finding.affected_resources,
            ["google_compute_instance.web", "google_compute_firewall.admin"],
        )
        self.assertIsNone(finding.trust_boundary_id)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["internet_ingress_reasons"],
            ["google_compute_firewall.admin ingress tcp 22 from 0.0.0.0/0"],
        )
        self.assertNotIn("public_exposure_reasons", evidence)

    def test_compute_os_login_disabled_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                TerraformResource(
                    address="google_compute_instance.app",
                    mode="managed",
                    resource_type="google_compute_instance",
                    name="app",
                    provider_name="registry.terraform.io/hashicorp/google",
                    values={
                        "name": "tfstride-app",
                        "metadata": {"enable-oslogin": "false"},
                    },
                )
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-compute-os-login-disabled"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-compute-os-login-disabled")
        self.assertEqual(finding.severity.value, "low")
        self.assertEqual(finding.affected_resources, ["google_compute_instance.app"])
        self.assertIsNone(finding.trust_boundary_id)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["os_login_posture"], ["metadata.enable-oslogin is false"])

    def test_compute_os_login_enabled_or_unset_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                TerraformResource(
                    address="google_compute_instance.enabled",
                    mode="managed",
                    resource_type="google_compute_instance",
                    name="enabled",
                    provider_name="registry.terraform.io/hashicorp/google",
                    values={"name": "enabled", "metadata": {"enable-oslogin": "true"}},
                ),
                TerraformResource(
                    address="google_compute_instance.unset",
                    mode="managed",
                    resource_type="google_compute_instance",
                    name="unset",
                    provider_name="registry.terraform.io/hashicorp/google",
                    values={"name": "unset"},
                ),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-compute-os-login-disabled"})),
        )

        self.assertEqual(findings, [])

    def test_gke_public_control_plane_rule_detects_public_cluster(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _gke_cluster(
                    authorized_networks=[{"display_name": "admin", "cidr_block": "203.0.113.0/24"}],
                    workload_identity_pool="tfstride-demo.svc.id.goog",
                    node_service_account="gke-nodes@tfstride-demo.iam.gserviceaccount.com",
                    oauth_scopes=["https://www.googleapis.com/auth/logging.write"],
                    disable_legacy_endpoints="true",
                    metadata_mode="GKE_METADATA",
                )
            ]
        )
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gke-public-control-plane"})),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "gcp-gke-public-control-plane")
        self.assertEqual(findings[0].affected_resources, ["google_container_cluster.app"])

    def test_gke_broad_authorized_networks_rule_detects_anywhere_cidr(self) -> None:
        inventory = GcpNormalizer().normalize(
            [_gke_cluster(authorized_networks=[{"display_name": "anywhere", "cidr_block": "0.0.0.0/0"}])]
        )
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gke-broad-authorized-networks"})),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "gcp-gke-broad-authorized-networks")
        self.assertIn("anywhere (0.0.0.0/0)", findings[0].evidence[0].values)

    def test_gke_broad_authorized_networks_rule_detects_missing_config(self) -> None:
        inventory = GcpNormalizer().normalize([_gke_cluster(authorized_networks_configured=False)])
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gke-broad-authorized-networks"})),
        )

        self.assertEqual(len(findings), 1)
        self.assertIn("master authorized networks are not configured", findings[0].evidence[0].values)

    def test_gke_broad_authorized_networks_rule_ignores_private_or_restricted_cluster(self) -> None:
        private_inventory = GcpNormalizer().normalize([_gke_cluster(endpoint=None, private_endpoint=True)])
        restricted_inventory = GcpNormalizer().normalize(
            [_gke_cluster(authorized_networks=[{"display_name": "admin", "cidr_block": "203.0.113.0/24"}])]
        )

        for inventory in (private_inventory, restricted_inventory):
            findings = StrideRuleEngine().evaluate(
                inventory,
                detect_trust_boundaries(inventory),
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gke-broad-authorized-networks"})),
            )
            self.assertEqual(findings, [])

    def test_gke_workload_identity_disabled_rule_detects_missing_workload_pool(self) -> None:
        inventory = GcpNormalizer().normalize([_gke_cluster()])
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gke-workload-identity-disabled"})),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "gcp-gke-workload-identity-disabled")

    def test_gke_workload_identity_disabled_rule_ignores_enabled_cluster(self) -> None:
        inventory = GcpNormalizer().normalize([_gke_cluster(workload_identity_pool="tfstride-demo.svc.id.goog")])
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gke-workload-identity-disabled"})),
        )

        self.assertEqual(findings, [])

    def test_gke_legacy_metadata_rule_detects_cluster_and_node_pool(self) -> None:
        inventory = GcpNormalizer().normalize([_gke_cluster(), _gke_node_pool()])
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gke-legacy-metadata-endpoints-enabled"})),
        )

        self.assertEqual(
            [finding.affected_resources for finding in findings],
            [["google_container_cluster.app"], ["google_container_node_pool.app"]],
        )

    def test_gke_legacy_metadata_rule_ignores_hardened_node_pool(self) -> None:
        inventory = GcpNormalizer().normalize(
            [_gke_node_pool(disable_legacy_endpoints="true", metadata_mode="GKE_METADATA")]
        )
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gke-legacy-metadata-endpoints-enabled"})),
        )

        self.assertEqual(findings, [])

    def test_gke_broad_node_service_account_rule_detects_default_sa_and_scope(self) -> None:
        inventory = GcpNormalizer().normalize([_gke_node_pool()])
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gke-broad-node-service-account"})),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "gcp-gke-broad-node-service-account")
        self.assertEqual(findings[0].affected_resources, ["google_container_node_pool.app"])

    def test_gke_broad_node_service_account_rule_ignores_dedicated_limited_identity(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _gke_node_pool(
                    node_service_account="gke-nodes@tfstride-demo.iam.gserviceaccount.com",
                    oauth_scopes=["https://www.googleapis.com/auth/logging.write"],
                    disable_legacy_endpoints="true",
                    metadata_mode="GKE_METADATA",
                )
            ]
        )
        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gke-broad-node-service-account"})),
        )

        self.assertEqual(findings, [])

    def test_gcs_public_bucket_iam_member_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_storage_bucket(), _storage_bucket_iam_member()])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gcs-public-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-gcs-public-access")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["google_storage_bucket.logs"])
        self.assertIsNone(finding.trust_boundary_id)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["public_exposure_reasons"],
            [
                "google_storage_bucket_iam_member.public_logs_reader grants "
                "roles/storage.objectViewer to allUsers"
            ],
        )

    def test_gcs_all_authenticated_users_bucket_iam_member_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [_storage_bucket(), _storage_bucket_iam_member(member="allAuthenticatedUsers")]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gcs-public-access"})),
        )

        self.assertEqual([finding.rule_id for finding in findings], ["gcp-gcs-public-access"])

    def test_gcs_public_access_prevention_suppresses_public_iam_grant(self) -> None:
        inventory = GcpNormalizer().normalize(
            [_storage_bucket(public_access_prevention="enforced"), _storage_bucket_iam_member()]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gcs-public-access"})),
        )

        self.assertEqual(findings, [])

    def test_gcs_non_public_member_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _storage_bucket(),
                _storage_bucket_iam_member(member="serviceAccount:reader@example.iam.gserviceaccount.com"),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gcs-public-access"})),
        )

        self.assertEqual(findings, [])

    def test_gcs_uniform_bucket_level_access_disabled_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_storage_bucket(uniform_bucket_level_access=False)])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset({"gcp-gcs-uniform-bucket-level-access-disabled"})
            ),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-gcs-uniform-bucket-level-access-disabled")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["google_storage_bucket.logs"])
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["access_control_posture"], ["uniform_bucket_level_access is false"])

    def test_gcs_public_access_prevention_not_enforced_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_storage_bucket(public_access_prevention="inherited")])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset({"gcp-gcs-public-access-prevention-not-enforced"})
            ),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-gcs-public-access-prevention-not-enforced")
        self.assertEqual(finding.severity.value, "medium")
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["access_control_posture"], ["public_access_prevention is inherited"])

    def test_gcs_public_access_prevention_enforced_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize([_storage_bucket(public_access_prevention="enforced")])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset({"gcp-gcs-public-access-prevention-not-enforced"})
            ),
        )

        self.assertEqual(findings, [])

    def test_gcs_versioning_disabled_is_detected_for_sensitive_bucket(self) -> None:
        inventory = GcpNormalizer().normalize([_storage_bucket(versioning_enabled=False)])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gcs-versioning-disabled"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-gcs-versioning-disabled")
        self.assertEqual(finding.severity.value, "medium")
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["data_protection_posture"],
            ["versioning.enabled is false", "data_sensitivity is sensitive"],
        )

    def test_gcs_customer_managed_encryption_missing_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_storage_bucket(default_kms_key_name=None)])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset({"gcp-gcs-customer-managed-encryption-missing"})
            ),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-gcs-customer-managed-encryption-missing")
        self.assertEqual(finding.severity.value, "medium")
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["encryption_posture"],
            ["default_kms_key_name is unset", "customer_managed_encryption is false"],
        )

    def test_gcs_customer_managed_encryption_is_not_flagged_when_kms_key_is_configured(self) -> None:
        inventory = GcpNormalizer().normalize([_storage_bucket()])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset({"gcp-gcs-customer-managed-encryption-missing"})
            ),
        )

        self.assertEqual(findings, [])

    def test_cloud_sql_public_authorized_network_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_sql_instance(
                    authorized_networks=[{"name": "anywhere", "value": "0.0.0.0/0"}],
                )
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset({"gcp-cloud-sql-public-authorized-network"})
            ),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-cloud-sql-public-authorized-network")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(finding.affected_resources, ["google_sql_database_instance.app"])
        self.assertEqual(
            finding.trust_boundary_id,
            "internet-to-service:internet->google_sql_database_instance.app",
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["authorized_networks"], ["anywhere (0.0.0.0/0)"])
        self.assertEqual(
            evidence["public_exposure_reasons"],
            ["authorized network `anywhere` allows 0.0.0.0/0"],
        )

    def test_cloud_sql_backup_disabled_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_sql_instance(
                    ipv4_enabled=False,
                    backup_enabled=False,
                    pitr_enabled=False,
                    private_network="google_compute_network.main.id",
                )
            ]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-cloud-sql-backup-disabled")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["google_sql_database_instance.app"])
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["backup_posture"],
            [
                "backup_configuration.enabled is false",
                "point_in_time_recovery_enabled is false",
                "engine is POSTGRES_15",
            ],
        )

    def test_private_backed_up_cloud_sql_instance_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_sql_instance(
                    ipv4_enabled=False,
                    backup_enabled=True,
                    pitr_enabled=True,
                    private_network="google_compute_network.main.id",
                )
            ]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(findings, [])


    def test_cloud_sql_public_ip_without_private_network_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_cloud_sql_instance(ipv4_enabled=True, private_network=None)])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset({"gcp-cloud-sql-public-ip-without-private-network"})
            ),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-cloud-sql-public-ip-without-private-network")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["google_sql_database_instance.app"])
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["network_posture"],
            [
                "ipv4_enabled is true",
                "private_network is unset",
                "authorized_networks configured: 0",
            ],
        )
        self.assertEqual(
            evidence["public_access_reasons"],
            ["Cloud SQL public IPv4 access is enabled"],
        )

    def test_cloud_sql_private_network_suppresses_public_ip_without_private_network(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_sql_instance(
                    ipv4_enabled=True,
                    private_network="google_compute_network.main.id",
                )
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset({"gcp-cloud-sql-public-ip-without-private-network"})
            ),
        )

        self.assertEqual(findings, [])

    def test_cloud_sql_ssl_not_required_is_detected_for_public_ipv4(self) -> None:
        inventory = GcpNormalizer().normalize([_cloud_sql_instance(require_ssl=False)])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-sql-ssl-not-required"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-cloud-sql-ssl-not-required")
        self.assertEqual(finding.severity.value, "medium")
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["ssl_posture"],
            ["require_ssl is false", "ssl_mode is unset", "ipv4_enabled is true"],
        )

    def test_cloud_sql_enforcing_ssl_mode_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize(
            [_cloud_sql_instance(require_ssl=False, ssl_mode="ENCRYPTED_ONLY")]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-sql-ssl-not-required"})),
        )

        self.assertEqual(findings, [])

    def test_cloud_sql_point_in_time_recovery_disabled_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_sql_instance(
                    ipv4_enabled=False,
                    backup_enabled=True,
                    pitr_enabled=False,
                    private_network="google_compute_network.main.id",
                )
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset({"gcp-cloud-sql-point-in-time-recovery-disabled"})
            ),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-cloud-sql-point-in-time-recovery-disabled")
        self.assertEqual(finding.severity.value, "medium")
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["backup_posture"],
            [
                "backup_configuration.enabled is true",
                "point_in_time_recovery_enabled is false",
                "engine is POSTGRES_15",
            ],
        )

    def test_cloud_sql_deletion_protection_disabled_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_sql_instance(
                    ipv4_enabled=False,
                    private_network="google_compute_network.main.id",
                    deletion_protection=False,
                )
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset({"gcp-cloud-sql-deletion-protection-disabled"})
            ),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-cloud-sql-deletion-protection-disabled")
        self.assertEqual(finding.severity.value, "medium")
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["lifecycle_posture"], ["deletion_protection is false"])


    def test_sensitive_secret_public_iam_binding_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [_secret_manager_secret(), _secret_manager_secret_iam_member()]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-sensitive-resource-iam-external-access")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            [
                "google_secret_manager_secret.api_key",
                "google_secret_manager_secret_iam_member.public_accessor",
            ],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["iam_binding"],
            [
                "source=google_secret_manager_secret_iam_member.public_accessor",
                "role=roles/secretmanager.secretAccessor",
                "member=allAuthenticatedUsers",
            ],
        )
        self.assertEqual(evidence["trust_scope"], ["member is public GCP principal `allAuthenticatedUsers`"])

    def test_sensitive_kms_foreign_service_account_binding_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_kms_crypto_key(), _kms_crypto_key_iam_member()])

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-sensitive-resource-iam-external-access")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(
            finding.affected_resources,
            ["google_kms_crypto_key.customer", "google_kms_crypto_key_iam_member.partner_decrypter"],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["trust_scope"],
            ["service account belongs to project `partner-project`, outside resource project `tfstride-demo`"],
        )

    def test_sensitive_kms_key_ring_foreign_service_account_binding_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_kms_crypto_key(), _kms_key_ring_iam_member()])

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-sensitive-resource-iam-external-access")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(
            finding.affected_resources,
            ["google_kms_crypto_key.customer", "google_kms_key_ring_iam_member.partner_decrypter"],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["iam_binding"],
            [
                "source=google_kms_key_ring_iam_member.partner_decrypter",
                "role=roles/cloudkms.cryptoKeyDecrypter",
                "member=serviceAccount:decryptor@partner-project.iam.gserviceaccount.com",
            ],
        )
        self.assertEqual(
            evidence["trust_scope"],
            ["service account belongs to project `partner-project`, outside resource project `tfstride-demo`"],
        )

    def test_pubsub_public_topic_publisher_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_pubsub_topic(), _pubsub_topic_iam_member()])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-pubsub-public-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-pubsub-public-access")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            ["google_pubsub_topic.events", "google_pubsub_topic_iam_member.public_publisher"],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["iam_binding"],
            [
                "source=google_pubsub_topic_iam_member.public_publisher",
                "role=roles/pubsub.publisher",
                "member=allUsers",
            ],
        )

    def test_pubsub_broad_subscription_subscriber_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [_pubsub_subscription(), _pubsub_subscription_iam_binding()]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-pubsub-public-access"})),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].affected_resources[0], "google_pubsub_subscription.events")
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(evidence["trust_scope"], ["member grants a whole Google Workspace domain"])

    def test_pubsub_non_broad_member_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize(
            [_pubsub_topic(), _pubsub_topic_iam_member(member="serviceAccount:publisher@tfstride-demo.iam.gserviceaccount.com")]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-pubsub-public-access"})),
        )

        self.assertEqual(findings, [])

    def test_bigquery_public_dataset_viewer_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_bigquery_dataset(), _bigquery_dataset_iam_member()])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-bigquery-public-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-bigquery-public-access")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            ["google_bigquery_dataset.analytics", "google_bigquery_dataset_iam_member.public_viewer"],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["trust_scope"], ["member is public GCP principal `allUsers`"])

    def test_bigquery_table_domain_owner_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [_bigquery_table(), _bigquery_table_iam_binding()]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-bigquery-public-access"})),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].affected_resources[0], "google_bigquery_table.events")
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(evidence["trust_scope"], ["member grants a whole Google Workspace domain"])

    def test_bigquery_non_broad_member_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize(
            [_bigquery_dataset(), _bigquery_dataset_iam_member(member="group:analytics@example.com")]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-bigquery-public-access"})),
        )

        self.assertEqual(findings, [])

    def test_sensitive_same_project_service_account_binding_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _kms_crypto_key(),
                _kms_crypto_key_iam_member(
                    member="serviceAccount:decryptor@tfstride-demo.iam.gserviceaccount.com"
                ),
            ]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(findings, [])


    def test_public_compute_service_account_secret_access_path_is_detected(self) -> None:
        service_account = "serviceAccount:tfstride-web@tfstride-demo.iam.gserviceaccount.com"
        inventory = GcpNormalizer().normalize(
            [
                _compute_network(),
                _compute_subnetwork(),
                _public_compute_firewall(),
                _compute_instance(),
                _secret_manager_secret(),
                _secret_manager_secret_iam_member(member=service_account),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-workload-sensitive-data-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-public-workload-sensitive-data-access")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            [
                "google_compute_instance.web",
                "google_secret_manager_secret.api_key",
                "google_secret_manager_secret_iam_member.public_accessor",
            ],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            "workload-to-data-store:google_compute_instance.web->google_secret_manager_secret.api_key",
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["workload_identity"], [service_account])
        self.assertEqual(
            evidence["data_access_path"],
            ["google_compute_instance.web reaches google_secret_manager_secret.api_key"],
        )
        self.assertIn(
            "google_secret_manager_secret_iam_member.public_accessor grants roles/secretmanager.secretAccessor",
            evidence["boundary_rationale"][0],
        )

    def test_public_cloud_run_service_account_bigquery_access_path_is_detected(self) -> None:
        service_account = "serviceAccount:tfstride-run@tfstride-demo.iam.gserviceaccount.com"
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run_service(),
                _cloud_run_service_iam_member(),
                _bigquery_dataset(),
                _bigquery_dataset_iam_member(member=service_account),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-workload-sensitive-data-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-public-workload-sensitive-data-access")
        self.assertEqual(
            finding.trust_boundary_id,
            "workload-to-data-store:google_cloud_run_v2_service.api->google_bigquery_dataset.analytics",
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["workload_identity"], [service_account])
        self.assertIn(
            "google_bigquery_dataset_iam_member.public_viewer grants roles/bigquery.dataViewer",
            evidence["boundary_rationale"][0],
        )

    def test_public_cloud_run_invoker_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_cloud_run_service(), _cloud_run_service_iam_member()])
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-run-public-invoker"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-cloud-run-public-invoker")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(
            finding.affected_resources,
            ["google_cloud_run_v2_service.api", "google_cloud_run_v2_service_iam_member.public_invoker"],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            "internet-to-service:internet->google_cloud_run_v2_service.api",
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["public_invoker_bindings"],
            [
                "source=google_cloud_run_v2_service_iam_member.public_invoker; "
                "role=roles/run.invoker; member=allUsers"
            ],
        )
        self.assertEqual(
            evidence["public_exposure_reasons"],
            ["google_cloud_run_v2_service_iam_member.public_invoker grants roles/run.invoker to allUsers"],
        )

    def test_cloud_run_public_invoker_reports_constraining_iam_condition(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run_service(),
                _cloud_run_service_iam_member(
                    condition={
                        "title": "expires_soon",
                        'expression': 'request.time < timestamp("2026-07-01T00:00:00Z")',
                    }
                ),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-run-public-invoker"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.severity.value, "low")
        self.assertEqual(finding.severity_reasoning.blast_radius, 0)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["iam_condition"],
            [
                "category=time_limited",
                "constraining=true",
                "title=expires_soon",
                'expression=request.time < timestamp("2026-07-01T00:00:00Z")',
            ],
        )

    def test_cloud_run_public_invoker_requires_public_ingress_and_public_member(self) -> None:
        private_inventory = GcpNormalizer().normalize(
            [_cloud_run_service(public_ingress=False), _cloud_run_service_iam_member()]
        )
        non_public_inventory = GcpNormalizer().normalize(
            [
                _cloud_run_service(),
                _cloud_run_service_iam_member(member="serviceAccount:caller@example.iam.gserviceaccount.com"),
            ]
        )

        engine = StrideRuleEngine()

        self.assertEqual(
            engine.evaluate(
                private_inventory,
                detect_trust_boundaries(private_inventory),
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-run-public-invoker"})),
            ),
            [],
        )
        self.assertEqual(
            engine.evaluate(
                non_public_inventory,
                detect_trust_boundaries(non_public_inventory),
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-run-public-invoker"})),
            ),
            [],
        )

    def test_public_cloud_function_invoker_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_cloudfunctions_function(), _cloudfunctions_function_iam_member()])
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-functions-public-invoker"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-cloud-functions-public-invoker")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(
            finding.affected_resources,
            ["google_cloudfunctions_function.fn", "google_cloudfunctions_function_iam_member.public_invoker"],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            "internet-to-service:internet->google_cloudfunctions_function.fn",
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["public_invoker_bindings"],
            [
                "source=google_cloudfunctions_function_iam_member.public_invoker; "
                "role=roles/cloudfunctions.invoker; member=allUsers"
            ],
        )
        self.assertEqual(
            evidence["public_exposure_reasons"],
            [
                "google_cloudfunctions_function_iam_member.public_invoker grants "
                "roles/cloudfunctions.invoker to allUsers"
            ],
        )

    def test_public_cloudfunctions2_binding_invoker_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [_cloudfunctions2_function(), _cloudfunctions2_function_iam_binding()]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-functions-public-invoker"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(
            finding.affected_resources,
            ["google_cloudfunctions2_function.fn2", "google_cloudfunctions2_function_iam_binding.public_invokers"],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["public_invoker_bindings"],
            [
                "source=google_cloudfunctions2_function_iam_binding.public_invokers; "
                "role=roles/cloudfunctions.invoker; member=allAuthenticatedUsers"
            ],
        )

    def test_cloud_function_public_invoker_requires_public_http_and_public_member(self) -> None:
        private_inventory = GcpNormalizer().normalize(
            [_cloudfunctions_function(public=False), _cloudfunctions_function_iam_member()]
        )
        non_public_inventory = GcpNormalizer().normalize(
            [
                _cloudfunctions_function(),
                _cloudfunctions_function_iam_member(member="serviceAccount:caller@example.iam.gserviceaccount.com"),
            ]
        )

        engine = StrideRuleEngine()

        self.assertEqual(
            engine.evaluate(
                private_inventory,
                detect_trust_boundaries(private_inventory),
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-functions-public-invoker"})),
            ),
            [],
        )
        self.assertEqual(
            engine.evaluate(
                non_public_inventory,
                detect_trust_boundaries(non_public_inventory),
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-functions-public-invoker"})),
            ),
            [],
        )

    def test_public_cloud_run_service_account_secret_access_path_is_detected(self) -> None:
        service_account = "serviceAccount:tfstride-run@tfstride-demo.iam.gserviceaccount.com"
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run_service(),
                _cloud_run_service_iam_member(),
                _secret_manager_secret(),
                _secret_manager_secret_iam_member(member=service_account),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-workload-sensitive-data-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-public-workload-sensitive-data-access")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            [
                "google_cloud_run_v2_service.api",
                "google_secret_manager_secret.api_key",
                "google_secret_manager_secret_iam_member.public_accessor",
            ],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            "workload-to-data-store:google_cloud_run_v2_service.api->google_secret_manager_secret.api_key",
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["public_exposure_reasons"],
            ["google_cloud_run_v2_service_iam_member.public_invoker grants roles/run.invoker to allUsers"],
        )
        self.assertEqual(evidence["workload_identity"], [service_account])
        self.assertEqual(
            evidence["data_access_path"],
            ["google_cloud_run_v2_service.api reaches google_secret_manager_secret.api_key"],
        )
        self.assertIn(
            "google_secret_manager_secret_iam_member.public_accessor grants roles/secretmanager.secretAccessor",
            evidence["boundary_rationale"][0],
        )

    def test_private_cloud_run_sensitive_data_path_is_not_reported(self) -> None:
        service_account = "serviceAccount:tfstride-run@tfstride-demo.iam.gserviceaccount.com"
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run_service(public_ingress=False),
                _cloud_run_service_iam_member(),
                _secret_manager_secret(),
                _secret_manager_secret_iam_member(member=service_account),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-workload-sensitive-data-access"})),
        )

        self.assertEqual(findings, [])

    def test_public_cloud_function_service_account_secret_access_path_is_detected(self) -> None:
        service_account = "serviceAccount:tfstride-fn@tfstride-demo.iam.gserviceaccount.com"
        inventory = GcpNormalizer().normalize(
            [
                _cloudfunctions_function(),
                _cloudfunctions_function_iam_member(),
                _secret_manager_secret(),
                _secret_manager_secret_iam_member(member=service_account),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-workload-sensitive-data-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(
            finding.affected_resources,
            [
                "google_cloudfunctions_function.fn",
                "google_secret_manager_secret.api_key",
                "google_secret_manager_secret_iam_member.public_accessor",
            ],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            "workload-to-data-store:google_cloudfunctions_function.fn->google_secret_manager_secret.api_key",
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["public_exposure_reasons"],
            [
                "google_cloudfunctions_function_iam_member.public_invoker grants "
                "roles/cloudfunctions.invoker to allUsers"
            ],
        )
        self.assertEqual(evidence["workload_identity"], [service_account])

    def test_project_iam_kms_access_path_is_detected_for_public_compute(self) -> None:
        service_account = "serviceAccount:tfstride-web@tfstride-demo.iam.gserviceaccount.com"
        inventory = GcpNormalizer().normalize(
            [
                _compute_network(),
                _compute_subnetwork(),
                _public_compute_firewall(),
                _compute_instance(),
                _kms_crypto_key(),
                _project_iam_member("roles/cloudkms.cryptoKeyDecrypter", member=service_account),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-workload-sensitive-data-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.affected_resources, ["google_compute_instance.web", "google_kms_crypto_key.customer"])
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertIn(
            "google_project_iam_member.binding grants roles/cloudkms.cryptoKeyDecrypter",
            evidence["boundary_rationale"][0],
        )

    def test_project_iam_custom_role_secret_access_path_is_detected_for_public_compute(self) -> None:
        service_account = "serviceAccount:tfstride-web@tfstride-demo.iam.gserviceaccount.com"
        inventory = GcpNormalizer().normalize(
            [
                _compute_network(),
                _compute_subnetwork(),
                _public_compute_firewall(),
                _compute_instance(),
                _secret_manager_secret(),
                _project_iam_custom_role(
                    role_id="secretReader",
                    permissions=["secretmanager.versions.access"],
                ),
                _project_iam_member("projects/tfstride-demo/roles/secretReader", member=service_account),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-workload-sensitive-data-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(
            finding.affected_resources,
            ["google_compute_instance.web", "google_secret_manager_secret.api_key"],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertIn(
            "google_project_iam_member.binding grants projects/tfstride-demo/roles/secretReader",
            evidence["boundary_rationale"][0],
        )

    def test_project_iam_binding_kms_access_path_is_detected_for_public_compute(self) -> None:
        service_account = "serviceAccount:tfstride-web@tfstride-demo.iam.gserviceaccount.com"
        inventory = GcpNormalizer().normalize(
            [
                _compute_network(),
                _compute_subnetwork(),
                _public_compute_firewall(),
                _compute_instance(),
                _kms_crypto_key(),
                _project_iam_binding("roles/cloudkms.cryptoKeyDecrypter", members=[service_account]),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-workload-sensitive-data-access"})),
        )

        self.assertEqual(len(findings), 1)
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertIn(
            "google_project_iam_binding.binding grants roles/cloudkms.cryptoKeyDecrypter",
            evidence["boundary_rationale"][0],
        )

    def test_private_compute_sensitive_data_path_is_not_reported(self) -> None:
        service_account = "serviceAccount:tfstride-web@tfstride-demo.iam.gserviceaccount.com"
        inventory = GcpNormalizer().normalize(
            [
                _compute_network(),
                _compute_subnetwork(),
                _compute_instance(public=False),
                _secret_manager_secret(),
                _secret_manager_secret_iam_member(member=service_account),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-workload-sensitive-data-access"})),
        )

        self.assertEqual(findings, [])

    def test_public_compute_to_private_cloud_sql_path_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _compute_network(),
                _compute_subnetwork(),
                _public_compute_firewall(),
                _compute_instance(),
                _cloud_sql_instance(
                    ipv4_enabled=False,
                    private_network="google_compute_network.main.id",
                ),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-workload-sensitive-data-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(
            finding.affected_resources,
            ["google_compute_instance.web", "google_sql_database_instance.app"],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            "workload-to-data-store:google_compute_instance.web->google_sql_database_instance.app",
        )

    def test_service_account_iam_public_principal_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_service_account(), _service_account_iam_binding()])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-service-account-iam-broad-principal"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-service-account-iam-broad-principal")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            ["google_service_account.deploy", "google_service_account_iam_binding.deploy_users"],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["iam_binding"],
            [
                "source=google_service_account_iam_binding.deploy_users",
                "member=allUsers",
                "role=roles/iam.serviceAccountUser",
            ],
        )
        self.assertEqual(evidence["trust_scope"], ["member is public GCP principal `allUsers`"])
        self.assertEqual(evidence["service_account_reference"], ["google_service_account.deploy.name"])

    def test_service_account_iam_domain_principal_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _service_account(),
                _service_account_iam_member(
                    role="roles/iam.serviceAccountUser",
                    member="domain:example.com",
                ),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-service-account-iam-broad-principal"})),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity.value, "medium")
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(evidence["trust_scope"], ["member grants a whole Google Workspace domain"])

    def test_service_account_iam_high_risk_role_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _service_account(),
                _service_account_iam_policy(
                    [
                        {"role": "roles/viewer", "members": ["group:ops@example.com"]},
                        {
                            "role": "roles/iam.serviceAccountTokenCreator",
                            "members": ["group:deploy@example.com"],
                        },
                    ]
                ),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-service-account-iam-privileged-role"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-service-account-iam-privileged-role")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            ["google_service_account.deploy", "google_service_account_iam_policy.deploy_policy"],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["iam_binding"],
            [
                "source=google_service_account_iam_policy.deploy_policy",
                "member=group:deploy@example.com",
                "role=roles/iam.serviceAccountTokenCreator",
            ],
        )
        self.assertEqual(evidence["role_risk"], ["service account token minting and impersonation"])

    def test_service_account_key_hygiene_detects_long_lived_key_without_keepers(self) -> None:
        inventory = GcpNormalizer().normalize([_service_account(), _service_account_key()])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-service-account-key-hygiene"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-service-account-key-hygiene")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(
            finding.affected_resources,
            ["google_service_account.deploy", "google_service_account_key.deploy"],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["key_context"],
            [
                "source=google_service_account_key.deploy",
                "service_account_reference=google_service_account.deploy.name",
                "key_algorithm=KEY_ALG_RSA_2048",
                "public_key_type=TYPE_X509_PEM_FILE",
            ],
        )
        self.assertEqual(
            evidence["key_risk"],
            [
                "Terraform manages a user-created service-account key",
                "validity window is 365 days and exceeds 180-day threshold",
                "no Terraform keepers rotation trigger observed",
            ],
        )
        self.assertEqual(
            evidence["validity_window"],
            [
                "valid_after=2026-01-01T00:00:00Z",
                "valid_before=2027-01-01T00:00:00Z",
                "validity_days=365",
            ],
        )
        self.assertEqual(
            evidence["rotation_control"],
            ["no Terraform keepers rotation trigger observed"],
        )

    def test_service_account_key_effective_access_detects_sensitive_data_grant(self) -> None:
        service_account = "serviceAccount:tfstride-deploy@tfstride-demo.iam.gserviceaccount.com"
        inventory = GcpNormalizer().normalize(
            [
                _service_account(),
                _service_account_key(),
                _bigquery_dataset(),
                _bigquery_dataset_iam_member(member=service_account),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset({"gcp-service-account-key-effective-access"})
            ),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-service-account-key-effective-access")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            [
                "google_service_account.deploy",
                "google_service_account_key.deploy",
                "google_bigquery_dataset.analytics",
                "google_bigquery_dataset_iam_member.public_viewer",
            ],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["service_account_principals"],
            [
                "serviceAccount:tfstride-deploy@tfstride-demo.iam.gserviceaccount.com",
                "tfstride-deploy@tfstride-demo.iam.gserviceaccount.com",
            ],
        )
        self.assertEqual(
            evidence["effective_access"],
            [
                "resource=google_bigquery_dataset.analytics; "
                "source=google_bigquery_dataset_iam_member.public_viewer; "
                "scope=BigQuery dataset IAM; role=roles/bigquery.dataViewer; "
                "member=serviceAccount:tfstride-deploy@tfstride-demo.iam.gserviceaccount.com; "
                "risk=BigQuery dataset IAM grants roles/bigquery.dataViewer",
            ],
        )

    def test_service_account_key_effective_access_ignores_viewer_only_project_grant(self) -> None:
        service_account = "serviceAccount:tfstride-deploy@tfstride-demo.iam.gserviceaccount.com"
        inventory = GcpNormalizer().normalize(
            [
                _service_account(),
                _service_account_key(),
                _project_iam_member("roles/viewer", member=service_account),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset({"gcp-service-account-key-effective-access"})
            ),
        )

        self.assertEqual(findings, [])

    def test_service_account_key_effective_access_detects_service_account_iam_grant(self) -> None:
        service_account = "serviceAccount:tfstride-deploy@tfstride-demo.iam.gserviceaccount.com"
        inventory = GcpNormalizer().normalize(
            [
                _service_account(),
                _service_account_key(),
                _service_account_iam_member(member=service_account),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset({"gcp-service-account-key-effective-access"})
            ),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            [
                "google_service_account.deploy",
                "google_service_account_key.deploy",
                "google_service_account_iam_member.deploy_token_creator",
            ],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["effective_access"],
            [
                "resource=google_service_account.deploy; "
                "source=google_service_account_iam_member.deploy_token_creator; "
                "scope=service account IAM; role=roles/iam.serviceAccountTokenCreator; "
                "member=serviceAccount:tfstride-deploy@tfstride-demo.iam.gserviceaccount.com; "
                "risk=service account token minting and impersonation",
            ],
        )


    def test_service_account_iam_low_risk_group_binding_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _service_account(),
                _service_account_iam_member(
                    role="roles/viewer",
                    member="group:ops@example.com",
                ),
            ]
        )

        engine = StrideRuleEngine()

        self.assertEqual(
            engine.evaluate(
                inventory,
                [],
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-service-account-iam-broad-principal"})),
            ),
            [],
        )
        self.assertEqual(
            engine.evaluate(
                inventory,
                [],
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-service-account-iam-privileged-role"})),
            ),
            [],
        )

    def test_organization_iam_broad_principal_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [_organization_iam_binding("roles/viewer", members=["domain:example.com", "group:ops@example.com"])]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-org-folder-iam-broad-principal")
        self.assertEqual(finding.affected_resources, ["google_organization_iam_binding.binding"])
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["iam_binding"], ["member=domain:example.com", "role=roles/viewer"])
        self.assertEqual(evidence["scope"], ["organization scope `1234567890`"])

    def test_folder_iam_public_principal_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_folder_iam_member("roles/viewer", member="allUsers")])

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-org-folder-iam-broad-principal")
        self.assertEqual(finding.severity.value, "high")
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["scope"], ["folder scope `folders/12345`"])

    def test_organization_iam_privileged_role_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_organization_iam_member("roles/resourcemanager.organizationAdmin")])

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-org-folder-iam-privileged-role")
        self.assertEqual(finding.affected_resources, ["google_organization_iam_member.binding"])
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["role_risk"], ["organization-level resource administration"])
        self.assertEqual(evidence["scope"], ["organization scope `1234567890`"])

    def test_folder_iam_policy_privileged_role_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _organization_iam_policy(
                    [{"role": "roles/viewer", "members": ["group:ops@example.com"]}]
                ),
                TerraformResource(
                    address="google_folder_iam_policy.policy",
                    mode="managed",
                    resource_type="google_folder_iam_policy",
                    name="policy",
                    provider_name="registry.terraform.io/hashicorp/google",
                    values={
                        "folder": "folders/12345",
                        "policy_data": {
                            "bindings": [
                                {"role": "roles/resourcemanager.folderAdmin", "members": ["group:admins@example.com"]}
                            ]
                        },
                    },
                ),
            ]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual([finding.rule_id for finding in findings], ["gcp-org-folder-iam-privileged-role"])
        self.assertEqual(findings[0].affected_resources, ["google_folder_iam_policy.policy"])

    def test_organization_iam_custom_role_privileged_permissions_are_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _organization_iam_custom_role(
                    role_id="orgAdmin",
                    permissions=["resourcemanager.projects.setIamPolicy", "iam.serviceAccounts.actAs"],
                ),
                _organization_iam_member("organizations/1234567890/roles/orgAdmin"),
            ]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual([finding.rule_id for finding in findings], ["gcp-org-folder-iam-privileged-role"])
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(
            evidence["role_risk"],
            ["custom role includes high-impact permissions: iam.serviceAccounts.actAs, resourcemanager.projects.setIamPolicy"],
        )
        self.assertEqual(
            evidence["custom_role_permissions"],
            ["iam.serviceAccounts.actAs", "resourcemanager.projects.setIamPolicy"],
        )

    def test_organization_iam_viewer_group_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize([_organization_iam_member("roles/viewer")])

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(findings, [])

    def test_project_iam_broad_principal_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _project_iam_member(
                    "roles/viewer",
                    member="allUsers",
                )
            ]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-project-iam-broad-principal")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["google_project_iam_member.binding"])
        self.assertIsNone(finding.trust_boundary_id)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["iam_binding"], ["member=allUsers", "role=roles/viewer"])

    def test_project_iam_binding_broad_principal_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [_project_iam_binding("roles/viewer", members=["allAuthenticatedUsers", "group:ops@example.com"])]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-project-iam-broad-principal")
        self.assertEqual(finding.affected_resources, ["google_project_iam_binding.binding"])
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["iam_binding"], ["member=allAuthenticatedUsers", "role=roles/viewer"])

    def test_project_iam_privileged_role_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_project_iam_member("roles/owner")])

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-project-iam-privileged-role")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(finding.affected_resources, ["google_project_iam_member.binding"])
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["iam_binding"],
            ["member=serviceAccount:deploy@example.iam.gserviceaccount.com", "role=roles/owner"],
        )
        self.assertEqual(evidence["role_risk"], ["full project administration"])

    def test_project_iam_policy_privileged_role_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _project_iam_policy(
                    [
                        {"role": "roles/viewer", "members": ["group:ops@example.com"]},
                        {"role": "roles/owner", "members": ["group:admins@example.com"]},
                    ]
                )
            ]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-project-iam-privileged-role")
        self.assertEqual(finding.affected_resources, ["google_project_iam_policy.policy"])
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["iam_binding"], ["member=group:admins@example.com", "role=roles/owner"])

    def test_project_iam_admin_class_role_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_project_iam_member("roles/compute.admin")])

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual([finding.rule_id for finding in findings], ["gcp-project-iam-privileged-role"])
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(
            evidence["role_risk"],
            ["admin-level control over a GCP service or project security surface"],
        )

    def test_project_iam_custom_role_privileged_permissions_are_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _project_iam_custom_role(
                    role_id="deployAdmin",
                    permissions=["iam.serviceAccounts.actAs", "cloudfunctions.functions.update"],
                ),
                _project_iam_member("projects/tfstride-demo/roles/deployAdmin"),
            ]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual([finding.rule_id for finding in findings], ["gcp-project-iam-privileged-role"])
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(
            evidence["role_risk"],
            ["custom role includes high-impact permissions: cloudfunctions.functions.update, iam.serviceAccounts.actAs"],
        )
        self.assertEqual(
            evidence["custom_role_permissions"],
            ["cloudfunctions.functions.update", "iam.serviceAccounts.actAs"],
        )

    def test_public_principal_with_privileged_role_reports_both_iam_findings(self) -> None:
        inventory = GcpNormalizer().normalize([_project_iam_member("roles/owner", member="allUsers")])

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(
            {finding.rule_id for finding in findings},
            {"gcp-project-iam-privileged-role", "gcp-project-iam-broad-principal"},
        )

    def test_project_iam_viewer_service_account_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize([_project_iam_member("roles/viewer")])

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(findings, [])

    def test_inherited_project_iam_data_role_reaches_sensitive_descendant(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _secret_manager_secret(),
                _bigquery_dataset(),
                _project_iam_member(
                    "roles/secretmanager.secretAccessor",
                    member="group:secops@example.com",
                ),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset({"gcp-inherited-iam-sensitive-resource-access"})
            ),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-inherited-iam-sensitive-resource-access")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(
            finding.affected_resources,
            [
                "google_project_iam_member.binding",
                "google_secret_manager_secret.api_key",
            ],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["iam_binding"],
            [
                "source=google_project_iam_member.binding",
                "scope=project:tfstride-demo",
                "member=group:secops@example.com",
                "role=roles/secretmanager.secretAccessor",
            ],
        )
        self.assertEqual(
            evidence["sensitive_descendants"],
            [
                "resource=google_secret_manager_secret.api_key; "
                "type=google_secret_manager_secret; "
                "risk=Secret Manager secret access through roles/secretmanager.secretAccessor"
            ],
        )

    def test_inherited_project_iam_viewer_does_not_reach_sensitive_descendant(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _secret_manager_secret(),
                _project_iam_member("roles/viewer", member="allUsers"),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset({"gcp-inherited-iam-sensitive-resource-access"})
            ),
        )

        self.assertEqual(findings, [])

    def test_inherited_folder_iam_data_role_reaches_folder_descendant(self) -> None:
        secret = _normalized_gcp_resource(
            "google_secret_manager_secret.folder_api",
            "google_secret_manager_secret",
            ResourceCategory.DATA,
            identifier="projects/tfstride-folder/secrets/api",
            data_sensitivity="sensitive",
            metadata={
                GcpResourceMetadata.FOLDER_ID.key: "folders/12345",
                GcpResourceMetadata.PROJECT.key: "tfstride-folder",
            },
        )
        folder_iam = _normalized_gcp_resource(
            "google_folder_iam_member.secret_reader",
            "google_folder_iam_member",
            ResourceCategory.IAM,
            metadata={
                GcpResourceMetadata.FOLDER_ID.key: "folders/12345",
                GcpResourceMetadata.IAM_ROLE.key: "roles/secretmanager.secretAccessor",
                GcpResourceMetadata.IAM_MEMBER.key: "allUsers",
            },
        )
        inventory = ResourceInventory(provider="gcp", resources=[secret, folder_iam])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset({"gcp-inherited-iam-sensitive-resource-access"})
            ),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            [
                "google_folder_iam_member.secret_reader",
                "google_secret_manager_secret.folder_api",
            ],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["iam_binding"],
            [
                "source=google_folder_iam_member.secret_reader",
                "scope=folder:12345",
                "member=allUsers",
                "role=roles/secretmanager.secretAccessor",
            ],
        )
        self.assertEqual(
            evidence["trust_scope"],
            ["member is public GCP principal `allUsers`"],
        )

    def test_inherited_project_iam_custom_role_data_permissions_are_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _project_iam_custom_role(
                    role_id="analyticsReader",
                    permissions=["bigquery.tables.getData"],
                ),
                _bigquery_dataset(),
                _project_iam_member(
                    "projects/tfstride-demo/roles/analyticsReader",
                    member="group:analytics@example.com",
                ),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset({"gcp-inherited-iam-sensitive-resource-access"})
            ),
        )

        self.assertEqual(len(findings), 1)
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(evidence["custom_role_permissions"], ["bigquery.tables.getData"])
        self.assertEqual(
            evidence["sensitive_descendants"],
            [
                "resource=google_bigquery_dataset.analytics; type=google_bigquery_dataset; "
                "risk=BigQuery dataset data access through custom role "
                "projects/tfstride-demo/roles/analyticsReader"
            ],
        )

    def test_inherited_project_iam_privileged_role_reports_descendant_blast_radius(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _secret_manager_secret(),
                _bigquery_dataset(),
                _project_iam_member(
                    "roles/editor",
                    member="serviceAccount:deployer@partner-project.iam.gserviceaccount.com",
                ),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-inherited-iam-blast-radius"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-inherited-iam-blast-radius")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            [
                "google_project_iam_member.binding",
                "google_bigquery_dataset.analytics",
                "google_secret_manager_secret.api_key",
            ],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["iam_binding"],
            [
                "source=google_project_iam_member.binding",
                "scope=project:tfstride-demo",
                "member=serviceAccount:deployer@partner-project.iam.gserviceaccount.com",
                "role=roles/editor",
            ],
        )
        self.assertEqual(evidence["role_risk"], ["broad write access across most project services"])
        self.assertEqual(
            evidence["trust_scope"],
            [
                "service account belongs to project `partner-project`, "
                "outside resource project `tfstride-demo`"
            ],
        )
        self.assertEqual(
            evidence["descendant_scope"],
            ["scope=project:tfstride-demo", "descendant_count=2", "resource_type_count=2", "projects=tfstride-demo"],
        )
        self.assertEqual(
            evidence["descendant_resource_types"],
            ["google_bigquery_dataset: 1", "google_secret_manager_secret: 1"],
        )

    def test_inherited_project_iam_low_risk_group_binding_is_not_blast_radius(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _secret_manager_secret(),
                _bigquery_dataset(),
                _project_iam_member("roles/viewer", member="group:ops@example.com"),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-inherited-iam-blast-radius"})),
        )

        self.assertEqual(findings, [])

    def test_inherited_folder_iam_broad_principal_reports_descendant_blast_radius(self) -> None:
        instance = _normalized_gcp_resource(
            "google_compute_instance.folder_web",
            "google_compute_instance",
            ResourceCategory.COMPUTE,
            metadata={GcpResourceMetadata.FOLDER_ID.key: "folders/12345"},
        )
        bucket = _normalized_gcp_resource(
            "google_storage_bucket.folder_logs",
            "google_storage_bucket",
            ResourceCategory.DATA,
            data_sensitivity="sensitive",
            metadata={GcpResourceMetadata.FOLDER_ID.key: "folders/12345"},
        )
        folder_iam = _normalized_gcp_resource(
            "google_folder_iam_member.domain_viewer",
            "google_folder_iam_member",
            ResourceCategory.IAM,
            metadata={
                GcpResourceMetadata.FOLDER_ID.key: "folders/12345",
                GcpResourceMetadata.IAM_ROLE.key: "roles/viewer",
                GcpResourceMetadata.IAM_MEMBER.key: "domain:example.com",
            },
        )
        inventory = ResourceInventory(provider="gcp", resources=[instance, bucket, folder_iam])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-inherited-iam-blast-radius"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(
            finding.affected_resources,
            [
                "google_folder_iam_member.domain_viewer",
                "google_compute_instance.folder_web",
                "google_storage_bucket.folder_logs",
            ],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["trust_scope"],
            ["member grants a whole Google Workspace domain"],
        )
        self.assertEqual(
            evidence["descendant_scope"],
            ["scope=folder:12345", "descendant_count=2", "resource_type_count=2", "folders=folders/12345"],
        )



if __name__ == "__main__":
    unittest.main()