from __future__ import annotations

from tfstride.models import TerraformResource


def _storage_bucket(
    public_access_prevention: str | None = None,
    *,
    uniform_bucket_level_access: bool = True,
    versioning_enabled: bool = True,
    default_kms_key_name: str | None = "projects/tfstride-demo/locations/global/keyRings/app/cryptoKeys/gcs",
    retention_policy: dict[str, object] | None = None,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    values = {
        "name": "tfstride-logs",
        "project": "tfstride-demo",
        "location": "US",
        "uniform_bucket_level_access": uniform_bucket_level_access,
        "versioning": [{"enabled": versioning_enabled}],
    }
    if public_access_prevention is not None:
        values["public_access_prevention"] = public_access_prevention
    if default_kms_key_name is not None:
        values["encryption"] = [{"default_kms_key_name": default_kms_key_name}]
    if retention_policy is not None:
        values["retention_policy"] = [retention_policy]
    return TerraformResource(
        address="google_storage_bucket.logs",
        mode="managed",
        resource_type="google_storage_bucket",
        name="logs",
        provider_name="registry.terraform.io/hashicorp/google",
        values=values,
        unknown_values=unknown_values or {},
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
    availability_type: str | None = None,
    query_insights_enabled: bool | None = None,
    connector_enforcement: str | None = None,
    unknown_settings: dict[str, object] | None = None,
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

    settings: dict[str, object] = {
        "backup_configuration": [
            {
                "enabled": backup_enabled,
                "point_in_time_recovery_enabled": pitr_enabled,
            }
        ],
        "ip_configuration": [ip_configuration],
    }
    if availability_type is not None:
        settings["availability_type"] = availability_type
    if connector_enforcement is not None:
        settings["connector_enforcement"] = connector_enforcement
    if query_insights_enabled is not None:
        settings["insights_config"] = [{"query_insights_enabled": query_insights_enabled}]

    return TerraformResource(
        address="google_sql_database_instance.app",
        mode="managed",
        resource_type="google_sql_database_instance",
        name="app",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "name": "tfstride-app-db",
            "database_version": "POSTGRES_15",
            "settings": [settings],
            "deletion_protection": deletion_protection,
        },
        unknown_values={"settings": [unknown_settings]} if unknown_settings is not None else {},
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
            "replication": [
                {
                    "auto": [
                        {
                            "customer_managed_encryption": [
                                {
                                    "kms_key_name": (
                                        "projects/tfstride-demo/locations/global/keyRings/app/"
                                        "cryptoKeys/tfstride-secret-manager"
                                    )
                                }
                            ]
                        }
                    ]
                }
            ],
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
            "rotation_period": "7776000s",
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
