from __future__ import annotations

from tfstride.models import TerraformResource


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
            "project": "tfstride-demo",
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
        "private_cluster_config": [
            {"enable_private_endpoint": private_endpoint, "enable_private_nodes": private_endpoint}
        ],
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
