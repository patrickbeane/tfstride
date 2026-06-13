from __future__ import annotations

import unittest

from tfstride.models import NormalizedResource, ResourceCategory, SecurityGroupRule
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_decorator import GcpResourceDecorator
from tfstride.providers.gcp.resource_types import GcpResourceType

_POLICY_REFERENCE = "google_compute_firewall_policy.org.name"


def _gcp_resource(
    address: str,
    resource_type: str,
    category: ResourceCategory,
    *,
    name: str | None = None,
    identifier: str | None = None,
    vpc_id: str | None = None,
    subnet_ids: tuple[str, ...] = (),
    public_access_configured: bool = False,
    network_rules: list[SecurityGroupRule] | None = None,
    metadata: dict[str, object] | None = None,
) -> NormalizedResource:
    return NormalizedResource(
        address=address,
        provider="gcp",
        resource_type=resource_type,
        name=name or address.rsplit(".", 1)[-1],
        category=category,
        identifier=identifier,
        vpc_id=vpc_id,
        subnet_ids=subnet_ids,
        public_access_configured=public_access_configured,
        network_rules=network_rules or [],
        metadata=metadata,
    )


def _policy_rule(
    address: str = "google_compute_firewall_policy_rule.public_admin",
    *,
    policy_reference: str = _POLICY_REFERENCE,
    action: str = "allow",
    direction: str = "ingress",
    ports: tuple[int, ...] = (22,),
    cidr_blocks: tuple[str, ...] = ("0.0.0.0/0",),
    disabled: bool = False,
    target_service_accounts: list[str] | None = None,
    target_resources: list[str] | None = None,
) -> NormalizedResource:
    metadata: dict[str, object] = {
        GcpResourceMetadata.FIREWALL_POLICY_REFERENCE: policy_reference,
        GcpResourceMetadata.FIREWALL_POLICY_ACTION: action,
        GcpResourceMetadata.FIREWALL_POLICY_DIRECTION: direction,
    }
    if disabled:
        metadata[GcpResourceMetadata.FIREWALL_POLICY_DISABLED] = True
    if target_service_accounts is not None:
        metadata[GcpResourceMetadata.FIREWALL_POLICY_TARGET_SERVICE_ACCOUNTS] = target_service_accounts
    if target_resources is not None:
        metadata[GcpResourceMetadata.FIREWALL_POLICY_TARGET_RESOURCES] = target_resources

    return _gcp_resource(
        address,
        "google_compute_firewall_policy_rule",
        ResourceCategory.NETWORK,
        network_rules=[
            SecurityGroupRule(
                direction=direction,
                protocol="tcp",
                from_port=port,
                to_port=port,
                cidr_blocks=list(cidr_blocks),
            )
            for port in ports
        ],
        metadata=metadata,
    )


def _policy_association(
    address: str,
    *,
    target: str,
    policy_reference: str = _POLICY_REFERENCE,
) -> NormalizedResource:
    return _gcp_resource(
        address,
        "google_compute_firewall_policy_association",
        ResourceCategory.NETWORK,
        metadata={
            GcpResourceMetadata.FIREWALL_POLICY_REFERENCE: policy_reference,
            GcpResourceMetadata.FIREWALL_POLICY_ATTACHMENT_TARGET: target,
        },
    )


def _instance(
    address: str = "google_compute_instance.web",
    *,
    folder_id: str | None = None,
    organization_id: str | None = None,
    project: str | None = None,
    service_account_email: str | None = None,
    public_access_configured: bool = True,
) -> NormalizedResource:
    metadata: dict[str, object] = {}
    if folder_id is not None:
        metadata[GcpResourceMetadata.FOLDER_ID] = folder_id
    if organization_id is not None:
        metadata[GcpResourceMetadata.ORGANIZATION_ID] = organization_id
    if project is not None:
        metadata[GcpResourceMetadata.PROJECT] = project
    if service_account_email is not None:
        metadata[GcpResourceMetadata.SERVICE_ACCOUNTS] = [{"email": service_account_email}]

    return _gcp_resource(
        address,
        "google_compute_instance",
        ResourceCategory.COMPUTE,
        vpc_id="google_compute_network.main.id",
        public_access_configured=public_access_configured,
        metadata=metadata,
    )


def _network() -> NormalizedResource:
    return _gcp_resource(
        "google_compute_network.main",
        GcpResourceType.COMPUTE_NETWORK,
        ResourceCategory.NETWORK,
        identifier="projects/demo/global/networks/main",
        metadata={
            GcpResourceMetadata.NAME: "main",
            GcpResourceMetadata.SELF_LINK: "projects/demo/global/networks/main",
        },
    )


def _subnetwork() -> NormalizedResource:
    return _gcp_resource(
        "google_compute_subnetwork.app",
        GcpResourceType.COMPUTE_SUBNETWORK,
        ResourceCategory.NETWORK,
        identifier="projects/demo/regions/us-central1/subnetworks/app",
        vpc_id="google_compute_network.main.id",
        metadata={
            GcpResourceMetadata.NAME: "app",
            GcpResourceMetadata.SELF_LINK: "projects/demo/regions/us-central1/subnetworks/app",
        },
    )


def _public_default_route() -> NormalizedResource:
    return _gcp_resource(
        "google_compute_route.default_internet",
        GcpResourceType.COMPUTE_ROUTE,
        ResourceCategory.NETWORK,
        vpc_id="google_compute_network.main.id",
        metadata={
            GcpResourceMetadata.ROUTE_DEST_RANGE: "0.0.0.0/0",
            GcpResourceMetadata.ROUTE_NEXT_HOP_GATEWAY: "default-internet-gateway",
        },
    )


def _router() -> NormalizedResource:
    return _gcp_resource(
        "google_compute_router.main",
        GcpResourceType.COMPUTE_ROUTER,
        ResourceCategory.NETWORK,
        vpc_id="google_compute_network.main.id",
        metadata={GcpResourceMetadata.NAME: "main"},
    )


def _router_nat() -> NormalizedResource:
    return _gcp_resource(
        "google_compute_router_nat.main",
        GcpResourceType.COMPUTE_ROUTER_NAT,
        ResourceCategory.NETWORK,
        metadata={
            "source_subnetwork_ip_ranges_to_nat": "ALL_SUBNETWORKS_ALL_IP_RANGES",
            GcpResourceMetadata.ROUTER_REFERENCE: "google_compute_router.main.name",
        },
    )


def _serverless_workload(
    address: str,
    resource_type: str,
    reference_field: object,
    reference: str,
) -> NormalizedResource:
    return _gcp_resource(
        address,
        resource_type,
        ResourceCategory.COMPUTE,
        identifier=reference,
        public_access_configured=True,
        metadata={
            GcpResourceMetadata.NAME: address.rsplit(".", 1)[-1],
            reference_field: reference,
        },
    )


def _iam_member(
    address: str,
    resource_type: str,
    target_field: object,
    target_reference: str,
    *,
    role: str,
    member: str,
) -> NormalizedResource:
    return _gcp_resource(
        address,
        resource_type,
        ResourceCategory.IAM,
        metadata={
            target_field: target_reference,
            GcpResourceMetadata.IAM_ROLE: role,
            GcpResourceMetadata.IAM_MEMBER: member,
        },
    )


class GcpResourceDecoratorTests(unittest.TestCase):
    def test_firewall_policy_folder_association_matches_public_ssh_and_rdp(self) -> None:
        policy_rule = _policy_rule(ports=(22, 3389))
        association = _policy_association(
            "google_compute_firewall_policy_association.folder",
            target="folders/12345",
        )
        instance = _instance(folder_id="folders/12345")

        GcpResourceDecorator().decorate([policy_rule, association, instance])

        self.assertTrue(instance.internet_ingress_capable)
        self.assertEqual(
            instance.internet_ingress_reasons,
            [
                "google_compute_firewall_policy_rule.public_admin ingress tcp 22 from 0.0.0.0/0",
                "google_compute_firewall_policy_rule.public_admin ingress tcp 3389 from 0.0.0.0/0",
            ],
        )
        self.assertEqual(
            instance.get_metadata_field(GcpResourceMetadata.INTERNET_INGRESS_FIREWALLS),
            ["google_compute_firewall_policy_rule.public_admin"],
        )
        self.assertTrue(instance.public_exposure)

    def test_firewall_policy_organization_association_matches_resource_organization_metadata(self) -> None:
        policy_rule = _policy_rule()
        association = _policy_association(
            "google_compute_firewall_policy_association.organization",
            target="organizations/1234567890",
        )
        instance = _instance(organization_id="1234567890")

        GcpResourceDecorator().decorate([policy_rule, association, instance])

        self.assertTrue(instance.internet_ingress_capable)
        self.assertEqual(
            instance.internet_ingress_reasons,
            ["google_compute_firewall_policy_rule.public_admin ingress tcp 22 from 0.0.0.0/0"],
        )
        self.assertTrue(instance.public_exposure)

    def test_firewall_policy_target_service_accounts_limit_compute_matches(self) -> None:
        policy_rule = _policy_rule(
            target_service_accounts=["tfstride-web@tfstride-demo.iam.gserviceaccount.com"]
        )
        association = _policy_association(
            "google_compute_firewall_policy_association.folder",
            target="folders/12345",
        )
        matching_instance = _instance(
            "google_compute_instance.web",
            folder_id="folders/12345",
            service_account_email="tfstride-web@tfstride-demo.iam.gserviceaccount.com",
        )
        unmatched_instance = _instance(
            "google_compute_instance.worker",
            folder_id="folders/12345",
            service_account_email="worker@tfstride-demo.iam.gserviceaccount.com",
        )

        GcpResourceDecorator().decorate([policy_rule, association, matching_instance, unmatched_instance])

        self.assertTrue(matching_instance.internet_ingress_capable)
        self.assertEqual(
            matching_instance.get_metadata_field(GcpResourceMetadata.INTERNET_INGRESS_FIREWALLS),
            ["google_compute_firewall_policy_rule.public_admin"],
        )
        self.assertFalse(unmatched_instance.internet_ingress_capable)
        self.assertEqual(unmatched_instance.internet_ingress_reasons, [])
        self.assertFalse(unmatched_instance.public_exposure)

    def test_firewall_policy_ignored_rules_do_not_create_public_compute_exposure(self) -> None:
        disabled_rule = _policy_rule(
            "google_compute_firewall_policy_rule.disabled_admin",
            disabled=True,
        )
        egress_rule = _policy_rule(
            "google_compute_firewall_policy_rule.egress_admin",
            direction="egress",
        )
        internal_rule = _policy_rule(
            "google_compute_firewall_policy_rule.internal_admin",
            cidr_blocks=("10.10.0.0/16",),
        )
        association = _policy_association(
            "google_compute_firewall_policy_association.folder",
            target="folders/12345",
        )
        instance = _instance(folder_id="folders/12345")

        GcpResourceDecorator().decorate([disabled_rule, egress_rule, internal_rule, association, instance])

        self.assertFalse(instance.internet_ingress_capable)
        self.assertEqual(instance.internet_ingress_reasons, [])
        self.assertEqual(instance.get_metadata_field(GcpResourceMetadata.INTERNET_INGRESS_FIREWALLS), [])
        self.assertFalse(instance.public_exposure)

    def test_route_and_router_nat_decoration_marks_subnet_and_instance_posture(self) -> None:
        network = _network()
        subnetwork = _subnetwork()
        route = _public_default_route()
        router = _router()
        router_nat = _router_nat()
        instance = _gcp_resource(
            "google_compute_instance.app",
            GcpResourceType.COMPUTE_INSTANCE,
            ResourceCategory.COMPUTE,
            subnet_ids=("google_compute_subnetwork.app.id",),
            metadata={
                GcpResourceMetadata.NETWORK_INTERFACES: [
                    {
                        "network": "google_compute_network.main.id",
                        "subnetwork": "google_compute_subnetwork.app.id",
                    }
                ]
            },
        )

        GcpResourceDecorator().decorate([network, subnetwork, route, router, router_nat, instance])

        self.assertTrue(subnetwork.is_public_subnet)
        self.assertTrue(subnetwork.has_public_route)
        self.assertTrue(subnetwork.has_nat_gateway_egress)
        self.assertEqual(instance.vpc_id, "google_compute_network.main.id")
        self.assertTrue(instance.in_public_subnet)
        self.assertTrue(instance.has_public_route)
        self.assertTrue(instance.has_nat_gateway_egress)

    def test_public_load_balancer_traversal_marks_reachable_backend_chain(self) -> None:
        forwarding_rule = _gcp_resource(
            "google_compute_global_forwarding_rule.web",
            GcpResourceType.COMPUTE_GLOBAL_FORWARDING_RULE,
            ResourceCategory.EDGE,
            public_access_configured=True,
            metadata={
                GcpResourceMetadata.FORWARDING_RULE_TARGET: (
                    "google_compute_target_https_proxy.web.id"
                ),
                GcpResourceMetadata.FORWARDING_RULE_LOAD_BALANCING_SCHEME: "EXTERNAL",
                GcpResourceMetadata.FORWARDING_RULE_IP_ADDRESS: "35.1.2.3",
                GcpResourceMetadata.FORWARDING_RULE_PORTS: ["443"],
            },
        )
        target_proxy = _gcp_resource(
            "google_compute_target_https_proxy.web",
            GcpResourceType.COMPUTE_TARGET_HTTPS_PROXY,
            ResourceCategory.EDGE,
            metadata={GcpResourceMetadata.LOAD_BALANCER_URL_MAP: "google_compute_url_map.web.id"},
        )
        url_map = _gcp_resource(
            "google_compute_url_map.web",
            GcpResourceType.COMPUTE_URL_MAP,
            ResourceCategory.EDGE,
            metadata={
                GcpResourceMetadata.LOAD_BALANCER_DEFAULT_SERVICE: (
                    "google_compute_backend_service.api.id"
                )
            },
        )
        backend_service = _gcp_resource(
            "google_compute_backend_service.api",
            GcpResourceType.COMPUTE_BACKEND_SERVICE,
            ResourceCategory.EDGE,
            metadata={
                GcpResourceMetadata.LOAD_BALANCER_BACKENDS: [
                    {"group": "google_compute_network_endpoint_group.api.id"}
                ]
            },
        )
        network_endpoint_group = _gcp_resource(
            "google_compute_network_endpoint_group.api",
            GcpResourceType.COMPUTE_NETWORK_ENDPOINT_GROUP,
            ResourceCategory.EDGE,
            metadata={
                GcpResourceMetadata.LOAD_BALANCER_SERVERLESS_ENDPOINTS: [
                    {"platform": "cloud_run", "service": "google_cloud_run_service.api.name"}
                ]
            },
        )
        cloud_run = _serverless_workload(
            "google_cloud_run_service.api",
            GcpResourceType.CLOUD_RUN_SERVICE,
            GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE,
            "projects/demo/locations/us-central1/services/api",
        )

        GcpResourceDecorator().decorate([
            forwarding_rule,
            target_proxy,
            url_map,
            backend_service,
            network_endpoint_group,
            cloud_run,
        ])

        self.assertTrue(
            backend_service.get_metadata_field(
                GcpResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER
            )
        )
        self.assertTrue(
            network_endpoint_group.get_metadata_field(
                GcpResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER
            )
        )
        self.assertTrue(
            cloud_run.get_metadata_field(
                GcpResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER
            )
        )
        self.assertEqual(
            cloud_run.get_metadata_field(
                GcpResourceMetadata.INTERNET_FACING_LOAD_BALANCER_ADDRESSES
            ),
            ["google_compute_global_forwarding_rule.web"],
        )
        self.assertEqual(
            [
                entry["backend"]
                for entry in forwarding_rule.get_metadata_field(
                    GcpResourceMetadata.LOAD_BALANCER_REACHABLE_BACKENDS
                )
            ],
            [
                "google_compute_backend_service.api",
                "google_compute_network_endpoint_group.api",
                "google_cloud_run_service.api",
            ],
        )
        self.assertEqual(
            cloud_run.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_FRONTENDS)[0]["path"],
            [
                "google_compute_global_forwarding_rule.web",
                "google_compute_target_https_proxy.web",
                "google_compute_url_map.web",
                "google_compute_backend_service.api",
                "google_compute_network_endpoint_group.api",
                "google_cloud_run_service.api",
            ],
        )

    def test_public_gcs_iam_binding_respects_public_access_prevention(self) -> None:
        bucket = _gcp_resource(
            "google_storage_bucket.logs",
            GcpResourceType.STORAGE_BUCKET,
            ResourceCategory.DATA,
            identifier="logs",
            metadata={
                GcpResourceMetadata.BUCKET_NAME: "logs",
                GcpResourceMetadata.PUBLIC_ACCESS_PREVENTION: "enforced",
            },
        )
        iam_member = _iam_member(
            "google_storage_bucket_iam_member.public_reader",
            GcpResourceType.STORAGE_BUCKET_IAM_MEMBER,
            GcpResourceMetadata.BUCKET_NAME,
            "logs",
            role="roles/storage.objectViewer",
            member="allUsers",
        )

        GcpResourceDecorator().decorate([bucket, iam_member])

        self.assertTrue(bucket.public_access_configured)
        self.assertEqual(
            bucket.public_access_reasons,
            [
                "google_storage_bucket_iam_member.public_reader grants "
                "roles/storage.objectViewer to allUsers"
            ],
        )
        self.assertFalse(bucket.public_exposure)
        self.assertEqual(bucket.public_exposure_reasons, [])

    def test_public_serverless_invoker_bindings_mark_cloud_run_and_functions_exposure(self) -> None:
        cloud_run = _serverless_workload(
            "google_cloud_run_service.api",
            GcpResourceType.CLOUD_RUN_SERVICE,
            GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE,
            "projects/demo/locations/us-central1/services/api",
        )
        cloud_run_iam = _iam_member(
            "google_cloud_run_service_iam_member.public_invoker",
            GcpResourceType.CLOUD_RUN_SERVICE_IAM_MEMBER,
            GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE,
            "projects/demo/locations/us-central1/services/api",
            role="roles/run.invoker",
            member="allUsers",
        )
        function = _serverless_workload(
            "google_cloudfunctions_function.worker",
            GcpResourceType.CLOUDFUNCTIONS_FUNCTION,
            GcpResourceMetadata.CLOUD_FUNCTION_REFERENCE,
            "projects/demo/locations/us-central1/functions/worker",
        )
        function_iam = _iam_member(
            "google_cloudfunctions_function_iam_member.public_invoker",
            GcpResourceType.CLOUDFUNCTIONS_FUNCTION_IAM_MEMBER,
            GcpResourceMetadata.CLOUD_FUNCTION_REFERENCE,
            "projects/demo/locations/us-central1/functions/worker",
            role="roles/cloudfunctions.invoker",
            member="allAuthenticatedUsers",
        )

        GcpResourceDecorator().decorate([cloud_run, cloud_run_iam, function, function_iam])

        self.assertTrue(cloud_run.public_exposure)
        self.assertEqual(
            cloud_run.public_exposure_reasons,
            [
                "google_cloud_run_service_iam_member.public_invoker grants "
                "roles/run.invoker to allUsers"
            ],
        )
        self.assertTrue(function.public_exposure)
        self.assertEqual(
            function.public_exposure_reasons,
            [
                "google_cloudfunctions_function_iam_member.public_invoker grants "
                "roles/cloudfunctions.invoker to allAuthenticatedUsers"
            ],
        )

    def test_sensitive_resource_iam_bindings_are_attached_to_target_resource(self) -> None:
        secret = _gcp_resource(
            "google_secret_manager_secret.api_key",
            GcpResourceType.SECRET_MANAGER_SECRET,
            ResourceCategory.DATA,
            identifier="projects/demo/secrets/api-key",
            metadata={
                GcpResourceMetadata.SECRET_ID: "api-key",
                GcpResourceMetadata.SECRET_REFERENCE: "projects/demo/secrets/api-key",
            },
        )
        iam_member = _iam_member(
            "google_secret_manager_secret_iam_member.reader",
            GcpResourceType.SECRET_MANAGER_SECRET_IAM_MEMBER,
            GcpResourceMetadata.SECRET_REFERENCE,
            "projects/demo/secrets/api-key",
            role="roles/secretmanager.secretAccessor",
            member="serviceAccount:app@demo.iam.gserviceaccount.com",
        )

        GcpResourceDecorator().decorate([secret, iam_member])

        self.assertEqual(
            secret.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [
                {
                    "role": "roles/secretmanager.secretAccessor",
                    "members": ["serviceAccount:app@demo.iam.gserviceaccount.com"],
                    "source": "google_secret_manager_secret_iam_member.reader",
                }
            ],
        )
        self.assertEqual(
            secret.get_metadata_field(GcpResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES),
            ["google_secret_manager_secret_iam_member.reader"],
        )


if __name__ == "__main__":
    unittest.main()