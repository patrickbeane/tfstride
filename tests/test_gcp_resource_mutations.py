from __future__ import annotations

import unittest

from tfstride.models import NormalizedResource, ResourceCategory
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_mutations import GcpResourceMutations, gcp_mutations


def _resource(
    *,
    resource_type: str = "google_compute_instance",
    metadata: dict[str, object] | None = None,
    vpc_id: str | None = None,
    public_access_configured: bool = False,
) -> NormalizedResource:
    return NormalizedResource(
        address=f"{resource_type}.app",
        provider="gcp",
        resource_type=resource_type,
        name="app",
        category=ResourceCategory.COMPUTE,
        metadata=metadata,
        vpc_id=vpc_id,
        public_access_configured=public_access_configured,
    )


class GcpResourceMutationsTests(unittest.TestCase):
    def test_vpc_inference_sets_only_missing_vpc_ids(self) -> None:
        resource = _resource()
        mutations = gcp_mutations(resource)

        self.assertIsInstance(mutations, GcpResourceMutations)
        self.assertFalse(mutations.infer_vpc_id(None))
        self.assertTrue(mutations.infer_vpc_id("google_compute_network.main.id"))
        self.assertFalse(mutations.infer_vpc_id("google_compute_network.edge.id"))
        self.assertEqual(resource.vpc_id, "google_compute_network.main.id")

        existing = _resource(vpc_id="google_compute_network.existing.id")
        self.assertFalse(gcp_mutations(existing).infer_vpc_id("google_compute_network.main.id"))
        self.assertEqual(existing.vpc_id, "google_compute_network.existing.id")

    def test_route_posture_writes_normalized_network_flags(self) -> None:
        subnetwork = _resource(resource_type="google_compute_subnetwork")
        instance = _resource()

        gcp_mutations(subnetwork).set_subnetwork_route_posture(
            has_public_route=True,
            has_nat_gateway_egress=False,
        )
        gcp_mutations(instance).set_instance_network_posture(
            in_public_subnet=True,
            has_nat_gateway_egress=True,
            has_public_route=True,
        )

        self.assertTrue(subnetwork.has_public_route)
        self.assertTrue(subnetwork.is_public_subnet)
        self.assertFalse(subnetwork.has_nat_gateway_egress)
        self.assertTrue(instance.in_public_subnet)
        self.assertTrue(instance.has_nat_gateway_egress)
        self.assertTrue(instance.has_public_route)

    def test_public_posture_writes_normalized_exposure_fields(self) -> None:
        resource = _resource(public_access_configured=True)
        mutations = gcp_mutations(resource)

        mutations.set_public_endpoint_posture(
            direct_internet_reachable=False,
            internet_ingress_capable=True,
            internet_ingress_reasons=["control plane endpoint is public"],
        )
        mutations.set_compute_internet_ingress(
            internet_ingress_reasons=["google_compute_firewall.web allows tcp/22 from 0.0.0.0/0"],
            firewall_addresses=["google_compute_firewall.web"],
        )
        mutations.set_public_access(configured=True, reasons=["public IAM grant"])
        mutations.set_publicly_accessible(True)
        mutations.set_storage_encrypted(True)
        mutations.set_public_exposure(True, reasons=["public IAM grant"])

        self.assertTrue(resource.internet_ingress_capable)
        self.assertEqual(
            resource.internet_ingress_reasons,
            ["google_compute_firewall.web allows tcp/22 from 0.0.0.0/0"],
        )
        self.assertEqual(
            resource.get_metadata_field(GcpResourceMetadata.INTERNET_INGRESS_FIREWALLS),
            ["google_compute_firewall.web"],
        )
        self.assertTrue(resource.public_access_configured)
        self.assertEqual(resource.public_access_reasons, ["public IAM grant"])
        self.assertTrue(resource.publicly_accessible)
        self.assertTrue(resource.storage_encrypted)
        self.assertTrue(resource.public_exposure)
        self.assertTrue(resource.direct_internet_reachable)
        self.assertEqual(resource.public_exposure_reasons, ["public IAM grant"])

    def test_load_balancer_metadata_writes_are_deduped(self) -> None:
        resource = _resource(
            resource_type="google_compute_backend_service",
            metadata={
                GcpResourceMetadata.LOAD_BALANCER_FRONTENDS.key: [
                    {"forwarding_rule": "google_compute_global_forwarding_rule.public", "path": ["old"]}
                ],
            },
        )
        mutations = gcp_mutations(resource)
        frontend = {"forwarding_rule": "google_compute_global_forwarding_rule.public", "ip_address": "203.0.113.10"}

        mutations.append_load_balancer_frontend(frontend, ["forwarding", "backend"])
        mutations.append_load_balancer_frontend(frontend, ["forwarding", "backend"])
        mutations.mark_fronted_by_public_load_balancer(frontend)
        mutations.mark_fronted_by_public_load_balancer(frontend)
        mutations.set_load_balancer_reachable_backends(
            [
                {"backend": "google_compute_backend_service.app"},
                {"backend": "google_compute_backend_service.app"},
            ]
        )

        self.assertEqual(
            resource.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_FRONTENDS),
            [
                {"forwarding_rule": "google_compute_global_forwarding_rule.public", "path": ["old"]},
                {
                    "forwarding_rule": "google_compute_global_forwarding_rule.public",
                    "ip_address": "203.0.113.10",
                    "path": ["forwarding", "backend"],
                },
            ],
        )
        self.assertTrue(resource.get_metadata_field(GcpResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER))
        self.assertEqual(
            resource.get_metadata_field(GcpResourceMetadata.INTERNET_FACING_LOAD_BALANCER_ADDRESSES),
            ["google_compute_global_forwarding_rule.public"],
        )
        self.assertEqual(
            resource.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_REACHABLE_BACKENDS),
            [{"backend": "google_compute_backend_service.app"}],
        )

    def test_sensitive_resource_iam_metadata_writes_provider_fields(self) -> None:
        resource = _resource(resource_type="google_secret_manager_secret")

        gcp_mutations(resource).set_sensitive_resource_iam_bindings(
            bindings=[
                {
                    "role": "roles/secretmanager.secretAccessor",
                    "members": ["allUsers"],
                    "source": "google_secret_manager_secret_iam_member.public",
                }
            ],
            source_addresses=["google_secret_manager_secret_iam_member.public"],
        )

        self.assertEqual(
            resource.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [
                {
                    "role": "roles/secretmanager.secretAccessor",
                    "members": ["allUsers"],
                    "source": "google_secret_manager_secret_iam_member.public",
                }
            ],
        )
        self.assertEqual(
            resource.get_metadata_field(GcpResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES),
            ["google_secret_manager_secret_iam_member.public"],
        )


if __name__ == "__main__":
    unittest.main()