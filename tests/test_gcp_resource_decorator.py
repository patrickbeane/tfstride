from __future__ import annotations

import unittest

from tfstride.models import NormalizedResource, ResourceCategory, SecurityGroupRule
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_decorator import GcpResourceDecorator


def _gcp_resource(
    address: str,
    resource_type: str,
    category: ResourceCategory,
    *,
    name: str | None = None,
    identifier: str | None = None,
    vpc_id: str | None = None,
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
        public_access_configured=public_access_configured,
        network_rules=network_rules or [],
        metadata=metadata,
    )


class GcpResourceDecoratorTests(unittest.TestCase):
    def test_firewall_policy_folder_association_matches_resource_folder_metadata(self) -> None:
        network = _gcp_resource(
            "google_compute_network.main",
            "google_compute_network",
            ResourceCategory.NETWORK,
            identifier="tfstride-main",
            metadata={GcpResourceMetadata.NAME.key: "tfstride-main"},
        )
        policy_rule = _gcp_resource(
            "google_compute_firewall_policy_rule.public_admin",
            "google_compute_firewall_policy_rule",
            ResourceCategory.NETWORK,
            network_rules=[
                SecurityGroupRule(
                    direction="ingress",
                    protocol="tcp",
                    from_port=22,
                    to_port=22,
                    cidr_blocks=["0.0.0.0/0"],
                )
            ],
            metadata={
                GcpResourceMetadata.FIREWALL_POLICY_REFERENCE.key: "google_compute_firewall_policy.org.name",
                GcpResourceMetadata.FIREWALL_POLICY_ACTION.key: "allow",
                GcpResourceMetadata.FIREWALL_POLICY_DIRECTION.key: "ingress",
            },
        )
        association = _gcp_resource(
            "google_compute_firewall_policy_association.folder",
            "google_compute_firewall_policy_association",
            ResourceCategory.NETWORK,
            metadata={
                GcpResourceMetadata.FIREWALL_POLICY_REFERENCE.key: "google_compute_firewall_policy.org.name",
                GcpResourceMetadata.FIREWALL_POLICY_ATTACHMENT_TARGET.key: "folders/12345",
            },
        )
        instance = _gcp_resource(
            "google_compute_instance.web",
            "google_compute_instance",
            ResourceCategory.COMPUTE,
            vpc_id="google_compute_network.main.id",
            public_access_configured=True,
            metadata={GcpResourceMetadata.FOLDER_ID.key: "folders/12345"},
        )

        GcpResourceDecorator().decorate([network, policy_rule, association, instance])

        self.assertTrue(instance.internet_ingress_capable)
        self.assertEqual(
            instance.internet_ingress_reasons,
            ["google_compute_firewall_policy_rule.public_admin ingress tcp 22 from 0.0.0.0/0"],
        )
        self.assertEqual(
            instance.get_metadata_field(GcpResourceMetadata.INTERNET_INGRESS_FIREWALLS),
            ["google_compute_firewall_policy_rule.public_admin"],
        )
        self.assertTrue(instance.public_exposure)


if __name__ == "__main__":
    unittest.main()