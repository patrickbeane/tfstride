from __future__ import annotations

import unittest

from tfstride.models import NormalizedResource, ResourceCategory, SecurityGroupRule
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_decorator import GcpResourceDecorator

_POLICY_REFERENCE = "google_compute_firewall_policy.org.name"


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
        GcpResourceMetadata.FIREWALL_POLICY_REFERENCE.key: policy_reference,
        GcpResourceMetadata.FIREWALL_POLICY_ACTION.key: action,
        GcpResourceMetadata.FIREWALL_POLICY_DIRECTION.key: direction,
    }
    if disabled:
        metadata[GcpResourceMetadata.FIREWALL_POLICY_DISABLED.key] = True
    if target_service_accounts is not None:
        metadata[GcpResourceMetadata.FIREWALL_POLICY_TARGET_SERVICE_ACCOUNTS.key] = target_service_accounts
    if target_resources is not None:
        metadata[GcpResourceMetadata.FIREWALL_POLICY_TARGET_RESOURCES.key] = target_resources

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
            GcpResourceMetadata.FIREWALL_POLICY_REFERENCE.key: policy_reference,
            GcpResourceMetadata.FIREWALL_POLICY_ATTACHMENT_TARGET.key: target,
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
        metadata[GcpResourceMetadata.FOLDER_ID.key] = folder_id
    if organization_id is not None:
        metadata[GcpResourceMetadata.ORGANIZATION_ID.key] = organization_id
    if project is not None:
        metadata[GcpResourceMetadata.PROJECT.key] = project
    if service_account_email is not None:
        metadata[GcpResourceMetadata.SERVICE_ACCOUNTS.key] = [{"email": service_account_email}]

    return _gcp_resource(
        address,
        "google_compute_instance",
        ResourceCategory.COMPUTE,
        vpc_id="google_compute_network.main.id",
        public_access_configured=public_access_configured,
        metadata=metadata,
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


if __name__ == "__main__":
    unittest.main()