from __future__ import annotations

import unittest
from pathlib import Path

from tfstride.input.terraform_plan import load_terraform_plan
from tfstride.models import ResourceCategory
from tfstride.providers.gcp.coercion import as_bool, as_list, as_optional_int, compact, first_item
from tfstride.providers.gcp.compute_normalizers import normalize_compute_instance
from tfstride.providers.gcp.data_normalizers import normalize_storage_bucket
from tfstride.providers.gcp.iam_normalizers import normalize_project_iam_member
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.network_normalizers import (
    normalize_compute_firewall,
    normalize_compute_network,
    normalize_compute_subnetwork,
    parse_firewall_allow_rules,
)
from tfstride.providers.gcp.resource_utils import last_path_segment


FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "sample_gcp_plan.json"


def _fixture_resources_by_address():
    return {resource.address: resource for resource in load_terraform_plan(FIXTURE_PATH).resources}


class GcpCoercionTests(unittest.TestCase):
    def test_coercion_helpers_normalize_terraform_shapes(self) -> None:
        self.assertEqual(as_list(None), [])
        self.assertEqual(as_list("value"), ["value"])
        self.assertEqual(as_list(("a", "b")), ["a", "b"])
        self.assertEqual(compact(["a", None, "", [], 1]), ["a", "1"])
        self.assertTrue(as_bool("enabled"))
        self.assertFalse(as_bool("disabled"))
        self.assertEqual(as_optional_int("22"), 22)
        self.assertIsNone(as_optional_int("not-a-port"))
        self.assertEqual(first_item([{"name": "first"}]), {"name": "first"})
        self.assertIsNone(first_item(["not-a-map"]))

    def test_resource_helpers_extract_provider_identifiers(self) -> None:
        self.assertEqual(
            last_path_segment("projects/demo/global/networks/tfstride-main"),
            "tfstride-main",
        )
        self.assertIsNone(last_path_segment(""))


class GcpResourceNormalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.resources = _fixture_resources_by_address()

    def test_compute_network_normalizer_preserves_network_metadata(self) -> None:
        normalized = normalize_compute_network(self.resources["google_compute_network.main"])

        self.assertEqual(normalized.provider, "gcp")
        self.assertEqual(normalized.category, ResourceCategory.NETWORK)
        self.assertEqual(normalized.identifier, "tfstride-main")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.NAME), "tfstride-main")
        self.assertFalse(normalized.get_metadata_field(GcpResourceMetadata.AUTO_CREATE_SUBNETWORKS))
        self.assertEqual(normalized.metadata_snapshot()["routing_mode"], "REGIONAL")

    def test_compute_subnetwork_normalizer_preserves_region_and_network(self) -> None:
        normalized = normalize_compute_subnetwork(self.resources["google_compute_subnetwork.app"])

        self.assertEqual(normalized.category, ResourceCategory.NETWORK)
        self.assertEqual(normalized.vpc_id, "google_compute_network.main.id")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.REGION), "us-central1")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.CIDR_RANGE), "10.10.1.0/24")

    def test_compute_firewall_normalizer_builds_allow_rules(self) -> None:
        normalized = normalize_compute_firewall(self.resources["google_compute_firewall.public_ssh"])

        self.assertEqual(normalized.category, ResourceCategory.NETWORK)
        self.assertEqual(normalized.vpc_id, "google_compute_network.main.name")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.FIREWALL_TARGET_TAGS), ["web"])
        self.assertEqual(len(normalized.network_rules), 1)
        rule = normalized.network_rules[0]
        self.assertEqual(rule.direction, "ingress")
        self.assertEqual(rule.protocol, "tcp")
        self.assertEqual(rule.from_port, 22)
        self.assertEqual(rule.to_port, 22)
        self.assertEqual(rule.cidr_blocks, ["0.0.0.0/0"])

    def test_firewall_rule_parser_handles_port_ranges_and_all_protocols(self) -> None:
        rules = parse_firewall_allow_rules(
            {
                "direction": "EGRESS",
                "destination_ranges": ["10.0.0.0/8"],
                "allow": [
                    {"protocol": "tcp", "ports": ["443", "8000-8080"]},
                    {"protocol": "all"},
                ],
            }
        )

        self.assertEqual([(rule.protocol, rule.from_port, rule.to_port) for rule in rules], [
            ("tcp", 443, 443),
            ("tcp", 8000, 8080),
            ("-1", None, None),
        ])
        self.assertEqual(rules[0].direction, "egress")
        self.assertEqual(rules[0].cidr_blocks, ["10.0.0.0/8"])

    def test_compute_instance_normalizer_preserves_network_and_identity_context(self) -> None:
        normalized = normalize_compute_instance(self.resources["google_compute_instance.web"])

        self.assertEqual(normalized.category, ResourceCategory.COMPUTE)
        self.assertEqual(normalized.subnet_ids, ("google_compute_subnetwork.app.id",))
        self.assertTrue(normalized.public_access_configured)
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.NETWORK_TAGS), ["web"])
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.ZONE), "us-central1-a")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNTS)[0]["email"],
            "tfstride-web@example.iam.gserviceaccount.com",
        )

    def test_storage_bucket_normalizer_preserves_bucket_posture(self) -> None:
        normalized = normalize_storage_bucket(self.resources["google_storage_bucket.logs"])

        self.assertEqual(normalized.category, ResourceCategory.DATA)
        self.assertEqual(normalized.identifier, "tfstride-logs")
        self.assertEqual(normalized.data_sensitivity, "sensitive")
        self.assertTrue(normalized.get_metadata_field(GcpResourceMetadata.UNIFORM_BUCKET_LEVEL_ACCESS))
        self.assertEqual(normalized.metadata_snapshot()["location"], "US")

    def test_normalizer_derives_public_compute_exposure_from_matching_firewall(self) -> None:
        inventory = GcpNormalizer().normalize(list(self.resources.values()))
        instance = inventory.get_by_address("google_compute_instance.web")

        self.assertIsNotNone(instance)
        assert instance is not None
        self.assertEqual(instance.vpc_id, "google_compute_network.main.id")
        self.assertTrue(instance.internet_ingress_capable)
        self.assertEqual(
            instance.internet_ingress_reasons,
            ["google_compute_firewall.public_ssh ingress tcp 22 from 0.0.0.0/0"],
        )
        self.assertTrue(instance.public_exposure)
        self.assertTrue(instance.direct_internet_reachable)
        self.assertEqual(
            instance.public_exposure_reasons,
            [
                "compute instance has an external access config and matching firewall rules allow internet ingress"
            ],
        )

    def test_project_iam_member_normalizer_preserves_binding_parts(self) -> None:
        normalized = normalize_project_iam_member(self.resources["google_project_iam_member.web_viewer"])

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(normalized.identifier, "roles/viewer:serviceAccount:tfstride-web@example.iam.gserviceaccount.com")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.PROJECT), "tfstride-demo")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.IAM_ROLE), "roles/viewer")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_MEMBER),
            "serviceAccount:tfstride-web@example.iam.gserviceaccount.com",
        )


if __name__ == "__main__":
    unittest.main()