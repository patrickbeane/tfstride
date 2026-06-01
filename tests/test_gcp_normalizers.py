from __future__ import annotations

import json
import unittest
from pathlib import Path

from tfstride.input.terraform_plan import load_terraform_plan
from tfstride.models import ResourceCategory, TerraformResource
from tfstride.providers.gcp.coercion import as_bool, as_list, as_optional_int, compact, first_item
from tfstride.providers.gcp.compute_normalizers import normalize_compute_instance
from tfstride.providers.gcp.data_normalizers import normalize_sql_database_instance, normalize_storage_bucket
from tfstride.providers.gcp.iam_normalizers import (
    normalize_project_iam_member,
    normalize_service_account,
    normalize_service_account_iam_binding,
    normalize_service_account_iam_member,
    normalize_service_account_iam_policy,
    normalize_service_account_key,
    normalize_storage_bucket_iam_binding,
    normalize_storage_bucket_iam_member,
    normalize_storage_bucket_iam_policy,
)
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


def _terraform_resource(
    address: str,
    resource_type: str,
    values: dict[str, object],
) -> TerraformResource:
    return TerraformResource(
        address=address,
        mode="managed",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        provider_name="registry.terraform.io/hashicorp/google",
        values=values,
    )


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

    def test_sql_database_instance_normalizer_preserves_database_posture(self) -> None:
        normalized = normalize_sql_database_instance(self.resources["google_sql_database_instance.app"])

        self.assertEqual(normalized.category, ResourceCategory.DATA)
        self.assertEqual(normalized.identifier, "tfstride-app-db")
        self.assertEqual(normalized.data_sensitivity, "sensitive")
        self.assertTrue(normalized.public_access_configured)
        self.assertTrue(normalized.public_exposure)
        self.assertTrue(normalized.direct_internet_reachable)
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.DATABASE_VERSION), "POSTGRES_15")
        self.assertFalse(normalized.get_metadata_field(GcpResourceMetadata.CLOUD_SQL_BACKUP_ENABLED))
        self.assertFalse(
            normalized.get_metadata_field(GcpResourceMetadata.CLOUD_SQL_POINT_IN_TIME_RECOVERY_ENABLED)
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.CLOUD_SQL_AUTHORIZED_NETWORKS),
            [{"name": "anywhere", "value": "0.0.0.0/0"}],
        )
        self.assertEqual(
            normalized.public_exposure_reasons,
            ["authorized network `anywhere` allows 0.0.0.0/0"],
        )

    def test_sql_database_instance_normalizer_handles_private_backed_up_instance(self) -> None:
        normalized = normalize_sql_database_instance(
            _terraform_resource(
                "google_sql_database_instance.private",
                "google_sql_database_instance",
                {
                    "name": "private-db",
                    "database_version": "MYSQL_8_0",
                    "settings": [
                        {
                            "backup_configuration": [
                                {
                                    "enabled": True,
                                    "point_in_time_recovery_enabled": True,
                                }
                            ],
                            "ip_configuration": [
                                {
                                    "ipv4_enabled": False,
                                    "private_network": "google_compute_network.main.id",
                                    "authorized_networks": [],
                                }
                            ],
                        }
                    ],
                },
            )
        )

        self.assertEqual(normalized.vpc_id, "google_compute_network.main.id")
        self.assertFalse(normalized.public_access_configured)
        self.assertFalse(normalized.public_exposure)
        self.assertFalse(normalized.direct_internet_reachable)
        self.assertTrue(normalized.get_metadata_field(GcpResourceMetadata.CLOUD_SQL_BACKUP_ENABLED))
        self.assertTrue(
            normalized.get_metadata_field(GcpResourceMetadata.CLOUD_SQL_POINT_IN_TIME_RECOVERY_ENABLED)
        )

    def test_service_account_normalizer_preserves_identity_context(self) -> None:
        normalized = normalize_service_account(self.resources["google_service_account.web"])

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(normalized.identifier, "tfstride-web@example.iam.gserviceaccount.com")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.PROJECT), "tfstride-demo")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_ACCOUNT_ID), "tfstride-web")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_EMAIL),
            "tfstride-web@example.iam.gserviceaccount.com",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_MEMBER),
            "serviceAccount:tfstride-web@example.iam.gserviceaccount.com",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_UNIQUE_ID),
            "100000000000000000001",
        )
        self.assertFalse(normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_DISABLED))

    def test_service_account_key_normalizer_preserves_key_context_without_secret_material(self) -> None:
        normalized = normalize_service_account_key(self.resources["google_service_account_key.web"])

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_REFERENCE),
            "google_service_account.web.email",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_KEY_ALGORITHM),
            "KEY_ALG_RSA_2048",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_PUBLIC_KEY_TYPE),
            "TYPE_X509_PEM_FILE",
        )
        metadata = normalized.metadata_snapshot()
        self.assertEqual(metadata["valid_after"], "2026-01-01T00:00:00Z")
        self.assertEqual(metadata["valid_before"], "2027-01-01T00:00:00Z")
        self.assertNotIn("private_key", metadata)

    def test_service_account_iam_member_normalizer_preserves_binding_parts(self) -> None:
        normalized = normalize_service_account_iam_member(
            _terraform_resource(
                "google_service_account_iam_member.web_token_creator",
                "google_service_account_iam_member",
                {
                    "service_account_id": "google_service_account.web.name",
                    "role": "roles/iam.serviceAccountTokenCreator",
                    "member": "group:deploy@example.com",
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(
            normalized.identifier,
            "google_service_account.web.name:roles/iam.serviceAccountTokenCreator:group:deploy@example.com",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_REFERENCE),
            "google_service_account.web.name",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [{"role": "roles/iam.serviceAccountTokenCreator", "members": ["group:deploy@example.com"]}],
        )

    def test_service_account_iam_binding_normalizer_preserves_member_list(self) -> None:
        normalized = normalize_service_account_iam_binding(
            _terraform_resource(
                "google_service_account_iam_binding.web_users",
                "google_service_account_iam_binding",
                {
                    "service_account_id": "google_service_account.web.name",
                    "role": "roles/iam.serviceAccountUser",
                    "members": ["group:deploy@example.com", "user:alice@example.com"],
                },
            )
        )

        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_MEMBERS),
            ["group:deploy@example.com", "user:alice@example.com"],
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [
                {
                    "role": "roles/iam.serviceAccountUser",
                    "members": ["group:deploy@example.com", "user:alice@example.com"],
                }
            ],
        )

    def test_service_account_iam_policy_normalizer_parses_policy_bindings(self) -> None:
        normalized = normalize_service_account_iam_policy(
            _terraform_resource(
                "google_service_account_iam_policy.web_policy",
                "google_service_account_iam_policy",
                {
                    "service_account_id": "google_service_account.web.name",
                    "policy_data": json.dumps(
                        {
                            "bindings": [
                                {
                                    "role": "roles/iam.serviceAccountUser",
                                    "members": ["group:deploy@example.com"],
                                }
                            ]
                        }
                    ),
                },
            )
        )

        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_REFERENCE),
            "google_service_account.web.name",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [{"role": "roles/iam.serviceAccountUser", "members": ["group:deploy@example.com"]}],
        )

    def test_storage_bucket_iam_member_normalizer_preserves_binding_parts(self) -> None:
        normalized = normalize_storage_bucket_iam_member(
            _terraform_resource(
                "google_storage_bucket_iam_member.public_logs_reader",
                "google_storage_bucket_iam_member",
                {
                    "bucket": "google_storage_bucket.logs.name",
                    "role": "roles/storage.objectViewer",
                    "member": "allUsers",
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(
            normalized.identifier,
            "google_storage_bucket.logs.name:roles/storage.objectViewer:allUsers",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.BUCKET_NAME),
            "google_storage_bucket.logs.name",
        )
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.IAM_ROLE), "roles/storage.objectViewer")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.IAM_MEMBER), "allUsers")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.IAM_MEMBERS), ["allUsers"])
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}],
        )

    def test_storage_bucket_iam_binding_normalizer_preserves_member_list(self) -> None:
        normalized = normalize_storage_bucket_iam_binding(
            _terraform_resource(
                "google_storage_bucket_iam_binding.logs_readers",
                "google_storage_bucket_iam_binding",
                {
                    "bucket": "tfstride-logs",
                    "role": "roles/storage.objectViewer",
                    "members": ["allUsers", "group:ops@example.com"],
                },
            )
        )

        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.BUCKET_NAME), "tfstride-logs")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_MEMBERS),
            ["allUsers", "group:ops@example.com"],
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [
                {
                    "role": "roles/storage.objectViewer",
                    "members": ["allUsers", "group:ops@example.com"],
                }
            ],
        )

    def test_storage_bucket_iam_policy_normalizer_parses_policy_bindings(self) -> None:
        normalized = normalize_storage_bucket_iam_policy(
            _terraform_resource(
                "google_storage_bucket_iam_policy.logs_policy",
                "google_storage_bucket_iam_policy",
                {
                    "bucket": "tfstride-logs",
                    "policy_data": json.dumps(
                        {
                            "bindings": [
                                {
                                    "role": "roles/storage.objectViewer",
                                    "members": ["allUsers"],
                                }
                            ]
                        }
                    ),
                },
            )
        )

        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}],
        )

    def test_normalizer_derives_public_bucket_exposure_from_bucket_iam_member(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _terraform_resource(
                    "google_storage_bucket.logs",
                    "google_storage_bucket",
                    {"name": "tfstride-logs", "location": "US"},
                ),
                _terraform_resource(
                    "google_storage_bucket_iam_member.public_logs_reader",
                    "google_storage_bucket_iam_member",
                    {
                        "bucket": "google_storage_bucket.logs.name",
                        "role": "roles/storage.objectViewer",
                        "member": "allUsers",
                    },
                ),
            ]
        )
        bucket = inventory.get_by_address("google_storage_bucket.logs")

        self.assertIsNotNone(bucket)
        assert bucket is not None
        self.assertTrue(bucket.public_access_configured)
        self.assertTrue(bucket.public_exposure)
        self.assertTrue(bucket.direct_internet_reachable)
        self.assertEqual(
            bucket.public_exposure_reasons,
            [
                "google_storage_bucket_iam_member.public_logs_reader grants "
                "roles/storage.objectViewer to allUsers"
            ],
        )

    def test_public_access_prevention_suppresses_public_bucket_exposure(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _terraform_resource(
                    "google_storage_bucket.logs",
                    "google_storage_bucket",
                    {
                        "name": "tfstride-logs",
                        "location": "US",
                        "public_access_prevention": "enforced",
                    },
                ),
                _terraform_resource(
                    "google_storage_bucket_iam_member.public_logs_reader",
                    "google_storage_bucket_iam_member",
                    {
                        "bucket": "tfstride-logs",
                        "role": "roles/storage.objectViewer",
                        "member": "allUsers",
                    },
                ),
            ]
        )
        bucket = inventory.get_by_address("google_storage_bucket.logs")

        self.assertIsNotNone(bucket)
        assert bucket is not None
        self.assertTrue(bucket.public_access_configured)
        self.assertFalse(bucket.public_exposure)
        self.assertFalse(bucket.direct_internet_reachable)
        self.assertEqual(bucket.public_exposure_reasons, [])

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
        self.assertEqual(
            instance.get_metadata_field(GcpResourceMetadata.INTERNET_INGRESS_FIREWALLS),
            ["google_compute_firewall.public_ssh"],
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