from __future__ import annotations

import unittest

from tfstride.providers.coercion import dedupe
from tfstride.providers.gcp.resource_utils import (
    GCP_NETWORK_REFERENCE_SUFFIXES,
    GCP_ROLE_REFERENCE_SUFFIXES,
    binding_members,
    gcp_reference_key,
    service_account_member,
)


class GcpResourceUtilsTests(unittest.TestCase):
    def test_dedupe_preserves_order(self) -> None:
        self.assertEqual(dedupe(["a", "b", "a", "c", "b"]), ["a", "b", "c"])

    def test_binding_members_coerces_single_and_repeated_values(self) -> None:
        self.assertEqual(binding_members({"members": ["user:a", None, "", "group:b"]}), ["user:a", "group:b"])
        self.assertEqual(binding_members({"members": "allUsers"}), ["allUsers"])
        self.assertEqual(binding_members({}), [])

    def test_service_account_member_preserves_existing_prefix(self) -> None:
        self.assertEqual(
            service_account_member("worker@example.iam.gserviceaccount.com"),
            "serviceAccount:worker@example.iam.gserviceaccount.com",
        )
        self.assertEqual(
            service_account_member("serviceAccount:worker@example.iam.gserviceaccount.com"),
            "serviceAccount:worker@example.iam.gserviceaccount.com",
        )
        self.assertIsNone(service_account_member(None))

    def test_reference_key_strips_provider_specific_suffixes_from_terraform_traversals(self) -> None:
        cases = (
            (
                "google_service_account.web.email",
                None,
                "google_service_account.web",
            ),
            (
                "google_project_iam_custom_role.deploy.role_id",
                GCP_ROLE_REFERENCE_SUFFIXES,
                "google_project_iam_custom_role.deploy",
            ),
            (
                "google_compute_network.main.self_link",
                GCP_NETWORK_REFERENCE_SUFFIXES,
                "google_compute_network.main",
            ),
            (
                'module.network["primary"].google_compute_network.main.self_link',
                GCP_NETWORK_REFERENCE_SUFFIXES,
                'module.network["primary"].google_compute_network.main',
            ),
            (
                'data.google_service_account.runtime["api"].email',
                None,
                'data.google_service_account.runtime["api"]',
            ),
            (
                "${google_service_account.web.email}",
                None,
                "google_service_account.web",
            ),
            (
                "google_compute_network.name.id",
                GCP_NETWORK_REFERENCE_SUFFIXES,
                "google_compute_network.name",
            ),
        )

        for reference, suffixes, expected in cases:
            with self.subTest(reference=reference):
                actual = gcp_reference_key(reference) if suffixes is None else gcp_reference_key(reference, suffixes)
                self.assertEqual(actual, expected)

    def test_reference_key_preserves_native_suffixes_and_exact_addresses(self) -> None:
        cases = (
            ("logs.name", None),
            ("projects/demo/buckets/logs.id", None),
            ("https://storage.googleapis.com/download/storage/v1/b/logs.name", None),
            ("projects/demo/roles/deploy.role_id", GCP_ROLE_REFERENCE_SUFFIXES),
            ("google_compute_network.name", GCP_NETWORK_REFERENCE_SUFFIXES),
            ("google_storage_bucket.id", None),
        )

        for reference, suffixes in cases:
            with self.subTest(reference=reference):
                actual = gcp_reference_key(reference) if suffixes is None else gcp_reference_key(reference, suffixes)
                self.assertEqual(actual, reference)


if __name__ == "__main__":
    unittest.main()
