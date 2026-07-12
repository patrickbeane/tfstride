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

    def test_reference_key_strips_provider_specific_suffixes(self) -> None:
        self.assertEqual(gcp_reference_key("google_service_account.web.email"), "google_service_account.web")
        self.assertEqual(
            gcp_reference_key("google_project_iam_custom_role.deploy.role_id", GCP_ROLE_REFERENCE_SUFFIXES),
            "google_project_iam_custom_role.deploy",
        )
        self.assertEqual(
            gcp_reference_key("google_compute_network.main.self_link", GCP_NETWORK_REFERENCE_SUFFIXES),
            "google_compute_network.main",
        )


if __name__ == "__main__":
    unittest.main()
