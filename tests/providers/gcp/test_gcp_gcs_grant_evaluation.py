from __future__ import annotations

import json
import unittest
from itertools import permutations
from unittest.mock import patch

from tests.helpers.gcp_gcs_plan import CASES, build_gcs_case, service_account_member
from tests.providers.gcp.normalizer_support import _terraform_resource
from tests.providers.gcp.test_gcp_cloud_run_gcs_access_paths import (
    _BUCKET_ADDRESS,
    _IAM_ADDRESS,
    _PROJECT,
    _SERVICE_ACCOUNT_MEMBER,
    _bucket,
    _bucket_iam_member,
    _custom_role,
    _normalize,
)
from tfstride.providers.gcp.custom_roles import build_gcp_custom_role_index
from tfstride.providers.gcp.gcs_grant_evaluation import GcsGrantConstraintContext, evaluate_gcs_bucket_grants
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType


class GcpGcsGrantEvaluationTests(unittest.TestCase):
    def test_prepared_context_matches_fresh_full_inventory_evaluation(self) -> None:
        for case in CASES:
            inventory = GcpNormalizer().normalize(build_gcs_case(case))
            buckets = inventory.by_type(GcpResourceType.STORAGE_BUCKET)
            prepared = GcsGrantConstraintContext.build(inventory.resources)
            for workload in range(3):
                principal = service_account_member(workload)
                expected = evaluate_gcs_bucket_grants(principal, buckets, resources=inventory.resources)
                with (
                    self.subTest(case=case, workload=workload),
                    patch.object(
                        GcsGrantConstraintContext, "build", side_effect=AssertionError("unexpected grant context")
                    ),
                ):
                    self.assertEqual(evaluate_gcs_bucket_grants(principal, buckets, context=prepared), expected)

    def test_empty_bucket_selection_does_not_construct_a_grant_context(self) -> None:
        inventory = _normalize([_bucket(), _bucket_iam_member()])
        custom_roles = build_gcp_custom_role_index(inventory.resources)
        with patch.object(GcsGrantConstraintContext, "build", side_effect=AssertionError("unexpected grant context")):
            self.assertEqual(
                evaluate_gcs_bucket_grants(_SERVICE_ACCOUNT_MEMBER, (), custom_roles, resources=inventory.resources),
                ([], []),
            )

    def test_grants_preserve_exact_target_principal_and_operation_without_a_workload(self) -> None:
        other_bucket = _terraform_resource(
            "google_storage_bucket.other",
            GcpResourceType.STORAGE_BUCKET,
            {"name": "other-data", "project": _PROJECT, "location": "US"},
        )
        resources = [_bucket(), other_bucket, _bucket_iam_member(role="roles/storage.objectCreator")]
        for ordered in permutations(resources):
            with self.subTest(order=[resource.address for resource in ordered]):
                inventory = _normalize(list(ordered))
                grants, uncertainties = evaluate_gcs_bucket_grants(
                    _SERVICE_ACCOUNT_MEMBER, inventory.resources, build_gcp_custom_role_index(inventory.resources)
                )
                self.assertEqual(uncertainties, [])
                self.assertEqual(len(grants), 1)
                grant = grants[0]
                self.assertEqual(grant["principal"], _SERVICE_ACCOUNT_MEMBER)
                self.assertEqual(grant["bucket_address"], _BUCKET_ADDRESS)
                self.assertEqual(grant["iam_resource_address"], _IAM_ADDRESS)
                self.assertEqual(grant["resource_scope"], "exact_bucket")
                self.assertEqual(grant["grant_basis"], "storage_bucket_iam")
                self.assertEqual(grant["access_classes"], ["write"])
                self.assertEqual(grant["access_state"], "granted")
                self.assertNotIn("workload_address", grant)
                self.assertEqual(
                    evaluate_gcs_bucket_grants(
                        "serviceAccount:other@example.com",
                        inventory.resources,
                        build_gcp_custom_role_index(inventory.resources),
                    ),
                    ([], []),
                )

    def test_custom_role_retains_full_permissions_and_matching_operation(self) -> None:
        permissions = ["resourcemanager.projects.get", "storage.objects.delete"]
        role = f"projects/{_PROJECT}/roles/cloudRunStorage"
        inventory = _normalize([_bucket(), _custom_role(permissions=permissions), _bucket_iam_member(role=role)])
        grants, uncertainties = evaluate_gcs_bucket_grants(
            _SERVICE_ACCOUNT_MEMBER, inventory.resources, build_gcp_custom_role_index(inventory.resources)
        )
        self.assertEqual(uncertainties, [])
        self.assertEqual(len(grants), 1)
        self.assertEqual(grants[0]["role"], role)
        self.assertEqual(grants[0]["role_kind"], "custom")
        self.assertEqual(grants[0]["custom_role_permissions"], permissions)
        self.assertEqual(grants[0]["matched_permissions"], ["storage.objects.delete"])
        self.assertEqual(grants[0]["access_classes"], ["delete"])
        # An empty prepared inventory must still honor caller-supplied local evidence and roles.
        prepared = GcsGrantConstraintContext.build(())
        self.assertEqual(
            evaluate_gcs_bucket_grants(
                _SERVICE_ACCOUNT_MEMBER,
                inventory.resources,
                build_gcp_custom_role_index(inventory.resources),
                context=prepared,
            ),
            (grants, uncertainties),
        )

    def test_deduplication_keeps_distinct_sources_and_conditions(self) -> None:
        inventory = _normalize([_bucket(), _bucket_iam_member()])
        bucket = inventory.get_by_address(_BUCKET_ADDRESS)
        assert bucket is not None
        facts = gcp_facts(bucket)
        binding = facts.bindings[0]
        first = {"title": "first", "expression": 'resource.name.startsWith("objects/first/")'}
        second = {"title": "second", "expression": 'resource.name.startsWith("objects/second/")'}
        alternatives = [
            {**binding, "condition": first},
            {**binding, "condition": second},
            {**binding, "condition": first, "source": "google_storage_bucket_iam_member.alternative"},
        ]
        expected = None
        for ordered in permutations(alternatives):
            facts.set(GcpResourceMetadata.IAM_BINDINGS, [*ordered, ordered[0]])
            grants, uncertainties = evaluate_gcs_bucket_grants(
                _SERVICE_ACCOUNT_MEMBER, [bucket], build_gcp_custom_role_index(inventory.resources)
            )
            self.assertEqual(uncertainties, [])
            self.assertEqual(len(grants), 3)
            self.assertTrue(all(grant["access_state"] == "conditional" for grant in grants))
            self.assertTrue(all(grant["condition_state"] == "configured" for grant in grants))
            self.assertEqual(grants[0]["condition"], ordered[0]["condition"])
            canonical = sorted(json.dumps(grant, sort_keys=True) for grant in grants)
            if expected is None:
                expected = canonical
            self.assertEqual(canonical, expected)

    def test_unresolved_roles_preserve_source_specific_uncertainty(self) -> None:
        custom_role = f"projects/{_PROJECT}/roles/missing"
        for role, reason in (
            ("unknown role", "IAM role is unresolved"),
            (custom_role, f"custom IAM role {custom_role} does not resolve to deterministic permissions"),
        ):
            with self.subTest(role=role):
                inventory = _normalize([_bucket(), _bucket_iam_member(role=role)])
                grants, uncertainties = evaluate_gcs_bucket_grants(
                    _SERVICE_ACCOUNT_MEMBER, inventory.resources, build_gcp_custom_role_index(inventory.resources)
                )
                self.assertEqual(grants, [])
                self.assertEqual(uncertainties, [f"{_IAM_ADDRESS} {reason}"])


if __name__ == "__main__":
    unittest.main()
