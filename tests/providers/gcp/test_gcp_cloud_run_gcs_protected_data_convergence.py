from __future__ import annotations

import unittest
from unittest.mock import patch

from tests.providers.gcp.test_gcp_cloud_run_gcs_access_paths import (
    _bucket_iam_member,
    _custom_role,
)
from tests.providers.gcp.test_gcp_cloud_run_kms_operation_paths import (
    _project_member,
    _ring_member,
)
from tests.providers.test_protected_data_key_authority_convergence import (
    _GCP_KEY_PATH,
    GCP_BUCKET_ADDRESS,
    GCP_KEY_RING,
    _gcp_bucket,
    _gcp_exact_key_mismatch_resources,
    _gcp_resources,
    _reference_resolution,
)
from tfstride.models import (
    ResourceInventory,
    TerraformReferenceResolutionState,
    TerraformResource,
)
from tfstride.providers.gcp.gcs_grant_evaluation import GcsGrantConstraintContext
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_decoration.cloud_run_gcs_protected_data_convergence import (
    ModelCloudRunGcsProtectedDataConvergenceStage,
)
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext, GcpResourceIndexBuilder
from tfstride.providers.gcp.resource_types import GcpResourceType

_WORKLOAD_ADDRESS = "google_cloud_run_v2_service.orders"
_KEY_ADDRESS = "google_kms_crypto_key.data"
_KEY_IAM_ADDRESS = "google_kms_crypto_key_iam_member.runtime_decrypter"


def _normalize(
    resources: list[TerraformResource],
) -> ResourceInventory:
    return GcpNormalizer().normalize(resources)


def _resource(inventory: ResourceInventory, address: str):
    resource = inventory.get_by_address(address)
    assert resource is not None
    return resource


def _workload_facts(inventory: ResourceInventory):
    return gcp_facts(_resource(inventory, _WORKLOAD_ADDRESS))


def _replace_key_grant(
    resources: list[TerraformResource],
    replacement: TerraformResource,
) -> list[TerraformResource]:
    return [resource for resource in resources if resource.address != _KEY_IAM_ADDRESS] + [replacement]


class GcpCloudRunGcsProtectedDataConvergenceTests(unittest.TestCase):
    def test_removed_bucket_clears_convergence_and_preserves_stale_access_diagnostic(self) -> None:
        inventory = _normalize(_gcp_resources())
        facts = _workload_facts(inventory)
        self.assertTrue(facts.cloud_run_gcs_protected_data_convergences)
        resources = [
            resource for resource in inventory.resources if resource.resource_type != GcpResourceType.STORAGE_BUCKET
        ]
        context = GcpDecorationContext(GcpResourceIndexBuilder().build(resources))
        with patch.object(GcsGrantConstraintContext, "build", side_effect=AssertionError("unexpected grant context")):
            ModelCloudRunGcsProtectedDataConvergenceStage().apply(resources, context)
        self.assertEqual(facts.cloud_run_gcs_protected_data_convergences, [])
        self.assertEqual(
            facts.cloud_run_gcs_protected_data_convergence_uncertainties,
            [
                f"{_WORKLOAD_ADDRESS}: GCS access evidence does not retain "
                "an exact modeled bucket for protected-data convergence"
            ],
        )

    def test_exact_runtime_read_cmek_dependency_and_decrypt_authority_converge(
        self,
    ) -> None:
        facts = _workload_facts(_normalize(_gcp_resources()))

        self.assertEqual(
            len(facts.cloud_run_gcs_protected_data_convergences),
            1,
        )
        convergence = facts.cloud_run_gcs_protected_data_convergences[0]
        self.assertEqual(
            convergence["workload_address"],
            _WORKLOAD_ADDRESS,
        )
        self.assertEqual(
            convergence["service_account_email"],
            "orders@tfstride-demo.iam.gserviceaccount.com",
        )
        self.assertEqual(
            convergence["service_account_member"],
            "serviceAccount:orders@tfstride-demo.iam.gserviceaccount.com",
        )
        self.assertEqual(
            convergence["bucket_address"],
            GCP_BUCKET_ADDRESS,
        )
        self.assertEqual(convergence["key_address"], _KEY_ADDRESS)
        self.assertEqual(
            convergence["key_resource_name"],
            _GCP_KEY_PATH,
        )
        self.assertEqual(
            convergence["operation"],
            "cloudkms.cryptoKeyVersions.useToDecrypt",
        )
        self.assertIs(convergence["runtime_identity_match"], True)
        self.assertIs(convergence["protected_resource_match"], True)
        self.assertIs(convergence["key_identity_match"], True)
        self.assertEqual(convergence["convergence_state"], "resolved")
        self.assertEqual(
            convergence["evaluation_basis"],
            "exact_gcs_access_cmek_dependency_and_decrypt_authority",
        )
        self.assertEqual(
            convergence["access_path"]["bucket_address"],
            convergence["encryption_dependency"]["dependent_address"],
        )
        self.assertEqual(
            convergence["key_operation_path"]["key_address"],
            convergence["encryption_dependency"]["key_address"],
        )
        self.assertEqual(
            convergence["key_operation_path"]["scope_type"],
            "crypto_key",
        )
        self.assertEqual(
            convergence["key_operation_path"]["scope"],
            _GCP_KEY_PATH,
        )
        self.assertIs(
            convergence["key_operation_path"]["iam_scope_is_key_version"],
            False,
        )
        self.assertEqual(convergence["posture_uncertainties"], [])
        self.assertEqual(
            facts.cloud_run_gcs_protected_data_convergence_uncertainties,
            [],
        )

    def test_project_key_ring_and_key_scope_remain_native_evidence(
        self,
    ) -> None:
        cases = (
            (
                _project_member(
                    "runtime_decrypter",
                    "roles/cloudkms.cryptoKeyDecrypter",
                ),
                "project",
                "tfstride-demo",
            ),
            (
                _ring_member(
                    "runtime_decrypter",
                    "roles/cloudkms.cryptoKeyDecrypter",
                ),
                "key_ring",
                GCP_KEY_RING,
            ),
        )
        for grant, expected_scope_type, expected_scope in cases:
            with self.subTest(scope_type=expected_scope_type):
                resources = _replace_key_grant(
                    _gcp_resources(),
                    grant,
                )
                facts = _workload_facts(_normalize(resources))
                self.assertEqual(
                    len(facts.cloud_run_gcs_protected_data_convergences),
                    1,
                )
                operation = facts.cloud_run_gcs_protected_data_convergences[0]["key_operation_path"]
                self.assertEqual(
                    operation["scope_type"],
                    expected_scope_type,
                )
                self.assertEqual(operation["scope"], expected_scope)
                self.assertEqual(operation["key_ring"], GCP_KEY_RING)
                self.assertEqual(
                    operation["key_resource_name"],
                    _GCP_KEY_PATH,
                )

    def test_exact_symbolic_cmek_reference_remains_unknown_without_convergence(
        self,
    ) -> None:
        resources = [resource for resource in _gcp_resources() if resource.address != GCP_BUCKET_ADDRESS]
        resources.append(
            _gcp_bucket(
                key_reference=None,
                resolution=_reference_resolution(
                    ("encryption", 0, "default_kms_key_name"),
                    (("google_kms_crypto_key.data", ".id"),),
                    state=TerraformReferenceResolutionState.SYMBOLIC,
                ),
            )
        )

        inventory = _normalize(resources)
        facts = _workload_facts(inventory)
        bucket = _resource(inventory, GCP_BUCKET_ADDRESS)
        dependency = gcp_facts(bucket).kms_encryption_dependencies[0]
        self.assertEqual(
            dependency["customer_managed_encryption_state"],
            "unknown",
        )
        self.assertEqual(
            dependency["reference_provenance"],
            "configuration_reference",
        )
        self.assertEqual(
            dependency["reference_kind"],
            "terraform_reference",
        )
        self.assertEqual(
            dependency["configured_key_reference"],
            "google_kms_crypto_key.data.id",
        )
        self.assertEqual(
            facts.cloud_run_gcs_protected_data_convergences,
            [],
        )
        self.assertTrue(
            any(
                "unresolved encryption ownership" in uncertainty
                for uncertainty in facts.cloud_run_gcs_protected_data_convergence_uncertainties
            )
        )

    def test_distinct_iam_scope_proofs_remain_distinct_convergences(
        self,
    ) -> None:
        resources = _gcp_resources()
        resources.append(
            _project_member(
                "additional_project_decrypter",
                "roles/cloudkms.cryptoKeyDecrypter",
            )
        )

        facts = _workload_facts(_normalize(resources))
        convergences = facts.cloud_run_gcs_protected_data_convergences
        self.assertEqual(len(convergences), 2)
        self.assertEqual(
            {convergence["key_operation_path"]["scope_type"] for convergence in convergences},
            {"project", "crypto_key"},
        )
        self.assertEqual(
            {
                (
                    convergence["bucket_address"],
                    convergence["key_address"],
                    tuple(convergence["encryption_dependency"]["configuration_path"]),
                )
                for convergence in convergences
            },
            {
                (
                    GCP_BUCKET_ADDRESS,
                    _KEY_ADDRESS,
                    ("encryption", 0, "default_kms_key_name"),
                )
            },
        )
        self.assertEqual(
            {convergence["encryption_dependency"]["configured_key_reference"] for convergence in convergences},
            {_GCP_KEY_PATH},
        )

    def test_exact_but_different_keys_do_not_converge(self) -> None:
        facts = _workload_facts(_normalize(_gcp_exact_key_mismatch_resources()))

        self.assertEqual(
            facts.cloud_run_gcs_protected_data_convergences,
            [],
        )
        self.assertEqual(
            facts.cloud_run_gcs_access_paths[0]["bucket_address"],
            GCP_BUCKET_ADDRESS,
        )
        self.assertEqual(
            facts.cloud_run_kms_operation_paths[0]["key_address"],
            "google_kms_crypto_key.audit",
        )
        bucket = _resource(
            _normalize(_gcp_exact_key_mismatch_resources()),
            GCP_BUCKET_ADDRESS,
        )
        self.assertEqual(
            gcp_facts(bucket).kms_encryption_dependencies[0]["key_address"],
            _KEY_ADDRESS,
        )

    def test_conditional_and_ambiguous_evidence_remains_uncertain(
        self,
    ) -> None:
        condition = {
            "title": "runtime",
            "expression": "request.time < timestamp('2030-01-01T00:00:00Z')",
        }
        cases = (
            _gcp_resources(bucket_condition=condition),
            _gcp_resources(kms_condition=condition),
            _gcp_resources(ambiguous_dependency=True),
        )
        for resources in cases:
            with self.subTest(resource_count=len(resources)):
                facts = _workload_facts(_normalize(resources))
                self.assertEqual(
                    facts.cloud_run_gcs_protected_data_convergences,
                    [],
                )
                self.assertTrue(facts.cloud_run_gcs_protected_data_convergence_uncertainties)

    def test_list_only_custom_role_does_not_establish_payload_read(
        self,
    ) -> None:
        resources = [
            resource
            for resource in _gcp_resources()
            if resource.address != "google_storage_bucket_iam_member.orders_access"
        ]
        resources.extend(
            [
                _custom_role(permissions=["storage.objects.list"]),
                _bucket_iam_member(role="projects/tfstride-demo/roles/cloudRunStorage"),
            ]
        )

        facts = _workload_facts(_normalize(resources))
        self.assertEqual(
            facts.cloud_run_gcs_access_paths[0]["access_classes"],
            ["read"],
        )
        self.assertEqual(
            facts.cloud_run_gcs_protected_data_convergences,
            [],
        )
        self.assertEqual(
            facts.cloud_run_gcs_protected_data_convergence_uncertainties,
            [],
        )

    def test_provider_managed_bucket_encryption_stays_quiet(self) -> None:
        resources = _gcp_resources()
        bucket = next(resource for resource in resources if resource.address == GCP_BUCKET_ADDRESS)
        bucket.values["encryption"] = []

        facts = _workload_facts(_normalize(resources))
        self.assertEqual(
            facts.cloud_run_gcs_protected_data_convergences,
            [],
        )
        self.assertEqual(
            facts.cloud_run_gcs_protected_data_convergence_uncertainties,
            [],
        )
