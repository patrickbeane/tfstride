from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_PROJECT = "tfstride-demo"
_SERVICE_ACCOUNT_EMAIL = "orders@tfstride-demo.iam.gserviceaccount.com"
_SERVICE_ACCOUNT_MEMBER = f"serviceAccount:{_SERVICE_ACCOUNT_EMAIL}"
_WORKLOAD_ADDRESS = "google_cloud_run_v2_service.orders"
_BUCKET_ADDRESS = "google_storage_bucket.orders"
_BUCKET_NAME = "tfstride-orders-data"
_IAM_ADDRESS = "google_storage_bucket_iam_member.orders_access"


def _cloud_run(*, service_account: str | None = _SERVICE_ACCOUNT_EMAIL) -> object:
    template: dict[str, object] = {}
    if service_account is not None:
        template["service_account"] = service_account
    return _terraform_resource(
        _WORKLOAD_ADDRESS,
        GcpResourceType.CLOUD_RUN_V2_SERVICE,
        {
            "name": "orders",
            "project": _PROJECT,
            "location": "us-central1",
            "template": [template],
        },
    )


def _bucket() -> object:
    return _terraform_resource(
        _BUCKET_ADDRESS,
        GcpResourceType.STORAGE_BUCKET,
        {
            "name": _BUCKET_NAME,
            "project": _PROJECT,
            "location": "US",
        },
    )


def _bucket_iam_member(
    *,
    role: str = "roles/storage.objectViewer",
    member: str = _SERVICE_ACCOUNT_MEMBER,
    bucket: str = f"{_BUCKET_ADDRESS}.name",
    condition: dict[str, str] | None = None,
) -> object:
    values: dict[str, object] = {
        "bucket": bucket,
        "role": role,
        "member": member,
    }
    if condition is not None:
        values["condition"] = [condition]
    return _terraform_resource(
        _IAM_ADDRESS,
        GcpResourceType.STORAGE_BUCKET_IAM_MEMBER,
        values,
    )


def _custom_role(
    *,
    role_id: str = "cloudRunStorage",
    permissions: list[str] | None = None,
) -> object:
    return _terraform_resource(
        "google_project_iam_custom_role.cloud_run_storage",
        GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
        {
            "project": _PROJECT,
            "role_id": role_id,
            "name": f"projects/{_PROJECT}/roles/{role_id}",
            "permissions": permissions
            or [
                "resourcemanager.projects.get",
                "storage.objects.create",
                "storage.objects.delete",
                "storage.objects.get",
            ],
        },
    )


def _normalize(resources: list[object]):
    return GcpNormalizer().normalize(resources)


def _workload_facts(inventory):
    workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
    assert workload is not None
    return gcp_facts(workload)


class GcpCloudRunGcsAccessPathTests(unittest.TestCase):
    def test_exact_bucket_viewer_grant_is_modeled_with_runtime_identity(self) -> None:
        facts = _workload_facts(_normalize([_cloud_run(), _bucket(), _bucket_iam_member()]))

        self.assertEqual(
            facts.cloud_run_gcs_access_paths,
            [
                {
                    "workload_address": _WORKLOAD_ADDRESS,
                    "workload_type": GcpResourceType.CLOUD_RUN_V2_SERVICE,
                    "service_account_email": _SERVICE_ACCOUNT_EMAIL,
                    "service_account_member": _SERVICE_ACCOUNT_MEMBER,
                    "identity_kind": "cloud_run_service_account",
                    "credential_context": "workload_runtime",
                    "bucket_address": _BUCKET_ADDRESS,
                    "bucket_name": _BUCKET_NAME,
                    "bucket_project": _PROJECT,
                    "iam_resource_address": _IAM_ADDRESS,
                    "role": "roles/storage.objectViewer",
                    "role_kind": "viewer",
                    "access_classes": ["read"],
                    "custom_role_permissions": [],
                    "matched_permissions": [],
                    "grant_basis": "storage_bucket_iam",
                    "resource_scope": "exact_bucket",
                    "condition": None,
                    "condition_state": "not_configured",
                    "access_state": "granted",
                }
            ],
        )
        self.assertEqual(facts.cloud_run_gcs_access_path_uncertainties, [])

    def test_builtin_storage_roles_preserve_distinct_role_kinds(self) -> None:
        expectations = {
            "roles/storage.objectViewer": ("viewer", ["read"]),
            "roles/storage.objectCreator": ("creator", ["write"]),
            "roles/storage.objectUser": ("user", ["read", "write", "delete"]),
            "roles/storage.objectAdmin": ("admin", ["read", "write", "delete"]),
        }

        for role, (role_kind, access_classes) in expectations.items():
            with self.subTest(role=role):
                facts = _workload_facts(_normalize([_cloud_run(), _bucket(), _bucket_iam_member(role=role)]))
                path = facts.cloud_run_gcs_access_paths[0]
                self.assertEqual(path["role_kind"], role_kind)
                self.assertEqual(path["access_classes"], access_classes)

    def test_custom_role_preserves_permissions_and_classifies_data_access(self) -> None:
        role = f"projects/{_PROJECT}/roles/cloudRunStorage"
        facts = _workload_facts(
            _normalize(
                [
                    _cloud_run(),
                    _bucket(),
                    _custom_role(),
                    _bucket_iam_member(role=role),
                ]
            )
        )

        path = facts.cloud_run_gcs_access_paths[0]
        self.assertEqual(path["role_kind"], "custom")
        self.assertEqual(path["access_classes"], ["read", "write", "delete"])
        self.assertEqual(
            path["custom_role_permissions"],
            [
                "resourcemanager.projects.get",
                "storage.objects.create",
                "storage.objects.delete",
                "storage.objects.get",
            ],
        )
        self.assertEqual(
            path["matched_permissions"],
            [
                "storage.objects.create",
                "storage.objects.delete",
                "storage.objects.get",
            ],
        )

    def test_conditional_grant_is_preserved_without_unconditional_access_claim(self) -> None:
        condition = {
            "title": "orders-prefix",
            "description": "Restrict access to order objects",
            "expression": ("resource.name.startsWith('projects/_/buckets/tfstride-orders-data/objects/orders/')"),
        }
        facts = _workload_facts(
            _normalize(
                [
                    _cloud_run(),
                    _bucket(),
                    _bucket_iam_member(role="roles/storage.objectUser", condition=condition),
                ]
            )
        )

        path = facts.cloud_run_gcs_access_paths[0]
        self.assertEqual(path["condition"], condition)
        self.assertEqual(path["condition_state"], "configured")
        self.assertEqual(path["access_state"], "conditional")
        self.assertEqual(path["access_classes"], ["read", "write", "delete"])

    def test_nonmatching_identity_or_bucket_reference_does_not_invent_path(self) -> None:
        other_identity = _workload_facts(
            _normalize(
                [
                    _cloud_run(),
                    _bucket(),
                    _bucket_iam_member(member="serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"),
                ]
            )
        )
        unresolved_bucket = _workload_facts(
            _normalize(
                [
                    _cloud_run(),
                    _bucket(),
                    _bucket_iam_member(bucket="google_storage_bucket.archive.name"),
                ]
            )
        )

        self.assertEqual(other_identity.cloud_run_gcs_access_paths, [])
        self.assertEqual(unresolved_bucket.cloud_run_gcs_access_paths, [])

    def test_unresolved_custom_role_permissions_are_retained_as_uncertainty(self) -> None:
        role = f"projects/{_PROJECT}/roles/externalStorageRole"
        facts = _workload_facts(
            _normalize(
                [
                    _cloud_run(),
                    _bucket(),
                    _bucket_iam_member(role=role),
                ]
            )
        )

        self.assertEqual(facts.cloud_run_gcs_access_paths, [])
        self.assertEqual(
            facts.cloud_run_gcs_access_path_uncertainties,
            [
                f"{_WORKLOAD_ADDRESS}: {_IAM_ADDRESS} custom IAM role {role} "
                "does not resolve to deterministic permissions"
            ],
        )

    def test_unresolved_service_account_does_not_create_access_claim(self) -> None:
        facts = _workload_facts(
            _normalize(
                [
                    _cloud_run(service_account=None),
                    _bucket(),
                    _bucket_iam_member(),
                ]
            )
        )

        self.assertEqual(facts.cloud_run_gcs_access_paths, [])
        self.assertEqual(
            facts.cloud_run_gcs_access_path_uncertainties,
            [f"{_WORKLOAD_ADDRESS}: Cloud Run service account is unresolved"],
        )


if __name__ == "__main__":
    unittest.main()
