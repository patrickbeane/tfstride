from __future__ import annotations

import json
import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_PROJECT = "tfstride-demo"
_OTHER_PROJECT = "tfstride-other"
_SERVICE_ACCOUNT_EMAIL = "orders@tfstride-demo.iam.gserviceaccount.com"
_SERVICE_ACCOUNT_MEMBER = f"serviceAccount:{_SERVICE_ACCOUNT_EMAIL}"
_WORKLOAD_ADDRESS = "google_cloud_run_v2_service.orders"
_BUCKET_ADDRESS = "google_storage_bucket.orders"
_BUCKET_NAME = "tfstride-orders-data"


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


def _bucket(
    *,
    address: str = _BUCKET_ADDRESS,
    name: str = _BUCKET_NAME,
    project: str = _PROJECT,
    versioning_enabled: bool | None = True,
    soft_delete_seconds: int | None = 604_800,
    include_soft_delete: bool = True,
    unknown_soft_delete: bool = False,
    retention_period: str | None = None,
    retention_locked: bool | None = None,
    unknown_retention: bool = False,
) -> object:
    values: dict[str, object] = {
        "name": name,
        "project": project,
        "location": "US",
        "versioning": [{"enabled": versioning_enabled}],
    }
    if include_soft_delete:
        values["soft_delete_policy"] = [{"retention_duration_seconds": soft_delete_seconds}]
    if retention_period is not None or retention_locked is not None:
        values["retention_policy"] = [
            {
                "retention_period": retention_period,
                "is_locked": retention_locked,
            }
        ]

    unknown_values: dict[str, object] = {}
    if unknown_soft_delete:
        unknown_values["soft_delete_policy"] = [{"retention_duration_seconds": True}]
    if unknown_retention:
        unknown_values["retention_policy"] = [{"retention_period": True, "is_locked": True}]
    return _terraform_resource(
        address,
        GcpResourceType.STORAGE_BUCKET,
        values,
        unknown_values=unknown_values,
    )


def _bucket_member(
    *,
    name: str = "orders_delete",
    bucket: str = f"{_BUCKET_ADDRESS}.name",
    role: str = "roles/storage.objectAdmin",
    member: str = _SERVICE_ACCOUNT_MEMBER,
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
        f"google_storage_bucket_iam_member.{name}",
        GcpResourceType.STORAGE_BUCKET_IAM_MEMBER,
        values,
    )


def _bucket_binding(
    *,
    name: str = "orders_delete",
    bucket: str = f"{_BUCKET_ADDRESS}.name",
    role: str = "roles/storage.objectAdmin",
    members: list[str] | None = None,
) -> object:
    return _terraform_resource(
        f"google_storage_bucket_iam_binding.{name}",
        GcpResourceType.STORAGE_BUCKET_IAM_BINDING,
        {
            "bucket": bucket,
            "role": role,
            "members": members or [_SERVICE_ACCOUNT_MEMBER],
        },
    )


def _bucket_policy(
    *,
    name: str = "orders",
    bucket: str = f"{_BUCKET_ADDRESS}.name",
    role: str = "roles/storage.objectAdmin",
) -> object:
    return _terraform_resource(
        f"google_storage_bucket_iam_policy.{name}",
        GcpResourceType.STORAGE_BUCKET_IAM_POLICY,
        {
            "bucket": bucket,
            "policy_data": json.dumps(
                {
                    "bindings": [
                        {
                            "role": role,
                            "members": [_SERVICE_ACCOUNT_MEMBER],
                        }
                    ]
                }
            ),
        },
    )


def _project_member(
    *,
    name: str = "orders_delete",
    project: str = _PROJECT,
    role: str = "roles/storage.objectAdmin",
    member: str = _SERVICE_ACCOUNT_MEMBER,
) -> object:
    return _terraform_resource(
        f"google_project_iam_member.{name}",
        GcpResourceType.PROJECT_IAM_MEMBER,
        {
            "project": project,
            "role": role,
            "member": member,
        },
    )


def _custom_role(
    *,
    role_id: str = "objectDeleter",
    address: str | None = None,
    permissions: list[str] | None = None,
    stage: str | None = None,
    deleted: bool | None = None,
    unknown_permissions: bool = False,
    unknown_stage: bool = False,
    unknown_deleted: bool = False,
) -> object:
    values: dict[str, object] = {
        "project": _PROJECT,
        "role_id": role_id,
        "name": f"projects/{_PROJECT}/roles/{role_id}",
        "permissions": permissions or ["storage.objects.delete"],
    }
    if stage is not None:
        values["stage"] = stage
    if deleted is not None:
        values["deleted"] = deleted
    unknown_values: dict[str, object] = {}
    if unknown_permissions:
        unknown_values["permissions"] = True
    if unknown_stage:
        unknown_values["stage"] = True
    if unknown_deleted:
        unknown_values["deleted"] = True
    return _terraform_resource(
        address or f"google_project_iam_custom_role.{role_id}",
        GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
        values,
        unknown_values=unknown_values,
    )


def _facts(resources: list[object]):
    inventory = GcpNormalizer().normalize(resources)
    workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
    assert workload is not None
    return inventory, gcp_facts(workload)


class GcpCloudRunGcsObjectDeletionPathTests(unittest.TestCase):
    def test_bucket_grant_models_logical_and_generation_namespaces(self) -> None:
        _, facts = _facts(
            [
                _cloud_run(),
                _bucket(),
                _bucket_member(),
            ]
        )

        paths = facts.cloud_run_gcs_object_deletion_paths
        self.assertEqual(len(paths), 2)
        self.assertEqual(
            {path["operation_class"] for path in paths},
            {"logical_object_deletion", "generation_deletion"},
        )
        self.assertEqual(
            {path["target_granularity"] for path in paths},
            {"bucket_object_namespace", "bucket_generation_namespace"},
        )
        for path in paths:
            self.assertEqual(path["service_account_email"], _SERVICE_ACCOUNT_EMAIL)
            self.assertEqual(path["service_account_member"], _SERVICE_ACCOUNT_MEMBER)
            self.assertEqual(path["bucket_address"], _BUCKET_ADDRESS)
            self.assertEqual(path["bucket_name"], _BUCKET_NAME)
            self.assertEqual(path["bucket_project"], _PROJECT)
            self.assertEqual(path["target_scope"], f"projects/_/buckets/{_BUCKET_NAME}/objects/*")
            self.assertEqual(path["matched_permissions"], ["storage.objects.delete"])
            self.assertEqual(path["authorization_state"], "granted")
            self.assertTrue(path["policy_complete"])
            self.assertEqual(path["scope_type"], "bucket")
            self.assertEqual(path["grant_basis"], "bucket_iam_additive_member")
            self.assertIsNone(path["object_name"])
            self.assertIsNone(path["generation"])
            self.assertEqual(path["recovery_evidence"]["soft_delete_state"], "enabled")
            self.assertEqual(
                path["recovery_evidence"]["soft_delete_retention_duration_seconds"],
                604_800,
            )
            self.assertTrue(path["recovery_evidence"]["versioning_enabled"])
        self.assertEqual(facts.cloud_run_gcs_object_deletion_path_uncertainties, [])

    def test_project_grants_fan_only_to_exact_same_project_buckets(self) -> None:
        archive_address = "google_storage_bucket.archive"
        archive_name = "tfstride-archive-data"
        foreign_address = "google_storage_bucket.foreign"
        _, facts = _facts(
            [
                _cloud_run(),
                _bucket(),
                _bucket(address=archive_address, name=archive_name),
                _bucket(
                    address=foreign_address,
                    name="tfstride-foreign-data",
                    project=_OTHER_PROJECT,
                ),
                _project_member(),
                _bucket_member(),
            ]
        )

        paths = facts.cloud_run_gcs_object_deletion_paths
        self.assertEqual(len(paths), 6)
        self.assertEqual(
            {path["bucket_address"] for path in paths},
            {_BUCKET_ADDRESS, archive_address},
        )
        orders_paths = [path for path in paths if path["bucket_address"] == _BUCKET_ADDRESS]
        self.assertEqual({path["scope_type"] for path in orders_paths}, {"project", "bucket"})
        self.assertEqual(
            {path["scope"] for path in orders_paths},
            {_PROJECT, f"projects/_/buckets/{_BUCKET_NAME}"},
        )
        self.assertFalse(any(path["bucket_address"] == foreign_address for path in paths))

    def test_basic_and_legacy_predefined_roles_respect_native_scope(self) -> None:
        for role in ("roles/editor", "roles/owner"):
            with self.subTest(role=role, scope="project"):
                _, facts = _facts(
                    [
                        _cloud_run(),
                        _bucket(),
                        _project_member(role=role),
                    ]
                )
                self.assertEqual(facts.cloud_run_gcs_object_deletion_paths, [])
                self.assertTrue(
                    any(
                        "unmodeled" in uncertainty
                        for uncertainty in facts.cloud_run_gcs_object_deletion_path_uncertainties
                    )
                )

        for role in (
            "roles/storage.legacyBucketOwner",
            "roles/storage.legacyBucketWriter",
        ):
            with self.subTest(role=role, scope="bucket"):
                _, facts = _facts(
                    [
                        _cloud_run(),
                        _bucket(),
                        _bucket_member(role=role),
                    ]
                )
                self.assertEqual(len(facts.cloud_run_gcs_object_deletion_paths), 2)
                self.assertEqual(
                    {path["scope_type"] for path in facts.cloud_run_gcs_object_deletion_paths},
                    {"bucket"},
                )

        _, incompatible = _facts(
            [
                _cloud_run(),
                _bucket(),
                _project_member(role="roles/storage.legacyBucketOwner"),
            ]
        )
        self.assertEqual(incompatible.cloud_run_gcs_object_deletion_paths, [])
        self.assertTrue(
            any(
                "incompatible_scope" in uncertainty
                for uncertainty in incompatible.cloud_run_gcs_object_deletion_path_uncertainties
            )
        )

    def test_custom_role_permissions_are_preserved(self) -> None:
        role = f"projects/{_PROJECT}/roles/objectDeleter"
        inventory, facts = _facts(
            [
                _cloud_run(),
                _bucket(),
                _custom_role(permissions=["storage.objects.delete", "storage.objects.get"]),
                _bucket_member(role=role),
            ]
        )

        role_resource = inventory.get_by_address("google_project_iam_custom_role.objectDeleter")
        assert role_resource is not None
        self.assertEqual(gcp_facts(role_resource).custom_role_stage, "GA")
        self.assertFalse(gcp_facts(role_resource).custom_role_deleted)
        self.assertEqual(
            gcp_facts(role_resource).custom_role_deleted_uncertainties,
            [],
        )
        self.assertEqual(len(facts.cloud_run_gcs_object_deletion_paths), 2)
        for path in facts.cloud_run_gcs_object_deletion_paths:
            self.assertEqual(path["role_kind"], "custom")
            self.assertEqual(
                path["custom_role_permissions"],
                ["storage.objects.delete", "storage.objects.get"],
            )
            self.assertEqual(path["matched_permissions"], ["storage.objects.delete"])
            self.assertEqual(
                path["iam_source_addresses"],
                [
                    "google_storage_bucket_iam_member.orders_delete",
                    "google_project_iam_custom_role.objectDeleter",
                ],
            )

    def test_conflicting_custom_roles_do_not_create_deletion_paths_in_either_order(self) -> None:
        role = f"projects/{_PROJECT}/roles/objectDeleter"
        privileged = _custom_role(
            address="google_project_iam_custom_role.privileged",
            permissions=["storage.objects.delete"],
        )
        benign = _custom_role(
            address="google_project_iam_custom_role.benign",
            permissions=["storage.objects.get"],
        )
        snapshots: list[tuple[str, ...]] = []

        for case, definitions in {
            "privileged first": [privileged, benign],
            "benign first": [benign, privileged],
        }.items():
            with self.subTest(case=case):
                _, facts = _facts(
                    [
                        _cloud_run(),
                        _bucket(),
                        *definitions,
                        _bucket_member(role=role),
                    ]
                )
                self.assertEqual(facts.cloud_run_gcs_object_deletion_paths, [])
                self.assertTrue(
                    any(
                        "ambiguous" in uncertainty
                        for uncertainty in facts.cloud_run_gcs_object_deletion_path_uncertainties
                    )
                )
                snapshots.append(tuple(facts.cloud_run_gcs_object_deletion_path_uncertainties))

        self.assertEqual(snapshots[0], snapshots[1])

    def test_disabled_and_unknown_custom_role_stages_do_not_create_paths(self) -> None:
        role = f"projects/{_PROJECT}/roles/objectDeleter"
        _, disabled = _facts(
            [
                _cloud_run(),
                _bucket(),
                _custom_role(stage="DISABLED"),
                _bucket_member(role=role),
            ]
        )
        self.assertEqual(disabled.cloud_run_gcs_object_deletion_paths, [])
        self.assertEqual(
            disabled.cloud_run_gcs_object_deletion_path_uncertainties,
            [],
        )

        inventory, unknown = _facts(
            [
                _cloud_run(),
                _bucket(),
                _custom_role(unknown_stage=True),
                _bucket_member(role=role),
            ]
        )
        role_resource = inventory.get_by_address("google_project_iam_custom_role.objectDeleter")
        assert role_resource is not None
        self.assertIsNone(gcp_facts(role_resource).custom_role_stage)
        self.assertEqual(unknown.cloud_run_gcs_object_deletion_paths, [])
        self.assertTrue(
            any(
                "unknown_stage" in uncertainty
                for uncertainty in unknown.cloud_run_gcs_object_deletion_path_uncertainties
            )
        )

    def test_deleted_and_unknown_custom_role_deletion_posture_do_not_create_paths(
        self,
    ) -> None:
        role = f"projects/{_PROJECT}/roles/objectDeleter"
        inventory, deleted = _facts(
            [
                _cloud_run(),
                _bucket(),
                _custom_role(stage="GA", deleted=True),
                _bucket_member(role=role),
            ]
        )
        role_resource = inventory.get_by_address("google_project_iam_custom_role.objectDeleter")
        assert role_resource is not None
        self.assertTrue(gcp_facts(role_resource).custom_role_deleted)
        self.assertEqual(deleted.cloud_run_gcs_object_deletion_paths, [])
        self.assertEqual(
            deleted.cloud_run_gcs_object_deletion_path_uncertainties,
            [],
        )

        inventory, unknown = _facts(
            [
                _cloud_run(),
                _bucket(),
                _custom_role(stage="GA", unknown_deleted=True),
                _bucket_member(role=role),
            ]
        )
        role_resource = inventory.get_by_address("google_project_iam_custom_role.objectDeleter")
        assert role_resource is not None
        role_facts = gcp_facts(role_resource)
        self.assertIsNone(role_facts.custom_role_deleted)
        self.assertEqual(
            role_facts.custom_role_deleted_uncertainties,
            ["deleted is unknown after planning"],
        )
        self.assertEqual(unknown.cloud_run_gcs_object_deletion_paths, [])
        self.assertTrue(
            any(
                "unknown_deleted_state" in uncertainty
                for uncertainty in unknown.cloud_run_gcs_object_deletion_path_uncertainties
            )
        )

        _, active = _facts(
            [
                _cloud_run(),
                _bucket(),
                _custom_role(stage="GA", deleted=False),
                _bucket_member(role=role),
            ]
        )
        self.assertEqual(len(active.cloud_run_gcs_object_deletion_paths), 2)

    def test_conditions_and_unknown_custom_roles_remain_uncertain(self) -> None:
        condition = {
            "title": "temporary-delete",
            "expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
        }
        _, conditional = _facts(
            [
                _cloud_run(),
                _bucket(),
                _bucket_member(condition=condition),
            ]
        )
        self.assertEqual(conditional.cloud_run_gcs_object_deletion_paths, [])
        self.assertTrue(
            any(
                "condition-dependent" in uncertainty
                for uncertainty in conditional.cloud_run_gcs_object_deletion_path_uncertainties
            )
        )

        role = f"projects/{_PROJECT}/roles/objectDeleter"
        _, unresolved = _facts(
            [
                _cloud_run(),
                _bucket(),
                _custom_role(unknown_permissions=True),
                _bucket_member(role=role),
            ]
        )
        self.assertEqual(unresolved.cloud_run_gcs_object_deletion_paths, [])
        self.assertTrue(
            any(
                "permissions for IAM role" in uncertainty
                for uncertainty in unresolved.cloud_run_gcs_object_deletion_path_uncertainties
            )
        )

    def test_overlapping_authoritative_and_additive_managers_fail_closed(self) -> None:
        _, binding_overlap = _facts(
            [
                _cloud_run(),
                _bucket(),
                _bucket_member(),
                _bucket_binding(),
            ]
        )
        self.assertEqual(binding_overlap.cloud_run_gcs_object_deletion_paths, [])
        self.assertTrue(
            any(
                "authoritative role bindings overlap" in uncertainty
                for uncertainty in binding_overlap.cloud_run_gcs_object_deletion_path_uncertainties
            )
        )

        _, policy_overlap = _facts(
            [
                _cloud_run(),
                _bucket(),
                _bucket_member(),
                _bucket_policy(),
            ]
        )
        self.assertEqual(policy_overlap.cloud_run_gcs_object_deletion_paths, [])
        self.assertTrue(
            any(
                "authoritative policy" in uncertainty
                for uncertainty in policy_overlap.cloud_run_gcs_object_deletion_path_uncertainties
            )
        )

    def test_soft_delete_states_do_not_infer_platform_defaults(self) -> None:
        cases = (
            ("enabled", _bucket(soft_delete_seconds=604_800), "enabled", 604_800, False),
            ("disabled", _bucket(soft_delete_seconds=0), "disabled", 0, False),
            (
                "not-observed",
                _bucket(include_soft_delete=False),
                "not_observed",
                None,
                True,
            ),
            (
                "unknown",
                _bucket(soft_delete_seconds=None, unknown_soft_delete=True),
                "unknown",
                None,
                True,
            ),
        )
        for case, bucket, expected_state, expected_duration, expect_uncertainty in cases:
            with self.subTest(case=case):
                inventory, facts = _facts([_cloud_run(), bucket, _bucket_member()])
                normalized_bucket = inventory.get_by_address(_BUCKET_ADDRESS)
                assert normalized_bucket is not None
                bucket_facts = gcp_facts(normalized_bucket)
                self.assertEqual(bucket_facts.gcs_soft_delete_state, expected_state)
                self.assertEqual(
                    bucket_facts.gcs_soft_delete_retention_duration_seconds,
                    expected_duration,
                )
                paths = facts.cloud_run_gcs_object_deletion_paths
                self.assertEqual(len(paths), 2)
                recovery = paths[0]["recovery_evidence"]
                self.assertEqual(recovery["soft_delete_state"], expected_state)
                self.assertEqual(
                    recovery["soft_delete_retention_duration_seconds"],
                    expected_duration,
                )
                self.assertIs(bool(recovery["uncertainties"]), expect_uncertainty)

    def test_retention_policy_is_recovery_evidence_not_target_age_claim(self) -> None:
        _, facts = _facts(
            [
                _cloud_run(),
                _bucket(retention_period="2592000", retention_locked=True),
                _bucket_member(),
            ]
        )

        self.assertEqual(len(facts.cloud_run_gcs_object_deletion_paths), 2)
        for path in facts.cloud_run_gcs_object_deletion_paths:
            self.assertEqual(path["lifecycle_compatibility_state"], "unknown")
            recovery = path["recovery_evidence"]
            self.assertEqual(recovery["retention_period_seconds"], 2_592_000)
            self.assertTrue(recovery["retention_policy_locked"])
            self.assertTrue(any("does not establish the age" in item for item in recovery["uncertainties"]))

    def test_other_identity_stays_quiet_and_unresolved_identity_is_uncertain(self) -> None:
        _, other = _facts(
            [
                _cloud_run(),
                _bucket(),
                _bucket_member(member="serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"),
            ]
        )
        self.assertEqual(other.cloud_run_gcs_object_deletion_paths, [])
        self.assertEqual(other.cloud_run_gcs_object_deletion_path_uncertainties, [])

        _, unresolved = _facts(
            [
                _cloud_run(service_account=None),
                _bucket(),
                _bucket_member(),
            ]
        )
        self.assertEqual(unresolved.cloud_run_gcs_object_deletion_paths, [])
        self.assertEqual(
            unresolved.cloud_run_gcs_object_deletion_path_uncertainties,
            [f"{_WORKLOAD_ADDRESS}: Cloud Run service account identity is unresolved"],
        )

    def test_unsupported_or_other_bucket_references_do_not_create_false_paths(self) -> None:
        _, unsupported = _facts(
            [
                _cloud_run(),
                _bucket(),
                _bucket_member(bucket=f"{_BUCKET_ADDRESS}.id"),
            ]
        )
        self.assertEqual(unsupported.cloud_run_gcs_object_deletion_paths, [])
        self.assertTrue(unsupported.cloud_run_gcs_object_deletion_path_uncertainties)

        _, unrelated = _facts(
            [
                _cloud_run(),
                _bucket(),
                _bucket_member(bucket="tfstride-archive-data"),
            ]
        )
        self.assertEqual(unrelated.cloud_run_gcs_object_deletion_paths, [])
        self.assertEqual(unrelated.cloud_run_gcs_object_deletion_path_uncertainties, [])


if __name__ == "__main__":
    unittest.main()
