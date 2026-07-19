from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_decoration.cloud_run_secret_access_paths import (
    ModelCloudRunSecretAccessPathsStage,
)
from tfstride.providers.gcp.resource_decorator import GcpResourceDecorator
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_PROJECT = "tfstride-demo"
_SERVICE_ACCOUNT_EMAIL = "run-api@tfstride-demo.iam.gserviceaccount.com"
_SERVICE_ACCOUNT_MEMBER = f"serviceAccount:{_SERVICE_ACCOUNT_EMAIL}"
_SECRET_NAME = f"projects/{_PROJECT}/secrets/orders-db"
_WORKLOAD_ADDRESS = "google_cloud_run_v2_service.api"
_SECRET_ADDRESS = "google_secret_manager_secret.orders"


def _cloud_run(
    *,
    secret_reference: str = _SECRET_NAME,
    service_account: str = _SERVICE_ACCOUNT_EMAIL,
) -> object:
    return _terraform_resource(
        _WORKLOAD_ADDRESS,
        GcpResourceType.CLOUD_RUN_V2_SERVICE,
        {
            "name": "api",
            "project": _PROJECT,
            "location": "us-central1",
            "template": [
                {
                    "service_account": service_account,
                    "containers": [
                        {
                            "name": "api",
                            "env": [
                                {
                                    "name": "DB_PASSWORD",
                                    "value_source": [
                                        {
                                            "secret_key_ref": [
                                                {
                                                    "secret": secret_reference,
                                                    "version": "5",
                                                }
                                            ]
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ],
        },
    )


def _secret() -> object:
    return _terraform_resource(
        _SECRET_ADDRESS,
        GcpResourceType.SECRET_MANAGER_SECRET,
        {
            "project": _PROJECT,
            "secret_id": "orders-db",
            "name": _SECRET_NAME,
            "replication": [{"auto": [{}]}],
        },
    )


def _iam_resource(
    resource_type: str,
    name: str,
    *,
    role: str = "roles/secretmanager.secretAccessor",
    member: str = _SERVICE_ACCOUNT_MEMBER,
    condition: list[dict[str, str]] | None = None,
    **scope_values: object,
) -> object:
    values: dict[str, object] = {
        "role": role,
        "member": member,
        **scope_values,
    }
    if condition is not None:
        values["condition"] = condition
    return _terraform_resource(f"{resource_type}.{name}", resource_type, values)


def _secret_iam_member(
    *,
    role: str = "roles/secretmanager.secretAccessor",
    member: str = _SERVICE_ACCOUNT_MEMBER,
    condition: list[dict[str, str]] | None = None,
    secret_id: str = _SECRET_NAME,
) -> object:
    return _iam_resource(
        GcpResourceType.SECRET_MANAGER_SECRET_IAM_MEMBER,
        "access",
        role=role,
        member=member,
        condition=condition,
        project=_PROJECT,
        secret_id=secret_id,
    )


def _project_iam_member(
    *,
    role: str = "roles/secretmanager.secretAccessor",
    member: str = _SERVICE_ACCOUNT_MEMBER,
    project: str = _PROJECT,
) -> object:
    return _iam_resource(
        GcpResourceType.PROJECT_IAM_MEMBER,
        "access",
        role=role,
        member=member,
        project=project,
    )


def _normalize(resources: list[object]):
    return GcpNormalizer().normalize(resources)


def _workload_facts(inventory):
    workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
    assert workload is not None
    return gcp_facts(workload)


def _rerun_path_stage(inventory, *, folder_id: str | None = None, organization_id: str | None = None):
    resources = list(inventory.resources)
    secret = inventory.get_by_address(_SECRET_ADDRESS)
    workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
    assert secret is not None
    assert workload is not None
    if folder_id is not None:
        secret.set_metadata_field(GcpResourceMetadata.FOLDER_ID, folder_id)
    if organization_id is not None:
        secret.set_metadata_field(GcpResourceMetadata.ORGANIZATION_ID, organization_id)
    workload.set_metadata_field(GcpResourceMetadata.CLOUD_RUN_SECRET_ACCESS_PATHS, [])
    workload.set_metadata_field(GcpResourceMetadata.CLOUD_RUN_SECRET_ACCESS_PATH_UNCERTAINTIES, [])
    GcpResourceDecorator(stages=[ModelCloudRunSecretAccessPathsStage()]).decorate(resources)
    return gcp_facts(workload)


class GcpCloudRunSecretAccessPathTests(unittest.TestCase):
    def test_secret_level_grant_preserves_condition_and_version_evidence(self) -> None:
        condition = [
            {
                "title": "deployment-window",
                "description": "temporary access",
                "expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
            }
        ]
        facts = _workload_facts(
            _normalize(
                [
                    _secret(),
                    _cloud_run(),
                    _secret_iam_member(condition=condition),
                ]
            )
        )

        self.assertEqual(len(facts.cloud_run_secret_access_paths), 1)
        self.assertEqual(
            facts.cloud_run_secret_access_paths[0],
            {
                "workload_address": _WORKLOAD_ADDRESS,
                "workload_type": GcpResourceType.CLOUD_RUN_V2_SERVICE,
                "secret_reference": _SECRET_NAME,
                "secret_reference_path": ("template[0].containers[0].env[0].value_source[0].secret_key_ref.secret"),
                "secret_resource_name": _SECRET_NAME,
                "secret_resource_address": _SECRET_ADDRESS,
                "secret_target_resolution": "resolved_in_plan",
                "secret_resolution_basis": "canonical_resource_name",
                "secret_version": "5",
                "secret_version_state": "configured",
                "version_path": ("template[0].containers[0].env[0].value_source[0].secret_key_ref.version"),
                "container_name": "api",
                "setting_name": "DB_PASSWORD",
                "service_account_email": _SERVICE_ACCOUNT_EMAIL,
                "service_account_member": _SERVICE_ACCOUNT_MEMBER,
                "identity_kind": "cloud_run_service_account",
                "credential_context": "workload_runtime",
                "iam_resource_address": "google_secret_manager_secret_iam_member.access",
                "iam_resource_type": GcpResourceType.SECRET_MANAGER_SECRET_IAM_MEMBER,
                "role": "roles/secretmanager.secretAccessor",
                "role_kind": "built_in",
                "custom_role_permissions": [],
                "grant_scope_type": "secret",
                "grant_scope": _SECRET_NAME,
                "grant_basis": "secret_resource_iam",
                "condition": condition[0],
                "condition_state": "configured",
                "access_state": "conditional",
            },
        )
        self.assertEqual(facts.cloud_run_secret_access_path_uncertainties, [])

    def test_project_level_grant_is_connected_to_exact_service_account(self) -> None:
        facts = _workload_facts(_normalize([_cloud_run(), _project_iam_member()]))

        self.assertEqual(len(facts.cloud_run_secret_access_paths), 1)
        path = facts.cloud_run_secret_access_paths[0]
        self.assertEqual(path["secret_target_resolution"], "canonical_name")
        self.assertIsNone(path["secret_resource_address"])
        self.assertEqual(path["grant_scope_type"], "project")
        self.assertEqual(path["grant_scope"], _PROJECT)
        self.assertEqual(path["grant_basis"], "project_iam")
        self.assertEqual(path["access_state"], "granted")

    def test_folder_and_organization_grants_use_modeled_hierarchy_only(self) -> None:
        folder_id = "folders/123456"
        organization_id = "organizations/987654"
        inventory = _normalize(
            [
                _secret(),
                _cloud_run(),
                _iam_resource(
                    GcpResourceType.FOLDER_IAM_MEMBER,
                    "folder_access",
                    folder=folder_id,
                ),
                _iam_resource(
                    GcpResourceType.ORGANIZATION_IAM_MEMBER,
                    "organization_access",
                    org_id=organization_id,
                ),
            ]
        )

        facts = _rerun_path_stage(
            inventory,
            folder_id=folder_id,
            organization_id=organization_id,
        )

        scopes = {
            (path["grant_scope_type"], path["grant_scope"], path["grant_basis"])
            for path in facts.cloud_run_secret_access_paths
        }
        self.assertEqual(
            scopes,
            {
                ("folder", "123456", "folder_iam"),
                ("organization", "987654", "organization_iam"),
            },
        )
        self.assertEqual(facts.cloud_run_secret_access_path_uncertainties, [])

    def test_exact_terraform_secret_reference_resolves_in_plan(self) -> None:
        reference = "$" + "{google_secret_manager_secret.orders.id}"
        facts = _workload_facts(
            _normalize(
                [
                    _secret(),
                    _cloud_run(secret_reference=reference),
                    _project_iam_member(),
                ]
            )
        )

        self.assertEqual(len(facts.cloud_run_secret_access_paths), 1)
        path = facts.cloud_run_secret_access_paths[0]
        self.assertEqual(path["secret_reference"], reference)
        self.assertEqual(path["secret_resource_name"], _SECRET_NAME)
        self.assertEqual(path["secret_resource_address"], _SECRET_ADDRESS)
        self.assertEqual(path["secret_resolution_basis"], "terraform_reference")

    def test_custom_role_with_secret_access_permission_is_connected(self) -> None:
        custom_role_name = f"projects/{_PROJECT}/roles/cloudRunSecretReader"
        custom_role = _terraform_resource(
            "google_project_iam_custom_role.cloud_run_secret_reader",
            GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
            {
                "project": _PROJECT,
                "role_id": "cloudRunSecretReader",
                "name": custom_role_name,
                "permissions": ["secretmanager.versions.access"],
            },
        )
        facts = _workload_facts(
            _normalize(
                [
                    _cloud_run(),
                    custom_role,
                    _project_iam_member(role=custom_role_name),
                ]
            )
        )

        path = facts.cloud_run_secret_access_paths[0]
        self.assertEqual(path["role_kind"], "custom")
        self.assertEqual(path["custom_role_permissions"], ["secretmanager.versions.access"])

    def test_nonmatching_identity_or_project_does_not_create_a_path(self) -> None:
        facts = _workload_facts(
            _normalize(
                [
                    _cloud_run(),
                    _project_iam_member(member="serviceAccount:other@example.iam.gserviceaccount.com"),
                    _project_iam_member(project="other-project"),
                ]
            )
        )

        self.assertEqual(facts.cloud_run_secret_access_paths, [])
        self.assertEqual(facts.cloud_run_secret_access_path_uncertainties, [])

    def test_exact_secret_scope_does_not_require_target_resource_in_plan(self) -> None:
        facts = _workload_facts(_normalize([_cloud_run(), _secret_iam_member()]))

        path = facts.cloud_run_secret_access_paths[0]
        self.assertEqual(path["secret_target_resolution"], "canonical_name")
        self.assertIsNone(path["secret_resource_address"])
        self.assertEqual(path["grant_scope_type"], "secret")
        self.assertEqual(path["grant_scope"], _SECRET_NAME)

    def test_unresolved_iam_member_is_preserved_without_identity_inference(self) -> None:
        unresolved_member = "serviceAccount:" + "$" + "{google_service_account.run.email}"
        facts = _workload_facts(
            _normalize(
                [
                    _cloud_run(),
                    _project_iam_member(member=unresolved_member),
                ]
            )
        )

        self.assertEqual(facts.cloud_run_secret_access_paths, [])
        self.assertEqual(
            facts.cloud_run_secret_access_path_uncertainties,
            [
                f"{_WORKLOAD_ADDRESS}: google_project_iam_member.access has an unresolved IAM member "
                "for roles/secretmanager.secretAccessor"
            ],
        )

    def test_unresolved_service_account_identity_is_preserved(self) -> None:
        service_account_reference = "$" + "{google_service_account.run.email}"
        facts = _workload_facts(
            _normalize(
                [
                    _cloud_run(service_account=service_account_reference),
                    _project_iam_member(),
                ]
            )
        )

        self.assertEqual(facts.cloud_run_secret_access_paths, [])
        self.assertEqual(
            facts.cloud_run_secret_access_path_uncertainties,
            [f"{_WORKLOAD_ADDRESS}: Cloud Run service account identity is unresolved"],
        )

    def test_unresolved_secret_reference_is_preserved_without_name_matching(self) -> None:
        secret_reference = "$" + "{google_secret_manager_secret.missing.id}"
        facts = _workload_facts(
            _normalize(
                [
                    _cloud_run(secret_reference=secret_reference),
                    _secret_iam_member(secret_id="orders-db"),
                    _project_iam_member(),
                ]
            )
        )

        self.assertEqual(facts.cloud_run_secret_access_paths, [])
        self.assertEqual(len(facts.cloud_run_secret_access_path_uncertainties), 1)
        self.assertIn(
            "does not resolve to an exact secret",
            facts.cloud_run_secret_access_path_uncertainties[0],
        )


if __name__ == "__main__":
    unittest.main()
