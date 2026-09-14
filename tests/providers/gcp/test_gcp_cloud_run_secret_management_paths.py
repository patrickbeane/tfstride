from __future__ import annotations

import json
import unittest
from typing import Any

from tfstride.models import (
    TerraformReferenceProvenance,
    TerraformReferenceResolution,
    TerraformReferenceResolutionState,
    TerraformReferenceTarget,
    TerraformResource,
)
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_PROJECT = "tfstride-demo"
_SERVICE_ACCOUNT_EMAIL = f"runtime@{_PROJECT}.iam.gserviceaccount.com"
_SERVICE_ACCOUNT_MEMBER = f"serviceAccount:{_SERVICE_ACCOUNT_EMAIL}"
_SECRET_PATH = f"projects/{_PROJECT}/secrets/orders"
_VERSION_PATH = f"{_SECRET_PATH}/versions/1"
_SECRET_ADDRESS = "google_secret_manager_secret.orders"
_VERSION_ADDRESS = "google_secret_manager_secret_version.orders"
_WORKLOAD_ADDRESS = "google_cloud_run_v2_service.orders"
_PAYLOAD_SENTINEL = "must-never-enter-normalized-metadata"


def _resource(
    resource_type: str,
    name: str,
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
    reference_resolutions: tuple[TerraformReferenceResolution, ...] = (),
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/google",
        values=values,
        unknown_values=unknown_values or {},
        reference_resolutions=reference_resolutions,
    )


def _cloud_run(*, service_account: str = _SERVICE_ACCOUNT_EMAIL) -> TerraformResource:
    return _resource(
        GcpResourceType.CLOUD_RUN_V2_SERVICE,
        "orders",
        {
            "name": "orders",
            "project": _PROJECT,
            "location": "us-central1",
            "template": [
                {
                    "service_account": service_account,
                    "containers": [{"name": "orders", "image": "example/orders:1"}],
                }
            ],
        },
    )


def _secret(
    name: str = "orders",
    *,
    project: str = _PROJECT,
    version_destroy_ttl: str = "604800s",
) -> TerraformResource:
    path = f"projects/{project}/secrets/{name}"
    return _resource(
        GcpResourceType.SECRET_MANAGER_SECRET,
        name,
        {
            "id": path,
            "name": path,
            "project": project,
            "secret_id": name,
            "replication": [{"auto": [{}]}],
            "version_destroy_ttl": version_destroy_ttl,
        },
    )


def _version(
    *,
    secret_reference: str | None = f"{_SECRET_ADDRESS}.id",
    version_path: str | None = _VERSION_PATH,
    enabled: bool | None = True,
    deletion_policy: str = "DELETE",
    unknown_values: dict[str, Any] | None = None,
    destroy_time: str | None = None,
    reference_resolutions: tuple[TerraformReferenceResolution, ...] = (),
) -> TerraformResource:
    values: dict[str, Any] = {
        "secret": secret_reference,
        "id": version_path,
        "name": version_path,
        "version": "1" if version_path is not None else None,
        "enabled": enabled,
        "deletion_policy": deletion_policy,
        "secret_data": _PAYLOAD_SENTINEL,
    }
    if destroy_time is not None:
        values["destroy_time"] = destroy_time
    return _resource(
        GcpResourceType.SECRET_MANAGER_SECRET_VERSION,
        "orders",
        values,
        unknown_values=unknown_values,
        reference_resolutions=reference_resolutions,
    )


def _symbolic_secret_parent_resolution(
    target_attribute: str = ".id",
) -> TerraformReferenceResolution:
    reference = f"{_SECRET_ADDRESS}{target_attribute}"
    return TerraformReferenceResolution(
        path=("secret",),
        state=TerraformReferenceResolutionState.SYMBOLIC,
        provenance=TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
        references=(reference,),
        targets=(
            TerraformReferenceTarget(
                address=_SECRET_ADDRESS,
                reference=reference,
            ),
        ),
    )


def _project_member(
    *,
    role: str = "roles/secretmanager.admin",
    member: str = _SERVICE_ACCOUNT_MEMBER,
    project: str = _PROJECT,
    name: str = "runtime",
) -> TerraformResource:
    return _resource(
        GcpResourceType.PROJECT_IAM_MEMBER,
        name,
        {
            "project": project,
            "role": role,
            "member": member,
        },
    )


def _unknown_project_policy() -> TerraformResource:
    return _resource(
        GcpResourceType.PROJECT_IAM_POLICY,
        "unknown_lifecycle_policy",
        {
            "project": _PROJECT,
            "policy_data": None,
        },
        unknown_values={"policy_data": True},
    )


def _secret_member(
    *,
    role: str,
    member: str = _SERVICE_ACCOUNT_MEMBER,
    name: str = "runtime",
    secret_reference: str | None = _SECRET_PATH,
    condition: dict[str, str] | None = None,
    unknown_values: dict[str, Any] | None = None,
    reference_resolutions: tuple[TerraformReferenceResolution, ...] = (),
) -> TerraformResource:
    values: dict[str, Any] = {
        "project": _PROJECT,
        "secret_id": secret_reference,
        "role": role,
        "member": member,
    }
    if condition is not None:
        values["condition"] = [condition]
    return _resource(
        GcpResourceType.SECRET_MANAGER_SECRET_IAM_MEMBER,
        name,
        values,
        unknown_values=unknown_values,
        reference_resolutions=reference_resolutions,
    )


def _symbolic_secret_iam_resolution(
    target_attribute: str,
) -> TerraformReferenceResolution:
    reference = f"{_SECRET_ADDRESS}{target_attribute}"
    return TerraformReferenceResolution(
        path=("secret_id",),
        state=TerraformReferenceResolutionState.SYMBOLIC,
        provenance=TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
        references=(reference,),
        targets=(
            TerraformReferenceTarget(
                address=_SECRET_ADDRESS,
                reference=reference,
            ),
        ),
    )


def _secret_binding(*, role: str) -> TerraformResource:
    return _resource(
        GcpResourceType.SECRET_MANAGER_SECRET_IAM_BINDING,
        "runtime",
        {
            "project": _PROJECT,
            "secret_id": _SECRET_PATH,
            "role": role,
            "members": [_SERVICE_ACCOUNT_MEMBER],
        },
    )


def _custom_role(
    permissions: list[str],
    *,
    name: str = "runtime_secret_lifecycle",
    permissions_unknown: bool = False,
) -> tuple[str, TerraformResource]:
    role = f"projects/{_PROJECT}/roles/runtimeSecretLifecycle"
    return role, _resource(
        GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
        name,
        {
            "id": role,
            "name": role,
            "project": _PROJECT,
            "role_id": "runtimeSecretLifecycle",
            "permissions": permissions,
        },
        unknown_values={"permissions": True} if permissions_unknown else None,
    )


def _normalize(resources: list[TerraformResource]):
    return GcpNormalizer().normalize(resources)


def _workload_facts(inventory):
    workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
    assert workload is not None
    return gcp_facts(workload)


class GcpCloudRunSecretManagementPathTests(unittest.TestCase):
    def test_project_admin_projects_exact_secret_and_version_lifecycle_paths(
        self,
    ) -> None:
        inventory = _normalize([_cloud_run(), _secret(), _version(), _project_member()])
        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        secret = inventory.get_by_address(_SECRET_ADDRESS)
        version = inventory.get_by_address(_VERSION_ADDRESS)
        assert workload is not None
        assert secret is not None
        assert version is not None

        self.assertFalse(workload.public_exposure)
        version_facts = gcp_facts(version)
        self.assertEqual(version.identifier, _VERSION_PATH)
        self.assertEqual(
            version_facts.secret_manager_version_resolved_secret_address,
            _SECRET_ADDRESS,
        )
        self.assertEqual(
            version_facts.secret_manager_version_lifecycle_state,
            "enabled",
        )
        self.assertEqual(
            version_facts.secret_manager_version_deletion_policy,
            "DELETE",
        )
        self.assertNotIn(
            _PAYLOAD_SENTINEL,
            json.dumps(dict(version.metadata), sort_keys=True),
        )

        secret_facts = gcp_facts(secret)
        self.assertEqual(len(secret_facts.secret_manager_iam_grants), 1)
        grant = secret_facts.secret_manager_iam_grants[0]
        self.assertEqual(grant["scope_type"], "project")
        self.assertEqual(grant["scope"], _PROJECT)
        self.assertEqual(grant["grant_basis"], "project_iam")
        self.assertEqual(grant["authorization_state"], "granted")
        self.assertEqual(grant["management_state"], "unambiguous")

        facts = gcp_facts(workload)
        paths = facts.cloud_run_secret_management_paths
        self.assertEqual(
            {path["operation"] for path in paths},
            {
                "secretmanager.versions.add",
                "secretmanager.versions.disable",
                "secretmanager.versions.destroy",
                "secretmanager.secrets.delete",
            },
        )
        self.assertEqual(facts.cloud_run_secret_management_path_uncertainties, [])
        for path in paths:
            self.assertEqual(path["service_account_member"], _SERVICE_ACCOUNT_MEMBER)
            self.assertEqual(path["scope_type"], "project")
            self.assertEqual(path["scope"], _PROJECT)
            self.assertEqual(path["authorization_state"], "granted")
            self.assertFalse(path["iam_scope_is_secret_version"])
            self.assertEqual(path["version_destroy_ttl"], "604800s")
            self.assertEqual(path["iam_grant_record"], grant)

        version_paths = [path for path in paths if path["target_type"] == "secret_version"]
        self.assertEqual(len(version_paths), 2)
        self.assertTrue(all(path["target_address"] == _VERSION_ADDRESS for path in version_paths))
        self.assertTrue(all(path["target_resource_name"] == _VERSION_PATH for path in version_paths))
        self.assertTrue(all(path["lifecycle_compatibility_state"] == "compatible" for path in version_paths))
        self.assertTrue(all(path["secret_version"] is not None for path in version_paths))

    def test_symbolic_secret_parent_resolves_first_apply_lifecycle_paths(
        self,
    ) -> None:
        inventory = _normalize(
            [
                _cloud_run(),
                _secret(),
                _version(
                    secret_reference=None,
                    unknown_values={"secret": True},
                    reference_resolutions=(_symbolic_secret_parent_resolution(),),
                ),
                _project_member(),
            ]
        )
        version = inventory.get_by_address(_VERSION_ADDRESS)
        assert version is not None

        version_facts = gcp_facts(version)
        self.assertEqual(
            version_facts.secret_manager_version_resolved_secret_address,
            _SECRET_ADDRESS,
        )
        self.assertNotIn(
            "secret is unknown after planning",
            version_facts.secret_manager_version_posture_uncertainties,
        )
        self.assertEqual(
            {path["operation"] for path in _workload_facts(inventory).cloud_run_secret_management_paths},
            {
                "secretmanager.versions.add",
                "secretmanager.versions.disable",
                "secretmanager.versions.destroy",
                "secretmanager.secrets.delete",
            },
        )

    def test_symbolic_secret_parent_name_is_not_promoted_by_fallback(
        self,
    ) -> None:
        inventory = _normalize(
            [
                _cloud_run(),
                _secret(),
                _version(
                    secret_reference=f"{_SECRET_ADDRESS}.name",
                    version_path=None,
                    reference_resolutions=(_symbolic_secret_parent_resolution(".name"),),
                ),
                _project_member(),
            ]
        )
        version = inventory.get_by_address(_VERSION_ADDRESS)
        assert version is not None

        self.assertIsNone(gcp_facts(version).secret_manager_version_resolved_secret_address)
        paths = _workload_facts(inventory).cloud_run_secret_management_paths
        self.assertEqual(
            {path["operation"] for path in paths},
            {
                "secretmanager.versions.add",
                "secretmanager.secrets.delete",
            },
        )
        self.assertFalse(any(path["target_type"] == "secret_version" for path in paths))

    def test_project_scope_fans_only_to_exact_same_project_secrets(self) -> None:
        inventory = _normalize(
            [
                _cloud_run(),
                _secret(),
                _version(),
                _secret("audit"),
                _secret("foreign", project="foreign-project"),
                _project_member(),
            ]
        )

        paths = _workload_facts(inventory).cloud_run_secret_management_paths
        self.assertEqual(
            {path["secret_address"] for path in paths},
            {
                _SECRET_ADDRESS,
                "google_secret_manager_secret.audit",
            },
        )
        self.assertFalse(any(path["secret_address"] == "google_secret_manager_secret.foreign" for path in paths))

    def test_secret_version_manager_preserves_secret_scope_and_keeps_delete_quiet(
        self,
    ) -> None:
        inventory = _normalize(
            [
                _cloud_run(),
                _secret(),
                _version(),
                _secret_member(role="roles/secretmanager.secretVersionManager"),
            ]
        )

        paths = _workload_facts(inventory).cloud_run_secret_management_paths
        self.assertEqual(
            {path["operation"] for path in paths},
            {
                "secretmanager.versions.add",
                "secretmanager.versions.disable",
                "secretmanager.versions.destroy",
            },
        )
        self.assertTrue(all(path["scope_type"] == "secret" for path in paths))
        self.assertTrue(all(path["scope"] == _SECRET_PATH for path in paths))
        self.assertTrue(all(path["grant_basis"] == "secret_resource_iam" for path in paths))

    def test_secret_iam_target_suffix_is_enforced_end_to_end(self) -> None:
        for target_attribute in (".id", ".name"):
            with self.subTest(target_attribute=target_attribute):
                iam_resource = _secret_member(
                    role="roles/secretmanager.secretVersionManager",
                    secret_reference=f"{_SECRET_ADDRESS}{target_attribute}",
                    reference_resolutions=(_symbolic_secret_iam_resolution(target_attribute),),
                )
                inventory = _normalize([_cloud_run(), _secret(), _version(), iam_resource])
                secret = inventory.get_by_address(_SECRET_ADDRESS)
                assert secret is not None

                self.assertEqual(gcp_facts(secret).secret_manager_iam_grants, [])
                self.assertEqual(
                    _workload_facts(inventory).cloud_run_secret_management_paths,
                    [],
                )

        exact_inventory = _normalize(
            [
                _cloud_run(),
                _secret(),
                _version(),
                _secret_member(
                    role="roles/secretmanager.secretVersionManager",
                    secret_reference=f"{_SECRET_ADDRESS}.secret_id",
                    reference_resolutions=(_symbolic_secret_iam_resolution(".secret_id"),),
                ),
            ]
        )
        exact_secret = exact_inventory.get_by_address(_SECRET_ADDRESS)
        assert exact_secret is not None

        self.assertEqual(len(gcp_facts(exact_secret).secret_manager_iam_grants), 1)
        self.assertEqual(
            {path["operation"] for path in _workload_facts(exact_inventory).cloud_run_secret_management_paths},
            {
                "secretmanager.versions.add",
                "secretmanager.versions.disable",
                "secretmanager.versions.destroy",
            },
        )

    def test_disabled_version_allows_destroy_but_not_disable(self) -> None:
        role, custom_role = _custom_role(
            [
                "secretmanager.versions.disable",
                "secretmanager.versions.destroy",
            ]
        )
        facts = _workload_facts(
            _normalize(
                [
                    _cloud_run(),
                    _secret(),
                    _version(enabled=False),
                    custom_role,
                    _secret_member(role=role),
                ]
            )
        )

        self.assertEqual(
            [path["operation"] for path in facts.cloud_run_secret_management_paths],
            ["secretmanager.versions.destroy"],
        )
        path = facts.cloud_run_secret_management_paths[0]
        self.assertEqual(path["role_kind"], "custom")
        self.assertEqual(
            path["role_definition_address"],
            "google_project_iam_custom_role.runtime_secret_lifecycle",
        )
        assert path["secret_version"] is not None
        self.assertEqual(path["secret_version"]["lifecycle_state"], "disabled")

    def test_conflicting_custom_roles_do_not_create_management_paths_in_either_order(self) -> None:
        role, privileged = _custom_role(
            ["secretmanager.versions.destroy"],
            name="privileged",
        )
        _, benign = _custom_role(
            ["secretmanager.versions.get"],
            name="benign",
        )
        snapshots: list[tuple[object, ...]] = []

        for case, definitions in {
            "privileged first": [privileged, benign],
            "benign first": [benign, privileged],
        }.items():
            with self.subTest(case=case):
                inventory = _normalize(
                    [
                        _cloud_run(),
                        _secret(),
                        _version(),
                        *definitions,
                        _secret_member(role=role),
                    ]
                )
                facts = _workload_facts(inventory)
                secret_resource = inventory.get_by_address(_SECRET_ADDRESS)
                assert secret_resource is not None
                grants = gcp_facts(secret_resource).secret_manager_iam_grants

                self.assertEqual(facts.cloud_run_secret_management_paths, [])
                self.assertEqual(len(grants), 1)
                self.assertEqual(grants[0]["role_resolution_state"], "ambiguous")
                self.assertEqual(grants[0]["modeled_secret_permissions"], [])
                self.assertNotIn("role_definition_address", grants[0])
                self.assertTrue(
                    any(
                        "Secret Manager role permissions are unresolved" in uncertainty
                        for uncertainty in facts.cloud_run_secret_management_path_uncertainties
                    )
                )
                snapshots.append(
                    (
                        grants[0],
                        tuple(facts.cloud_run_secret_management_path_uncertainties),
                    )
                )

        self.assertEqual(snapshots[0], snapshots[1])

    def test_unknown_version_lifecycle_remains_uncertain(self) -> None:
        role, custom_role = _custom_role(["secretmanager.versions.destroy"])
        facts = _workload_facts(
            _normalize(
                [
                    _cloud_run(),
                    _secret(),
                    _version(enabled=None, unknown_values={"enabled": True}),
                    custom_role,
                    _secret_member(role=role),
                ]
            )
        )

        self.assertEqual(facts.cloud_run_secret_management_paths, [])
        self.assertTrue(
            any(
                "lifecycle compatibility" in uncertainty
                for uncertainty in facts.cloud_run_secret_management_path_uncertainties
            )
        )

    def test_conditional_and_ambiguous_iam_fail_closed(self) -> None:
        condition = {
            "title": "deployment-window",
            "expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
        }
        cases = {
            "conditional": [
                _secret_member(
                    role="roles/secretmanager.admin",
                    condition=condition,
                )
            ],
            "overlapping managers": [
                _secret_member(role="roles/secretmanager.admin"),
                _secret_binding(role="roles/secretmanager.admin"),
            ],
            "unknown authoritative policy": [
                _project_member(),
                _unknown_project_policy(),
            ],
        }

        for case, iam_resources in cases.items():
            with self.subTest(case=case):
                facts = _workload_facts(_normalize([_cloud_run(), _secret(), _version(), *iam_resources]))
                self.assertEqual(facts.cloud_run_secret_management_paths, [])
                self.assertTrue(facts.cloud_run_secret_management_path_uncertainties)

    def test_unknown_member_and_custom_role_permissions_remain_uncertain(self) -> None:
        unresolved_member = "serviceAccount:${google_service_account.runtime.email}"
        role, custom_role = _custom_role(
            ["secretmanager.versions.add"],
            permissions_unknown=True,
        )
        facts = _workload_facts(
            _normalize(
                [
                    _cloud_run(),
                    _secret(),
                    _version(),
                    custom_role,
                    _secret_member(
                        role=role,
                        member=unresolved_member,
                        unknown_values={"member": True},
                    ),
                ]
            )
        )

        self.assertEqual(facts.cloud_run_secret_management_paths, [])
        self.assertTrue(facts.cloud_run_secret_management_path_uncertainties)

    def test_other_runtime_member_and_quiet_roles_stay_quiet(self) -> None:
        cases = {
            "other member": _project_member(member=f"serviceAccount:other@{_PROJECT}.iam.gserviceaccount.com"),
            "secret accessor": _project_member(role="roles/secretmanager.secretAccessor"),
            "viewer": _project_member(role="roles/secretmanager.viewer"),
        }
        for case, iam_resource in cases.items():
            with self.subTest(case=case):
                facts = _workload_facts(_normalize([_cloud_run(), _secret(), _version(), iam_resource]))
                self.assertEqual(facts.cloud_run_secret_management_paths, [])
                self.assertEqual(
                    facts.cloud_run_secret_management_path_uncertainties,
                    [],
                )

    def test_unresolved_version_identity_is_gated_by_runtime_version_authority(
        self,
    ) -> None:
        role, custom_role = _custom_role(["secretmanager.versions.destroy"])
        runtime_facts = _workload_facts(
            _normalize(
                [
                    _cloud_run(),
                    _secret(),
                    _version(version_path=None),
                    custom_role,
                    _secret_member(role=role),
                ]
            )
        )
        self.assertEqual(runtime_facts.cloud_run_secret_management_paths, [])
        self.assertTrue(
            any(
                "unresolved exact identity" in uncertainty
                for uncertainty in runtime_facts.cloud_run_secret_management_path_uncertainties
            )
        )

        other_facts = _workload_facts(
            _normalize(
                [
                    _cloud_run(),
                    _secret(),
                    _version(version_path=None),
                    custom_role,
                    _secret_member(
                        role=role,
                        member=f"serviceAccount:other@{_PROJECT}.iam.gserviceaccount.com",
                    ),
                ]
            )
        )
        self.assertEqual(other_facts.cloud_run_secret_management_paths, [])
        self.assertEqual(
            other_facts.cloud_run_secret_management_path_uncertainties,
            [],
        )

    def test_conflicting_version_parent_evidence_does_not_create_a_version_path(
        self,
    ) -> None:
        role, custom_role = _custom_role(["secretmanager.versions.destroy"])
        references = (
            "google_secret_manager_secret.audit.id",
            f"projects/{_PROJECT}/secrets/audit",
        )
        for secret_reference in references:
            with self.subTest(secret_reference=secret_reference):
                facts = _workload_facts(
                    _normalize(
                        [
                            _cloud_run(),
                            _secret(),
                            _secret("audit"),
                            _version(secret_reference=secret_reference),
                            custom_role,
                            _project_member(role=role),
                        ]
                    )
                )

                self.assertEqual(facts.cloud_run_secret_management_paths, [])
                self.assertTrue(
                    any(
                        "unresolved exact identity or secret ancestry" in uncertainty
                        for uncertainty in facts.cloud_run_secret_management_path_uncertainties
                    )
                )

    def test_unresolved_cloud_run_identity_remains_uncertain(self) -> None:
        facts = _workload_facts(
            _normalize(
                [
                    _cloud_run(service_account="${google_service_account.runtime.email}"),
                    _secret(),
                    _version(),
                    _project_member(),
                ]
            )
        )

        self.assertEqual(facts.cloud_run_secret_management_paths, [])
        self.assertEqual(
            facts.cloud_run_secret_management_path_uncertainties,
            [f"{_WORKLOAD_ADDRESS}: Cloud Run service account identity is unresolved"],
        )


if __name__ == "__main__":
    unittest.main()
