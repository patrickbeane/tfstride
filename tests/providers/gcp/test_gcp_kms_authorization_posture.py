from __future__ import annotations

import json
import unittest
from typing import Any

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_PROJECT = "tfstride-demo"
_KEY_RING = f"projects/{_PROJECT}/locations/global/keyRings/application"
_KEY_PATH = f"{_KEY_RING}/cryptoKeys/customer"
_RUNTIME_MEMBER = "serviceAccount:orders@tfstride-demo.iam.gserviceaccount.com"


def _key(
    *,
    address: str = "google_kms_crypto_key.customer",
    name: str = "customer",
    key_ring: str = _KEY_RING,
    key_id: str | None = None,
) -> TerraformResource:
    return _terraform_resource(
        address,
        GcpResourceType.KMS_CRYPTO_KEY,
        {
            "id": key_id or f"{key_ring}/cryptoKeys/{name}",
            "name": name,
            "key_ring": key_ring,
            "purpose": "ENCRYPT_DECRYPT",
        },
    )


def _ring(address: str) -> TerraformResource:
    return _terraform_resource(
        address,
        GcpResourceType.KMS_KEY_RING,
        {
            "id": _KEY_RING,
            "name": "application",
            "project": _PROJECT,
            "location": "global",
        },
    )


def _custom_role(address: str, permissions: list[str]) -> TerraformResource:
    return _terraform_resource(
        address,
        GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
        {
            "project": _PROJECT,
            "role_id": "runtimeCrypto",
            "permissions": permissions,
        },
    )


def _project_member(
    address: str,
    *,
    project: str | None = _PROJECT,
    role: str | None = "roles/cloudkms.cryptoKeyDecrypter",
    member: str | None = _RUNTIME_MEMBER,
    condition: list[dict[str, str]] | None = None,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {}
    if project is not None:
        values["project"] = project
    if role is not None:
        values["role"] = role
    if member is not None:
        values["member"] = member
    if condition is not None:
        values["condition"] = condition
    return _terraform_resource(
        address,
        GcpResourceType.PROJECT_IAM_MEMBER,
        values,
        unknown_values=unknown_values,
    )


def _ring_binding(
    address: str,
    *,
    key_ring: str | None = _KEY_RING,
    role: str = "roles/cloudkms.admin",
    condition: list[dict[str, str]] | None = None,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "role": role,
        "members": ["group:key-operators@example.com"],
    }
    if key_ring is not None:
        values["key_ring_id"] = key_ring
    if condition is not None:
        values["condition"] = condition
    return _terraform_resource(
        address,
        GcpResourceType.KMS_KEY_RING_IAM_BINDING,
        values,
        unknown_values=unknown_values,
    )


def _key_member(
    address: str,
    *,
    key_reference: str | None = "google_kms_crypto_key.customer.id",
    role: str | None = "roles/cloudkms.cryptoKeyEncrypter",
    member: str | None = _RUNTIME_MEMBER,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {}
    if key_reference is not None:
        values["crypto_key_id"] = key_reference
    if role is not None:
        values["role"] = role
    if member is not None:
        values["member"] = member
    return _terraform_resource(
        address,
        GcpResourceType.KMS_CRYPTO_KEY_IAM_MEMBER,
        values,
        unknown_values=unknown_values,
    )


class GcpKmsAuthorizationPostureTests(unittest.TestCase):
    def test_project_ring_and_key_grants_preserve_native_scope_and_conditions(self) -> None:
        ring_condition = {
            "title": "business-hours",
            "expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
        }
        inventory = GcpNormalizer().normalize(
            [
                _key(),
                _project_member("google_project_iam_member.runtime_decrypter"),
                _ring_binding(
                    "google_kms_key_ring_iam_binding.operators",
                    condition=[ring_condition],
                ),
                _key_member(
                    "google_kms_crypto_key_iam_member.runtime_encrypter",
                    unknown_values={"condition": True},
                ),
            ]
        )
        key = inventory.get_by_address("google_kms_crypto_key.customer")
        assert key is not None

        facts = gcp_facts(key)
        grants = {grant["source"]: grant for grant in facts.kms_iam_grants}
        self.assertEqual(
            set(grants),
            {
                "google_project_iam_member.runtime_decrypter",
                "google_kms_key_ring_iam_binding.operators",
                "google_kms_crypto_key_iam_member.runtime_encrypter",
            },
        )

        project_grant = grants["google_project_iam_member.runtime_decrypter"]
        self.assertEqual(project_grant["scope_type"], "project")
        self.assertEqual(project_grant["scope"], _PROJECT)
        self.assertEqual(project_grant["authorization_state"], "granted")
        self.assertEqual(project_grant["role_resolution_state"], "modeled_subset")
        self.assertEqual(project_grant["management_mode"], "additive_member")
        self.assertEqual(project_grant["management_state"], "unambiguous")
        self.assertEqual(
            project_grant["scope_effective_permissions"],
            ["cloudkms.cryptoKeyVersions.useToDecrypt"],
        )

        ring_grant = grants["google_kms_key_ring_iam_binding.operators"]
        self.assertEqual(ring_grant["scope_type"], "key_ring")
        self.assertEqual(ring_grant["scope"], _KEY_RING)
        self.assertEqual(ring_grant["condition_state"], "configured")
        self.assertEqual(ring_grant["authorization_state"], "conditional")
        self.assertEqual(ring_grant["condition"], ring_condition)
        self.assertIn("cloudkms.cryptoKeyVersions.destroy", ring_grant["scope_effective_permissions"])
        self.assertIn("cloudkms.cryptoKeys.setIamPolicy", ring_grant["scope_effective_permissions"])

        key_grant = grants["google_kms_crypto_key_iam_member.runtime_encrypter"]
        self.assertEqual(key_grant["scope_type"], "crypto_key")
        self.assertEqual(key_grant["scope"], _KEY_PATH)
        self.assertEqual(key_grant["condition_state"], "unknown")
        self.assertEqual(key_grant["authorization_state"], "unknown")
        self.assertTrue(
            any("condition applicability" in uncertainty for uncertainty in facts.kms_iam_posture_uncertainties)
        )

    def test_shared_terraform_ring_reference_resolves_to_canonical_scope(self) -> None:
        ring_reference = "google_kms_key_ring.application.id"
        inventory = GcpNormalizer().normalize(
            [
                _key(key_ring=ring_reference, key_id=_KEY_PATH),
                _ring_binding(
                    "google_kms_key_ring_iam_binding.operators",
                    key_ring=ring_reference,
                ),
            ]
        )
        key = inventory.get_by_address("google_kms_crypto_key.customer")
        assert key is not None

        grant = gcp_facts(key).kms_iam_grants[0]
        self.assertEqual(grant["scope_type"], "key_ring")
        self.assertEqual(grant["scope"], _KEY_RING)
        self.assertEqual(grant["source_scope_reference"], ring_reference)

    def test_custom_role_preserves_full_and_kms_permissions(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _key(),
                _terraform_resource(
                    "google_project_iam_custom_role.runtime_crypto",
                    GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
                    {
                        "project": _PROJECT,
                        "role_id": "runtimeCrypto",
                        "name": f"projects/{_PROJECT}/roles/runtimeCrypto",
                        "permissions": [
                            "cloudkms.cryptoKeyVersions.useToDecrypt",
                            "cloudkms.cryptoKeyVersions.useToEncrypt",
                            "storage.objects.get",
                        ],
                    },
                ),
                _project_member(
                    "google_project_iam_member.runtime_custom",
                    role="google_project_iam_custom_role.runtime_crypto.id",
                ),
            ]
        )
        key = inventory.get_by_address("google_kms_crypto_key.customer")
        assert key is not None

        grant = gcp_facts(key).kms_iam_grants[0]
        self.assertEqual(grant["role_kind"], "custom")
        self.assertEqual(grant["role_resolution_state"], "resolved")
        self.assertEqual(
            grant["modeled_kms_permissions"],
            [
                "cloudkms.cryptoKeyVersions.useToDecrypt",
                "cloudkms.cryptoKeyVersions.useToEncrypt",
            ],
        )
        self.assertEqual(
            grant["scope_effective_permissions"],
            [
                "cloudkms.cryptoKeyVersions.useToDecrypt",
                "cloudkms.cryptoKeyVersions.useToEncrypt",
            ],
        )
        self.assertEqual(
            grant["custom_role_permissions"],
            [
                "cloudkms.cryptoKeyVersions.useToDecrypt",
                "cloudkms.cryptoKeyVersions.useToEncrypt",
                "storage.objects.get",
            ],
        )
        self.assertEqual(
            grant["role_definition_address"],
            "google_project_iam_custom_role.runtime_crypto",
        )

    def test_conflicting_duplicate_custom_roles_are_ambiguous_in_both_orders(self) -> None:
        role = f"projects/{_PROJECT}/roles/runtimeCrypto"
        privileged = _custom_role(
            "google_project_iam_custom_role.privileged",
            ["cloudkms.cryptoKeyVersions.useToDecrypt"],
        )
        benign = _custom_role(
            "google_project_iam_custom_role.benign",
            ["storage.objects.get"],
        )
        snapshots: list[tuple[object, ...]] = []

        for case, definitions in {
            "privileged first": [privileged, benign],
            "benign first": [benign, privileged],
        }.items():
            with self.subTest(case=case):
                inventory = GcpNormalizer().normalize(
                    [
                        _key(),
                        *definitions,
                        _key_member(
                            "google_kms_crypto_key_iam_member.runtime",
                            role=role,
                        ),
                    ]
                )
                key = inventory.get_by_address("google_kms_crypto_key.customer")
                assert key is not None

                facts = gcp_facts(key)
                self.assertEqual(len(facts.kms_iam_grants), 1)
                grant = facts.kms_iam_grants[0]
                self.assertEqual(grant["role_resolution_state"], "ambiguous")
                self.assertEqual(grant["modeled_kms_permissions"], [])
                self.assertEqual(grant["authorization_state"], "unknown")
                self.assertNotIn("role_definition_address", grant)
                self.assertTrue(
                    any(
                        f"permissions for IAM role {role} are ambiguous" in uncertainty
                        for uncertainty in facts.kms_iam_posture_uncertainties
                    )
                )
                snapshots.append((grant, tuple(facts.kms_iam_posture_uncertainties)))

        self.assertEqual(snapshots[0], snapshots[1])

    def test_unresolved_inherited_policy_and_role_evidence_remains_uncertain(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _key(),
                _terraform_resource(
                    "google_project_iam_policy.unknown",
                    GcpResourceType.PROJECT_IAM_POLICY,
                    {"project": _PROJECT},
                    unknown_values={"policy_data": True},
                ),
                _ring_binding(
                    "google_kms_key_ring_iam_binding.unknown_ring",
                    key_ring=None,
                    unknown_values={"key_ring_id": True},
                ),
                _key_member(
                    "google_kms_crypto_key_iam_member.unknown_role",
                    role=None,
                    unknown_values={"role": True},
                ),
                _project_member(
                    "google_project_iam_member.external_custom",
                    role="projects/external/roles/runtimeCrypto",
                ),
            ]
        )
        key = inventory.get_by_address("google_kms_crypto_key.customer")
        assert key is not None

        facts = gcp_facts(key)
        self.assertEqual(
            [grant["source"] for grant in facts.kms_iam_grants],
            ["google_project_iam_member.external_custom"],
        )
        self.assertEqual(facts.kms_iam_grants[0]["role_resolution_state"], "external_or_unresolved")
        self.assertEqual(facts.kms_iam_grants[0]["authorization_state"], "unknown")
        self.assertTrue(any("IAM policy_data is unknown" in item for item in facts.kms_iam_posture_uncertainties))
        self.assertTrue(
            any("unknown_ring: IAM scope is unresolved" in item for item in facts.kms_iam_posture_uncertainties)
        )
        self.assertTrue(
            any("unknown_role: IAM role is unresolved" in item for item in facts.kms_iam_posture_uncertainties)
        )
        self.assertTrue(any("external_or_unresolved" in item for item in facts.kms_iam_posture_uncertainties))

    def test_unknown_custom_permissions_do_not_become_authoritative(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _key(),
                _terraform_resource(
                    "google_project_iam_custom_role.unknown",
                    GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
                    {
                        "project": _PROJECT,
                        "role_id": "unknownCrypto",
                        "name": f"projects/{_PROJECT}/roles/unknownCrypto",
                        "permissions": ["cloudkms.cryptoKeyVersions.useToDecrypt"],
                    },
                    unknown_values={"permissions": True},
                ),
                _project_member(
                    "google_project_iam_member.unknown_custom",
                    role="google_project_iam_custom_role.unknown.id",
                ),
            ]
        )
        key = inventory.get_by_address("google_kms_crypto_key.customer")
        assert key is not None

        facts = gcp_facts(key)
        self.assertEqual(len(facts.kms_iam_grants), 1)
        grant = facts.kms_iam_grants[0]
        self.assertEqual(grant["role_kind"], "custom")
        self.assertEqual(grant["role_resolution_state"], "unknown")
        self.assertEqual(grant["modeled_kms_permissions"], [])
        self.assertEqual(grant["scope_effective_permissions"], [])
        self.assertEqual(grant["authorization_state"], "unknown")
        role = inventory.get_by_address("google_project_iam_custom_role.unknown")
        assert role is not None
        self.assertEqual(gcp_facts(role).custom_role_permissions, [])
        self.assertEqual(gcp_facts(role).custom_role_permissions_state, "unknown")

    def test_resolved_non_kms_custom_role_does_not_attach_to_key(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _key(),
                _terraform_resource(
                    "google_project_iam_custom_role.storage_reader",
                    GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
                    {
                        "project": _PROJECT,
                        "role_id": "storageReader",
                        "name": f"projects/{_PROJECT}/roles/storageReader",
                        "permissions": ["storage.objects.get"],
                    },
                ),
                _project_member(
                    "google_project_iam_member.storage_reader",
                    role="google_project_iam_custom_role.storage_reader.id",
                ),
            ]
        )
        key = inventory.get_by_address("google_kms_crypto_key.customer")
        assert key is not None

        facts = gcp_facts(key)
        self.assertEqual(facts.kms_iam_grants, [])
        self.assertEqual(facts.kms_iam_posture_uncertainties, [])

    def test_unmodeled_predefined_role_remains_uncertain(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _key(),
                _project_member(
                    "google_project_iam_member.container_kms_user",
                    role="roles/container.cloudKmsKeyUser",
                ),
            ]
        )
        key = inventory.get_by_address("google_kms_crypto_key.customer")
        assert key is not None

        facts = gcp_facts(key)
        self.assertEqual(len(facts.kms_iam_grants), 1)
        grant = facts.kms_iam_grants[0]
        self.assertEqual(grant["role_kind"], "predefined")
        self.assertEqual(grant["role_resolution_state"], "unmodeled")
        self.assertEqual(grant["modeled_kms_permissions"], [])
        self.assertEqual(grant["scope_effective_permissions"], [])
        self.assertEqual(grant["authorization_state"], "unknown")
        self.assertTrue(
            any(
                "roles/container.cloudKmsKeyUser" in uncertainty and "unmodeled" in uncertainty
                for uncertainty in facts.kms_iam_posture_uncertainties
            )
        )

    def test_known_other_scopes_do_not_attach_to_modeled_key(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _key(),
                _project_member(
                    "google_project_iam_member.other_project",
                    project="other-project",
                ),
                _ring_binding(
                    "google_kms_key_ring_iam_binding.other_ring",
                    key_ring=f"projects/{_PROJECT}/locations/global/keyRings/other",
                ),
                _key_member(
                    "google_kms_crypto_key_iam_member.external_key",
                    key_reference=f"{_KEY_RING}/cryptoKeys/external",
                ),
            ]
        )
        key = inventory.get_by_address("google_kms_crypto_key.customer")
        assert key is not None

        facts = gcp_facts(key)
        self.assertEqual(facts.kms_iam_grants, [])
        self.assertEqual(facts.kms_iam_posture_uncertainties, [])

    def test_duplicate_exact_crypto_key_target_does_not_attach_iam(self) -> None:
        addresses = (
            "google_kms_crypto_key.first",
            "google_kms_crypto_key.second",
        )
        inventory = GcpNormalizer().normalize(
            [
                *(_key(address=address) for address in addresses),
                _key_member(
                    "google_kms_crypto_key_iam_member.ambiguous",
                    key_reference=_KEY_PATH,
                ),
            ]
        )

        for address in addresses:
            with self.subTest(address=address):
                key = inventory.get_by_address(address)
                assert key is not None
                self.assertEqual(gcp_facts(key).bindings, [])
                self.assertEqual(gcp_facts(key).kms_iam_grants, [])

    def test_duplicate_exact_key_ring_target_does_not_attach_iam(self) -> None:
        addresses = (
            "google_kms_key_ring.first",
            "google_kms_key_ring.second",
        )
        inventory = GcpNormalizer().normalize(
            [
                *(_ring(address) for address in addresses),
                _key(),
                _ring_binding(
                    "google_kms_key_ring_iam_binding.ambiguous",
                    key_ring=_KEY_RING,
                ),
            ]
        )

        for address in addresses:
            with self.subTest(address=address):
                key_ring = inventory.get_by_address(address)
                assert key_ring is not None
                self.assertEqual(gcp_facts(key_ring).kms_key_ring_iam_grants, [])

        key = inventory.get_by_address("google_kms_crypto_key.customer")
        assert key is not None
        self.assertEqual(gcp_facts(key).bindings, [])
        self.assertEqual(gcp_facts(key).kms_iam_grants, [])

    def test_key_scope_filters_modeled_role_permissions_to_key_resources(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _key(),
                _key_member(
                    "google_kms_crypto_key_iam_member.key_admin",
                    role="roles/cloudkms.admin",
                ),
            ]
        )
        key = inventory.get_by_address("google_kms_crypto_key.customer")
        assert key is not None

        grant = gcp_facts(key).kms_iam_grants[0]
        self.assertIn(
            "cloudkms.keyRings.setIamPolicy",
            grant["modeled_kms_permissions"],
        )
        self.assertNotIn(
            "cloudkms.keyRings.setIamPolicy",
            grant["scope_effective_permissions"],
        )
        self.assertIn(
            "cloudkms.cryptoKeyVersions.destroy",
            grant["scope_effective_permissions"],
        )

    def test_policy_binding_preserves_condition_and_policy_source_state(self) -> None:
        condition = {
            "title": "version-one-only",
            "expression": "resource.name.endsWith('/cryptoKeyVersions/1')",
        }
        inventory = GcpNormalizer().normalize(
            [
                _key(),
                _terraform_resource(
                    "google_kms_crypto_key_iam_policy.runtime",
                    GcpResourceType.KMS_CRYPTO_KEY_IAM_POLICY,
                    {
                        "crypto_key_id": _KEY_PATH,
                        "policy_data": json.dumps(
                            {
                                "bindings": [
                                    {
                                        "role": "roles/cloudkms.cryptoKeyDecrypter",
                                        "members": [_RUNTIME_MEMBER],
                                        "condition": condition,
                                    }
                                ]
                            }
                        ),
                    },
                ),
            ]
        )
        key = inventory.get_by_address("google_kms_crypto_key.customer")
        assert key is not None

        grant = gcp_facts(key).kms_iam_grants[0]
        self.assertEqual(grant["scope_type"], "crypto_key")
        self.assertEqual(grant["condition"], condition)
        self.assertEqual(grant["condition_state"], "configured")
        self.assertEqual(grant["policy_data_state"], "configured")

    def test_key_policy_and_member_overlap_are_ambiguous(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _key(),
                _terraform_resource(
                    "google_kms_crypto_key_iam_policy.authoritative",
                    GcpResourceType.KMS_CRYPTO_KEY_IAM_POLICY,
                    {
                        "crypto_key_id": _KEY_PATH,
                        "policy_data": json.dumps(
                            {
                                "bindings": [
                                    {
                                        "role": "roles/cloudkms.cryptoKeyDecrypter",
                                        "members": [_RUNTIME_MEMBER],
                                    }
                                ]
                            }
                        ),
                    },
                ),
                _key_member("google_kms_crypto_key_iam_member.additive"),
            ]
        )
        key = inventory.get_by_address("google_kms_crypto_key.customer")
        assert key is not None

        facts = gcp_facts(key)
        self.assertEqual(len(facts.kms_iam_grants), 2)
        self.assertEqual(
            {grant["management_mode"] for grant in facts.kms_iam_grants},
            {"authoritative_policy", "additive_member"},
        )
        self.assertEqual(
            {grant["management_state"] for grant in facts.kms_iam_grants},
            {"ambiguous"},
        )
        self.assertEqual(
            {grant["authorization_state"] for grant in facts.kms_iam_grants},
            {"ambiguous"},
        )
        self.assertTrue(
            any(
                "authoritative policy and other Terraform IAM managers overlap" in uncertainty
                for uncertainty in facts.kms_iam_posture_uncertainties
            )
        )

    def test_project_binding_and_member_for_same_role_are_ambiguous(self) -> None:
        role = "roles/cloudkms.cryptoKeyDecrypter"
        inventory = GcpNormalizer().normalize(
            [
                _key(),
                _terraform_resource(
                    "google_project_iam_binding.authoritative",
                    GcpResourceType.PROJECT_IAM_BINDING,
                    {
                        "project": _PROJECT,
                        "role": role,
                        "members": [_RUNTIME_MEMBER],
                    },
                ),
                _project_member(
                    "google_project_iam_member.additive",
                    role=role,
                    member="serviceAccount:other@tfstride-demo.iam.gserviceaccount.com",
                ),
            ]
        )
        key = inventory.get_by_address("google_kms_crypto_key.customer")
        assert key is not None

        facts = gcp_facts(key)
        self.assertEqual(len(facts.kms_iam_grants), 2)
        self.assertEqual(
            {grant["management_state"] for grant in facts.kms_iam_grants},
            {"ambiguous"},
        )
        self.assertEqual(
            {grant["authorization_state"] for grant in facts.kms_iam_grants},
            {"ambiguous"},
        )
        self.assertTrue(
            any(
                f"effective IAM membership for role {role}" in uncertainty
                for uncertainty in facts.kms_iam_posture_uncertainties
            )
        )

    def test_key_versions_do_not_receive_iam_grants(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _key(),
                _project_member("google_project_iam_member.runtime_decrypter"),
                _terraform_resource(
                    "google_kms_crypto_key_version.primary",
                    GcpResourceType.KMS_CRYPTO_KEY_VERSION,
                    {
                        "crypto_key": "google_kms_crypto_key.customer.id",
                        "id": f"{_KEY_PATH}/cryptoKeyVersions/1",
                        "name": f"{_KEY_PATH}/cryptoKeyVersions/1",
                        "state": "ENABLED",
                        "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
                        "protection_level": "SOFTWARE",
                        "generate_time": "2026-07-19T00:00:00Z",
                    },
                ),
            ]
        )
        version = inventory.get_by_address("google_kms_crypto_key_version.primary")
        assert version is not None

        facts = gcp_facts(version)
        self.assertEqual(facts.bindings, [])
        self.assertEqual(facts.kms_iam_grants, [])
        self.assertEqual(facts.kms_iam_posture_uncertainties, [])


if __name__ == "__main__":
    unittest.main()
