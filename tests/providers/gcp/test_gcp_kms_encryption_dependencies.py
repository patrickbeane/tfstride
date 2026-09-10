from __future__ import annotations

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
_KEY_RING = f"projects/{_PROJECT}/locations/global/keyRings/application"
_KEY_PATH = f"{_KEY_RING}/cryptoKeys/orders"
_AUDIT_KEY_PATH = f"{_KEY_RING}/cryptoKeys/audit"
_VERSION_PATH = f"{_KEY_PATH}/cryptoKeyVersions/1"


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


def _key_ring() -> TerraformResource:
    return _resource(
        GcpResourceType.KMS_KEY_RING,
        "application",
        {
            "id": _KEY_RING,
            "name": "application",
            "project": _PROJECT,
            "location": "global",
        },
    )


def _key(
    name: str = "orders",
    *,
    exact_identity: bool = True,
) -> TerraformResource:
    key_path = _KEY_PATH if name == "orders" else f"{_KEY_RING}/cryptoKeys/{name}"
    values: dict[str, Any] = {
        "name": name,
        "purpose": "ENCRYPT_DECRYPT",
    }
    unknown_values: dict[str, Any] = {}
    if exact_identity:
        values.update({"id": key_path, "key_ring": _KEY_RING})
    else:
        values.update({"id": None, "key_ring": None})
        unknown_values.update({"id": True, "key_ring": True})
    return _resource(
        GcpResourceType.KMS_CRYPTO_KEY,
        name,
        values,
        unknown_values=unknown_values,
    )


def _version() -> TerraformResource:
    return _resource(
        GcpResourceType.KMS_CRYPTO_KEY_VERSION,
        "primary",
        {
            "crypto_key": _KEY_PATH,
            "id": _VERSION_PATH,
            "name": _VERSION_PATH,
            "state": "ENABLED",
            "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
            "protection_level": "SOFTWARE",
            "generate_time": "2026-07-24T00:00:00Z",
        },
    )


def _resolution(
    path: tuple[str | int, ...],
    targets: tuple[tuple[str, str], ...],
    *,
    state: TerraformReferenceResolutionState = TerraformReferenceResolutionState.SYMBOLIC,
) -> TerraformReferenceResolution:
    references = tuple(f"{address}{suffix}" for address, suffix in targets)
    return TerraformReferenceResolution(
        path=path,
        state=state,
        provenance=TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
        references=references,
        targets=tuple(
            TerraformReferenceTarget(address=address, reference=reference)
            for (address, _), reference in zip(targets, references, strict=True)
        ),
    )


def _bucket(
    name: str,
    *,
    key_name: str | None = None,
    resolution: TerraformReferenceResolution | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": name,
        "name": name,
        "project": _PROJECT,
    }
    unknown_values: dict[str, Any] = {}
    if key_name is not None:
        values["encryption"] = [{"default_kms_key_name": key_name}]
    elif resolution is not None:
        values["encryption"] = [{"default_kms_key_name": None}]
        unknown_values["encryption"] = [{"default_kms_key_name": True}]
    return _resource(
        GcpResourceType.STORAGE_BUCKET,
        name,
        values,
        unknown_values=unknown_values,
        reference_resolutions=(resolution,) if resolution is not None else (),
    )


def _topic(
    name: str,
    *,
    key_name: str | None = None,
    resolution: TerraformReferenceResolution | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": f"projects/{_PROJECT}/topics/{name}",
        "name": name,
        "project": _PROJECT,
    }
    unknown_values: dict[str, Any] = {}
    if key_name is not None:
        values["kms_key_name"] = key_name
    elif resolution is not None:
        values["kms_key_name"] = None
        unknown_values["kms_key_name"] = True
    return _resource(
        GcpResourceType.PUBSUB_TOPIC,
        name,
        values,
        unknown_values=unknown_values,
        reference_resolutions=(resolution,) if resolution is not None else (),
    )


def _firestore(
    name: str,
    *,
    key_name: str | None = None,
    resolution: TerraformReferenceResolution | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": f"projects/{_PROJECT}/databases/{name}",
        "name": name,
        "project": _PROJECT,
        "location_id": "nam5",
        "type": "FIRESTORE_NATIVE",
    }
    unknown_values: dict[str, Any] = {}
    if key_name is not None:
        values["cmek_config"] = [{"kms_key_name": key_name}]
    elif resolution is not None:
        values["cmek_config"] = [{"kms_key_name": None}]
        unknown_values["cmek_config"] = [{"kms_key_name": True}]
    return _resource(
        GcpResourceType.FIRESTORE_DATABASE,
        name,
        values,
        unknown_values=unknown_values,
        reference_resolutions=(resolution,) if resolution is not None else (),
    )


def _secret(
    name: str,
    *,
    key_name: str | None = None,
    resolution: TerraformReferenceResolution | None = None,
) -> TerraformResource:
    cmek = [{"kms_key_name": key_name}]
    values = {
        "id": f"projects/{_PROJECT}/secrets/{name}",
        "name": f"projects/{_PROJECT}/secrets/{name}",
        "secret_id": name,
        "project": _PROJECT,
        "replication": [
            {
                "auto": [
                    {
                        "customer_managed_encryption": cmek,
                    }
                ]
            }
        ],
    }
    unknown_values: dict[str, Any] = {}
    if resolution is not None:
        unknown_values = {"replication": [{"auto": [{"customer_managed_encryption": [{"kms_key_name": True}]}]}]}
    elif key_name is None:
        values["replication"] = [{"auto": [{}]}]
    return _resource(
        GcpResourceType.SECRET_MANAGER_SECRET,
        name,
        values,
        unknown_values=unknown_values,
        reference_resolutions=(resolution,) if resolution is not None else (),
    )


def _artifact_repository(
    name: str,
    *,
    key_name: str | None = None,
    resolution: TerraformReferenceResolution | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": f"projects/{_PROJECT}/locations/us-central1/repositories/{name}",
        "repository_id": name,
        "project": _PROJECT,
        "location": "us-central1",
        "format": "DOCKER",
    }
    unknown_values: dict[str, Any] = {}
    if key_name is not None:
        values["kms_key_name"] = key_name
    elif resolution is not None:
        values["kms_key_name"] = None
        unknown_values["kms_key_name"] = True
    return _resource(
        GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY,
        name,
        values,
        unknown_values=unknown_values,
        reference_resolutions=(resolution,) if resolution is not None else (),
    )


class GcpKmsEncryptionDependencyTests(unittest.TestCase):
    def test_exact_crypto_key_references_cover_supported_cmek_resources(self) -> None:
        resources = [
            _key_ring(),
            _key(),
            _bucket("orders", key_name=_KEY_PATH),
            _topic("orders", key_name=_KEY_PATH),
            _firestore("orders", key_name=_KEY_PATH),
            _secret("orders", key_name=_KEY_PATH),
            _artifact_repository("orders", key_name=_KEY_PATH),
        ]
        inventory = GcpNormalizer().normalize(resources)

        expected_paths = {
            "google_storage_bucket.orders": [
                "encryption",
                0,
                "default_kms_key_name",
            ],
            "google_pubsub_topic.orders": ["kms_key_name"],
            "google_firestore_database.orders": [
                "cmek_config",
                0,
                "kms_key_name",
            ],
            "google_secret_manager_secret.orders": [
                "replication",
                0,
                "auto",
                0,
                "customer_managed_encryption",
                0,
                "kms_key_name",
            ],
            "google_artifact_registry_repository.orders": ["kms_key_name"],
        }
        for address, configuration_path in expected_paths.items():
            with self.subTest(address=address):
                resource = inventory.get_by_address(address)
                assert resource is not None
                dependencies = gcp_facts(resource).kms_encryption_dependencies
                self.assertEqual(len(dependencies), 1)
                dependency = dependencies[0]
                self.assertEqual(dependency["resolution_state"], "resolved")
                self.assertEqual(dependency["reference_provenance"], "planned_value")
                self.assertEqual(
                    dependency["reference_kind"],
                    "crypto_key_resource_name",
                )
                self.assertEqual(dependency["configuration_path"], configuration_path)
                self.assertEqual(dependency["key_address"], "google_kms_crypto_key.orders")
                self.assertEqual(dependency["key_resource_name"], _KEY_PATH)
                self.assertEqual(dependency["key_project"], _PROJECT)
                self.assertEqual(dependency["key_location"], "global")
                self.assertEqual(dependency["key_ring"], _KEY_RING)
                self.assertEqual(dependency["key_purpose"], "ENCRYPT_DECRYPT")
                self.assertIsNone(dependency["key_version_address"])
                self.assertIsNone(dependency["key_version_resource_name"])
                self.assertFalse(dependency["version_reference_is_explicit"])
                self.assertEqual(
                    dependency["candidate_targets"],
                    [
                        {
                            "address": "google_kms_crypto_key.orders",
                            "target_kind": "crypto_key",
                        }
                    ],
                )

        key = inventory.get_by_address("google_kms_crypto_key.orders")
        assert key is not None
        self.assertEqual(
            [dependency["dependent_address"] for dependency in gcp_facts(key).kms_encryption_dependencies],
            sorted(expected_paths),
        )

    def test_exact_symbolic_id_references_resolve_for_each_source_shape(self) -> None:
        source_specs = (
            (
                _bucket,
                ("encryption", 0, "default_kms_key_name"),
            ),
            (_topic, ("kms_key_name",)),
            (_firestore, ("cmek_config", 0, "kms_key_name")),
            (
                _secret,
                (
                    "replication",
                    0,
                    "auto",
                    0,
                    "customer_managed_encryption",
                    0,
                    "kms_key_name",
                ),
            ),
            (_artifact_repository, ("kms_key_name",)),
        )
        resources = [_key_ring(), _key()]
        expected_addresses: set[str] = set()
        for index, (factory, path) in enumerate(source_specs):
            name = f"symbolic-{index}"
            resolution = _resolution(
                path,
                (("google_kms_crypto_key.orders", ".id"),),
            )
            source = factory(name, resolution=resolution)
            resources.append(source)
            expected_addresses.add(source.address)

        inventory = GcpNormalizer().normalize(resources)
        for address in expected_addresses:
            with self.subTest(address=address):
                resource = inventory.get_by_address(address)
                assert resource is not None
                dependency = gcp_facts(resource).kms_encryption_dependencies[0]
                self.assertEqual(dependency["resolution_state"], "resolved")
                self.assertEqual(
                    dependency["reference_provenance"],
                    "configuration_reference",
                )
                self.assertEqual(dependency["reference_kind"], "terraform_reference")
                self.assertEqual(
                    dependency["customer_managed_encryption_state"],
                    "unknown",
                )
                self.assertEqual(dependency["key_address"], "google_kms_crypto_key.orders")
                self.assertEqual(dependency["key_resource_name"], _KEY_PATH)
                self.assertEqual(dependency["posture_uncertainties"], [])

    def test_provider_managed_defaults_do_not_create_key_dependencies(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _key_ring(),
                _key(),
                _bucket("default"),
                _topic("default"),
                _firestore("default"),
                _secret("default"),
                _artifact_repository("default"),
            ]
        )

        for address in (
            "google_storage_bucket.default",
            "google_pubsub_topic.default",
            "google_firestore_database.default",
            "google_secret_manager_secret.default",
            "google_artifact_registry_repository.default",
        ):
            with self.subTest(address=address):
                resource = inventory.get_by_address(address)
                assert resource is not None
                self.assertEqual(gcp_facts(resource).kms_encryption_dependencies, [])

        key = inventory.get_by_address("google_kms_crypto_key.orders")
        assert key is not None
        self.assertEqual(gcp_facts(key).kms_encryption_dependencies, [])

    def test_unknown_gcs_key_without_configuration_resolution_remains_unresolved(
        self,
    ) -> None:
        unknown_bucket = _resource(
            GcpResourceType.STORAGE_BUCKET,
            "unknown-key",
            {
                "id": "unknown-key",
                "name": "unknown-key",
                "project": _PROJECT,
                "encryption": [{"default_kms_key_name": None}],
            },
            unknown_values={
                "encryption": [{"default_kms_key_name": True}],
            },
        )
        inventory = GcpNormalizer().normalize([_key_ring(), _key(), unknown_bucket])

        bucket = inventory.get_by_address("google_storage_bucket.unknown-key")
        key = inventory.get_by_address("google_kms_crypto_key.orders")
        assert bucket is not None
        assert key is not None

        dependencies = gcp_facts(bucket).kms_encryption_dependencies
        self.assertEqual(len(dependencies), 1)
        dependency = dependencies[0]
        self.assertEqual(
            dependency["configuration_path"],
            ["encryption", 0, "default_kms_key_name"],
        )
        self.assertEqual(dependency["resolution_state"], "unresolved")
        self.assertEqual(
            dependency["customer_managed_encryption_state"],
            "unknown",
        )
        self.assertEqual(dependency["candidate_targets"], [])
        self.assertIsNone(dependency["key_address"])
        self.assertTrue(dependency["posture_uncertainties"])
        self.assertTrue(gcp_facts(bucket).kms_encryption_dependency_uncertainties)
        self.assertEqual(gcp_facts(key).kms_encryption_dependencies, [])

    def test_symbolic_confidence_and_target_attributes_fail_closed(self) -> None:
        ambiguous = _resolution(
            ("kms_key_name",),
            (
                ("google_kms_crypto_key.orders", ".id"),
                ("google_kms_crypto_key.audit", ".id"),
                ("google_kms_crypto_key.orders", ".id"),
            ),
            state=TerraformReferenceResolutionState.AMBIGUOUS,
        )
        unresolved = _resolution(
            ("kms_key_name",),
            (("google_kms_crypto_key.orders", ".id"),),
            state=TerraformReferenceResolutionState.UNRESOLVED,
        )
        wrong_suffix = _resolution(
            ("kms_key_name",),
            (("google_kms_crypto_key.orders", ".name"),),
        )
        missing_identity = _resolution(
            ("kms_key_name",),
            (("google_kms_crypto_key.unresolved", ".id"),),
        )
        inventory = GcpNormalizer().normalize(
            [
                _key_ring(),
                _key(),
                _key("audit"),
                _key("unresolved", exact_identity=False),
                _topic("ambiguous", resolution=ambiguous),
                _topic("unresolved", resolution=unresolved),
                _topic("wrong-suffix", resolution=wrong_suffix),
                _topic("missing-identity", resolution=missing_identity),
            ]
        )

        expected = {
            "google_pubsub_topic.ambiguous": (
                "ambiguous",
                [
                    {
                        "address": "google_kms_crypto_key.audit",
                        "target_kind": "crypto_key",
                    },
                    {
                        "address": "google_kms_crypto_key.orders",
                        "target_kind": "crypto_key",
                    },
                ],
                [
                    "Terraform configuration reference has multiple modeled Cloud KMS targets",
                    "kms_key_name is unknown after planning",
                ],
            ),
            "google_pubsub_topic.unresolved": (
                "unresolved",
                [
                    {
                        "address": "google_kms_crypto_key.orders",
                        "target_kind": "crypto_key",
                    }
                ],
                [
                    "Terraform configuration reference does not resolve to a modeled Cloud KMS CryptoKey",
                    "kms_key_name is unknown after planning",
                ],
            ),
            "google_pubsub_topic.wrong-suffix": (
                "unsupported",
                [
                    {
                        "address": "google_kms_crypto_key.orders",
                        "target_kind": "crypto_key",
                    }
                ],
                [
                    "Terraform target reference google_kms_crypto_key.orders.name is unsupported "
                    "for google_pubsub_topic",
                    "kms_key_name is unknown after planning",
                ],
            ),
            "google_pubsub_topic.missing-identity": (
                "unresolved",
                [
                    {
                        "address": "google_kms_crypto_key.unresolved",
                        "target_kind": "crypto_key",
                    }
                ],
                [
                    "google_kms_crypto_key.unresolved does not retain an exact provider-native CryptoKey resource name",
                    "kms_key_name is unknown after planning",
                ],
            ),
        }
        for address, (state, candidates, uncertainties) in expected.items():
            with self.subTest(address=address):
                resource = inventory.get_by_address(address)
                assert resource is not None
                dependency = gcp_facts(resource).kms_encryption_dependencies[0]
                self.assertEqual(dependency["resolution_state"], state)
                self.assertEqual(dependency["configuration_path"], ["kms_key_name"])
                self.assertEqual(
                    dependency["reference_provenance"],
                    "configuration_reference",
                )
                self.assertEqual(dependency["reference_kind"], "terraform_reference")
                self.assertEqual(dependency["candidate_targets"], candidates)
                self.assertIsNone(dependency["key_address"])
                self.assertIsNone(dependency["key_resource_name"])
                self.assertEqual(dependency["posture_uncertainties"], uncertainties)
                self.assertEqual(
                    gcp_facts(resource).kms_encryption_dependency_uncertainties,
                    [f"{address}: {uncertainty}" for uncertainty in uncertainties],
                )

        for key_address in (
            "google_kms_crypto_key.orders",
            "google_kms_crypto_key.audit",
            "google_kms_crypto_key.unresolved",
        ):
            key = inventory.get_by_address(key_address)
            assert key is not None
            self.assertEqual(gcp_facts(key).kms_encryption_dependencies, [])

    def test_version_references_remain_candidates_not_key_scoped_dependencies(self) -> None:
        symbolic_version = _resolution(
            ("kms_key_name",),
            (("google_kms_crypto_key_version.primary", ".id"),),
        )
        inventory = GcpNormalizer().normalize(
            [
                _key_ring(),
                _key(),
                _version(),
                _topic("native-version", key_name=_VERSION_PATH),
                _topic("symbolic-version", resolution=symbolic_version),
                _topic("key", key_name=_KEY_PATH),
            ]
        )

        for address in (
            "google_pubsub_topic.native-version",
            "google_pubsub_topic.symbolic-version",
        ):
            with self.subTest(address=address):
                resource = inventory.get_by_address(address)
                assert resource is not None
                dependency = gcp_facts(resource).kms_encryption_dependencies[0]
                self.assertEqual(dependency["resolution_state"], "unsupported")
                self.assertEqual(
                    dependency["candidate_targets"],
                    [
                        {
                            "address": "google_kms_crypto_key_version.primary",
                            "target_kind": "crypto_key_version",
                        }
                    ],
                )
                self.assertTrue(dependency["version_reference_is_explicit"])
                self.assertIsNone(dependency["key_address"])
                self.assertIsNone(dependency["key_version_address"])

        key_topic = inventory.get_by_address("google_pubsub_topic.key")
        version = inventory.get_by_address("google_kms_crypto_key_version.primary")
        assert key_topic is not None
        assert version is not None
        key_dependency = gcp_facts(key_topic).kms_encryption_dependencies[0]
        self.assertEqual(key_dependency["resolution_state"], "resolved")
        self.assertIsNone(key_dependency["key_version_address"])
        self.assertFalse(key_dependency["version_reference_is_explicit"])
        self.assertEqual(
            gcp_facts(version).kms_crypto_key_version_resolved_key_address,
            "google_kms_crypto_key.orders",
        )
        self.assertEqual(gcp_facts(version).kms_encryption_dependencies, [])

    def test_secret_manager_replica_paths_remain_local(self) -> None:
        replica_resolution = _resolution(
            (
                "replication",
                0,
                "user_managed",
                0,
                "replicas",
                0,
                "customer_managed_encryption",
                0,
                "kms_key_name",
            ),
            (("google_kms_crypto_key.orders", ".id"),),
        )
        secret = _resource(
            GcpResourceType.SECRET_MANAGER_SECRET,
            "replicated",
            {
                "id": f"projects/{_PROJECT}/secrets/replicated",
                "name": f"projects/{_PROJECT}/secrets/replicated",
                "secret_id": "replicated",
                "project": _PROJECT,
                "replication": [
                    {
                        "user_managed": [
                            {
                                "replicas": [
                                    {
                                        "location": "us-central1",
                                        "customer_managed_encryption": [{"kms_key_name": None}],
                                    },
                                    {
                                        "location": "us-east1",
                                        "customer_managed_encryption": [{"kms_key_name": _AUDIT_KEY_PATH}],
                                    },
                                ]
                            }
                        ]
                    }
                ],
            },
            unknown_values={
                "replication": [
                    {
                        "user_managed": [
                            {
                                "replicas": [
                                    {"customer_managed_encryption": [{"kms_key_name": True}]},
                                    {},
                                ]
                            }
                        ]
                    }
                ]
            },
            reference_resolutions=(replica_resolution,),
        )
        inventory = GcpNormalizer().normalize([_key_ring(), _key(), _key("audit"), secret])

        normalized = inventory.get_by_address("google_secret_manager_secret.replicated")
        assert normalized is not None
        dependencies = gcp_facts(normalized).kms_encryption_dependencies
        self.assertEqual(len(dependencies), 2)
        self.assertEqual(
            [dependency["configuration_path"] for dependency in dependencies],
            [
                [
                    "replication",
                    0,
                    "user_managed",
                    0,
                    "replicas",
                    0,
                    "customer_managed_encryption",
                    0,
                    "kms_key_name",
                ],
                [
                    "replication",
                    0,
                    "user_managed",
                    0,
                    "replicas",
                    1,
                    "customer_managed_encryption",
                    0,
                    "kms_key_name",
                ],
            ],
        )
        self.assertEqual(
            [dependency["key_address"] for dependency in dependencies],
            [
                "google_kms_crypto_key.orders",
                "google_kms_crypto_key.audit",
            ],
        )
        self.assertTrue(all(dependency["resolution_state"] == "resolved" for dependency in dependencies))


if __name__ == "__main__":
    unittest.main()
