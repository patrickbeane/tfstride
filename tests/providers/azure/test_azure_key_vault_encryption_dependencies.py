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
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_VAULT_ID = "/subscriptions/sub-0001/resourceGroups/security/providers/Microsoft.KeyVault/vaults/application"
_VAULT_URI = "https://application.vault.azure.net"
_KEY_VERSION = "version-0001"
_KEY_VERSIONLESS_URI = f"{_VAULT_URI}/keys/data"
_KEY_URI = f"{_KEY_VERSIONLESS_URI}/{_KEY_VERSION}"
_KEY_VERSIONLESS_RESOURCE_ID = f"{_VAULT_ID}/keys/data"
_KEY_RESOURCE_ID = f"{_KEY_VERSIONLESS_RESOURCE_ID}/{_KEY_VERSION}"
_NAMESPACE_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.ServiceBus/namespaces/events"


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
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values=values,
        unknown_values=unknown_values or {},
        reference_resolutions=reference_resolutions,
    )


def _vault() -> TerraformResource:
    return _resource(
        AzureResourceType.KEY_VAULT,
        "application",
        {
            "id": _VAULT_ID,
            "name": "application",
            "vault_uri": _VAULT_URI,
            "tenant_id": "tenant-id",
        },
    )


def _key(
    name: str = "data",
    *,
    exact_identity: bool = True,
) -> TerraformResource:
    versionless_uri = f"{_VAULT_URI}/keys/{name}"
    key_uri = f"{versionless_uri}/{_KEY_VERSION}"
    versionless_resource_id = f"{_VAULT_ID}/keys/{name}"
    key_resource_id = f"{versionless_resource_id}/{_KEY_VERSION}"
    values: dict[str, Any] = {
        "name": name,
        "key_type": "RSA",
        "key_opts": ["decrypt", "encrypt", "unwrapKey", "wrapKey"],
    }
    unknown_values: dict[str, Any] = {}
    if exact_identity:
        values.update(
            {
                "id": key_uri,
                "versionless_id": versionless_uri,
                "resource_id": key_resource_id,
                "resource_versionless_id": versionless_resource_id,
                "version": _KEY_VERSION,
                "key_vault_id": "azurerm_key_vault.application.id",
            }
        )
    else:
        values.update(
            {
                "id": None,
                "versionless_id": None,
                "resource_id": None,
                "resource_versionless_id": None,
                "version": None,
                "key_vault_id": None,
            }
        )
        unknown_values.update(
            {
                "id": True,
                "versionless_id": True,
                "resource_id": True,
                "resource_versionless_id": True,
                "version": True,
                "key_vault_id": True,
            }
        )
    return _resource(
        AzureResourceType.KEY_VAULT_KEY,
        name,
        values,
        unknown_values=unknown_values,
    )


def _reference_resolution(
    path: tuple[str | int, ...],
    targets: tuple[str, ...],
    suffix: str,
    *,
    state: TerraformReferenceResolutionState = (TerraformReferenceResolutionState.SYMBOLIC),
) -> TerraformReferenceResolution:
    references = tuple(f"{target}{suffix}" for target in targets)
    return TerraformReferenceResolution(
        path=path,
        state=state,
        provenance=TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
        references=references,
        targets=tuple(
            TerraformReferenceTarget(address=target, reference=reference)
            for target, reference in zip(targets, references, strict=True)
        ),
    )


def _cosmos_account(
    name: str,
    *,
    key_reference: str | None = None,
    resolution: TerraformReferenceResolution | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": (f"/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.DocumentDB/databaseAccounts/{name}"),
        "name": name,
        "resource_group_name": "app",
        "location": "eastus",
        "offer_type": "Standard",
    }
    unknown_values: dict[str, Any] = {}
    if key_reference is not None:
        values["key_vault_key_id"] = key_reference
    elif resolution is not None:
        values["key_vault_key_id"] = None
        unknown_values["key_vault_key_id"] = True
    return _resource(
        AzureResourceType.COSMOSDB_ACCOUNT,
        name,
        values,
        unknown_values=unknown_values,
        reference_resolutions=(resolution,) if resolution is not None else (),
    )


class AzureKeyVaultEncryptionDependencyTests(unittest.TestCase):
    def test_exact_storage_service_bus_cosmos_registry_and_aks_dependencies_resolve(
        self,
    ) -> None:
        storage = _resource(
            AzureResourceType.STORAGE_ACCOUNT,
            "data",
            {
                "id": ("/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/data"),
                "name": "data",
                "customer_managed_key": [
                    {
                        "key_vault_key_id": _KEY_URI,
                        "user_assigned_identity_id": "identity-id",
                    }
                ],
            },
        )
        namespace = _resource(
            AzureResourceType.SERVICE_BUS_NAMESPACE,
            "events",
            {
                "id": _NAMESPACE_ID,
                "name": "events",
                "sku": "Premium",
            },
        )
        service_bus_key = _resource(
            AzureResourceType.SERVICE_BUS_NAMESPACE_CUSTOMER_MANAGED_KEY,
            "events",
            {
                "namespace_id": _NAMESPACE_ID,
                "key_vault_key_id": _KEY_VERSIONLESS_URI,
            },
        )
        cosmos = _cosmos_account("orders", key_reference=_KEY_VERSIONLESS_URI)
        registry = _resource(
            AzureResourceType.CONTAINER_REGISTRY,
            "images",
            {
                "id": (
                    "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.ContainerRegistry/registries/images"
                ),
                "name": "images",
                "location": "eastus",
                "sku": "Premium",
                "encryption": [
                    {
                        "key_vault_key_id": _KEY_URI,
                        "identity_client_id": "client-id",
                    }
                ],
            },
        )
        cluster = _resource(
            AzureResourceType.KUBERNETES_CLUSTER,
            "application",
            {
                "id": (
                    "/subscriptions/sub-0001/resourceGroups/app/providers/"
                    "Microsoft.ContainerService/managedClusters/application"
                ),
                "name": "application",
                "location": "eastus",
                "key_management_service": [{"key_vault_key_id": _KEY_VERSIONLESS_URI}],
            },
        )

        inventory = AzureNormalizer().normalize(
            [
                _vault(),
                _key(),
                storage,
                namespace,
                service_bus_key,
                cosmos,
                registry,
                cluster,
            ]
        )
        expected = {
            storage.address: (
                "versioned_uri",
                "key_version",
                storage.address,
                ["customer_managed_key", 0, "key_vault_key_id"],
            ),
            namespace.address: (
                "versionless_uri",
                "key",
                service_bus_key.address,
                ["key_vault_key_id"],
            ),
            cosmos.address: (
                "versionless_uri",
                "key",
                cosmos.address,
                ["key_vault_key_id"],
            ),
            registry.address: (
                "versioned_uri",
                "key_version",
                registry.address,
                ["encryption", 0, "key_vault_key_id"],
            ),
            cluster.address: (
                "versionless_uri",
                "key",
                cluster.address,
                ["key_management_service", 0, "key_vault_key_id"],
            ),
        }

        for address, (
            reference_kind,
            target_kind,
            source_address,
            configuration_path,
        ) in expected.items():
            with self.subTest(address=address):
                dependent = inventory.get_by_address(address)
                assert dependent is not None
                dependencies = azure_facts(dependent).key_vault_encryption_dependencies
                self.assertEqual(len(dependencies), 1)
                dependency = dependencies[0]
                self.assertEqual(dependency["resolution_state"], "resolved")
                self.assertEqual(dependency["reference_kind"], reference_kind)
                self.assertEqual(dependency["target_kind"], target_kind)
                self.assertEqual(
                    dependency["dependency_source_address"],
                    source_address,
                )
                self.assertEqual(
                    dependency["configuration_path"],
                    configuration_path,
                )
                self.assertEqual(
                    dependency["candidate_key_addresses"],
                    ["azurerm_key_vault_key.data"],
                )
                self.assertEqual(
                    dependency["key_address"],
                    "azurerm_key_vault_key.data",
                )
                self.assertEqual(
                    dependency["key_vault_address"],
                    "azurerm_key_vault.application",
                )
                self.assertEqual(dependency["key_vault_id"], _VAULT_ID)
                self.assertEqual(dependency["key_vault_uri"], _VAULT_URI)
                self.assertEqual(dependency["key_name"], "data")
                self.assertEqual(dependency["key_version"], _KEY_VERSION)
                self.assertEqual(dependency["key_uri"], _KEY_URI)
                self.assertEqual(
                    dependency["key_versionless_uri"],
                    _KEY_VERSIONLESS_URI,
                )
                self.assertEqual(
                    dependency["key_resource_id"],
                    _KEY_RESOURCE_ID,
                )
                self.assertEqual(
                    dependency["key_versionless_resource_id"],
                    _KEY_VERSIONLESS_RESOURCE_ID,
                )

        key = inventory.get_by_address("azurerm_key_vault_key.data")
        assert key is not None
        self.assertEqual(
            [dependency["dependent_address"] for dependency in azure_facts(key).key_vault_encryption_dependencies],
            sorted(expected),
        )

    def test_symbolic_versionless_reference_resolves_without_fabricating_a_uri(
        self,
    ) -> None:
        resolution = _reference_resolution(
            ("key_vault_key_id",),
            ("azurerm_key_vault_key.data",),
            ".versionless_id",
        )
        inventory = AzureNormalizer().normalize(
            [
                _vault(),
                _key(),
                _cosmos_account("symbolic", resolution=resolution),
            ]
        )
        account = inventory.get_by_address("azurerm_cosmosdb_account.symbolic")
        assert account is not None
        dependency = azure_facts(account).key_vault_encryption_dependencies[0]

        self.assertEqual(dependency["resolution_state"], "resolved")
        self.assertEqual(
            dependency["reference_provenance"],
            "configuration_reference",
        )
        self.assertEqual(dependency["reference_kind"], "terraform_reference")
        self.assertEqual(dependency["target_kind"], "key")
        self.assertEqual(
            dependency["configured_key_reference"],
            "azurerm_key_vault_key.data.versionless_id",
        )
        self.assertEqual(
            dependency["key_versionless_uri"],
            _KEY_VERSIONLESS_URI,
        )
        self.assertEqual(dependency["key_uri"], _KEY_URI)

    def test_versionless_only_key_does_not_populate_versioned_dependency_identity(
        self,
    ) -> None:
        key = _resource(
            AzureResourceType.KEY_VAULT_KEY,
            "data",
            {
                "name": "data",
                "versionless_id": _KEY_VERSIONLESS_URI,
                "resource_versionless_id": _KEY_VERSIONLESS_RESOURCE_ID,
                "key_vault_id": "azurerm_key_vault.application.id",
                "key_type": "RSA",
                "key_opts": ["decrypt", "encrypt"],
            },
        )
        inventory = AzureNormalizer().normalize(
            [
                _vault(),
                key,
                _cosmos_account(
                    "versionless",
                    key_reference=_KEY_VERSIONLESS_URI,
                ),
            ]
        )
        account = inventory.get_by_address("azurerm_cosmosdb_account.versionless")
        assert account is not None
        dependency = azure_facts(account).key_vault_encryption_dependencies[0]

        self.assertEqual(dependency["resolution_state"], "resolved")
        self.assertEqual(dependency["target_kind"], "key")
        self.assertIsNone(dependency["key_version"])
        self.assertIsNone(dependency["key_uri"])
        self.assertEqual(
            dependency["key_versionless_uri"],
            _KEY_VERSIONLESS_URI,
        )
        self.assertIsNone(dependency["key_resource_id"])
        self.assertEqual(
            dependency["key_versionless_resource_id"],
            _KEY_VERSIONLESS_RESOURCE_ID,
        )

    def test_ambiguous_symbolic_reference_preserves_candidates_without_reverse_indexing(
        self,
    ) -> None:
        resolution = _reference_resolution(
            ("key_vault_key_id",),
            (
                "azurerm_key_vault_key.data",
                "azurerm_key_vault_key.audit",
                "azurerm_key_vault_key.data",
            ),
            ".versionless_id",
            state=TerraformReferenceResolutionState.AMBIGUOUS,
        )
        inventory = AzureNormalizer().normalize(
            [
                _vault(),
                _key(),
                _key("audit"),
                _cosmos_account("ambiguous", resolution=resolution),
            ]
        )
        account = inventory.get_by_address("azurerm_cosmosdb_account.ambiguous")
        data_key = inventory.get_by_address("azurerm_key_vault_key.data")
        audit_key = inventory.get_by_address("azurerm_key_vault_key.audit")
        assert account is not None
        assert data_key is not None
        assert audit_key is not None
        dependency = azure_facts(account).key_vault_encryption_dependencies[0]

        self.assertEqual(dependency["resolution_state"], "ambiguous")
        self.assertEqual(dependency["configuration_path"], ["key_vault_key_id"])
        self.assertEqual(
            dependency["reference_provenance"],
            "configuration_reference",
        )
        self.assertEqual(dependency["reference_kind"], "terraform_reference")
        self.assertEqual(
            dependency["candidate_key_addresses"],
            [
                "azurerm_key_vault_key.audit",
                "azurerm_key_vault_key.data",
            ],
        )
        self.assertEqual(dependency["target_kind"], "key")
        self.assertIsNone(dependency["key_address"])
        self.assertIsNone(dependency["key_versionless_uri"])
        self.assertEqual(
            dependency["posture_uncertainties"],
            [
                "Terraform configuration reference has multiple modeled Key Vault key targets",
                "key_vault_key_id is unknown after planning",
            ],
        )
        self.assertEqual(
            azure_facts(account).key_vault_encryption_dependency_uncertainties,
            [
                "azurerm_cosmosdb_account.ambiguous: Terraform configuration reference has "
                "multiple modeled Key Vault key targets",
                "azurerm_cosmosdb_account.ambiguous: key_vault_key_id is unknown after planning",
            ],
        )
        self.assertEqual(
            azure_facts(data_key).key_vault_encryption_dependencies,
            [],
        )
        self.assertEqual(
            azure_facts(audit_key).key_vault_encryption_dependencies,
            [],
        )

    def test_symbolic_candidate_with_unknown_cloud_identity_remains_unresolved(
        self,
    ) -> None:
        resolution = _reference_resolution(
            ("key_vault_key_id",),
            ("azurerm_key_vault_key.data",),
            ".versionless_id",
        )
        inventory = AzureNormalizer().normalize(
            [
                _key(exact_identity=False),
                _cosmos_account("unresolved", resolution=resolution),
            ]
        )
        account = inventory.get_by_address("azurerm_cosmosdb_account.unresolved")
        key = inventory.get_by_address("azurerm_key_vault_key.data")
        assert account is not None
        assert key is not None
        dependency = azure_facts(account).key_vault_encryption_dependencies[0]

        self.assertEqual(dependency["resolution_state"], "unresolved")
        self.assertEqual(
            dependency["candidate_key_addresses"],
            ["azurerm_key_vault_key.data"],
        )
        self.assertEqual(dependency["target_kind"], "key")
        self.assertEqual(dependency["configuration_path"], ["key_vault_key_id"])
        self.assertEqual(
            dependency["reference_provenance"],
            "configuration_reference",
        )
        self.assertIsNone(dependency["key_address"])
        self.assertIsNone(dependency["key_uri"])
        self.assertIsNone(dependency["key_versionless_uri"])
        self.assertEqual(
            dependency["posture_uncertainties"],
            [
                "azurerm_key_vault_key.data does not retain the exact provider-native "
                "versionless Key Vault key identity required by the dependency",
                "key_vault_key_id is unknown after planning",
            ],
        )
        self.assertEqual(
            azure_facts(key).key_vault_encryption_dependencies,
            [],
        )
        self.assertEqual(
            azure_facts(account).key_vault_encryption_dependency_uncertainties,
            [
                "azurerm_cosmosdb_account.unresolved: azurerm_key_vault_key.data does not retain "
                "the exact provider-native versionless Key Vault key identity required by the "
                "dependency",
                "azurerm_cosmosdb_account.unresolved: key_vault_key_id is unknown after planning",
            ],
        )

    def test_cosmosdb_rejects_versioned_or_arm_key_references(self) -> None:
        versioned_symbolic = _reference_resolution(
            ("key_vault_key_id",),
            ("azurerm_key_vault_key.data",),
            ".id",
        )
        inventory = AzureNormalizer().normalize(
            [
                _vault(),
                _key(),
                _cosmos_account("symbolic", resolution=versioned_symbolic),
                _cosmos_account("versioned", key_reference=_KEY_URI),
                _cosmos_account(
                    "arm",
                    key_reference=_KEY_VERSIONLESS_RESOURCE_ID,
                ),
            ]
        )

        for name in ("symbolic", "versioned", "arm"):
            with self.subTest(name=name):
                account = inventory.get_by_address(f"azurerm_cosmosdb_account.{name}")
                assert account is not None
                dependency = azure_facts(account).key_vault_encryption_dependencies[0]
                self.assertEqual(
                    dependency["resolution_state"],
                    "unsupported",
                )
                self.assertIsNone(dependency["key_address"])

    def test_unknown_registry_key_remains_unresolved_and_defaults_stay_empty(
        self,
    ) -> None:
        unknown_registry = _resource(
            AzureResourceType.CONTAINER_REGISTRY,
            "unknown",
            {
                "name": "unknown",
                "location": "eastus",
                "sku": "Premium",
                "encryption": [
                    {
                        "key_vault_key_id": None,
                        "identity_client_id": "client-id",
                    }
                ],
            },
            unknown_values={
                "encryption": [{"key_vault_key_id": True}],
            },
        )
        default_storage = _resource(
            AzureResourceType.STORAGE_ACCOUNT,
            "default",
            {"name": "default"},
        )
        default_cosmos = _cosmos_account("default")
        inventory = AzureNormalizer().normalize([unknown_registry, default_storage, default_cosmos])
        registry = inventory.get_by_address("azurerm_container_registry.unknown")
        storage = inventory.get_by_address("azurerm_storage_account.default")
        cosmos = inventory.get_by_address("azurerm_cosmosdb_account.default")
        assert registry is not None
        assert storage is not None
        assert cosmos is not None

        dependencies = azure_facts(registry).key_vault_encryption_dependencies
        self.assertEqual(len(dependencies), 1)
        self.assertEqual(dependencies[0]["resolution_state"], "unresolved")
        self.assertEqual(
            dependencies[0]["customer_managed_key_state"],
            "unknown",
        )
        self.assertEqual(dependencies[0]["candidate_key_addresses"], [])
        self.assertTrue(azure_facts(registry).key_vault_encryption_dependency_uncertainties)
        self.assertEqual(
            azure_facts(storage).key_vault_encryption_dependencies,
            [],
        )
        self.assertEqual(
            azure_facts(cosmos).key_vault_encryption_dependencies,
            [],
        )

    def test_alternate_storage_and_inline_service_bus_uri_fields_retain_exact_paths(
        self,
    ) -> None:
        storage = _resource(
            AzureResourceType.STORAGE_ACCOUNT,
            "uri",
            {
                "name": "uri",
                "customer_managed_key": [{"key_vault_key_uri": _KEY_URI}],
            },
        )
        namespace = _resource(
            AzureResourceType.SERVICE_BUS_NAMESPACE,
            "inline",
            {
                "id": _NAMESPACE_ID,
                "name": "inline",
                "sku": "Premium",
                "customer_managed_key": [{"key_vault_key_uri": _KEY_VERSIONLESS_URI}],
            },
        )
        inventory = AzureNormalizer().normalize([_vault(), _key(), storage, namespace])

        expected = {
            storage.address: [
                "customer_managed_key",
                0,
                "key_vault_key_uri",
            ],
            namespace.address: [
                "customer_managed_key",
                0,
                "key_vault_key_uri",
            ],
        }
        for address, configuration_path in expected.items():
            with self.subTest(address=address):
                dependent = inventory.get_by_address(address)
                assert dependent is not None
                dependencies = azure_facts(dependent).key_vault_encryption_dependencies
                self.assertEqual(len(dependencies), 1)
                self.assertEqual(
                    dependencies[0]["configuration_path"],
                    configuration_path,
                )
                self.assertEqual(
                    dependencies[0]["resolution_state"],
                    "resolved",
                )

    def test_unknown_storage_uri_retains_unresolved_uri_path(self) -> None:
        storage = _resource(
            AzureResourceType.STORAGE_ACCOUNT,
            "unknown_uri",
            {
                "name": "unknown_uri",
                "customer_managed_key": [{"key_vault_key_uri": None}],
            },
            unknown_values={"customer_managed_key": [{"key_vault_key_uri": True}]},
        )
        inventory = AzureNormalizer().normalize([storage])
        normalized = inventory.get_by_address(storage.address)
        assert normalized is not None
        dependencies = azure_facts(normalized).key_vault_encryption_dependencies

        self.assertEqual(len(dependencies), 1)
        self.assertEqual(
            dependencies[0]["configuration_path"],
            ["customer_managed_key", 0, "key_vault_key_uri"],
        )
        self.assertEqual(dependencies[0]["resolution_state"], "unresolved")
        self.assertEqual(dependencies[0]["customer_managed_key_state"], "unknown")

    def test_concrete_versioned_uri_and_matching_symbolic_id_resolve_as_planned_value(
        self,
    ) -> None:
        path = ("customer_managed_key", 0, "key_vault_key_id")
        storage = _resource(
            AzureResourceType.STORAGE_ACCOUNT,
            "matching",
            {
                "name": "matching",
                "customer_managed_key": [{"key_vault_key_id": _KEY_URI}],
            },
            reference_resolutions=(
                _reference_resolution(
                    path,
                    ("azurerm_key_vault_key.data",),
                    ".id",
                ),
            ),
        )
        inventory = AzureNormalizer().normalize([_vault(), _key(), storage])
        normalized = inventory.get_by_address(storage.address)
        assert normalized is not None
        dependency = azure_facts(normalized).key_vault_encryption_dependencies[0]

        self.assertEqual(dependency["resolution_state"], "resolved")
        self.assertEqual(dependency["reference_provenance"], "planned_value")
        self.assertEqual(dependency["reference_kind"], "versioned_uri")
        self.assertEqual(dependency["target_kind"], "key_version")
        self.assertEqual(dependency["configured_key_reference"], _KEY_URI)

    def test_concrete_versioned_uri_conflicting_with_versionless_symbolic_target_fails_closed(
        self,
    ) -> None:
        path = ("customer_managed_key", 0, "key_vault_key_id")
        storage = _resource(
            AzureResourceType.STORAGE_ACCOUNT,
            "conflicting",
            {
                "name": "conflicting",
                "customer_managed_key": [{"key_vault_key_id": _KEY_URI}],
            },
            reference_resolutions=(
                _reference_resolution(
                    path,
                    ("azurerm_key_vault_key.data",),
                    ".versionless_id",
                ),
            ),
        )
        inventory = AzureNormalizer().normalize([_vault(), _key(), storage])
        normalized = inventory.get_by_address(storage.address)
        key = inventory.get_by_address("azurerm_key_vault_key.data")
        assert normalized is not None
        assert key is not None
        dependency = azure_facts(normalized).key_vault_encryption_dependencies[0]

        self.assertEqual(dependency["resolution_state"], "ambiguous")
        self.assertEqual(
            dependency["configuration_path"],
            ["customer_managed_key", 0, "key_vault_key_id"],
        )
        self.assertEqual(dependency["reference_provenance"], "planned_value")
        self.assertEqual(dependency["reference_kind"], "versioned_uri")
        self.assertEqual(
            dependency["candidate_key_addresses"],
            ["azurerm_key_vault_key.data"],
        )
        self.assertIsNone(dependency["target_kind"])
        self.assertIsNone(dependency["key_address"])
        self.assertEqual(
            dependency["posture_uncertainties"],
            [
                "Concrete Key Vault key identity conflicts with symbolic configuration evidence "
                "at ['customer_managed_key', 0, 'key_vault_key_id']"
            ],
        )
        self.assertEqual(
            azure_facts(normalized).key_vault_encryption_dependency_uncertainties,
            [
                "azurerm_storage_account.conflicting: Concrete Key Vault key identity conflicts "
                "with symbolic configuration evidence at "
                "['customer_managed_key', 0, 'key_vault_key_id']"
            ],
        )
        self.assertEqual(
            azure_facts(key).key_vault_encryption_dependencies,
            [],
        )

    def test_concrete_uri_takes_precedence_over_unresolved_symbolic_evidence(
        self,
    ) -> None:
        path = ("customer_managed_key", 0, "key_vault_key_id")
        storage = _resource(
            AzureResourceType.STORAGE_ACCOUNT,
            "concrete",
            {
                "name": "concrete",
                "customer_managed_key": [{"key_vault_key_id": _KEY_URI}],
            },
            reference_resolutions=(
                _reference_resolution(
                    path,
                    ("azurerm_key_vault_key.data",),
                    ".id",
                    state=TerraformReferenceResolutionState.UNRESOLVED,
                ),
            ),
        )
        inventory = AzureNormalizer().normalize([_vault(), _key(), storage])
        normalized = inventory.get_by_address(storage.address)
        assert normalized is not None
        dependency = azure_facts(normalized).key_vault_encryption_dependencies[0]

        self.assertEqual(dependency["resolution_state"], "resolved")
        self.assertEqual(dependency["reference_provenance"], "planned_value")
        self.assertEqual(dependency["key_address"], "azurerm_key_vault_key.data")

    def test_conflicting_alternate_storage_fields_are_not_reverse_indexed(
        self,
    ) -> None:
        storage = _resource(
            AzureResourceType.STORAGE_ACCOUNT,
            "alternate_conflict",
            {
                "name": "alternate_conflict",
                "customer_managed_key": [
                    {
                        "key_vault_key_id": _KEY_URI,
                        "key_vault_key_uri": (f"{_VAULT_URI}/keys/audit/{_KEY_VERSION}"),
                    }
                ],
            },
        )
        inventory = AzureNormalizer().normalize([_vault(), _key(), _key("audit"), storage])
        normalized = inventory.get_by_address(storage.address)
        data_key = inventory.get_by_address("azurerm_key_vault_key.data")
        audit_key = inventory.get_by_address("azurerm_key_vault_key.audit")
        assert normalized is not None
        assert data_key is not None
        assert audit_key is not None
        dependencies = azure_facts(normalized).key_vault_encryption_dependencies

        self.assertEqual(len(dependencies), 2)
        self.assertEqual(
            [dependency["configuration_path"] for dependency in dependencies],
            [
                ["customer_managed_key", 0, "key_vault_key_id"],
                ["customer_managed_key", 0, "key_vault_key_uri"],
            ],
        )
        self.assertEqual(
            [dependency["configured_key_reference"] for dependency in dependencies],
            [
                _KEY_URI,
                f"{_VAULT_URI}/keys/audit/{_KEY_VERSION}",
            ],
        )
        self.assertTrue(all(dependency["resolution_state"] == "ambiguous" for dependency in dependencies))
        self.assertTrue(all(dependency["key_address"] is None for dependency in dependencies))
        self.assertEqual(
            azure_facts(normalized).key_vault_encryption_dependency_uncertainties,
            [
                "azurerm_storage_account.alternate_conflict: Multiple alternate Key Vault key "
                "fields contain relationship evidence; no exact source field is authoritative"
            ],
        )
        self.assertEqual(
            azure_facts(data_key).key_vault_encryption_dependencies,
            [],
        )
        self.assertEqual(
            azure_facts(audit_key).key_vault_encryption_dependencies,
            [],
        )


if __name__ == "__main__":
    unittest.main()
