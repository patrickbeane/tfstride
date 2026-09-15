from __future__ import annotations

import unittest

from tfstride.models import NormalizedResource, ResourceCategory
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_decoration.storage import DecorateStorageRelationshipsStage
from tfstride.providers.azure.resource_decorator import AzureResourceDecorator
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureResourceIndexBuilder
from tfstride.providers.azure.resource_types import AzureResourceType


def _resource(
    address: str,
    resource_type: str,
    *,
    identifier: str | None = None,
    metadata: dict[object, object] | None = None,
) -> NormalizedResource:
    return NormalizedResource(
        address=address,
        provider="azure",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        category=ResourceCategory.DATA,
        identifier=identifier,
        metadata=metadata,
    )


def _arm_id(
    subscription: str,
    resource_group: str,
    provider_path: str,
) -> str:
    return f"/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/{provider_path}"


class AzureResourceReferenceIndexTests(unittest.TestCase):
    def test_native_alias_collisions_are_deterministic_and_fail_closed(self) -> None:
        first_account = _resource(
            "azurerm_storage_account.first",
            AzureResourceType.STORAGE_ACCOUNT,
            identifier=_arm_id(
                "sub-0001",
                "application",
                "Microsoft.Storage/storageAccounts/shared",
            ),
            metadata={AzureResourceMetadata.NAME: "shared"},
        )
        second_account = _resource(
            "azurerm_storage_account.second",
            AzureResourceType.STORAGE_ACCOUNT,
            identifier=_arm_id(
                "sub-0002",
                "application",
                "Microsoft.Storage/storageAccounts/shared",
            ),
            metadata={AzureResourceMetadata.NAME: "shared"},
        )

        for resources in (
            [first_account, second_account],
            [second_account, first_account],
        ):
            with self.subTest(order=[resource.address for resource in resources]):
                references = AzureResourceIndexBuilder().build(resources).resources_by_reference
                resolution = references.resolve(
                    "SHARED",
                    resource_types={AzureResourceType.STORAGE_ACCOUNT},
                )

                self.assertEqual(resolution.state, "ambiguous")
                self.assertEqual(resolution.candidates, (first_account, second_account))
                self.assertIsNone(resolution.selected_candidate)
                self.assertIsNone(
                    references.get(
                        "shared",
                        resource_types={AzureResourceType.STORAGE_ACCOUNT},
                    )
                )
                self.assertIsNone(references.get(first_account.address.upper()))
                self.assertIs(references.get(first_account.address), first_account)
                self.assertIs(references.get(second_account.address), second_account)

    def test_exact_address_precedes_a_colliding_native_alias(self) -> None:
        exact_account = _resource(
            "azurerm_storage_account.exact",
            AzureResourceType.STORAGE_ACCOUNT,
            identifier=_arm_id(
                "sub-0001",
                "application",
                "Microsoft.Storage/storageAccounts/exact",
            ),
            metadata={AzureResourceMetadata.NAME: "exact"},
        )
        colliding_account = _resource(
            "azurerm_storage_account.colliding",
            AzureResourceType.STORAGE_ACCOUNT,
            identifier=_arm_id(
                "sub-0002",
                "application",
                "Microsoft.Storage/storageAccounts/colliding",
            ),
            metadata={AzureResourceMetadata.NAME: exact_account.address},
        )

        for resources in (
            [exact_account, colliding_account],
            [colliding_account, exact_account],
        ):
            with self.subTest(order=[resource.address for resource in resources]):
                resolution = (
                    AzureResourceIndexBuilder()
                    .build(resources)
                    .resources_by_reference.resolve(
                        f"${{{exact_account.address}.id}}",
                        resource_types={AzureResourceType.STORAGE_ACCOUNT},
                    )
                )

                self.assertEqual(resolution.state, "resolved")
                self.assertIs(resolution.selected_candidate, exact_account)

    def test_case_distinct_terraform_addresses_resolve_independently(self) -> None:
        upper_label = _resource(
            "azurerm_storage_account.Foo",
            AzureResourceType.STORAGE_ACCOUNT,
            identifier=_arm_id(
                "sub-0001",
                "application",
                "Microsoft.Storage/storageAccounts/upperlabel",
            ),
        )
        lower_label = _resource(
            "azurerm_storage_account.foo",
            AzureResourceType.STORAGE_ACCOUNT,
            identifier=_arm_id(
                "sub-0001",
                "application",
                "Microsoft.Storage/storageAccounts/lowerlabel",
            ),
        )

        for resources in (
            [upper_label, lower_label],
            [lower_label, upper_label],
        ):
            with self.subTest(order=[resource.address for resource in resources]):
                references = AzureResourceIndexBuilder().build(resources).resources_by_reference

                self.assertIs(references.get(upper_label.address), upper_label)
                self.assertIs(references.get(lower_label.address), lower_label)
                self.assertIs(
                    references.get(f"${{{upper_label.address}.id}}"),
                    upper_label,
                )
                self.assertIsNone(references.get("azurerm_storage_account.FOO"))

    def test_arm_ids_ending_in_terraform_suffixes_remain_distinct(self) -> None:
        plain_id = _arm_id(
            "sub-0001",
            "application",
            "Microsoft.Network/privateDnsZones/example",
        )
        suffixed_id = f"{plain_id}.id"
        plain_zone = _resource(
            "azurerm_private_dns_zone.plain",
            AzureResourceType.PRIVATE_DNS_ZONE,
            identifier=plain_id,
            metadata={AzureResourceMetadata.NAME: "example"},
        )
        suffixed_zone = _resource(
            "azurerm_private_dns_zone.suffixed",
            AzureResourceType.PRIVATE_DNS_ZONE,
            identifier=suffixed_id,
            metadata={AzureResourceMetadata.NAME: "example.id"},
        )

        for resources in (
            [plain_zone, suffixed_zone],
            [suffixed_zone, plain_zone],
        ):
            with self.subTest(order=[resource.address for resource in resources]):
                references = AzureResourceIndexBuilder().build(resources).resources_by_reference

                self.assertIs(
                    references.get(
                        plain_id.upper(),
                        resource_types={AzureResourceType.PRIVATE_DNS_ZONE},
                    ),
                    plain_zone,
                )
                self.assertIs(
                    references.get(
                        suffixed_id.upper(),
                        resource_types={AzureResourceType.PRIVATE_DNS_ZONE},
                    ),
                    suffixed_zone,
                )

    def test_resolution_filters_by_type_subscription_and_resource_group(self) -> None:
        primary_account = _resource(
            "azurerm_storage_account.primary",
            AzureResourceType.STORAGE_ACCOUNT,
            identifier=_arm_id(
                "sub-0001",
                "application",
                "Microsoft.Storage/storageAccounts/shared",
            ),
            metadata={AzureResourceMetadata.NAME: "shared"},
        )
        sibling_account = _resource(
            "azurerm_storage_account.sibling",
            AzureResourceType.STORAGE_ACCOUNT,
            identifier=_arm_id(
                "sub-0001",
                "secondary",
                "Microsoft.Storage/storageAccounts/shared",
            ),
            metadata={AzureResourceMetadata.NAME: "shared"},
        )
        foreign_account = _resource(
            "azurerm_storage_account.foreign",
            AzureResourceType.STORAGE_ACCOUNT,
            identifier=_arm_id(
                "sub-0002",
                "application",
                "Microsoft.Storage/storageAccounts/shared",
            ),
            metadata={AzureResourceMetadata.NAME: "shared"},
        )
        foreign_unique = _resource(
            "azurerm_storage_account.foreign_unique",
            AzureResourceType.STORAGE_ACCOUNT,
            identifier=_arm_id(
                "sub-0002",
                "application",
                "Microsoft.Storage/storageAccounts/unique",
            ),
            metadata={AzureResourceMetadata.NAME: "unique"},
        )
        primary_vault = _resource(
            "azurerm_key_vault.shared",
            AzureResourceType.KEY_VAULT,
            identifier=_arm_id(
                "sub-0001",
                "application",
                "Microsoft.KeyVault/vaults/shared",
            ),
            metadata={AzureResourceMetadata.NAME: "shared"},
        )
        source = _resource(
            "azurerm_storage_container.source",
            AzureResourceType.STORAGE_CONTAINER,
            identifier=_arm_id(
                "sub-0001",
                "application",
                "Microsoft.Storage/storageAccounts/source/blobServices/default/containers/source",
            ),
        )
        subscription_source = _resource(
            "azurerm_role_definition.source",
            AzureResourceType.ROLE_DEFINITION,
            identifier=("/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/source"),
        )
        references = (
            AzureResourceIndexBuilder()
            .build(
                [
                    foreign_account,
                    primary_vault,
                    sibling_account,
                    foreign_unique,
                    primary_account,
                ]
            )
            .resources_by_reference
        )

        unscoped = references.resolve(
            "shared",
            resource_types={AzureResourceType.STORAGE_ACCOUNT},
        )
        scoped = references.resolve(
            "shared",
            source=source,
            resource_types={AzureResourceType.STORAGE_ACCOUNT},
        )
        subscription_scoped = references.resolve(
            "shared",
            source=subscription_source,
            resource_types={AzureResourceType.STORAGE_ACCOUNT},
        )
        typed = references.resolve(
            "shared",
            source=source,
            resource_types={AzureResourceType.KEY_VAULT},
        )
        weak_cross_scope = references.resolve(
            "unique",
            source=source,
            resource_types={AzureResourceType.STORAGE_ACCOUNT},
        )
        strong_cross_scope = references.resolve(
            foreign_unique.identifier.upper(),
            source=source,
            resource_types={AzureResourceType.STORAGE_ACCOUNT},
        )

        self.assertEqual(unscoped.state, "ambiguous")
        self.assertEqual(
            unscoped.candidates,
            (foreign_account, primary_account, sibling_account),
        )
        self.assertEqual(scoped.state, "resolved")
        self.assertIs(scoped.selected_candidate, primary_account)
        self.assertEqual(subscription_scoped.state, "ambiguous")
        self.assertEqual(
            subscription_scoped.candidates,
            (primary_account, sibling_account),
        )
        self.assertEqual(typed.state, "resolved")
        self.assertIs(typed.selected_candidate, primary_vault)
        self.assertEqual(weak_cross_scope.state, "unresolved")
        self.assertEqual(strong_cross_scope.state, "resolved")
        self.assertIs(strong_cross_scope.selected_candidate, foreign_unique)

    def test_weak_reference_scope_contract_fails_closed_on_unknown_candidates(self) -> None:
        local = _resource(
            "azurerm_storage_account.local",
            AzureResourceType.STORAGE_ACCOUNT,
            identifier=_arm_id(
                "sub-0001",
                "application",
                "Microsoft.Storage/storageAccounts/local",
            ),
            metadata={AzureResourceMetadata.NAME: "shared"},
        )
        foreign = _resource(
            "azurerm_storage_account.foreign",
            AzureResourceType.STORAGE_ACCOUNT,
            identifier=_arm_id(
                "sub-0001",
                "secondary",
                "Microsoft.Storage/storageAccounts/foreign",
            ),
            metadata={AzureResourceMetadata.NAME: "shared"},
        )
        unknown = _resource(
            "azurerm_storage_account.unknown",
            AzureResourceType.STORAGE_ACCOUNT,
            metadata={AzureResourceMetadata.NAME: "shared"},
        )
        source = _resource(
            "azurerm_storage_container.source",
            AzureResourceType.STORAGE_CONTAINER,
            identifier=_arm_id(
                "sub-0001",
                "application",
                "Microsoft.Storage/storageAccounts/source/blobServices/default/containers/source",
            ),
        )
        cases = (
            ("known-local", (local,), "resolved", (local,)),
            ("known-local-and-known-foreign", (local, foreign), "resolved", (local,)),
            ("known-local-and-unknown", (local, unknown), "ambiguous", (local, unknown)),
            (
                "known-local-known-foreign-and-unknown",
                (local, foreign, unknown),
                "ambiguous",
                (local, unknown),
            ),
            ("known-foreign", (foreign,), "unresolved", ()),
            ("unknown", (unknown,), "unresolved", ()),
            ("known-foreign-and-unknown", (foreign, unknown), "unresolved", ()),
        )

        for name, candidates, expected_state, expected_candidates in cases:
            for ordered_candidates in (candidates, tuple(reversed(candidates))):
                with self.subTest(
                    case=name,
                    order=[candidate.address for candidate in ordered_candidates],
                ):
                    resolution = (
                        AzureResourceIndexBuilder()
                        .build(list(ordered_candidates))
                        .resources_by_reference.resolve(
                            "shared",
                            source=source,
                            resource_types={AzureResourceType.STORAGE_ACCOUNT},
                        )
                    )

                    self.assertEqual(resolution.state, expected_state)
                    self.assertEqual(resolution.candidates, expected_candidates)

        exact = (
            AzureResourceIndexBuilder()
            .build([unknown])
            .resources_by_reference.resolve(
                unknown.address,
                source=source,
                resource_types={AzureResourceType.STORAGE_ACCOUNT},
            )
        )
        self.assertEqual(exact.state, "resolved")
        self.assertIs(exact.selected_candidate, unknown)

    def test_ambiguous_storage_reference_does_not_decorate_an_arbitrary_account(self) -> None:
        def snapshot(reverse: bool) -> tuple[str | None, tuple[str, ...]]:
            accounts = [
                _resource(
                    f"azurerm_storage_account.{name}",
                    AzureResourceType.STORAGE_ACCOUNT,
                    identifier=_arm_id(
                        "sub-0001",
                        "application",
                        f"Microsoft.Storage/storageAccounts/{name}",
                    ),
                    metadata={
                        AzureResourceMetadata.NAME: "shared",
                        AzureResourceMetadata.ALLOW_NESTED_ITEMS_TO_BE_PUBLIC: True,
                        AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED: True,
                        AzureResourceMetadata.NETWORK_DEFAULT_ACTION: "Allow",
                    },
                )
                for name in ("first", "second")
            ]
            container = _resource(
                "azurerm_storage_container.objects",
                AzureResourceType.STORAGE_CONTAINER,
                identifier=_arm_id(
                    "sub-0001",
                    "application",
                    "Microsoft.Storage/storageAccounts/source/blobServices/default/containers/objects",
                ),
                metadata={
                    AzureResourceMetadata.STORAGE_ACCOUNT_REFERENCE: "shared",
                    AzureResourceMetadata.CONTAINER_ACCESS_TYPE: "blob",
                },
            )
            resources = [*accounts, container]
            if reverse:
                resources.reverse()
            AzureResourceDecorator(stages=(DecorateStorageRelationshipsStage(),)).decorate(resources)
            return (
                azure_facts(container).resolved_storage_account_address,
                tuple(
                    container.metadata_snapshot().get(
                        "unresolved_storage_account_references",
                        (),
                    )
                ),
            )

        expected = (None, ("shared",))
        self.assertEqual(snapshot(reverse=False), expected)
        self.assertEqual(snapshot(reverse=True), expected)

    def test_storage_decoration_uses_source_scope_and_target_type_in_both_orders(self) -> None:
        def snapshot(reverse: bool) -> tuple[str | None, bool, tuple[str, ...]]:
            primary_account = _resource(
                "azurerm_storage_account.primary",
                AzureResourceType.STORAGE_ACCOUNT,
                identifier=_arm_id(
                    "sub-0001",
                    "application",
                    "Microsoft.Storage/storageAccounts/primary",
                ),
                metadata={
                    AzureResourceMetadata.NAME: "shared",
                    AzureResourceMetadata.ALLOW_NESTED_ITEMS_TO_BE_PUBLIC: True,
                    AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED: True,
                    AzureResourceMetadata.NETWORK_DEFAULT_ACTION: "Allow",
                },
            )
            sibling_account = _resource(
                "azurerm_storage_account.sibling",
                AzureResourceType.STORAGE_ACCOUNT,
                identifier=_arm_id(
                    "sub-0001",
                    "secondary",
                    "Microsoft.Storage/storageAccounts/sibling",
                ),
                metadata={
                    AzureResourceMetadata.NAME: "shared",
                    AzureResourceMetadata.ALLOW_NESTED_ITEMS_TO_BE_PUBLIC: False,
                    AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED: True,
                    AzureResourceMetadata.NETWORK_DEFAULT_ACTION: "Allow",
                },
            )
            colliding_vault = _resource(
                "azurerm_key_vault.shared",
                AzureResourceType.KEY_VAULT,
                identifier=_arm_id(
                    "sub-0001",
                    "application",
                    "Microsoft.KeyVault/vaults/shared",
                ),
                metadata={AzureResourceMetadata.NAME: "shared"},
            )
            container = _resource(
                "azurerm_storage_container.objects",
                AzureResourceType.STORAGE_CONTAINER,
                identifier=_arm_id(
                    "sub-0001",
                    "application",
                    "Microsoft.Storage/storageAccounts/primary/blobServices/default/containers/objects",
                ),
                metadata={
                    AzureResourceMetadata.STORAGE_ACCOUNT_REFERENCE: "shared",
                    AzureResourceMetadata.CONTAINER_ACCESS_TYPE: "blob",
                },
            )
            resources = [
                sibling_account,
                colliding_vault,
                container,
                primary_account,
            ]
            if reverse:
                resources.reverse()
            AzureResourceDecorator(stages=(DecorateStorageRelationshipsStage(),)).decorate(resources)
            return (
                azure_facts(container).resolved_storage_account_address,
                container.public_exposure,
                tuple(
                    container.metadata_snapshot().get(
                        "unresolved_storage_account_references",
                        (),
                    )
                ),
            )

        expected = ("azurerm_storage_account.primary", True, ())
        self.assertEqual(snapshot(reverse=False), expected)
        self.assertEqual(snapshot(reverse=True), expected)


if __name__ == "__main__":
    unittest.main()
