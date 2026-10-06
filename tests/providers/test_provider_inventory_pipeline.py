from __future__ import annotations

import unittest

from tfstride.models import (
    NormalizedResource,
    ResourceCategory,
    TerraformReferenceProvenance,
    TerraformReferenceResolution,
    TerraformReferenceResolutionState,
    TerraformResource,
)
from tfstride.providers.normalization import normalize_provider_inventory
from tfstride.resource_metadata import InventoryMetadata

_PROVIDER = "example"
_PROVIDER_NAME = "registry.example.com/example/provider"
_SUPPORTED_TYPE = "example_supported"
_UNSUPPORTED_TYPE = "example_unsupported"
_OTHER_UNSUPPORTED_TYPE = "example_other_unsupported"
_DECORATION_MARKER = "arn:example:decorated"


def _reference_resolution(name: str) -> TerraformReferenceResolution:
    return TerraformReferenceResolution(
        path=("dependency_id",),
        state=TerraformReferenceResolutionState.SYMBOLIC,
        provenance=TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
        references=(f"module.{name}.id",),
    )


def _terraform_resource(
    address: str,
    resource_type: str,
    *,
    provider_name: str = _PROVIDER_NAME,
    provider_config_key: str | None = None,
    reference_resolutions: tuple[TerraformReferenceResolution, ...] = (),
) -> TerraformResource:
    return TerraformResource(
        address=address,
        mode="managed",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        provider_name=provider_name,
        values={},
        provider_config_key=provider_config_key,
        reference_resolutions=reference_resolutions,
    )


class ProviderInventoryPipelineTests(unittest.TestCase):
    def test_decoration_sets_identity_before_inventory_indexes_are_sealed(self) -> None:
        source = _terraform_resource(f"{_SUPPORTED_TYPE}.example", _SUPPORTED_TYPE)

        def normalize_resource(resource: TerraformResource) -> NormalizedResource:
            return NormalizedResource(
                address=resource.address,
                provider=_PROVIDER,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.DATA,
            )

        def decorate_resources(resources: list[NormalizedResource]) -> None:
            resources[0].identifier = "decorated-id"
            resources[0].arn = "arn:example:decorated-id"

        inventory = normalize_provider_inventory(
            [source],
            provider=_PROVIDER,
            owns_resource=lambda resource: True,
            resource_normalizers={_SUPPORTED_TYPE: normalize_resource},
            decorate_resources=decorate_resources,
        )

        decorated = inventory.resources[0]
        self.assertIs(inventory.get_by_address(source.address), decorated)
        self.assertIs(inventory.get_by_identifier("decorated-id"), decorated)
        self.assertIs(inventory.get_by_identifier("arn:example:decorated-id"), decorated)
        with self.assertRaisesRegex(AttributeError, "identifier"):
            decorated.identifier = "late-id"

    def test_pipeline_runs_provider_neutral_inventory_workflow_in_order(self) -> None:
        first = _terraform_resource(
            f"{_SUPPORTED_TYPE}.zeta",
            _SUPPORTED_TYPE,
            provider_config_key="example.zeta",
            reference_resolutions=(_reference_resolution("zeta"),),
        )
        second = _terraform_resource(
            f"{_SUPPORTED_TYPE}.alpha",
            _SUPPORTED_TYPE,
            provider_config_key="example.alpha",
            reference_resolutions=(_reference_resolution("alpha"),),
        )
        unsupported_zeta = _terraform_resource(
            f"{_UNSUPPORTED_TYPE}.zeta",
            _UNSUPPORTED_TYPE,
        )
        unsupported_alpha = _terraform_resource(
            f"{_UNSUPPORTED_TYPE}.alpha",
            _UNSUPPORTED_TYPE,
        )
        other_unsupported = _terraform_resource(
            f"{_OTHER_UNSUPPORTED_TYPE}.example",
            _OTHER_UNSUPPORTED_TYPE,
        )
        foreign = _terraform_resource(
            "foreign_resource.ignored",
            "foreign_resource",
            provider_name="registry.example.com/foreign/provider",
        )
        resources = [
            first,
            unsupported_zeta,
            foreign,
            second,
            other_unsupported,
            unsupported_alpha,
        ]
        events: list[str] = []
        provider_configs_at_decoration: tuple[str | None, ...] = ()
        reference_resolutions_at_decoration: tuple[tuple[TerraformReferenceResolution, ...], ...] = ()
        resources_frozen_at_metadata_enrichment: tuple[bool, ...] = ()

        def owns_resource(resource: TerraformResource) -> bool:
            events.append(f"owns:{resource.address}")
            return resource.provider_name == _PROVIDER_NAME

        def normalize_resource(resource: TerraformResource) -> NormalizedResource:
            events.append(f"normalize:{resource.address}")
            return NormalizedResource(
                address=resource.address,
                provider=_PROVIDER,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.DATA,
            )

        def decorate_resources(resources: list[NormalizedResource]) -> None:
            nonlocal provider_configs_at_decoration, reference_resolutions_at_decoration
            addresses = tuple(resource.address for resource in resources)
            events.append(f"decorate:{','.join(addresses)}")
            provider_configs_at_decoration = tuple(resource.provider_config_key for resource in resources)
            reference_resolutions_at_decoration = tuple(resource.reference_resolutions for resource in resources)
            for resource in resources:
                resource.add_attached_role_arn(_DECORATION_MARKER)

        def enrich_inventory_metadata(
            resources: list[NormalizedResource],
            metadata: dict[str, object],
        ) -> None:
            nonlocal resources_frozen_at_metadata_enrichment
            addresses = tuple(resource.address for resource in resources)
            events.append(f"metadata:{','.join(addresses)}")
            frozen_states: list[bool] = []
            for resource in resources:
                try:
                    resource.add_attached_role_arn("arn:example:metadata-enrichment")
                except RuntimeError:
                    frozen_states.append(True)
                else:
                    frozen_states.append(False)
            resources_frozen_at_metadata_enrichment = tuple(frozen_states)
            metadata["provider_extension"] = "retained"
            InventoryMetadata.TOTAL_INPUT_RESOURCES.set(metadata, 999)

        inventory = normalize_provider_inventory(
            resources,
            provider=_PROVIDER,
            owns_resource=owns_resource,
            resource_normalizers={_SUPPORTED_TYPE: normalize_resource},
            decorate_resources=decorate_resources,
            enrich_inventory_metadata=enrich_inventory_metadata,
        )

        supported_addresses = (first.address, second.address)
        self.assertEqual(
            events,
            [
                *(f"owns:{resource.address}" for resource in resources),
                f"normalize:{first.address}",
                f"normalize:{second.address}",
                f"decorate:{','.join(supported_addresses)}",
                f"metadata:{','.join(supported_addresses)}",
            ],
        )
        self.assertEqual(inventory.provider, _PROVIDER)
        self.assertEqual(
            tuple(resource.address for resource in inventory.resources),
            supported_addresses,
        )
        self.assertEqual(
            inventory.unsupported_resources,
            sorted([unsupported_zeta.address, other_unsupported.address, unsupported_alpha.address]),
        )
        self.assertEqual(
            provider_configs_at_decoration,
            (first.provider_config_key, second.provider_config_key),
        )
        self.assertEqual(
            reference_resolutions_at_decoration,
            (first.reference_resolutions, second.reference_resolutions),
        )
        self.assertEqual(resources_frozen_at_metadata_enrichment, (True, True))
        for resource in inventory.resources:
            self.assertEqual(resource.attached_role_arns, (_DECORATION_MARKER,))
            with self.assertRaisesRegex(RuntimeError, "decoration state is frozen"):
                resource.add_attached_role_arn("arn:example:late-decoration")
        self.assertEqual(
            inventory.metadata_snapshot(),
            {
                "provider_extension": "retained",
                InventoryMetadata.SUPPORTED_RESOURCE_TYPES.key: [_SUPPORTED_TYPE],
                InventoryMetadata.TOTAL_INPUT_RESOURCES.key: len(resources),
                InventoryMetadata.PROVIDER_RESOURCE_COUNT.key: 5,
                InventoryMetadata.NORMALIZED_RESOURCE_COUNT.key: 2,
                InventoryMetadata.UNSUPPORTED_RESOURCE_TYPES.key: {
                    _OTHER_UNSUPPORTED_TYPE: 1,
                    _UNSUPPORTED_TYPE: 2,
                },
            },
        )

    def test_pipeline_decorates_empty_inventory_without_metadata_enrichment(self) -> None:
        decorated_resources: list[NormalizedResource] | None = None

        def decorate_resources(resources: list[NormalizedResource]) -> None:
            nonlocal decorated_resources
            decorated_resources = resources

        inventory = normalize_provider_inventory(
            [],
            provider=_PROVIDER,
            owns_resource=lambda resource: True,
            resource_normalizers={},
            decorate_resources=decorate_resources,
        )

        self.assertEqual(decorated_resources, [])
        self.assertEqual(inventory.resources, ())
        self.assertEqual(inventory.unsupported_resources, [])
        self.assertEqual(
            inventory.metadata_snapshot(),
            {
                InventoryMetadata.SUPPORTED_RESOURCE_TYPES.key: [],
                InventoryMetadata.TOTAL_INPUT_RESOURCES.key: 0,
                InventoryMetadata.PROVIDER_RESOURCE_COUNT.key: 0,
                InventoryMetadata.NORMALIZED_RESOURCE_COUNT.key: 0,
                InventoryMetadata.UNSUPPORTED_RESOURCE_TYPES.key: {},
            },
        )


if __name__ == "__main__":
    unittest.main()
