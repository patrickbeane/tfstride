from __future__ import annotations

import unittest
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol, cast
from unittest.mock import patch

from tfstride.models import NormalizedResource, ResourceCategory
from tfstride.providers.aws.resource_decoration_stages import AwsDecorationStage
from tfstride.providers.aws.resource_decorator import AwsResourceDecorator
from tfstride.providers.aws.resource_index import AwsResourceIndexBuilder
from tfstride.providers.azure.resource_decoration_stages import (
    AzureDecorationStage,
    default_azure_decoration_stages,
)
from tfstride.providers.azure.resource_decorator import AzureResourceDecorator
from tfstride.providers.azure.resource_index import AzureResourceIndexBuilder
from tfstride.providers.gcp.resource_decoration_stages import GcpDecorationStage
from tfstride.providers.gcp.resource_decorator import GcpResourceDecorator
from tfstride.providers.gcp.resource_index import GcpResourceIndexBuilder

_DECORATION_MARKER = "arn:test:decorated"


class _Decorator(Protocol):
    def decorate(self, resources: list[NormalizedResource]) -> None: ...


_StageAction = Callable[[list[NormalizedResource], object], None]


class _RecordingIndexBuilder:
    def __init__(self, events: list[str]) -> None:
        self._events = events
        self.index = object()
        self.resources: list[list[NormalizedResource]] = []

    def build(self, resources: list[NormalizedResource]) -> object:
        self._events.append("build")
        self.resources.append(resources)
        return self.index


@dataclass(frozen=True, slots=True)
class _RecordingContext:
    index: object


class _RecordingContextFactory:
    def __init__(self) -> None:
        self.contexts: list[_RecordingContext] = []

    def __call__(self, *, index: object) -> _RecordingContext:
        context = _RecordingContext(index=index)
        self.contexts.append(context)
        return context


class _RecordingStage:
    def __init__(
        self,
        name: str,
        events: list[str],
        action: _StageAction | None = None,
    ) -> None:
        self.name = name
        self._events = events
        self._action = action
        self.resources: list[list[NormalizedResource]] = []
        self.contexts: list[object] = []

    def apply(self, resources: list[NormalizedResource], context: object) -> None:
        self._events.append(f"stage:{self.name}")
        self.resources.append(resources)
        self.contexts.append(context)
        if self._action is not None:
            self._action(resources, context)


def _aws_decorator(
    index_builder: _RecordingIndexBuilder,
    stages: Sequence[_RecordingStage],
) -> _Decorator:
    return AwsResourceDecorator(
        index_builder=cast(AwsResourceIndexBuilder, index_builder),
        stages=cast(Sequence[AwsDecorationStage], stages),
    )


def _gcp_decorator(
    index_builder: _RecordingIndexBuilder,
    stages: Sequence[_RecordingStage],
) -> _Decorator:
    return GcpResourceDecorator(
        index_builder=cast(GcpResourceIndexBuilder, index_builder),
        stages=cast(Sequence[GcpDecorationStage], stages),
    )


def _azure_decorator(
    index_builder: _RecordingIndexBuilder,
    stages: Sequence[_RecordingStage],
) -> _Decorator:
    return AzureResourceDecorator(
        index_builder=cast(AzureResourceIndexBuilder, index_builder),
        stages=cast(Sequence[AzureDecorationStage], stages),
    )


_DecoratorFactory = Callable[[_RecordingIndexBuilder, Sequence[_RecordingStage]], _Decorator]


@dataclass(frozen=True, slots=True)
class _DecoratorCase:
    provider: str
    factory: _DecoratorFactory
    context_patch_target: str
    default_stages_patch_target: str


_DECORATOR_CASES = (
    _DecoratorCase(
        provider="aws",
        factory=_aws_decorator,
        context_patch_target="tfstride.providers.aws.resource_decorator.AwsDecorationContext",
        default_stages_patch_target="tfstride.providers.aws.resource_decorator.default_aws_decoration_stages",
    ),
    _DecoratorCase(
        provider="gcp",
        factory=_gcp_decorator,
        context_patch_target="tfstride.providers.gcp.resource_decorator.GcpDecorationContext",
        default_stages_patch_target="tfstride.providers.gcp.resource_decorator.default_gcp_decoration_stages",
    ),
    _DecoratorCase(
        provider="azure",
        factory=_azure_decorator,
        context_patch_target="tfstride.providers.azure.resource_decorator.AzureDecorationContext",
        default_stages_patch_target="tfstride.providers.azure.resource_decorator.default_azure_decoration_stages",
    ),
)


def _resource() -> NormalizedResource:
    return NormalizedResource(
        address="example_resource.target",
        provider="example",
        resource_type="example_resource",
        name="target",
        category=ResourceCategory.DATA,
    )


def _add_decoration(
    resources: list[NormalizedResource],
    _context: object,
) -> None:
    resources[0].add_attached_role_arn(_DECORATION_MARKER)


def _observe_decoration(
    observations: list[tuple[str, ...]],
) -> _StageAction:
    def observe(
        resources: list[NormalizedResource],
        _context: object,
    ) -> None:
        observations.append(resources[0].attached_role_arns)

    return observe


class _DecorationFailure(RuntimeError):
    pass


class ProviderDecorationRunnerContractTests(unittest.TestCase):
    def test_runner_builds_one_context_then_runs_stages_in_order_with_shared_state(self) -> None:
        for case in _DECORATOR_CASES:
            with self.subTest(provider=case.provider):
                events: list[str] = []
                resources = [_resource()]
                downstream_attached_roles: list[tuple[str, ...]] = []

                first = _RecordingStage("first", events, _add_decoration)
                second = _RecordingStage("second", events, _observe_decoration(downstream_attached_roles))
                index_builder = _RecordingIndexBuilder(events)
                context_factory = _RecordingContextFactory()

                with patch(case.context_patch_target, side_effect=context_factory) as context_constructor:
                    case.factory(index_builder, (first, second)).decorate(resources)

                self.assertEqual(events, ["build", "stage:first", "stage:second"])
                self.assertEqual(len(index_builder.resources), 1)
                self.assertIs(index_builder.resources[0], resources)
                context_constructor.assert_called_once()
                self.assertEqual(len(context_factory.contexts), 1)
                self.assertIs(context_factory.contexts[0].index, index_builder.index)
                self.assertIs(first.resources[0], resources)
                self.assertIs(second.resources[0], resources)
                self.assertIs(first.contexts[0], context_factory.contexts[0])
                self.assertIs(second.contexts[0], context_factory.contexts[0])
                self.assertEqual(downstream_attached_roles, [(_DECORATION_MARKER,)])

    def test_runner_stops_after_stage_failure_and_propagates_exception(self) -> None:
        for case in _DECORATOR_CASES:
            with self.subTest(provider=case.provider):
                events: list[str] = []

                def fail(
                    _resources: list[NormalizedResource],
                    _context: object,
                ) -> None:
                    raise _DecorationFailure("decoration failed")

                stages = (
                    _RecordingStage("before", events),
                    _RecordingStage("failing", events, fail),
                    _RecordingStage("after", events),
                )
                index_builder = _RecordingIndexBuilder(events)
                context_factory = _RecordingContextFactory()

                with (
                    patch(case.context_patch_target, side_effect=context_factory),
                    self.assertRaisesRegex(_DecorationFailure, "decoration failed"),
                ):
                    case.factory(index_builder, stages).decorate([_resource()])

                self.assertEqual(events, ["build", "stage:before", "stage:failing"])
                self.assertEqual(stages[2].resources, [])
                self.assertEqual(stages[2].contexts, [])

    def test_configured_stages_replace_provider_defaults(self) -> None:
        for case in _DECORATOR_CASES:
            with self.subTest(provider=case.provider):
                events: list[str] = []
                stage = _RecordingStage("configured", events)
                index_builder = _RecordingIndexBuilder(events)
                context_factory = _RecordingContextFactory()

                with (
                    patch(case.context_patch_target, side_effect=context_factory),
                    patch(case.default_stages_patch_target) as default_stages,
                ):
                    case.factory(index_builder, (stage,)).decorate([_resource()])

                default_stages.assert_not_called()
                self.assertEqual(events, ["build", "stage:configured"])

    def test_azure_default_decoration_stages_are_ordered_by_contract(self) -> None:
        self.assertEqual(
            [stage.name for stage in default_azure_decoration_stages()],
            [
                "resolve_azure_symbolic_relationships",
                "resolve_azure_network_symbolic_relationships",
                "merge_network_security_rules",
                "resolve_subnet_virtual_networks",
                "resolve_network_security_associations",
                "resolve_network_interface_relationships",
                "resolve_virtual_machine_relationships",
                "derive_public_compute_exposure",
                "evaluate_app_service_ingress",
                "decorate_storage_relationships",
                "decorate_service_bus_relationships",
                "decorate_cosmosdb_nosql_relationships",
                "decorate_key_vault_relationships",
                "resolve_azure_key_vault_encryption_dependencies",
                "decorate_managed_identity_role_assignments",
                "normalize_key_vault_key_authorization_posture",
                "normalize_key_vault_secret_authorization_posture",
                "model_app_service_key_vault_operation_paths",
                "model_app_service_key_vault_management_paths",
                "model_app_service_key_vault_secret_management_paths",
                "model_app_service_cosmosdb_access_paths",
                "model_app_service_cosmosdb_item_deletion_paths",
                "model_app_service_cosmosdb_topology_destruction_paths",
                "model_app_service_diagnostic_setting_audit_telemetry_disruption_paths",
                "model_app_service_key_vault_access_paths",
                "model_app_service_storage_access_paths",
                "model_app_service_blob_deletion_paths",
                "model_app_service_storage_container_topology_destruction_paths",
                "model_app_service_service_bus_access_paths",
                "model_app_service_service_bus_message_removal_paths",
                "model_app_service_service_bus_topology_destruction_paths",
                "model_app_service_key_vault_protected_data_convergence",
                "model_federated_managed_identity_trust_paths",
                "model_app_service_acr_write_paths",
            ],
        )


if __name__ == "__main__":
    unittest.main()
