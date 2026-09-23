from __future__ import annotations

import json
import tempfile
import unittest
from collections.abc import Callable
from itertools import permutations
from pathlib import Path

from tests.helpers.paths import FIXTURES_DIR
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.app import TfStride
from tfstride.models import BoundaryType, NormalizedResource, ResourceCategory, ResourceInventory
from tfstride.providers.aws.resource_index import AwsResourceIndexBuilder
from tfstride.providers.azure.resource_index import AzureResourceIndexBuilder
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_index import build_gcp_network_reference_view
from tfstride.providers.network_scope import NetworkScopeResolution

_TYPES = {
    "aws": ("aws_vpc", "aws_subnet"),
    "gcp": ("google_compute_network", "google_compute_subnetwork"),
    "azure": ("azurerm_virtual_network", "azurerm_subnet"),
}
_NETWORK_ATTRIBUTE = {"aws": "vpc_id", "gcp": "network", "azure": "virtual_network_name"}


def _native_network(provider: str, scope: str) -> str:
    if provider == "aws":
        account = "111122223333" if scope == "a" else "444455556666"
        return f"arn:aws:ec2:us-east-1:{account}:vpc/vpc-shared"
    if provider == "gcp":
        return f"projects/{scope}/global/networks/shared"
    return f"/subscriptions/{scope}/resourceGroups/group/providers/Microsoft.Network/virtualNetworks/shared"


def _network(provider: str, scope: str | None, label: str = "main") -> NormalizedResource:
    resource_type = _TYPES[provider][0]
    native = _native_network(provider, scope) if scope else None
    return NormalizedResource(
        address=f"{resource_type}.{label}",
        provider=provider,
        resource_type=resource_type,
        name=label,
        category=ResourceCategory.NETWORK,
        identifier="vpc-shared" if provider == "aws" else native or "shared",
        arn=native if provider == "aws" else None,
        provider_config_key=f"{provider}.{scope}" if scope else None,
        metadata={"name": "shared", **({GcpResourceMetadata.PROJECT: scope} if provider == "gcp" else {})},
    )


def _subnet(
    provider: str,
    scope: str | None,
    label: str,
    *,
    public: bool = False,
    reference: str | None = None,
) -> NormalizedResource:
    resource_type = _TYPES[provider][1]
    identifier = None
    if scope and provider == "azure":
        identifier = f"{_native_network(provider, scope)}/subnets/{label}"
    subnet = NormalizedResource(
        address=f"{resource_type}.{label}",
        provider=provider,
        resource_type=resource_type,
        name=label,
        category=ResourceCategory.NETWORK,
        identifier=identifier,
        provider_config_key=f"{provider}.{scope}" if scope else None,
        vpc_id=reference or ("vpc-shared" if provider == "aws" else "shared"),
        metadata={GcpResourceMetadata.PROJECT: scope} if provider == "gcp" else {},
    )
    subnet.is_public_subnet = public
    return subnet


def _resolver(
    provider: str, resources: list[NormalizedResource]
) -> Callable[[NormalizedResource], NetworkScopeResolution]:
    if provider == "aws":
        return AwsResourceIndexBuilder().build(resources).subnet_network_scope
    if provider == "gcp":
        return build_gcp_network_reference_view(resources).subnet_network_scope
    return AzureResourceIndexBuilder().build(resources).subnet_network_scope


def _boundaries(provider: str, resources: list[NormalizedResource]):
    return [
        boundary
        for boundary in detect_trust_boundaries(ResourceInventory(provider=provider, resources=resources))
        if boundary.boundary_type == BoundaryType.PUBLIC_TO_PRIVATE
    ]


class SubnetNetworkBoundaryTests(unittest.TestCase):
    def test_same_alias_in_different_scopes_does_not_connect_networks(self) -> None:
        for provider in _TYPES:
            with self.subTest(provider=provider):
                resources = [
                    _network(provider, "a", "first"),
                    _network(provider, "b", "second"),
                    _subnet(provider, "a", "public", public=True),
                    _subnet(provider, "b", "private"),
                ]
                for order in permutations(resources):
                    self.assertEqual(_boundaries(provider, list(order)), [])

    def test_native_alias_and_terraform_address_resolve_to_one_network(self) -> None:
        for provider in _TYPES:
            network = _network(provider, "a")
            for reference in (network.address, f"{network.address}.id", _native_network(provider, "a")):
                with self.subTest(provider=provider, reference=reference):
                    public = _subnet(provider, "a", "public", public=True, reference=reference)
                    private = _subnet(provider, "a", "private")
                    boundaries = _boundaries(provider, [public, private, network])
                    self.assertEqual(
                        [(item.source, item.target) for item in boundaries], [(public.address, private.address)]
                    )
                    self.assertIn("does not establish packet reachability", boundaries[0].rationale)
                    self.assertIn("separate trust zones", boundaries[0].description)

    def test_strong_cross_configuration_reference_survives_unrelated_local_alias(self) -> None:
        for provider in _TYPES:
            remote = _network(provider, "b", "remote")
            local = _network(provider, "a", "local")
            for reference in (remote.address, f"{remote.address}.id", _native_network(provider, "b")):
                with self.subTest(provider=provider, reference=reference):
                    public = _subnet(provider, "a", "public", public=True, reference=reference)
                    private = _subnet(provider, "b", "private")
                    resources = [public, remote, private, local]
                    for order in permutations(resources):
                        boundaries = _boundaries(provider, list(order))
                        self.assertEqual(
                            [(item.source, item.target) for item in boundaries], [(public.address, private.address)]
                        )

    def test_colliding_candidates_remain_ambiguous(self) -> None:
        for provider in _TYPES:
            with self.subTest(provider=provider):
                public = _subnet(provider, "a", "public", public=True)
                resources = [
                    _network(provider, "a", "first"),
                    _network(provider, "a", "second"),
                    public,
                    _subnet(provider, "a", "private"),
                ]
                for order in (resources, list(reversed(resources))):
                    resolution = _resolver(provider, order)(public)
                    self.assertEqual(resolution.state, "ambiguous")
                    self.assertIsNone(resolution.key)
                    self.assertEqual(len(resolution.reference_resolution.candidates), 2)
                    self.assertEqual(_boundaries(provider, order), [])

    def test_unknown_scope_cannot_merge_even_a_unique_modeled_weak_alias(self) -> None:
        for provider in _TYPES:
            for network_scope in (None, "a"):
                for modeled in (False, True):
                    with self.subTest(provider=provider, network_scope=network_scope, modeled=modeled):
                        public = _subnet(provider, None, "public", public=True)
                        resources = [public, _subnet(provider, None, "private")]
                        if modeled:
                            resources.append(_network(provider, network_scope))
                        resolution = _resolver(provider, resources)(public)
                        self.assertEqual(resolution.state, "unresolved")
                        self.assertIn("scope" if provider != "aws" else "configuration", resolution.reason)
                        self.assertEqual(_boundaries(provider, resources), [])

    def test_exact_reference_does_not_require_source_scope(self) -> None:
        for provider in _TYPES:
            with self.subTest(provider=provider):
                network = _network(provider, "a")
                resources = [
                    network,
                    _subnet(provider, None, "public", public=True, reference=f"{network.address}.id"),
                    _subnet(provider, "a", "private"),
                ]
                self.assertEqual(len(_boundaries(provider, resources)), 1)

    def test_known_scope_can_identify_an_unmodeled_network(self) -> None:
        for provider in _TYPES:
            with self.subTest(provider=provider):
                resources = [_subnet(provider, "a", "public", public=True), _subnet(provider, "a", "private")]
                self.assertEqual(len(_boundaries(provider, resources)), 1)
                resources[-1] = _subnet(provider, "b", "private")
                self.assertEqual(_boundaries(provider, resources), [])

    def test_unmodeled_strong_native_reference_keeps_its_scope_across_configurations(self) -> None:
        for provider in _TYPES:
            with self.subTest(provider=provider):
                reference = _native_network(provider, "b")
                public = _subnet(provider, "a", "public", public=True, reference=reference)
                private = _subnet(provider, "b", "private", reference=reference)
                self.assertEqual(len(_boundaries(provider, [public, private])), 1)

    def test_unresolved_expressions_are_not_network_identities(self) -> None:
        for provider in _TYPES:
            for reference in ("${var.network}", "unknown/network"):
                with self.subTest(provider=provider, reference=reference):
                    public = _subnet(provider, "a", "public", public=True, reference=reference)
                    private = _subnet(provider, "a", "private", reference=reference)
                    self.assertEqual(_boundaries(provider, [public, private]), [])

    def test_cloud_scope_takes_precedence_over_alias_equality(self) -> None:
        for provider in ("gcp", "azure"):
            with self.subTest(provider=provider):
                network = _network(provider, "a")
                public = _subnet(provider, "a", "public", public=True)
                private = _subnet(provider, "a", "private")
                private.provider_config_key = f"{provider}.another_alias"
                self.assertEqual(len(_boundaries(provider, [public, private, network])), 1)
                private = _subnet(provider, "b", "private")
                private.provider_config_key = public.provider_config_key
                self.assertEqual(_boundaries(provider, [public, private, network]), [])

    def test_azure_resource_group_is_part_of_the_network_namespace(self) -> None:
        public = _subnet("azure", "a", "public", public=True)
        private = _subnet("azure", "a", "private")
        assert private.identifier is not None
        private.identifier = private.identifier.replace("/group/", "/other/")
        self.assertEqual(_boundaries("azure", [public, private]), [])

    def test_canonical_native_spelling_is_provider_specific(self) -> None:
        for provider, reference in (
            ("gcp", "https://www.googleapis.com/compute/v1/projects/a/global/networks/shared"),
            ("azure", _native_network("azure", "a").upper()),
        ):
            with self.subTest(provider=provider):
                resources = [
                    _network(provider, "a"),
                    _subnet(provider, "a", "public", public=True, reference=reference),
                    _subnet(provider, "a", "private"),
                ]
                self.assertEqual(len(_boundaries(provider, resources)), 1)

    def test_multiple_boundary_order_is_independent_of_resource_order(self) -> None:
        for provider in _TYPES:
            with self.subTest(provider=provider):
                resources = [
                    _subnet(provider, "a", "public_b", public=True),
                    _subnet(provider, "a", "private_b"),
                    _subnet(provider, "a", "public_a", public=True),
                    _subnet(provider, "a", "private_a"),
                ]
                expected = sorted(
                    (public.address, private.address)
                    for public in resources
                    if public.is_public_subnet
                    for private in resources
                    if not private.is_public_subnet
                )
                for order in permutations(resources):
                    self.assertEqual(
                        [(item.source, item.target) for item in _boundaries(provider, list(order))], expected
                    )

    def test_unknown_candidate_scope_does_not_resolve_an_alias_collision(self) -> None:
        for provider in _TYPES:
            with self.subTest(provider=provider):
                public = _subnet(provider, "a", "public", public=True)
                resources = [
                    public,
                    _subnet(provider, "a", "private"),
                    _network(provider, "a", "known"),
                    _network(provider, None, "unknown"),
                ]
                resolution = _resolver(provider, resources)(public)
                self.assertEqual(resolution.state, "ambiguous")
                self.assertEqual(_boundaries(provider, resources), [])

    def test_aws_malformed_arn_is_not_a_strong_cross_configuration_identity(self) -> None:
        network = _network("aws", "b")
        network.arn = "not-an-arn"
        public = _subnet("aws", "a", "public", public=True, reference=network.arn)
        private = _subnet("aws", "b", "private")
        self.assertEqual(_boundaries("aws", [network, public, private]), [])


def _plan(provider: str, *, symbolic: bool, ambiguous: bool = False, suffix: str | None = None) -> dict:
    network = _network(provider, "b", "remote")
    public = _subnet(provider, "a", "public", public=True)
    private = _subnet(provider, "b", "private")
    attribute = _NETWORK_ATTRIBUTE[provider]
    suffix = suffix or ("name" if provider == "azure" else "id")
    references = [f"{network.address}.{suffix}"]
    resources = [network, public, private]
    if ambiguous:
        local = _network(provider, "a", "local")
        resources.append(local)
        references.append(f"{local.address}.{suffix}")
    planned = []
    configurations = []
    changes = []
    for resource in resources:
        declaration = {
            "address": resource.address,
            "mode": "managed",
            "type": resource.resource_type,
            "name": resource.name,
        }
        values = {
            "id": resource.identifier,
            "name": "shared" if resource.resource_type == _TYPES[provider][0] else resource.name,
        }
        if provider == "aws":
            values["arn"] = resource.arn
        elif provider == "gcp":
            values["project"] = "a" if resource is public else "b"
        expressions = {}
        if resource in (public, private):
            values[attribute] = None if symbolic else _native_network(provider, "b")
            expressions[attribute] = {"references": references}
            if symbolic:
                changes.append({**declaration, "change": {"actions": ["create"], "after_unknown": {attribute: True}}})
        planned.append({**declaration, "values": values})
        configurations.append(
            {**declaration, "provider_config_key": resource.provider_config_key, "expressions": expressions}
        )
    if provider == "aws":
        # An explicit route association establishes public posture independently
        # of the VPC reference being known on first apply.
        for resource_type, name, values in (
            (
                "aws_route_table",
                "public",
                {"id": "rtb-public", "route": [{"cidr_block": "0.0.0.0/0", "gateway_id": "igw-main"}]},
            ),
            (
                "aws_route_table_association",
                "public",
                {"subnet_id": public.address, "route_table_id": "aws_route_table.public"},
            ),
        ):
            declaration = {"address": f"{resource_type}.{name}", "mode": "managed", "type": resource_type, "name": name}
            planned.append({**declaration, "values": values})
            configurations.append({**declaration, "provider_config_key": "aws.a", "expressions": {}})
    return {
        "terraform_version": "1.8.5",
        "planned_values": {"root_module": {"resources": planned}},
        "configuration": {"root_module": {"resources": configurations}},
        "resource_changes": changes,
    }


def _analyze(payload: dict):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "plan.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return TfStride().analyze_plan(path)


class PlanSubnetNetworkScopeTests(unittest.TestCase):
    def test_curated_aws_subnet_boundaries_require_their_configuration_evidence(self) -> None:
        scenarios = {
            "sample_aws_plan.json": [("public_app", "private_data")],
            "sample_aws_baseline_plan.json": [("public_edge", "private_app"), ("public_edge", "private_data")],
            "sample_aws_safe_plan.json": [("public_edge", "private_app"), ("public_edge", "private_data")],
            "sample_aws_nightmare_plan.json": [("public_web", "private_data"), ("public_web", "private_ops")],
            "sample_aws_alb_ec2_rds_plan.json": [("public_edge", "private_app"), ("public_edge", "private_data")],
            "sample_aws_lambda_deploy_role_plan.json": [("public_edge", "private_app")],
            "sample_aws_ecs_fargate_plan.json": [("public_a", "private_app"), ("public_b", "private_app")],
        }
        for name, pairs in scenarios.items():
            with self.subTest(fixture=name):
                payload = json.loads((FIXTURES_DIR / "aws" / name).read_text(encoding="utf-8"))
                scoped = _analyze(payload)
                self.assertEqual(
                    [
                        (item.source, item.target)
                        for item in scoped.trust_boundaries
                        if item.boundary_type == BoundaryType.PUBLIC_TO_PRIVATE
                    ],
                    [(f"aws_subnet.{source}", f"aws_subnet.{target}") for source, target in pairs],
                )
                payload.pop("configuration")
                unscoped = _analyze(payload)
                self.assertEqual(
                    [
                        item
                        for item in unscoped.trust_boundaries
                        if item.boundary_type == BoundaryType.PUBLIC_TO_PRIVATE
                    ],
                    [],
                )
                # Losing scope evidence removes the membership assertion without
                # changing subnet posture or independently established findings.
                self.assertEqual(
                    [(item.address, item.is_public_subnet) for item in scoped.inventory.by_type("aws_subnet")],
                    [(item.address, item.is_public_subnet) for item in unscoped.inventory.by_type("aws_subnet")],
                )
                self.assertEqual(
                    [(item.rule_id, item.severity, item.affected_resources) for item in scoped.findings],
                    [(item.rule_id, item.severity, item.affected_resources) for item in unscoped.findings],
                )

    def test_ingestion_preserves_strong_native_and_first_apply_cross_configuration_references(self) -> None:
        for provider in _TYPES:
            for symbolic in (False, True):
                with self.subTest(provider=provider, symbolic=symbolic):
                    result = _analyze(_plan(provider, symbolic=symbolic))
                    public = result.inventory.get_by_address(f"{_TYPES[provider][1]}.public")
                    private = result.inventory.get_by_address(f"{_TYPES[provider][1]}.private")
                    assert public is not None and private is not None
                    resolver = _resolver(provider, list(result.inventory.resources))
                    self.assertEqual(resolver(public).state, "resolved")
                    self.assertEqual(resolver(public).key, resolver(private).key)
                    if provider == "aws":
                        self.assertEqual(
                            len(
                                [
                                    item
                                    for item in result.trust_boundaries
                                    if item.boundary_type == BoundaryType.PUBLIC_TO_PRIVATE
                                ]
                            ),
                            1,
                        )

    def test_known_planned_identity_is_not_overridden_by_multiple_configuration_dependencies(self) -> None:
        for provider in _TYPES:
            with self.subTest(provider=provider):
                result = _analyze(_plan(provider, symbolic=False, ambiguous=True))
                public = result.inventory.get_by_address(f"{_TYPES[provider][1]}.public")
                assert public is not None
                resolution = _resolver(provider, list(result.inventory.resources))(public)
                self.assertEqual(resolution.state, "resolved")
                candidate = resolution.reference_resolution.selected_candidate
                assert candidate is not None
                self.assertEqual(candidate.address, f"{_TYPES[provider][0]}.remote")

    def test_conditional_or_nonidentity_symbolic_references_do_not_create_boundaries(self) -> None:
        for provider in _TYPES:
            for ambiguous, suffix in ((True, None), (False, "description")):
                with self.subTest(provider=provider, ambiguous=ambiguous, suffix=suffix):
                    result = _analyze(_plan(provider, symbolic=True, ambiguous=ambiguous, suffix=suffix))
                    public = result.inventory.get_by_address(f"{_TYPES[provider][1]}.public")
                    assert public is not None
                    resolution = _resolver(provider, list(result.inventory.resources))(public)
                    self.assertIsNone(resolution.key)
                    self.assertIn("symbolic identity", resolution.reason)
                    self.assertEqual(resolution.state, "ambiguous" if ambiguous else "unresolved")
                    self.assertEqual(
                        [
                            item
                            for item in result.trust_boundaries
                            if item.boundary_type == BoundaryType.PUBLIC_TO_PRIVATE
                        ],
                        [],
                    )


if __name__ == "__main__":
    unittest.main()
