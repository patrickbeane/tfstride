from __future__ import annotations

import unittest
from collections.abc import Iterable
from itertools import permutations

from tfstride.analysis.rule_definitions import BoundaryIndex
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import (
    BoundaryType,
    Finding,
    NormalizedResource,
    ResourceCategory,
    ResourceInventory,
    SecurityGroupRule,
    TrustBoundary,
)
from tfstride.providers.aws.network_data_rules import _select_workload_to_database_boundary

_DATABASE = "module.data.aws_db_instance.app"
_WORKLOAD = "module.compute.aws_instance.web[0]"


def _boundary(
    source: str,
    target: str,
    *,
    boundary_type: BoundaryType = BoundaryType.WORKLOAD_TO_DATA_STORE,
    identifier: str | None = None,
) -> TrustBoundary:
    return TrustBoundary(
        identifier=identifier or f"{boundary_type.value}:{source}->{target}",
        boundary_type=boundary_type,
        source=source,
        target=target,
        description=f"{source} can reach {target}.",
        rationale="Modeled path evidence.",
    )


def _boundary_index(boundaries: Iterable[TrustBoundary]) -> BoundaryIndex:
    return {(boundary.boundary_type, boundary.source, boundary.target): boundary for boundary in boundaries}


def _resource(
    address: str,
    resource_type: str,
    category: ResourceCategory,
    *,
    identifier: str | None = None,
    vpc_id: str | None = None,
    security_group_ids: tuple[str, ...] = (),
    network_rules: tuple[SecurityGroupRule, ...] = (),
    public_exposure: bool = False,
) -> NormalizedResource:
    return NormalizedResource(
        address=address,
        provider="aws",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        category=category,
        identifier=identifier,
        vpc_id=vpc_id,
        security_group_ids=security_group_ids,
        network_rules=network_rules,
        public_exposure=public_exposure,
        provider_config_key="aws.default",
    )


def _database_exposure_resources(
    *workload_addresses: str,
) -> tuple[list[NormalizedResource], NormalizedResource]:
    source_groups = [
        _resource(
            f"aws_security_group.source_{index}",
            "aws_security_group",
            ResourceCategory.NETWORK,
            identifier=f"sg-source-{index}",
            vpc_id="vpc-shared",
        )
        for index, _ in enumerate(workload_addresses)
    ]
    workloads = [
        _resource(
            address,
            "aws_instance",
            ResourceCategory.COMPUTE,
            vpc_id="vpc-shared",
            security_group_ids=(source_group.identifier or "",),
            public_exposure=True,
        )
        for address, source_group in zip(workload_addresses, source_groups, strict=True)
    ]
    database_group = _resource(
        "aws_security_group.database",
        "aws_security_group",
        ResourceCategory.NETWORK,
        identifier="sg-database",
        vpc_id="vpc-shared",
        network_rules=(
            SecurityGroupRule(
                direction="ingress",
                protocol="tcp",
                from_port=5432,
                to_port=5432,
                referenced_security_group_ids=[group.identifier or "" for group in source_groups],
            ),
        ),
    )
    database = _resource(
        _DATABASE,
        "aws_db_instance",
        ResourceCategory.DATA,
        identifier="database",
        vpc_id="vpc-shared",
        security_group_ids=("sg-database",),
    )
    return [*source_groups, *workloads, database_group, database], database


def _database_exposure_finding(
    resources: list[NormalizedResource],
    boundaries: Iterable[TrustBoundary],
) -> Finding:
    findings = StrideRuleEngine().evaluate(
        ResourceInventory(provider="aws", resources=resources),
        list(boundaries),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({"aws-database-permissive-ingress"})),
    )
    if len(findings) != 1:
        raise AssertionError(f"Expected one database exposure finding, received {len(findings)}")
    return findings[0]


class AwsWorkloadToDatabaseBoundarySelectionTests(unittest.TestCase):
    def test_selects_exact_endpoints_among_unrelated_boundaries(self) -> None:
        matching = _boundary(_WORKLOAD, _DATABASE)
        unrelated = (
            _boundary("module.compute.aws_instance.web[1]", _DATABASE),
            _boundary("module.other.aws_instance.web[0]", _DATABASE),
            _boundary(_WORKLOAD, "module.other.aws_db_instance.app"),
            _boundary(_DATABASE, _WORKLOAD),
            _boundary(_WORKLOAD, _DATABASE, boundary_type=BoundaryType.CONTROL_TO_WORKLOAD),
            _boundary("internet", _DATABASE, boundary_type=BoundaryType.INTERNET_TO_SERVICE),
            _boundary(
                "aws_subnet.public",
                "aws_subnet.private",
                boundary_type=BoundaryType.PUBLIC_TO_PRIVATE,
            ),
        )

        for matching_first in (True, False):
            with self.subTest(matching_first=matching_first):
                boundaries = (matching, *unrelated) if matching_first else (*unrelated, matching)
                selected = _select_workload_to_database_boundary(
                    _boundary_index(boundaries),
                    _DATABASE,
                    [_WORKLOAD],
                )

                self.assertIs(selected, matching)

    def test_multiple_matches_are_independent_of_boundary_and_workload_order(self) -> None:
        # Boundary identifiers deliberately sort in the opposite order to sources.
        first = _boundary("aws_instance.alpha", _DATABASE, identifier="z-first-workload")
        second = _boundary("aws_instance.zeta", _DATABASE, identifier="a-second-workload")
        wrong_database = _boundary("aws_instance.aaa", "aws_db_instance.other")
        workloads = ("aws_instance.aaa", "aws_instance.alpha", "aws_instance.zeta")

        for boundaries in permutations((first, second, wrong_database)):
            for workload_order in permutations(workloads):
                with self.subTest(
                    boundaries=tuple(boundary.identifier for boundary in boundaries),
                    workloads=workload_order,
                ):
                    selected = _select_workload_to_database_boundary(
                        _boundary_index(boundaries),
                        _DATABASE,
                        workload_order,
                    )

                    self.assertIs(selected, first)

    def test_returns_none_when_no_exact_match_exists(self) -> None:
        matching = _boundary(_WORKLOAD, _DATABASE)
        cases = (
            ("empty index", (), (_WORKLOAD,), _DATABASE),
            ("no matched workloads", (matching,), (), _DATABASE),
            ("unmatched source", (matching,), ("module.compute.aws_instance.web",), _DATABASE),
            ("different target", (matching,), (_WORKLOAD,), "module.other.aws_db_instance.app"),
            ("reversed endpoints", (_boundary(_DATABASE, _WORKLOAD),), (_WORKLOAD,), _DATABASE),
            (
                "different boundary type",
                (_boundary(_WORKLOAD, _DATABASE, boundary_type=BoundaryType.PUBLIC_TO_PRIVATE),),
                (_WORKLOAD,),
                _DATABASE,
            ),
        )

        for name, boundaries, workloads, database in cases:
            with self.subTest(case=name):
                self.assertIsNone(
                    _select_workload_to_database_boundary(
                        _boundary_index(boundaries),
                        database,
                        workloads,
                    )
                )

    def test_duplicate_workload_addresses_in_an_iterator_do_not_change_selection(self) -> None:
        first = _boundary("aws_instance.alpha", _DATABASE)
        second = _boundary("aws_instance.zeta", _DATABASE)
        workloads = iter(("aws_instance.zeta", "aws_instance.alpha", "aws_instance.zeta", "aws_instance.alpha"))

        selected = _select_workload_to_database_boundary(
            _boundary_index((second, first)),
            _DATABASE,
            workloads,
        )

        self.assertIs(selected, first)


class AwsDatabaseExposureBoundaryAttributionTests(unittest.TestCase):
    def test_unrelated_boundaries_are_not_attributed_and_finding_remains(self) -> None:
        resources, database = _database_exposure_resources(_WORKLOAD)
        resources.extend(
            (
                _resource(
                    "aws_subnet.public_same_vpc",
                    "aws_subnet",
                    ResourceCategory.NETWORK,
                    identifier="subnet-public-same-vpc",
                    vpc_id="vpc-shared",
                ),
                _resource(
                    "aws_subnet.private_same_vpc",
                    "aws_subnet",
                    ResourceCategory.NETWORK,
                    identifier="subnet-private-same-vpc",
                    vpc_id="vpc-shared",
                ),
                _resource(
                    "aws_subnet.public_other_vpc",
                    "aws_subnet",
                    ResourceCategory.NETWORK,
                    identifier="subnet-public-other-vpc",
                    vpc_id="vpc-other",
                ),
                _resource(
                    "aws_subnet.private_other_vpc",
                    "aws_subnet",
                    ResourceCategory.NETWORK,
                    identifier="subnet-private-other-vpc",
                    vpc_id="vpc-other",
                ),
            )
        )
        unrelated_boundaries = (
            _boundary(
                "aws_subnet.public_same_vpc",
                "aws_subnet.private_same_vpc",
                boundary_type=BoundaryType.PUBLIC_TO_PRIVATE,
                identifier="same-vpc-subnet-boundary",
            ),
            _boundary(
                "aws_subnet.public_other_vpc",
                "aws_subnet.private_other_vpc",
                boundary_type=BoundaryType.PUBLIC_TO_PRIVATE,
                identifier="other-vpc-subnet-boundary",
            ),
            _boundary(
                _WORKLOAD,
                "aws_db_instance.unrelated",
                identifier="wrong-database-boundary",
            ),
        )

        for ordered_boundaries in (unrelated_boundaries, tuple(reversed(unrelated_boundaries))):
            for ordered_resources in (resources, list(reversed(resources))):
                with self.subTest(
                    boundary_order=[boundary.identifier for boundary in ordered_boundaries],
                    resource_order=[resource.address for resource in ordered_resources],
                ):
                    finding = _database_exposure_finding(ordered_resources, ordered_boundaries)

                    self.assertIn(database.address, finding.affected_resources)
                    self.assertIsNone(finding.trust_boundary_id)

    def test_selects_matching_boundary_for_later_matched_workload(self) -> None:
        first_workload = "aws_instance.alpha"
        later_workload = "aws_instance.zeta"
        resources, _ = _database_exposure_resources(first_workload, later_workload)
        matching = _boundary(later_workload, _DATABASE, identifier="later-workload-boundary")
        unrelated = _boundary(first_workload, "aws_db_instance.unrelated", identifier="unrelated-boundary")

        for ordered_boundaries in ((unrelated, matching), (matching, unrelated)):
            for ordered_resources in (resources, list(reversed(resources))):
                with self.subTest(
                    boundary_order=[boundary.identifier for boundary in ordered_boundaries],
                    resource_order=[resource.address for resource in ordered_resources],
                ):
                    finding = _database_exposure_finding(ordered_resources, ordered_boundaries)

                    self.assertEqual(finding.trust_boundary_id, matching.identifier)


if __name__ == "__main__":
    unittest.main()
