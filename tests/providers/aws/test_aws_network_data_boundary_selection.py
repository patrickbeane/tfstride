from __future__ import annotations

import unittest
from collections.abc import Iterable
from itertools import permutations

from tfstride.analysis.rule_definitions import BoundaryIndex
from tfstride.models import BoundaryType, TrustBoundary
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


if __name__ == "__main__":
    unittest.main()
