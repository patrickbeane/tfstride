from __future__ import annotations

import unittest
from dataclasses import asdict, replace
from itertools import permutations
from unittest.mock import patch

from tests.helpers.paths import FIXTURES_DIR
from tfstride.analysis.boundaries.types import BoundaryAccumulator, BoundaryAssessmentScope, BoundarySupport
from tfstride.analysis.relationships import (
    RelationshipAssessment,
    RelationshipKind,
    RelationshipOutcome,
    RelationshipPrerequisite,
    RelationshipTrafficScope,
)
from tfstride.app import TfStride
from tfstride.models import BoundaryType, TrustBoundary
from tfstride.reporting.json_report import build_json_report_payload

EDGE = (BoundaryType.INTERNET_TO_SERVICE, "internet", "aws_lb.web")


def _assessment() -> RelationshipAssessment:
    return RelationshipAssessment(
        source_address="internet",
        target_address="aws_ecs_service.app",
        kind=RelationshipKind.EFFECTIVE_INGRESS,
        operation="accept_public_request",
        outcome=RelationshipOutcome.ESTABLISHED,
        traffic_scope=(RelationshipTrafficScope("listener", "tcp", "HTTPS", 443, 443),),
        prerequisites=(RelationshipPrerequisite("forwarding_association", RelationshipOutcome.ESTABLISHED),),
        remaining_conditions=("path=/app/*",),
    )


def _add(accumulator: BoundaryAccumulator, support: BoundarySupport) -> None:
    accumulator.add_boundary(
        *EDGE,
        support.description,
        support.rationale,
        assessment=support.assessment,
        assessment_scope=support.assessment_scope,
    )


class BoundarySupportTests(unittest.TestCase):
    def test_path_crossing_is_distinct_from_whole_relationship_support(self) -> None:
        support = BoundarySupport("Public entry", "Verified path", _assessment())
        crossing = replace(support, assessment_scope="path_crossing")
        snapshots = []
        for ordering in ((support, crossing), (crossing, support)):
            accumulator = BoundaryAccumulator()
            for item in ordering:
                _add(accumulator, item)
            snapshots.append(accumulator.supports(*EDGE))
        self.assertEqual(snapshots[0], snapshots[1])
        self.assertEqual(set(snapshots[0]), {support, crossing})

    def test_exact_duplicates_are_deduplicated_without_losing_other_contributions(self) -> None:
        assessment = _assessment()
        support = BoundarySupport("Public entry", "Verified path", assessment)
        different_presentation = replace(support, rationale="Another explanation")
        accumulator = BoundaryAccumulator()
        for item in (support, replace(support, assessment=replace(assessment)), different_presentation):
            _add(accumulator, item)

        self.assertEqual(len(accumulator.boundaries()), 1)
        self.assertEqual(set(accumulator.supports(*EDGE)), {support, different_presentation})

    def test_conditional_alternatives_and_presentation_are_order_independent(self) -> None:
        assessment = _assessment()
        alternatives = (
            BoundarySupport("Public entry", "Verified path", assessment),
            BoundarySupport(
                "Public entry",
                "Verified path",
                replace(
                    assessment,
                    traffic_scope=(RelationshipTrafficScope("listener", "tcp", "HTTP", 80, 80),),
                    remaining_conditions=("path=/other/*",),
                ),
            ),
            BoundarySupport("Alternate entry", "A separate rationale", assessment),
        )
        expected = None
        for ordering in permutations(alternatives):
            accumulator = BoundaryAccumulator()
            for support in ordering:
                _add(accumulator, support)
            actual = (accumulator.supports(*EDGE), accumulator.boundaries())
            if expected is None:
                expected = actual
            self.assertEqual(actual, expected)
            self.assertEqual(set(accumulator.supports(*EDGE)), set(alternatives))
            boundary = accumulator.boundaries()[0]
            self.assertIn(
                (boundary.description, boundary.rationale),
                {(support.description, support.rationale) for support in alternatives},
            )

    def test_uncertainty_and_prerequisite_outcomes_remain_separate(self) -> None:
        established = _assessment()
        unknown = replace(
            established,
            outcome=RelationshipOutcome.UNKNOWN,
            prerequisites=(
                RelationshipPrerequisite(
                    "forwarding_association",
                    RelationshipOutcome.UNKNOWN,
                    conditions=("header constraint",),
                    uncertainties=("unknown forwarding action",),
                ),
            ),
            uncertainties=("unknown forwarding action",),
        )
        accumulator = BoundaryAccumulator()
        for assessment in (established, unknown):
            _add(accumulator, BoundarySupport("Public entry", "Path assessment", assessment))
        self.assertEqual({support.assessment for support in accumulator.supports(*EDGE)}, {established, unknown})

    def test_legacy_support_does_not_manufacture_an_assessment_or_change_serialization(self) -> None:
        accumulator = BoundaryAccumulator()
        accumulator.add_boundary(*EDGE, "Public entry", "Public endpoint")
        self.assertEqual(accumulator.supports(*EDGE), (BoundarySupport("Public entry", "Public endpoint"),))
        self.assertEqual(
            asdict(accumulator.boundaries()[0]),
            {
                "identifier": "internet-to-service:internet->aws_lb.web",
                "boundary_type": BoundaryType.INTERNET_TO_SERVICE,
                "source": "internet",
                "target": "aws_lb.web",
                "description": "Public entry",
                "rationale": "Public endpoint",
            },
        )

    def test_support_is_local_to_its_edge_and_returns_a_snapshot(self) -> None:
        accumulator = BoundaryAccumulator()
        support = BoundarySupport("Public entry", "Verified path", _assessment())
        _add(accumulator, support)
        snapshot = accumulator.supports(*EDGE)
        other_edge = (BoundaryType.INTERNET_TO_SERVICE, "internet", "aws_lb.other")
        self.assertEqual(accumulator.supports(*other_edge), ())
        accumulator.add_boundary(*other_edge, "Other entry", "Other endpoint")
        _add(accumulator, replace(support, rationale="Additional explanation"))
        self.assertEqual(snapshot, (support,))
        self.assertEqual(len(accumulator.supports(*EDGE)), 2)
        self.assertEqual(accumulator.supports(*other_edge), (BoundarySupport("Other entry", "Other endpoint"),))
        self.assertEqual([boundary.target for boundary in accumulator.boundaries()], [EDGE[2], other_edge[2]])

    def test_typed_support_does_not_leak_into_boundary_serialization(self) -> None:
        accumulator = BoundaryAccumulator()
        accumulator.add_boundary(*EDGE, "Public entry", "Verified path")
        before = asdict(accumulator.boundaries()[0])

        _add(accumulator, BoundarySupport("Public entry", "Verified path", _assessment()))

        self.assertEqual(len(accumulator.supports(*EDGE)), 2)
        self.assertEqual(asdict(accumulator.boundaries()[0]), before)


class _LegacyAccumulator:
    """Pre-migration first-writer behavior, for external-output parity checks."""

    def __init__(self) -> None:
        self.edges: dict[tuple[BoundaryType, str, str], TrustBoundary] = {}

    def add_boundary(
        self,
        boundary_type: BoundaryType,
        source: str,
        target: str,
        description: str,
        rationale: str,
        *,
        assessment: RelationshipAssessment | None = None,
        assessment_scope: BoundaryAssessmentScope = "relationship",
    ) -> None:
        self.edges.setdefault(
            (boundary_type, source, target),
            TrustBoundary(
                f"{boundary_type.value}:{source}->{target}",
                boundary_type,
                source,
                target,
                description,
                rationale,
            ),
        )

    def boundaries(self) -> list[TrustBoundary]:
        return list(self.edges.values())

    def support_index(self):
        return {}


class BoundarySupportParityTests(unittest.TestCase):
    def test_existing_fixtures_preserve_serialized_boundaries_and_findings(self) -> None:
        for fixture in (
            "aws/sample_aws_plan.json",
            "aws/sample_aws_ecs_fargate_plan.json",
            "gcp/sample_gcp_plan.json",
            "gcp/sample_gcp_serverless_plan.json",
            "azure/sample_azure_plan.json",
        ):
            with self.subTest(fixture=fixture):
                path = FIXTURES_DIR / fixture
                with patch("tfstride.analysis.boundaries.core.BoundaryAccumulator", _LegacyAccumulator):
                    legacy = build_json_report_payload(TfStride().analyze_plan(path))
                current = build_json_report_payload(TfStride().analyze_plan(path))
                self.assertEqual(current["trust_boundaries"], legacy["trust_boundaries"])
                # Includes finding fingerprints, cited boundaries, and all evidence.
                self.assertEqual(current["findings"], legacy["findings"])


if __name__ == "__main__":
    unittest.main()
