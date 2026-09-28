from __future__ import annotations

import unittest

from tfstride.analysis.relationships import (
    RelationshipKind,
    RelationshipReferenceResolution,
)
from tfstride.models import TerraformReferenceProvenance, TerraformReferenceResolutionState


class RelationshipReferenceResolutionTests(unittest.TestCase):
    def test_exact_symbolic_configuration_reference_establishes_identity(self) -> None:
        resolution = RelationshipReferenceResolution(
            source_address="aws_ecs_service.app",
            target_addresses=("aws_ecs_task_definition.app",),
            expression_path=("task_definition",),
            state=TerraformReferenceResolutionState.SYMBOLIC,
            provenance=TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
            references=("aws_ecs_task_definition.app.arn",),
        )

        self.assertTrue(resolution.establishes_identity)

    def test_unresolved_or_ambiguous_reference_does_not_establish_identity(self) -> None:
        for state, targets in (
            (TerraformReferenceResolutionState.UNRESOLVED, ("aws_ecs_task_definition.app",)),
            (
                TerraformReferenceResolutionState.AMBIGUOUS,
                ("aws_ecs_task_definition.app", "aws_ecs_task_definition.other"),
            ),
        ):
            with self.subTest(state=state):
                resolution = RelationshipReferenceResolution(
                    source_address="aws_ecs_service.app",
                    target_addresses=targets,
                    expression_path=("task_definition",),
                    state=state,
                    provenance=TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
                )

                self.assertFalse(resolution.establishes_identity)

    def test_relationship_kinds_do_not_collapse_distinct_claims(self) -> None:
        self.assertEqual(
            {kind.value for kind in RelationshipKind},
            {
                "identity_attachment",
                "authorization",
                "network_permission",
                "forwarding",
                "effective_ingress",
            },
        )


if __name__ == "__main__":
    unittest.main()
