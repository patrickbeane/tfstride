from __future__ import annotations

import unittest
from unittest.mock import Mock

from tfstride.analysis.boundaries.types import BoundaryContributionContext
from tfstride.analysis.preparation import prepare_analysis
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import BoundaryType, NormalizedResource, ResourceCategory, ResourceInventory
from tfstride.providers.aws.analysis_indexes import AwsAnalysisIndexes, build_aws_analysis_indexes


def _public_load_balancer(name: str) -> NormalizedResource:
    resource = NormalizedResource(
        address=f"aws_lb.{name}",
        provider="aws",
        resource_type="aws_lb",
        name=name,
        category=ResourceCategory.NETWORK,
        security_group_ids=["sg-before"],
        public_exposure=True,
    )
    resource.direct_internet_reachable = True
    return resource


class AnalysisPreparationTests(unittest.TestCase):
    def test_preparing_modified_inventory_refreshes_indexes_and_boundaries(self) -> None:
        role = NormalizedResource(
            address="aws_iam_role.app",
            provider="aws",
            resource_type="aws_iam_role",
            name="app",
            category=ResourceCategory.IAM,
            arn="arn:aws:iam::111122223333:role/before",
        )
        security_group = NormalizedResource(
            address="aws_security_group.app",
            provider="aws",
            resource_type="aws_security_group",
            name="app",
            category=ResourceCategory.NETWORK,
            identifier="sg-before",
        )
        web = _public_load_balancer("web")
        admin = _public_load_balancer("admin")
        inventory = ResourceInventory(provider="aws", resources=[role, security_group, web, admin])
        for resource in inventory.resources:
            resource.freeze_decoration_state()
        rule_set = StrideRuleEngine().rule_set_for("aws")
        extension_factory = Mock(wraps=build_aws_analysis_indexes)

        before = prepare_analysis(
            inventory,
            rule_set=rule_set,
            provider_extension_factory=extension_factory,
            provider_boundary_contributor_factories=(),
        )

        role.arn = "arn:aws:iam::111122223333:role/after"
        security_group.identifier = "sg-after"
        web.security_group_ids = ("sg-after",)
        admin.security_group_ids = ("sg-after",)
        web.public_exposure = False
        web.direct_internet_reachable = False

        after = prepare_analysis(
            inventory,
            rule_set=rule_set,
            provider_extension_factory=extension_factory,
            provider_boundary_contributor_factories=(),
        )

        self.assertEqual(extension_factory.call_count, 2)
        self.assertIs(before.inventory, inventory)
        self.assertIs(after.inventory, inventory)
        self.assertIs(before.rule_set, rule_set)
        self.assertIs(after.rule_set, rule_set)
        self.assertIsNot(before, after)
        self.assertIsNot(before.indexes, after.indexes)
        self.assertIsNot(before.boundaries, after.boundaries)
        self.assertIs(before.indexes.role_index.unique_candidate("arn:aws:iam::111122223333:role/before"), role)
        self.assertIsNone(before.indexes.role_index.unique_candidate(role.arn))
        self.assertIsNone(after.indexes.role_index.unique_candidate("arn:aws:iam::111122223333:role/before"))
        self.assertIs(after.indexes.role_index.unique_candidate(role.arn), role)
        self.assertIsNone(after.indexes.security_groups_by_reference.unique_candidate("sg-before"))
        self.assertIs(after.indexes.security_groups_by_reference.unique_candidate("sg-after"), security_group)
        self.assertEqual(before.indexes.public_workloads_by_security_group["sg-before"], (web, admin))
        self.assertEqual(after.indexes.resources_by_security_group["sg-after"], (web, admin))
        self.assertEqual(after.indexes.public_workloads_by_security_group["sg-after"], (admin,))

        before_extension = before.indexes.require_provider_extension(AwsAnalysisIndexes)
        after_extension = after.indexes.require_provider_extension(AwsAnalysisIndexes)
        self.assertIsNot(before_extension, after_extension)
        self.assertIsNone(
            before_extension.security_group_relationships.resource_index.security_groups.get("sg-after", source=web)
        )
        self.assertIs(
            after_extension.security_group_relationships.resource_index.security_groups.get("sg-after", source=web),
            security_group,
        )
        self.assertEqual([boundary.target for boundary in before.boundaries], [web.address, admin.address])
        self.assertEqual([boundary.target for boundary in after.boundaries], [admin.address])

    def test_each_preparation_builds_indexes_before_creating_boundary_contributors(self) -> None:
        workload = _public_load_balancer("web")
        inventory = ResourceInventory(provider="aws", resources=[workload])
        rule_set = StrideRuleEngine().rule_set_for("aws")
        events: list[str] = []
        contributors: list[RecordingContributor] = []
        contexts: list[BoundaryContributionContext] = []

        def extension_factory(_inventory: ResourceInventory) -> None:
            events.append("indexes")
            return None

        class RecordingContributor:
            def __init__(self) -> None:
                events.append("create_contributor")
                contributors.append(self)

            def contribute(self, context: BoundaryContributionContext) -> None:
                events.append("contribute")
                contexts.append(context)
                context.add_boundary(
                    BoundaryType.INTERNET_TO_SERVICE,
                    "internet",
                    workload.address,
                    "Duplicate provider description.",
                    "Duplicate provider rationale.",
                )
                context.add_boundary(
                    BoundaryType.CONTROL_TO_WORKLOAD,
                    "provider:control",
                    workload.address,
                    "Provider control boundary.",
                    "Provider rationale.",
                )

        prepared_runs = [
            prepare_analysis(
                inventory,
                rule_set=rule_set,
                provider_extension_factory=extension_factory,
                provider_boundary_contributor_factories=(RecordingContributor,),
            )
            for _ in range(2)
        ]

        self.assertEqual(events, ["indexes", "create_contributor", "contribute"] * 2)
        self.assertIsNot(contributors[0], contributors[1])
        for prepared, context in zip(prepared_runs, contexts, strict=True):
            self.assertIs(context.inventory, inventory)
            self.assertIs(context.indexes, prepared.indexes)
            self.assertIsNone(prepared.indexes.provider_extension)
            self.assertEqual(
                [boundary.boundary_type for boundary in prepared.boundaries],
                [BoundaryType.INTERNET_TO_SERVICE, BoundaryType.CONTROL_TO_WORKLOAD],
            )
            self.assertEqual(
                prepared.boundaries[0].description,
                f"Traffic can cross from the public internet to {workload.display_name}.",
            )
            self.assertEqual(prepared.boundaries[1].rationale, "Provider rationale.")


if __name__ == "__main__":
    unittest.main()
