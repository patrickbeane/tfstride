from __future__ import annotations

import unittest

from tfstride.analysis.indexes import build_analysis_indexes
from tfstride.models import NormalizedResource, ResourceCategory, ResourceInventory


def _resource(
    *,
    address: str,
    resource_type: str,
    category: ResourceCategory,
    identifier: str | None = None,
    arn: str | None = None,
    security_group_ids: list[str] | None = None,
    public_exposure: bool = False,
) -> NormalizedResource:
    return NormalizedResource(
        address=address,
        provider="aws",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        category=category,
        identifier=identifier,
        arn=arn,
        security_group_ids=security_group_ids or [],
        public_exposure=public_exposure,
    )


class AnalysisIndexTests(unittest.TestCase):
    def test_build_analysis_indexes_maps_roles_security_groups_and_public_resources(self) -> None:
        role = _resource(
            address="aws_iam_role.app",
            resource_type="aws_iam_role",
            category=ResourceCategory.IAM,
            identifier="app-role",
            arn="arn:aws:iam::111122223333:role/app",
        )
        security_group = _resource(
            address="aws_security_group.web",
            resource_type="aws_security_group",
            category=ResourceCategory.NETWORK,
            identifier="sg-web",
            arn="arn:aws:ec2:us-east-1:111122223333:security-group/sg-web",
        )
        public_workload = _resource(
            address="aws_instance.web",
            resource_type="aws_instance",
            category=ResourceCategory.COMPUTE,
            security_group_ids=["sg-web"],
            public_exposure=True,
        )
        private_database = _resource(
            address="aws_db_instance.app",
            resource_type="aws_db_instance",
            category=ResourceCategory.DATA,
            security_group_ids=["sg-web"],
        )
        inventory = ResourceInventory(
            provider="aws",
            resources=[role, security_group, public_workload, private_database],
        )

        indexes = build_analysis_indexes(inventory)

        self.assertIs(indexes.role_index["aws_iam_role.app"], role)
        self.assertIs(indexes.role_index["app-role"], role)
        self.assertIs(indexes.role_index["arn:aws:iam::111122223333:role/app"], role)
        self.assertIs(indexes.security_groups_by_reference["sg-web"], security_group)
        self.assertIs(indexes.security_groups_by_reference["aws_security_group.web"], security_group)
        self.assertEqual(
            indexes.resources_by_security_group["sg-web"],
            (public_workload, private_database),
        )
        self.assertEqual(
            indexes.public_workloads_by_security_group["sg-web"],
            (public_workload,),
        )
        self.assertEqual(indexes.attached_security_groups(public_workload), [security_group])

    def test_attached_security_groups_preserves_inventory_reference_precedence(self) -> None:
        conflicting_resource = _resource(
            address="aws_instance.conflict",
            resource_type="aws_instance",
            category=ResourceCategory.COMPUTE,
            identifier="sg-shared",
        )
        security_group = _resource(
            address="aws_security_group.shared",
            resource_type="aws_security_group",
            category=ResourceCategory.NETWORK,
            identifier="sg-shared",
        )
        workload = _resource(
            address="aws_instance.web",
            resource_type="aws_instance",
            category=ResourceCategory.COMPUTE,
            security_group_ids=["sg-shared", "aws_security_group.shared"],
        )
        inventory = ResourceInventory(
            provider="aws",
            resources=[conflicting_resource, security_group, workload],
        )

        indexes = build_analysis_indexes(inventory)

        self.assertNotIn("sg-shared", indexes.security_groups_by_reference)
        self.assertEqual(indexes.attached_security_groups(workload), [security_group])

    def test_index_maps_are_top_level_immutable(self) -> None:
        role = _resource(
            address="aws_iam_role.app",
            resource_type="aws_iam_role",
            category=ResourceCategory.IAM,
        )
        indexes = build_analysis_indexes(ResourceInventory(provider="aws", resources=[role]))

        with self.assertRaises(TypeError):
            indexes.role_index["aws_iam_role.other"] = role


if __name__ == "__main__":
    unittest.main()
