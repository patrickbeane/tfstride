from __future__ import annotations

import unittest
from unittest.mock import patch

from tfstride.analysis.indexes import build_analysis_indexes
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import (
    BoundaryType,
    NormalizedResource,
    ResourceCategory,
    ResourceInventory,
    SecurityGroupRule,
)


def _resource(
    *,
    address: str,
    resource_type: str,
    category: ResourceCategory,
    identifier: str | None = None,
    arn: str | None = None,
    vpc_id: str | None = None,
    security_group_ids: list[str] | None = None,
    attached_role_arns: list[str] | None = None,
    network_rules: list[SecurityGroupRule] | None = None,
) -> NormalizedResource:
    return NormalizedResource(
        address=address,
        provider="aws",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        category=category,
        identifier=identifier,
        arn=arn,
        vpc_id=vpc_id,
        security_group_ids=security_group_ids or [],
        attached_role_arns=attached_role_arns or [],
        network_rules=network_rules or [],
    )


class TrustBoundaryIndexTests(unittest.TestCase):
    def test_detect_trust_boundaries_uses_supplied_indexes(self) -> None:
        role = _resource(
            address="aws_iam_role.app",
            resource_type="aws_iam_role",
            category=ResourceCategory.IAM,
            arn="arn:aws:iam::111122223333:role/app",
        )
        app_security_group = _resource(
            address="aws_security_group.app",
            resource_type="aws_security_group",
            category=ResourceCategory.NETWORK,
            identifier="sg-app",
        )
        database_security_group = _resource(
            address="aws_security_group.db",
            resource_type="aws_security_group",
            category=ResourceCategory.NETWORK,
            identifier="sg-db",
            network_rules=[
                SecurityGroupRule(
                    direction="ingress",
                    protocol="tcp",
                    from_port=5432,
                    to_port=5432,
                    referenced_security_group_ids=["sg-app"],
                )
            ],
        )
        workload = _resource(
            address="aws_instance.app",
            resource_type="aws_instance",
            category=ResourceCategory.COMPUTE,
            vpc_id="vpc-1",
            security_group_ids=["sg-app"],
            attached_role_arns=["arn:aws:iam::111122223333:role/app"],
        )
        database = _resource(
            address="aws_db_instance.app",
            resource_type="aws_db_instance",
            category=ResourceCategory.DATA,
            vpc_id="vpc-1",
            security_group_ids=["sg-db"],
        )
        inventory = ResourceInventory(
            provider="aws",
            resources=[role, app_security_group, database_security_group, workload, database],
        )
        indexes = build_analysis_indexes(inventory)

        with patch("tfstride.analysis.trust_boundaries.build_analysis_indexes") as build_indexes:
            boundaries = detect_trust_boundaries(inventory, indexes=indexes)

        build_indexes.assert_not_called()
        boundary_pairs = {
            (boundary.boundary_type, boundary.source, boundary.target)
            for boundary in boundaries
        }
        self.assertIn(
            (BoundaryType.CONTROL_TO_WORKLOAD, "aws_iam_role.app", "aws_instance.app"),
            boundary_pairs,
        )
        self.assertIn(
            (BoundaryType.WORKLOAD_TO_DATA_STORE, "aws_instance.app", "aws_db_instance.app"),
            boundary_pairs,
        )


if __name__ == "__main__":
    unittest.main()