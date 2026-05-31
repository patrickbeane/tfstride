from __future__ import annotations

import unittest
from unittest.mock import patch

from tfstride.analysis.indexes import build_analysis_indexes
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import (
    BoundaryType,
    IAMPolicyStatement,
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

    def test_workload_data_store_candidates_preserve_reachable_store_order(self) -> None:
        role = _resource(
            address="aws_iam_role.app",
            resource_type="aws_iam_role",
            category=ResourceCategory.IAM,
            arn="arn:aws:iam::111122223333:role/app",
        )
        role.extend_policy_statements(
            [
                IAMPolicyStatement(
                    effect="Allow",
                    actions=["s3:GetObject", "secretsmanager:GetSecretValue"],
                )
            ]
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
            vpc_id="vpc-a",
            security_group_ids=["sg-app"],
            attached_role_arns=["arn:aws:iam::111122223333:role/app"],
        )
        bucket = _resource(
            address="aws_s3_bucket.assets",
            resource_type="aws_s3_bucket",
            category=ResourceCategory.DATA,
        )
        database_by_security_group = _resource(
            address="aws_db_instance.by_sg",
            resource_type="aws_db_instance",
            category=ResourceCategory.DATA,
            vpc_id="vpc-a",
            security_group_ids=["sg-db"],
        )
        secret = _resource(
            address="aws_secretsmanager_secret.app",
            resource_type="aws_secretsmanager_secret",
            category=ResourceCategory.DATA,
        )
        database_missing_security_group = _resource(
            address="aws_db_instance.missing_sg",
            resource_type="aws_db_instance",
            category=ResourceCategory.DATA,
            vpc_id="vpc-a",
        )
        unrelated_database = _resource(
            address="aws_db_instance.unrelated",
            resource_type="aws_db_instance",
            category=ResourceCategory.DATA,
            vpc_id="vpc-b",
        )
        inventory = ResourceInventory(
            provider="aws",
            resources=[
                role,
                database_security_group,
                workload,
                bucket,
                database_by_security_group,
                secret,
                database_missing_security_group,
                unrelated_database,
            ],
        )

        boundaries = detect_trust_boundaries(inventory)

        workload_data_store_pairs = [
            (boundary.source, boundary.target)
            for boundary in boundaries
            if boundary.boundary_type == BoundaryType.WORKLOAD_TO_DATA_STORE
        ]
        self.assertEqual(
            workload_data_store_pairs,
            [
                ("aws_instance.app", "aws_s3_bucket.assets"),
                ("aws_instance.app", "aws_db_instance.by_sg"),
                ("aws_instance.app", "aws_secretsmanager_secret.app"),
                ("aws_instance.app", "aws_db_instance.missing_sg"),
            ],
        )

    def test_public_private_subnet_boundaries_are_indexed_by_vpc(self) -> None:
        public_a = _resource(
            address="aws_subnet.public_a",
            resource_type="aws_subnet",
            category=ResourceCategory.NETWORK,
            vpc_id="vpc-a",
        )
        private_a = _resource(
            address="aws_subnet.private_a",
            resource_type="aws_subnet",
            category=ResourceCategory.NETWORK,
            vpc_id="vpc-a",
        )
        private_b = _resource(
            address="aws_subnet.private_b",
            resource_type="aws_subnet",
            category=ResourceCategory.NETWORK,
            vpc_id="vpc-b",
        )
        public_b = _resource(
            address="aws_subnet.public_b",
            resource_type="aws_subnet",
            category=ResourceCategory.NETWORK,
            vpc_id="vpc-b",
        )
        private_a_late = _resource(
            address="aws_subnet.private_a_late",
            resource_type="aws_subnet",
            category=ResourceCategory.NETWORK,
            vpc_id="vpc-a",
        )
        public_without_vpc = _resource(
            address="aws_subnet.public_without_vpc",
            resource_type="aws_subnet",
            category=ResourceCategory.NETWORK,
        )
        public_a.is_public_subnet = True
        public_b.is_public_subnet = True
        public_without_vpc.is_public_subnet = True
        inventory = ResourceInventory(
            provider="aws",
            resources=[
                public_a,
                private_a,
                private_b,
                public_b,
                private_a_late,
                public_without_vpc,
            ],
        )

        boundaries = detect_trust_boundaries(inventory)

        public_to_private_pairs = [
            (boundary.source, boundary.target)
            for boundary in boundaries
            if boundary.boundary_type == BoundaryType.PUBLIC_TO_PRIVATE
        ]
        self.assertEqual(
            public_to_private_pairs,
            [
                ("aws_subnet.public_a", "aws_subnet.private_a"),
                ("aws_subnet.public_a", "aws_subnet.private_a_late"),
                ("aws_subnet.public_b", "aws_subnet.private_b"),
            ],
        )


if __name__ == "__main__":
    unittest.main()