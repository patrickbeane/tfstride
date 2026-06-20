from __future__ import annotations

import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch

from tfstride.analysis.boundaries.core import detect_trust_boundaries as detect_trust_boundaries_from_core
from tfstride.analysis.boundaries.types import BoundaryContributionContext
from tfstride.analysis.indexes import build_analysis_indexes
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.app import TfStride
from tfstride.models import (
    BoundaryType,
    IAMPolicyStatement,
    NormalizedResource,
    ResourceCategory,
    ResourceInventory,
    SecurityGroupRule,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"


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


class FixtureTrustBoundaryCharacterizationTests(unittest.TestCase):
    FIXTURE_EXPECTATIONS = {
        "aws-mixed": {
            "path": FIXTURES / "aws" / "sample_aws_plan.json",
            "provider": "aws",
            "counts": {
                BoundaryType.INTERNET_TO_SERVICE: 3,
                BoundaryType.PUBLIC_TO_PRIVATE: 1,
                BoundaryType.WORKLOAD_TO_DATA_STORE: 3,
                BoundaryType.CONTROL_TO_WORKLOAD: 1,
                BoundaryType.CROSS_ACCOUNT_OR_ROLE: 1,
            },
            "identifiers": [
                "internet-to-service:internet->aws_lb.web",
                "internet-to-service:internet->aws_instance.app",
                "internet-to-service:internet->aws_s3_bucket.assets",
                "public-subnet-to-private-subnet:aws_subnet.public_app->aws_subnet.private_data",
                "workload-to-data-store:aws_instance.app->aws_db_instance.app",
                "workload-to-data-store:aws_lambda_function.processor->aws_db_instance.app",
                "workload-to-data-store:aws_lambda_function.processor->aws_s3_bucket.assets",
                "admin-to-workload-plane:aws_iam_role.workload->aws_lambda_function.processor",
                "cross-account-or-role-access:arn:aws:iam::999988887777:root->aws_iam_role.workload",
            ],
        },
        "aws-ecs-fargate": {
            "path": FIXTURES / "aws" / "sample_aws_ecs_fargate_plan.json",
            "provider": "aws",
            "counts": {
                BoundaryType.INTERNET_TO_SERVICE: 1,
                BoundaryType.PUBLIC_TO_PRIVATE: 2,
                BoundaryType.WORKLOAD_TO_DATA_STORE: 2,
                BoundaryType.CONTROL_TO_WORKLOAD: 1,
            },
            "identifiers": [
                "internet-to-service:internet->aws_lb.web",
                "public-subnet-to-private-subnet:aws_subnet.public_a->aws_subnet.private_app",
                "public-subnet-to-private-subnet:aws_subnet.public_b->aws_subnet.private_app",
                "workload-to-data-store:aws_ecs_service.app->aws_db_instance.app",
                "workload-to-data-store:aws_ecs_service.app->aws_secretsmanager_secret.app",
                "admin-to-workload-plane:aws_iam_role.task->aws_ecs_service.app",
            ],
        },
        "gcp-mixed": {
            "path": FIXTURES / "gcp" / "sample_gcp_plan.json",
            "provider": "gcp",
            "counts": {
                BoundaryType.INTERNET_TO_SERVICE: 3,
                BoundaryType.WORKLOAD_TO_DATA_STORE: 1,
            },
            "identifiers": [
                "internet-to-service:internet->google_compute_instance.web",
                "internet-to-service:internet->google_sql_database_instance.app",
                "internet-to-service:internet->google_storage_bucket.logs",
                "workload-to-data-store:google_compute_instance.web->google_bigquery_dataset.analytics",
            ],
        },
        "gcp-serverless": {
            "path": FIXTURES / "gcp" / "sample_gcp_serverless_plan.json",
            "provider": "gcp",
            "counts": {
                BoundaryType.INTERNET_TO_SERVICE: 2,
                BoundaryType.WORKLOAD_TO_DATA_STORE: 2,
            },
            "identifiers": [
                "internet-to-service:internet->google_cloud_run_v2_service.api",
                "internet-to-service:internet->google_cloudfunctions_function.worker",
                "workload-to-data-store:google_cloud_run_v2_service.api->google_secret_manager_secret.api_key",
                "workload-to-data-store:google_cloudfunctions_function.worker->google_secret_manager_secret.api_key",
            ],
        },
    }

    @classmethod
    def setUpClass(cls) -> None:
        engine = TfStride()
        cls.results = {
            scenario_id: engine.analyze_plan(expectation["path"])
            for scenario_id, expectation in cls.FIXTURE_EXPECTATIONS.items()
        }

    def test_fixture_boundary_ids_types_and_counts_match_current_output(self) -> None:
        for scenario_id, expectation in self.FIXTURE_EXPECTATIONS.items():
            with self.subTest(scenario=scenario_id):
                result = self.results[scenario_id]

                self.assertEqual(result.inventory.provider, expectation["provider"])
                self.assertEqual(
                    [boundary.identifier for boundary in result.trust_boundaries],
                    expectation["identifiers"],
                )
                self.assertEqual(
                    dict(Counter(boundary.boundary_type for boundary in result.trust_boundaries)),
                    expectation["counts"],
                )

    def test_fixture_boundary_ids_are_deduped_and_ordered(self) -> None:
        for scenario_id, result in self.results.items():
            with self.subTest(scenario=scenario_id):
                identifiers = [boundary.identifier for boundary in result.trust_boundaries]
                logical_edges = [
                    (boundary.boundary_type, boundary.source, boundary.target) for boundary in result.trust_boundaries
                ]

                self.assertEqual(identifiers, self.FIXTURE_EXPECTATIONS[scenario_id]["identifiers"])
                self.assertEqual(len(identifiers), len(set(identifiers)))
                self.assertEqual(len(logical_edges), len(set(logical_edges)))

    def test_fixture_workload_to_data_store_boundaries_cover_aws_and_gcp_paths(self) -> None:
        expected_pairs = {
            "aws-mixed": {
                ("aws_instance.app", "aws_db_instance.app"),
                ("aws_lambda_function.processor", "aws_db_instance.app"),
                ("aws_lambda_function.processor", "aws_s3_bucket.assets"),
            },
            "gcp-mixed": {
                ("google_compute_instance.web", "google_bigquery_dataset.analytics"),
            },
            "gcp-serverless": {
                ("google_cloud_run_v2_service.api", "google_secret_manager_secret.api_key"),
                ("google_cloudfunctions_function.worker", "google_secret_manager_secret.api_key"),
            },
        }

        for scenario_id, pairs in expected_pairs.items():
            with self.subTest(scenario=scenario_id):
                result = self.results[scenario_id]
                actual_pairs = {
                    (boundary.source, boundary.target)
                    for boundary in result.trust_boundaries
                    if boundary.boundary_type == BoundaryType.WORKLOAD_TO_DATA_STORE
                }

                self.assertEqual(actual_pairs, pairs)


class RecordingBoundaryContributor:
    def contribute(self, context: BoundaryContributionContext) -> None:
        context.add_boundary(
            BoundaryType.INTERNET_TO_SERVICE,
            "internet",
            "aws_lb.web",
            "Traffic can cross from the public internet to aws_lb.web.",
            "The resource is public.",
        )
        context.add_boundary(
            BoundaryType.INTERNET_TO_SERVICE,
            "internet",
            "aws_lb.web",
            "Duplicate edge with different wording.",
            "Duplicate rationale.",
        )


class BoundaryCoreTests(unittest.TestCase):
    def test_core_runs_contributors_and_dedupes_boundaries(self) -> None:
        inventory = ResourceInventory(provider="aws", resources=[])

        boundaries = detect_trust_boundaries_from_core(
            inventory,
            contributors=(RecordingBoundaryContributor(),),
        )

        self.assertEqual(len(boundaries), 1)
        self.assertEqual(boundaries[0].identifier, "internet-to-service:internet->aws_lb.web")
        self.assertEqual(boundaries[0].description, "Traffic can cross from the public internet to aws_lb.web.")


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

        with patch("tfstride.analysis.boundaries.core.build_analysis_indexes") as build_indexes:
            boundaries = detect_trust_boundaries(inventory, indexes=indexes)

        build_indexes.assert_not_called()
        boundary_pairs = {(boundary.boundary_type, boundary.source, boundary.target) for boundary in boundaries}
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
