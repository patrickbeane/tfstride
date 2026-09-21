from __future__ import annotations

import unittest
from itertools import permutations

from tfstride.analysis.indexes import build_analysis_indexes
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.filtering import finding_fingerprint
from tfstride.models import (
    BoundaryType,
    NormalizedResource,
    ResourceCategory,
    ResourceInventory,
    SecurityGroupRule,
    Severity,
    TrustBoundary,
)

_RULE_ID = "aws-missing-tier-segmentation"


def _data_path_resources(
    module: str,
    *,
    provider_config_key: str = "aws",
    security_group_prefix: str | None = None,
) -> list[NormalizedResource]:
    group_prefix = security_group_prefix if security_group_prefix is not None else module
    workload_group_id = f"sg-{group_prefix}-workload"
    database_group_id = f"sg-{group_prefix}-database"
    return [
        NormalizedResource(
            address=f"module.{module}.aws_security_group.workload",
            provider="aws",
            resource_type="aws_security_group",
            name="workload",
            category=ResourceCategory.NETWORK,
            provider_config_key=provider_config_key,
            identifier=workload_group_id,
        ),
        NormalizedResource(
            address=f"module.{module}.aws_instance.app",
            provider="aws",
            resource_type="aws_instance",
            name="app",
            category=ResourceCategory.COMPUTE,
            provider_config_key=provider_config_key,
            security_group_ids=(workload_group_id,),
            public_exposure=True,
        ),
        NormalizedResource(
            address=f"module.{module}.aws_security_group.database",
            provider="aws",
            resource_type="aws_security_group",
            name="database",
            category=ResourceCategory.NETWORK,
            provider_config_key=provider_config_key,
            identifier=database_group_id,
            network_rules=(
                SecurityGroupRule(
                    direction="ingress",
                    protocol="tcp",
                    from_port=5432,
                    to_port=5432,
                    referenced_security_group_ids=[workload_group_id],
                ),
            ),
        ),
        NormalizedResource(
            address=f"module.{module}.aws_db_instance.app",
            provider="aws",
            resource_type="aws_db_instance",
            name="app",
            category=ResourceCategory.DATA,
            provider_config_key=provider_config_key,
            security_group_ids=(database_group_id,),
        ),
    ]


def _boundaries(resources: list[NormalizedResource]) -> list[TrustBoundary]:
    return [
        *detect_trust_boundaries(ResourceInventory(provider="aws", resources=resources)),
        TrustBoundary(
            identifier="public-subnet-to-private-subnet:aws_subnet.public->aws_subnet.unrelated",
            boundary_type=BoundaryType.PUBLIC_TO_PRIVATE,
            source="aws_subnet.public",
            target="aws_subnet.unrelated",
            description="An unrelated subnet boundary.",
            rationale="The subnet boundary is not a workload-to-database path.",
        ),
    ]


class AwsSegmentationFindingTests(unittest.TestCase):
    def test_multiple_databases_keep_distinct_boundaries_and_fingerprints_across_orders(self) -> None:
        resources = [*_data_path_resources("billing"), *_data_path_resources("customer")]

        self._assert_stable_findings(
            resources,
            _boundaries(resources),
            {
                (
                    "module.billing.aws_db_instance.app",
                    "module.billing.aws_instance.app",
                    "module.billing.aws_security_group.database",
                ): "workload-to-data-store:module.billing.aws_instance.app->module.billing.aws_db_instance.app",
                (
                    "module.customer.aws_db_instance.app",
                    "module.customer.aws_instance.app",
                    "module.customer.aws_security_group.database",
                ): "workload-to-data-store:module.customer.aws_instance.app->module.customer.aws_db_instance.app",
            },
        )

    def test_colliding_security_group_ids_stay_within_provider_config_across_orders(self) -> None:
        resources = [
            *_data_path_resources("primary", provider_config_key="aws.primary", security_group_prefix="shared"),
            *_data_path_resources("secondary", provider_config_key="aws.secondary", security_group_prefix="shared"),
        ]

        self._assert_stable_findings(
            resources,
            _boundaries(resources),
            {
                (
                    "module.primary.aws_db_instance.app",
                    "module.primary.aws_instance.app",
                    "module.primary.aws_security_group.database",
                ): "workload-to-data-store:module.primary.aws_instance.app->module.primary.aws_db_instance.app",
                (
                    "module.secondary.aws_db_instance.app",
                    "module.secondary.aws_instance.app",
                    "module.secondary.aws_security_group.database",
                ): "workload-to-data-store:module.secondary.aws_instance.app->module.secondary.aws_db_instance.app",
            },
        )

    def test_missing_boundary_keeps_fingerprint_stable_with_unrelated_paths(self) -> None:
        resources = [*_data_path_resources("billing"), *_data_path_resources("customer")]
        boundaries = [
            boundary for boundary in _boundaries(resources) if boundary.target != "module.customer.aws_db_instance.app"
        ]

        self._assert_stable_findings(
            resources,
            boundaries,
            {
                (
                    "module.billing.aws_db_instance.app",
                    "module.billing.aws_instance.app",
                    "module.billing.aws_security_group.database",
                ): "workload-to-data-store:module.billing.aws_instance.app->module.billing.aws_db_instance.app",
                (
                    "module.customer.aws_db_instance.app",
                    "module.customer.aws_instance.app",
                    "module.customer.aws_security_group.database",
                ): None,
            },
        )

    def _assert_stable_findings(
        self,
        resources: list[NormalizedResource],
        boundaries: list[TrustBoundary],
        expected_boundaries: dict[tuple[str, ...], str | None],
    ) -> None:
        engine = StrideRuleEngine()
        policy = RulePolicy(enabled_rule_ids=frozenset({_RULE_ID}))
        expected_fingerprints: dict[tuple[str, ...], str] | None = None
        resource_orders = (resources, list(reversed(resources)), resources[1:] + resources[:1])
        for ordered_resources in resource_orders:
            inventory = ResourceInventory(provider="aws", resources=ordered_resources)
            indexes = build_analysis_indexes(inventory)
            for ordered_boundaries in permutations(boundaries):
                with self.subTest(
                    resources=tuple(resource.address for resource in ordered_resources),
                    boundaries=tuple(boundary.identifier for boundary in ordered_boundaries),
                ):
                    findings = engine.evaluate(
                        inventory,
                        list(ordered_boundaries),
                        analysis_indexes=indexes,
                        rule_policy=policy,
                    )
                    self.assertEqual(len(findings), len(expected_boundaries))
                    self.assertEqual({finding.rule_id for finding in findings}, {_RULE_ID})
                    self.assertEqual({finding.severity for finding in findings}, {Severity.HIGH})
                    self.assertEqual(
                        {tuple(finding.affected_resources): finding.trust_boundary_id for finding in findings},
                        expected_boundaries,
                    )
                    fingerprints = {
                        tuple(finding.affected_resources): finding_fingerprint(finding) for finding in findings
                    }
                    self.assertEqual(len(set(fingerprints.values())), len(expected_boundaries))
                    if expected_fingerprints is None:
                        expected_fingerprints = fingerprints
                    self.assertEqual(fingerprints, expected_fingerprints)


if __name__ == "__main__":
    unittest.main()
