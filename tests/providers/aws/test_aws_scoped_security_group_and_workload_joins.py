from __future__ import annotations

import unittest
from collections.abc import Mapping
from dataclasses import replace
from typing import Any

from tfstride.analysis.indexes import build_analysis_indexes
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import (
    BoundaryType,
    NormalizedResource,
    ResourceCategory,
    ResourceInventory,
    SecurityGroupRule,
    TrustBoundary,
)
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.resource_decoration.ecs import MarkEcsLoadBalancerExposureStage
from tfstride.providers.aws.resource_decoration.ecs_secret_access_paths import (
    ProjectEcsSecretAccessPathsOntoServicesStage,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext, AwsResourceIndexBuilder
from tfstride.resource_metadata import MetadataField

_LOCAL = "aws.primary"
_FOREIGN = "aws.secondary"


def _resource(
    address: str,
    resource_type: str,
    category: ResourceCategory,
    *,
    provider_config_key: str,
    identifier: str | None = None,
    arn: str | None = None,
    vpc_id: str | None = None,
    security_group_ids: tuple[str, ...] = (),
    network_rules: list[SecurityGroupRule] | None = None,
    public_exposure: bool = False,
    metadata: Mapping[str | MetadataField[Any], Any] | None = None,
) -> NormalizedResource:
    return NormalizedResource(
        address=address,
        provider="aws",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        category=category,
        provider_config_key=provider_config_key,
        identifier=identifier,
        arn=arn,
        vpc_id=vpc_id,
        security_group_ids=security_group_ids,
        network_rules=tuple(network_rules or ()),
        public_exposure=public_exposure,
        metadata=metadata,
    )


def _security_group_rule(*references: str) -> SecurityGroupRule:
    return SecurityGroupRule(
        direction="ingress",
        protocol="tcp",
        from_port=443,
        to_port=443,
        referenced_security_group_ids=list(references),
    )


def _public_ingress_rule() -> SecurityGroupRule:
    return SecurityGroupRule(
        direction="ingress",
        protocol="tcp",
        from_port=22,
        to_port=22,
        cidr_blocks=["0.0.0.0/0"],
    )


def _context(resources: list[NormalizedResource]) -> AwsDecorationContext:
    return AwsDecorationContext(index=AwsResourceIndexBuilder().build(resources))


def _evaluate(
    inventory: ResourceInventory,
    boundaries: list[TrustBoundary],
    *rule_ids: str,
):
    return StrideRuleEngine().evaluate(
        inventory,
        boundaries,
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


class AwsScopedSecurityGroupAndWorkloadJoinTests(unittest.TestCase):
    def test_foreign_security_group_alias_creates_no_database_boundary_or_finding(self) -> None:
        for reverse_candidates in (False, True):
            with self.subTest(reverse_candidates=reverse_candidates):
                foreign_source_group = _resource(
                    "aws_security_group.foreign_source",
                    "aws_security_group",
                    ResourceCategory.NETWORK,
                    provider_config_key=_FOREIGN,
                    identifier="sg-shared",
                )
                local_source_group = _resource(
                    "aws_security_group.local_source",
                    "aws_security_group",
                    ResourceCategory.NETWORK,
                    provider_config_key=_LOCAL,
                    identifier="sg-shared",
                )
                source_groups = [foreign_source_group, local_source_group]
                if reverse_candidates:
                    source_groups.reverse()
                foreign_workload = _resource(
                    "aws_instance.foreign_edge",
                    "aws_instance",
                    ResourceCategory.COMPUTE,
                    provider_config_key=_FOREIGN,
                    security_group_ids=("sg-shared",),
                    public_exposure=True,
                )
                database_group = _resource(
                    "aws_security_group.database",
                    "aws_security_group",
                    ResourceCategory.NETWORK,
                    provider_config_key=_LOCAL,
                    identifier="sg-database",
                    network_rules=[_security_group_rule("sg-shared")],
                )
                database = _resource(
                    "aws_db_instance.customer",
                    "aws_db_instance",
                    ResourceCategory.DATA,
                    provider_config_key=_LOCAL,
                    identifier="customer",
                    security_group_ids=("sg-database",),
                    metadata={"engine": "postgres", "storage_encrypted": True},
                )
                inventory = ResourceInventory(
                    provider="aws",
                    resources=[*source_groups, foreign_workload, database_group, database],
                )

                boundaries = detect_trust_boundaries(inventory)
                boundary_pairs = {(boundary.boundary_type, boundary.source, boundary.target) for boundary in boundaries}
                findings = _evaluate(
                    inventory,
                    boundaries,
                    "aws-database-permissive-ingress",
                    "aws-missing-tier-segmentation",
                )

                self.assertNotIn(
                    (
                        BoundaryType.WORKLOAD_TO_DATA_STORE,
                        foreign_workload.address,
                        database.address,
                    ),
                    boundary_pairs,
                )
                self.assertEqual(findings, [])

    def test_same_vpc_alias_does_not_cross_provider_configs(self) -> None:
        for reverse_resources in (False, True):
            with self.subTest(reverse_resources=reverse_resources):
                workload = _resource(
                    "aws_instance.foreign",
                    "aws_instance",
                    ResourceCategory.COMPUTE,
                    provider_config_key=_FOREIGN,
                    vpc_id="vpc-shared",
                )
                database = _resource(
                    "aws_db_instance.local",
                    "aws_db_instance",
                    ResourceCategory.DATA,
                    provider_config_key=_LOCAL,
                    identifier="local",
                    vpc_id="vpc-shared",
                    metadata={"engine": "postgres"},
                )
                resources = [workload, database]
                if reverse_resources:
                    resources.reverse()

                boundaries = detect_trust_boundaries(ResourceInventory(provider="aws", resources=resources))

                self.assertNotIn(
                    (
                        BoundaryType.WORKLOAD_TO_DATA_STORE,
                        workload.address,
                        database.address,
                    ),
                    {(boundary.boundary_type, boundary.source, boundary.target) for boundary in boundaries},
                )

    def test_injected_legacy_analysis_indexes_keep_scoped_vpc_fallback(self) -> None:
        workload = _resource(
            "aws_instance.foreign",
            "aws_instance",
            ResourceCategory.COMPUTE,
            provider_config_key=_FOREIGN,
            vpc_id="vpc-shared",
        )
        database = _resource(
            "aws_db_instance.local",
            "aws_db_instance",
            ResourceCategory.DATA,
            provider_config_key=_LOCAL,
            identifier="local",
            vpc_id="vpc-shared",
            metadata={"engine": "postgres"},
        )
        inventory = ResourceInventory(provider="aws", resources=[workload, database])
        legacy_indexes = replace(
            build_analysis_indexes(inventory),
            provider_extension=None,
        )

        boundaries = detect_trust_boundaries(inventory, indexes=legacy_indexes)

        self.assertNotIn(
            (
                BoundaryType.WORKLOAD_TO_DATA_STORE,
                workload.address,
                database.address,
            ),
            {(boundary.boundary_type, boundary.source, boundary.target) for boundary in boundaries},
        )

    def test_foreign_security_group_alias_creates_no_transitive_path_finding(self) -> None:
        for reverse_candidates in (False, True):
            with self.subTest(reverse_candidates=reverse_candidates):
                foreign_source_group = _resource(
                    "aws_security_group.foreign_edge",
                    "aws_security_group",
                    ResourceCategory.NETWORK,
                    provider_config_key=_FOREIGN,
                    identifier="sg-shared",
                )
                local_source_group = _resource(
                    "aws_security_group.local_edge",
                    "aws_security_group",
                    ResourceCategory.NETWORK,
                    provider_config_key=_LOCAL,
                    identifier="sg-shared",
                )
                source_groups = [foreign_source_group, local_source_group]
                if reverse_candidates:
                    source_groups.reverse()
                entry = _resource(
                    "aws_instance.foreign_edge",
                    "aws_instance",
                    ResourceCategory.COMPUTE,
                    provider_config_key=_FOREIGN,
                    security_group_ids=("sg-shared",),
                    public_exposure=True,
                )
                middle_group = _resource(
                    "aws_security_group.middle",
                    "aws_security_group",
                    ResourceCategory.NETWORK,
                    provider_config_key=_LOCAL,
                    identifier="sg-middle",
                    network_rules=[_security_group_rule("sg-shared")],
                )
                middle = _resource(
                    "aws_instance.middle",
                    "aws_instance",
                    ResourceCategory.COMPUTE,
                    provider_config_key=_LOCAL,
                    security_group_ids=("sg-middle",),
                )
                database = _resource(
                    "aws_db_instance.customer",
                    "aws_db_instance",
                    ResourceCategory.DATA,
                    provider_config_key=_LOCAL,
                    identifier="customer",
                    metadata={"engine": "postgres"},
                )
                inventory = ResourceInventory(
                    provider="aws",
                    resources=[*source_groups, entry, middle_group, middle, database],
                )
                boundaries = [
                    TrustBoundary(
                        identifier=f"internet-to-service:internet->{entry.address}",
                        boundary_type=BoundaryType.INTERNET_TO_SERVICE,
                        source="internet",
                        target=entry.address,
                        description="Internet edge.",
                        rationale="The entry workload is public.",
                    ),
                    TrustBoundary(
                        identifier=f"workload-to-data-store:{middle.address}->{database.address}",
                        boundary_type=BoundaryType.WORKLOAD_TO_DATA_STORE,
                        source=middle.address,
                        target=database.address,
                        description="Private data path.",
                        rationale="The middle workload reaches the private database.",
                    ),
                ]

                findings = _evaluate(
                    inventory,
                    boundaries,
                    "aws-private-data-transitive-exposure",
                )

                self.assertEqual(findings, [])

    def test_public_compute_does_not_attach_unique_foreign_security_group(self) -> None:
        for reverse_resources in (False, True):
            with self.subTest(reverse_resources=reverse_resources):
                foreign_group = _resource(
                    "aws_security_group.foreign_admin",
                    "aws_security_group",
                    ResourceCategory.NETWORK,
                    provider_config_key=_FOREIGN,
                    identifier="sg-admin",
                    network_rules=[_public_ingress_rule()],
                )
                local_workload = _resource(
                    "aws_instance.local",
                    "aws_instance",
                    ResourceCategory.COMPUTE,
                    provider_config_key=_LOCAL,
                    security_group_ids=("sg-admin",),
                    public_exposure=True,
                )
                resources = [foreign_group, local_workload]
                if reverse_resources:
                    resources.reverse()
                inventory = ResourceInventory(provider="aws", resources=resources)

                findings = _evaluate(
                    inventory,
                    [],
                    "aws-public-compute-broad-ingress",
                )

                self.assertEqual(findings, [])

    def test_ecs_security_group_alias_does_not_cross_provider_configs(self) -> None:
        for reverse_candidates in (False, True):
            with self.subTest(reverse_candidates=reverse_candidates):
                foreign_load_balancer_group = _resource(
                    "aws_security_group.foreign_lb",
                    "aws_security_group",
                    ResourceCategory.NETWORK,
                    provider_config_key=_FOREIGN,
                    identifier="sg-shared",
                )
                local_unrelated_group = _resource(
                    "aws_security_group.local_unrelated",
                    "aws_security_group",
                    ResourceCategory.NETWORK,
                    provider_config_key=_LOCAL,
                    identifier="sg-shared",
                )
                candidate_groups = [foreign_load_balancer_group, local_unrelated_group]
                if reverse_candidates:
                    candidate_groups.reverse()
                load_balancer = _resource(
                    "aws_lb.foreign",
                    "aws_lb",
                    ResourceCategory.EDGE,
                    provider_config_key=_FOREIGN,
                    security_group_ids=("sg-shared",),
                    public_exposure=True,
                )
                service_group = _resource(
                    "aws_security_group.service",
                    "aws_security_group",
                    ResourceCategory.NETWORK,
                    provider_config_key=_LOCAL,
                    identifier="sg-service",
                    network_rules=[_security_group_rule("sg-shared")],
                )
                service = _resource(
                    "aws_ecs_service.app",
                    "aws_ecs_service",
                    ResourceCategory.COMPUTE,
                    provider_config_key=_LOCAL,
                    security_group_ids=("sg-service",),
                )
                resources = [*candidate_groups, load_balancer, service_group, service]

                MarkEcsLoadBalancerExposureStage().apply(resources, _context(resources))

                self.assertFalse(
                    service.get_metadata_field(AwsResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER)
                )
                self.assertEqual(aws_facts(service).internet_facing_load_balancer_addresses, [])

    def test_foreign_target_group_alias_creates_no_ecs_path_or_finding(self) -> None:
        for reverse_candidates in (False, True):
            with self.subTest(reverse_candidates=reverse_candidates):
                resources, service = self._target_group_collision_resources(reverse_candidates)

                context = _context(resources)
                MarkEcsLoadBalancerExposureStage().apply(resources, context)
                ProjectEcsSecretAccessPathsOntoServicesStage().apply(resources, context)
                inventory = ResourceInventory(provider="aws", resources=resources)
                findings = _evaluate(
                    inventory,
                    [],
                    "aws-public-ecs-secret-access",
                )

                self.assertFalse(
                    service.get_metadata_field(AwsResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER)
                )
                self.assertEqual(aws_facts(service).internet_facing_load_balancer_addresses, [])
                self.assertEqual(
                    aws_facts(service).ecs_secret_access_paths[0]["internet_facing_load_balancers"],
                    [],
                )
                self.assertEqual(findings, [])

    def test_exact_target_group_address_can_cross_provider_configs(self) -> None:
        target_group = _resource(
            "aws_lb_target_group.shared",
            "aws_lb_target_group",
            ResourceCategory.EDGE,
            provider_config_key=_LOCAL,
            identifier="shared-target",
        )
        load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/foreign/abc"
        listener_arn = f"{load_balancer_arn}/listener/443"
        load_balancer = _resource(
            "aws_lb.foreign",
            "aws_lb",
            ResourceCategory.EDGE,
            provider_config_key=_FOREIGN,
            identifier=load_balancer_arn,
            arn=load_balancer_arn,
            public_exposure=True,
        )
        listener = _resource(
            "aws_lb_listener.foreign",
            "aws_lb_listener",
            ResourceCategory.EDGE,
            provider_config_key=_FOREIGN,
            identifier=listener_arn,
            arn=listener_arn,
            metadata={
                "load_balancer_arn": load_balancer_arn,
                "target_group_arns": [target_group.address],
            },
        )
        service = _resource(
            "aws_ecs_service.consumer",
            "aws_ecs_service",
            ResourceCategory.COMPUTE,
            provider_config_key=_FOREIGN,
            metadata={"load_balancers": [{"target_group_arn": target_group.address}]},
        )
        resources = [load_balancer, listener, target_group, service]

        MarkEcsLoadBalancerExposureStage().apply(resources, _context(resources))

        self.assertTrue(service.get_metadata_field(AwsResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER))
        self.assertEqual(
            aws_facts(service).internet_facing_load_balancer_addresses,
            [load_balancer.address],
        )

    def _target_group_collision_resources(
        self,
        reverse_candidates: bool,
    ) -> tuple[list[NormalizedResource], NormalizedResource]:
        target_group_alias = "shared-target"
        foreign_target_group = _resource(
            "aws_lb_target_group.foreign",
            "aws_lb_target_group",
            ResourceCategory.EDGE,
            provider_config_key=_FOREIGN,
            identifier=target_group_alias,
        )
        local_target_group = _resource(
            "aws_lb_target_group.local",
            "aws_lb_target_group",
            ResourceCategory.EDGE,
            provider_config_key=_LOCAL,
            identifier=target_group_alias,
        )
        target_groups = [foreign_target_group, local_target_group]
        if reverse_candidates:
            target_groups.reverse()

        load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/foreign/abc"
        listener_arn = f"{load_balancer_arn}/listener/443"
        load_balancer = _resource(
            "aws_lb.foreign",
            "aws_lb",
            ResourceCategory.EDGE,
            provider_config_key=_FOREIGN,
            identifier=load_balancer_arn,
            arn=load_balancer_arn,
            public_exposure=True,
        )
        listener = _resource(
            "aws_lb_listener.foreign",
            "aws_lb_listener",
            ResourceCategory.EDGE,
            provider_config_key=_FOREIGN,
            identifier=listener_arn,
            arn=listener_arn,
            metadata={
                "load_balancer_arn": load_balancer_arn,
                "target_group_arns": [target_group_alias],
            },
        )
        task_definition = _resource(
            "aws_ecs_task_definition.app",
            "aws_ecs_task_definition",
            ResourceCategory.COMPUTE,
            provider_config_key=_LOCAL,
            identifier="app:1",
            metadata={
                "ecs_secret_access_paths": [
                    {
                        "workload_address": "aws_ecs_task_definition.app",
                        "workload_type": "aws_ecs_task_definition",
                        "role_address": "aws_iam_role.execution",
                        "role_arn": "arn:aws:iam::111122223333:role/execution",
                        "secret_arn": "arn:aws:secretsmanager:us-east-1:111122223333:secret:app",
                        "access_state": "allowed",
                        "modeled_access_state": "allowed",
                        "role_policy_complete": True,
                        "explicit_deny": False,
                        "conditional_evaluation_required": False,
                        "matched_actions": ["secretsmanager:GetSecretValue"],
                    }
                ]
            },
        )
        service = _resource(
            "aws_ecs_service.app",
            "aws_ecs_service",
            ResourceCategory.COMPUTE,
            provider_config_key=_LOCAL,
            metadata={
                "load_balancers": [{"target_group_arn": target_group_alias}],
                "resolved_task_definition_addresses": [task_definition.address],
            },
        )
        return [
            load_balancer,
            listener,
            *target_groups,
            task_definition,
            service,
        ], service


if __name__ == "__main__":
    unittest.main()
