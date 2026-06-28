from __future__ import annotations

import unittest

from tfstride.models import (
    IAMPolicyStatement,
    NormalizedResource,
    ResourceCategory,
    SecurityGroupRule,
)
from tfstride.providers.aws.resource_decoration.ecs import (
    MarkEcsLoadBalancerExposureStage,
    ResolveEcsServiceRelationshipsStage,
)
from tfstride.providers.aws.resource_decoration.iam import (
    ResolveInstanceProfileRolesStage,
)
from tfstride.providers.aws.resource_decoration.network_posture import (
    DeriveSubnetPostureStage,
    InferVpcIdsStage,
)
from tfstride.providers.aws.resource_decoration.public_exposure import (
    DerivePublicExposureStage,
)
from tfstride.providers.aws.resource_decoration.resource_policies import (
    ApplyS3PostureResourcesStage,
    ApplyS3PublicAccessBlocksStage,
    MergeResourcePolicyResourcesStage,
)
from tfstride.providers.aws.resource_decoration.security_groups import (
    MergeStandaloneSecurityGroupRulesStage,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext, AwsResourceIndexBuilder


def _resource(
    address: str,
    resource_type: str,
    category: ResourceCategory,
    *,
    identifier: str | None = None,
    arn: str | None = None,
    vpc_id: str | None = None,
    subnet_ids: tuple[str, ...] = (),
    security_group_ids: tuple[str, ...] = (),
    network_rules: list[SecurityGroupRule] | None = None,
    policy_statements: list[IAMPolicyStatement] | None = None,
    public_access_configured: bool = False,
    public_exposure: bool = False,
    metadata: dict | None = None,
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
        subnet_ids=subnet_ids,
        security_group_ids=security_group_ids,
        network_rules=network_rules or [],
        policy_statements=policy_statements or [],
        public_access_configured=public_access_configured,
        public_exposure=public_exposure,
        metadata=metadata or {},
    )


def _context(resources: list[NormalizedResource]) -> AwsDecorationContext:
    return AwsDecorationContext(index=AwsResourceIndexBuilder().build(resources))


def _public_http_rule() -> SecurityGroupRule:
    return SecurityGroupRule(
        direction="ingress",
        protocol="tcp",
        from_port=80,
        to_port=80,
        cidr_blocks=["0.0.0.0/0"],
    )


def _private_http_rule() -> SecurityGroupRule:
    return SecurityGroupRule(
        direction="ingress",
        protocol="tcp",
        from_port=80,
        to_port=80,
        cidr_blocks=["10.0.0.0/8"],
    )


def _referenced_security_group_rule(security_group_id: str) -> SecurityGroupRule:
    return SecurityGroupRule(
        direction="ingress",
        protocol="tcp",
        from_port=80,
        to_port=80,
        referenced_security_group_ids=[security_group_id],
    )


class AwsResourceDecorationStageTests(unittest.TestCase):
    def test_security_group_stage_merges_standalone_rules_into_target_groups(self) -> None:
        security_group = _resource(
            "aws_security_group.app",
            "aws_security_group",
            ResourceCategory.NETWORK,
            identifier="sg-app",
        )
        standalone_rule = _public_http_rule()
        rule_resource = _resource(
            "aws_security_group_rule.app_http",
            "aws_security_group_rule",
            ResourceCategory.NETWORK,
            network_rules=[standalone_rule],
            metadata={"security_group_id": "sg-app"},
        )
        resources = [security_group, rule_resource]

        MergeStandaloneSecurityGroupRulesStage().apply(resources, _context(resources))

        self.assertEqual(len(security_group.network_rules), 1)
        self.assertIsNot(security_group.network_rules[0], standalone_rule)
        self.assertTrue(security_group.network_rules[0].allows_internet())
        self.assertEqual(
            security_group.metadata["standalone_rule_addresses"],
            ["aws_security_group_rule.app_http"],
        )

    def test_network_posture_stage_applies_explicit_public_and_nat_routes(self) -> None:
        public_subnet = _resource(
            "aws_subnet.public",
            "aws_subnet",
            ResourceCategory.NETWORK,
            identifier="subnet-public",
            vpc_id="vpc-app",
        )
        private_subnet = _resource(
            "aws_subnet.private",
            "aws_subnet",
            ResourceCategory.NETWORK,
            identifier="subnet-private",
            vpc_id="vpc-app",
        )
        public_route_table = _resource(
            "aws_route_table.public",
            "aws_route_table",
            ResourceCategory.NETWORK,
            identifier="rtb-public",
            vpc_id="vpc-app",
            metadata={
                "routes": [
                    {
                        "destination_cidr_block": "0.0.0.0/0",
                        "gateway_id": "igw-app",
                    }
                ]
            },
        )
        private_route_table = _resource(
            "aws_route_table.private",
            "aws_route_table",
            ResourceCategory.NETWORK,
            identifier="rtb-private",
            vpc_id="vpc-app",
            metadata={
                "routes": [
                    {
                        "destination_cidr_block": "0.0.0.0/0",
                        "nat_gateway_id": "nat-app",
                    }
                ]
            },
        )
        nat_gateway = _resource(
            "aws_nat_gateway.private",
            "aws_nat_gateway",
            ResourceCategory.NETWORK,
            identifier="nat-app",
        )
        public_association = _resource(
            "aws_route_table_association.public",
            "aws_route_table_association",
            ResourceCategory.NETWORK,
            metadata={"subnet_id": "subnet-public", "route_table_id": "rtb-public"},
        )
        private_association = _resource(
            "aws_route_table_association.private",
            "aws_route_table_association",
            ResourceCategory.NETWORK,
            metadata={"subnet_id": "subnet-private", "route_table_id": "rtb-private"},
        )
        resources = [
            public_subnet,
            private_subnet,
            public_route_table,
            private_route_table,
            nat_gateway,
            public_association,
            private_association,
        ]
        context = _context(resources)

        DeriveSubnetPostureStage().apply(resources, context)

        self.assertTrue(public_subnet.is_public_subnet)
        self.assertTrue(public_subnet.has_public_route)
        self.assertFalse(public_subnet.has_nat_gateway_egress)
        self.assertEqual(public_subnet.metadata["route_table_ids"], ["rtb-public"])
        self.assertFalse(private_subnet.is_public_subnet)
        self.assertFalse(private_subnet.has_public_route)
        self.assertTrue(private_subnet.has_nat_gateway_egress)
        self.assertEqual(private_subnet.metadata["route_table_ids"], ["rtb-private"])
        self.assertEqual(context.public_subnet_ids, {"subnet-public"})

    def test_vpc_inference_stage_uses_subnet_then_security_group_references(self) -> None:
        subnet = _resource(
            "aws_subnet.app",
            "aws_subnet",
            ResourceCategory.NETWORK,
            identifier="subnet-app",
            vpc_id="vpc-from-subnet",
        )
        security_group = _resource(
            "aws_security_group.worker",
            "aws_security_group",
            ResourceCategory.NETWORK,
            identifier="sg-worker",
            vpc_id="vpc-from-security-group",
        )
        subnet_workload = _resource(
            "aws_instance.app",
            "aws_instance",
            ResourceCategory.COMPUTE,
            subnet_ids=("subnet-app",),
        )
        security_group_workload = _resource(
            "aws_lambda_function.worker",
            "aws_lambda_function",
            ResourceCategory.COMPUTE,
            security_group_ids=("sg-worker",),
        )
        resources = [subnet, security_group, subnet_workload, security_group_workload]

        InferVpcIdsStage().apply(resources, _context(resources))

        self.assertEqual(subnet_workload.vpc_id, "vpc-from-subnet")
        self.assertEqual(security_group_workload.vpc_id, "vpc-from-security-group")

    def test_public_exposure_stage_marks_public_instance_with_internet_ingress(self) -> None:
        security_group = _resource(
            "aws_security_group.web",
            "aws_security_group",
            ResourceCategory.NETWORK,
            identifier="sg-web",
            network_rules=[_public_http_rule()],
        )
        subnet = _resource(
            "aws_subnet.public",
            "aws_subnet",
            ResourceCategory.NETWORK,
            identifier="subnet-public",
        )
        instance = _resource(
            "aws_instance.web",
            "aws_instance",
            ResourceCategory.COMPUTE,
            subnet_ids=("subnet-public",),
            security_group_ids=("sg-web",),
            public_access_configured=True,
            metadata={"public_access_reasons": ["instance requests a public IP"]},
        )
        resources = [security_group, subnet, instance]
        context = _context(resources)
        context.public_subnet_ids = {"subnet-public"}

        DerivePublicExposureStage().apply(resources, context)

        self.assertTrue(instance.in_public_subnet)
        self.assertTrue(instance.internet_ingress_capable)
        self.assertTrue(instance.public_exposure)
        self.assertTrue(instance.direct_internet_reachable)
        self.assertEqual(
            instance.internet_ingress_reasons,
            ["aws_security_group.web ingress tcp 80 from 0.0.0.0/0"],
        )
        self.assertEqual(
            instance.public_exposure_reasons,
            ["instance has a public IP path and attached security groups allow internet ingress"],
        )

    def test_public_exposure_stage_uses_explicit_public_route_association_for_instances(self) -> None:
        security_group = _resource(
            "aws_security_group.web",
            "aws_security_group",
            ResourceCategory.NETWORK,
            identifier="sg-web",
            network_rules=[_public_http_rule()],
        )
        subnet = _resource(
            "aws_subnet.public",
            "aws_subnet",
            ResourceCategory.NETWORK,
            identifier="subnet-public",
            vpc_id="vpc-app",
        )
        route_table = _resource(
            "aws_route_table.public",
            "aws_route_table",
            ResourceCategory.NETWORK,
            identifier="rtb-public",
            vpc_id="vpc-app",
            metadata={
                "routes": [
                    {
                        "destination_cidr_block": "0.0.0.0/0",
                        "gateway_id": "igw-app",
                    }
                ]
            },
        )
        association = _resource(
            "aws_route_table_association.public",
            "aws_route_table_association",
            ResourceCategory.NETWORK,
            metadata={"subnet_id": "subnet-public", "route_table_id": "rtb-public"},
        )
        instance = _resource(
            "aws_instance.web",
            "aws_instance",
            ResourceCategory.COMPUTE,
            subnet_ids=("subnet-public",),
            security_group_ids=("sg-web",),
            public_access_configured=True,
        )
        resources = [security_group, subnet, route_table, association, instance]
        context = _context(resources)

        DeriveSubnetPostureStage().apply(resources, context)
        DerivePublicExposureStage().apply(resources, context)

        self.assertEqual(context.public_subnet_ids, {"subnet-public"})
        self.assertTrue(subnet.is_public_subnet)
        self.assertTrue(instance.in_public_subnet)
        self.assertTrue(instance.internet_ingress_capable)
        self.assertTrue(instance.public_exposure)
        self.assertTrue(instance.direct_internet_reachable)

    def test_public_exposure_stage_keeps_nat_only_subnet_instance_private(self) -> None:
        security_group = _resource(
            "aws_security_group.web",
            "aws_security_group",
            ResourceCategory.NETWORK,
            identifier="sg-web",
            network_rules=[_public_http_rule()],
        )
        subnet = _resource(
            "aws_subnet.private",
            "aws_subnet",
            ResourceCategory.NETWORK,
            identifier="subnet-private",
            vpc_id="vpc-app",
            metadata={"map_public_ip_on_launch": True},
        )
        internet_gateway = _resource(
            "aws_internet_gateway.main",
            "aws_internet_gateway",
            ResourceCategory.NETWORK,
            identifier="igw-app",
            vpc_id="vpc-app",
        )
        public_route_table = _resource(
            "aws_route_table.public",
            "aws_route_table",
            ResourceCategory.NETWORK,
            identifier="rtb-public",
            vpc_id="vpc-app",
            metadata={
                "routes": [
                    {
                        "destination_cidr_block": "0.0.0.0/0",
                        "gateway_id": "igw-app",
                    }
                ]
            },
        )
        private_route_table = _resource(
            "aws_route_table.private",
            "aws_route_table",
            ResourceCategory.NETWORK,
            identifier="rtb-private",
            vpc_id="vpc-app",
            metadata={
                "routes": [
                    {
                        "destination_cidr_block": "0.0.0.0/0",
                        "nat_gateway_id": "nat-app",
                    }
                ]
            },
        )
        nat_gateway = _resource(
            "aws_nat_gateway.private",
            "aws_nat_gateway",
            ResourceCategory.NETWORK,
            identifier="nat-app",
        )
        association = _resource(
            "aws_route_table_association.private",
            "aws_route_table_association",
            ResourceCategory.NETWORK,
            metadata={"subnet_id": "subnet-private", "route_table_id": "rtb-private"},
        )
        instance = _resource(
            "aws_instance.web",
            "aws_instance",
            ResourceCategory.COMPUTE,
            subnet_ids=("subnet-private",),
            security_group_ids=("sg-web",),
            public_access_configured=True,
        )
        resources = [
            security_group,
            subnet,
            internet_gateway,
            public_route_table,
            private_route_table,
            nat_gateway,
            association,
            instance,
        ]
        context = _context(resources)

        DeriveSubnetPostureStage().apply(resources, context)
        DerivePublicExposureStage().apply(resources, context)

        self.assertEqual(context.public_subnet_ids, set())
        self.assertFalse(subnet.is_public_subnet)
        self.assertFalse(subnet.has_public_route)
        self.assertTrue(subnet.has_nat_gateway_egress)
        self.assertFalse(instance.in_public_subnet)
        self.assertTrue(instance.has_nat_gateway_egress)
        self.assertTrue(instance.internet_ingress_capable)
        self.assertFalse(instance.public_exposure)
        self.assertFalse(instance.direct_internet_reachable)
        self.assertEqual(instance.public_exposure_reasons, [])

    def test_public_exposure_stage_requires_instance_public_access_configured(self) -> None:
        security_group = _resource(
            "aws_security_group.web",
            "aws_security_group",
            ResourceCategory.NETWORK,
            identifier="sg-web",
            network_rules=[_public_http_rule()],
        )
        subnet = _resource(
            "aws_subnet.public",
            "aws_subnet",
            ResourceCategory.NETWORK,
            identifier="subnet-public",
        )
        instance = _resource(
            "aws_instance.web",
            "aws_instance",
            ResourceCategory.COMPUTE,
            subnet_ids=("subnet-public",),
            security_group_ids=("sg-web",),
            public_access_configured=False,
        )
        resources = [security_group, subnet, instance]
        context = _context(resources)
        context.public_subnet_ids = {"subnet-public"}

        DerivePublicExposureStage().apply(resources, context)

        self.assertTrue(instance.in_public_subnet)
        self.assertTrue(instance.internet_ingress_capable)
        self.assertFalse(instance.public_exposure)
        self.assertFalse(instance.direct_internet_reachable)
        self.assertEqual(instance.public_exposure_reasons, [])

    def test_public_exposure_stage_keeps_instance_without_security_groups_private(self) -> None:
        subnet = _resource(
            "aws_subnet.public",
            "aws_subnet",
            ResourceCategory.NETWORK,
            identifier="subnet-public",
        )
        instance = _resource(
            "aws_instance.web",
            "aws_instance",
            ResourceCategory.COMPUTE,
            subnet_ids=("subnet-public",),
            public_access_configured=True,
        )
        resources = [subnet, instance]
        context = _context(resources)
        context.public_subnet_ids = {"subnet-public"}

        DerivePublicExposureStage().apply(resources, context)

        self.assertTrue(instance.in_public_subnet)
        self.assertFalse(instance.internet_ingress_capable)
        self.assertEqual(instance.internet_ingress_reasons, [])
        self.assertFalse(instance.public_exposure)
        self.assertFalse(instance.direct_internet_reachable)
        self.assertEqual(instance.public_exposure_reasons, [])

    def test_public_exposure_stage_marks_public_db_without_security_groups(self) -> None:
        database = _resource(
            "aws_db_instance.app",
            "aws_db_instance",
            ResourceCategory.DATA,
            public_access_configured=True,
        )
        resources = [database]

        DerivePublicExposureStage().apply(resources, _context(resources))

        self.assertFalse(database.internet_ingress_capable)
        self.assertTrue(database.public_exposure)
        self.assertTrue(database.direct_internet_reachable)
        self.assertEqual(
            database.public_exposure_reasons,
            ["database is marked publicly_accessible and no attached security groups provide ingress evidence"],
        )

    def test_public_exposure_stage_keeps_public_db_with_private_sg_private(self) -> None:
        security_group = _resource(
            "aws_security_group.db",
            "aws_security_group",
            ResourceCategory.NETWORK,
            identifier="sg-db",
            network_rules=[_private_http_rule()],
        )
        database = _resource(
            "aws_db_instance.app",
            "aws_db_instance",
            ResourceCategory.DATA,
            security_group_ids=("sg-db",),
            public_access_configured=True,
        )
        resources = [security_group, database]

        DerivePublicExposureStage().apply(resources, _context(resources))

        self.assertFalse(database.internet_ingress_capable)
        self.assertFalse(database.public_exposure)
        self.assertFalse(database.direct_internet_reachable)
        self.assertEqual(database.public_exposure_reasons, [])

    def test_public_exposure_stage_marks_public_db_with_internet_sg(self) -> None:
        security_group = _resource(
            "aws_security_group.db",
            "aws_security_group",
            ResourceCategory.NETWORK,
            identifier="sg-db",
            network_rules=[_public_http_rule()],
        )
        database = _resource(
            "aws_db_instance.app",
            "aws_db_instance",
            ResourceCategory.DATA,
            security_group_ids=("sg-db",),
            public_access_configured=True,
        )
        resources = [security_group, database]

        DerivePublicExposureStage().apply(resources, _context(resources))

        self.assertTrue(database.internet_ingress_capable)
        self.assertTrue(database.public_exposure)
        self.assertTrue(database.direct_internet_reachable)
        self.assertEqual(
            database.public_exposure_reasons,
            ["database is marked publicly_accessible and attached security groups allow internet ingress"],
        )

    def test_public_exposure_stage_marks_internet_facing_lb_without_security_groups(self) -> None:
        load_balancer = _resource(
            "aws_lb.web",
            "aws_lb",
            ResourceCategory.EDGE,
            public_access_configured=True,
        )
        resources = [load_balancer]

        DerivePublicExposureStage().apply(resources, _context(resources))

        self.assertFalse(load_balancer.internet_ingress_capable)
        self.assertTrue(load_balancer.public_exposure)
        self.assertTrue(load_balancer.direct_internet_reachable)
        self.assertEqual(
            load_balancer.public_exposure_reasons,
            ["load balancer is configured as internet-facing"],
        )

    def test_public_exposure_stage_marks_internet_facing_lb_with_internet_sg(self) -> None:
        security_group = _resource(
            "aws_security_group.lb",
            "aws_security_group",
            ResourceCategory.NETWORK,
            identifier="sg-lb",
            network_rules=[_public_http_rule()],
        )
        load_balancer = _resource(
            "aws_lb.web",
            "aws_lb",
            ResourceCategory.EDGE,
            security_group_ids=("sg-lb",),
            public_access_configured=True,
        )
        resources = [security_group, load_balancer]

        DerivePublicExposureStage().apply(resources, _context(resources))

        self.assertTrue(load_balancer.internet_ingress_capable)
        self.assertEqual(
            load_balancer.internet_ingress_reasons,
            ["aws_security_group.lb ingress tcp 80 from 0.0.0.0/0"],
        )
        self.assertTrue(load_balancer.public_exposure)
        self.assertTrue(load_balancer.direct_internet_reachable)
        self.assertEqual(
            load_balancer.public_exposure_reasons,
            ["load balancer is internet-facing and attached security groups allow internet ingress"],
        )

    def test_public_exposure_stage_keeps_internet_facing_lb_with_private_sg_private(self) -> None:
        security_group = _resource(
            "aws_security_group.lb",
            "aws_security_group",
            ResourceCategory.NETWORK,
            identifier="sg-lb",
            network_rules=[_private_http_rule()],
        )
        load_balancer = _resource(
            "aws_lb.web",
            "aws_lb",
            ResourceCategory.EDGE,
            security_group_ids=("sg-lb",),
            public_access_configured=True,
        )
        resources = [security_group, load_balancer]

        DerivePublicExposureStage().apply(resources, _context(resources))

        self.assertFalse(load_balancer.internet_ingress_capable)
        self.assertFalse(load_balancer.public_exposure)
        self.assertFalse(load_balancer.direct_internet_reachable)
        self.assertEqual(load_balancer.public_exposure_reasons, [])

    def test_resource_policy_stage_merges_bucket_policy_statements_and_document(self) -> None:
        bucket = _resource(
            "aws_s3_bucket.logs",
            "aws_s3_bucket",
            ResourceCategory.DATA,
            identifier="logs",
            arn="arn:aws:s3:::logs",
            metadata={
                "bucket": "logs",
                "policy_document": {"Statement": [{"Sid": "Base"}]},
            },
        )
        statement = IAMPolicyStatement(
            effect="Allow",
            actions=["s3:GetObject"],
            resources=["arn:aws:s3:::logs/*"],
            principals=["*"],
        )
        bucket_policy = _resource(
            "aws_s3_bucket_policy.logs_public_read",
            "aws_s3_bucket_policy",
            ResourceCategory.DATA,
            policy_statements=[statement],
            metadata={
                "bucket": "logs",
                "policy_document": {"Statement": [{"Sid": "Extra"}]},
            },
        )
        resources = [bucket, bucket_policy]

        MergeResourcePolicyResourcesStage().apply(resources, _context(resources))

        self.assertEqual(len(bucket.policy_statements), 1)
        self.assertIsNot(bucket.policy_statements[0], statement)
        self.assertEqual(bucket.policy_statements[0].actions, ["s3:GetObject"])
        self.assertEqual(
            aws_facts(bucket).resource_policy_source_addresses,
            ["aws_s3_bucket_policy.logs_public_read"],
        )
        self.assertEqual(
            aws_facts(bucket).policy_document,
            {"Statement": [{"Sid": "Base"}, {"Sid": "Extra"}]},
        )

    def test_s3_public_access_block_stage_suppresses_bucket_exposure(self) -> None:
        bucket = _resource(
            "aws_s3_bucket.logs",
            "aws_s3_bucket",
            ResourceCategory.DATA,
            identifier="logs",
            public_access_configured=True,
            public_exposure=True,
            metadata={
                "bucket": "logs",
                "acl": "public-read",
                "policy_document": {},
                "public_exposure_reasons": ["bucket ACL `public-read` grants public access"],
            },
        )
        access_block = _resource(
            "aws_s3_bucket_public_access_block.logs",
            "aws_s3_bucket_public_access_block",
            ResourceCategory.DATA,
            metadata={
                "bucket": "logs",
                "block_public_acls": True,
                "block_public_policy": True,
                "ignore_public_acls": True,
                "restrict_public_buckets": True,
            },
        )
        resources = [bucket, access_block]

        ApplyS3PublicAccessBlocksStage().apply(resources, _context(resources))

        self.assertFalse(bucket.public_exposure)
        self.assertEqual(bucket.public_exposure_reasons, [])
        self.assertEqual(
            aws_facts(bucket).public_access_block,
            {
                "block_public_acls": True,
                "block_public_policy": True,
                "ignore_public_acls": True,
                "restrict_public_buckets": True,
            },
        )

    def test_s3_posture_stage_applies_versioning_and_encryption_to_bucket(self) -> None:
        bucket = _resource(
            "aws_s3_bucket.logs",
            "aws_s3_bucket",
            ResourceCategory.DATA,
            identifier="logs",
            arn="arn:aws:s3:::logs",
            metadata={"bucket": "logs"},
        )
        versioning = _resource(
            "aws_s3_bucket_versioning.logs",
            "aws_s3_bucket_versioning",
            ResourceCategory.DATA,
            metadata={
                "bucket": "logs",
                "s3_versioning_status": "Enabled",
                "s3_versioning_configuration": {"status": "Enabled"},
            },
        )
        encryption = _resource(
            "aws_s3_bucket_server_side_encryption_configuration.logs",
            "aws_s3_bucket_server_side_encryption_configuration",
            ResourceCategory.DATA,
            metadata={
                "bucket": "logs",
                "s3_encryption_algorithm": "aws:kms",
                "s3_kms_master_key_id": "arn:aws:kms:us-east-1:111122223333:key/storage",
                "s3_bucket_key_enabled_state": "enabled",
                "s3_server_side_encryption_configuration": {"rule": []},
                "s3_posture_uncertainties": ["rule.bucket_key_enabled is unknown after planning"],
            },
        )
        resources = [bucket, versioning, encryption]

        ApplyS3PostureResourcesStage().apply(resources, _context(resources))

        bucket_facts = aws_facts(bucket)
        self.assertEqual(bucket_facts.s3_versioning_status, "Enabled")
        self.assertTrue(bucket_facts.s3_versioning_enabled)
        self.assertEqual(bucket_facts.s3_versioning_source_address, "aws_s3_bucket_versioning.logs")
        self.assertEqual(bucket_facts.s3_versioning_configuration, {"status": "Enabled"})
        self.assertEqual(bucket_facts.s3_encryption_algorithm, "aws:kms")
        self.assertEqual(
            bucket_facts.s3_kms_master_key_id,
            "arn:aws:kms:us-east-1:111122223333:key/storage",
        )
        self.assertTrue(bucket_facts.s3_bucket_key_enabled)
        self.assertEqual(
            bucket_facts.s3_encryption_source_address,
            "aws_s3_bucket_server_side_encryption_configuration.logs",
        )
        self.assertEqual(bucket_facts.s3_server_side_encryption_configuration, {"rule": []})
        self.assertEqual(
            bucket_facts.s3_posture_uncertainties,
            [
                "aws_s3_bucket_server_side_encryption_configuration.logs: "
                "rule.bucket_key_enabled is unknown after planning"
            ],
        )

    def test_s3_posture_stage_records_unresolved_bucket_references(self) -> None:
        versioning = _resource(
            "aws_s3_bucket_versioning.logs",
            "aws_s3_bucket_versioning",
            ResourceCategory.DATA,
            metadata={"bucket": "logs", "s3_versioning_status": "Enabled"},
        )

        ApplyS3PostureResourcesStage().apply([versioning], _context([versioning]))

        self.assertEqual(versioning.metadata["unresolved_bucket_references"], ["logs"])

    def test_ecs_stage_resolves_task_definition_roles_and_runtime_metadata(self) -> None:
        cluster = _resource(
            "aws_ecs_cluster.main",
            "aws_ecs_cluster",
            ResourceCategory.COMPUTE,
            identifier="main",
        )
        task_role = _resource(
            "aws_iam_role.task",
            "aws_iam_role",
            ResourceCategory.IAM,
            arn="arn:aws:iam::111122223333:role/task",
        )
        execution_role = _resource(
            "aws_iam_role.execution",
            "aws_iam_role",
            ResourceCategory.IAM,
            arn="arn:aws:iam::111122223333:role/execution",
        )
        task_definition = _resource(
            "aws_ecs_task_definition.app",
            "aws_ecs_task_definition",
            ResourceCategory.COMPUTE,
            identifier="app:12",
            metadata={
                "family": "app",
                "revision": 12,
                "network_mode": "awsvpc",
                "requires_compatibilities": ["FARGATE"],
                "task_role_arn": "arn:aws:iam::111122223333:role/task",
                "execution_role_arn": "arn:aws:iam::111122223333:role/execution",
            },
        )
        service = _resource(
            "aws_ecs_service.app",
            "aws_ecs_service",
            ResourceCategory.COMPUTE,
            metadata={"cluster": "main", "task_definition": "app:12"},
        )
        resources = [cluster, task_role, execution_role, task_definition, service]

        ResolveEcsServiceRelationshipsStage().apply(resources, _context(resources))

        self.assertEqual(aws_facts(service).network_mode, "awsvpc")
        self.assertEqual(aws_facts(service).requires_compatibilities, ["FARGATE"])
        self.assertEqual(
            aws_facts(service).task_role_arn,
            "arn:aws:iam::111122223333:role/task",
        )
        self.assertEqual(service.attached_role_arns, ["arn:aws:iam::111122223333:role/task"])
        self.assertEqual(
            service.metadata["resolved_cluster_addresses"],
            ["aws_ecs_cluster.main"],
        )
        self.assertEqual(
            service.metadata["resolved_task_definition_addresses"],
            ["aws_ecs_task_definition.app"],
        )
        self.assertEqual(service.metadata["resolved_task_role_addresses"], ["aws_iam_role.task"])
        self.assertEqual(
            service.metadata["resolved_execution_role_addresses"],
            ["aws_iam_role.execution"],
        )

    def test_instance_profile_stage_attaches_resolved_roles_to_ec2_workloads(self) -> None:
        role = _resource(
            "aws_iam_role.web",
            "aws_iam_role",
            ResourceCategory.IAM,
            identifier="web-role",
            arn="arn:aws:iam::111122223333:role/web",
        )
        instance_profile = _resource(
            "aws_iam_instance_profile.web",
            "aws_iam_instance_profile",
            ResourceCategory.IAM,
            identifier="web-profile",
            metadata={"role_references": ["web-role"]},
        )
        instance = _resource(
            "aws_instance.web",
            "aws_instance",
            ResourceCategory.COMPUTE,
            metadata={"iam_instance_profile": "web-profile"},
        )
        resources = [role, instance_profile, instance]

        ResolveInstanceProfileRolesStage().apply(resources, _context(resources))

        self.assertEqual(
            aws_facts(instance_profile).resolved_role_references,
            ["arn:aws:iam::111122223333:role/web"],
        )
        self.assertEqual(instance.attached_role_arns, ["arn:aws:iam::111122223333:role/web"])
        self.assertEqual(
            instance.metadata["resolved_instance_profile_addresses"],
            ["aws_iam_instance_profile.web"],
        )

    def test_ecs_load_balancer_stage_marks_services_fronted_by_public_load_balancer(self) -> None:
        load_balancer = _resource(
            "aws_lb.web",
            "aws_lb",
            ResourceCategory.NETWORK,
            security_group_ids=("sg-lb",),
            public_exposure=True,
        )
        load_balancer_security_group = _resource(
            "aws_security_group.lb",
            "aws_security_group",
            ResourceCategory.NETWORK,
            identifier="sg-lb",
        )
        service_security_group = _resource(
            "aws_security_group.service",
            "aws_security_group",
            ResourceCategory.NETWORK,
            identifier="sg-service",
            network_rules=[_referenced_security_group_rule("sg-lb")],
        )
        service = _resource(
            "aws_ecs_service.app",
            "aws_ecs_service",
            ResourceCategory.COMPUTE,
            security_group_ids=("sg-service",),
        )
        resources = [
            load_balancer,
            load_balancer_security_group,
            service_security_group,
            service,
        ]

        MarkEcsLoadBalancerExposureStage().apply(resources, _context(resources))

        self.assertTrue(service.metadata["fronted_by_internet_facing_load_balancer"])
        self.assertEqual(
            service.metadata["internet_facing_load_balancer_addresses"],
            ["aws_lb.web"],
        )

    def test_ecs_load_balancer_stage_marks_services_from_listener_target_group_path(self) -> None:
        load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/web/abc"
        listener_arn = f"{load_balancer_arn}/listener/443"
        target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/app/def"
        load_balancer = _resource(
            "aws_lb.web",
            "aws_lb",
            ResourceCategory.EDGE,
            identifier="app/web/abc",
            arn=load_balancer_arn,
            public_exposure=True,
        )
        listener = _resource(
            "aws_lb_listener.https",
            "aws_lb_listener",
            ResourceCategory.EDGE,
            identifier=listener_arn,
            arn=listener_arn,
            metadata={
                "load_balancer_arn": load_balancer_arn,
                "target_group_arns": [target_group_arn],
            },
        )
        target_group = _resource(
            "aws_lb_target_group.app",
            "aws_lb_target_group",
            ResourceCategory.EDGE,
            identifier=target_group_arn,
            arn=target_group_arn,
        )
        service = _resource(
            "aws_ecs_service.app",
            "aws_ecs_service",
            ResourceCategory.COMPUTE,
            metadata={
                "load_balancers": [
                    {
                        "target_group_arn": target_group_arn,
                        "container_name": "app",
                        "container_port": 8080,
                    }
                ]
            },
        )
        resources = [load_balancer, listener, target_group, service]

        MarkEcsLoadBalancerExposureStage().apply(resources, _context(resources))

        self.assertTrue(service.metadata["fronted_by_internet_facing_load_balancer"])
        self.assertEqual(
            service.metadata["internet_facing_load_balancer_addresses"],
            ["aws_lb.web"],
        )

    def test_ecs_load_balancer_stage_marks_services_from_listener_rule_target_group_path(self) -> None:
        load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/web/abc"
        listener_arn = f"{load_balancer_arn}/listener/443"
        target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/app/def"
        target_group_reference = "aws_lb_target_group.app.arn"
        load_balancer = _resource(
            "aws_lb.web",
            "aws_lb",
            ResourceCategory.EDGE,
            identifier="app/web/abc",
            arn=load_balancer_arn,
            public_exposure=True,
        )
        listener = _resource(
            "aws_lb_listener.https",
            "aws_lb_listener",
            ResourceCategory.EDGE,
            identifier=listener_arn,
            arn=listener_arn,
            metadata={"load_balancer_arn": load_balancer_arn, "target_group_arns": []},
        )
        listener_rule = _resource(
            "aws_lb_listener_rule.app",
            "aws_lb_listener_rule",
            ResourceCategory.EDGE,
            metadata={
                "listener_arn": listener_arn,
                "target_group_arns": [target_group_reference],
            },
        )
        target_group = _resource(
            "aws_lb_target_group.app",
            "aws_lb_target_group",
            ResourceCategory.EDGE,
            identifier=target_group_arn,
            arn=target_group_arn,
        )
        service = _resource(
            "aws_ecs_service.app",
            "aws_ecs_service",
            ResourceCategory.COMPUTE,
            metadata={"load_balancers": [{"target_group_arn": target_group_reference}]},
        )
        resources = [load_balancer, listener, listener_rule, target_group, service]

        MarkEcsLoadBalancerExposureStage().apply(resources, _context(resources))

        self.assertTrue(service.metadata["fronted_by_internet_facing_load_balancer"])
        self.assertEqual(
            service.metadata["internet_facing_load_balancer_addresses"],
            ["aws_lb.web"],
        )

    def test_ecs_load_balancer_stage_ignores_private_listener_target_group_path(self) -> None:
        load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/private/abc"
        listener_arn = f"{load_balancer_arn}/listener/443"
        target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/app/def"
        load_balancer = _resource(
            "aws_lb.private",
            "aws_lb",
            ResourceCategory.EDGE,
            identifier="app/private/abc",
            arn=load_balancer_arn,
            public_exposure=False,
        )
        listener = _resource(
            "aws_lb_listener.https",
            "aws_lb_listener",
            ResourceCategory.EDGE,
            identifier=listener_arn,
            arn=listener_arn,
            metadata={
                "load_balancer_arn": load_balancer_arn,
                "target_group_arns": [target_group_arn],
            },
        )
        target_group = _resource(
            "aws_lb_target_group.app",
            "aws_lb_target_group",
            ResourceCategory.EDGE,
            identifier=target_group_arn,
            arn=target_group_arn,
        )
        service = _resource(
            "aws_ecs_service.app",
            "aws_ecs_service",
            ResourceCategory.COMPUTE,
            metadata={"load_balancers": [{"target_group_arn": target_group_arn}]},
        )
        resources = [load_balancer, listener, target_group, service]

        MarkEcsLoadBalancerExposureStage().apply(resources, _context(resources))

        self.assertFalse(service.metadata["fronted_by_internet_facing_load_balancer"])
        self.assertNotIn("internet_facing_load_balancer_addresses", service.metadata)


if __name__ == "__main__":
    unittest.main()
