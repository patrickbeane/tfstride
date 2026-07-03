from __future__ import annotations

import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from tests.integration.analysis_support import (
    ALB_EC2_RDS_FIXTURE_PATH,
    ECS_FARGATE_FIXTURE_PATH,
    FIXTURE_PATH,
    LAMBDA_DEPLOY_ROLE_FIXTURE_PATH,
    SAFE_FIXTURE_PATH,
    TFSIntegrationTestCase,
)
from tfstride.models import (
    BoundaryType,
    Severity,
)


class AwsNetworkAnalysisIntegrationTests(TFSIntegrationTestCase):
    def test_standalone_security_group_rules_merge_into_target_groups(self) -> None:
        safe_result = self.engine.analyze_plan(SAFE_FIXTURE_PATH)
        mixed_result = self.engine.analyze_plan(FIXTURE_PATH)

        safe_app_group = safe_result.inventory.get_by_address("aws_security_group.app")
        mixed_db_group = mixed_result.inventory.get_by_address("aws_security_group.db")

        self.assertIn(
            "aws_security_group_rule.app_from_lb", safe_app_group.metadata.get("standalone_rule_addresses", [])
        )
        self.assertEqual(len(safe_app_group.network_rules), 2)
        self.assertIn(
            "aws_security_group_rule.db_from_public_app", mixed_db_group.metadata.get("standalone_rule_addresses", [])
        )
        self.assertIn(
            "aws_security_group_rule.db_from_internet", mixed_db_group.metadata.get("standalone_rule_addresses", [])
        )
        self.assertEqual(len(mixed_db_group.network_rules), 3)

    def test_route_table_associations_and_nat_gateways_refine_subnet_classification(self) -> None:
        safe_result = self.engine.analyze_plan(SAFE_FIXTURE_PATH)
        mixed_result = self.engine.analyze_plan(FIXTURE_PATH)

        safe_public_subnet = safe_result.inventory.get_by_address("aws_subnet.public_edge")
        safe_private_subnet = safe_result.inventory.get_by_address("aws_subnet.private_app")
        mixed_private_subnet = mixed_result.inventory.get_by_address("aws_subnet.private_data")

        self.assertEqual(safe_public_subnet.metadata.get("route_table_ids"), ["rtb-safe-001"])
        self.assertTrue(safe_public_subnet.metadata.get("is_public_subnet"))
        self.assertTrue(safe_public_subnet.metadata.get("has_public_route"))
        self.assertNotIn("in_public_subnet", safe_public_subnet.metadata)
        self.assertFalse(safe_public_subnet.metadata.get("has_nat_gateway_egress"))

        self.assertEqual(safe_private_subnet.metadata.get("route_table_ids"), ["rtb-safe-private-001"])
        self.assertFalse(safe_private_subnet.metadata.get("is_public_subnet"))
        self.assertNotIn("in_public_subnet", safe_private_subnet.metadata)
        self.assertTrue(safe_private_subnet.metadata.get("has_nat_gateway_egress"))

        self.assertEqual(mixed_private_subnet.metadata.get("route_table_ids"), ["rtb-private-001"])
        self.assertTrue(mixed_private_subnet.metadata.get("has_nat_gateway_egress"))

    def test_public_ip_without_internet_ingress_does_not_create_internet_boundary(self) -> None:
        payload = {
            "format_version": "1.2",
            "terraform_version": "1.8.5",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "address": "aws_vpc.main",
                            "mode": "managed",
                            "type": "aws_vpc",
                            "name": "main",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {"id": "vpc-1"},
                        },
                        {
                            "address": "aws_subnet.public",
                            "mode": "managed",
                            "type": "aws_subnet",
                            "name": "public",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "subnet-1",
                                "vpc_id": "vpc-1",
                                "cidr_block": "10.0.1.0/24",
                                "map_public_ip_on_launch": True,
                            },
                        },
                        {
                            "address": "aws_internet_gateway.main",
                            "mode": "managed",
                            "type": "aws_internet_gateway",
                            "name": "main",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {"id": "igw-1", "vpc_id": "vpc-1"},
                        },
                        {
                            "address": "aws_route_table.public",
                            "mode": "managed",
                            "type": "aws_route_table",
                            "name": "public",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "rtb-1",
                                "vpc_id": "vpc-1",
                                "route": [{"cidr_block": "0.0.0.0/0", "gateway_id": "igw-1"}],
                            },
                        },
                        {
                            "address": "aws_route_table_association.public",
                            "mode": "managed",
                            "type": "aws_route_table_association",
                            "name": "public",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "assoc-1",
                                "subnet_id": "subnet-1",
                                "route_table_id": "rtb-1",
                            },
                        },
                        {
                            "address": "aws_security_group.web",
                            "mode": "managed",
                            "type": "aws_security_group",
                            "name": "web",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "sg-1",
                                "vpc_id": "vpc-1",
                                "ingress": [],
                                "egress": [
                                    {"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}
                                ],
                            },
                        },
                        {
                            "address": "aws_instance.web",
                            "mode": "managed",
                            "type": "aws_instance",
                            "name": "web",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "i-1",
                                "subnet_id": "subnet-1",
                                "vpc_security_group_ids": ["sg-1"],
                                "associate_public_ip_address": True,
                            },
                        },
                    ]
                }
            },
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            plan_path = Path(tmp_dir) / "plan.json"
            plan_path.write_text(json.dumps(payload), encoding="utf-8")
            result = self.engine.analyze_plan(plan_path)

        instance = result.inventory.get_by_address("aws_instance.web")
        internet_boundaries = [
            boundary
            for boundary in result.trust_boundaries
            if boundary.boundary_type == BoundaryType.INTERNET_TO_SERVICE and boundary.target == "aws_instance.web"
        ]

        self.assertIsNotNone(instance)
        self.assertTrue(instance.public_access_configured)
        self.assertTrue(instance.metadata.get("in_public_subnet"))
        self.assertFalse(instance.metadata.get("internet_ingress_capable"))
        self.assertFalse(instance.public_exposure)
        self.assertEqual(
            instance.metadata.get("public_access_reasons"), ["instance requests an associated public IP address"]
        )
        self.assertEqual(instance.metadata.get("public_exposure_reasons"), [])
        self.assertEqual(internet_boundaries, [])
        self.assertNotIn(
            "Internet-exposed compute service permits overly broad ingress",
            {finding.title for finding in result.findings},
        )

    def test_database_reachability_prefers_security_group_evidence_over_same_vpc_only(self) -> None:
        safe_result = self.engine.analyze_plan(SAFE_FIXTURE_PATH)
        mixed_result = self.engine.analyze_plan(FIXTURE_PATH)

        safe_boundary = next(
            boundary
            for boundary in safe_result.trust_boundaries
            if boundary.boundary_type == BoundaryType.WORKLOAD_TO_DATA_STORE
            and boundary.source == "aws_instance.app"
            and boundary.target == "aws_db_instance.app"
        )
        self.assertIn("explicitly trust the workload security group", safe_boundary.rationale)

        mixed_db = mixed_result.inventory.get_by_address("aws_db_instance.app")
        internet_boundaries_to_db = [
            boundary
            for boundary in mixed_result.trust_boundaries
            if boundary.boundary_type == BoundaryType.INTERNET_TO_SERVICE and boundary.target == "aws_db_instance.app"
        ]

        self.assertFalse(mixed_db.public_exposure)
        self.assertTrue(mixed_db.metadata.get("internet_ingress_capable"))
        self.assertEqual(internet_boundaries_to_db, [])

    def test_realistic_alb_ec2_rds_fixture_surfaces_transitive_data_path(self) -> None:
        result = self.engine.analyze_plan(ALB_EC2_RDS_FIXTURE_PATH)
        boundary_types = Counter(boundary.boundary_type for boundary in result.trust_boundaries)
        title_counts = Counter(finding.title for finding in result.findings)

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(len(result.inventory.resources), 19)
        self.assertEqual(
            dict(title_counts),
            {"Sensitive data tier is transitively reachable from an internet-exposed path": 1},
        )
        self.assertEqual(boundary_types[BoundaryType.INTERNET_TO_SERVICE], 1)
        self.assertEqual(boundary_types[BoundaryType.PUBLIC_TO_PRIVATE], 2)
        self.assertEqual(boundary_types[BoundaryType.WORKLOAD_TO_DATA_STORE], 1)

    def test_realistic_ecs_fargate_fixture_models_private_workload_boundaries(self) -> None:
        result = self.engine.analyze_plan(ECS_FARGATE_FIXTURE_PATH)
        ecs_service = result.inventory.get_by_address("aws_ecs_service.app")
        boundary_pairs = {
            (boundary.boundary_type, boundary.source, boundary.target) for boundary in result.trust_boundaries
        }
        findings_by_title = Counter(finding.title for finding in result.findings)

        self.assertIsNotNone(ecs_service)
        self.assertFalse(ecs_service.public_exposure)
        self.assertFalse(ecs_service.metadata.get("in_public_subnet"))
        self.assertTrue(ecs_service.metadata.get("fronted_by_internet_facing_load_balancer"))
        self.assertEqual(
            ecs_service.metadata.get("internet_facing_load_balancer_addresses"),
            ["aws_lb.web"],
        )
        self.assertEqual(
            ecs_service.attached_role_arns,
            ("arn:aws:iam::111122223333:role/app-task-role",),
        )
        self.assertEqual(
            ecs_service.metadata.get("execution_role_arn"),
            "arn:aws:iam::111122223333:role/app-execution-role",
        )
        self.assertIn(
            (BoundaryType.INTERNET_TO_SERVICE, "internet", "aws_lb.web"),
            boundary_pairs,
        )
        self.assertNotIn(
            (BoundaryType.INTERNET_TO_SERVICE, "internet", "aws_ecs_service.app"),
            boundary_pairs,
        )
        self.assertIn(
            (BoundaryType.WORKLOAD_TO_DATA_STORE, "aws_ecs_service.app", "aws_db_instance.app"),
            boundary_pairs,
        )
        self.assertIn(
            (BoundaryType.WORKLOAD_TO_DATA_STORE, "aws_ecs_service.app", "aws_secretsmanager_secret.app"),
            boundary_pairs,
        )
        self.assertIn(
            (BoundaryType.CONTROL_TO_WORKLOAD, "aws_iam_role.task", "aws_ecs_service.app"),
            boundary_pairs,
        )
        self.assertNotIn(
            (BoundaryType.CONTROL_TO_WORKLOAD, "aws_iam_role.execution", "aws_ecs_service.app"),
            boundary_pairs,
        )
        self.assertEqual(findings_by_title["Workload role carries sensitive permissions"], 1)

    def test_realistic_lambda_deploy_role_fixture_surfaces_four_medium_findings(self) -> None:
        result = self.engine.analyze_plan(LAMBDA_DEPLOY_ROLE_FIXTURE_PATH)
        boundary_types = Counter(boundary.boundary_type for boundary in result.trust_boundaries)
        severity_counts = Counter(finding.severity.value for finding in result.findings)
        title_counts = Counter(finding.title for finding in result.findings)

        self.assertEqual(len(result.inventory.resources), 13)
        self.assertEqual(len(result.findings), 4)
        self.assertEqual(dict(severity_counts), {"medium": 4})
        self.assertEqual(
            dict(title_counts),
            {
                "Cross-account or broad role trust lacks narrowing conditions": 1,
                "Role trust relationship expands blast radius": 1,
                "Workload role carries sensitive permissions": 1,
                "Workload uses S3 without a VPC endpoint": 1,
            },
        )
        self.assertEqual(boundary_types[BoundaryType.INTERNET_TO_SERVICE], 0)
        self.assertEqual(boundary_types[BoundaryType.PUBLIC_TO_PRIVATE], 1)
        self.assertEqual(boundary_types[BoundaryType.WORKLOAD_TO_DATA_STORE], 1)
        self.assertEqual(boundary_types[BoundaryType.CONTROL_TO_WORKLOAD], 1)
        self.assertEqual(boundary_types[BoundaryType.CROSS_ACCOUNT_OR_ROLE], 1)

    def test_transitive_private_data_path_from_public_edge_is_detected(self) -> None:
        payload = {
            "format_version": "1.2",
            "terraform_version": "1.8.5",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "address": "aws_vpc.main",
                            "mode": "managed",
                            "type": "aws_vpc",
                            "name": "main",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {"id": "vpc-1", "cidr_block": "10.42.0.0/16"},
                        },
                        {
                            "address": "aws_subnet.public_edge",
                            "mode": "managed",
                            "type": "aws_subnet",
                            "name": "public_edge",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "subnet-public-1",
                                "vpc_id": "vpc-1",
                                "cidr_block": "10.42.1.0/24",
                                "map_public_ip_on_launch": True,
                            },
                        },
                        {
                            "address": "aws_subnet.private_app",
                            "mode": "managed",
                            "type": "aws_subnet",
                            "name": "private_app",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "subnet-private-app-1",
                                "vpc_id": "vpc-1",
                                "cidr_block": "10.42.2.0/24",
                                "map_public_ip_on_launch": False,
                            },
                        },
                        {
                            "address": "aws_subnet.private_worker",
                            "mode": "managed",
                            "type": "aws_subnet",
                            "name": "private_worker",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "subnet-private-worker-1",
                                "vpc_id": "vpc-1",
                                "cidr_block": "10.42.3.0/24",
                                "map_public_ip_on_launch": False,
                            },
                        },
                        {
                            "address": "aws_internet_gateway.main",
                            "mode": "managed",
                            "type": "aws_internet_gateway",
                            "name": "main",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {"id": "igw-1", "vpc_id": "vpc-1"},
                        },
                        {
                            "address": "aws_route_table.public",
                            "mode": "managed",
                            "type": "aws_route_table",
                            "name": "public",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "rtb-public-1",
                                "vpc_id": "vpc-1",
                                "route": [{"cidr_block": "0.0.0.0/0", "gateway_id": "igw-1"}],
                            },
                        },
                        {
                            "address": "aws_nat_gateway.main",
                            "mode": "managed",
                            "type": "aws_nat_gateway",
                            "name": "main",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "nat-1",
                                "subnet_id": "subnet-public-1",
                                "allocation_id": "eipalloc-1",
                                "connectivity_type": "public",
                            },
                        },
                        {
                            "address": "aws_route_table.private",
                            "mode": "managed",
                            "type": "aws_route_table",
                            "name": "private",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "rtb-private-1",
                                "vpc_id": "vpc-1",
                                "route": [{"cidr_block": "0.0.0.0/0", "nat_gateway_id": "nat-1"}],
                            },
                        },
                        {
                            "address": "aws_route_table_association.public_edge",
                            "mode": "managed",
                            "type": "aws_route_table_association",
                            "name": "public_edge",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "assoc-public-1",
                                "subnet_id": "subnet-public-1",
                                "route_table_id": "rtb-public-1",
                            },
                        },
                        {
                            "address": "aws_route_table_association.private_app",
                            "mode": "managed",
                            "type": "aws_route_table_association",
                            "name": "private_app",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "assoc-private-app-1",
                                "subnet_id": "subnet-private-app-1",
                                "route_table_id": "rtb-private-1",
                            },
                        },
                        {
                            "address": "aws_route_table_association.private_worker",
                            "mode": "managed",
                            "type": "aws_route_table_association",
                            "name": "private_worker",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "assoc-private-worker-1",
                                "subnet_id": "subnet-private-worker-1",
                                "route_table_id": "rtb-private-1",
                            },
                        },
                        {
                            "address": "aws_security_group.lb",
                            "mode": "managed",
                            "type": "aws_security_group",
                            "name": "lb",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "sg-lb-1",
                                "vpc_id": "vpc-1",
                                "ingress": [
                                    {
                                        "protocol": "tcp",
                                        "from_port": 443,
                                        "to_port": 443,
                                        "cidr_blocks": ["0.0.0.0/0"],
                                    }
                                ],
                                "egress": [
                                    {"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}
                                ],
                            },
                        },
                        {
                            "address": "aws_security_group.app",
                            "mode": "managed",
                            "type": "aws_security_group",
                            "name": "app",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "sg-app-1",
                                "vpc_id": "vpc-1",
                                "ingress": [],
                                "egress": [
                                    {"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}
                                ],
                            },
                        },
                        {
                            "address": "aws_security_group_rule.app_from_lb",
                            "mode": "managed",
                            "type": "aws_security_group_rule",
                            "name": "app_from_lb",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "sgr-app-from-lb",
                                "type": "ingress",
                                "protocol": "tcp",
                                "from_port": 8443,
                                "to_port": 8443,
                                "security_group_id": "sg-app-1",
                                "source_security_group_id": "sg-lb-1",
                            },
                        },
                        {
                            "address": "aws_security_group.worker",
                            "mode": "managed",
                            "type": "aws_security_group",
                            "name": "worker",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "sg-worker-1",
                                "vpc_id": "vpc-1",
                                "ingress": [],
                                "egress": [
                                    {"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}
                                ],
                            },
                        },
                        {
                            "address": "aws_security_group_rule.worker_from_app",
                            "mode": "managed",
                            "type": "aws_security_group_rule",
                            "name": "worker_from_app",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "sgr-worker-from-app",
                                "type": "ingress",
                                "protocol": "tcp",
                                "from_port": 9000,
                                "to_port": 9000,
                                "security_group_id": "sg-worker-1",
                                "source_security_group_id": "sg-app-1",
                            },
                        },
                        {
                            "address": "aws_security_group.db",
                            "mode": "managed",
                            "type": "aws_security_group",
                            "name": "db",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "sg-db-1",
                                "vpc_id": "vpc-1",
                                "ingress": [],
                                "egress": [
                                    {"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}
                                ],
                            },
                        },
                        {
                            "address": "aws_security_group_rule.db_from_worker",
                            "mode": "managed",
                            "type": "aws_security_group_rule",
                            "name": "db_from_worker",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "sgr-db-from-worker",
                                "type": "ingress",
                                "protocol": "tcp",
                                "from_port": 5432,
                                "to_port": 5432,
                                "security_group_id": "sg-db-1",
                                "source_security_group_id": "sg-worker-1",
                            },
                        },
                        {
                            "address": "aws_lb.edge",
                            "mode": "managed",
                            "type": "aws_lb",
                            "name": "edge",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "alb-1",
                                "arn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/edge/123456",
                                "name": "edge",
                                "internal": False,
                                "load_balancer_type": "application",
                                "security_groups": ["sg-lb-1"],
                                "subnets": ["subnet-public-1"],
                            },
                        },
                        {
                            "address": "aws_instance.app",
                            "mode": "managed",
                            "type": "aws_instance",
                            "name": "app",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "i-app-1",
                                "arn": "arn:aws:ec2:us-east-1:111122223333:instance/i-app-1",
                                "subnet_id": "subnet-private-app-1",
                                "vpc_security_group_ids": ["sg-app-1"],
                                "associate_public_ip_address": False,
                            },
                        },
                        {
                            "address": "aws_instance.worker",
                            "mode": "managed",
                            "type": "aws_instance",
                            "name": "worker",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "i-worker-1",
                                "arn": "arn:aws:ec2:us-east-1:111122223333:instance/i-worker-1",
                                "subnet_id": "subnet-private-worker-1",
                                "vpc_security_group_ids": ["sg-worker-1"],
                                "associate_public_ip_address": False,
                            },
                        },
                        {
                            "address": "aws_db_instance.app",
                            "mode": "managed",
                            "type": "aws_db_instance",
                            "name": "app",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "db-1",
                                "identifier": "private-app-db",
                                "arn": "arn:aws:rds:us-east-1:111122223333:db:private-app-db",
                                "engine": "postgres",
                                "publicly_accessible": False,
                                "storage_encrypted": True,
                                "db_subnet_group_name": "private-data",
                                "vpc_security_group_ids": ["sg-db-1"],
                            },
                        },
                    ]
                }
            },
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            plan_path = Path(tmp_dir) / "plan.json"
            plan_path.write_text(json.dumps(payload), encoding="utf-8")
            result = self.engine.analyze_plan(plan_path)

        transitive_finding = next(
            finding
            for finding in result.findings
            if finding.title == "Sensitive data tier is transitively reachable from an internet-exposed path"
        )
        evidence_by_key = {item.key: item.values for item in transitive_finding.evidence}

        self.assertEqual(transitive_finding.severity, Severity.MEDIUM)
        self.assertEqual(
            transitive_finding.affected_resources,
            [
                "aws_lb.edge",
                "aws_instance.app",
                "aws_instance.worker",
                "aws_db_instance.app",
                "aws_security_group.app",
                "aws_security_group.worker",
            ],
        )
        self.assertEqual(
            evidence_by_key["network_path"],
            [
                "internet reaches aws_lb.edge",
                "aws_lb.edge reaches aws_instance.app",
                "aws_instance.app reaches aws_instance.worker",
                "aws_instance.worker reaches aws_db_instance.app",
            ],
        )
        self.assertIn(
            "aws_security_group.app ingress tcp 8443 from sg-lb-1",
            evidence_by_key["security_group_rules"][0],
        )
        self.assertIn(
            "aws_security_group.worker ingress tcp 9000 from sg-app-1",
            evidence_by_key["security_group_rules"][1],
        )
        self.assertEqual(
            evidence_by_key["data_tier_posture"],
            [
                "aws_db_instance.app is not directly public",
                "database has no direct internet ingress path",
            ],
        )
        self.assertIsNotNone(transitive_finding.trust_boundary_id)
        self.assertEqual(
            transitive_finding.trust_boundary_id,
            "workload-to-data-store:aws_instance.worker->aws_db_instance.app",
        )
        self.assertEqual(transitive_finding.severity_reasoning.final_score, 5)

    def test_ecs_service_with_missing_task_definition_and_network_data_degrades_gracefully(self) -> None:
        result = self._analyze_payload(
            {
                "format_version": "1.2",
                "terraform_version": "1.8.5",
                "planned_values": {
                    "root_module": {
                        "resources": [
                            {
                                "address": "aws_ecs_cluster.main",
                                "mode": "managed",
                                "type": "aws_ecs_cluster",
                                "name": "main",
                                "provider_name": "registry.terraform.io/hashicorp/aws",
                                "values": {
                                    "id": "arn:aws:ecs:us-east-1:111122223333:cluster/main",
                                    "arn": "arn:aws:ecs:us-east-1:111122223333:cluster/main",
                                    "name": "main",
                                },
                            },
                            {
                                "address": "aws_ecs_service.app",
                                "mode": "managed",
                                "type": "aws_ecs_service",
                                "name": "app",
                                "provider_name": "registry.terraform.io/hashicorp/aws",
                                "values": {
                                    "id": "arn:aws:ecs:us-east-1:111122223333:service/main/app",
                                    "name": "app",
                                    "cluster": "arn:aws:ecs:us-east-1:111122223333:cluster/main",
                                },
                            },
                        ]
                    }
                },
            }
        )

        ecs_service = result.inventory.get_by_address("aws_ecs_service.app")

        self.assertIsNotNone(ecs_service)
        self.assertEqual(ecs_service.subnet_ids, ())
        self.assertEqual(ecs_service.security_group_ids, ())
        self.assertEqual(ecs_service.attached_role_arns, ())
        self.assertFalse(ecs_service.public_exposure)
        self.assertFalse(ecs_service.metadata.get("fronted_by_internet_facing_load_balancer", False))
        self.assertEqual(result.inventory.unsupported_resources, [])
        self.assertEqual(result.findings, [])
        self.assertEqual(result.trust_boundaries, [])


if __name__ == "__main__":
    unittest.main()
