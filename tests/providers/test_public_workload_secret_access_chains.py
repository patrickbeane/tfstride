from __future__ import annotations

import unittest

from tests.integration.analysis_support import ECS_FARGATE_FIXTURE_PATH
from tests.providers.azure.test_azure_managed_identity_rules import (
    _app_service,
    _role_assignment,
    _storage_account,
    _system_assigned_app_identity,
)
from tests.providers.gcp.rule_support.data import (
    _secret_manager_secret,
    _secret_manager_secret_iam_member,
)
from tests.providers.gcp.rule_support.serverless import (
    _cloud_run_service,
    _cloud_run_service_iam_member,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.app import TfStride
from tfstride.models import Finding
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.gcp.normalizer import GcpNormalizer


def _evidence(finding: Finding) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


class PublicWorkloadSecretAccessChainCharacterizationTests(unittest.TestCase):
    def test_aws_ecs_exposure_and_secret_access_remain_separate_path_segments(self) -> None:
        result = TfStride().analyze_plan(ECS_FARGATE_FIXTURE_PATH)
        load_balancer = result.inventory.get_by_address("aws_lb.web")
        service = result.inventory.get_by_address("aws_ecs_service.app")
        assert load_balancer is not None
        assert service is not None

        self.assertTrue(load_balancer.public_exposure)
        self.assertFalse(service.public_exposure)
        self.assertTrue(service.metadata["fronted_by_internet_facing_load_balancer"])
        self.assertEqual(
            service.metadata["internet_facing_load_balancer_addresses"],
            ["aws_lb.web"],
        )

        boundaries = {boundary.identifier: boundary for boundary in result.trust_boundaries}
        self.assertIn("internet-to-service:internet->aws_lb.web", boundaries)
        secret_boundary_id = "workload-to-data-store:aws_ecs_service.app->aws_secretsmanager_secret.app"
        self.assertIn(secret_boundary_id, boundaries)

        finding = next(
            finding
            for finding in result.findings
            if finding.rule_id == "aws-private-data-transitive-exposure"
            and "aws_secretsmanager_secret.app" in finding.affected_resources
        )
        self.assertEqual(
            finding.affected_resources,
            [
                "aws_lb.web",
                "aws_ecs_service.app",
                "aws_secretsmanager_secret.app",
                "aws_security_group.ecs",
            ],
        )
        self.assertEqual(finding.trust_boundary_id, secret_boundary_id)
        evidence = _evidence(finding)
        self.assertEqual(
            evidence["network_path"],
            [
                "internet reaches aws_lb.web",
                "aws_lb.web reaches aws_ecs_service.app",
                "aws_ecs_service.app reaches aws_secretsmanager_secret.app",
            ],
        )
        self.assertIn("secretsmanager:GetSecretValue", evidence["boundary_rationale"][0])

    def test_gcp_cloud_run_public_invoker_secret_access_evidence_is_pinned(self) -> None:
        service_account = "serviceAccount:tfstride-run@tfstride-demo.iam.gserviceaccount.com"
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run_service(),
                _cloud_run_service_iam_member(),
                _secret_manager_secret(),
                _secret_manager_secret_iam_member(member=service_account),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)
        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-public-workload-sensitive-data-access"})),
        )

        self.assertEqual([finding.rule_id for finding in findings], ["gcp-public-workload-sensitive-data-access"])
        finding = findings[0]
        self.assertEqual(
            finding.affected_resources,
            [
                "google_cloud_run_v2_service.api",
                "google_secret_manager_secret.api_key",
                "google_secret_manager_secret_iam_member.public_accessor",
            ],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            "workload-to-data-store:google_cloud_run_v2_service.api->google_secret_manager_secret.api_key",
        )
        evidence = _evidence(finding)
        self.assertEqual(
            evidence["public_exposure_reasons"],
            ["google_cloud_run_v2_service_iam_member.public_invoker grants roles/run.invoker to allUsers"],
        )
        self.assertEqual(evidence["workload_identity"], [service_account])
        self.assertEqual(
            evidence["data_access_path"],
            ["google_cloud_run_v2_service.api reaches google_secret_manager_secret.api_key"],
        )

    def test_azure_app_service_public_access_secret_assignment_evidence_is_pinned(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _storage_account(),
                _app_service(identity=_system_assigned_app_identity()),
                _role_assignment(
                    role_definition_name="Storage Blob Data Owner",
                    scope="azurerm_storage_account.logs.id",
                ),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)
        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"azure-public-workload-sensitive-resource-access"})),
        )

        self.assertEqual(boundaries, [])
        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["azure-public-workload-sensitive-resource-access"],
        )
        finding = findings[0]
        self.assertEqual(
            finding.affected_resources,
            [
                "azurerm_linux_web_app.app",
                "azurerm_role_assignment.assignment",
                "azurerm_storage_account.logs",
            ],
        )
        self.assertIsNone(finding.trust_boundary_id)
        evidence = _evidence(finding)
        self.assertEqual(
            evidence["public_workloads"],
            ["address=azurerm_linux_web_app.app; public_network_access_enabled=true"],
        )
        self.assertIn("identity_type=SystemAssigned", evidence["managed_identity"])
        self.assertIn(
            "target=azurerm_storage_account.logs",
            evidence["sensitive_resource_assignments"][0],
        )
