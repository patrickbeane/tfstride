from __future__ import annotations

import unittest

from tests.integration.analysis_support import ECS_FARGATE_FIXTURE_PATH
from tests.providers.azure.test_azure_app_service_key_vault_access_paths import (
    _role_assignment as _azure_key_vault_role_assignment,
)
from tests.providers.azure.test_azure_app_service_key_vault_access_paths import (
    _secret as _azure_key_vault_secret,
)
from tests.providers.azure.test_azure_app_service_key_vault_access_paths import (
    _vault as _azure_key_vault,
)
from tests.providers.azure.test_azure_app_service_key_vault_access_paths import (
    _web_app as _azure_web_app,
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
                _cloud_run_service(secret_reference="projects/tfstride-demo/secrets/tfstride-api-key"),
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
            evidence["cloud_run_secret_access_paths"],
            [
                "secret_resource=google_secret_manager_secret.api_key; "
                "secret_reference=projects/tfstride-demo/secrets/tfstride-api-key; "
                "secret_version=5; service_account=tfstride-run@tfstride-demo.iam.gserviceaccount.com; "
                "iam_resource=google_secret_manager_secret_iam_member.public_accessor; "
                "role=roles/secretmanager.secretAccessor; "
                "grant_scope=secret:projects/tfstride-demo/secrets/tfstride-api-key; "
                "access_state=granted; condition_state=not_configured"
            ],
        )

    def test_azure_app_service_public_access_secret_assignment_evidence_is_pinned(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _azure_key_vault(rbac_enabled=True),
                _azure_key_vault_secret(),
                _azure_web_app(public_network_access_enabled=True),
                _azure_key_vault_role_assignment(role_name="Key Vault Secrets User"),
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
                "azurerm_linux_web_app.api",
                "azurerm_role_assignment.secret_access",
                "azurerm_key_vault.orders",
                "azurerm_key_vault_secret.database_password",
            ],
        )
        self.assertIsNone(finding.trust_boundary_id)
        evidence = _evidence(finding)
        self.assertEqual(
            evidence["public_workloads"],
            ["address=azurerm_linux_web_app.api; public_network_access_enabled=true"],
        )
        self.assertIn("identity_kind=system_assigned", evidence["app_service_key_vault_access_paths"][0])
        self.assertIn("vault=azurerm_key_vault.orders", evidence["app_service_key_vault_access_paths"][0])
        self.assertIn(
            "secret=azurerm_key_vault_secret.database_password",
            evidence["app_service_key_vault_access_paths"][0],
        )
        self.assertIn("role=Key Vault Secrets User", evidence["app_service_key_vault_access_paths"][0])
