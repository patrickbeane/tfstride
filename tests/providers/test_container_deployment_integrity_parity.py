from __future__ import annotations

import unittest
from collections import Counter

from tests.providers.aws.test_aws_container_rules import _ecr_repository, _ecs_task_definition
from tests.providers.azure.test_azure_container_image_rules import _web_app
from tests.providers.gcp.test_gcp_container_rules import _artifact_registry_repository, _cloud_run_service
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import Finding, TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

AWS_IMAGE_PIN_RULE = "aws-workload-image-not-digest-pinned"
AWS_MUTABLE_REGISTRY_RULE = "aws-workload-ecr-mutable-tag"
GCP_IMAGE_PIN_RULE = "gcp-cloud-run-image-not-digest-pinned"
GCP_MUTABLE_REGISTRY_RULE = "gcp-cloud-run-artifact-registry-mutable-tag"
AZURE_IMAGE_PIN_RULE = "azure-app-service-image-not-digest-pinned"

AWS_CONTAINER_DEPLOYMENT_RULE_IDS = frozenset({AWS_IMAGE_PIN_RULE, AWS_MUTABLE_REGISTRY_RULE})
GCP_CONTAINER_DEPLOYMENT_RULE_IDS = frozenset({GCP_IMAGE_PIN_RULE, GCP_MUTABLE_REGISTRY_RULE})
AZURE_CONTAINER_DEPLOYMENT_RULE_IDS = frozenset({AZURE_IMAGE_PIN_RULE})
ALL_CONTAINER_DEPLOYMENT_RULE_IDS = (
    AWS_CONTAINER_DEPLOYMENT_RULE_IDS | GCP_CONTAINER_DEPLOYMENT_RULE_IDS | AZURE_CONTAINER_DEPLOYMENT_RULE_IDS
)

_AWS_ECR_URL = "111122223333.dkr.ecr.us-east-1.amazonaws.com/orders"
_GCP_IMAGE = "us-central1-docker.pkg.dev/tfstride-demo/images/api"
_DIGEST = "sha256:" + "a" * 64


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for rule_group in rule_groups for rule_id in rule_group)


def _evaluate(
    normalizer: ProviderNormalizer,
    resources: list[TerraformResource],
    rule_ids: frozenset[str] = ALL_CONTAINER_DEPLOYMENT_RULE_IDS,
) -> list[Finding]:
    inventory = normalizer.normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=rule_ids),
    )


def _rule_counts(findings: list[Finding]) -> Counter[str]:
    return Counter(finding.rule_id for finding in findings)


class ContainerDeploymentIntegrityParityTests(unittest.TestCase):
    def test_container_deployment_integrity_rule_families_are_registered(self) -> None:
        self.assertLessEqual(AWS_CONTAINER_DEPLOYMENT_RULE_IDS, _flatten(AWS_RULE_GROUP_IDS))
        self.assertLessEqual(GCP_CONTAINER_DEPLOYMENT_RULE_IDS, _flatten(GCP_RULE_GROUP_IDS))
        self.assertLessEqual(AZURE_CONTAINER_DEPLOYMENT_RULE_IDS, _flatten(AZURE_RULE_GROUP_IDS))

    def test_digest_pinning_and_provider_specific_registry_mutability_are_pinned(self) -> None:
        aws_findings = _evaluate(
            AwsNormalizer(),
            [_ecs_task_definition(f"{_AWS_ECR_URL}:stable"), _ecr_repository()],
        )
        gcp_findings = _evaluate(
            GcpNormalizer(),
            [_cloud_run_service(f"{_GCP_IMAGE}:stable"), _artifact_registry_repository()],
        )
        azure_findings = _evaluate(
            AzureNormalizer(),
            [_web_app("team/api:stable")],
        )

        self.assertEqual(
            _rule_counts(aws_findings),
            Counter({AWS_IMAGE_PIN_RULE: 1, AWS_MUTABLE_REGISTRY_RULE: 1}),
        )
        self.assertEqual(
            _rule_counts(gcp_findings),
            Counter({GCP_IMAGE_PIN_RULE: 1, GCP_MUTABLE_REGISTRY_RULE: 1}),
        )
        self.assertEqual(_rule_counts(azure_findings), Counter({AZURE_IMAGE_PIN_RULE: 1}))

    def test_digest_pinned_references_are_quiet_across_providers(self) -> None:
        self.assertEqual(
            _evaluate(
                AwsNormalizer(),
                [_ecs_task_definition(f"{_AWS_ECR_URL}@{_DIGEST}"), _ecr_repository()],
            ),
            [],
        )
        self.assertEqual(
            _evaluate(
                GcpNormalizer(),
                [_cloud_run_service(f"{_GCP_IMAGE}@{_DIGEST}"), _artifact_registry_repository()],
            ),
            [],
        )
        self.assertEqual(
            _evaluate(AzureNormalizer(), [_web_app(f"team/api@{_DIGEST}")]),
            [],
        )

    def test_unknown_image_references_do_not_become_integrity_or_mutability_claims(self) -> None:
        aws_findings = _evaluate(
            AwsNormalizer(),
            [
                _ecs_task_definition(None, unknown_values={"container_definitions": True}),
                _ecr_repository(),
            ],
        )
        gcp_findings = _evaluate(
            GcpNormalizer(),
            [
                _cloud_run_service(None, unknown_values={"template": True}),
                _artifact_registry_repository(),
            ],
        )
        azure_findings = _evaluate(
            AzureNormalizer(),
            [
                _web_app(
                    None,
                    unknown_values={
                        "site_config": [
                            {
                                "application_stack": [
                                    {"docker_image_name": True},
                                ]
                            }
                        ]
                    },
                )
            ],
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_findings, [])
        self.assertEqual(azure_findings, [])

    def test_container_deployment_findings_do_not_leak_across_provider_inventories(self) -> None:
        aws_findings = _evaluate(
            AwsNormalizer(),
            [_ecs_task_definition(f"{_AWS_ECR_URL}:stable"), _ecr_repository()],
        )
        gcp_findings = _evaluate(
            GcpNormalizer(),
            [_cloud_run_service(f"{_GCP_IMAGE}:stable"), _artifact_registry_repository()],
        )
        azure_findings = _evaluate(AzureNormalizer(), [_web_app("team/api:stable")])

        self.assertTrue(all(finding.rule_id.startswith("aws-") for finding in aws_findings))
        self.assertTrue(all(finding.rule_id.startswith("gcp-") for finding in gcp_findings))
        self.assertTrue(all(finding.rule_id.startswith("azure-") for finding in azure_findings))
        self.assertLessEqual(set(_rule_counts(aws_findings)), AWS_CONTAINER_DEPLOYMENT_RULE_IDS)
        self.assertLessEqual(set(_rule_counts(gcp_findings)), GCP_CONTAINER_DEPLOYMENT_RULE_IDS)
        self.assertLessEqual(set(_rule_counts(azure_findings)), AZURE_CONTAINER_DEPLOYMENT_RULE_IDS)


if __name__ == "__main__":
    unittest.main()
