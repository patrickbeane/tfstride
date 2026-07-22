from __future__ import annotations

import unittest
from collections import Counter
from typing import Any

from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _BUCKET_ARN as AWS_BUCKET_ARN,
)
from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _TASK_ROLE_ARN as AWS_TASK_ROLE_ARN,
)
from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _bucket as aws_bucket,
)
from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _role as aws_role,
)
from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _role_policy_attachment as aws_role_policy_attachment,
)
from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _statement as aws_statement,
)
from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _task_definition as aws_task_definition,
)
from tests.providers.aws.test_aws_public_ecs_s3_mutation_rules import (
    _load_balancer as aws_load_balancer,
)
from tests.providers.aws.test_aws_public_ecs_s3_mutation_rules import (
    _service as aws_service,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _custom_role as azure_custom_role,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _custom_role_assignment as azure_custom_role_assignment,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _role_assignment as azure_role_assignment,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _storage_account as azure_storage_account,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _web_app as azure_web_app,
)
from tests.providers.gcp.test_gcp_cloud_run_gcs_access_paths import (
    _PROJECT as GCP_PROJECT,
)
from tests.providers.gcp.test_gcp_cloud_run_gcs_access_paths import (
    _bucket as gcp_bucket,
)
from tests.providers.gcp.test_gcp_cloud_run_gcs_access_paths import (
    _bucket_iam_member as gcp_bucket_iam_member,
)
from tests.providers.gcp.test_gcp_public_cloud_run_gcs_mutation_rules import (
    _cloud_run as gcp_cloud_run,
)
from tests.providers.gcp.test_gcp_public_cloud_run_gcs_mutation_rules import (
    _public_invoker as gcp_public_invoker,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import Finding, ResourceInventory, StrideCategory, TerraformResource, TrustBoundary
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

AWS_MUTATION_RULE = "aws-public-ecs-s3-mutation-access"
GCP_MUTATION_RULE = "gcp-public-cloud-run-gcs-mutation-access"
AZURE_MUTATION_RULE = "azure-public-app-service-storage-mutation-access"
AWS_BROAD_ACCESS_RULE = "aws-workload-role-sensitive-permissions"
GCP_DISCLOSURE_RULE = "gcp-public-workload-sensitive-data-access"
AZURE_DISCLOSURE_RULE = "azure-public-workload-sensitive-resource-access"

MUTATION_RULE_IDS = frozenset(
    {
        AWS_MUTATION_RULE,
        GCP_MUTATION_RULE,
        AZURE_MUTATION_RULE,
    }
)


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for group in rule_groups for rule_id in group)


def _public_azure_app(*, public: object = True) -> TerraformResource:
    app = azure_web_app()
    app.values["public_network_access_enabled"] = public
    return app


def _aws_resources(
    *,
    actions: str | list[str] = ("s3:PutObject", "s3:DeleteObject"),
    internal: bool = False,
    condition: dict[str, object] | None = None,
) -> list[TerraformResource]:
    return [
        aws_load_balancer(internal=internal),
        aws_bucket(),
        aws_role(
            "orders_task",
            AWS_TASK_ROLE_ARN,
            [
                aws_statement(
                    "Allow",
                    actions,
                    f"{AWS_BUCKET_ARN}/*",
                    condition=condition,
                )
            ],
        ),
        aws_task_definition(execution_role_arn=None),
        aws_service(),
    ]


def _gcp_resources(
    *,
    role: str = "roles/storage.objectUser",
    public: bool = True,
    member: str | None = None,
    condition: dict[str, str] | None = None,
) -> list[TerraformResource]:
    iam_kwargs: dict[str, object] = {"role": role}
    if member is not None:
        iam_kwargs["member"] = member
    if condition is not None:
        iam_kwargs["condition"] = condition
    return [
        gcp_cloud_run(public_ingress=public),
        gcp_public_invoker(),
        gcp_bucket(),
        gcp_bucket_iam_member(**iam_kwargs),
    ]


def _azure_resources(
    *,
    public: object = True,
    role_name: object = "Storage Blob Data Contributor",
    role_definition_id: object = (
        "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/ba92f5b4-2d11-453d-a403-e96b0029c9fe"
    ),
    principal_id: object = "app-system-principal-id",
    scope: object = "azurerm_storage_account.orders.id",
    condition: object | None = None,
) -> list[TerraformResource]:
    return [
        azure_storage_account(),
        _public_azure_app(public=public),
        azure_role_assignment(
            principal_id=principal_id,
            scope=scope,
            role_name=role_name,
            role_definition_id=role_definition_id,
            condition=condition,
        ),
    ]


def _evaluate(
    normalizer: ProviderNormalizer,
    resources: list[Any],
    rule_ids: frozenset[str] = MUTATION_RULE_IDS,
) -> tuple[ResourceInventory, list[TrustBoundary], list[Finding]]:
    inventory = normalizer.normalize(resources)
    boundaries = detect_trust_boundaries(inventory)
    findings = StrideRuleEngine().evaluate(
        inventory,
        boundaries,
        rule_policy=RulePolicy(enabled_rule_ids=rule_ids),
    )
    return inventory, boundaries, findings


def _evidence(finding: Finding) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


class PublicWorkloadObjectStorageMutationPathParityTests(unittest.TestCase):
    def test_provider_local_mutation_rule_families_are_registered(self) -> None:
        self.assertIn(AWS_MUTATION_RULE, _flatten(AWS_RULE_GROUP_IDS))
        self.assertIn(GCP_MUTATION_RULE, _flatten(GCP_RULE_GROUP_IDS))
        self.assertIn(AZURE_MUTATION_RULE, _flatten(AZURE_RULE_GROUP_IDS))

    def test_public_workload_with_exact_mutation_access_emits_only_provider_rule(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(),
                AWS_MUTATION_RULE,
                "s3_mutation_paths",
                "bucket_address=aws_s3_bucket.orders",
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_resources(),
                GCP_MUTATION_RULE,
                "gcs_mutation_paths",
                "bucket_address=google_storage_bucket.orders",
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources(),
                AZURE_MUTATION_RULE,
                "storage_mutation_paths",
                "storage_resource_address=azurerm_storage_account.orders",
            ),
        )

        for provider, normalizer, resources, expected_rule, evidence_key, evidence_fragment in cases:
            with self.subTest(provider=provider):
                _, _, findings = _evaluate(normalizer, resources)

                self.assertEqual([finding.rule_id for finding in findings], [expected_rule])
                self.assertEqual(findings[0].category, StrideCategory.TAMPERING)
                self.assertTrue(all(finding.rule_id.startswith(f"{provider}-") for finding in findings))
                evidence = _evidence(findings[0])
                self.assertTrue(any(evidence_fragment in value for value in evidence[evidence_key]))

    def test_private_workloads_and_read_only_grants_remain_quiet(self) -> None:
        cases = (
            ("aws-private", AwsNormalizer(), _aws_resources(internal=True)),
            ("aws-read-only", AwsNormalizer(), _aws_resources(actions="s3:GetObject")),
            ("gcp-private", GcpNormalizer(), _gcp_resources(public=False)),
            ("gcp-read-only", GcpNormalizer(), _gcp_resources(role="roles/storage.objectViewer")),
            ("azure-private", AzureNormalizer(), _azure_resources(public=False)),
            (
                "azure-read-only",
                AzureNormalizer(),
                _azure_resources(
                    role_name="Storage Blob Data Reader",
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/"
                        "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"
                    ),
                ),
            ),
        )

        for case, normalizer, resources in cases:
            with self.subTest(case=case):
                _, _, findings = _evaluate(normalizer, resources)
                self.assertEqual(findings, [])

    def test_conditional_denied_external_and_unresolved_access_remains_quiet(self) -> None:
        aws_external_policy_arn = "arn:aws:iam::aws:policy/ExternalS3Access"
        gcp_condition = {
            "title": "orders-prefix",
            "expression": "resource.name.startsWith('projects/_/buckets/orders/objects/orders/')",
        }
        azure_condition = (
            "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringEquals 'orders'"
        )
        cases = (
            (
                "aws-denied",
                AwsNormalizer(),
                [
                    aws_load_balancer(),
                    aws_bucket(),
                    aws_role(
                        "orders_task",
                        AWS_TASK_ROLE_ARN,
                        [
                            aws_statement("Allow", "s3:PutObject", f"{AWS_BUCKET_ARN}/*"),
                            aws_statement("Deny", "s3:PutObject", f"{AWS_BUCKET_ARN}/*"),
                        ],
                    ),
                    aws_task_definition(execution_role_arn=None),
                    aws_service(),
                ],
            ),
            (
                "aws-conditional",
                AwsNormalizer(),
                _aws_resources(
                    actions="s3:PutObject",
                    condition={"StringEquals": {"aws:SourceVpc": "vpc-123"}},
                ),
            ),
            (
                "aws-external-policy",
                AwsNormalizer(),
                [
                    *_aws_resources(actions="s3:PutObject"),
                    aws_role_policy_attachment(AWS_TASK_ROLE_ARN, aws_external_policy_arn),
                ],
            ),
            (
                "aws-unresolved-task-definition",
                AwsNormalizer(),
                [
                    aws_load_balancer(),
                    aws_bucket(),
                    aws_role(
                        "orders_task",
                        AWS_TASK_ROLE_ARN,
                        [aws_statement("Allow", "s3:PutObject", f"{AWS_BUCKET_ARN}/*")],
                    ),
                    aws_service("missing:1"),
                ],
            ),
            (
                "gcp-conditional",
                GcpNormalizer(),
                _gcp_resources(role="roles/storage.objectCreator", condition=gcp_condition),
            ),
            (
                "gcp-external-principal",
                GcpNormalizer(),
                _gcp_resources(
                    role="roles/storage.objectCreator",
                    member="serviceAccount:external@partner-project.iam.gserviceaccount.com",
                ),
            ),
            (
                "gcp-unresolved-custom-role",
                GcpNormalizer(),
                _gcp_resources(role=f"projects/{GCP_PROJECT}/roles/externalStorageWriter"),
            ),
            (
                "azure-denied-custom-role",
                AzureNormalizer(),
                [
                    azure_storage_account(),
                    _public_azure_app(),
                    azure_custom_role(
                        data_actions=[
                            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
                        ],
                        not_data_actions=[
                            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
                        ],
                    ),
                    azure_custom_role_assignment(),
                ],
            ),
            (
                "azure-conditional",
                AzureNormalizer(),
                _azure_resources(condition=azure_condition),
            ),
            (
                "azure-external-principal",
                AzureNormalizer(),
                _azure_resources(principal_id="external-principal-id"),
            ),
            (
                "azure-unresolved-storage",
                AzureNormalizer(),
                _azure_resources(scope="azurerm_storage_account.missing.id"),
            ),
        )

        for case, normalizer, resources in cases:
            with self.subTest(case=case):
                _, _, findings = _evaluate(normalizer, resources)
                self.assertEqual(findings, [])

    def test_broad_access_and_disclosure_findings_remain_distinct(self) -> None:
        aws_resources = [
            aws_load_balancer(),
            aws_bucket(),
            aws_role(
                "orders_task",
                AWS_TASK_ROLE_ARN,
                [
                    aws_statement("Allow", "s3:*", AWS_BUCKET_ARN),
                    aws_statement("Allow", "s3:*", f"{AWS_BUCKET_ARN}/*"),
                ],
            ),
            aws_task_definition(execution_role_arn=None),
            aws_service(),
        ]
        cases = (
            (
                "aws",
                AwsNormalizer(),
                aws_resources,
                AWS_MUTATION_RULE,
                AWS_BROAD_ACCESS_RULE,
                "s3_mutation_paths",
                "iam_actions",
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_resources(role="roles/storage.objectUser"),
                GCP_MUTATION_RULE,
                GCP_DISCLOSURE_RULE,
                "gcs_mutation_paths",
                "data_access_path",
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources(),
                AZURE_MUTATION_RULE,
                AZURE_DISCLOSURE_RULE,
                "storage_mutation_paths",
                "sensitive_resource_assignments",
            ),
        )

        for provider, normalizer, resources, mutation_rule, related_rule, mutation_key, related_key in cases:
            with self.subTest(provider=provider):
                _, _, findings = _evaluate(
                    normalizer,
                    resources,
                    frozenset({mutation_rule, related_rule}),
                )

                self.assertEqual(
                    Counter(finding.rule_id for finding in findings),
                    Counter({mutation_rule: 1, related_rule: 1}),
                )
                findings_by_rule = {finding.rule_id: finding for finding in findings}
                mutation_finding = findings_by_rule[mutation_rule]
                related_finding = findings_by_rule[related_rule]
                mutation_evidence = _evidence(mutation_finding)
                related_evidence = _evidence(related_finding)
                self.assertEqual(mutation_finding.category, StrideCategory.TAMPERING)
                self.assertIn(mutation_key, mutation_evidence)
                self.assertNotIn(mutation_key, related_evidence)
                self.assertIn(related_key, related_evidence)
                self.assertNotIn(related_key, mutation_evidence)
                self.assertNotEqual(mutation_finding.rationale, related_finding.rationale)


if __name__ == "__main__":
    unittest.main()
