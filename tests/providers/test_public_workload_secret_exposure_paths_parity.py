from __future__ import annotations

import unittest
from collections import Counter
from typing import Any

from tests.providers.aws.test_aws_ecs_secret_access_paths import (
    _ACCOUNT_ID as AWS_ACCOUNT_ID,
)
from tests.providers.aws.test_aws_ecs_secret_access_paths import (
    _EXECUTION_ROLE_ARN as AWS_EXECUTION_ROLE_ARN,
)
from tests.providers.aws.test_aws_ecs_secret_access_paths import (
    _SECRET_ARN as AWS_SECRET_ARN,
)
from tests.providers.aws.test_aws_ecs_secret_access_paths import (
    _role as aws_role,
)
from tests.providers.aws.test_aws_ecs_secret_access_paths import (
    _role_policy_attachment as aws_role_policy_attachment,
)
from tests.providers.aws.test_aws_ecs_secret_access_paths import (
    _statement as aws_statement,
)
from tests.providers.aws.test_aws_ecs_secret_access_paths import (
    _task_definition as aws_task_definition,
)
from tests.providers.aws.test_aws_public_ecs_secret_access_rules import (
    _load_balancer as aws_load_balancer,
)
from tests.providers.aws.test_aws_public_ecs_secret_access_rules import (
    _secret as aws_secret,
)
from tests.providers.aws.test_aws_public_ecs_secret_access_rules import (
    _service as aws_service,
)
from tests.providers.azure.test_azure_app_service_key_vault_access_paths import (
    _custom_role as azure_custom_role,
)
from tests.providers.azure.test_azure_app_service_key_vault_access_paths import (
    _role_assignment as azure_role_assignment,
)
from tests.providers.azure.test_azure_app_service_key_vault_access_paths import (
    _secret as azure_secret,
)
from tests.providers.azure.test_azure_app_service_key_vault_access_paths import (
    _vault as azure_vault,
)
from tests.providers.azure.test_azure_app_service_key_vault_access_paths import (
    _web_app as azure_web_app,
)
from tests.providers.gcp.rule_support.data import (
    _secret_manager_secret as gcp_secret,
)
from tests.providers.gcp.rule_support.serverless import (
    _cloud_run_service as gcp_cloud_run,
)
from tests.providers.gcp.rule_support.serverless import (
    _cloud_run_service_iam_member as gcp_public_invoker,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import AnalysisResult, Finding, ResourceInventory, TerraformResource, TrustBoundary
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS
from tfstride.reporting.json_report import render_json

AWS_PUBLIC_RULE = "aws-public-ecs-secret-access"
GCP_PUBLIC_RULE = "gcp-public-workload-sensitive-data-access"
AZURE_PUBLIC_RULE = "azure-public-workload-sensitive-resource-access"
AWS_BROAD_RULE = "aws-ecs-secret-access-blast-radius"
GCP_BROAD_RULE = "gcp-cloud-run-secret-access-blast-radius"
AZURE_BROAD_RULE = "azure-managed-identity-broad-rbac"

PUBLIC_RULE_IDS = frozenset({AWS_PUBLIC_RULE, GCP_PUBLIC_RULE, AZURE_PUBLIC_RULE})
_GCP_SERVICE_ACCOUNT_EMAIL = "tfstride-run@tfstride-demo.iam.gserviceaccount.com"
_GCP_SERVICE_ACCOUNT_MEMBER = f"serviceAccount:{_GCP_SERVICE_ACCOUNT_EMAIL}"
_GCP_SECRET_NAME = "projects/tfstride-demo/secrets/tfstride-api-key"


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for group in rule_groups for rule_id in group)


def _gcp_secret_iam_member(
    *,
    member: str = _GCP_SERVICE_ACCOUNT_MEMBER,
    condition: dict[str, object] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address="google_secret_manager_secret_iam_member.runtime_accessor",
        mode="managed",
        resource_type="google_secret_manager_secret_iam_member",
        name="runtime_accessor",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "secret_id": "google_secret_manager_secret.api_key.id",
            "role": "roles/secretmanager.secretAccessor",
            "member": member,
            **({"condition": [condition]} if condition else {}),
        },
    )


def _gcp_project_iam_member() -> TerraformResource:
    return TerraformResource(
        address="google_project_iam_member.secret_accessor",
        mode="managed",
        resource_type="google_project_iam_member",
        name="secret_accessor",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "project": "tfstride-demo",
            "role": "roles/secretmanager.secretAccessor",
            "member": _GCP_SERVICE_ACCOUNT_MEMBER,
        },
    )


def _aws_public_resources(*, internal: bool = False) -> list[TerraformResource]:
    return [
        aws_load_balancer(internal=internal),
        aws_secret(),
        aws_role(
            "execution",
            AWS_EXECUTION_ROLE_ARN,
            [aws_statement("Allow", "secretsmanager:GetSecretValue", AWS_SECRET_ARN)],
        ),
        aws_task_definition(task_role_arn=None),
        aws_service(),
    ]


def _gcp_public_resources(*, public: bool = True) -> list[TerraformResource]:
    return [
        gcp_cloud_run(public_ingress=public, secret_reference=_GCP_SECRET_NAME),
        gcp_public_invoker(),
        gcp_secret(),
        _gcp_secret_iam_member(),
    ]


def _azure_public_resources(*, public: bool = True) -> list[TerraformResource]:
    return [
        azure_vault(rbac_enabled=True),
        azure_secret(),
        azure_web_app(public_network_access_enabled=public),
        azure_role_assignment(role_name="Key Vault Secrets User"),
    ]


def _evaluate(
    normalizer: ProviderNormalizer,
    resources: list[Any],
    rule_ids: frozenset[str] = PUBLIC_RULE_IDS,
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


def _report_payload(
    inventory: ResourceInventory,
    boundaries: list[TrustBoundary],
    findings: list[Finding],
) -> str:
    return render_json(
        AnalysisResult(
            title="Public workload secret exposure path parity",
            analyzed_file="synthetic-plan.json",
            analyzed_path="synthetic-plan.json",
            inventory=inventory,
            trust_boundaries=boundaries,
            findings=findings,
        )
    )


class PublicWorkloadSecretExposurePathParityTests(unittest.TestCase):
    def test_public_secret_path_rule_families_are_registered(self) -> None:
        self.assertIn(AWS_PUBLIC_RULE, _flatten(AWS_RULE_GROUP_IDS))
        self.assertIn(GCP_PUBLIC_RULE, _flatten(GCP_RULE_GROUP_IDS))
        self.assertIn(AZURE_PUBLIC_RULE, _flatten(AZURE_RULE_GROUP_IDS))

    def test_public_workload_with_deterministic_secret_access_emits_provider_local_finding(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_public_resources(),
                AWS_PUBLIC_RULE,
                {
                    "network_path": "aws_lb.public fronts aws_ecs_service.orders",
                    "execution_roles": "address=aws_iam_role.execution",
                    "secret_access_paths": f"secret_arn={AWS_SECRET_ARN}",
                },
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_public_resources(),
                GCP_PUBLIC_RULE,
                {
                    "workload_identity": _GCP_SERVICE_ACCOUNT_MEMBER,
                    "cloud_run_secret_access_paths": ("secret_resource=google_secret_manager_secret.api_key"),
                },
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_public_resources(),
                AZURE_PUBLIC_RULE,
                {
                    "public_workloads": "address=azurerm_linux_web_app.api",
                    "app_service_key_vault_access_paths": ("identity=azurerm_linux_web_app.api"),
                },
            ),
        )

        for provider, normalizer, resources, expected_rule, evidence_fragments in cases:
            with self.subTest(provider=provider):
                _, _, findings = _evaluate(normalizer, resources)

                self.assertEqual([finding.rule_id for finding in findings], [expected_rule])
                self.assertTrue(all(finding.rule_id.startswith(f"{provider}-") for finding in findings))
                evidence = _evidence(findings[0])
                for key, fragment in evidence_fragments.items():
                    self.assertIn(key, evidence)
                    self.assertTrue(
                        any(fragment in value for value in evidence[key]),
                        f"{fragment!r} missing from {key}: {evidence[key]!r}",
                    )

    def test_private_workloads_with_deterministic_secret_access_remain_quiet(self) -> None:
        cases = (
            ("aws", AwsNormalizer(), _aws_public_resources(internal=True)),
            ("gcp", GcpNormalizer(), _gcp_public_resources(public=False)),
            ("azure", AzureNormalizer(), _azure_public_resources(public=False)),
        )

        for provider, normalizer, resources in cases:
            with self.subTest(provider=provider):
                _, _, findings = _evaluate(normalizer, resources)
                self.assertEqual(findings, [])

    def test_denied_conditional_unresolved_and_external_paths_remain_quiet(self) -> None:
        condition = {
            "title": "runtime-window",
            "expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
        }
        external_policy_arn = "arn:aws:iam::aws:policy/ExternalSecretAccess"
        cases = (
            (
                "aws-denied",
                AwsNormalizer(),
                [
                    aws_load_balancer(),
                    aws_role(
                        "execution",
                        AWS_EXECUTION_ROLE_ARN,
                        [
                            aws_statement("Allow", "secretsmanager:GetSecretValue", AWS_SECRET_ARN),
                            aws_statement("Deny", "secretsmanager:GetSecretValue", AWS_SECRET_ARN),
                        ],
                    ),
                    aws_task_definition(task_role_arn=None),
                    aws_service(),
                ],
            ),
            (
                "aws-conditional",
                AwsNormalizer(),
                [
                    aws_load_balancer(),
                    aws_role(
                        "execution",
                        AWS_EXECUTION_ROLE_ARN,
                        [
                            aws_statement(
                                "Allow",
                                "secretsmanager:GetSecretValue",
                                AWS_SECRET_ARN,
                                condition={"StringEquals": {"aws:PrincipalAccount": AWS_ACCOUNT_ID}},
                            )
                        ],
                    ),
                    aws_task_definition(task_role_arn=None),
                    aws_service(),
                ],
            ),
            (
                "aws-external-policy",
                AwsNormalizer(),
                [
                    aws_load_balancer(),
                    aws_role(
                        "execution",
                        AWS_EXECUTION_ROLE_ARN,
                        [aws_statement("Allow", "secretsmanager:GetSecretValue", AWS_SECRET_ARN)],
                    ),
                    aws_role_policy_attachment(AWS_EXECUTION_ROLE_ARN, external_policy_arn),
                    aws_task_definition(task_role_arn=None),
                    aws_service(),
                ],
            ),
            (
                "aws-unresolved-role",
                AwsNormalizer(),
                [aws_load_balancer(), aws_task_definition(task_role_arn=None), aws_service()],
            ),
            (
                "gcp-conditional",
                GcpNormalizer(),
                [
                    gcp_cloud_run(secret_reference=_GCP_SECRET_NAME),
                    gcp_public_invoker(),
                    gcp_secret(),
                    _gcp_secret_iam_member(condition=condition),
                ],
            ),
            (
                "gcp-external-principal",
                GcpNormalizer(),
                [
                    gcp_cloud_run(secret_reference=_GCP_SECRET_NAME),
                    gcp_public_invoker(),
                    gcp_secret(),
                    _gcp_secret_iam_member(member="serviceAccount:external@partner-project.iam.gserviceaccount.com"),
                ],
            ),
            (
                "gcp-unresolved-secret",
                GcpNormalizer(),
                [
                    gcp_cloud_run(secret_reference="${google_secret_manager_secret.runtime.id}"),
                    gcp_public_invoker(),
                    gcp_secret(),
                    _gcp_secret_iam_member(),
                ],
            ),
            (
                "azure-denied-custom-role",
                AzureNormalizer(),
                [
                    azure_vault(rbac_enabled=True),
                    azure_secret(),
                    azure_web_app(public_network_access_enabled=True),
                    azure_custom_role(not_data_actions=["Microsoft.KeyVault/vaults/secrets/getSecret/action"]),
                    azure_role_assignment(
                        role_name=None,
                        role_definition_id=("azurerm_role_definition.secret_reader.role_definition_resource_id"),
                    ),
                ],
            ),
            (
                "azure-conditional",
                AzureNormalizer(),
                [
                    azure_vault(rbac_enabled=True),
                    azure_secret(),
                    azure_web_app(public_network_access_enabled=True),
                    azure_role_assignment(
                        role_name="Key Vault Secrets User",
                        condition=("@Resource[Microsoft.KeyVault/vaults].name StringEquals 'orders'"),
                    ),
                ],
            ),
            (
                "azure-external-principal",
                AzureNormalizer(),
                [
                    azure_vault(rbac_enabled=True),
                    azure_secret(),
                    azure_web_app(public_network_access_enabled=True),
                    azure_role_assignment(
                        principal_id="external-principal-id",
                        role_name="Key Vault Secrets User",
                    ),
                ],
            ),
            (
                "azure-unresolved-secret",
                AzureNormalizer(),
                [
                    azure_vault(rbac_enabled=True),
                    azure_web_app(
                        public_network_access_enabled=True,
                        secret_uri="https://external.vault.azure.net/secrets/database-password",
                    ),
                    azure_role_assignment(role_name="Key Vault Secrets User"),
                ],
            ),
        )

        for case, normalizer, resources in cases:
            with self.subTest(case=case):
                _, _, findings = _evaluate(normalizer, resources)
                self.assertEqual(findings, [])

    def test_secret_values_never_enter_public_path_evidence_or_reports(self) -> None:
        aws_sentinel = "aws-public-path-secret-value"
        aws_resources = _aws_public_resources()
        aws_resources[1].values["secret_string"] = aws_sentinel

        gcp_sentinel = "gcp-public-path-secret-value"
        gcp_resources = _gcp_public_resources()
        gcp_resources[2].values["secret_data"] = gcp_sentinel

        azure_sentinel = "azure-public-path-secret-value"
        azure_resources = _azure_public_resources()
        azure_resources[1].values["value"] = azure_sentinel

        cases = (
            (AwsNormalizer(), aws_resources, aws_sentinel),
            (GcpNormalizer(), gcp_resources, gcp_sentinel),
            (AzureNormalizer(), azure_resources, azure_sentinel),
        )

        for normalizer, resources, sentinel in cases:
            with self.subTest(provider=normalizer.provider):
                inventory, boundaries, findings = _evaluate(normalizer, resources)

                self.assertEqual(len(findings), 1)
                self.assertNotIn(sentinel, repr(findings))
                self.assertNotIn(sentinel, _report_payload(inventory, boundaries, findings))

    def test_broad_access_and_public_path_findings_remain_distinct(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                [
                    aws_load_balancer(),
                    aws_secret(),
                    aws_role(
                        "execution",
                        AWS_EXECUTION_ROLE_ARN,
                        [aws_statement("Allow", "secretsmanager:GetSecretValue", "*")],
                    ),
                    aws_task_definition(task_role_arn=None),
                    aws_service(),
                ],
                AWS_PUBLIC_RULE,
                AWS_BROAD_RULE,
                "network_path",
                "broader_policy_grants",
            ),
            (
                "gcp",
                GcpNormalizer(),
                [
                    gcp_cloud_run(secret_reference=_GCP_SECRET_NAME),
                    gcp_public_invoker(),
                    gcp_secret(),
                    _gcp_project_iam_member(),
                ],
                GCP_PUBLIC_RULE,
                GCP_BROAD_RULE,
                "public_exposure_reasons",
                "broad_secret_access_grant",
            ),
            (
                "azure",
                AzureNormalizer(),
                [
                    azure_vault(rbac_enabled=True),
                    azure_secret(),
                    azure_web_app(public_network_access_enabled=True),
                    azure_role_assignment(
                        role_name="Key Vault Administrator",
                        scope="/subscriptions/sub-0001/resourceGroups/app",
                    ),
                ],
                AZURE_PUBLIC_RULE,
                AZURE_BROAD_RULE,
                "public_workloads",
                "breadth_signals",
            ),
        )

        for (
            provider,
            normalizer,
            resources,
            public_rule,
            broad_rule,
            public_focus,
            broad_focus,
        ) in cases:
            with self.subTest(provider=provider):
                _, _, findings = _evaluate(
                    normalizer,
                    resources,
                    frozenset({public_rule, broad_rule}),
                )

                self.assertEqual(
                    Counter(finding.rule_id for finding in findings), Counter({public_rule: 1, broad_rule: 1})
                )
                findings_by_rule = {finding.rule_id: finding for finding in findings}
                public_finding = findings_by_rule[public_rule]
                broad_finding = findings_by_rule[broad_rule]
                public_evidence = _evidence(public_finding)
                broad_evidence = _evidence(broad_finding)
                self.assertIn(public_focus, public_evidence)
                self.assertNotIn(public_focus, broad_evidence)
                self.assertIn(broad_focus, broad_evidence)
                self.assertNotIn(broad_focus, public_evidence)
                self.assertNotEqual(public_finding.rationale, broad_finding.rationale)


if __name__ == "__main__":
    unittest.main()
