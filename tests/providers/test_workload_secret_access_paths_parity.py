from __future__ import annotations

import unittest
from collections import Counter
from typing import Any

from tests.providers.aws.test_aws_ecs_secret_access_rules import (
    _ACCOUNT_ID as AWS_ACCOUNT_ID,
)
from tests.providers.aws.test_aws_ecs_secret_access_rules import (
    _EXECUTION_ROLE_ARN as AWS_EXECUTION_ROLE_ARN,
)
from tests.providers.aws.test_aws_ecs_secret_access_rules import (
    _SECRET_ARN as AWS_SECRET_ARN,
)
from tests.providers.aws.test_aws_ecs_secret_access_rules import (
    _role as aws_role,
)
from tests.providers.aws.test_aws_ecs_secret_access_rules import (
    _role_policy_attachment as aws_role_policy_attachment,
)
from tests.providers.aws.test_aws_ecs_secret_access_rules import (
    _statement as aws_statement,
)
from tests.providers.aws.test_aws_ecs_secret_access_rules import (
    _task_definition as aws_task_definition,
)
from tests.providers.azure.test_azure_app_service_key_vault_access_paths import (
    _SYSTEM_PRINCIPAL_ID as AZURE_SYSTEM_PRINCIPAL_ID,
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
from tests.providers.gcp.test_gcp_cloud_run_secret_access_rules import (
    _SERVICE_ACCOUNT_EMAIL as GCP_SERVICE_ACCOUNT_EMAIL,
)
from tests.providers.gcp.test_gcp_cloud_run_secret_access_rules import (
    _cloud_run as gcp_cloud_run,
)
from tests.providers.gcp.test_gcp_cloud_run_secret_access_rules import (
    _project_iam_member as gcp_project_iam_member,
)
from tests.providers.gcp.test_gcp_cloud_run_secret_access_rules import (
    _secret as gcp_secret,
)
from tests.providers.gcp.test_gcp_cloud_run_secret_access_rules import (
    _secret_iam_member as gcp_secret_iam_member,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import AnalysisResult, Finding, ResourceInventory, TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS
from tfstride.reporting.json_report import render_json

AWS_ACCESS_RULE = "aws-ecs-secret-access-blast-radius"
GCP_ACCESS_RULE = "gcp-cloud-run-secret-access-blast-radius"
AZURE_REFERENCE_IDENTITY_RULE = "azure-app-service-key-vault-reference-identity-not-configured"
AZURE_OVERPRIVILEGED_RULE = "azure-app-service-key-vault-secret-access-overprivileged"
AZURE_BROAD_IDENTITY_RULE = "azure-managed-identity-broad-rbac"

ALL_ACCESS_RULE_IDS = frozenset(
    {
        AWS_ACCESS_RULE,
        GCP_ACCESS_RULE,
        AZURE_REFERENCE_IDENTITY_RULE,
        AZURE_OVERPRIVILEGED_RULE,
        AZURE_BROAD_IDENTITY_RULE,
    }
)

_AWS_WORKLOAD_ADDRESS = "aws_ecs_task_definition.orders"
_GCP_WORKLOAD_ADDRESS = "google_cloud_run_v2_service.api"
_AZURE_WORKLOAD_ADDRESS = "azurerm_linux_web_app.api"


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for group in rule_groups for rule_id in group)


def _normalize_and_evaluate(
    normalizer: ProviderNormalizer,
    resources: list[Any],
) -> tuple[ResourceInventory, list[Finding]]:
    inventory = normalizer.normalize(resources)
    findings = StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=ALL_ACCESS_RULE_IDS),
    )
    return inventory, findings


def _finding_counts(findings: list[Finding]) -> Counter[str]:
    return Counter(finding.rule_id for finding in findings)


def _report_payload(inventory: ResourceInventory, findings: list[Finding]) -> str:
    return render_json(
        AnalysisResult(
            title="Workload secret access path parity",
            analyzed_file="synthetic-plan.json",
            analyzed_path="synthetic-plan.json",
            inventory=inventory,
            trust_boundaries=[],
            findings=findings,
        )
    )


def _aws_secret(*, raw_secret_value: str | None = None) -> TerraformResource:
    values: dict[str, Any] = {
        "name": "orders-db",
        "arn": AWS_SECRET_ARN,
        "recovery_window_in_days": 30,
    }
    if raw_secret_value is not None:
        values["secret_string"] = raw_secret_value
    return TerraformResource(
        address="aws_secretsmanager_secret.orders",
        mode="managed",
        resource_type="aws_secretsmanager_secret",
        name="orders",
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
    )


def _exact_aws_resources() -> list[Any]:
    return [
        _aws_secret(),
        aws_role(
            "execution",
            AWS_EXECUTION_ROLE_ARN,
            [aws_statement("Allow", "secretsmanager:GetSecretValue", AWS_SECRET_ARN)],
        ),
        aws_task_definition(task_role_arn=None),
    ]


def _exact_gcp_resources() -> list[Any]:
    return [gcp_secret(), gcp_cloud_run(), gcp_secret_iam_member()]


def _exact_azure_resources() -> list[Any]:
    return [
        azure_vault(rbac_enabled=True),
        azure_secret(),
        azure_web_app(),
        azure_role_assignment(role_name="Key Vault Secrets User"),
    ]


class WorkloadSecretAccessPathParityTests(unittest.TestCase):
    def test_workload_secret_access_rule_families_are_registered(self) -> None:
        self.assertIn(AWS_ACCESS_RULE, _flatten(AWS_RULE_GROUP_IDS))
        self.assertIn(GCP_ACCESS_RULE, _flatten(GCP_RULE_GROUP_IDS))
        self.assertTrue(
            {
                AZURE_REFERENCE_IDENTITY_RULE,
                AZURE_OVERPRIVILEGED_RULE,
                AZURE_BROAD_IDENTITY_RULE,
            }.issubset(_flatten(AZURE_RULE_GROUP_IDS))
        )

    def test_exact_workload_identity_secret_paths_resolve_and_stay_quiet(self) -> None:
        aws_inventory, aws_findings = _normalize_and_evaluate(AwsNormalizer(), _exact_aws_resources())
        aws_workload = aws_inventory.get_by_address(_AWS_WORKLOAD_ADDRESS)
        assert aws_workload is not None
        aws_path = aws_facts(aws_workload).ecs_secret_access_paths[0]
        self.assertEqual(aws_path["workload_address"], _AWS_WORKLOAD_ADDRESS)
        self.assertEqual(aws_path["role_address"], "aws_iam_role.execution")
        self.assertEqual(aws_path["secret_arn"], AWS_SECRET_ARN)
        self.assertEqual(aws_path["access_state"], "allowed")
        self.assertEqual(aws_findings, [])

        gcp_inventory, gcp_findings = _normalize_and_evaluate(GcpNormalizer(), _exact_gcp_resources())
        gcp_workload = gcp_inventory.get_by_address(_GCP_WORKLOAD_ADDRESS)
        assert gcp_workload is not None
        gcp_path = gcp_facts(gcp_workload).cloud_run_secret_access_paths[0]
        self.assertEqual(gcp_path["workload_address"], _GCP_WORKLOAD_ADDRESS)
        self.assertEqual(gcp_path["service_account_email"], GCP_SERVICE_ACCOUNT_EMAIL)
        self.assertEqual(gcp_path["secret_resource_address"], "google_secret_manager_secret.orders")
        self.assertEqual(gcp_path["grant_scope_type"], "secret")
        self.assertEqual(gcp_path["access_state"], "granted")
        self.assertEqual(gcp_findings, [])

        azure_inventory, azure_findings = _normalize_and_evaluate(
            AzureNormalizer(),
            _exact_azure_resources(),
        )
        azure_workload = azure_inventory.get_by_address(_AZURE_WORKLOAD_ADDRESS)
        assert azure_workload is not None
        azure_path = azure_facts(azure_workload).app_service_key_vault_access_paths[0]
        self.assertEqual(azure_path["workload_address"], _AZURE_WORKLOAD_ADDRESS)
        self.assertEqual(azure_path["identity_address"], _AZURE_WORKLOAD_ADDRESS)
        self.assertEqual(azure_path["secret_resource_address"], "azurerm_key_vault_secret.database_password")
        self.assertEqual(azure_path["grant_scope_type"], "vault")
        self.assertEqual(azure_path["access_state"], "granted")
        self.assertEqual(azure_findings, [])

    def test_broad_secret_access_emits_only_provider_local_findings(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                [
                    _aws_secret(),
                    aws_role(
                        "execution",
                        AWS_EXECUTION_ROLE_ARN,
                        [aws_statement("Allow", "secretsmanager:GetSecretValue", "*")],
                    ),
                    aws_task_definition(task_role_arn=None),
                ],
                Counter({AWS_ACCESS_RULE: 1}),
            ),
            (
                "gcp",
                GcpNormalizer(),
                [gcp_secret(), gcp_cloud_run(), gcp_project_iam_member()],
                Counter({GCP_ACCESS_RULE: 1}),
            ),
            (
                "azure",
                AzureNormalizer(),
                [
                    azure_vault(rbac_enabled=True),
                    azure_secret(),
                    azure_web_app(),
                    azure_role_assignment(
                        role_name="Key Vault Administrator",
                        scope="/subscriptions/sub-0001/resourceGroups/app",
                    ),
                ],
                Counter({AZURE_BROAD_IDENTITY_RULE: 1}),
            ),
        )

        for provider, normalizer, resources, expected in cases:
            with self.subTest(provider=provider):
                _, findings = _normalize_and_evaluate(normalizer, resources)

                self.assertEqual(_finding_counts(findings), expected)
                self.assertTrue(all(finding.rule_id.startswith(f"{provider}-") for finding in findings))

    def test_explicit_denies_and_narrowing_conditions_remain_quiet(self) -> None:
        cases = (
            (
                "aws-explicit-deny",
                AwsNormalizer(),
                [
                    aws_role(
                        "execution",
                        AWS_EXECUTION_ROLE_ARN,
                        [
                            aws_statement("Allow", "secretsmanager:GetSecretValue", "*"),
                            aws_statement("Deny", "secretsmanager:GetSecretValue", AWS_SECRET_ARN),
                        ],
                    ),
                    aws_task_definition(task_role_arn=None),
                ],
            ),
            (
                "aws-condition",
                AwsNormalizer(),
                [
                    aws_role(
                        "execution",
                        AWS_EXECUTION_ROLE_ARN,
                        [
                            aws_statement(
                                "Allow",
                                "secretsmanager:GetSecretValue",
                                "*",
                                condition={"StringEquals": {"aws:PrincipalAccount": AWS_ACCOUNT_ID}},
                            )
                        ],
                    ),
                    aws_task_definition(task_role_arn=None),
                ],
            ),
            (
                "gcp-condition",
                GcpNormalizer(),
                [
                    gcp_secret(),
                    gcp_cloud_run(),
                    gcp_project_iam_member(
                        condition=[
                            {
                                "title": "runtime-window",
                                "expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
                            }
                        ]
                    ),
                ],
            ),
            (
                "azure-condition",
                AzureNormalizer(),
                [
                    azure_vault(rbac_enabled=True),
                    azure_secret(),
                    azure_web_app(),
                    azure_custom_role(),
                    azure_role_assignment(
                        role_name=None,
                        role_definition_id=("azurerm_role_definition.secret_reader.role_definition_resource_id"),
                        condition="@Resource[Microsoft.KeyVault/vaults:name] StringEquals 'orders'",
                    ),
                ],
            ),
        )

        for case, normalizer, resources in cases:
            with self.subTest(case=case):
                _, findings = _normalize_and_evaluate(normalizer, resources)
                self.assertEqual(findings, [])

    def test_external_or_computed_access_data_stays_uncertain_and_quiet(self) -> None:
        external_policy_arn = "arn:aws:iam::aws:policy/ExternalSecretAccess"
        aws_inventory, aws_findings = _normalize_and_evaluate(
            AwsNormalizer(),
            [
                aws_role(
                    "execution",
                    AWS_EXECUTION_ROLE_ARN,
                    [aws_statement("Allow", "secretsmanager:GetSecretValue", "*")],
                ),
                aws_role_policy_attachment(AWS_EXECUTION_ROLE_ARN, external_policy_arn),
                aws_task_definition(task_role_arn=None),
            ],
        )
        aws_workload = aws_inventory.get_by_address(_AWS_WORKLOAD_ADDRESS)
        assert aws_workload is not None
        self.assertEqual(aws_findings, [])
        self.assertEqual(aws_facts(aws_workload).ecs_secret_access_paths[0]["access_state"], "unknown")
        self.assertTrue(aws_facts(aws_workload).ecs_secret_access_path_uncertainties)

        gcp_inventory, gcp_findings = _normalize_and_evaluate(
            GcpNormalizer(),
            [
                gcp_secret(),
                gcp_cloud_run(service_account="$" + "{google_service_account.run.email}"),
                gcp_project_iam_member(),
            ],
        )
        gcp_workload = gcp_inventory.get_by_address(_GCP_WORKLOAD_ADDRESS)
        assert gcp_workload is not None
        self.assertEqual(gcp_findings, [])
        self.assertEqual(gcp_facts(gcp_workload).cloud_run_secret_access_paths, [])
        self.assertTrue(gcp_facts(gcp_workload).cloud_run_secret_access_path_uncertainties)

        azure_inventory, azure_findings = _normalize_and_evaluate(
            AzureNormalizer(),
            [
                azure_vault(rbac_enabled=True),
                azure_secret(),
                azure_web_app(
                    key_vault_reference_identity_id=None,
                    unknown_values={"key_vault_reference_identity_id": True},
                ),
                azure_role_assignment(
                    principal_id=AZURE_SYSTEM_PRINCIPAL_ID,
                    role_name="Key Vault Secrets User",
                ),
            ],
        )
        azure_workload = azure_inventory.get_by_address(_AZURE_WORKLOAD_ADDRESS)
        assert azure_workload is not None
        self.assertEqual(azure_findings, [])
        self.assertEqual(azure_facts(azure_workload).app_service_key_vault_access_paths, [])
        self.assertTrue(azure_facts(azure_workload).app_service_key_vault_access_path_uncertainties)

    def test_secret_values_never_enter_access_facts_findings_or_reports(self) -> None:
        cases: list[tuple[str, ProviderNormalizer, list[Any], str]] = []

        aws_sentinel = "aws-super-secret-value"
        cases.append(
            (
                _AWS_WORKLOAD_ADDRESS,
                AwsNormalizer(),
                [
                    _aws_secret(raw_secret_value=aws_sentinel),
                    aws_role(
                        "execution",
                        AWS_EXECUTION_ROLE_ARN,
                        [aws_statement("Allow", "secretsmanager:GetSecretValue", "*")],
                    ),
                    aws_task_definition(task_role_arn=None),
                ],
                aws_sentinel,
            )
        )

        gcp_sentinel = "gcp-super-secret-value"
        gcp_secret_resource = gcp_secret()
        gcp_secret_resource.values["secret_data"] = gcp_sentinel
        cases.append(
            (
                _GCP_WORKLOAD_ADDRESS,
                GcpNormalizer(),
                [gcp_secret_resource, gcp_cloud_run(), gcp_project_iam_member()],
                gcp_sentinel,
            )
        )

        azure_sentinel = "azure-super-secret-value"
        azure_secret_resource = azure_secret()
        azure_secret_resource.values["value"] = azure_sentinel
        cases.append(
            (
                _AZURE_WORKLOAD_ADDRESS,
                AzureNormalizer(),
                [
                    azure_vault(rbac_enabled=True),
                    azure_secret_resource,
                    azure_web_app(),
                    azure_role_assignment(role_name="Key Vault Administrator"),
                ],
                azure_sentinel,
            )
        )

        for workload_address, normalizer, resources, sentinel in cases:
            with self.subTest(provider=normalizer.provider):
                inventory, findings = _normalize_and_evaluate(normalizer, resources)
                workload = inventory.get_by_address(workload_address)
                assert workload is not None

                self.assertNotIn(sentinel, repr(workload.metadata))
                self.assertNotIn(sentinel, repr(findings))
                self.assertNotIn(sentinel, _report_payload(inventory, findings))


if __name__ == "__main__":
    unittest.main()
