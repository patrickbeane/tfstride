from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_oidc_role_trust import (
    _PROVIDER_ADDRESS as _AWS_PROVIDER_ADDRESS,
)
from tests.providers.aws.test_aws_oidc_role_trust import _PROVIDER_ARN as _AWS_PROVIDER_ARN
from tests.providers.aws.test_aws_oidc_role_trust import _provider as _aws_provider
from tests.providers.aws.test_aws_oidc_role_trust import _role as _aws_role
from tests.providers.azure.test_azure_federated_identity_rules import (
    _role_assignment as _azure_role_assignment,
)
from tests.providers.azure.test_azure_federated_identity_trust_paths import (
    _credential as _azure_credential,
)
from tests.providers.azure.test_azure_federated_identity_trust_paths import (
    _identity as _azure_identity,
)
from tests.providers.gcp.rule_support.iam import _project_iam_member
from tests.providers.gcp.test_gcp_workload_identity_rules import (
    _provider_without_condition as _gcp_provider_without_condition,
)
from tests.providers.gcp.test_gcp_workload_identity_trust_paths import (
    _PROVIDER_ADDRESS as _GCP_PROVIDER_ADDRESS,
)
from tests.providers.gcp.test_gcp_workload_identity_trust_paths import (
    _SERVICE_ACCOUNT_ADDRESS as _GCP_SERVICE_ACCOUNT_ADDRESS,
)
from tests.providers.gcp.test_gcp_workload_identity_trust_paths import (
    _SERVICE_ACCOUNT_EMAIL as _GCP_SERVICE_ACCOUNT_EMAIL,
)
from tests.providers.gcp.test_gcp_workload_identity_trust_paths import _iam_member as _gcp_iam_member
from tests.providers.gcp.test_gcp_workload_identity_trust_paths import _pool as _gcp_pool
from tests.providers.gcp.test_gcp_workload_identity_trust_paths import _principal as _gcp_principal
from tests.providers.gcp.test_gcp_workload_identity_trust_paths import _principal_set as _gcp_principal_set
from tests.providers.gcp.test_gcp_workload_identity_trust_paths import _provider as _gcp_provider
from tests.providers.gcp.test_gcp_workload_identity_trust_paths import (
    _service_account as _gcp_service_account,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import Finding, TerraformResource
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

AWS_FEDERATION_RULE_IDS = frozenset(
    {
        "aws-role-trust-expansion",
        "aws-role-trust-missing-narrowing",
    }
)
GCP_FEDERATION_RULE_IDS = frozenset(
    {
        "gcp-workload-identity-pool-wide-impersonation",
        "gcp-workload-identity-provider-unconditioned-broad-trust",
        "gcp-workload-identity-privileged-service-account-access",
    }
)
AZURE_FEDERATION_RULE_IDS = frozenset({"azure-federated-identity-privileged-access"})
ALL_FEDERATION_RULE_IDS = AWS_FEDERATION_RULE_IDS | GCP_FEDERATION_RULE_IDS | AZURE_FEDERATION_RULE_IDS


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for rule_group in rule_groups for rule_id in rule_group)


def _evaluate(
    normalizer: ProviderNormalizer,
    resources: list[TerraformResource],
) -> list[Finding]:
    return StrideRuleEngine().evaluate(
        normalizer.normalize(resources),
        [],
        rule_policy=RulePolicy(enabled_rule_ids=ALL_FEDERATION_RULE_IDS),
    )


def _finding_ids(findings: list[Finding]) -> frozenset[str]:
    return frozenset(finding.rule_id for finding in findings)


def _aws_narrowing_conditions() -> dict[str, object]:
    return {
        "StringEquals": {
            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
            "token.actions.githubusercontent.com:sub": "repo:tfstride/tfstride:ref:refs/heads/main",
        }
    }


class FederatedWorkloadIdentityPostureParityTests(unittest.TestCase):
    def test_provider_federation_rule_families_are_registered(self) -> None:
        self.assertLessEqual(AWS_FEDERATION_RULE_IDS, _flatten(AWS_RULE_GROUP_IDS))
        self.assertLessEqual(GCP_FEDERATION_RULE_IDS, _flatten(GCP_RULE_GROUP_IDS))
        self.assertLessEqual(AZURE_FEDERATION_RULE_IDS, _flatten(AZURE_RULE_GROUP_IDS))

    def test_exact_issuer_to_identity_relationships_are_pinned(self) -> None:
        aws_inventory = AwsNormalizer().normalize(
            [
                _aws_provider(),
                _aws_role(
                    f"{_AWS_PROVIDER_ADDRESS}.arn",
                    conditions=_aws_narrowing_conditions(),
                ),
            ]
        )
        aws_role = aws_inventory.get_by_address("aws_iam_role.deploy")
        assert aws_role is not None
        aws_provider = aws_facts(aws_role).trust_statements[0]["resolved_oidc_providers"][0]

        gcp_inventory = GcpNormalizer().normalize(
            [
                _gcp_pool(),
                _gcp_provider(),
                _gcp_service_account(),
                _gcp_iam_member(_gcp_principal("repo:tfstride/tfstride:ref:refs/heads/main")),
            ]
        )
        gcp_service_account = gcp_inventory.get_by_address(_GCP_SERVICE_ACCOUNT_ADDRESS)
        assert gcp_service_account is not None
        gcp_path = gcp_facts(gcp_service_account).workload_identity_federation_trust_paths[0]

        azure_inventory = AzureNormalizer().normalize([_azure_identity(), _azure_credential()])
        azure_identity = azure_inventory.get_by_address("azurerm_user_assigned_identity.deploy")
        assert azure_identity is not None
        azure_path = azure_facts(azure_identity).federated_managed_identity_trust_paths[0]

        self.assertEqual(
            (aws_provider["address"], aws_provider["url"]),
            (_AWS_PROVIDER_ADDRESS, "https://token.actions.githubusercontent.com"),
        )
        self.assertEqual(
            (gcp_path["provider_address"], gcp_path["provider_issuer_uri"], gcp_path["service_account_address"]),
            (
                _GCP_PROVIDER_ADDRESS,
                "https://token.actions.githubusercontent.com",
                _GCP_SERVICE_ACCOUNT_ADDRESS,
            ),
        )
        self.assertEqual(
            (azure_path["issuer"], azure_path["identity_address"]),
            (
                "https://token.actions.githubusercontent.com",
                "azurerm_user_assigned_identity.deploy",
            ),
        )

    def test_narrowed_federated_trust_stays_quiet(self) -> None:
        aws_findings = _evaluate(
            AwsNormalizer(),
            [
                _aws_provider(),
                _aws_role(_AWS_PROVIDER_ARN, conditions=_aws_narrowing_conditions()),
            ],
        )
        gcp_findings = _evaluate(
            GcpNormalizer(),
            [
                _gcp_pool(),
                _gcp_provider(),
                _gcp_service_account(),
                _gcp_iam_member(_gcp_principal("repo:tfstride/tfstride:ref:refs/heads/main")),
            ],
        )
        azure_findings = _evaluate(
            AzureNormalizer(),
            [
                _azure_identity(),
                _azure_credential(),
                _azure_role_assignment(role_name="Reader", role_id="reader"),
            ],
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_findings, [])
        self.assertEqual(azure_findings, [])

    def test_broad_privileged_federation_is_detected_without_provider_leakage(self) -> None:
        aws_findings = _evaluate(
            AwsNormalizer(),
            [_aws_provider(), _aws_role(_AWS_PROVIDER_ARN)],
        )
        gcp_findings = _evaluate(
            GcpNormalizer(),
            [
                _gcp_pool(),
                _gcp_provider_without_condition(),
                _gcp_service_account(),
                _gcp_iam_member(_gcp_principal_set("*")),
                _project_iam_member(
                    "roles/owner",
                    member=f"serviceAccount:{_GCP_SERVICE_ACCOUNT_EMAIL}",
                ),
            ],
        )
        azure_findings = _evaluate(
            AzureNormalizer(),
            [_azure_identity(), _azure_credential(), _azure_role_assignment()],
        )

        self.assertEqual(_finding_ids(aws_findings), AWS_FEDERATION_RULE_IDS)
        self.assertEqual(_finding_ids(gcp_findings), GCP_FEDERATION_RULE_IDS)
        self.assertEqual(_finding_ids(azure_findings), AZURE_FEDERATION_RULE_IDS)
        for provider, findings in (
            ("aws", aws_findings),
            ("gcp", gcp_findings),
            ("azure", azure_findings),
        ):
            with self.subTest(provider=provider):
                self.assertTrue(findings)
                self.assertTrue(all(finding.rule_id.startswith(f"{provider}-") for finding in findings))

    def test_unresolved_federation_inputs_do_not_create_access_claims(self) -> None:
        aws_findings = _evaluate(
            AwsNormalizer(),
            [
                _aws_provider(arn=None),
                _aws_role(
                    f"{_AWS_PROVIDER_ADDRESS}.arn",
                    conditions=_aws_narrowing_conditions(),
                ),
            ],
        )

        unresolved_gcp_provider = _gcp_provider(resource_name=None)
        gcp_findings = _evaluate(
            GcpNormalizer(),
            [
                _gcp_pool(),
                unresolved_gcp_provider,
                _gcp_service_account(),
                _gcp_iam_member(_gcp_principal("repo:tfstride/tfstride")),
                _project_iam_member(
                    "roles/owner",
                    member=f"serviceAccount:{_GCP_SERVICE_ACCOUNT_EMAIL}",
                ),
            ],
        )

        unknown_claim_findings = _evaluate(
            AzureNormalizer(),
            [
                _azure_identity(),
                _azure_credential(
                    issuer=None,
                    subject=None,
                    audiences=(),
                    unknown_values={"issuer": True, "subject": True, "audiences": True},
                ),
                _azure_role_assignment(),
            ],
        )
        unresolved_identity_findings = _evaluate(
            AzureNormalizer(),
            [
                _azure_identity(),
                _azure_credential(parent_id=None, unknown_values={"parent_id": True}),
                _azure_role_assignment(),
            ],
        )
        unknown_assignment_findings = _evaluate(
            AzureNormalizer(),
            [
                _azure_identity(),
                _azure_credential(),
                _azure_role_assignment(
                    role_name=None,
                    role_id=None,
                    unknown_values={"role_definition_name": True, "role_definition_id": True},
                ),
            ],
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_findings, [])
        self.assertEqual(unknown_claim_findings, [])
        self.assertEqual(unresolved_identity_findings, [])
        self.assertEqual(unknown_assignment_findings, [])


if __name__ == "__main__":
    unittest.main()
