from __future__ import annotations

import unittest
from collections import Counter

from tests.providers.aws.test_aws_api_gateway_rules import (
    _AUTHORIZATION_RULE as AWS_AUTHORIZATION_RULE,
)
from tests.providers.aws.test_aws_api_gateway_rules import (
    _STAGE_LOGGING_RULE as AWS_STAGE_LOGGING_RULE,
)
from tests.providers.aws.test_aws_api_gateway_rules import _findings as _aws_findings
from tests.providers.aws.test_aws_api_gateway_rules import _rest_api as _aws_rest_api
from tests.providers.aws.test_aws_api_gateway_rules import _rest_method as _aws_rest_method
from tests.providers.aws.test_aws_api_gateway_rules import _rest_stage as _aws_rest_stage
from tests.providers.azure.test_azure_app_service_rules import _app as _azure_app
from tests.providers.azure.test_azure_app_service_rules import _evaluate as _azure_findings
from tests.providers.azure.test_azure_audit_rules import _diagnostic_setting as _azure_diagnostic_setting
from tests.providers.gcp.rule_support.serverless import (
    _cloud_run_service,
    _cloud_run_service_iam_member,
    _cloudfunctions_function,
    _cloudfunctions_function_iam_member,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import Finding, TerraformResource
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

GCP_CLOUD_RUN_PUBLIC_INVOKER_RULE = "gcp-cloud-run-public-invoker"
GCP_CLOUD_FUNCTIONS_PUBLIC_INVOKER_RULE = "gcp-cloud-functions-public-invoker"
AZURE_PLATFORM_AUTH_DISABLED_RULE = "azure-app-service-platform-authentication-disabled"
AZURE_ANONYMOUS_PLATFORM_ACCESS_RULE = "azure-app-service-anonymous-platform-access-allowed"
AZURE_DIAGNOSTIC_SETTINGS_MISSING_RULE = "azure-diagnostic-settings-missing"

AWS_PUBLIC_APPLICATION_RULE_IDS = frozenset({AWS_AUTHORIZATION_RULE, AWS_STAGE_LOGGING_RULE})
GCP_PUBLIC_APPLICATION_RULE_IDS = frozenset(
    {GCP_CLOUD_RUN_PUBLIC_INVOKER_RULE, GCP_CLOUD_FUNCTIONS_PUBLIC_INVOKER_RULE}
)
AZURE_PUBLIC_APPLICATION_RULE_IDS = frozenset(
    {
        AZURE_PLATFORM_AUTH_DISABLED_RULE,
        AZURE_ANONYMOUS_PLATFORM_ACCESS_RULE,
        AZURE_DIAGNOSTIC_SETTINGS_MISSING_RULE,
    }
)
ALL_PUBLIC_APPLICATION_RULE_IDS = (
    AWS_PUBLIC_APPLICATION_RULE_IDS | GCP_PUBLIC_APPLICATION_RULE_IDS | AZURE_PUBLIC_APPLICATION_RULE_IDS
)


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for rule_group in rule_groups for rule_id in rule_group)


def _rule_counts(findings: list[Finding]) -> Counter[str]:
    return Counter(finding.rule_id for finding in findings)


def _evidence_keys(findings: list[Finding]) -> set[str]:
    return {item.key for finding in findings for item in finding.evidence}


def _gcp_findings(resources: list[TerraformResource], rule_ids: frozenset[str]) -> list[Finding]:
    inventory = GcpNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=rule_ids),
    )


def _azure_auth_settings(*, enabled: bool, unauthenticated_action: str) -> list[dict[str, object]]:
    return [
        {
            "auth_enabled": enabled,
            "require_authentication": enabled,
            "unauthenticated_action": unauthenticated_action,
            "default_provider": "azureactivedirectory",
            "login": [{"token_store_enabled": True}],
        }
    ]


class PublicApplicationAuthenticationTelemetryParityTests(unittest.TestCase):
    def test_public_application_rule_families_are_registered(self) -> None:
        self.assertLessEqual(AWS_PUBLIC_APPLICATION_RULE_IDS, _flatten(AWS_RULE_GROUP_IDS))
        self.assertLessEqual(GCP_PUBLIC_APPLICATION_RULE_IDS, _flatten(GCP_RULE_GROUP_IDS))
        self.assertLessEqual(AZURE_PUBLIC_APPLICATION_RULE_IDS, _flatten(AZURE_RULE_GROUP_IDS))

    def test_public_application_authentication_and_telemetry_findings_are_pinned(self) -> None:
        aws_findings = _aws_findings(
            [_aws_rest_api(), _aws_rest_method(), _aws_rest_stage()],
            *ALL_PUBLIC_APPLICATION_RULE_IDS,
        )
        gcp_findings = _gcp_findings(
            [
                _cloud_run_service(),
                _cloud_run_service_iam_member(),
                _cloudfunctions_function(),
                _cloudfunctions_function_iam_member(),
            ],
            ALL_PUBLIC_APPLICATION_RULE_IDS,
        )
        azure_findings = _azure_findings(
            [
                _azure_app(
                    name="disabled",
                    public_network=True,
                    auth_settings_v2=_azure_auth_settings(
                        enabled=False,
                        unauthenticated_action="AllowAnonymous",
                    ),
                ),
                _azure_app(
                    name="anonymous",
                    public_network=True,
                    auth_settings_v2=_azure_auth_settings(
                        enabled=True,
                        unauthenticated_action="AllowAnonymous",
                    ),
                ),
            ],
            *ALL_PUBLIC_APPLICATION_RULE_IDS,
        )

        self.assertEqual(
            _rule_counts(aws_findings),
            Counter({AWS_AUTHORIZATION_RULE: 1, AWS_STAGE_LOGGING_RULE: 1}),
        )
        self.assertEqual(
            _rule_counts(gcp_findings),
            Counter({GCP_CLOUD_RUN_PUBLIC_INVOKER_RULE: 1, GCP_CLOUD_FUNCTIONS_PUBLIC_INVOKER_RULE: 1}),
        )
        self.assertEqual(
            _rule_counts(azure_findings),
            Counter(
                {
                    AZURE_PLATFORM_AUTH_DISABLED_RULE: 1,
                    AZURE_ANONYMOUS_PLATFORM_ACCESS_RULE: 1,
                    AZURE_DIAGNOSTIC_SETTINGS_MISSING_RULE: 2,
                }
            ),
        )
        self.assertLessEqual(
            {"unauthenticated_method_or_route", "stage_telemetry"},
            _evidence_keys(aws_findings),
        )
        self.assertIn("public_invoker_bindings", _evidence_keys(gcp_findings))
        self.assertLessEqual(
            {"platform_authentication", "diagnostic_coverage"},
            _evidence_keys(azure_findings),
        )

    def test_authenticated_and_observed_public_application_posture_is_quiet(self) -> None:
        aws_findings = _aws_findings(
            [
                _aws_rest_api(),
                _aws_rest_method(authorization="AWS_IAM"),
                _aws_rest_stage(
                    access_log_settings={
                        "destination_arn": "arn:aws:logs:us-east-1:111122223333:log-group:api-access",
                        "format": "$context.requestId",
                    }
                ),
            ],
            *AWS_PUBLIC_APPLICATION_RULE_IDS,
        )
        gcp_findings = _gcp_findings(
            [
                _cloud_run_service(),
                _cloud_run_service_iam_member(member="serviceAccount:caller@example.iam.gserviceaccount.com"),
                _cloudfunctions_function(),
                _cloudfunctions_function_iam_member(member="serviceAccount:caller@example.iam.gserviceaccount.com"),
            ],
            GCP_PUBLIC_APPLICATION_RULE_IDS,
        )
        azure_findings = _azure_findings(
            [
                _azure_app(
                    public_network=True,
                    auth_settings_v2=_azure_auth_settings(
                        enabled=True,
                        unauthenticated_action="Return401",
                    ),
                ),
                _azure_diagnostic_setting("app_audit", "azurerm_linux_web_app.app.id"),
            ],
            *AZURE_PUBLIC_APPLICATION_RULE_IDS,
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_findings, [])
        self.assertEqual(azure_findings, [])


if __name__ == "__main__":
    unittest.main()
