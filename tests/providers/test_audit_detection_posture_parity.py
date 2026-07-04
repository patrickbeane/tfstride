from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_audit_rules import _AUDIT_RULE_IDS as AWS_ACCOUNT_AUDIT_RULE_IDS
from tests.providers.aws.test_aws_audit_rules import _cloudtrail as _aws_cloudtrail
from tests.providers.aws.test_aws_audit_rules import _config_recorder as _aws_config_recorder
from tests.providers.aws.test_aws_audit_rules import _guardduty as _aws_guardduty
from tests.providers.aws.test_aws_audit_rules import _securityhub as _aws_securityhub
from tests.providers.gcp.normalizer_support import _terraform_resource as _gcp_resource
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import SUPPORTED_AWS_TYPES, AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.normalizer import SUPPORTED_AZURE_TYPES, AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.gcp.normalizer import SUPPORTED_GCP_TYPES, GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

GCP_AUDIT_SECURITY_RESOURCE_TYPES = frozenset(
    {
        GcpResourceType.LOGGING_PROJECT_SINK,
        GcpResourceType.LOGGING_ORGANIZATION_SINK,
        GcpResourceType.LOGGING_PROJECT_EXCLUSION,
        GcpResourceType.LOGGING_ORGANIZATION_EXCLUSION,
        GcpResourceType.SCC_ORGANIZATION_SETTINGS,
    }
)
AZURE_AUDIT_SECURITY_RESOURCE_TYPES = frozenset(
    {
        AzureResourceType.MONITOR_DIAGNOSTIC_SETTING,
        AzureResourceType.SECURITY_CENTER_SUBSCRIPTION_PRICING,
        AzureResourceType.SECURITY_CENTER_AUTO_PROVISIONING,
        AzureResourceType.SECURITY_CENTER_CONTACT,
        AzureResourceType.SECURITY_CENTER_WORKSPACE,
        AzureResourceType.SECURITY_CENTER_SETTING,
        AzureResourceType.ADVANCED_THREAT_PROTECTION,
    }
)
AWS_AUDIT_SECURITY_RESOURCE_TYPES = frozenset(
    {
        "aws_cloudtrail",
        "aws_guardduty_detector",
        "aws_securityhub_account",
        "aws_config_configuration_recorder",
    }
)

GCP_ACCOUNT_AUDIT_RULE_CONCEPTS = {
    "central_audit_export": frozenset({"gcp-central-audit-sink-not-modeled"}),
    "audit_log_exclusion": frozenset({"gcp-logging-exclusion-drops-audit-security-logs"}),
    "security_posture_inventory": frozenset({"gcp-scc-asset-discovery-disabled"}),
}
AZURE_ACCOUNT_AUDIT_RULE_CONCEPTS = {
    "resource_diagnostics": frozenset(
        {"azure-diagnostic-settings-missing", "azure-diagnostic-setting-no-log-destination"}
    ),
    "defender_plan": frozenset({"azure-defender-pricing-tier-not-standard"}),
    "security_agent_provisioning": frozenset({"azure-security-center-auto-provisioning-disabled"}),
}
AWS_ACCOUNT_AUDIT_RULE_CONCEPTS = {
    "account_audit_trail": frozenset(
        {"aws-cloudtrail-multi-region-disabled", "aws-cloudtrail-log-file-validation-disabled"}
    ),
    "threat_detection": frozenset({"aws-guardduty-detector-disabled-or-missing"}),
    "security_posture_management": frozenset({"aws-securityhub-account-missing"}),
}

GCP_ACCOUNT_AUDIT_RULE_IDS = frozenset().union(*GCP_ACCOUNT_AUDIT_RULE_CONCEPTS.values())
AZURE_ACCOUNT_AUDIT_RULE_IDS = frozenset().union(*AZURE_ACCOUNT_AUDIT_RULE_CONCEPTS.values())
ALL_ACCOUNT_AUDIT_RULE_IDS = (
    frozenset(AWS_ACCOUNT_AUDIT_RULE_IDS) | GCP_ACCOUNT_AUDIT_RULE_IDS | AZURE_ACCOUNT_AUDIT_RULE_IDS
)

_AZURE_STORAGE_ID = "/subscriptions/example/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/logs"
_AZURE_KEY_VAULT_ID = "/subscriptions/example/resourceGroups/app/providers/Microsoft.KeyVault/vaults/app"


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for rule_group in rule_groups for rule_id in rule_group)


def _finding_ids(findings) -> frozenset[str]:
    return frozenset(finding.rule_id for finding in findings)


def _evaluate_aws(resources: list[TerraformResource], rule_ids=ALL_ACCOUNT_AUDIT_RULE_IDS):
    return StrideRuleEngine().evaluate(
        AwsNormalizer().normalize(resources),
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evaluate_gcp(resources: list[TerraformResource], rule_ids=ALL_ACCOUNT_AUDIT_RULE_IDS):
    return StrideRuleEngine().evaluate(
        GcpNormalizer().normalize(resources),
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evaluate_azure(resources: list[TerraformResource], rule_ids=ALL_ACCOUNT_AUDIT_RULE_IDS):
    return StrideRuleEngine().evaluate(
        AzureNormalizer().normalize(resources),
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _assert_concepts_emit(test_case: unittest.TestCase, findings, concepts: dict[str, frozenset[str]]) -> None:
    finding_ids = _finding_ids(findings)
    for concept, rule_ids in concepts.items():
        with test_case.subTest(concept=concept):
            test_case.assertLessEqual(rule_ids, finding_ids)
    expected_ids = frozenset().union(*concepts.values())
    test_case.assertEqual(finding_ids, expected_ids)


def _azure_diagnostic_setting(
    name: str,
    target_resource_id: object,
    *,
    log_analytics_workspace_id: str
    | None = "/subscriptions/example/resourceGroups/obs/providers/Microsoft.OperationalInsights/workspaces/sec",
) -> TerraformResource:
    values: dict[str, object] = {
        "name": name,
        "target_resource_id": target_resource_id,
        "enabled_log": [{"category": "AuditEvent"}],
        "metric": [{"category": "AllMetrics", "enabled": True}],
    }
    if log_analytics_workspace_id is not None:
        values["log_analytics_workspace_id"] = log_analytics_workspace_id
    return _azure_resource(AzureResourceType.MONITOR_DIAGNOSTIC_SETTING, values, name=name)


def _azure_storage_account() -> TerraformResource:
    return _azure_resource(
        AzureResourceType.STORAGE_ACCOUNT,
        {
            "id": _AZURE_STORAGE_ID,
            "name": "logs",
            "public_network_access_enabled": False,
            "allow_nested_items_to_be_public": False,
            "shared_access_key_enabled": False,
        },
        name="logs",
    )


def _azure_resource(resource_type: str, values: dict[str, object], *, name: str = "example") -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values=values,
    )


def _unsafe_aws_account_audit_resources() -> list[TerraformResource]:
    return [
        _aws_cloudtrail(multi_region=False, log_file_validation=False),
        _aws_guardduty(enabled=False),
        _aws_config_recorder(),
    ]


def _unsafe_gcp_account_audit_resources() -> list[TerraformResource]:
    return [
        _gcp_resource(
            "google_scc_organization_settings.main",
            GcpResourceType.SCC_ORGANIZATION_SETTINGS,
            {"organization": "1234567890", "enable_asset_discovery": False},
        ),
        _gcp_resource(
            "google_logging_project_exclusion.audit",
            GcpResourceType.LOGGING_PROJECT_EXCLUSION,
            {
                "name": "drop-audit",
                "project": "tfstride-demo",
                "filter": "logName:cloudaudit.googleapis.com",
                "disabled": False,
            },
        ),
    ]


def _unsafe_azure_account_audit_resources() -> list[TerraformResource]:
    return [
        _azure_storage_account(),
        _azure_diagnostic_setting("audit", _AZURE_KEY_VAULT_ID, log_analytics_workspace_id=None),
        _azure_resource(
            AzureResourceType.SECURITY_CENTER_SUBSCRIPTION_PRICING,
            {"resource_type": "StorageAccounts", "tier": "Free"},
            name="storage",
        ),
        _azure_resource(
            AzureResourceType.SECURITY_CENTER_AUTO_PROVISIONING,
            {"auto_provision": "Off"},
            name="auto",
        ),
    ]


class AuditDetectionPostureParityTests(unittest.TestCase):
    def test_account_audit_detection_resource_types_and_rule_concepts_are_registered(self) -> None:
        self.assertLessEqual(AWS_AUDIT_SECURITY_RESOURCE_TYPES, SUPPORTED_AWS_TYPES)
        self.assertLessEqual(GCP_AUDIT_SECURITY_RESOURCE_TYPES, SUPPORTED_GCP_TYPES)
        self.assertLessEqual(AZURE_AUDIT_SECURITY_RESOURCE_TYPES, SUPPORTED_AZURE_TYPES)
        self.assertEqual(
            frozenset(AWS_ACCOUNT_AUDIT_RULE_IDS),
            frozenset().union(*AWS_ACCOUNT_AUDIT_RULE_CONCEPTS.values()),
        )
        self.assertLessEqual(frozenset(AWS_ACCOUNT_AUDIT_RULE_IDS), _flatten(AWS_RULE_GROUP_IDS))
        self.assertLessEqual(GCP_ACCOUNT_AUDIT_RULE_IDS, _flatten(GCP_RULE_GROUP_IDS))
        self.assertLessEqual(AZURE_ACCOUNT_AUDIT_RULE_IDS, _flatten(AZURE_RULE_GROUP_IDS))

    def test_audit_logging_and_security_monitoring_facts_are_pinned_by_provider(self) -> None:
        aws_inventory = AwsNormalizer().normalize(
            [
                _aws_cloudtrail(multi_region=True, log_file_validation=True),
                _aws_guardduty(enabled=True),
                _aws_securityhub(),
            ]
        )
        gcp_inventory = GcpNormalizer().normalize(
            [
                _gcp_resource(
                    "google_logging_project_sink.audit",
                    GcpResourceType.LOGGING_PROJECT_SINK,
                    {
                        "name": "audit",
                        "project": "tfstride-demo",
                        "destination": "storage.googleapis.com/tfstride-audit-logs",
                        "filter": "logName:cloudaudit.googleapis.com",
                        "writer_identity": "serviceAccount:cloud-logs@example.iam.gserviceaccount.com",
                        "unique_writer_identity": True,
                    },
                ),
                _gcp_resource(
                    "google_scc_organization_settings.main",
                    GcpResourceType.SCC_ORGANIZATION_SETTINGS,
                    {
                        "organization": "1234567890",
                        "enable_asset_discovery": True,
                        "asset_discovery_config": [{"inclusion_mode": "ALL"}],
                    },
                ),
            ]
        )
        azure_inventory = AzureNormalizer().normalize(
            [
                _azure_resource(
                    AzureResourceType.MONITOR_DIAGNOSTIC_SETTING,
                    {
                        "name": "audit",
                        "target_resource_id": _AZURE_KEY_VAULT_ID,
                        "log_analytics_workspace_id": (
                            "/subscriptions/example/resourceGroups/obs/providers/"
                            "Microsoft.OperationalInsights/workspaces/sec"
                        ),
                        "enabled_log": [{"category": "AuditEvent"}],
                        "metric": [{"category": "AllMetrics", "enabled": True}],
                    },
                    name="audit",
                ),
                _azure_resource(
                    AzureResourceType.SECURITY_CENTER_SUBSCRIPTION_PRICING,
                    {"resource_type": "VirtualMachines", "tier": "Standard"},
                    name="vm",
                ),
                _azure_resource(
                    AzureResourceType.SECURITY_CENTER_AUTO_PROVISIONING,
                    {"auto_provision": "On"},
                    name="auto",
                ),
            ]
        )

        aws_by_type = {resource.resource_type: resource for resource in aws_inventory.resources}
        gcp_by_type = {resource.resource_type: resource for resource in gcp_inventory.resources}
        azure_by_type = {resource.resource_type: resource for resource in azure_inventory.resources}

        self.assertEqual(aws_facts(aws_by_type["aws_cloudtrail"]).cloudtrail_multi_region_state, "enabled")
        self.assertEqual(
            aws_facts(aws_by_type["aws_cloudtrail"]).cloudtrail_log_file_validation_state,
            "enabled",
        )
        self.assertEqual(aws_facts(aws_by_type["aws_guardduty_detector"]).guardduty_enable_state, "enabled")
        self.assertEqual(
            aws_facts(aws_by_type["aws_securityhub_account"]).securityhub_enable_default_standards_state,
            "enabled",
        )
        self.assertEqual(
            gcp_facts(gcp_by_type[GcpResourceType.LOGGING_PROJECT_SINK]).logging_sink_destination,
            "storage.googleapis.com/tfstride-audit-logs",
        )
        self.assertEqual(
            gcp_facts(gcp_by_type[GcpResourceType.LOGGING_PROJECT_SINK]).logging_sink_scope_type, "project"
        )
        self.assertEqual(
            gcp_facts(gcp_by_type[GcpResourceType.SCC_ORGANIZATION_SETTINGS]).scc_asset_discovery_state,
            "enabled",
        )
        self.assertEqual(
            azure_facts(azure_by_type[AzureResourceType.MONITOR_DIAGNOSTIC_SETTING]).diagnostic_enabled_log_categories,
            ["AuditEvent"],
        )
        self.assertEqual(
            azure_facts(azure_by_type[AzureResourceType.MONITOR_DIAGNOSTIC_SETTING]).diagnostic_metric_categories,
            ["AllMetrics"],
        )
        self.assertEqual(
            azure_facts(azure_by_type[AzureResourceType.SECURITY_CENTER_SUBSCRIPTION_PRICING]).defender_pricing_tier,
            "Standard",
        )
        self.assertEqual(
            azure_facts(
                azure_by_type[AzureResourceType.SECURITY_CENTER_AUTO_PROVISIONING]
            ).security_center_auto_provisioning_state,
            "enabled",
        )

    def test_account_audit_and_detection_findings_are_pinned_by_provider_concept(self) -> None:
        aws_findings = _evaluate_aws(_unsafe_aws_account_audit_resources(), AWS_ACCOUNT_AUDIT_RULE_IDS)
        gcp_findings = _evaluate_gcp(_unsafe_gcp_account_audit_resources(), GCP_ACCOUNT_AUDIT_RULE_IDS)
        azure_findings = _evaluate_azure(_unsafe_azure_account_audit_resources(), AZURE_ACCOUNT_AUDIT_RULE_IDS)

        _assert_concepts_emit(self, aws_findings, AWS_ACCOUNT_AUDIT_RULE_CONCEPTS)
        _assert_concepts_emit(self, gcp_findings, GCP_ACCOUNT_AUDIT_RULE_CONCEPTS)
        _assert_concepts_emit(self, azure_findings, AZURE_ACCOUNT_AUDIT_RULE_CONCEPTS)

    def test_safe_account_audit_and_detection_posture_stays_quiet(self) -> None:
        aws_findings = _evaluate_aws(
            [_aws_cloudtrail(), _aws_guardduty(), _aws_securityhub(), _aws_config_recorder()],
            AWS_ACCOUNT_AUDIT_RULE_IDS,
        )
        gcp_findings = _evaluate_gcp(
            [
                _gcp_resource(
                    "google_logging_project_sink.audit",
                    GcpResourceType.LOGGING_PROJECT_SINK,
                    {
                        "name": "audit",
                        "project": "tfstride-demo",
                        "destination": "storage.googleapis.com/tfstride-audit-logs",
                    },
                ),
                _gcp_resource(
                    "google_scc_organization_settings.main",
                    GcpResourceType.SCC_ORGANIZATION_SETTINGS,
                    {"organization": "1234567890", "enable_asset_discovery": True},
                ),
            ],
            GCP_ACCOUNT_AUDIT_RULE_IDS,
        )
        azure_findings = _evaluate_azure(
            [
                _azure_storage_account(),
                _azure_diagnostic_setting("storage_audit", _AZURE_STORAGE_ID),
                _azure_resource(
                    AzureResourceType.SECURITY_CENTER_SUBSCRIPTION_PRICING,
                    {"resource_type": "VirtualMachines", "tier": "Standard"},
                    name="vm",
                ),
                _azure_resource(
                    AzureResourceType.SECURITY_CENTER_AUTO_PROVISIONING,
                    {"auto_provision": "On"},
                    name="auto",
                ),
            ],
            AZURE_ACCOUNT_AUDIT_RULE_IDS,
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_findings, [])
        self.assertEqual(azure_findings, [])

    def test_account_audit_detection_findings_remain_provider_local(self) -> None:
        findings_by_provider = {
            "aws": _evaluate_aws(_unsafe_aws_account_audit_resources(), ALL_ACCOUNT_AUDIT_RULE_IDS),
            "gcp": _evaluate_gcp(_unsafe_gcp_account_audit_resources(), ALL_ACCOUNT_AUDIT_RULE_IDS),
            "azure": _evaluate_azure(_unsafe_azure_account_audit_resources(), ALL_ACCOUNT_AUDIT_RULE_IDS),
        }

        for provider, findings in findings_by_provider.items():
            with self.subTest(provider=provider):
                self.assertTrue(findings)
                self.assertTrue(all(finding.rule_id.startswith(f"{provider}-") for finding in findings))


if __name__ == "__main__":
    unittest.main()
