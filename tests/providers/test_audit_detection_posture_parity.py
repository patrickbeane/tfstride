from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_audit_rules import _AUDIT_RULE_IDS as AWS_AUDIT_RULE_IDS
from tests.providers.aws.test_aws_audit_rules import _cloudtrail as _aws_cloudtrail
from tests.providers.aws.test_aws_audit_rules import _config_recorder as _aws_config_recorder
from tests.providers.aws.test_aws_audit_rules import _guardduty as _aws_guardduty
from tests.providers.aws.test_aws_audit_rules import _securityhub as _aws_securityhub
from tests.providers.azure.test_azure_aks_rules import _cluster as _azure_aks_cluster
from tests.providers.gcp.normalizer_support import _terraform_resource as _gcp_resource
from tests.providers.gcp.rule_support.compute import _gke_cluster, _gke_node_pool
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
GCP_AUDIT_DETECTION_RULE_IDS = frozenset(
    {
        "gcp-gke-control-plane-logging-incomplete",
        "gcp-scc-asset-discovery-disabled",
        "gcp-logging-exclusion-drops-audit-security-logs",
        "gcp-central-audit-sink-not-modeled",
    }
)
AZURE_AUDIT_DETECTION_RULE_IDS = frozenset(
    {
        "azure-diagnostic-settings-missing",
        "azure-diagnostic-setting-no-log-destination",
        "azure-defender-pricing-tier-not-standard",
        "azure-security-center-auto-provisioning-disabled",
        "azure-aks-monitoring-agent-not-enabled",
        "azure-aks-defender-not-enabled",
        "azure-aks-azure-policy-not-enabled",
    }
)
ALL_AUDIT_DETECTION_RULE_IDS = (
    frozenset(AWS_AUDIT_RULE_IDS) | GCP_AUDIT_DETECTION_RULE_IDS | AZURE_AUDIT_DETECTION_RULE_IDS
)


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for rule_group in rule_groups for rule_id in rule_group)


def _finding_ids(findings) -> frozenset[str]:
    return frozenset(finding.rule_id for finding in findings)


def _evaluate_aws(resources: list[TerraformResource], rule_ids=ALL_AUDIT_DETECTION_RULE_IDS):
    return StrideRuleEngine().evaluate(
        AwsNormalizer().normalize(resources),
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evaluate_gcp(resources: list[TerraformResource], rule_ids=ALL_AUDIT_DETECTION_RULE_IDS):
    return StrideRuleEngine().evaluate(
        GcpNormalizer().normalize(resources),
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evaluate_azure(resources: list[TerraformResource], rule_ids=ALL_AUDIT_DETECTION_RULE_IDS):
    return StrideRuleEngine().evaluate(
        AzureNormalizer().normalize(resources),
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


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


def _azure_resource(resource_type: str, values: dict[str, object], *, name: str = "example") -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values=values,
    )


class AuditDetectionPostureParityTests(unittest.TestCase):
    def test_audit_detection_resource_types_and_rule_families_are_registered(self) -> None:
        self.assertLessEqual(AWS_AUDIT_SECURITY_RESOURCE_TYPES, SUPPORTED_AWS_TYPES)
        self.assertLessEqual(GCP_AUDIT_SECURITY_RESOURCE_TYPES, SUPPORTED_GCP_TYPES)
        self.assertLessEqual(AZURE_AUDIT_SECURITY_RESOURCE_TYPES, SUPPORTED_AZURE_TYPES)
        self.assertLessEqual(frozenset(AWS_AUDIT_RULE_IDS), _flatten(AWS_RULE_GROUP_IDS))
        self.assertLessEqual(GCP_AUDIT_DETECTION_RULE_IDS, _flatten(GCP_RULE_GROUP_IDS))
        self.assertLessEqual(AZURE_AUDIT_DETECTION_RULE_IDS, _flatten(AZURE_RULE_GROUP_IDS))

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
                        "target_resource_id": "/subscriptions/example/resourceGroups/app/providers/Microsoft.KeyVault/vaults/app",
                        "log_analytics_workspace_id": "/subscriptions/example/resourceGroups/obs/providers/Microsoft.OperationalInsights/workspaces/sec",
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

    def test_audit_logging_and_security_monitoring_findings_are_pinned_where_rules_exist(self) -> None:
        aws_findings = _evaluate_aws(
            [
                _aws_cloudtrail(multi_region=False, log_file_validation=False),
                _aws_guardduty(enabled=False),
                _aws_config_recorder(),
            ],
            AWS_AUDIT_RULE_IDS,
        )
        gcp_findings = _evaluate_gcp(
            [
                _gke_cluster(logging_service="logging.googleapis.com/none", logging_components=[]),
                _gke_node_pool(),
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
            ],
            GCP_AUDIT_DETECTION_RULE_IDS,
        )
        azure_findings = _evaluate_azure(
            [
                _azure_aks_cluster(oms_workspace_id=None, defender=False, azure_policy=False),
                _azure_diagnostic_setting("audit", "azurerm_key_vault.app.id", log_analytics_workspace_id=None),
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
            ],
            AZURE_AUDIT_DETECTION_RULE_IDS,
        )

        self.assertEqual(_finding_ids(aws_findings), frozenset(AWS_AUDIT_RULE_IDS))
        self.assertEqual(_finding_ids(gcp_findings), GCP_AUDIT_DETECTION_RULE_IDS)
        self.assertEqual(_finding_ids(azure_findings), AZURE_AUDIT_DETECTION_RULE_IDS)

    def test_safe_audit_logging_and_security_monitoring_posture_stays_quiet(self) -> None:
        aws_findings = _evaluate_aws(
            [_aws_cloudtrail(), _aws_guardduty(), _aws_securityhub(), _aws_config_recorder()],
            AWS_AUDIT_RULE_IDS,
        )
        gcp_findings = _evaluate_gcp(
            [
                _gke_cluster(
                    logging_service="logging.googleapis.com/kubernetes",
                    logging_components=["SYSTEM_COMPONENTS", "APISERVER", "SCHEDULER", "CONTROLLER_MANAGER"],
                ),
                _gke_node_pool(),
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
            GCP_AUDIT_DETECTION_RULE_IDS,
        )
        azure_findings = _evaluate_azure(
            [
                _azure_aks_cluster(
                    oms_workspace_id="azurerm_log_analytics_workspace.aks.id",
                    defender=True,
                    azure_policy=True,
                ),
                _azure_diagnostic_setting("aks_audit", "azurerm_kubernetes_cluster.cluster.id"),
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
            AZURE_AUDIT_DETECTION_RULE_IDS,
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_findings, [])
        self.assertEqual(azure_findings, [])

    def test_audit_detection_findings_remain_provider_local(self) -> None:
        findings_by_provider = {
            "aws": _evaluate_aws(
                [_aws_cloudtrail(multi_region=False, log_file_validation=False), _aws_guardduty(enabled=False)],
                ALL_AUDIT_DETECTION_RULE_IDS,
            ),
            "gcp": _evaluate_gcp(
                [_gke_cluster(logging_service="logging.googleapis.com/none", logging_components=[])],
                ALL_AUDIT_DETECTION_RULE_IDS,
            ),
            "azure": _evaluate_azure(
                [_azure_aks_cluster(oms_workspace_id=None, defender=False, azure_policy=False)],
                ALL_AUDIT_DETECTION_RULE_IDS,
            ),
        }

        for provider, findings in findings_by_provider.items():
            with self.subTest(provider=provider):
                self.assertTrue(findings)
                self.assertTrue(all(finding.rule_id.startswith(f"{provider}-") for finding in findings))


if __name__ == "__main__":
    unittest.main()
