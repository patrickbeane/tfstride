"""Characterize how diagnostic-setting audit relevance is judged in two places.

The posture rule (`azure-diagnostic-setting-audit-logs-incomplete`) and the
public App Service diagnostic-setting disruption path each decide whether an
enabled log category or category group carries audit or security telemetry for
the monitored resource, using different matchers. This table pins the current
answer of each so later changes move the baseline deliberately. It records
current behavior only; it does not assert which categories Azure documents for
each resource type.
"""

from __future__ import annotations

import unittest
from dataclasses import dataclass

from tests.providers.azure.test_azure_app_service_diagnostic_setting_audit_telemetry_disruption_paths import (
    _built_in_assignment,
    _valid_resources,
    _workload_paths,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import _resource
from tests.providers.test_public_workload_audit_telemetry_disruption_boundaries import (
    _azure_diagnostic_setting,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_types import AzureResourceType

_POSTURE_RULE = "azure-diagnostic-setting-audit-logs-incomplete"
_PROVIDERS = "/subscriptions/sub-0001/resourceGroups/ops/providers/"
_SUBSCRIPTION_SCOPE = "/subscriptions/sub-0001"

_MONITORED_RESOURCES = {
    "linux web app": (AzureResourceType.LINUX_WEB_APP, "Microsoft.Web/sites/target"),
    "windows web app": (AzureResourceType.WINDOWS_WEB_APP, "Microsoft.Web/sites/target"),
    "linux function app": (AzureResourceType.LINUX_FUNCTION_APP, "Microsoft.Web/sites/target"),
    "key vault": (AzureResourceType.KEY_VAULT, "Microsoft.KeyVault/vaults/target"),
    "storage account": (AzureResourceType.STORAGE_ACCOUNT, "Microsoft.Storage/storageAccounts/target"),
    "sql server": (AzureResourceType.MSSQL_SERVER, "Microsoft.Sql/servers/target"),
    "postgresql server": (
        AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER,
        "Microsoft.DBforPostgreSQL/flexibleServers/target",
    ),
    "aks cluster": (AzureResourceType.KUBERNETES_CLUSTER, "Microsoft.ContainerService/managedClusters/target"),
}


@dataclass(frozen=True)
class _Case:
    resource: str
    log: dict[str, object]
    # The posture rule stays quiet: it treats the setting as carrying audit logs.
    posture_accepts: bool
    # The disruption path is established: relevance is proven for this resource.
    disruption_established: bool

    @property
    def name(self) -> str:
        return f"{self.resource}: {self.log}"


def _group(name: str) -> dict[str, object]:
    return {"category_group": name}


def _category(name: str) -> dict[str, object]:
    return {"category": name}


_CASES = (
    _Case("linux web app", _group("audit"), True, True),
    _Case("linux web app", _group("allLogs"), True, True),
    _Case("linux web app", _category("AppServiceAuditLogs"), True, True),
    _Case("linux web app", _category("AppServiceHTTPLogs"), False, False),
    _Case("windows web app", _category("AppServiceAuditLogs"), True, True),
    _Case("linux function app", _group("audit"), True, True),
    _Case("linux function app", _category("FunctionAppLogs"), False, False),
    _Case("key vault", _group("audit"), True, True),
    _Case("storage account", _group("audit"), True, True),
    _Case("storage account", _category("StorageRead"), False, False),
    _Case("sql server", _group("audit"), True, True),
    _Case("postgresql server", _group("audit"), True, True),
    _Case("aks cluster", _group("audit"), True, True),
    # Documented audit categories and groups now establish relevance for the
    # resource types the catalog covers.
    _Case("key vault", _group("allLogs"), True, True),
    _Case("key vault", _category("AuditEvent"), True, True),
    _Case("aks cluster", _group("allLogs"), True, True),
    _Case("aks cluster", _category("kube-audit"), True, True),
    # Rows below are the remaining disagreements, and they are intentional:
    # posture only claims a setting does not clearly enable audit logs, while
    # the disruption path needs proof, so cases the catalog cannot resolve stay
    # accepted by posture and unestablished for disruption, where the catalog
    # records an uncertainty for each unresolved case.
    _Case("linux function app", _group("allLogs"), True, False),
    _Case("storage account", _group("allLogs"), True, False),
    _Case("sql server", _group("allLogs"), True, False),
    _Case("sql server", _category("SQLSecurityAuditEvents"), True, False),
    _Case("postgresql server", _group("allLogs"), True, False),
    # A category that belongs to a different resource type is still accepted
    # by posture, which matches on the words "audit" and "security" alone, and
    # is unresolved for disruption because the catalog does not list it there.
    _Case("linux web app", _category("AuditEvent"), True, False),
)


def _resources(case: _Case):
    resource_type, suffix = _MONITORED_RESOURCES[case.resource]
    resource_id = f"{_PROVIDERS}{suffix}"
    monitored = _resource(resource_type, {"id": resource_id, "name": "target"}, name="target")
    diagnostic = _azure_diagnostic_setting(target_id=resource_id, enabled_log=[case.log])
    diagnostic.values["id"] = f"{resource_id}|audit"
    return [
        *_valid_resources(
            diagnostic=diagnostic,
            assignment=_built_in_assignment(scope=_SUBSCRIPTION_SCOPE),
        ),
        monitored,
    ]


def _posture_accepts(case: _Case) -> bool:
    inventory = AzureNormalizer().normalize(_resources(case))
    findings = StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_POSTURE_RULE})),
    )
    return not findings


def _disruption_established(case: _Case) -> bool:
    return bool(_workload_paths(_resources(case)))


class AzureDiagnosticAuditRelevanceParityBaselineTests(unittest.TestCase):
    def test_audit_relevance_baseline(self) -> None:
        for case in _CASES:
            with self.subTest(case=case.name):
                self.assertEqual(_posture_accepts(case), case.posture_accepts)
                self.assertEqual(_disruption_established(case), case.disruption_established)

    def test_baseline_disagreements_are_the_known_ones(self) -> None:
        disagreements = sorted(case.name for case in _CASES if case.posture_accepts != case.disruption_established)
        self.assertEqual(
            disagreements,
            sorted(
                [
                    "linux function app: {'category_group': 'allLogs'}",
                    "linux web app: {'category': 'AuditEvent'}",
                    "postgresql server: {'category_group': 'allLogs'}",
                    "sql server: {'category': 'SQLSecurityAuditEvents'}",
                    "sql server: {'category_group': 'allLogs'}",
                    "storage account: {'category_group': 'allLogs'}",
                ]
            ),
        )
