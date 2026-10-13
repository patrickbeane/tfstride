"""Documented resource-log categories for diagnostic-setting audit relevance.

Each entry records, for one monitored Azure resource type, which resource log
categories carry audit or security telemetry, and what the ``allLogs`` category
group is known to contain. The data comes from Microsoft's per-resource-type
"Supported log categories" references (checked 2026-09-28), which are linked on
each entry. A resource type without an entry is unmodeled, and callers must
treat categories and ``allLogs`` for it as unresolved instead of guessing.

The ``audit`` category group is defined by Microsoft as "all resource logs that
record customer interactions with data or the settings of the service", so it
carries audit telemetry for any resource type that offers it and needs no
per-type entry.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from tfstride.providers.azure.resource_types import AzureResourceType

AllLogsAuditState = Literal["carries_audit", "no_audit", "unresolved"]
CategoryAuditRelevance = Literal["audit", "not_audit", "unresolved"]

_SUPPORTED_LOGS = "https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-logs/"
_LOGS_INDEX = "https://learn.microsoft.com/en-us/azure/azure-monitor/reference/logs-index"


@dataclass(frozen=True, slots=True)
class AzureDiagnosticLogCatalogEntry:
    arm_type: str
    audit_categories: frozenset[str]
    other_categories: frozenset[str]
    all_logs_state: AllLogsAuditState
    source: str


def _entry(
    arm_type: str,
    *,
    audit: tuple[str, ...] = (),
    other: tuple[str, ...] = (),
    all_logs: AllLogsAuditState,
    source: str,
) -> AzureDiagnosticLogCatalogEntry:
    return AzureDiagnosticLogCatalogEntry(
        arm_type=arm_type,
        audit_categories=frozenset(name.casefold() for name in audit),
        other_categories=frozenset(name.casefold() for name in other),
        all_logs_state=all_logs,
        source=source,
    )


# Web Apps and Function Apps are both Microsoft.Web/sites, and the reference does
# not say which categories each kind emits. Only AppServiceAuditLogs (publishing
# user sign-ins) and AppServiceFileAuditLogs (content modification) are counted as
# audit evidence. AppServiceIPSecAuditLogs and AppServiceAntivirusScanAuditLogs are
# left out because their documented descriptions do not describe actor activity.
_WEB_APP_ENTRY = _entry(
    "Microsoft.Web/sites",
    audit=("AppServiceAuditLogs", "AppServiceFileAuditLogs"),
    other=(
        "AppServiceAntivirusScanAuditLogs",
        "AppServiceAppLogs",
        "AppServiceAuthenticationLogs",
        "AppServiceConsoleLogs",
        "AppServiceHTTPLogs",
        "AppServiceIPSecAuditLogs",
        "AppServicePlatformLogs",
    ),
    all_logs="carries_audit",
    source=f"{_SUPPORTED_LOGS}microsoft-web-sites-logs",
)
_FUNCTION_APP_ENTRY = _entry(
    "Microsoft.Web/sites",
    other=("FunctionAppLogs",),
    all_logs="unresolved",
    source=f"{_SUPPORTED_LOGS}microsoft-web-sites-logs",
)

# Resource logs for Storage exist only on the blob, file, queue, and table service
# sub-resources, and for SQL only on servers/databases and managed instances. The
# account-level and server-level resource types have no documented log categories.
_STORAGE_ACCOUNT_ENTRY = _entry(
    "Microsoft.Storage/storageAccounts",
    all_logs="unresolved",
    source=_LOGS_INDEX,
)
_SQL_SERVER_ENTRY = _entry(
    "Microsoft.Sql/servers",
    all_logs="unresolved",
    source=_LOGS_INDEX,
)

_CATALOG: dict[str, AzureDiagnosticLogCatalogEntry] = {
    AzureResourceType.LINUX_WEB_APP: _WEB_APP_ENTRY,
    AzureResourceType.WINDOWS_WEB_APP: _WEB_APP_ENTRY,
    AzureResourceType.FUNCTION_APP: _FUNCTION_APP_ENTRY,
    AzureResourceType.LINUX_FUNCTION_APP: _FUNCTION_APP_ENTRY,
    AzureResourceType.WINDOWS_FUNCTION_APP: _FUNCTION_APP_ENTRY,
    AzureResourceType.KEY_VAULT: _entry(
        "Microsoft.KeyVault/vaults",
        audit=("AuditEvent",),
        other=("AzurePolicyEvaluationDetails",),
        all_logs="carries_audit",
        source=f"{_SUPPORTED_LOGS}microsoft-keyvault-vaults-logs",
    ),
    AzureResourceType.STORAGE_ACCOUNT: _STORAGE_ACCOUNT_ENTRY,
    AzureResourceType.MSSQL_SERVER: _SQL_SERVER_ENTRY,
    AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER: _entry(
        "Microsoft.DBforPostgreSQL/flexibleServers",
        other=(
            "PostgreSQLFlexDatabaseXacts",
            "PostgreSQLFlexPGBouncer",
            "PostgreSQLFlexQueryStoreRuntime",
            "PostgreSQLFlexQueryStoreWaitStats",
            "PostgreSQLFlexSessions",
            "PostgreSQLFlexTableStats",
            "PostgreSQLLogs",
            "PostgreSQLQueryStoreSqlText",
        ),
        all_logs="no_audit",
        source=f"{_SUPPORTED_LOGS}microsoft-dbforpostgresql-flexibleservers-logs",
    ),
    AzureResourceType.KUBERNETES_CLUSTER: _entry(
        "Microsoft.ContainerService/managedClusters",
        audit=("kube-audit", "kube-audit-admin"),
        other=(
            "cloud-controller-manager",
            "cluster-autoscaler",
            "csi-azuredisk-controller",
            "csi-azurefile-controller",
            "csi-snapshot-controller",
            "fleet-mcs-controller-manager",
            "fleet-member-agent",
            "fleet-member-net-controller-manager",
            "guard",
            "karpenter-events",
            "kube-apiserver",
            "kube-controller-manager",
            "kube-scheduler",
        ),
        all_logs="carries_audit",
        source=f"{_SUPPORTED_LOGS}microsoft-containerservice-managedclusters-logs",
    ),
}


def diagnostic_log_catalog_entry(resource_type: str) -> AzureDiagnosticLogCatalogEntry | None:
    return _CATALOG.get(resource_type)


def cataloged_resource_types() -> frozenset[str]:
    return frozenset(_CATALOG)


def category_audit_relevance(resource_type: str, category: str) -> CategoryAuditRelevance:
    """Whether one enabled log category carries audit telemetry for the resource type.

    A category the catalog does not list for the type, and any category on an
    unmodeled type, is unresolved rather than non-audit.
    """

    entry = _CATALOG.get(resource_type)
    if entry is None:
        return "unresolved"
    key = category.strip().casefold()
    if key in entry.audit_categories:
        return "audit"
    if key in entry.other_categories:
        return "not_audit"
    return "unresolved"


def category_group_audit_relevance(resource_type: str, group: str) -> CategoryAuditRelevance:
    """Whether an enabled category group carries audit telemetry for the resource type."""

    key = "".join(character for character in group.strip().lower() if character.isalnum())
    if key == "audit":
        return "audit"
    if key != "alllogs":
        return "unresolved"
    entry = _CATALOG.get(resource_type)
    if entry is None or entry.all_logs_state == "unresolved":
        return "unresolved"
    return "audit" if entry.all_logs_state == "carries_audit" else "not_audit"
