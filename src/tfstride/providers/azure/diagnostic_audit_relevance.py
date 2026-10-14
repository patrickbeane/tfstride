"""Audit/security relevance matching for enabled diagnostic-setting logs.

Two matchers coexist. The lenient matcher backs the posture rule by looking for
the words "audit" and "security". It stays lenient on purpose: the posture rule
claims a setting "does not clearly enable audit logs", and a wrong claim is
noise on a compliant configuration, so cases the documented category catalog
cannot resolve are accepted rather than flagged. The strict matcher backs
public-workload disruption paths, which need proof, and only knows Web App
categories until it moves to the catalog.
"""

from __future__ import annotations

from tfstride.providers.azure.diagnostic_log_catalog import normalize_category_token
from tfstride.providers.azure.resource_types import AzureResourceType

_AUDIT_SECURITY_CATEGORY_GROUPS = frozenset({"audit", "alllogs"})

# Web App diagnostic categories deterministically include AppServiceAuditLogs.
# Do not generalize allLogs relevance to Function Apps or other Azure targets.
_ALL_LOGS_AUDIT_SECURITY_RESOURCE_TYPES = frozenset(
    {
        AzureResourceType.LINUX_WEB_APP,
        AzureResourceType.WINDOWS_WEB_APP,
    }
)
_AUDIT_SECURITY_CATEGORIES_BY_RESOURCE_TYPE = {
    AzureResourceType.LINUX_WEB_APP: frozenset({"appserviceauditlogs"}),
    AzureResourceType.WINDOWS_WEB_APP: frozenset({"appserviceauditlogs"}),
}


def lenient_is_audit_or_security_category(value: str) -> bool:
    normalized = normalize_category_token(value)
    return "audit" in normalized or "security" in normalized


def lenient_is_audit_or_security_category_group(value: str) -> bool:
    normalized = normalize_category_token(value)
    return normalized in _AUDIT_SECURITY_CATEGORY_GROUPS or "audit" in normalized or "security" in normalized


def strict_is_audit_or_security_category(value: str, monitored_resource_type: str) -> bool:
    supported = _AUDIT_SECURITY_CATEGORIES_BY_RESOURCE_TYPE.get(
        monitored_resource_type,
        frozenset(),
    )
    return value.strip().casefold() in supported


def strict_is_audit_or_security_category_group(value: str, monitored_resource_type: str) -> bool:
    normalized = normalize_category_token(value)
    if normalized == "audit":
        return True
    return normalized == "alllogs" and monitored_resource_type in _ALL_LOGS_AUDIT_SECURITY_RESOURCE_TYPES
