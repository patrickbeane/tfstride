"""Audit/security relevance matching for enabled diagnostic-setting logs.

The lenient matcher backs the posture rule by looking for the words "audit"
and "security". It stays lenient on purpose: the posture rule claims a setting "does not clearly enable audit logs", and a wrong claim is
noise on a compliant configuration, so cases the documented category catalog
cannot resolve are accepted rather than flagged. Public-workload disruption
paths need proof instead, so they use the documented category catalog directly.
"""

from __future__ import annotations

from tfstride.providers.azure.diagnostic_log_catalog import normalize_category_token

_AUDIT_SECURITY_CATEGORY_GROUPS = frozenset({"audit", "alllogs"})


def lenient_is_audit_or_security_category(value: str) -> bool:
    normalized = normalize_category_token(value)
    return "audit" in normalized or "security" in normalized


def lenient_is_audit_or_security_category_group(value: str) -> bool:
    normalized = normalize_category_token(value)
    return normalized in _AUDIT_SECURITY_CATEGORY_GROUPS or "audit" in normalized or "security" in normalized
