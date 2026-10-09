"""Audit/security relevance matching for Cloud Logging filters.

Two matchers coexist while callers are unified: the lenient matcher backs the
posture rules and reports which audit/security streams a filter mentions, and
the strict matcher backs public-workload disruption paths and only accepts a
filter that is exactly one positive audit/security term.
"""

from __future__ import annotations

import re

_LENIENT_AUDIT_SECURITY_FILTER_SIGNALS = (
    ("cloudaudit.googleapis.com", "matches Cloud Audit Logs"),
    ("google.cloud.audit.auditlog", "matches AuditLog proto payloads"),
    ("protopayload.@type", "matches protoPayload audit log records"),
    ("protopayload.servicename", "matches service audit payloads"),
    ("securitycenter.googleapis.com", "matches Security Command Center logs"),
    ("security_command_center", "matches Security Command Center logs"),
    ("securitycenter", "matches security center logs"),
    ('resource.type="gce_firewall_rule"', "matches firewall rule logs"),
    ("resource.type=gce_firewall_rule", "matches firewall rule logs"),
)

_NEGATIVE_FILTER_OPERATOR_PATTERN = re.compile(
    r"(?:\bnot\b|!=|!~|(?:^|[\s(])-\s*)",
    re.IGNORECASE,
)

_STRICT_AUDIT_SECURITY_FILTER_PATTERNS = (
    (
        "cloudaudit.googleapis.com",
        re.compile(
            r'logname\s*(?::|=|=~)\s*(?:"(?:projects/[^"/\s]+/logs/)?cloudaudit\.googleapis\.com(?:%2f[^"]+)?"|(?:projects/[^\s()/]+/logs/)?cloudaudit\.googleapis\.com(?:%2f[^\s()]+)?)'
        ),
    ),
    (
        "google.cloud.audit.auditlog",
        re.compile(
            r'protopayload\.@type\s*(?::|=|=~)\s*(?:"(?:type\.googleapis\.com/)?google\.cloud\.audit\.auditlog"|(?:type\.googleapis\.com/)?google\.cloud\.audit\.auditlog)(?=$|[\s)])'
        ),
    ),
    (
        "securitycenter.googleapis.com",
        re.compile(
            r'logname\s*(?::|=|=~)\s*(?:"(?:projects/[^"/\s]+/logs/)?securitycenter\.googleapis\.com(?:%2f[^"]+)?"|(?:projects/[^\s()/]+/logs/)?securitycenter\.googleapis\.com(?:%2f[^\s()]+)?)'
        ),
    ),
    (
        "security_command_center",
        re.compile(r'resource\.type\s*(?::|=|=~)\s*(?:"security_command_center"|security_command_center)(?=$|[\s)])'),
    ),
    (
        "securitycenter",
        re.compile(r'resource\.type\s*(?::|=|=~)\s*(?:"securitycenter"|securitycenter)(?=$|[\s)])'),
    ),
    (
        'resource.type="gce_firewall_rule"',
        re.compile(r'resource\.type\s*(?::|=|=~)\s*(?:"gce_firewall_rule"|gce_firewall_rule)(?=$|[\s)])'),
    ),
)


def normalize_logging_filter(filter_text: str) -> str:
    return " ".join(filter_text.lower().replace(chr(39), chr(34)).split())


def lenient_audit_security_filter_signals(filter_text: str | None) -> list[str]:
    if not filter_text:
        return []
    normalized = normalize_logging_filter(filter_text)
    return [description for signal, description in _LENIENT_AUDIT_SECURITY_FILTER_SIGNALS if signal in normalized]


def strict_audit_security_filter_signals(filter_text: str) -> list[str]:
    normalized = normalize_logging_filter(filter_text)
    if _NEGATIVE_FILTER_OPERATOR_PATTERN.search(normalized):
        return []
    return [
        signal
        for signal, pattern in _STRICT_AUDIT_SECURITY_FILTER_PATTERNS
        if pattern.fullmatch(normalized) is not None
    ]
