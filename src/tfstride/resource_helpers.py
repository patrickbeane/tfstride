from __future__ import annotations

from typing import Any, Mapping

from tfstride.models import NormalizedResource, SecurityGroupRule


def policy_allows_public_access(policy_document: Mapping[str, Any] | None) -> bool:
    if not isinstance(policy_document, Mapping):
        return False

    raw_statements = policy_document.get("Statement", [])
    if isinstance(raw_statements, Mapping):
        raw_statements = [raw_statements]
    elif not isinstance(raw_statements, list):
        raw_statements = [raw_statements]

    for statement in raw_statements:
        if not isinstance(statement, Mapping):
            continue
        if str(statement.get("Effect", "Allow")) != "Allow":
            continue
        if _principal_allows_public_access(statement.get("Principal")):
            return True
    return False


def describe_security_group_rule(security_group: NormalizedResource, rule: SecurityGroupRule) -> str:
    port_range = format_port_range(rule)
    sources = list(rule.cidr_blocks) + list(rule.ipv6_cidr_blocks)
    if rule.referenced_security_group_ids:
        sources.extend(rule.referenced_security_group_ids)
    source_text = ", ".join(sorted(sources)) if sources else "unspecified sources"
    description = f"{security_group.address} {rule.direction} {rule.protocol} {port_range} from {source_text}"
    if rule.description:
        return f"{description} ({rule.description})"
    return description


def format_port_range(rule: SecurityGroupRule) -> str:
    if rule.protocol == "-1":
        return "all ports"
    if rule.from_port is None or rule.to_port is None:
        return "unspecified ports"
    if rule.from_port == rule.to_port:
        return str(rule.from_port)
    return f"{rule.from_port}-{rule.to_port}"


def parse_aws_account_id(value: str | None, *, allow_bare: bool = False) -> str | None:
    if not value:
        return None
    text = value.strip()
    if allow_bare and text.isdigit() and len(text) == 12:
        return text
    if not text.startswith("arn:"):
        return None
    parts = text.split(":")
    if len(parts) < 5:
        return None
    return parts[4] or None


def _principal_allows_public_access(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, str):
        return principal == "*"
    if isinstance(principal, Mapping):
        return any(_principal_allows_public_access(value) for value in principal.values())
    if isinstance(principal, list):
        return any(_principal_allows_public_access(item) for item in principal)
    return False