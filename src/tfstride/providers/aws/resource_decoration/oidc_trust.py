from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext

_WEB_IDENTITY_ACTION = "sts:assumerolewithwebidentity"


class ResolveOidcProviderTrustStage:
    name = "resolve_oidc_provider_trust"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        for role in resources:
            if role.resource_type != "aws_iam_role":
                continue
            statements = [
                _resolve_trust_statement(statement, context) for statement in aws_facts(role).trust_statements
            ]
            aws_facts(role).set_trust_statements(statements)


def _resolve_trust_statement(
    trust_statement: dict[str, Any],
    context: AwsDecorationContext,
) -> dict[str, Any]:
    resolved_statement = dict(trust_statement)
    if _WEB_IDENTITY_ACTION not in {action.lower() for action in _string_list(trust_statement.get("actions"))}:
        return resolved_statement

    raw_entries = trust_statement.get("principal_entries")
    if not isinstance(raw_entries, list):
        return resolved_statement

    resolved_entries: list[dict[str, Any]] = []
    principal_replacements: dict[str, str] = {}
    resolved_providers: list[dict[str, str | None]] = []
    unresolved_references: list[str] = []

    for raw_entry in raw_entries:
        if not isinstance(raw_entry, Mapping):
            continue
        entry = dict(raw_entry)
        source_value = str(entry.get("value") or "").strip()
        kind = str(entry.get("kind") or "").strip().lower()
        if kind != "federated" or not source_value:
            resolved_entries.append(entry)
            continue

        provider = context.index.oidc_provider_index.get(_unwrap_exact_interpolation(source_value))
        if provider is None:
            if _looks_like_oidc_provider_reference(source_value):
                unresolved_references.append(source_value)
            resolved_entries.append(entry)
            continue

        provider_arn = aws_facts(provider).oidc_provider_arn or provider.arn
        resolved_principal = provider_arn or source_value
        if provider_arn:
            entry["value"] = provider_arn
            principal_replacements[source_value] = provider_arn
        resolved_entries.append(entry)
        resolved_providers.append(
            {
                "address": provider.address,
                "arn": provider_arn,
                "principal": resolved_principal,
                "reference": source_value,
                "url": aws_facts(provider).oidc_provider_url,
            }
        )
        if provider_arn is None:
            unresolved_references.append(source_value)

    resolved_statement["principal_entries"] = resolved_entries
    resolved_statement["principals"] = sorted(
        {
            principal_replacements.get(principal, principal)
            for principal in _string_list(trust_statement.get("principals"))
        }
    )
    if resolved_providers:
        resolved_statement["resolved_oidc_providers"] = _dedupe_provider_records(resolved_providers)
    if unresolved_references:
        resolved_statement["unresolved_oidc_provider_references"] = sorted(set(unresolved_references))
    return resolved_statement


def _unwrap_exact_interpolation(value: str) -> str:
    stripped = value.strip()
    if stripped.startswith("$" + "{") and stripped.endswith("}"):
        return stripped[2:-1].strip()
    return stripped


def _looks_like_oidc_provider_reference(value: str) -> bool:
    reference = _unwrap_exact_interpolation(value)
    return reference.endswith(".arn") and (
        reference.startswith("aws_iam_openid_connect_provider.") or ".aws_iam_openid_connect_provider." in reference
    )


def _string_list(value: object) -> list[str]:
    values = value if isinstance(value, list) else [value]
    return [str(item).strip() for item in values if item not in (None, "") and str(item).strip()]


def _dedupe_provider_records(
    records: list[dict[str, str | None]],
) -> list[dict[str, str | None]]:
    deduped: list[dict[str, str | None]] = []
    seen: set[tuple[str | None, str | None]] = set()
    for record in records:
        key = (record.get("address"), record.get("principal"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(record)
    return deduped
