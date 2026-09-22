from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from tfstride.models import IAMPolicyStatement, NormalizedResource, TerraformResource
from tfstride.providers.aws.policy_documents import parse_policy_statements, policy_statement_is_fully_representable
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.coercion import STATE_CONFIGURED, STATE_NOT_CONFIGURED, STATE_UNKNOWN, attribute_unknown
from tfstride.providers.json_documents import load_json_document

S3PrincipalMatch = Literal["role", "account", "wildcard", "unknown"]


def s3_bucket_policy_details(
    resource: TerraformResource,
    *,
    allow_absent: bool,
) -> tuple[list[IAMPolicyStatement], dict[str, Any], str, str, list[str]]:
    if attribute_unknown(resource.unknown_values, "policy"):
        return [], {}, STATE_UNKNOWN, STATE_UNKNOWN, ["bucket policy is unknown after planning"]
    raw = resource.values.get("policy")
    if raw in (None, "") and allow_absent:
        return [], {}, STATE_NOT_CONFIGURED, "complete", []
    document = load_json_document(raw)
    raw_statements = document.get("Statement")
    if isinstance(raw_statements, Mapping):
        statement_documents = [raw_statements]
    elif isinstance(raw_statements, list) and all(isinstance(statement, Mapping) for statement in raw_statements):
        statement_documents = raw_statements
    else:
        return [], document, STATE_CONFIGURED, STATE_UNKNOWN, ["bucket policy is missing or malformed"]
    try:
        statements = parse_policy_statements(document)
        complete = (
            bool(statement_documents)
            and len(statements) == len(statement_documents)
            and all(
                policy_statement_is_fully_representable(raw_statement, statement, principal_mode="required")
                for raw_statement, statement in zip(statement_documents, statements, strict=True)
            )
        )
    except (TypeError, ValueError, AttributeError):
        return [], document, STATE_CONFIGURED, STATE_UNKNOWN, ["bucket policy has malformed statements"]
    return (
        statements,
        document,
        STATE_CONFIGURED,
        "complete" if complete else STATE_UNKNOWN,
        [] if complete else ["bucket policy contains incomplete or unsupported statements"],
    )


@dataclass(frozen=True, slots=True)
class S3BucketPolicySources:
    sources: tuple[NormalizedResource, ...]
    unresolved_sources: tuple[NormalizedResource, ...]
    source_addresses: tuple[str, ...]
    complete: bool
    uncertainties: tuple[str, ...]


def prepare_s3_bucket_policy_sources(
    resources: list[NormalizedResource],
    context: AwsDecorationContext,
) -> dict[str, S3BucketPolicySources]:
    """Read decorated source associations once, preserving ambiguous targets as constraints."""
    buckets = [resource for resource in resources if resource.resource_type == "aws_s3_bucket"]
    unresolved: dict[str, list[NormalizedResource]] = {bucket.address: [] for bucket in buckets}
    for source in resources:
        if source.resource_type != "aws_s3_bucket_policy":
            continue
        target = aws_facts(source).bucket_name
        resolution = context.index.buckets.resolve(target, source=source)
        if len(resolution.candidates) == 1:
            continue
        candidate_addresses = {candidate.address for candidate in resolution.candidates}
        if not candidate_addresses and target:
            # Missing provider scope is uncertainty, not evidence that a same-named bucket is absent.
            candidate_addresses = {
                candidate.address
                for candidate in context.index.buckets.resolve(target).candidates
                if candidate.provider_config_key is None or source.provider_config_key is None
            }
        if not candidate_addresses and _exact_bucket_reference(target):
            continue
        for bucket in buckets:
            if candidate_addresses:
                if bucket.address not in candidate_addresses:
                    continue
            elif (
                source.provider_config_key is not None
                and bucket.provider_config_key is not None
                and source.provider_config_key != bucket.provider_config_key
            ):
                continue
            unresolved[bucket.address].append(source)

    result: dict[str, S3BucketPolicySources] = {}
    for bucket in buckets:
        facts = aws_facts(bucket)
        addresses = set(facts.resource_policy_source_addresses)
        sources: list[NormalizedResource] = []
        uncertainties: list[str] = []
        if facts.s3_bucket_policy_state != STATE_NOT_CONFIGURED:
            addresses.add(bucket.address)
            sources.append(bucket)
        for address in sorted(addresses - {bucket.address}):
            source = context.index.resources_by_address.get(address)
            if source is None or source.resource_type != "aws_s3_bucket_policy":
                uncertainties.append(f"{bucket.address}: bucket-policy source {address} is unavailable")
            else:
                sources.append(source)
        for source in sources:
            source_facts = aws_facts(source)
            if source_facts.s3_bucket_policy_completeness_state != "complete":
                details = source_facts.s3_bucket_policy_uncertainties or ["bucket-policy completeness is unresolved"]
                uncertainties.extend(f"{source.address}: {detail}" for detail in details)
        if len(addresses) > 1:
            uncertainties.append(
                f"{bucket.address}: multiple bucket-policy sources provide conflicting authoritative evidence"
            )
        result[bucket.address] = S3BucketPolicySources(
            sources=tuple(sorted(sources, key=lambda source: source.address)),
            unresolved_sources=tuple(sorted(unresolved[bucket.address], key=lambda source: source.address)),
            source_addresses=tuple(sorted(addresses)),
            complete=not uncertainties,
            uncertainties=tuple(uncertainties),
        )
    return result


def _exact_bucket_reference(value: str | None) -> bool:
    if not value or value.startswith(("module.", "aws_s3_bucket.", "${")):
        return False
    if ":s3:::" in value:
        value = value.partition(":s3:::")[2]
    return re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", value) is not None


def s3_bucket_principal_match(statement: IAMPolicyStatement, role_arn: str | None) -> S3PrincipalMatch | None:
    """Match the runtime role; session names and unmapped principal kinds stay uncertain."""
    role_parts = role_arn.split(":", 5) if role_arn else []
    exact_role = (
        len(role_parts) == 6 and role_parts[0] == "arn" and role_parts[2] == "iam" and role_parts[5].startswith("role/")
    )
    matches: set[S3PrincipalMatch] = set()
    for principal in statement.principal_entries:
        kind, value = principal.kind.casefold(), principal.value
        if kind in {"service", "federated"}:
            continue
        if kind not in {"aws", "unknown"}:
            matches.add("unknown")
            continue
        if value == "*":
            matches.add("wildcard")
            continue
        if not exact_role:
            matches.add("unknown")
            continue
        partition, account = role_parts[1], role_parts[4]
        if value == role_arn:
            matches.add("role")
        elif value in {account, f"arn:{partition}:iam::{account}:root"}:
            matches.add("account")
        elif re.fullmatch(r"\d{12}", value):
            continue
        else:
            parts = value.split(":", 5)
            if len(parts) == 6 and parts[0] == "arn" and "*" not in value and "?" not in value:
                if parts[1] != partition or parts[4] != account:
                    continue
                if parts[2] == "iam" and parts[5].startswith(("role/", "user/")):
                    continue
                if parts[2] == "sts" and parts[5].startswith("assumed-role/"):
                    session_role = parts[5].split("/")[1]
                    if session_role != role_parts[5].rsplit("/", 1)[-1]:
                        continue
            matches.add("unknown")
    return next((match for match in ("role", "account", "wildcard", "unknown") if match in matches), None)
