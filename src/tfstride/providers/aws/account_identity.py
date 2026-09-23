"""Resource-local AWS account evidence, independent of inventory summaries."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from tfstride.models import NormalizedResource
from tfstride.providers.aws.account_identity_evidence import AwsAccountArnInput, AwsAccountResolution
from tfstride.providers.aws.resource_facts import aws_facts

_ACCOUNT = re.compile(r"[0-9]{12}")
_COMPONENT = re.compile(r"[a-z0-9-]+")
_PARTITION = re.compile(r"aws(?:-[a-z0-9]+)*")
# Creation of these managed resources establishes ownership in the provider's
# account. Attachments, policies on other resources, grants, and data lookups
# must not inherit caller ownership merely because they use its credentials.
_PROVIDER_OWNED_TYPES: dict[str, tuple[frozenset[str], str]] = {
    "aws_iam_role": (frozenset({"iam"}), "role/"),
    "aws_iam_policy": (frozenset({"iam"}), "policy/"),
    "aws_iam_instance_profile": (frozenset({"iam"}), "instance-profile/"),
    "aws_iam_openid_connect_provider": (frozenset({"iam"}), "oidc-provider/"),
    "aws_s3_bucket": (frozenset({"s3"}), ""),
    "aws_kms_key": (frozenset({"kms"}), "key/"),
    "aws_kms_alias": (frozenset({"kms"}), "alias/"),
    "aws_secretsmanager_secret": (frozenset({"secretsmanager"}), "secret:"),
    "aws_sns_topic": (frozenset({"sns"}), ""),
    "aws_sqs_queue": (frozenset({"sqs"}), ""),
    "aws_lambda_function": (frozenset({"lambda"}), "function:"),
    "aws_dynamodb_table": (frozenset({"dynamodb"}), "table/"),
    "aws_api_gateway_rest_api": (frozenset({"apigateway", "execute-api"}), ""),
    "aws_apigatewayv2_api": (frozenset({"apigateway", "execute-api"}), ""),
}


def _arn_identity(value: str, *, label: str, resource_type: str) -> AwsAccountResolution:
    parts = value.split(":", 5)
    if (
        len(parts) != 6
        or parts[0] != "arn"
        or not _PARTITION.fullmatch(parts[1])
        or not _COMPONENT.fullmatch(parts[2])
        or (parts[3] and not _COMPONENT.fullmatch(parts[3]))
        or not parts[5]
        or any(character.isspace() for character in value)
        or any(marker in value for marker in ("*", "?", "${"))
    ):
        return AwsAccountResolution(None, "invalid", uncertainties=(f"{label}: ARN is malformed or not exact",))
    _, partition, service, region, account, name = parts
    expected = _PROVIDER_OWNED_TYPES.get(resource_type)
    if expected and (service not in expected[0] or not name.startswith(expected[1]) or name == expected[1]):
        return AwsAccountResolution(
            None, "invalid", uncertainties=(f"{label}: ARN does not identify this resource type",)
        )
    if service in {"iam", "sts"} and region:
        return AwsAccountResolution(None, "invalid", uncertainties=(f"{label}: IAM/STS ARN has a region",))
    if resource_type == "aws_caller_identity" and not (
        (service == "iam" and (name == "root" or re.fullmatch(r"(?:user|role)/.+", name)))
        or (service == "sts" and re.fullmatch(r"(?:assumed-role/.+/.+|federated-user/.+)", name))
    ):
        return AwsAccountResolution(
            None, "invalid", uncertainties=(f"{label}: ARN does not identify a caller principal",)
        )
    if resource_type == "aws_s3_bucket" and (region or account or "/" in name or ":" in name):
        return AwsAccountResolution(
            None, "invalid", uncertainties=(f"{label}: bucket ARN does not identify an S3 bucket",)
        )
    evidence = (f"{label} = {value}",)
    if account == "aws" and service == "iam" and name.startswith("policy/"):
        return AwsAccountResolution(
            None, "unknown", evidence, (f"{label}: AWS-managed policy has no customer account owner",), partition
        )
    if not account and service in {"s3", "apigateway", "route53"}:
        return AwsAccountResolution(None, "unknown", evidence, (), partition)
    if not _ACCOUNT.fullmatch(account):
        return AwsAccountResolution(
            None, "invalid", evidence, (f"{label}: ARN account must be 12 ASCII digits",), partition
        )
    return AwsAccountResolution(account, "resolved", evidence, (), partition)


def _combine(results: Iterable[AwsAccountResolution], *, require_all: bool, label: str) -> AwsAccountResolution:
    items = tuple(results)
    evidence = tuple(sorted({value for item in items for value in item.evidence}))
    uncertainties = {value for item in items for value in item.uncertainties}
    accounts = {item.account_id for item in items if item.account_id is not None}
    partitions = {item.partition for item in items if item.partition is not None}
    partition = next(iter(partitions)) if len(partitions) == 1 else None
    if any(item.state == "invalid" for item in items):
        return AwsAccountResolution(None, "invalid", evidence, tuple(sorted(uncertainties)), partition)
    if len(accounts) > 1 or len(partitions) > 1 or any(item.state == "ambiguous" for item in items):
        uncertainties.add(f"{label}: conflicting account or partition evidence")
        return AwsAccountResolution(None, "ambiguous", evidence, tuple(sorted(uncertainties)))
    if len(accounts) == 1 and (not require_all or all(item.state == "resolved" for item in items)):
        return AwsAccountResolution(next(iter(accounts)), "resolved", evidence, tuple(sorted(uncertainties)), partition)
    if require_all:
        uncertainties.add(f"{label}: caller account evidence is incomplete")
    return AwsAccountResolution(None, "unknown", evidence, tuple(sorted(uncertainties)), partition)


def _arn_inputs(resource: NormalizedResource) -> list[AwsAccountArnInput]:
    facts = aws_facts(resource)
    if facts.has_account_identity_inputs:
        return facts.account_identity_arn_inputs
    # Hand-built normalized inventories can supply a known own ARN, but cannot
    # assert managed-resource ownership without retained source provenance.
    return [AwsAccountArnInput(field="arn", value=resource.arn, state="known")] if resource.arn else []


def _strong_identity(resource: NormalizedResource) -> AwsAccountResolution:
    results: list[AwsAccountResolution] = []
    for item in _arn_inputs(resource):
        label = f"{resource.address}.{item['field']}"
        if item["state"] != "known" or item["value"] is None:
            state = "unknown" if item["state"] == "unknown" else "invalid"
            results.append(AwsAccountResolution(None, state, uncertainties=(f"{label}: {state} identity evidence",)))
        else:
            results.append(_arn_identity(item["value"], label=label, resource_type=resource.resource_type))
    combined = _combine(results, require_all=False, label=resource.address)
    if combined.state == "resolved" and _has_aws_managed_policy_identity(resource):
        return AwsAccountResolution(
            None,
            "ambiguous",
            combined.evidence,
            tuple(
                sorted(
                    {
                        *combined.uncertainties,
                        f"{resource.address}: customer and AWS-managed policy identities conflict",
                    }
                )
            ),
            combined.partition,
        )
    return combined


def _has_aws_managed_policy_identity(resource: NormalizedResource) -> bool:
    for item in _arn_inputs(resource):
        parts = (item["value"] or "").split(":", 5)
        if len(parts) == 6 and parts[2] == "iam" and parts[4] == "aws" and parts[5].startswith("policy/"):
            return True
    return False


def _caller_identity(resource: NormalizedResource) -> AwsAccountResolution:
    facts = aws_facts(resource)
    state = facts.caller_identity_account_id_state
    account = facts.caller_identity_account_id
    uncertainties = tuple(sorted(facts.caller_identity_posture_uncertainties))
    evidence = tuple(
        sorted(
            {
                f"{resource.address}: caller identity state={state or 'unknown'}, account={account or 'unknown'}",
                *(f"{resource.address}.{item}" for item in facts.caller_identity_account_evidence),
            }
        )
    )
    if state in ("invalid", "ambiguous"):
        return AwsAccountResolution(None, state, evidence, uncertainties)
    if state != "resolved" or account is None:
        return AwsAccountResolution(None, "unknown", evidence, uncertainties)
    if not _ACCOUNT.fullmatch(account):
        return AwsAccountResolution(
            None, "invalid", evidence, (*uncertainties, f"{resource.address}: invalid caller account")
        )
    result = AwsAccountResolution(account, "resolved", evidence, uncertainties)
    # Validate the caller ARN as well as its normalized account state. Some
    # legacy normalized inventories retained only the account-bearing segment.
    if resource.arn:
        return _combine(
            (
                result,
                _arn_identity(resource.arn, label=f"{resource.address}.arn", resource_type=resource.resource_type),
            ),
            require_all=True,
            label=resource.address,
        )
    return result


@dataclass(frozen=True, slots=True)
class AwsAccountIdentityIndex:
    provider_accounts: Mapping[str, AwsAccountResolution]

    def resolve(self, resource: NormalizedResource) -> AwsAccountResolution:
        if resource.provider != "aws":
            return AwsAccountResolution(None, "unknown", uncertainties=("resource is not an AWS resource",))
        if resource.resource_type == "aws_caller_identity":
            return _caller_identity(resource)
        strong = _strong_identity(resource)
        if strong.state != "unknown":
            return strong
        # An AWS-managed IAM policy belongs to AWS even if its declaration
        # accidentally claims managed mode. Caller credentials cannot own it.
        if _has_aws_managed_policy_identity(resource):
            return strong
        source_mode = aws_facts(resource).account_identity_source_mode
        if source_mode != "managed" or resource.resource_type not in _PROVIDER_OWNED_TYPES:
            return _with_reason(
                strong, f"{resource.address}: provider configuration does not establish resource ownership"
            )
        scope = resource.provider_config_key
        if not scope:
            return _with_reason(strong, f"{resource.address}: provider configuration is unknown")
        caller = self.provider_accounts.get(scope)
        if caller is None:
            return _with_reason(
                strong, f"{resource.address}: no caller identity is modeled for provider configuration {scope}"
            )
        evidence = (
            *strong.evidence,
            f"{resource.address}: managed resource uses provider configuration {scope}",
            *caller.evidence,
        )
        uncertainties = set(strong.uncertainties) | set(caller.uncertainties)
        if strong.partition and caller.partition and strong.partition != caller.partition:
            uncertainties.add(f"{resource.address}: resource and scoped caller partitions conflict")
            return AwsAccountResolution(None, "ambiguous", tuple(sorted(evidence)), tuple(sorted(uncertainties)))
        return AwsAccountResolution(
            caller.account_id,
            caller.state,
            tuple(sorted(evidence)),
            tuple(sorted(uncertainties)),
            strong.partition or caller.partition,
        )


def _with_reason(result: AwsAccountResolution, reason: str) -> AwsAccountResolution:
    return AwsAccountResolution(
        result.account_id,
        result.state,
        result.evidence,
        tuple(sorted({*result.uncertainties, reason})),
        result.partition,
    )


def build_aws_account_identity_index(resources: Iterable[NormalizedResource]) -> AwsAccountIdentityIndex:
    grouped: dict[str, list[AwsAccountResolution]] = {}
    for resource in resources:
        if (
            resource.provider == "aws"
            and resource.resource_type == "aws_caller_identity"
            and resource.provider_config_key
        ):
            grouped.setdefault(resource.provider_config_key, []).append(_caller_identity(resource))
    return AwsAccountIdentityIndex(
        MappingProxyType(
            {
                scope: _combine(callers, require_all=True, label=f"provider configuration {scope}")
                for scope, callers in sorted(grouped.items())
            }
        )
    )
