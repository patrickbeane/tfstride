from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.aws.account_identity_evidence import AwsAccountArnInput
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.network_normalizers import AWS_PROVIDER
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.coercion import attribute_unknown, known_string
from tfstride.providers.normalization import ResourceNormalizer
from tfstride.resource_helpers import parse_aws_account_id

_STATE_RESOLVED = "resolved"
_STATE_AMBIGUOUS = "ambiguous"
_STATE_INVALID = "invalid"
_STATE_UNKNOWN = "unknown"


def with_account_identity_inputs(normalizer: ResourceNormalizer) -> ResourceNormalizer:
    """Retain own-identity provenance before normalization loses mode/unknowns.

    Related identities (role_arn, resource_arn, etc.) are deliberately excluded:
    credentials and reference targets do not establish this resource's owner.
    """

    def normalize(resource: TerraformResource) -> NormalizedResource:
        normalized = normalizer(resource)
        inputs: list[AwsAccountArnInput] = []
        fields = ["arn", "id"]
        if resource.resource_type in {"aws_api_gateway_rest_api", "aws_apigatewayv2_api"}:
            fields.append("execution_arn")
        for field in fields:
            value = resource.values.get(field)
            if attribute_unknown(resource.unknown_values, field):
                inputs.append(AwsAccountArnInput(field=field, value=None, state="unknown"))
            elif field == "id" and not (isinstance(value, str) and value.startswith("arn:")):
                continue
            elif value is not None:
                inputs.append(
                    AwsAccountArnInput(
                        field=field,
                        value=value if isinstance(value, str) else None,
                        state="known" if isinstance(value, str) else "invalid",
                    )
                )
        aws_facts(normalized).set_account_identity_inputs(resource.mode, inputs)
        return normalized

    return normalize


def normalize_caller_identity(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    account_id, account_candidate, account_invalid = _caller_account_evidence(
        values,
        unknown_values,
        "account_id",
        uncertainties,
        allow_bare=True,
    )
    identifier, identifier_candidate, identifier_invalid = _caller_account_evidence(
        values,
        unknown_values,
        "id",
        uncertainties,
        allow_bare=True,
    )
    arn, arn_candidate, arn_invalid = _caller_account_evidence(
        values,
        unknown_values,
        "arn",
        uncertainties,
        allow_bare=False,
    )
    user_id = known_string(values, unknown_values, "user_id", uncertainties, require_string=True)

    account_candidates = {
        candidate
        for candidate in (
            account_candidate,
            identifier_candidate,
            arn_candidate,
        )
        if candidate is not None
    }
    if account_invalid or identifier_invalid or arn_invalid:
        resolved_account_id = None
        account_id_state = _STATE_INVALID
    elif len(account_candidates) > 1:
        resolved_account_id = None
        account_id_state = _STATE_AMBIGUOUS
        uncertainties.append("aws_caller_identity account_id, id, and arn contain conflicting AWS account IDs")
    elif len(account_candidates) == 1:
        resolved_account_id = next(iter(account_candidates))
        account_id_state = _STATE_RESOLVED
    else:
        resolved_account_id = None
        account_id_state = _STATE_UNKNOWN

    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=resolved_account_id or arn or account_id or identifier or resource.address,
        arn=arn,
        metadata={
            AwsResourceMetadata.CALLER_IDENTITY_ACCOUNT_ID: resolved_account_id,
            AwsResourceMetadata.CALLER_IDENTITY_ACCOUNT_ID_STATE: account_id_state,
            AwsResourceMetadata.CALLER_IDENTITY_ACCOUNT_EVIDENCE: [
                f"{field} = {value}"
                for field, value in (("account_id", account_id), ("id", identifier), ("arn", arn))
                if value is not None
            ],
            AwsResourceMetadata.CALLER_IDENTITY_USER_ID: user_id,
            AwsResourceMetadata.CALLER_IDENTITY_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def _caller_account_evidence(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    field: str,
    uncertainties: list[str],
    *,
    allow_bare: bool,
) -> tuple[str | None, str | None, bool]:
    value = known_string(
        values,
        unknown_values,
        field,
        uncertainties,
        require_string=True,
    )
    if value is None:
        if attribute_unknown(unknown_values, field):
            return None, None, False
        raw_value = values.get(field)
        return None, None, raw_value is not None

    account_id = parse_aws_account_id(value, allow_bare=allow_bare)
    if account_id is not None:
        return value, account_id, False

    uncertainties.append(f"{field} does not contain a valid 12-digit AWS account ID")
    return value, None, True
