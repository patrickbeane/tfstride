from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.coercion import (
    STATE_DISABLED,
    STATE_ENABLED,
    STATE_UNKNOWN,
    attribute_unknown,
    first_mapping,
    known_block_string,
    known_block_strings,
    known_bool,
    known_string,
)
from tfstride.providers.gcp.attributes import GcpAttr
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer_common import GCP_PROVIDER
from tfstride.providers.kubernetes import dedupe, first_unknown_block


def normalize_workload_identity_pool(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    uncertainties: list[str] = []
    pool_id = _known_identifier(values, resource.unknown_values, GcpAttr.WORKLOAD_IDENTITY_POOL_ID.key, uncertainties)
    resource_id = _known_identifier(values, resource.unknown_values, GcpAttr.ID.key, uncertainties)
    name = known_string(values, resource.unknown_values, GcpAttr.NAME.key, uncertainties) or resource.name
    mode = known_string(values, resource.unknown_values, GcpAttr.MODE.key, uncertainties, require_string=True)
    disabled = known_bool(values, resource.unknown_values, GcpAttr.DISABLED.key, uncertainties, allow_string=False)

    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=resource_id or pool_id or resource.address,
        metadata={
            GcpResourceMetadata.NAME: name,
            GcpResourceMetadata.WORKLOAD_IDENTITY_POOL_ID: pool_id,
            GcpResourceMetadata.WORKLOAD_IDENTITY_POOL_MODE: mode,
            GcpResourceMetadata.WORKLOAD_IDENTITY_POOL_STATE: _disabled_state(disabled),
            GcpResourceMetadata.WORKLOAD_IDENTITY_POOL_POSTURE_UNCERTAINTIES: dedupe(uncertainties),
        },
    )


def normalize_workload_identity_pool_provider(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    provider_id = _known_identifier(
        values,
        unknown_values,
        GcpAttr.WORKLOAD_IDENTITY_POOL_PROVIDER_ID.key,
        uncertainties,
    )
    resource_id = _known_identifier(values, unknown_values, GcpAttr.ID.key, uncertainties)
    pool_id = known_string(
        values,
        unknown_values,
        GcpAttr.WORKLOAD_IDENTITY_POOL_ID.key,
        uncertainties,
        require_string=True,
    )
    name = known_string(values, unknown_values, GcpAttr.NAME.key, uncertainties) or provider_id or resource.name
    disabled = known_bool(values, unknown_values, GcpAttr.DISABLED.key, uncertainties, allow_string=False)

    oidc_values = first_mapping(values.get(GcpAttr.OIDC.key), expand_tuples=True, scan_all=True)
    oidc_unknown = first_unknown_block(unknown_values.get(GcpAttr.OIDC.key))
    aws_values = first_mapping(values.get(GcpAttr.AWS.key), expand_tuples=True, scan_all=True)
    aws_unknown = first_unknown_block(unknown_values.get(GcpAttr.AWS.key))
    provider_type = _provider_type(
        oidc_values is not None or oidc_unknown is True,
        aws_values is not None or aws_unknown is True,
        uncertainties,
    )
    issuer_uri = known_block_string(
        oidc_values,
        oidc_unknown,
        GcpAttr.ISSUER_URI.key,
        uncertainties,
        path=GcpAttr.OIDC.key,
    )
    allowed_audiences = known_block_strings(
        oidc_values,
        oidc_unknown,
        GcpAttr.ALLOWED_AUDIENCES.key,
        uncertainties,
        path=GcpAttr.OIDC.key,
    )
    aws_account_id = known_block_string(
        aws_values,
        aws_unknown,
        GcpAttr.ACCOUNT_ID.key,
        uncertainties,
        path=GcpAttr.AWS.key,
    )
    attribute_mappings = _known_mapping(
        values,
        unknown_values,
        GcpAttr.ATTRIBUTE_MAPPING.key,
        uncertainties,
    )
    attribute_condition = known_string(
        values,
        unknown_values,
        GcpAttr.ATTRIBUTE_CONDITION.key,
        uncertainties,
        require_string=True,
    )

    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=resource_id or provider_id or resource.address,
        metadata={
            GcpResourceMetadata.NAME: name,
            GcpResourceMetadata.WORKLOAD_IDENTITY_POOL_ID: pool_id,
            GcpResourceMetadata.WORKLOAD_IDENTITY_POOL_PROVIDER_ID: provider_id,
            GcpResourceMetadata.WORKLOAD_IDENTITY_POOL_PROVIDER_TYPE: provider_type,
            GcpResourceMetadata.WORKLOAD_IDENTITY_POOL_PROVIDER_STATE: _disabled_state(disabled),
            GcpResourceMetadata.WORKLOAD_IDENTITY_POOL_PROVIDER_ISSUER_URI: issuer_uri,
            GcpResourceMetadata.WORKLOAD_IDENTITY_POOL_PROVIDER_ALLOWED_AUDIENCES: allowed_audiences,
            GcpResourceMetadata.WORKLOAD_IDENTITY_POOL_PROVIDER_ATTRIBUTE_MAPPINGS: attribute_mappings,
            GcpResourceMetadata.WORKLOAD_IDENTITY_POOL_PROVIDER_ATTRIBUTE_CONDITION: attribute_condition,
            GcpResourceMetadata.WORKLOAD_IDENTITY_POOL_PROVIDER_AWS_ACCOUNT_ID: aws_account_id,
            GcpResourceMetadata.WORKLOAD_IDENTITY_POOL_POSTURE_UNCERTAINTIES: dedupe(uncertainties),
        },
    )


def _known_identifier(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any],
    key: str,
    uncertainties: list[str],
) -> str | None:
    return known_string(values, unknown_values, key, uncertainties, require_string=True)


def _disabled_state(value: bool | None) -> str:
    if value is True:
        return STATE_DISABLED
    if value is False:
        return STATE_ENABLED
    return STATE_UNKNOWN


def _provider_type(
    oidc_present: bool,
    aws_present: bool,
    uncertainties: list[str],
) -> str:
    if oidc_present and aws_present:
        uncertainties.append("multiple workload identity provider configurations are present")
        return STATE_UNKNOWN
    if oidc_present:
        return "oidc"
    if aws_present:
        return "aws"
    uncertainties.append("workload identity provider type is unknown after planning")
    return STATE_UNKNOWN


def _known_mapping(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any],
    key: str,
    uncertainties: list[str],
) -> dict[str, Any]:
    if attribute_unknown(unknown_values, key):
        uncertainties.append(f"{key} is unknown after planning")
        return {}
    raw = values.get(key)
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        uncertainties.append(f"{key} has an unrecognized value shape")
        return {}
    return {str(item_key): item_value for item_key, item_value in sorted(raw.items(), key=lambda item: str(item[0]))}
