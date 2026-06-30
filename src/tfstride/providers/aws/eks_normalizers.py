from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.network_normalizers import AWS_PROVIDER
from tfstride.providers.coercion import (
    as_list,
    block_attribute_unknown,
    compact_strings,
    first_mapping,
    known_block_bool,
    known_block_string,
    known_block_strings,
    known_bool,
    known_string,
    known_string_list,
)
from tfstride.providers.kubernetes import block_value, dedupe, first_unknown_block, unknown_block_at_index

_STATE_ENABLED = "enabled"
_STATE_DISABLED = "disabled"
_STATE_CONFIGURED = "configured"
_STATE_NOT_CONFIGURED = "not_configured"
_STATE_UNKNOWN = "unknown"
_EKS_ADDON_TARGET_CLASSES = {
    "vpc-cni": "networking",
    "coredns": "dns",
    "kube-proxy": "node-proxy",
    "aws-ebs-csi-driver": "storage-csi",
}


def normalize_eks_cluster(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    cluster_name = known_string(values, unknown_values, "name", uncertainties) or resource.name
    cluster_arn = known_string(values, unknown_values, "arn", uncertainties)
    role_arn = known_string(values, unknown_values, "role_arn", uncertainties)
    vpc_config = first_mapping(values.get("vpc_config"), scan_all=True)
    vpc_unknown = first_unknown_block(unknown_values.get("vpc_config"))
    access_config = first_mapping(values.get("access_config"), scan_all=True)
    access_unknown = first_unknown_block(unknown_values.get("access_config"))
    public_access_cidrs = known_block_strings(
        vpc_config,
        vpc_unknown,
        "public_access_cidrs",
        uncertainties,
        path="vpc_config",
    )
    subnet_ids = known_block_strings(vpc_config, vpc_unknown, "subnet_ids", uncertainties, path="vpc_config")
    security_group_ids = known_block_strings(
        vpc_config,
        vpc_unknown,
        "security_group_ids",
        uncertainties,
        path="vpc_config",
    )
    log_types = known_string_list(
        values,
        unknown_values,
        "enabled_cluster_log_types",
        uncertainties,
    )
    encryption_config = _encryption_config(resource, uncertainties)
    encryption_resources = _encryption_resources(encryption_config)
    encryption_key_arn = _first_non_empty(record.get("key_arn") for record in encryption_config)
    endpoint_public_access_state = _block_bool_state(
        vpc_config,
        vpc_unknown,
        "endpoint_public_access",
        uncertainties,
        path="vpc_config",
    )

    metadata: dict[Any, Any] = {
        AwsResourceMetadata.NAME: cluster_name,
        AwsResourceMetadata.EKS_CLUSTER_ARN: cluster_arn,
        AwsResourceMetadata.EKS_CLUSTER_ROLE_ARN: role_arn,
        AwsResourceMetadata.EKS_KUBERNETES_VERSION: known_string(values, unknown_values, "version", uncertainties),
        AwsResourceMetadata.EKS_ENDPOINT_PUBLIC_ACCESS_STATE: endpoint_public_access_state,
        AwsResourceMetadata.EKS_ENDPOINT_PRIVATE_ACCESS_STATE: _block_bool_state(
            vpc_config,
            vpc_unknown,
            "endpoint_private_access",
            uncertainties,
            path="vpc_config",
        ),
        AwsResourceMetadata.EKS_PUBLIC_ACCESS_CIDRS: public_access_cidrs,
        AwsResourceMetadata.EKS_PUBLIC_ACCESS_CIDRS_STATE: _block_list_config_state(
            public_access_cidrs,
            vpc_config,
            vpc_unknown,
            "public_access_cidrs",
        ),
        AwsResourceMetadata.EKS_SUBNET_IDS: subnet_ids,
        AwsResourceMetadata.EKS_SECURITY_GROUP_IDS: security_group_ids,
        AwsResourceMetadata.EKS_CLUSTER_SECURITY_GROUP_ID: known_block_string(
            vpc_config,
            vpc_unknown,
            "cluster_security_group_id",
            uncertainties,
            path="vpc_config",
        ),
        AwsResourceMetadata.EKS_VPC_CONFIG: dict(vpc_config) if vpc_config is not None else None,
        AwsResourceMetadata.EKS_ENABLED_CLUSTER_LOG_TYPES: log_types,
        AwsResourceMetadata.EKS_CONTROL_PLANE_LOGGING_STATE: _top_level_list_config_state(
            unknown_values,
            "enabled_cluster_log_types",
            log_types,
        ),
        AwsResourceMetadata.EKS_ENCRYPTION_CONFIG: encryption_config,
        AwsResourceMetadata.EKS_ENCRYPTION_CONFIG_STATE: _record_config_state(
            encryption_config,
            unknown_values.get("encryption_config"),
        ),
        AwsResourceMetadata.EKS_SECRETS_ENCRYPTION_STATE: _secrets_encryption_state(
            encryption_config,
            unknown_values.get("encryption_config"),
        ),
        AwsResourceMetadata.EKS_ENCRYPTION_KEY_ARN: encryption_key_arn,
        AwsResourceMetadata.EKS_ENCRYPTION_RESOURCES: encryption_resources,
        AwsResourceMetadata.EKS_ACCESS_CONFIG_STATE: _block_config_state(access_config, access_unknown),
        AwsResourceMetadata.EKS_AUTHENTICATION_MODE: known_block_string(
            access_config,
            access_unknown,
            "authentication_mode",
            uncertainties,
            path="access_config",
        ),
        AwsResourceMetadata.EKS_BOOTSTRAP_CLUSTER_CREATOR_ADMIN_PERMISSIONS_STATE: _block_bool_state(
            access_config,
            access_unknown,
            "bootstrap_cluster_creator_admin_permissions",
            uncertainties,
            path="access_config",
        ),
        AwsResourceMetadata.EKS_ACCESS_CONFIG: dict(access_config) if access_config is not None else None,
    }
    if uncertainties:
        metadata[AwsResourceMetadata.EKS_POSTURE_UNCERTAINTIES] = dedupe(uncertainties)

    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.COMPUTE,
        identifier=cluster_name or values.get("id") or resource.address,
        arn=cluster_arn,
        subnet_ids=tuple(subnet_ids),
        security_group_ids=tuple(security_group_ids),
        attached_role_arns=compact_strings([role_arn]),
        public_access_configured=endpoint_public_access_state == _STATE_ENABLED,
        metadata=metadata,
    )


def normalize_eks_addon(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    addon_name = known_string(values, unknown_values, "addon_name", uncertainties)
    cluster_name = known_string(values, unknown_values, "cluster_name", uncertainties)
    addon_version = known_string(values, unknown_values, "addon_version", uncertainties)
    configuration_values = known_string(
        values,
        unknown_values,
        "configuration_values",
        uncertainties,
        require_string=True,
    )
    preserve_state = _top_level_bool_state(values, unknown_values, "preserve", uncertainties)
    service_account_role_arn = known_string(values, unknown_values, "service_account_role_arn", uncertainties)

    metadata: dict[Any, Any] = {
        AwsResourceMetadata.NAME: addon_name or resource.name,
        AwsResourceMetadata.EKS_ADDON_NAME: addon_name,
        AwsResourceMetadata.EKS_ADDON_CLUSTER_NAME: cluster_name,
        AwsResourceMetadata.EKS_ADDON_VERSION: addon_version,
        AwsResourceMetadata.EKS_ADDON_CONFIGURATION_VALUES: configuration_values,
        AwsResourceMetadata.EKS_ADDON_CONFIGURATION_KEYS: _configuration_keys(configuration_values, uncertainties),
        AwsResourceMetadata.EKS_ADDON_PRESERVE_STATE: preserve_state,
        AwsResourceMetadata.EKS_ADDON_SERVICE_ACCOUNT_ROLE_ARN: service_account_role_arn,
        AwsResourceMetadata.EKS_ADDON_TARGET_CLASS: _addon_target_class(addon_name),
    }
    if uncertainties:
        metadata[AwsResourceMetadata.EKS_POSTURE_UNCERTAINTIES] = dedupe(uncertainties)

    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.COMPUTE,
        identifier=addon_name or values.get("id") or resource.address,
        attached_role_arns=compact_strings([service_account_role_arn]),
        metadata=metadata,
    )


def _block_bool_state(
    block: Mapping[str, Any] | None,
    unknown_block: Any,
    key: str,
    uncertainties: list[str],
    *,
    path: str,
) -> str:
    value = known_block_bool(block, unknown_block, key, uncertainties, path=path)
    if value is None:
        return _STATE_UNKNOWN
    return _STATE_ENABLED if value else _STATE_DISABLED


def _block_config_state(block: Mapping[str, Any] | None, unknown_block: Any) -> str:
    if unknown_block is True and block is None:
        return _STATE_UNKNOWN
    return _STATE_CONFIGURED if block else _STATE_NOT_CONFIGURED


def _top_level_bool_state(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any],
    key: str,
    uncertainties: list[str],
) -> str | None:
    value = known_bool(values, unknown_values, key, uncertainties)
    if value is None:
        return _STATE_UNKNOWN if block_attribute_unknown(unknown_values, key) else None
    return _STATE_ENABLED if value else _STATE_DISABLED


def _block_list_config_state(
    values: list[str],
    block: Mapping[str, Any] | None,
    unknown_block: Any,
    key: str,
) -> str:
    if block_attribute_unknown(unknown_block, key):
        return _STATE_UNKNOWN
    if block is None:
        return _STATE_UNKNOWN
    return _STATE_CONFIGURED if values else _STATE_NOT_CONFIGURED


def _top_level_list_config_state(
    unknown_values: Mapping[str, Any],
    key: str,
    list_values: list[str],
) -> str:
    if block_attribute_unknown(unknown_values, key):
        return _STATE_UNKNOWN
    return _STATE_CONFIGURED if list_values else _STATE_NOT_CONFIGURED


def _record_config_state(records: list[dict[str, Any]], unknown_block: Any) -> str:
    if unknown_block is True and not records:
        return _STATE_UNKNOWN
    return _STATE_CONFIGURED if records else _STATE_NOT_CONFIGURED


def _secrets_encryption_state(records: list[dict[str, Any]], unknown_block: Any) -> str:
    if unknown_block is True and not records:
        return _STATE_UNKNOWN
    resources_unknown = _encryption_resources_unknown(unknown_block)
    for record in records:
        resources = {str(value).strip().lower() for value in record.get("resources", [])}
        if "secrets" in resources:
            return _STATE_ENABLED
    return _STATE_UNKNOWN if resources_unknown else _STATE_DISABLED


def _encryption_config(resource: TerraformResource, uncertainties: list[str]) -> list[dict[str, Any]]:
    raw_unknown = resource.unknown_values.get("encryption_config")
    raw_config = resource.values.get("encryption_config")
    if raw_unknown is True and not raw_config:
        uncertainties.append("encryption_config is unknown after planning")
        return []

    records: list[dict[str, Any]] = []
    for index, item in enumerate(as_list(raw_config)):
        if not isinstance(item, Mapping):
            if item is not None:
                uncertainties.append(f"encryption_config[{index}] has an unrecognized value shape")
            continue
        path = f"encryption_config[{index}]"
        unknown_item = unknown_block_at_index(raw_unknown, index, mapping_applies_to_any_index=True)
        provider = first_mapping(item.get("provider"), scan_all=True)
        provider_unknown = first_unknown_block(block_value(unknown_item, "provider"))
        key_arn = known_block_string(provider, provider_unknown, "key_arn", uncertainties, path=f"{path}.provider")
        resources = known_block_strings(item, unknown_item, "resources", uncertainties, path=path)
        record: dict[str, Any] = {}
        if key_arn:
            record["key_arn"] = key_arn
        if resources:
            record["resources"] = resources
        records.append(record)
    return records


def _encryption_resources(records: list[dict[str, Any]]) -> list[str]:
    return dedupe(value for record in records for value in record.get("resources", []))


def _encryption_resources_unknown(unknown_block: Any) -> bool:
    if unknown_block is True:
        return True
    for item in as_list(unknown_block):
        if item is True:
            return True
        if isinstance(item, Mapping) and block_attribute_unknown(item, "resources"):
            return True
    return False


def _configuration_keys(configuration_values: str | None, uncertainties: list[str]) -> list[str]:
    if not configuration_values:
        return []
    try:
        parsed = json.loads(configuration_values)
    except json.JSONDecodeError:
        uncertainties.append("configuration_values is not valid JSON")
        return []
    if not isinstance(parsed, Mapping):
        uncertainties.append("configuration_values has an unrecognized JSON shape")
        return []
    return sorted(str(key) for key in parsed)


def _addon_target_class(addon_name: str | None) -> str | None:
    if addon_name is None:
        return None
    return _EKS_ADDON_TARGET_CLASSES.get(addon_name.strip().lower())


def _first_non_empty(values: Any) -> str | None:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None
