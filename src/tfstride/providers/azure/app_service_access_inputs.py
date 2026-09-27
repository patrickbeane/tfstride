"""Completeness and ordering of App Service restriction inputs.

Restriction records remain in their existing metadata fields. These states keep
an omitted setting distinct from unknown or malformed planned configuration.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import TerraformResource
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.coercion import block_attribute_unknown, first_mapping


def site_config_inputs(resource: TerraformResource) -> tuple[Mapping[str, Any], Any]:
    raw = resource.values.get("site_config")
    unknown = resource.unknown_values.get("site_config")
    if unknown is True or (isinstance(unknown, list) and len(unknown) > 1):
        return {}, True
    if isinstance(unknown, list):
        unknown = unknown[0] if unknown else None
    if unknown not in (None, False) and not isinstance(unknown, Mapping):
        return {}, True
    if isinstance(raw, Mapping):
        return raw, unknown
    if isinstance(raw, list) and len(raw) == 1 and isinstance(raw[0], Mapping):
        return raw[0], unknown
    if raw in (None, []):
        return {}, unknown
    return {}, True


def app_service_restriction_inputs(resource: TerraformResource) -> dict[str, Any]:
    values, unknown = site_config_inputs(resource)
    managed = resource.mode == "managed"
    result: dict[str, Any] = {"rule_defaults_known": managed}
    for site, field in (("main", "ip_restriction"), ("scm", "scm_ip_restriction")):
        raw = values.get(field)
        unknown_rules = first_mapping(unknown)
        unknown_rules = unknown_rules.get(field) if unknown_rules is not None else unknown
        default_key = f"{field}_default_action"
        raw_default = values.get(default_key)
        default_state = "known" if raw_default in ("Allow", "Deny") else "implicit"
        if (
            block_attribute_unknown(unknown, default_key)
            or raw_default not in (None, "Allow", "Deny")
            or (not managed and default_key not in values)
        ):
            default_state = "unknown"
        result[site] = {
            "rules_complete": unknown_rules is not True
            and (unknown_rules in (None, False) or isinstance(unknown_rules, list))
            and (raw is None or isinstance(raw, list))
            and (managed or field in values)
            and unknown is not True,
            # Modern AzureRM restriction lists preserve ARM order. The legacy
            # function-app schema does not establish that tie-break contract.
            "rule_order_known": isinstance(raw, list) and resource.resource_type != AzureResourceType.FUNCTION_APP,
            "default_action_state": default_state,
        }
    inheritance = values.get("scm_use_main_ip_restriction")
    result["scm_inheritance_state"] = (
        "unknown"
        if block_attribute_unknown(unknown, "scm_use_main_ip_restriction")
        or (inheritance is not None and type(inheritance) is not bool)
        or (not managed and "scm_use_main_ip_restriction" not in values)
        else "main"
        if inheritance is True
        else "separate"
    )
    return result
