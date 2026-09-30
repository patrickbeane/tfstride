from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.coercion import (
    STATE_CONFIGURED,
    STATE_NOT_CONFIGURED,
    STATE_UNKNOWN,
    as_list,
    block_attribute_unknown,
    dedupe,
    first_mapping,
    known_string,
    unknown_block_at,
    value_is_unknown,
)
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer_common import GCP_PROVIDER
from tfstride.providers.gcp.resource_utils import first_non_empty


def normalize_iam_deny_policy(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    parent_uncertainties: list[str] = []
    parent = known_string(
        values,
        resource.unknown_values,
        "parent",
        parent_uncertainties,
        require_string=True,
    )
    if parent_uncertainties:
        parent_state = STATE_UNKNOWN
    elif parent is not None:
        parent_state = STATE_CONFIGURED
    else:
        parent_state = STATE_NOT_CONFIGURED

    rules, rule_uncertainties = _deny_policy_rules(
        values.get("rules"),
        resource.unknown_values.get("rules"),
    )
    uncertainties = dedupe([*parent_uncertainties, *rule_uncertainties])
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(
            values.get("id"),
            values.get("name"),
            resource.address,
        ),
        metadata={
            GcpResourceMetadata.IAM_DENY_POLICY_PARENT: parent,
            GcpResourceMetadata.IAM_DENY_POLICY_PARENT_STATE: parent_state,
            GcpResourceMetadata.IAM_DENY_POLICY_RULES: rules,
            GcpResourceMetadata.IAM_DENY_POLICY_COMPLETENESS_STATE: (
                "complete" if not rule_uncertainties else STATE_UNKNOWN
            ),
            GcpResourceMetadata.IAM_DENY_POLICY_UNCERTAINTIES: uncertainties,
        },
    )


def _deny_policy_rules(
    raw_rules: object,
    raw_unknown_rules: object,
) -> tuple[list[dict[str, Any]], list[str]]:
    uncertainties: list[str] = []
    if raw_unknown_rules is True:
        uncertainties.append("rules are unknown after planning")
    rules: list[dict[str, Any]] = []
    rule_values = as_list(raw_rules)
    # after_unknown can contain blocks absent from planned values. An existing
    # field-level uncertainty must not hide an additional rule with unknown scope.
    if isinstance(raw_unknown_rules, list) and value_is_unknown(raw_unknown_rules[len(rule_values) :]):
        uncertainties.append("rules contain additional unknown blocks after planning")
    if not rule_values:
        if value_is_unknown(raw_unknown_rules):
            uncertainties.append("rules are unknown after planning")
        else:
            uncertainties.append("rules are not configured")
        return rules, dedupe(uncertainties)
    for rule_index, raw_rule in enumerate(rule_values):
        rule_path = f"rules[{rule_index}]"
        if not isinstance(raw_rule, Mapping):
            uncertainties.append(f"{rule_path} has an unrecognized value shape")
            continue
        rule_mapping = cast(Mapping[str, object], raw_rule)
        unknown_rule = unknown_block_at(raw_unknown_rules, rule_index)
        raw_deny_rules = as_list(rule_mapping.get("deny_rule"))
        if isinstance(unknown_rule, Mapping):
            unknown_rule_mapping = cast(Mapping[str, object], unknown_rule)
            unknown_deny_rules = unknown_rule_mapping.get("deny_rule")
        else:
            unknown_deny_rules = unknown_rule
        if isinstance(unknown_deny_rules, list) and value_is_unknown(unknown_deny_rules[len(raw_deny_rules) :]):
            uncertainties.append(f"{rule_path}.deny_rule contains additional unknown blocks after planning")
        if not raw_deny_rules:
            if value_is_unknown(unknown_deny_rules):
                uncertainties.append(f"{rule_path}.deny_rule is unknown after planning")
            else:
                uncertainties.append(f"{rule_path}.deny_rule is not configured")
            continue
        if len(raw_deny_rules) != 1:
            uncertainties.append(f"{rule_path}.deny_rule has an unrecognized value shape")
        for deny_index, raw_deny_rule in enumerate(raw_deny_rules):
            deny_path = f"{rule_path}.deny_rule[{deny_index}]"
            unknown_deny_rule = unknown_block_at(
                unknown_deny_rules,
                deny_index,
            )
            normalized = _deny_rule(
                raw_deny_rule,
                unknown_deny_rule,
                deny_path,
                uncertainties,
            )
            if normalized is not None:
                rules.append(normalized)
    if value_is_unknown(raw_unknown_rules) and not uncertainties:
        uncertainties.append("rules contain unknown values after planning")
    return rules, dedupe(uncertainties)


def _deny_rule(
    raw_rule: object,
    unknown_rule: object,
    path: str,
    uncertainties: list[str],
) -> dict[str, Any] | None:
    if not isinstance(raw_rule, Mapping):
        uncertainties.append(f"{path} has an unrecognized value shape")
        return None

    rule_mapping = cast(Mapping[str, Any], raw_rule)
    denied_principals, denied_principals_state = _rule_strings(
        rule_mapping,
        unknown_rule,
        "denied_principals",
        path,
        uncertainties,
        required=True,
    )
    exception_principals, exception_principals_state = _rule_strings(
        rule_mapping,
        unknown_rule,
        "exception_principals",
        path,
        uncertainties,
    )
    denied_permissions, denied_permissions_state = _rule_strings(
        rule_mapping,
        unknown_rule,
        "denied_permissions",
        path,
        uncertainties,
        required=True,
    )
    exception_permissions, exception_permissions_state = _rule_strings(
        rule_mapping,
        unknown_rule,
        "exception_permissions",
        path,
        uncertainties,
    )

    condition_path = f"{path}.denial_condition"
    if block_attribute_unknown(unknown_rule, "denial_condition"):
        condition = None
        condition_state = STATE_UNKNOWN
        uncertainties.append(f"{condition_path} is unknown after planning")
    else:
        raw_condition = rule_mapping.get("denial_condition")
        condition_mapping = first_mapping(
            raw_condition,
            expand_tuples=True,
        )
        if raw_condition not in (None, [], {}) and condition_mapping is None:
            condition = None
            condition_state = STATE_UNKNOWN
            uncertainties.append(f"{condition_path} has an unrecognized value shape")
        elif condition_mapping:
            condition = {str(key): value for key, value in condition_mapping.items()}
            condition_state = STATE_CONFIGURED
        else:
            condition = None
            condition_state = STATE_NOT_CONFIGURED

    return {
        "denied_principals": denied_principals,
        "denied_principals_state": denied_principals_state,
        "exception_principals": exception_principals,
        "exception_principals_state": exception_principals_state,
        "denied_permissions": denied_permissions,
        "denied_permissions_state": denied_permissions_state,
        "exception_permissions": exception_permissions,
        "exception_permissions_state": exception_permissions_state,
        "condition": condition,
        "condition_state": condition_state,
    }


def _rule_strings(
    values: Mapping[str, Any],
    unknown_rule: object,
    key: str,
    path: str,
    uncertainties: list[str],
    *,
    required: bool = False,
) -> tuple[list[str], str]:
    field_path = f"{path}.{key}"
    if block_attribute_unknown(unknown_rule, key):
        uncertainties.append(f"{field_path} is unknown after planning")
        return [], STATE_UNKNOWN
    raw_items = values.get(key)
    if raw_items in (None, []):
        if required:
            uncertainties.append(f"{field_path} is not configured")
            return [], STATE_UNKNOWN
        return [], STATE_NOT_CONFIGURED
    if not isinstance(raw_items, (list, tuple)):
        uncertainties.append(f"{field_path} has an unrecognized value shape")
        return [], STATE_UNKNOWN
    items: list[str] = []
    for raw_item in raw_items:
        if not isinstance(raw_item, str) or not raw_item.strip():
            uncertainties.append(f"{field_path} has an unrecognized value shape")
            return [], STATE_UNKNOWN
        items.append(raw_item.strip())
    return sorted(set(items)), STATE_CONFIGURED
