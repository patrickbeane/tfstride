from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.gcp.coercion import as_bool, as_list, compact, first_item
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.network_normalizers import GCP_PROVIDER
from tfstride.providers.gcp.resource_utils import first_non_empty, resource_identifier, resource_name


def normalize_org_policy_policy(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    parent = first_non_empty(values.get("parent"))
    constraint = first_non_empty(values.get("constraint"), _constraint_from_policy_name(values.get("name")))
    spec = first_item(values.get("spec")) or {}
    if not isinstance(spec, dict):
        spec = {}
    rules = _new_policy_rules(spec)
    return _org_policy_resource(
        resource,
        constraint=constraint,
        scope=parent,
        scope_type=_scope_type(parent),
        project=_scope_identifier(parent, "projects/"),
        folder_id=_scope_identifier(parent, "folders/"),
        organization_id=_scope_identifier(parent, "organizations/"),
        inherit_from_parent=_optional_bool(spec.get("inherit_from_parent")),
        restore_default=_optional_bool(first_non_empty(values.get("reset"), spec.get("reset"))),
        rules=rules,
        allowed_values=_rule_values(rules, "allowed_values"),
        denied_values=_rule_values(rules, "denied_values"),
        enforced=_rule_enforced(rules),
    )


def normalize_organization_policy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_legacy_org_policy(
        resource,
        scope_type="organization",
        scope_field=GcpResourceMetadata.ORGANIZATION_ID,
        scope_keys=("org_id", "organization_id", "organization"),
    )


def normalize_folder_organization_policy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_legacy_org_policy(
        resource,
        scope_type="folder",
        scope_field=GcpResourceMetadata.FOLDER_ID,
        scope_keys=("folder", "folder_id"),
    )


def normalize_project_organization_policy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_legacy_org_policy(
        resource,
        scope_type="project",
        scope_field=GcpResourceMetadata.PROJECT,
        scope_keys=("project",),
    )


def _normalize_legacy_org_policy(
    resource: TerraformResource,
    *,
    scope_type: str,
    scope_field: Any,
    scope_keys: tuple[str, ...],
) -> NormalizedResource:
    values = resource.values
    scope = first_non_empty(*(values.get(key) for key in scope_keys))
    rules = _legacy_policy_rules(values)
    metadata_scope = {scope_field: scope} if scope else {}
    return _org_policy_resource(
        resource,
        constraint=first_non_empty(values.get("constraint")),
        scope=scope,
        scope_type=scope_type,
        project=scope if scope_field == GcpResourceMetadata.PROJECT else None,
        folder_id=scope if scope_field == GcpResourceMetadata.FOLDER_ID else None,
        organization_id=scope if scope_field == GcpResourceMetadata.ORGANIZATION_ID else None,
        inherit_from_parent=_legacy_inherit_from_parent(values),
        restore_default=_legacy_restore_default(values),
        rules=rules,
        allowed_values=_rule_values(rules, "allowed_values"),
        denied_values=_rule_values(rules, "denied_values"),
        enforced=_rule_enforced(rules),
        extra_metadata=metadata_scope,
    )


def _org_policy_resource(
    resource: TerraformResource,
    *,
    constraint: str | None,
    scope: str | None,
    scope_type: str | None,
    project: str | None,
    folder_id: str | None,
    organization_id: str | None,
    inherit_from_parent: bool | None,
    restore_default: bool | None,
    rules: list[dict[str, Any]],
    allowed_values: list[str],
    denied_values: list[str],
    enforced: bool | None,
    extra_metadata: dict[str, Any] | None = None,
) -> NormalizedResource:
    metadata = {
        GcpResourceMetadata.NAME: resource_name(resource),
        GcpResourceMetadata.SELF_LINK: resource.values.get("self_link"),
        GcpResourceMetadata.PROJECT: project,
        GcpResourceMetadata.FOLDER_ID: folder_id,
        GcpResourceMetadata.ORGANIZATION_ID: organization_id,
        GcpResourceMetadata.ORG_POLICY_CONSTRAINT: constraint,
        GcpResourceMetadata.ORG_POLICY_SCOPE: scope,
        GcpResourceMetadata.ORG_POLICY_SCOPE_TYPE: scope_type,
        GcpResourceMetadata.ORG_POLICY_RULES: rules,
        GcpResourceMetadata.ORG_POLICY_ALLOWED_VALUES: allowed_values,
        GcpResourceMetadata.ORG_POLICY_DENIED_VALUES: denied_values,
    }
    if inherit_from_parent is not None:
        metadata[GcpResourceMetadata.ORG_POLICY_INHERIT_FROM_PARENT] = inherit_from_parent
    if restore_default is not None:
        metadata[GcpResourceMetadata.ORG_POLICY_RESTORE_DEFAULT] = restore_default
    if enforced is not None:
        metadata[GcpResourceMetadata.ORG_POLICY_ENFORCED] = enforced
    if extra_metadata:
        metadata.update(extra_metadata)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(resource.values.get("id"), resource_identifier(resource)),
        metadata=metadata,
    )


def _new_policy_rules(spec: dict[str, Any]) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for rule in as_list(spec.get("rules")):
        if not isinstance(rule, dict):
            continue
        values = first_item(rule.get("values")) or {}
        if not isinstance(values, dict):
            values = {}
        normalized = {
            "enforced": _optional_bool(rule.get("enforce")),
            "allow_all": _optional_bool(rule.get("allow_all")),
            "deny_all": _optional_bool(rule.get("deny_all")),
            "allowed_values": compact(as_list(values.get("allowed_values"))),
            "denied_values": compact(as_list(values.get("denied_values"))),
            "condition": first_item(rule.get("condition")) or {},
        }
        rules.append(_compact_rule(normalized))
    return rules


def _legacy_policy_rules(values: dict[str, Any]) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for policy in as_list(values.get("boolean_policy")):
        if not isinstance(policy, dict):
            continue
        rules.append(_compact_rule({"enforced": _optional_bool(policy.get("enforced"))}))
    for policy in as_list(values.get("list_policy")):
        if not isinstance(policy, dict):
            continue
        allow = first_item(policy.get("allow")) or {}
        deny = first_item(policy.get("deny")) or {}
        if not isinstance(allow, dict):
            allow = {}
        if not isinstance(deny, dict):
            deny = {}
        rules.append(
            _compact_rule(
                {
                    "allow_all": _optional_bool(allow.get("all")),
                    "deny_all": _optional_bool(deny.get("all")),
                    "allowed_values": compact(as_list(allow.get("values"))),
                    "denied_values": compact(as_list(deny.get("values"))),
                    "inherit_from_parent": _optional_bool(policy.get("inherit_from_parent")),
                    "suggested_value": first_non_empty(policy.get("suggested_value")),
                }
            )
        )
    for policy in as_list(values.get("restore_policy")):
        if isinstance(policy, dict):
            rules.append(_compact_rule({"restore_default": _optional_bool(policy.get("default"))}))
    return rules


def _legacy_inherit_from_parent(values: dict[str, Any]) -> bool | None:
    for policy in as_list(values.get("list_policy")):
        if not isinstance(policy, dict):
            continue
        parsed = _optional_bool(policy.get("inherit_from_parent"))
        if parsed is not None:
            return parsed
    return None


def _legacy_restore_default(values: dict[str, Any]) -> bool | None:
    restore_policies = as_list(values.get("restore_policy"))
    if not restore_policies:
        return None
    for policy in restore_policies:
        if not isinstance(policy, dict):
            continue
        parsed = _optional_bool(policy.get("default"))
        if parsed is not None:
            return parsed
    return True


def _rule_values(rules: list[dict[str, Any]], key: str) -> list[str]:
    values: list[str] = []
    for rule in rules:
        raw_values = rule.get(key)
        if isinstance(raw_values, list):
            values.extend(str(value) for value in raw_values if value not in (None, ""))
    return compact(values)


def _rule_enforced(rules: list[dict[str, Any]]) -> bool | None:
    values = [rule.get("enforced") for rule in rules if isinstance(rule.get("enforced"), bool)]
    if not values:
        return None
    return any(values)


def _constraint_from_policy_name(value: Any) -> str | None:
    text = first_non_empty(value)
    if text is None:
        return None
    if "/policies/" not in text:
        return None
    return text.rsplit("/policies/", 1)[-1]


def _scope_type(value: str | None) -> str | None:
    if value is None:
        return None
    if value.startswith("projects/"):
        return "project"
    if value.startswith("folders/"):
        return "folder"
    if value.startswith("organizations/"):
        return "organization"
    return None


def _scope_identifier(value: str | None, prefix: str) -> str | None:
    if value is None or not value.startswith(prefix):
        return None
    return value.removeprefix(prefix)


def _optional_bool(value: Any) -> bool | None:
    if value is None or value == "":
        return None
    return as_bool(value)


def _compact_rule(rule: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in rule.items()
        if value not in (None, "", [], {})
    }