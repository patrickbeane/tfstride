from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, SecurityGroupRule, TerraformResource
from tfstride.providers.coercion import attribute_unknown
from tfstride.providers.gcp.attributes import GcpAttr, GcpValues
from tfstride.providers.gcp.coercion import first_item
from tfstride.providers.gcp.firewall_matches import firewall_match_network_rules, normalize_firewall_matches
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.network_normalizer_utils import _gcp_values
from tfstride.providers.gcp.normalizer_common import GCP_PROVIDER
from tfstride.providers.gcp.resource_utils import first_non_empty, resource_identifier, resource_name
from tfstride.resource_metadata import MetadataField


def normalize_compute_firewall(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    matches = normalize_firewall_matches(resource.values, resource.unknown_values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=resource_identifier(resource),
        vpc_id=values.get(GcpAttr.NETWORK),
        network_rules=tuple(
            rule for match in matches if match["action"] == "allow" for rule in firewall_match_network_rules(match)
        ),
        metadata={
            GcpResourceMetadata.FIREWALL_MATCHES: matches,
            GcpResourceMetadata.NAME: resource_name(resource),
            GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
            GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
            GcpResourceMetadata.NETWORK: values.get(GcpAttr.NETWORK),
            GcpResourceMetadata.FIREWALL_ALLOW: values.get(GcpAttr.ALLOW),
            GcpResourceMetadata.FIREWALL_DENY: values.get(GcpAttr.DENY),
            GcpResourceMetadata.FIREWALL_SOURCE_RANGES: values.get(GcpAttr.SOURCE_RANGES),
            GcpResourceMetadata.FIREWALL_DESTINATION_RANGES: values.get(GcpAttr.DESTINATION_RANGES),
            GcpResourceMetadata.FIREWALL_TARGET_TAGS: values.get(GcpAttr.TARGET_TAGS),
            GcpResourceMetadata.FIREWALL_SOURCE_TAGS: values.get(GcpAttr.SOURCE_TAGS),
            GcpResourceMetadata.FIREWALL_TARGET_SERVICE_ACCOUNTS: values.get(GcpAttr.TARGET_SERVICE_ACCOUNTS),
            GcpResourceMetadata.FIREWALL_SOURCE_SERVICE_ACCOUNTS: values.get(GcpAttr.SOURCE_SERVICE_ACCOUNTS),
            GcpResourceMetadata.FIREWALL_DIRECTION: str(values.get(GcpAttr.DIRECTION) or "INGRESS").lower(),
            GcpResourceMetadata.FIREWALL_PRIORITY: values.get(GcpAttr.PRIORITY),
            GcpResourceMetadata.FIREWALL_DISABLED: values.get(GcpAttr.DISABLED),
        },
    )


def normalize_compute_firewall_policy(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=first_non_empty(
            values.get(GcpAttr.SHORT_NAME), values.get(GcpAttr.NAME), resource_identifier(resource)
        ),
        metadata={
            **_policy_unknown_metadata(resource),
            GcpResourceMetadata.NAME: first_non_empty(values.get(GcpAttr.SHORT_NAME), values.get(GcpAttr.NAME)),
            GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
            GcpResourceMetadata.FIREWALL_POLICY_REFERENCE: values.get(GcpAttr.NAME),
            GcpResourceMetadata.FIREWALL_POLICY_PARENT: values.get(GcpAttr.PARENT),
            "description": values.get(GcpAttr.DESCRIPTION),
            "display_name": values.get(GcpAttr.DISPLAY_NAME),
        },
    )


def normalize_compute_firewall_policy_rule(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    match = _firewall_policy_match(values)
    matches = normalize_firewall_matches(resource.values, resource.unknown_values, policy=True)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=_firewall_policy_rule_identifier(resource),
        network_rules=tuple(rule for match_record in matches for rule in firewall_match_network_rules(match_record)),
        metadata={
            GcpResourceMetadata.FIREWALL_MATCHES: matches,
            GcpResourceMetadata.NAME: first_non_empty(values.get(GcpAttr.NAME)),
            GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
            GcpResourceMetadata.FIREWALL_POLICY_REFERENCE: values.get(GcpAttr.FIREWALL_POLICY),
            GcpResourceMetadata.FIREWALL_POLICY_ACTION: values.get(GcpAttr.ACTION),
            GcpResourceMetadata.FIREWALL_POLICY_DIRECTION: _firewall_policy_direction(values),
            GcpResourceMetadata.FIREWALL_POLICY_PRIORITY: values.get(GcpAttr.PRIORITY),
            GcpResourceMetadata.FIREWALL_POLICY_MATCH: match,
            GcpResourceMetadata.FIREWALL_SOURCE_RANGES: _firewall_policy_source_ranges(match),
            GcpResourceMetadata.FIREWALL_DESTINATION_RANGES: _firewall_policy_destination_ranges(match),
            GcpResourceMetadata.FIREWALL_POLICY_TARGET_RESOURCES: values.get(GcpAttr.TARGET_RESOURCES),
            GcpResourceMetadata.FIREWALL_POLICY_TARGET_SERVICE_ACCOUNTS: values.get(GcpAttr.TARGET_SERVICE_ACCOUNTS),
            GcpResourceMetadata.FIREWALL_POLICY_DISABLED: values.get(GcpAttr.DISABLED),
            GcpResourceMetadata.FIREWALL_POLICY_ENABLE_LOGGING: values.get(GcpAttr.ENABLE_LOGGING),
            "description": values.get(GcpAttr.DESCRIPTION),
        },
    )


def normalize_compute_firewall_policy_association(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=first_non_empty(
            values.get(GcpAttr.ATTACHMENT_TARGET), values.get(GcpAttr.NAME), resource_identifier(resource)
        ),
        metadata={
            **_policy_unknown_metadata(resource),
            GcpResourceMetadata.NAME: first_non_empty(values.get(GcpAttr.NAME)),
            GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
            GcpResourceMetadata.FIREWALL_POLICY_REFERENCE: values.get(GcpAttr.FIREWALL_POLICY),
            GcpResourceMetadata.FIREWALL_POLICY_ATTACHMENT_TARGET: values.get(GcpAttr.ATTACHMENT_TARGET),
            "display_name": values.get(GcpAttr.DISPLAY_NAME),
        },
    )


def _policy_unknown_metadata(resource: TerraformResource) -> dict[MetadataField[list[str]], list[str]]:
    fields = [
        key
        for key in ("firewall_policy", "attachment_target", "name", "short_name", "id", "self_link")
        if attribute_unknown(resource.unknown_values, key)
    ]
    return {GcpResourceMetadata.FIREWALL_POLICY_UNKNOWN_FIELDS: fields} if fields else {}


def parse_firewall_allow_rules(values: dict[str, Any] | GcpValues) -> list[SecurityGroupRule]:
    return [
        rule
        for match in normalize_firewall_matches(_gcp_values(values).values)
        if match["action"] == "allow"
        for rule in firewall_match_network_rules(match)
    ]


def parse_firewall_policy_allow_rules(values: dict[str, Any] | GcpValues) -> list[SecurityGroupRule]:
    gcp_values = _gcp_values(values)
    if str(gcp_values.get(GcpAttr.ACTION) or "").strip().lower() != "allow":
        return []
    return parse_firewall_policy_rules(gcp_values)


def parse_firewall_policy_rules(values: dict[str, Any] | GcpValues) -> list[SecurityGroupRule]:
    return [
        rule
        for match in normalize_firewall_matches(_gcp_values(values).values, policy=True)
        for rule in firewall_match_network_rules(match)
    ]


def _firewall_policy_rule_identifier(resource: TerraformResource) -> str | None:
    values = GcpValues(resource.values)
    firewall_policy = first_non_empty(values.get(GcpAttr.FIREWALL_POLICY))
    priority = first_non_empty(values.get(GcpAttr.PRIORITY))
    if firewall_policy and priority:
        return f"{firewall_policy}/rules/{priority}"
    return resource_identifier(resource)


def _firewall_policy_match(values: GcpValues) -> dict[str, Any]:
    return first_item(values.get(GcpAttr.MATCH)) or {}


def _firewall_policy_direction(values: GcpValues) -> str:
    return str(values.get(GcpAttr.DIRECTION) or "INGRESS").strip().lower()


def _firewall_policy_source_ranges(match: dict[str, Any]) -> list[str]:
    match_values = GcpValues(match)
    return match_values.get(GcpAttr.SRC_IP_RANGES) or match_values.get(GcpAttr.SRC_IP_RANGE)


def _firewall_policy_destination_ranges(match: dict[str, Any]) -> list[str]:
    match_values = GcpValues(match)
    return match_values.get(GcpAttr.DEST_IP_RANGES) or match_values.get(GcpAttr.DEST_IP_RANGE)
