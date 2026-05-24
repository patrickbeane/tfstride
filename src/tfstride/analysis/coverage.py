from __future__ import annotations
from collections.abc import Mapping
import json
from typing import Any

from tfstride.analysis.rule_registry import DEFAULT_RULE_REGISTRY, RulePolicy, RuleRegistry
from tfstride.models import (
    AnalysisCoverage,
    NormalizedResource,
    ReferenceCoverage,
    ResourceCoverage,
    ResourceInventory,
    RuleCoverage,
    UnresolvedReference,
)


UNRESOLVED_REFERENCE_PREFIX = "unresolved_"


def build_analysis_coverage(
    inventory: ResourceInventory,
    *,
    rule_registry: RuleRegistry = DEFAULT_RULE_REGISTRY,
    rule_policy: RulePolicy | None = None,
) -> AnalysisCoverage:
    return AnalysisCoverage(
        resources=_build_resource_coverage(inventory),
        rules=_build_rule_coverage(rule_registry, rule_policy),
        references=_build_reference_coverage(inventory.resources),
    )


def _build_resource_coverage(inventory: ResourceInventory) -> ResourceCoverage:
    return ResourceCoverage(
        total_resources=_metadata_int(inventory.metadata, "total_input_resources", len(inventory.resources)),
        provider_resources=_metadata_int(inventory.metadata, "provider_resource_count", len(inventory.resources)),
        normalized_resources=len(inventory.resources),
        unsupported_resources=len(inventory.unsupported_resources),
        unsupported_resource_types=_metadata_int_map(inventory.metadata, "unsupported_resource_types"),
    )


def _build_rule_coverage(rule_registry: RuleRegistry, rule_policy: RulePolicy | None) -> RuleCoverage:
    rules = rule_registry.rules()
    enabled_rules = [
        rule.rule_id
        for rule in rules
        if rule_policy is None or rule_policy.is_enabled(rule.rule_id, rule_registry)
    ]
    enabled_rule_ids = set(enabled_rules)
    disabled_rules = [rule.rule_id for rule in rules if rule.rule_id not in enabled_rule_ids]
    severity_overrides = {}
    if rule_policy is not None:
        severity_overrides = {
            rule.rule_id: rule_policy.severity_overrides[rule.rule_id]
            for rule in rules
            if rule.rule_id in rule_policy.severity_overrides
        }

    return RuleCoverage(
        registered_rule_count=len(rules),
        enabled_rules=enabled_rules,
        disabled_rules=disabled_rules,
        severity_overrides=severity_overrides,
    )


def _build_reference_coverage(resources: list[NormalizedResource]) -> ReferenceCoverage:
    unresolved_references: list[UnresolvedReference] = []
    unresolved_count = 0

    for resource in sorted(resources, key=lambda item: item.address):
        references = {
            key: values
            for key, values in (
                (key, _coerce_reference_values(value))
                for key, value in sorted(resource.metadata.items())
                if key.startswith(UNRESOLVED_REFERENCE_PREFIX)
            )
            if values
        }
        if not references:
            continue

        unresolved_count += sum(len(values) for values in references.values())
        unresolved_references.append(
            UnresolvedReference(
                resource=resource.address,
                references=references,
            )
        )

    return ReferenceCoverage(
        unresolved_reference_count=unresolved_count,
        unresolved_references=unresolved_references,
    )


def _metadata_int(metadata: Mapping[str, Any], key: str, default: int) -> int:
    try:
        return int(metadata.get(key, default))
    except (TypeError, ValueError):
        return default


def _metadata_int_map(metadata: Mapping[str, Any], key: str) -> dict[str, int]:
    value = metadata.get(key)
    if not isinstance(value, dict):
        return {}

    parsed: dict[str, int] = {}
    for item_key, item_value in value.items():
        try:
            count = int(item_value)
        except (TypeError, ValueError):
            continue
        parsed[str(item_key)] = count
    return dict(sorted(parsed.items()))


def _coerce_reference_values(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [_reference_value_to_string(item) for item in value if item not in (None, "")]
    return [_reference_value_to_string(value)]


def _reference_value_to_string(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, int | float | bool):
        return str(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"))