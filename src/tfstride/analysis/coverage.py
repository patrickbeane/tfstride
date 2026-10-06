from __future__ import annotations

from collections.abc import Sequence

from tfstride.analysis.rule_registry import RulePolicy, RuleRegistry, default_rule_registry
from tfstride.models import (
    AnalysisCoverage,
    NormalizedResource,
    ReferenceCoverage,
    ResourceCoverage,
    ResourceInventory,
    RuleCoverage,
    TerraformReferenceResolutionState,
    UnresolvedReference,
)
from tfstride.resource_metadata import InventoryMetadata


def build_analysis_coverage(
    inventory: ResourceInventory,
    *,
    rule_registry: RuleRegistry | None = None,
    rule_policy: RulePolicy | None = None,
) -> AnalysisCoverage:
    resolved_rule_registry = rule_registry if rule_registry is not None else default_rule_registry()
    return AnalysisCoverage(
        resources=_build_resource_coverage(inventory),
        rules=_build_rule_coverage(resolved_rule_registry, rule_policy),
        references=_build_reference_coverage(inventory.resources),
    )


def _build_resource_coverage(inventory: ResourceInventory) -> ResourceCoverage:
    total_resources = inventory.get_metadata_field(InventoryMetadata.TOTAL_INPUT_RESOURCES)
    provider_resources = inventory.get_metadata_field(InventoryMetadata.PROVIDER_RESOURCE_COUNT)

    return ResourceCoverage(
        total_resources=total_resources if total_resources is not None else len(inventory.resources),
        provider_resources=provider_resources if provider_resources is not None else len(inventory.resources),
        normalized_resources=len(inventory.resources),
        unsupported_resources=len(inventory.unsupported_resources),
        plan_time_unknown_resources=inventory.plan_time_unknown_resources,
        unsupported_resource_types=inventory.get_metadata_field(InventoryMetadata.UNSUPPORTED_RESOURCE_TYPES),
    )


def _build_rule_coverage(rule_registry: RuleRegistry, rule_policy: RulePolicy | None) -> RuleCoverage:
    rules = rule_registry.rules()
    enabled_rules = [
        rule.rule_id for rule in rules if rule_policy is None or rule_policy.is_enabled(rule.rule_id, rule_registry)
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


def _build_reference_coverage(resources: Sequence[NormalizedResource]) -> ReferenceCoverage:
    unresolved_references: list[UnresolvedReference] = []
    unresolved_count = 0
    symbolically_resolved_relationships = 0
    ambiguous_symbolic_relationships = 0
    unresolved_symbolic_relationships = 0
    unsupported_symbolic_relationships = 0

    for resource in sorted(resources, key=lambda item: item.address):
        for resolution in resource.reference_resolutions:
            if resolution.state is TerraformReferenceResolutionState.SYMBOLIC:
                symbolically_resolved_relationships += 1
            elif resolution.state is TerraformReferenceResolutionState.AMBIGUOUS:
                ambiguous_symbolic_relationships += 1
            elif resolution.state is TerraformReferenceResolutionState.UNRESOLVED:
                unresolved_symbolic_relationships += 1
            elif resolution.state is TerraformReferenceResolutionState.UNSUPPORTED:
                unsupported_symbolic_relationships += 1

        references = _unresolved_reference_metadata(resource)
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
        symbolically_resolved_relationships=symbolically_resolved_relationships,
        ambiguous_symbolic_relationships=ambiguous_symbolic_relationships,
        unresolved_symbolic_relationships=unresolved_symbolic_relationships,
        unsupported_symbolic_relationships=unsupported_symbolic_relationships,
    )


def _unresolved_reference_metadata(resource: NormalizedResource) -> dict[str, list[str]]:
    return resource.unresolved_reference_keys()
