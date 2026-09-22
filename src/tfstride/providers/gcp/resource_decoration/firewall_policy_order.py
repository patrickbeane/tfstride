"""Resolve attachment order independently of rule priority.

Unknown scope/order blocks unconditional policy and VPC decisions. Stable
address ordering is used only for evidence presentation, never cloud precedence.
"""

from __future__ import annotations

from dataclasses import dataclass

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_decoration.firewall_policy_hierarchy import firewall_policy_hierarchy
from tfstride.providers.gcp.resource_decoration.firewall_uncertainty import firewall_field_is_uncertain
from tfstride.providers.gcp.resource_index import GcpResourceIndex
from tfstride.providers.gcp.resource_types import GcpResourceType
from tfstride.providers.gcp.resource_utils import gcp_reference_key


@dataclass(frozen=True, slots=True)
class FirewallPolicyGroup:
    key: str
    attachment_position: int
    rules: tuple[NormalizedResource, ...]


@dataclass(frozen=True, slots=True)
class FirewallPolicyOrder:
    groups: tuple[FirewallPolicyGroup, ...]
    uncertainties: tuple[str, ...]


def _policy_key(resource: NormalizedResource, index: GcpResourceIndex) -> tuple[str | None, str | None]:
    reference = resource.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_REFERENCE)
    unknown = resource.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_UNKNOWN_FIELDS)
    if not reference or "firewall_policy" in unknown or firewall_field_is_uncertain(resource, "firewall_policy"):
        return None, "firewall policy reference is missing or unknown"
    resolution = index.resources_by_reference.resolve(
        reference, source=resource, resource_types={GcpResourceType.COMPUTE_FIREWALL_POLICY}
    )
    if resolution.state == "ambiguous":
        return None, "firewall policy reference is ambiguous"
    selected = resolution.selected_candidate
    if selected:
        if (
            selected.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_UNKNOWN_FIELDS)
            and gcp_reference_key(reference) != selected.address
        ):
            return None, "firewall policy identity is unknown"
        return selected.address, None
    # A matching explicit reference can join rules and associations even when
    # the policy object is managed outside this plan.
    if "${" in reference or not reference.strip():
        return None, "firewall policy reference is unresolved"
    return gcp_reference_key(reference), None


def resolve_firewall_policy_order(
    instance: NormalizedResource,
    index: GcpResourceIndex,
    rules: tuple[NormalizedResource, ...],
) -> FirewallPolicyOrder:
    hierarchy = firewall_policy_hierarchy(instance, index)
    uncertainties: set[str] = set()
    associated_keys: set[str] = set()
    positions: dict[str, set[int]] = {}
    for association in index.firewall_policy_associations:
        key, key_issue = _policy_key(association, index)
        if key:
            associated_keys.add(key)
        unknown = association.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_UNKNOWN_FIELDS)
        target = association.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_ATTACHMENT_TARGET)
        position, scope_issue = hierarchy.attachment_position(None if "attachment_target" in unknown else target, index)
        if position is None and scope_issue is None:
            continue  # Proven unrelated scope cannot constrain this instance.
        for issue in (key_issue, scope_issue):
            if issue:
                uncertainties.add(f"{association.address}: {issue}")
        if key and position is not None:
            positions.setdefault(key, set()).add(position)

    grouped: dict[str, list[NormalizedResource]] = {}
    for rule in rules:
        key, issue = _policy_key(rule, index)
        if issue:
            uncertainties.add(f"{rule.address}: {issue}")
        if key is None:
            continue
        if key not in associated_keys:
            uncertainties.add(f"{rule.address}: applicable firewall policy association is not modeled")
        if key in positions:
            grouped.setdefault(key, []).append(rule)

    by_position: dict[int, set[str]] = {}
    for key, values in positions.items():
        if len(values) != 1:
            uncertainties.add(f"{key}: multiple applicable firewall policy attachment scopes")
        for position in values:
            by_position.setdefault(position, set()).add(key)
    for keys in by_position.values():
        if len(keys) > 1:
            uncertainties.add(
                f"firewall policy order is ambiguous at the same attachment scope: {', '.join(sorted(keys))}"
            )

    # Never select an arbitrary linearization of ambiguous attachment evidence.
    if uncertainties:
        return FirewallPolicyOrder((), tuple(sorted(uncertainties)))
    return FirewallPolicyOrder(
        tuple(
            FirewallPolicyGroup(
                key=key,
                attachment_position=next(iter(positions[key])),
                rules=tuple(sorted(group, key=lambda rule: rule.address)),
            )
            for key, group in sorted(grouped.items(), key=lambda item: -next(iter(positions[item[0]])))
        ),
        (),
    )
