from __future__ import annotations

from tfstride.models import NormalizedResource, SecurityGroupRule
from tfstride.providers.gcp.attributes import GcpAttr
from tfstride.providers.gcp.firewall_matches import firewall_match_network_rules, normalize_firewall_matches
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_decoration.firewall_decisions import (
    FirewallIngressDecision,
    FirewallIngressSource,
)
from tfstride.providers.gcp.resource_decoration.firewall_policy_exposure import (
    firewall_policy_ingress_decision,
)
from tfstride.providers.gcp.resource_decoration.firewall_rules import (
    firewall_rules_overlap,
    priority_value,
)
from tfstride.providers.gcp.resource_decoration.firewall_targets import (
    instance_service_account_keys,
    service_account_reference_keys,
)
from tfstride.providers.gcp.resource_decoration.firewall_uncertainty import (
    firewall_field_is_uncertain,
    uncertain_firewall_matches,
    uncertain_match_can_override,
)
from tfstride.providers.gcp.resource_decoration.network_posture import (
    resource_has_network_reference,
)
from tfstride.providers.gcp.resource_index import GcpResourceIndex
from tfstride.providers.gcp.resource_mutations import gcp_mutations
from tfstride.providers.gcp.resource_types import GcpResourceType
from tfstride.resource_helpers import describe_security_group_rule


def derive_public_compute_exposure(resource: NormalizedResource, index: GcpResourceIndex) -> None:
    ingress_decision = _compute_internet_ingress_decision(resource, index)
    gcp_mutations(resource).set_compute_internet_ingress(
        internet_ingress_reasons=ingress_decision.internet_ingress_reasons,
        firewall_addresses=ingress_decision.firewall_addresses,
        uncertainties=ingress_decision.uncertainties,
    )

    public_exposure = bool(resource.public_access_configured and ingress_decision.has_internet_ingress)
    gcp_mutations(resource).set_public_exposure(
        public_exposure,
        reasons=(
            ["compute instance has an external access config and matching firewall rules allow internet ingress"]
            if public_exposure
            else None
        ),
    )


def _compute_internet_ingress_decision(
    resource: NormalizedResource,
    index: GcpResourceIndex,
) -> FirewallIngressDecision:
    policy_decision = firewall_policy_ingress_decision(resource, index)
    sources = (
        policy_decision.sources
        if not policy_decision.continues_to_compute_firewalls
        else _compute_firewall_ingress_sources(resource, index)
    )
    policy_uncertainties = policy_decision.uncertain_matches
    compute_uncertainties = tuple(
        (firewall, match)
        for firewall in index.firewalls
        if _firewall_applies_to_instance(firewall, resource, index)
        for match in uncertain_firewall_matches(firewall)
    )
    uncertainties = tuple(
        sorted(
            {
                f"{firewall.address}: {reason}"
                for firewall, match in (*policy_uncertainties, *compute_uncertainties)
                for reason in match["uncertainties"]
            }
        )
    )
    effective_sources: list[FirewallIngressSource] = []
    for source in sources:
        is_policy = source.resource.resource_type == GcpResourceType.COMPUTE_FIREWALL_POLICY_RULE
        constraints = policy_uncertainties if is_policy else (*policy_uncertainties, *compute_uncertainties)
        reasons: list[str] = []
        for rule in source.resource.network_rules:
            description = describe_security_group_rule(source.resource, rule)
            if description not in source.internet_ingress_reasons:
                continue
            if any(
                uncertain_match_can_override(
                    match,
                    source.resource,
                    rule,
                    same_policy=bool(
                        is_policy
                        and source.resource.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_REFERENCE)
                        and source.resource.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_REFERENCE)
                        == firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_REFERENCE)
                    ),
                    policy_constraint=firewall.resource_type == GcpResourceType.COMPUTE_FIREWALL_POLICY_RULE,
                )
                for firewall, match in constraints
            ):
                continue
            reasons.append(description)
        if reasons:
            effective_sources.append(
                FirewallIngressSource(resource=source.resource, internet_ingress_reasons=tuple(reasons))
            )
    return FirewallIngressDecision(sources=tuple(effective_sources), uncertainties=uncertainties)


def _compute_firewall_ingress_sources(
    resource: NormalizedResource,
    index: GcpResourceIndex,
) -> tuple[FirewallIngressSource, ...]:
    applicable_firewalls = tuple(
        firewall for firewall in index.firewalls if _firewall_applies_to_instance(firewall, resource, index)
    )
    return tuple(
        source
        for firewall in applicable_firewalls
        for source in (
            _effective_compute_firewall_ingress_source(
                firewall,
                applicable_firewalls,
            ),
        )
        if source is not None
    )


def _effective_compute_firewall_ingress_source(
    firewall: NormalizedResource,
    applicable_firewalls: tuple[NormalizedResource, ...],
) -> FirewallIngressSource | None:
    internet_ingress_reasons = tuple(
        describe_security_group_rule(firewall, allow_rule)
        for allow_rule in _compute_firewall_internet_ingress_rules(firewall)
        if _compute_firewall_allow_rule_is_effective(
            firewall,
            allow_rule,
            applicable_firewalls,
        )
    )
    if not internet_ingress_reasons:
        return None
    return FirewallIngressSource(
        resource=firewall,
        internet_ingress_reasons=internet_ingress_reasons,
    )


def _compute_firewall_allow_rule_is_effective(
    allow_firewall: NormalizedResource,
    allow_rule: SecurityGroupRule,
    applicable_firewalls: tuple[NormalizedResource, ...],
) -> bool:
    allow_priority = _compute_firewall_priority(allow_firewall)
    winning_priority = min(
        _compute_firewall_priority(firewall)
        for firewall in applicable_firewalls
        if _compute_firewall_has_overlapping_internet_rule(firewall, allow_rule)
    )
    if allow_priority != winning_priority:
        return False
    return not any(
        _compute_firewall_priority(firewall) == allow_priority
        and any(
            firewall_rules_overlap(deny_rule, allow_rule)
            for deny_rule in _compute_firewall_internet_deny_rules(firewall)
        )
        for firewall in applicable_firewalls
    )


def _compute_firewall_has_overlapping_internet_rule(
    firewall: NormalizedResource,
    allow_rule: SecurityGroupRule,
) -> bool:
    return any(
        firewall_rules_overlap(candidate_rule, allow_rule)
        for candidate_rule in (
            *_compute_firewall_internet_ingress_rules(firewall),
            *_compute_firewall_internet_deny_rules(firewall),
        )
    )


def _firewall_applies_to_instance(
    firewall: NormalizedResource,
    instance: NormalizedResource,
    index: GcpResourceIndex,
) -> bool:
    if firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_DISABLED) and not firewall_field_is_uncertain(
        firewall, "disabled"
    ):
        return False
    firewall_direction = (
        str(firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_DIRECTION) or "ingress").strip().lower()
    )
    if firewall_direction != "ingress" and not firewall_field_is_uncertain(firewall, "direction"):
        return False
    if not firewall_field_is_uncertain(firewall, "network") and not resource_has_network_reference(
        instance, firewall.vpc_id, index
    ):
        return False

    target_tags = set(firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_TARGET_TAGS))
    if target_tags and not firewall_field_is_uncertain(firewall, "target_tags"):
        instance_tags = set(instance.get_metadata_field(GcpResourceMetadata.NETWORK_TAGS))
        if not target_tags.intersection(instance_tags):
            return False

    target_service_accounts = service_account_reference_keys(
        firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_TARGET_SERVICE_ACCOUNTS)
    )
    if target_service_accounts and not firewall_field_is_uncertain(firewall, "target_service_accounts"):
        instance_service_accounts = instance_service_account_keys(instance)
        if not target_service_accounts.intersection(instance_service_accounts):
            return False

    return True


def _compute_firewall_internet_ingress_rules(
    firewall: NormalizedResource,
) -> tuple[SecurityGroupRule, ...]:
    return tuple(rule for rule in firewall.network_rules if rule.direction == "ingress" and rule.allows_internet())


def _compute_firewall_internet_deny_rules(firewall: NormalizedResource) -> tuple[SecurityGroupRule, ...]:
    if firewall.has_metadata_field(GcpResourceMetadata.FIREWALL_MATCHES):
        matches = firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_MATCHES)
    else:
        # Compatibility for callers constructing normalized resources directly.
        matches = normalize_firewall_matches(
            {
                GcpAttr.DIRECTION.key: firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_DIRECTION),
                "source_ranges": firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_SOURCE_RANGES),
                "source_tags": firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_SOURCE_TAGS),
                "source_service_accounts": firewall.get_metadata_field(
                    GcpResourceMetadata.FIREWALL_SOURCE_SERVICE_ACCOUNTS
                ),
                "deny": firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_DENY),
            }
        )
    return tuple(
        rule
        for match in matches
        if match["action"] == "deny"
        for rule in firewall_match_network_rules(match)
        if rule.direction == "ingress" and rule.allows_internet()
    )


def _compute_firewall_priority(firewall: NormalizedResource) -> int:
    return priority_value(firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_PRIORITY))
