from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from tfstride.models import NormalizedResource, SecurityGroupRule
from tfstride.providers.gcp.firewall_ingress_evidence import ingress_from_policy_rule
from tfstride.providers.gcp.firewall_matches import GcpFirewallMatch
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_decoration.firewall_decisions import FirewallIngressSource
from tfstride.providers.gcp.resource_decoration.firewall_policy_order import resolve_firewall_policy_order
from tfstride.providers.gcp.resource_decoration.firewall_rules import priority_value
from tfstride.providers.gcp.resource_decoration.firewall_targets import (
    instance_service_account_keys,
    service_account_reference_keys,
)
from tfstride.providers.gcp.resource_decoration.firewall_uncertainty import (
    firewall_field_is_uncertain,
    uncertain_firewall_matches,
)
from tfstride.providers.gcp.resource_decoration.network_posture import (
    resource_has_network_reference,
)
from tfstride.providers.gcp.resource_index import GcpResourceIndex
from tfstride.resource_helpers import describe_security_group_rule


class _FirewallPolicyAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    GOTO_NEXT = "goto_next"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class _FirewallPolicyIngressCandidate:
    policy_rule: NormalizedResource
    policy_key: str
    action: _FirewallPolicyAction
    priority: int
    matches_internet_ingress: bool
    internet_ingress_reasons: tuple[str, ...]

    @property
    def is_allow(self) -> bool:
        return self.action == _FirewallPolicyAction.ALLOW

    @property
    def is_terminal(self) -> bool:
        return self.action in {
            _FirewallPolicyAction.ALLOW,
            _FirewallPolicyAction.DENY,
        }


@dataclass(frozen=True, slots=True)
class _FirewallPolicyIngressDecision:
    policies: tuple[tuple[_FirewallPolicyIngressCandidate, ...], ...]
    uncertainties: tuple[str, ...] = ()

    @property
    def candidates(self) -> tuple[_FirewallPolicyIngressCandidate, ...]:
        return tuple(candidate for policy in self.policies for candidate in policy)

    @property
    def evaluated_candidates(self) -> tuple[_FirewallPolicyIngressCandidate, ...]:
        evaluated: list[_FirewallPolicyIngressCandidate] = []
        for policy in self.policies:
            for candidate in policy:
                evaluated.append(candidate)
                if not candidate.matches_internet_ingress:
                    continue
                if candidate.action == _FirewallPolicyAction.GOTO_NEXT:
                    break
                if candidate.is_terminal:
                    return tuple(evaluated)
        return tuple(evaluated)

    @property
    def uncertain_matches(self) -> tuple[tuple[NormalizedResource, GcpFirewallMatch], ...]:
        evaluated = {candidate.policy_key: candidate for candidate in self.evaluated_candidates}
        return tuple(
            (candidate.policy_rule, match)
            for candidate in self.candidates
            if candidate.policy_key in evaluated
            for match in uncertain_firewall_matches(candidate.policy_rule)
            if (
                not evaluated[candidate.policy_key].matches_internet_ingress
                or match["rule_priority"] is None
                or match["rule_priority"] <= evaluated[candidate.policy_key].priority
            )
        )

    def same_policy(self, left: NormalizedResource, right: NormalizedResource) -> bool:
        keys = {candidate.policy_rule.address: candidate.policy_key for candidate in self.candidates}
        return left.address in keys and keys.get(left.address) == keys.get(right.address)

    @property
    def terminal_candidate(self) -> _FirewallPolicyIngressCandidate | None:
        for candidate in self.evaluated_candidates:
            if candidate.matches_internet_ingress and candidate.is_terminal:
                return candidate
        return None

    @property
    def continues_to_compute_firewalls(self) -> bool:
        return not self.uncertainties and self.terminal_candidate is None

    @property
    def sources(self) -> tuple[FirewallIngressSource, ...]:
        candidate = self.terminal_candidate
        if candidate is None or not candidate.is_allow or not candidate.internet_ingress_reasons:
            return ()
        return (
            FirewallIngressSource(
                resource=candidate.policy_rule,
                internet_ingress_reasons=candidate.internet_ingress_reasons,
                effective_ingress=tuple(
                    ingress_from_policy_rule(
                        candidate.policy_rule, rule, priority=candidate.priority, match_path=f"network_rules[{index}]"
                    )
                    for index, rule in enumerate(candidate.policy_rule.network_rules)
                    if describe_security_group_rule(candidate.policy_rule, rule) in candidate.internet_ingress_reasons
                ),
            ),
        )


def firewall_policy_ingress_decision(
    resource: NormalizedResource,
    index: GcpResourceIndex,
) -> _FirewallPolicyIngressDecision:
    order = resolve_firewall_policy_order(
        resource,
        index,
        tuple(
            rule
            for rule in index.firewall_policy_rules
            if _firewall_policy_rule_targets_instance(rule, resource, index)
        ),
    )
    return _FirewallPolicyIngressDecision(
        policies=tuple(
            tuple(
                sorted(
                    (_firewall_policy_ingress_candidate(rule, group.key) for rule in group.rules),
                    key=lambda candidate: (
                        candidate.priority,
                        0 if candidate.action == _FirewallPolicyAction.DENY else 1,
                        candidate.policy_rule.address,
                    ),
                )
            )
            for group in order.groups
        ),
        uncertainties=order.uncertainties,
    )


def _firewall_policy_ingress_candidate(
    policy_rule: NormalizedResource,
    policy_key: str,
) -> _FirewallPolicyIngressCandidate:
    action = _firewall_policy_action(policy_rule)
    internet_ingress_rules = _firewall_policy_internet_ingress_rules(policy_rule)
    return _FirewallPolicyIngressCandidate(
        policy_rule=policy_rule,
        policy_key=policy_key,
        action=action,
        priority=_firewall_policy_priority(policy_rule),
        matches_internet_ingress=bool(internet_ingress_rules),
        internet_ingress_reasons=(
            tuple(describe_security_group_rule(policy_rule, rule) for rule in internet_ingress_rules)
            if action == _FirewallPolicyAction.ALLOW
            else ()
        ),
    )


def _firewall_policy_action(policy_rule: NormalizedResource) -> _FirewallPolicyAction:
    action = str(policy_rule.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_ACTION) or "").strip().lower()
    if action == "allow":
        return _FirewallPolicyAction.ALLOW
    if action == "deny":
        return _FirewallPolicyAction.DENY
    if action in {"goto_next", "go_to_next"}:
        return _FirewallPolicyAction.GOTO_NEXT
    return _FirewallPolicyAction.UNKNOWN


def _firewall_policy_priority(policy_rule: NormalizedResource) -> int:
    return priority_value(policy_rule.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_PRIORITY))


def _firewall_policy_internet_ingress_rules(
    policy_rule: NormalizedResource,
) -> tuple[SecurityGroupRule, ...]:
    return tuple(rule for rule in policy_rule.network_rules if rule.direction == "ingress" and rule.allows_internet())


def _firewall_policy_rule_targets_instance(
    policy_rule: NormalizedResource,
    instance: NormalizedResource,
    index: GcpResourceIndex,
) -> bool:
    if policy_rule.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_DISABLED) and not firewall_field_is_uncertain(
        policy_rule, "disabled"
    ):
        return False
    policy_direction = (
        str(policy_rule.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_DIRECTION) or "").strip().lower()
    )
    if policy_direction != "ingress" and not firewall_field_is_uncertain(policy_rule, "direction"):
        return False

    target_resources = policy_rule.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_TARGET_RESOURCES)
    target_resource_applies = bool(target_resources) and any(
        resource_has_network_reference(instance, target_resource, index) for target_resource in target_resources
    )
    if (
        target_resources
        and not target_resource_applies
        and not firewall_field_is_uncertain(policy_rule, "target_resources")
    ):
        return False

    target_service_accounts = service_account_reference_keys(
        policy_rule.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_TARGET_SERVICE_ACCOUNTS)
    )
    if (
        target_service_accounts
        and not target_service_accounts.intersection(instance_service_account_keys(instance))
        and not firewall_field_is_uncertain(policy_rule, "target_service_accounts")
    ):
        return False

    return True
