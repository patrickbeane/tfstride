from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from tfstride.models import NormalizedResource, SecurityGroupRule
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_decoration.firewall_decisions import FirewallIngressSource
from tfstride.providers.gcp.resource_decoration.firewall_rules import priority_value
from tfstride.providers.gcp.resource_decoration.firewall_targets import (
    instance_service_account_keys,
    service_account_reference_keys,
)
from tfstride.providers.gcp.resource_decoration.network_posture import (
    resource_has_network_reference,
)
from tfstride.providers.gcp.resource_index import GcpResourceIndex
from tfstride.providers.gcp.resource_types import GcpResourceType
from tfstride.providers.gcp.resource_utils import gcp_reference_key
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
    candidates: tuple[_FirewallPolicyIngressCandidate, ...]

    @property
    def terminal_candidate(self) -> _FirewallPolicyIngressCandidate | None:
        skipped_policy_keys: set[str] = set()
        for candidate in sorted(
            self.candidates,
            key=lambda candidate: (candidate.priority, candidate.policy_rule.address),
        ):
            if candidate.policy_key in skipped_policy_keys:
                continue
            if not candidate.matches_internet_ingress:
                continue
            if candidate.action == _FirewallPolicyAction.GOTO_NEXT:
                skipped_policy_keys.add(candidate.policy_key)
                continue
            if candidate.is_terminal:
                return candidate
        return None

    @property
    def continues_to_compute_firewalls(self) -> bool:
        return self.terminal_candidate is None

    @property
    def sources(self) -> tuple[FirewallIngressSource, ...]:
        candidate = self.terminal_candidate
        if candidate is None or not candidate.is_allow or not candidate.internet_ingress_reasons:
            return ()
        return (
            FirewallIngressSource(
                resource=candidate.policy_rule,
                internet_ingress_reasons=candidate.internet_ingress_reasons,
            ),
        )


def firewall_policy_ingress_decision(
    resource: NormalizedResource,
    index: GcpResourceIndex,
) -> _FirewallPolicyIngressDecision:
    return _FirewallPolicyIngressDecision(candidates=_firewall_policy_ingress_candidates(resource, index))


def _firewall_policy_ingress_candidates(
    resource: NormalizedResource,
    index: GcpResourceIndex,
) -> tuple[_FirewallPolicyIngressCandidate, ...]:
    return tuple(
        candidate
        for policy_rule in index.firewall_policy_rules
        if _firewall_policy_rule_targets_instance(policy_rule, resource, index)
        for candidate in (_firewall_policy_ingress_candidate(policy_rule, index),)
    )


def _firewall_policy_ingress_candidate(
    policy_rule: NormalizedResource,
    index: GcpResourceIndex,
) -> _FirewallPolicyIngressCandidate:
    action = _firewall_policy_action(policy_rule)
    internet_ingress_rules = _firewall_policy_internet_ingress_rules(policy_rule)
    return _FirewallPolicyIngressCandidate(
        policy_rule=policy_rule,
        policy_key=_firewall_policy_group_key(policy_rule, index),
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


def _firewall_policy_group_key(
    policy_rule: NormalizedResource,
    index: GcpResourceIndex,
) -> str:
    policy_reference = policy_rule.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_REFERENCE)
    if policy_reference:
        return gcp_reference_key(str(policy_reference))
    policy_references = sorted(_firewall_policy_reference_keys(policy_rule, index))
    return policy_references[0] if policy_references else gcp_reference_key(policy_rule.address)


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
    if policy_rule.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_DISABLED):
        return False
    policy_direction = (
        str(policy_rule.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_DIRECTION) or "").strip().lower()
    )
    if policy_direction != "ingress":
        return False

    target_resources = policy_rule.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_TARGET_RESOURCES)
    target_resource_applies = bool(target_resources) and any(
        resource_has_network_reference(instance, target_resource, index) for target_resource in target_resources
    )
    if target_resources and not target_resource_applies:
        return False

    target_service_accounts = service_account_reference_keys(
        policy_rule.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_TARGET_SERVICE_ACCOUNTS)
    )
    if target_service_accounts and not target_service_accounts.intersection(instance_service_account_keys(instance)):
        return False

    associations = _firewall_policy_associations_for_rule(policy_rule, index)
    if not associations:
        return target_resource_applies
    return any(
        _firewall_policy_association_applies_to_instance(association, instance, index) for association in associations
    )


def _firewall_policy_associations_for_rule(
    policy_rule: NormalizedResource,
    index: GcpResourceIndex,
) -> tuple[NormalizedResource, ...]:
    policy_references = _firewall_policy_reference_keys(policy_rule, index)
    if not policy_references:
        return ()
    return tuple(
        association
        for association in index.firewall_policy_associations
        if policy_references.intersection(_firewall_policy_reference_keys(association, index))
    )


def _firewall_policy_association_applies_to_instance(
    association: NormalizedResource,
    instance: NormalizedResource,
    index: GcpResourceIndex,
) -> bool:
    target = association.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_ATTACHMENT_TARGET)
    if not target:
        return False
    if resource_has_network_reference(instance, target, index):
        return True

    project = _project_from_scope_reference(target)
    if project and project == _resource_project(instance):
        return True

    folder_id = _hierarchy_id_from_scope_reference(target, "folders")
    if folder_id and folder_id == _resource_folder_id(instance):
        return True

    organization_id = _hierarchy_id_from_scope_reference(target, "organizations")
    if organization_id and organization_id == _resource_organization_id(instance):
        return True

    return False


def _firewall_policy_reference_keys(
    resource: NormalizedResource,
    index: GcpResourceIndex | None = None,
) -> set[str]:
    references = {
        resource.address,
        f"{resource.address}.id",
        f"{resource.address}.name",
    }
    for reference in (
        resource.identifier,
        resource.get_metadata_field(GcpResourceMetadata.NAME),
        resource.get_metadata_field(GcpResourceMetadata.SELF_LINK),
        resource.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_REFERENCE),
    ):
        if reference:
            references.add(reference)
    keys = {gcp_reference_key(str(reference)) for reference in references if str(reference).strip()}
    if index is None:
        return keys

    expanded_keys = set(keys)
    for key in keys:
        policy = index.resources_by_reference.get(key)
        if policy is None or policy.resource_type != GcpResourceType.COMPUTE_FIREWALL_POLICY:
            continue
        expanded_keys.update(_firewall_policy_reference_keys(policy))
    return expanded_keys


def _resource_project(resource: NormalizedResource) -> str | None:
    project = resource.get_metadata_field(GcpResourceMetadata.PROJECT)
    if project:
        return project
    for reference in (
        resource.identifier,
        resource.get_metadata_field(GcpResourceMetadata.SELF_LINK),
        resource.vpc_id,
    ):
        project = _project_from_scope_reference(reference)
        if project:
            return project
    return None


def _resource_folder_id(resource: NormalizedResource) -> str | None:
    folder_id = resource.get_metadata_field(GcpResourceMetadata.FOLDER_ID)
    if folder_id:
        return _normalize_hierarchy_id(folder_id, "folders")
    for reference in (
        resource.identifier,
        resource.get_metadata_field(GcpResourceMetadata.SELF_LINK),
    ):
        folder_id = _hierarchy_id_from_scope_reference(reference, "folders")
        if folder_id:
            return folder_id
    return None


def _resource_organization_id(resource: NormalizedResource) -> str | None:
    organization_id = resource.get_metadata_field(GcpResourceMetadata.ORGANIZATION_ID)
    if organization_id:
        return _normalize_hierarchy_id(organization_id, "organizations")
    for reference in (
        resource.identifier,
        resource.get_metadata_field(GcpResourceMetadata.SELF_LINK),
    ):
        organization_id = _hierarchy_id_from_scope_reference(reference, "organizations")
        if organization_id:
            return organization_id
    return None


def _project_from_scope_reference(value: object) -> str | None:
    text = str(value or "").strip().rstrip("/")
    if not text:
        return None
    parts = [part for part in text.split("/") if part]
    for index, part in enumerate(parts[:-1]):
        if part == "projects":
            return parts[index + 1] or None
    return None


def _hierarchy_id_from_scope_reference(value: object, marker: str) -> str | None:
    text = str(value or "").strip().rstrip("/")
    if not text:
        return None
    parts = [part for part in text.split("/") if part]
    for index, part in enumerate(parts[:-1]):
        if part == marker:
            return _normalize_hierarchy_id(parts[index + 1], marker)
    return _normalize_hierarchy_id(text, marker) if text.startswith(f"{marker}/") else None


def _normalize_hierarchy_id(value: str | None, marker: str) -> str | None:
    text = str(value or "").strip().rstrip("/")
    if not text:
        return None
    prefix = f"{marker}/"
    if text.startswith(prefix):
        return text.removeprefix(prefix) or None
    return text
