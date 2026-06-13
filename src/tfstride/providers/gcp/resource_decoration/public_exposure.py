from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

from tfstride.models import NormalizedResource, SecurityGroupRule
from tfstride.providers.gcp.constants import PUBLIC_GCP_IAM_MEMBERS
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_decoration.iam import (
    iam_bindings,
    resource_iam_target_reference,
    serverless_iam_resources,
)
from tfstride.providers.gcp.resource_decoration.network_posture import (
    resource_has_network_reference,
)
from tfstride.providers.gcp.resource_index import (
    GcpDecorationContext,
    GcpResourceIndex,
    gcp_resource_references,
)
from tfstride.providers.gcp.resource_mutations import gcp_mutations
from tfstride.providers.gcp.resource_types import (
    GCP_SERVERLESS_WORKLOAD_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.gcp.resource_utils import (
    GCP_NETWORK_REFERENCE_SUFFIXES,
    binding_members,
    dedupe,
    gcp_reference_key,
)
from tfstride.resource_helpers import describe_security_group_rule


_SERVERLESS_PUBLIC_INVOKER_ROLES = frozenset({"roles/run.invoker", "roles/cloudfunctions.invoker"})


@dataclass(frozen=True, slots=True)
class _FirewallIngressSource:
    resource: NormalizedResource
    internet_ingress_reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _FirewallIngressDecision:
    sources: tuple[_FirewallIngressSource, ...]

    @property
    def has_internet_ingress(self) -> bool:
        return any(source.internet_ingress_reasons for source in self.sources)

    @property
    def internet_ingress_reasons(self) -> tuple[str, ...]:
        return tuple(
            reason
            for source in self.sources
            for reason in source.internet_ingress_reasons
        )

    @property
    def firewall_addresses(self) -> tuple[str, ...]:
        return tuple(source.resource.address for source in self.sources)


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
    def sources(self) -> tuple[_FirewallIngressSource, ...]:
        candidate = self.terminal_candidate
        if candidate is None or not candidate.is_allow or not candidate.internet_ingress_reasons:
            return ()
        return (
            _FirewallIngressSource(
                resource=candidate.policy_rule,
                internet_ingress_reasons=candidate.internet_ingress_reasons,
            ),
        )


class DerivePublicExposureStage:
    name = "derive_public_exposure"

    def apply(self, resources: list[NormalizedResource], context: GcpDecorationContext) -> None:
        index = context.index
        for resource in resources:
            if resource.resource_type == GcpResourceType.COMPUTE_INSTANCE:
                _derive_public_compute_exposure(resource, index)
            elif resource.resource_type in GCP_SERVERLESS_WORKLOAD_RESOURCE_TYPES:
                _derive_public_serverless_exposure(resource, index)
            elif resource.resource_type == GcpResourceType.STORAGE_BUCKET:
                _derive_public_bucket_exposure(resource, index)


def _derive_public_compute_exposure(resource: NormalizedResource, index: GcpResourceIndex) -> None:
    ingress_decision = _compute_internet_ingress_decision(resource, index)
    gcp_mutations(resource).set_compute_internet_ingress(
        internet_ingress_reasons=ingress_decision.internet_ingress_reasons,
        firewall_addresses=ingress_decision.firewall_addresses,
    )

    public_exposure = bool(
        resource.public_access_configured and ingress_decision.has_internet_ingress
    )
    gcp_mutations(resource).set_public_exposure(
        public_exposure,
        reasons=(
            [
                "compute instance has an external access config and matching firewall "
                "rules allow internet ingress"
            ]
            if public_exposure
            else None
        ),
    )


def _compute_internet_ingress_decision(
    resource: NormalizedResource,
    index: GcpResourceIndex,
) -> _FirewallIngressDecision:
    policy_decision = _firewall_policy_ingress_decision(resource, index)
    if not policy_decision.continues_to_compute_firewalls:
        return _FirewallIngressDecision(sources=policy_decision.sources)
    return _FirewallIngressDecision(
        sources=(*_compute_firewall_ingress_sources(resource, index),)
    )


def _compute_firewall_ingress_sources(
    resource: NormalizedResource,
    index: GcpResourceIndex,
) -> tuple[_FirewallIngressSource, ...]:
    applicable_firewalls = tuple(
        firewall
        for firewall in index.firewalls
        if _firewall_applies_to_instance(firewall, resource, index)
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
) -> _FirewallIngressSource | None:
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
    return _FirewallIngressSource(
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
            _firewall_rules_overlap(deny_rule, allow_rule)
            for deny_rule in _compute_firewall_internet_deny_rules(firewall)
        )
        for firewall in applicable_firewalls
    )


def _compute_firewall_has_overlapping_internet_rule(
    firewall: NormalizedResource,
    allow_rule: SecurityGroupRule,
) -> bool:
    return any(
        _firewall_rules_overlap(candidate_rule, allow_rule)
        for candidate_rule in (
            *_compute_firewall_internet_ingress_rules(firewall),
            *_compute_firewall_internet_deny_rules(firewall),
        )
    )


def _firewall_policy_ingress_decision(
    resource: NormalizedResource,
    index: GcpResourceIndex,
) -> _FirewallPolicyIngressDecision:
    return _FirewallPolicyIngressDecision(
        candidates=_firewall_policy_ingress_candidates(resource, index)
    )


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
            tuple(
                describe_security_group_rule(policy_rule, rule)
                for rule in internet_ingress_rules
            )
            if action == _FirewallPolicyAction.ALLOW
            else ()
        ),
    )


def _derive_public_bucket_exposure(bucket: NormalizedResource, index: GcpResourceIndex) -> None:
    public_access_reasons = _bucket_public_access_reasons(bucket, index)
    gcp_mutations(bucket).set_public_access(
        configured=bool(public_access_reasons),
        reasons=public_access_reasons,
    )

    public_exposure = bool(public_access_reasons) and not _public_access_prevention_enforced(bucket)
    gcp_mutations(bucket).set_public_exposure(
        public_exposure,
        reasons=public_access_reasons if public_exposure else None,
    )


def _derive_public_serverless_exposure(
    resource: NormalizedResource,
    index: GcpResourceIndex,
) -> None:
    public_access_reasons = _serverless_public_access_reasons(
        resource,
        serverless_iam_resources(resource, index),
    )
    if public_access_reasons:
        gcp_mutations(resource).set_public_access_reasons(public_access_reasons)
    public_exposure = bool(resource.public_access_configured and public_access_reasons)
    gcp_mutations(resource).set_public_exposure(
        public_exposure,
        reasons=public_access_reasons if public_exposure else None,
    )


def _bucket_public_access_reasons(bucket: NormalizedResource, index: GcpResourceIndex) -> list[str]:
    reasons: list[str] = []
    bucket_references = set(gcp_resource_references(bucket))
    for iam_resource in index.bucket_iam_resources:
        iam_bucket = iam_resource.get_metadata_field(GcpResourceMetadata.BUCKET_NAME)
        if (
            not iam_bucket
            or gcp_reference_key(iam_bucket, GCP_NETWORK_REFERENCE_SUFFIXES)
            not in bucket_references
        ):
            continue
        for binding in iam_bindings(iam_resource):
            role = str(binding.get("role") or "unknown role")
            public_members = sorted(
                member
                for member in binding_members(binding)
                if member in PUBLIC_GCP_IAM_MEMBERS
            )
            for member in public_members:
                reasons.append(f"{iam_resource.address} grants {role} to {member}")
    return dedupe(reasons)


def _serverless_public_access_reasons(
    resource: NormalizedResource,
    iam_resources: tuple[NormalizedResource, ...],
) -> list[str]:
    reasons: list[str] = []
    resource_references = set(gcp_resource_references(resource))
    for iam_resource in iam_resources:
        target_reference = resource_iam_target_reference(iam_resource)
        if (
            not target_reference
            or gcp_reference_key(target_reference, GCP_NETWORK_REFERENCE_SUFFIXES)
            not in resource_references
        ):
            continue
        for binding in iam_bindings(iam_resource):
            role = str(binding.get("role") or "unknown role")
            if role not in _SERVERLESS_PUBLIC_INVOKER_ROLES:
                continue
            public_members = sorted(
                member
                for member in binding_members(binding)
                if member in PUBLIC_GCP_IAM_MEMBERS
            )
            for member in public_members:
                reasons.append(f"{iam_resource.address} grants {role} to {member}")
    return dedupe(reasons)


def _public_access_prevention_enforced(bucket: NormalizedResource) -> bool:
    value = bucket.get_metadata_field(GcpResourceMetadata.PUBLIC_ACCESS_PREVENTION)
    return value is not None and value.strip().lower() == "enforced"


def _firewall_applies_to_instance(
    firewall: NormalizedResource,
    instance: NormalizedResource,
    index: GcpResourceIndex,
) -> bool:
    if firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_DISABLED):
        return False
    firewall_direction = str(
        firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_DIRECTION) or "ingress"
    ).strip().lower()
    if firewall_direction != "ingress":
        return False
    if not resource_has_network_reference(instance, firewall.vpc_id, index):
        return False

    target_tags = set(firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_TARGET_TAGS))
    if target_tags:
        instance_tags = set(instance.get_metadata_field(GcpResourceMetadata.NETWORK_TAGS))
        if not target_tags.intersection(instance_tags):
            return False

    target_service_accounts = _service_account_reference_keys(
        firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_TARGET_SERVICE_ACCOUNTS)
    )
    if target_service_accounts:
        instance_service_accounts = _instance_service_account_keys(instance)
        if not target_service_accounts.intersection(instance_service_accounts):
            return False

    return True


def _compute_firewall_internet_ingress_rules(
    firewall: NormalizedResource,
) -> tuple[SecurityGroupRule, ...]:
    return tuple(
        rule
        for rule in firewall.network_rules
        if rule.direction == "ingress" and rule.allows_internet()
    )


def _compute_firewall_internet_deny_rules(
    firewall: NormalizedResource,
) -> tuple[SecurityGroupRule, ...]:
    return tuple(
        rule
        for rule in _metadata_firewall_rules(
            firewall,
            GcpResourceMetadata.FIREWALL_DENY,
        )
        if rule.direction == "ingress" and rule.allows_internet()
    )


def _metadata_firewall_rules(
    firewall: NormalizedResource,
    metadata_field: object,
) -> tuple[SecurityGroupRule, ...]:
    direction = str(
        firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_DIRECTION) or "ingress"
    ).strip().lower()
    cidr_blocks = _firewall_cidr_blocks(firewall, direction)
    rules: list[SecurityGroupRule] = []
    for rule_block in firewall.get_metadata_field(metadata_field):
        if not isinstance(rule_block, Mapping):
            continue
        protocol = str(rule_block.get("protocol") or "-1")
        ports = rule_block.get("ports")
        if not ports:
            rules.append(_firewall_rule(direction, protocol, None, None, cidr_blocks))
            continue
        for port in ports if isinstance(ports, list) else [ports]:
            from_port, to_port = _parse_firewall_port_range(port)
            rules.append(
                _firewall_rule(direction, protocol, from_port, to_port, cidr_blocks)
            )
    return tuple(rules)


def _firewall_rule(
    direction: str,
    protocol: str,
    from_port: int | None,
    to_port: int | None,
    cidr_blocks: list[str],
) -> SecurityGroupRule:
    return SecurityGroupRule(
        direction=direction,
        protocol="-1" if protocol.lower() in {"all", "-1"} else protocol,
        from_port=from_port,
        to_port=to_port,
        cidr_blocks=list(cidr_blocks),
    )


def _firewall_cidr_blocks(firewall: NormalizedResource, direction: str) -> list[str]:
    source_ranges = firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_SOURCE_RANGES)
    destination_ranges = firewall.get_metadata_field(
        GcpResourceMetadata.FIREWALL_DESTINATION_RANGES
    )
    if direction == "egress" and destination_ranges:
        return destination_ranges
    if source_ranges:
        return source_ranges
    source_tags = firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_SOURCE_TAGS)
    source_service_accounts = firewall.get_metadata_field(
        GcpResourceMetadata.FIREWALL_SOURCE_SERVICE_ACCOUNTS
    )
    if direction == "ingress" and not source_tags and not source_service_accounts:
        return ["0.0.0.0/0"]
    return []


def _parse_firewall_port_range(value: object) -> tuple[int | None, int | None]:
    text = str(value).strip()
    if not text:
        return (None, None)
    if "-" not in text:
        port = _optional_int(text)
        return (port, port)
    start, end = text.split("-", 1)
    return (_optional_int(start.strip()), _optional_int(end.strip()))


def _optional_int(value: str) -> int | None:
    try:
        return int(value)
    except ValueError:
        return None


def _compute_firewall_priority(firewall: NormalizedResource) -> int:
    return _priority_value(
        firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_PRIORITY)
    )


def _priority_value(value: object, *, default: int = 1000) -> int:
    if value is None:
        return default
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except ValueError:
        return default


def _firewall_rules_overlap(left: SecurityGroupRule, right: SecurityGroupRule) -> bool:
    if not _firewall_protocols_overlap(left.protocol, right.protocol):
        return False
    left_ports = _firewall_port_range(left)
    right_ports = _firewall_port_range(right)
    if left_ports is None or right_ports is None:
        return True
    left_start, left_end = left_ports
    right_start, right_end = right_ports
    return left_start <= right_end and right_start <= left_end


def _firewall_protocols_overlap(left: str, right: str) -> bool:
    left_protocol = left.lower()
    right_protocol = right.lower()
    return (
        left_protocol == "-1"
        or right_protocol == "-1"
        or left_protocol == right_protocol
    )


def _firewall_port_range(rule: SecurityGroupRule) -> tuple[int, int] | None:
    if rule.protocol == "-1" or rule.from_port is None or rule.to_port is None:
        return None
    return (rule.from_port, rule.to_port)


def _firewall_policy_action(policy_rule: NormalizedResource) -> _FirewallPolicyAction:
    action = str(
        policy_rule.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_ACTION) or ""
    ).strip().lower()
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
    policy_reference = policy_rule.get_metadata_field(
        GcpResourceMetadata.FIREWALL_POLICY_REFERENCE
    )
    if policy_reference:
        return gcp_reference_key(str(policy_reference))
    policy_references = sorted(_firewall_policy_reference_keys(policy_rule, index))
    return (
        policy_references[0]
        if policy_references
        else gcp_reference_key(policy_rule.address)
    )


def _firewall_policy_priority(policy_rule: NormalizedResource) -> int:
    return _priority_value(
        policy_rule.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_PRIORITY)
    )


def _firewall_policy_internet_ingress_rules(
    policy_rule: NormalizedResource,
) -> tuple[SecurityGroupRule, ...]:
    return tuple(
        rule
        for rule in policy_rule.network_rules
        if rule.direction == "ingress" and rule.allows_internet()
    )


def _firewall_policy_rule_targets_instance(
    policy_rule: NormalizedResource,
    instance: NormalizedResource,
    index: GcpResourceIndex,
) -> bool:
    if policy_rule.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_DISABLED):
        return False
    policy_direction = str(
        policy_rule.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_DIRECTION) or ""
    ).strip().lower()
    if policy_direction != "ingress":
        return False

    target_resources = policy_rule.get_metadata_field(
        GcpResourceMetadata.FIREWALL_POLICY_TARGET_RESOURCES
    )
    target_resource_applies = bool(target_resources) and any(
        resource_has_network_reference(instance, target_resource, index)
        for target_resource in target_resources
    )
    if target_resources and not target_resource_applies:
        return False

    target_service_accounts = _service_account_reference_keys(
        policy_rule.get_metadata_field(
            GcpResourceMetadata.FIREWALL_POLICY_TARGET_SERVICE_ACCOUNTS
        )
    )
    if target_service_accounts and not target_service_accounts.intersection(
        _instance_service_account_keys(instance)
    ):
        return False

    associations = _firewall_policy_associations_for_rule(policy_rule, index)
    if not associations:
        return target_resource_applies
    return any(
        _firewall_policy_association_applies_to_instance(association, instance, index)
        for association in associations
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


def _instance_service_account_keys(instance: NormalizedResource) -> set[str]:
    keys: set[str] = set()
    for account in instance.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNTS):
        if not isinstance(account, dict):
            continue
        keys.update(_service_account_reference_keys([account.get("email")]))
    return keys


def _service_account_reference_keys(values: list[object]) -> set[str]:
    keys: set[str] = set()
    for value in values:
        if value in (None, "", "default"):
            continue
        text = str(value).strip()
        if not text or text == "default":
            continue
        keys.add(text)
        if text.startswith("serviceAccount:"):
            keys.add(text.removeprefix("serviceAccount:"))
        else:
            keys.add(f"serviceAccount:{text}")
    return keys