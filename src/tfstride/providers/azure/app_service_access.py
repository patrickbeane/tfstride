"""Effective App Service default-endpoint restrictions, independent of authentication.

Address intervals are partitioned at rule boundaries. A rule with uncertain
matching or priority contributes only where it could be the first match. Known
header witnesses can establish constrained access without erasing the headers.
Service-tag expansion and service-endpoint reachability remain offline unknowns.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass
from itertools import islice, product
from typing import Any, cast

from tfstride.models import NormalizedResource
from tfstride.providers.azure.resource_facts import azure_facts

_MAX_PRIORITY = 2147483647
_HEADER_WITNESS_LIMIT = 32
_HEADERS = frozenset({"x_forwarded_for", "x_forwarded_host", "x_azure_fdid", "x_fd_health_probe"})
_SELECTORS = ("ip_address", "service_tag", "virtual_network_subnet_id")
_Network = ipaddress.IPv4Network | ipaddress.IPv6Network
_Interval = tuple[int, int]


@dataclass(frozen=True, slots=True)
class _Rule:
    index: int
    priority: int | None
    actions: frozenset[str]
    networks: tuple[_Network, ...]
    source_known: bool
    headers: dict[str, tuple[str, ...]]
    headers_known: bool
    record: dict[str, Any]

    def matches(self, version: int, source: int, headers: Mapping[str, str] | None) -> bool | None:
        if self.networks and not any(
            network.version == version and int(network.network_address) <= source <= int(network.broadcast_address)
            for network in self.networks
        ):
            return False
        if headers is not None and any(headers.get(key) not in values for key, values in self.headers.items()):
            return False
        if not self.source_known or not self.headers_known or (self.headers and headers is None):
            return None
        return True

    def rank(self, *, upper: bool, ordered: bool) -> tuple[int, int]:
        priority = self.priority if self.priority is not None else (_MAX_PRIORITY if upper else 1)
        return priority, self.index if ordered else int(upper)


@dataclass(frozen=True, slots=True)
class _Decision:
    actions: frozenset[str]
    winners: tuple[int, ...]
    default_possible: bool


def evaluate_app_service_access(resource: NormalizedResource) -> dict[str, Any]:
    """Re-evaluate normalized inputs; cached effective-ingress metadata is never proof."""
    facts = azure_facts(resource)
    inputs = facts.app_service_restriction_inputs
    main = _site(
        facts.app_service_access_restrictions,
        facts.app_service_ip_restriction_default_action,
        inputs.get("main", {}),
        inputs.get("rule_defaults_known") is True,
        "ip_restriction",
    )
    separate = _site(
        facts.app_service_scm_access_restrictions,
        facts.app_service_scm_ip_restriction_default_action,
        inputs.get("scm", {}),
        inputs.get("rule_defaults_known") is True,
        "scm_ip_restriction",
    )
    inheritance = inputs.get("scm_inheritance_state", "unknown")
    if inheritance == "main":
        scm = {**main, "inheritance": "main"}
    elif inheritance == "separate":
        scm = {**separate, "inheritance": "separate"}
    else:
        scm = {
            "state": main["state"] if main["state"] == separate["state"] else "unresolved",
            "external_access": main["external_access"]
            if main["external_access"] == separate["external_access"]
            else "unknown",
            "inheritance": "unknown",
            "alternatives": {"main": main, "separate": separate},
            "uncertainties": ["scm_use_main_ip_restriction is not established"],
        }
    enabled = facts.public_network_access_enabled
    return {
        "assessment_scope": "default_endpoint_access_restrictions",
        "public_network_access": "enabled" if enabled is True else "disabled" if enabled is False else "unknown",
        "main": _endpoint(main, enabled),
        "scm": _endpoint(scm, enabled),
    }


def _endpoint(policy: dict[str, Any], enabled: bool | None) -> dict[str, Any]:
    result = {**policy, "restriction_state": policy["state"]}
    if enabled is False:
        result.update(
            state="blocked", external_access="blocked", endpoint_evidence="public_network_access_enabled=false"
        )
    elif enabled is None and policy["state"] != "blocked":
        result.update(
            state="unresolved",
            external_access="unknown",
            endpoint_evidence="public_network_access_enabled is not established",
        )
    else:
        result["endpoint_evidence"] = (
            "public_network_access_enabled=true"
            if enabled
            else "restrictions block access independently of endpoint configuration"
        )
    return result


def _site(
    records: list[dict[str, Any]], default: str | None, inputs: dict[str, Any], defaults_known: bool, field: str
) -> dict[str, Any]:
    complete = inputs.get("rules_complete") is True
    rules = [_rule(record, index, defaults_known) for index, record in enumerate(records)]
    if not complete:
        rules.append(_rule({"unknown_fields": ["action", "priority", *_SELECTORS, "headers"]}, -1, False))
    default_state = inputs.get("default_action_state", "unknown")
    default_source = default_state
    if default_state == "implicit":
        default = ("Deny" if records else "Allow") if complete else None
        default_source = (
            "implicit_deny_with_rules"
            if records and complete
            else "implicit_allow_without_rules"
            if complete
            else "unknown_rule_presence"
        )
    elif default_state != "known":
        default = None
    default_actions = frozenset({default}) if default in {"Allow", "Deny"} else frozenset({"Allow", "Deny"})
    ordered = inputs.get("rule_order_known") is True and complete
    witnesses, exhaustive_headers = _header_witnesses(rules)
    scopes: list[dict[str, Any]] = []
    allowed: dict[int, list[_Interval]] = {4: [], 6: []}
    blocked: dict[int, list[_Interval]] = {4: [], 6: []}
    allow_proven = deny_proven = external_proven = False
    uncertain = False
    for version, width in ((4, 32), (6, 128)):
        boundaries = {0, 1 << width}
        for rule in rules:
            for network in rule.networks:
                if network.version == version:
                    boundaries.update((int(network.network_address), int(network.broadcast_address) + 1))
        positions = sorted(boundaries)
        for start, stop in zip(positions, positions[1:], strict=False):
            decision = _decide(rules, version, start, None, ordered, default_actions)
            concrete_decisions: list[tuple[dict[str, str], _Decision]] = []
            if len(decision.actions) > 1:
                concrete_decisions = [
                    (headers, _decide(rules, version, start, headers, ordered, default_actions))
                    for headers in witnesses
                ]
                if exhaustive_headers:
                    decision = _Decision(
                        frozenset(action for _, item in concrete_decisions for action in item.actions),
                        tuple(sorted({winner for _, item in concrete_decisions for winner in item.winners})),
                        any(item.default_possible for _, item in concrete_decisions),
                    )
            state = (
                "allowed" if decision.actions == {"Allow"} else "blocked" if decision.actions == {"Deny"} else "unknown"
            )
            proof: dict[str, Any] = {}
            if state == "allowed":
                allowed[version].append((start, stop - 1))
                allow_proven = True
                external_proven |= _internet_witness(version, start, stop - 1) is not None
            elif state == "blocked":
                blocked[version].append((start, stop - 1))
                deny_proven = True
            else:
                conditional = exhaustive_headers and all(len(item.actions) == 1 for _, item in concrete_decisions)
                state = "conditional" if conditional else "unknown"
                uncertain |= not conditional
                for headers, concrete in concrete_decisions:
                    if concrete.actions == {"Allow"} and "allow_witness" not in proof:
                        internet = _internet_witness(version, start, stop - 1)
                        proof["allow_witness"] = {"source_ip": internet or _address(version, start), "headers": headers}
                        allow_proven = True
                        external_proven |= internet is not None
                    if concrete.actions == {"Deny"} and "deny_witness" not in proof:
                        proof["deny_witness"] = {"source_ip": _address(version, start), "headers": headers}
                        deny_proven = True
                    if len(proof) == 2:
                        break
            scopes.append(
                {
                    "source_cidrs": _cidrs(version, [(start, stop - 1)]),
                    "state": state,
                    "possible_actions": sorted(decision.actions),
                    "rule_indices": list(decision.winners),
                    "default_possible": decision.default_possible,
                    **proof,
                }
            )
    if all(scope["state"] == "allowed" for scope in scopes):
        state = "unrestricted"
    elif all(scope["state"] == "blocked" for scope in scopes):
        state = "blocked"
    elif allow_proven and deny_proven:
        state = "restricted"
    else:
        state = "unresolved"
    return {
        "state": state,
        "external_access": "allowed" if external_proven else "blocked" if state == "blocked" else "unknown",
        "default_action": default if len(default_actions) == 1 else None,
        "default_action_source": default_source,
        "rule_order": "priority_then_plan_list" if ordered else "priority_with_unresolved_ties",
        "allowed_source_cidrs": [cidr for version, ranges in allowed.items() for cidr in _cidrs(version, ranges)],
        "blocked_source_cidrs": [cidr for version, ranges in blocked.items() for cidr in _cidrs(version, ranges)],
        "source_scopes": scopes,
        "rule_evidence": [
            {
                "rule_index": rule.index,
                "path": f"site_config.{field}[{rule.index}]",
                "effective_priority": rule.priority,
                "effective_actions": sorted(rule.actions),
                **rule.record,
            }
            for rule in rules
        ],
        "uncertainties": [
            "some source/request subsets require unresolved priority, selectors, headers, or default action"
        ]
        if uncertain
        else [],
        "header_witness_limit": _HEADER_WITNESS_LIMIT,
        "header_partition_complete": exhaustive_headers,
    }


def _rule(record: dict[str, Any], index: int, defaults_known: bool) -> _Rule:
    unknown = set(record.get("unknown_fields", []))
    action = record.get("action", "Allow" if defaults_known else None)
    actions = (
        frozenset({action}) if action in {"Allow", "Deny"} and "action" not in unknown else frozenset({"Allow", "Deny"})
    )
    priority = record.get("priority", 65000 if defaults_known else None)
    if type(priority) is not int or not 1 <= priority <= _MAX_PRIORITY or "priority" in unknown:
        priority = None
    selectors = [key for key in _SELECTORS if record.get(key) and key not in unknown]
    networks: list[_Network] = []
    source_known = selectors == ["ip_address"] and not unknown.intersection(_SELECTORS)
    if source_known:
        value = record["ip_address"]
        try:
            # Azure supports comma-separated multi-source rules. Service tags,
            # AnyVnets, and malformed addresses remain constraints, not 0/0.
            networks = [ipaddress.ip_network(item.strip(), strict=True) for item in value.split(",")]
            if len(networks) > 8:
                networks = []
                source_known = False
        except (ValueError, AttributeError):
            source_known = False
    headers: dict[str, tuple[str, ...]] = {}
    headers_known = "headers" not in unknown
    unknown_headers = record.get("unknown_header_fields")
    for block in record.get("headers", []) if headers_known or isinstance(unknown_headers, list) else []:
        block = cast(dict[str, Any], block)
        for key, values in block.items():
            if isinstance(unknown_headers, list) and key in unknown_headers:
                continue
            if (
                key not in _HEADERS
                or not values
                or len(values) > 8
                or any(not isinstance(value, str) or not value or len(value) > 64 or "*" in value for value in values)
            ):
                headers_known = False
                continue
            if key == "x_forwarded_for":
                try:
                    values = [str(ipaddress.ip_address(value)) for value in values]
                except ValueError:
                    headers_known = False
                    continue
            headers[key] = tuple(values)
    return _Rule(index, priority, actions, tuple(networks), source_known, headers, headers_known, record)


def _decide(
    rules: list[_Rule],
    version: int,
    source: int,
    headers: Mapping[str, str] | None,
    ordered: bool,
    default: frozenset[str],
) -> _Decision:
    matches = [(rule, rule.matches(version, source, headers)) for rule in rules]
    guaranteed = [rule.rank(upper=True, ordered=ordered) for rule, match in matches if match is True]
    first_guaranteed = min(guaranteed) if guaranteed else None
    winners = [
        rule
        for rule, match in matches
        if match is not False
        and (first_guaranteed is None or rule.rank(upper=False, ordered=ordered) <= first_guaranteed)
    ]
    actions = {action for rule in winners for action in rule.actions}
    if not guaranteed:
        actions.update(default)
    return _Decision(frozenset(actions), tuple(rule.index for rule in winners), not guaranteed)


def _header_witnesses(rules: list[_Rule]) -> tuple[list[dict[str, str]], bool]:
    # For supported exact header values, each value plus an absent/unmatched
    # representative forms a complete partition. Cap the Cartesian product;
    # an incomplete partition may prove witnesses, but never exhaustive denial.
    values_by_key: dict[str, set[str]] = {}
    for rule in rules:
        for key, values in rule.headers.items():
            values_by_key.setdefault(key, set()).update(values)
    keys = sorted(values_by_key)
    combinations = 1
    for values in values_by_key.values():
        combinations *= len(values) + 1
    witnesses = [
        {key: value for key, value in zip(keys, values, strict=True) if value is not None}
        for values in islice(product(*([None, *sorted(values_by_key[key])] for key in keys)), _HEADER_WITNESS_LIMIT)
    ]
    return witnesses, combinations <= _HEADER_WITNESS_LIMIT


def _address(version: int, value: int) -> str:
    return str(ipaddress.IPv4Address(value) if version == 4 else ipaddress.IPv6Address(value))


def _cidrs(version: int, intervals: list[_Interval]) -> list[str]:
    address = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    merged: list[_Interval] = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return [
        str(network)
        for start, end in merged
        for network in ipaddress.summarize_address_range(address(start), address(end))
    ]


def _internet_witness(version: int, start: int, end: int) -> str | None:
    candidates = [start, end, int(ipaddress.ip_address("8.8.8.8" if version == 4 else "2001:4860:4860::8888"))]
    for cidr in _cidrs(version, [(start, end)]):
        network = ipaddress.ip_network(cidr)
        candidates.extend((int(network.network_address), int(network.broadcast_address)))
    for candidate in candidates:
        if start <= candidate <= end:
            address = ipaddress.ip_address(_address(version, candidate))
            if address.is_global and not address.is_multicast:
                return str(address)
    return None
