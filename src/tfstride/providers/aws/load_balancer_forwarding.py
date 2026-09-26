"""Preserve forwarding decisions and their Terraform reference locations.

Target references are deliberately separate from action completeness: a symbolic
reference can resolve a target, but cannot establish an action type or weight.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from tfstride.models import TerraformResource
from tfstride.providers.coercion import (
    block_attribute_unknown,
    unknown_block_at,
    value_is_unknown,
)


def _blocks(value: Any, unknown: Any) -> list[tuple[Mapping[str, Any], Any]]:
    if unknown is True or not isinstance(value, list):
        return [({}, True)] if unknown is True or value is not None else []
    count = max(len(value), len(unknown) if isinstance(unknown, list) else 0)
    return [
        (value[i], unknown_block_at(unknown, i)) if i < len(value) and isinstance(value[i], Mapping) else ({}, True)
        for i in range(count)
    ]


def _integer(values: Mapping[str, Any], unknown: Any, key: str, default: int | None, maximum: int) -> int | None:
    if block_attribute_unknown(unknown, key):
        return None
    value = values.get(key)
    if value is None:
        return default
    return value if type(value) is int and 0 <= value <= maximum else None


def _string(values: Mapping[str, Any], unknown: Any, key: str) -> str | None:
    value = None if block_attribute_unknown(unknown, key) else values.get(key)
    return value if isinstance(value, str) and value.strip() else None


def normalize_forwarding_actions(resource: TerraformResource, field: str) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    for i, (values, unknown) in enumerate(_blocks(resource.values.get(field), resource.unknown_values.get(field))):
        uncertainties: list[str] = []
        path = f"{field}[{i}]"
        action_type = _string(values, unknown, "type")
        order = _integer(values, unknown, "order", None, 50000)
        if block_attribute_unknown(unknown, "order") or (
            values.get("order") is not None and (order is None or order < 1)
        ):
            uncertainties.append(f"{path}.order is unknown or invalid")
        targets: list[dict[str, Any]] = []
        if unknown is True:
            uncertainties.append(f"{path} is unknown or malformed")
        elif action_type == "forward":
            forward = values.get("forward")
            forward_unknown = cast(Mapping[str, Any], unknown).get("forward") if isinstance(unknown, Mapping) else None
            if forward_unknown is True or (forward in (None, []) and value_is_unknown(forward_unknown)):
                uncertainties.append(f"{path}.forward is unknown")
            elif forward not in (None, []):
                blocks = _blocks(forward, forward_unknown)
                if len(blocks) != 1 or blocks[0][1] is True:
                    uncertainties.append(f"{path}.forward is not one known block")
                else:
                    block, block_unknown = blocks[0]
                    target_unknown = (
                        cast(Mapping[str, Any], block_unknown).get("target_group")
                        if isinstance(block_unknown, Mapping)
                        else None
                    )
                    if target_unknown is True:
                        uncertainties.append(f"{path}.forward.target_group is unknown")
                    else:
                        for j, (target, target_unknown_item) in enumerate(
                            _blocks(block.get("target_group"), target_unknown)
                        ):
                            targets.append(
                                _target(
                                    target,
                                    target_unknown_item,
                                    "arn",
                                    [field, i, "forward", 0, "target_group", j, "arn"],
                                )
                            )
                    # Both AWS representations may be populated only for the same single target.
                    direct = values.get("target_group_arn")
                    if block_attribute_unknown(unknown, "target_group_arn") or (
                        direct and (len(targets) != 1 or targets[0]["reference"] != direct)
                    ):
                        uncertainties.append(f"{path} has unresolved or conflicting forwarding representations")
            else:
                targets.append(_target(values, unknown, "target_group_arn", [field, i, "target_group_arn"]))
        actions.append({"type": action_type, "order": order, "targets": targets, "uncertainties": uncertainties})
    return actions


def _target(values: Mapping[str, Any], unknown: Any, key: str, path: list[str | int]) -> dict[str, Any]:
    reference = None if block_attribute_unknown(unknown, key) else values.get(key)
    return {
        "reference": reference if isinstance(reference, str) and reference.strip() else None,
        "weight": _integer(values, unknown, "weight", 1, 999),
        "configuration_path": path,
    }


def forwarding_targets(actions: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    """Return positive-weight targets only from an established terminal forward action."""
    uncertainties = [reason for action in actions for reason in action["uncertainties"]]
    if not actions:
        return [], ["listener actions are not established"]
    ordered = actions
    if len(actions) > 1:
        orders = [action["order"] for action in actions]
        if any(order is None or order < 1 for order in orders) or len(set(orders)) != len(orders):
            return [], [*uncertainties, "listener action order is unknown or conflicting"]
        ordered = sorted(actions, key=lambda action: action["order"])
    if any(action["type"] not in {"authenticate-cognito", "authenticate-oidc"} for action in ordered[:-1]):
        uncertainties.append("listener action sequence has an unsupported or nonterminal action")
    terminal = ordered[-1]
    if terminal["type"] not in {"forward", "redirect", "fixed-response"}:
        uncertainties.append("terminal listener action is unknown or unsupported")
    if uncertainties or terminal["type"] != "forward":
        return [], sorted(set(uncertainties))
    targets = terminal["targets"]
    if not targets:
        uncertainties.append("forward action has no established targets")
    if any(target["weight"] is None for target in targets):
        uncertainties.append("forward target weight is unknown or invalid")
    return [target for target in targets if target["weight"] is not None and target["weight"] > 0], uncertainties


def action_target_references(actions: list[dict[str, Any]]) -> list[str]:
    targets, _ = forwarding_targets(actions)
    return sorted({target["reference"] for target in targets if target["reference"]})


def normalize_ecs_bindings(resource: TerraformResource) -> list[dict[str, Any]]:
    bindings: list[dict[str, Any]] = []
    for values, unknown in _blocks(resource.values.get("load_balancer"), resource.unknown_values.get("load_balancer")):
        binding = {key: _string(values, unknown, key) for key in ("target_group_arn", "elb_name", "container_name")}
        # A symbolic target can fill this field later without proving the other binding fields.
        bindings.append(
            {
                **{key: value for key, value in binding.items() if value is not None},
                "container_port": _integer(values, unknown, "container_port", None, 65535),
            }
        )
    return bindings


def normalize_listener_conditions(resource: TerraformResource) -> tuple[list[dict[str, Any]], list[str]]:
    """Known host/path/method conditions; other selectors remain explicit uncertainty."""
    conditions: list[dict[str, Any]] = []
    uncertainties: list[str] = []
    if value_is_unknown(resource.unknown_values.get("condition")):
        return [], ["listener rule conditions are unknown"]
    for values, unknown in _blocks(resource.values.get("condition"), None):
        configured = [key for key, value in values.items() if value not in (None, [])]
        if (
            unknown is True
            or len(configured) != 1
            or configured[0] not in {"host_header", "path_pattern", "http_request_method"}
        ):
            uncertainties.append("listener rule condition is malformed or uses an unsupported selector")
            continue
        field = configured[0]
        blocks = _blocks(values[field], None)
        if len(blocks) != 1 or blocks[0][1] is True:
            uncertainties.append(f"{field} condition is malformed")
            continue
        block = blocks[0][0]
        patterns = block.get("values")
        if (
            block.get("regex_values")
            or not isinstance(patterns, list)
            or not patterns
            or any(not isinstance(pattern, str) or not pattern for pattern in patterns)
        ):
            uncertainties.append(f"{field} condition values are unsupported or incomplete")
            continue
        conditions.append({"field": field, "values": sorted(set(patterns))})
    if not conditions and not uncertainties:
        uncertainties.append("listener rule conditions are absent")
    if len({condition["field"] for condition in conditions}) != len(conditions):
        uncertainties.append("listener rule repeats a condition selector")
    return conditions, sorted(set(uncertainties))
