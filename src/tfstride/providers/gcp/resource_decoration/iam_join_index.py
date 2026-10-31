"""Per-target index of IAM resources for joining grants to workload identities.

Pub/Sub path stages join every Cloud Run workload to every target through the
IAM resources that could grant it authority. Which IAM resources matter for a
given workload identity is decided by facts that do not depend on the workload:
each IAM resource's scope for the target, its policy state, and the members of
each binding. `build_target_iam_join_index` resolves those facts once per target
so a workload only visits the IAM resources that can affect its member: those
whose bindings list the member, plus those that report an uncertainty for every
workload (unresolved policy data, or a binding with an unresolved role or
members). Candidates are returned in the original IAM resource order so stages
emit paths and uncertainties in exactly the order a full scan would.
"""

from __future__ import annotations

from bisect import insort
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.resource_decoration.iam import iam_bindings
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_utils import binding_members

_UNUSABLE_POLICY_STATES = frozenset({"unknown", "invalid", "not_configured"})


@dataclass(frozen=True, slots=True)
class IamBindingStep:
    """One binding of one IAM resource, with the facts a workload join needs."""

    binding: Mapping[str, Any]
    source: str
    unresolved: bool
    members: frozenset[str]


@dataclass(frozen=True, slots=True)
class IamJoinItem:
    """One IAM resource evaluated against one target."""

    iam_resource: NormalizedResource
    scope_type: Any
    scope: str | None
    scope_uncertainty: str | None
    unusable_policy_state: str | None
    steps: tuple[IamBindingStep, ...]


@dataclass(frozen=True, slots=True)
class TargetIamJoinIndex:
    items: tuple[IamJoinItem, ...] = ()
    always_positions: tuple[int, ...] = ()
    positions_by_member: Mapping[str, tuple[int, ...]] = field(default_factory=dict)

    def candidates(self, member: str) -> Iterator[IamJoinItem]:
        """Yield the IAM resources that can affect `member`, in original order."""

        member_positions = self.positions_by_member.get(member, ())
        if not self.always_positions:
            positions: Sequence[int] = member_positions
        elif not member_positions:
            positions = self.always_positions
        else:
            positions = sorted({*self.always_positions, *member_positions})
        for position in positions:
            yield self.items[position]


def build_binding_steps(
    iam_resources: Sequence[NormalizedResource],
    known_string: Callable[[object], str | None],
) -> dict[str, tuple[IamBindingStep, ...]]:
    """Resolve each IAM resource's bindings once, independent of any target."""

    return {
        resource.address: tuple(
            IamBindingStep(
                binding=binding,
                source=known_string(binding.get("source")) or resource.address,
                unresolved=binding.get("role_state") == "unknown" or binding.get("members_state") == "unknown",
                members=frozenset(binding_members(binding)),
            )
            for binding in iam_bindings(resource)
        )
        for resource in iam_resources
    }


def build_target_iam_join_index(
    iam_resources: Sequence[NormalizedResource],
    steps_by_resource: Mapping[str, tuple[IamBindingStep, ...]],
    scope_of: Callable[[NormalizedResource], tuple[Any, str | None, str | None]],
) -> TargetIamJoinIndex:
    items: list[IamJoinItem] = []
    always_positions: list[int] = []
    member_positions: dict[str, list[int]] = {}
    for iam_resource in iam_resources:
        scope_type, scope, scope_uncertainty = scope_of(iam_resource)
        resolved = scope_type is not None and scope is not None
        if not resolved and scope_uncertainty is None:
            continue
        steps = steps_by_resource[iam_resource.address]
        unusable_policy_state: str | None = None
        always = False
        if resolved:
            policy_state = gcp_facts(iam_resource).iam_policy_data_state
            if policy_state in _UNUSABLE_POLICY_STATES:
                unusable_policy_state = policy_state
            always = unusable_policy_state is not None or any(step.unresolved for step in steps)
        position = len(items)
        items.append(
            IamJoinItem(
                iam_resource=iam_resource,
                scope_type=scope_type,
                scope=scope,
                scope_uncertainty=scope_uncertainty,
                unusable_policy_state=unusable_policy_state,
                steps=steps,
            )
        )
        if always:
            always_positions.append(position)
        for member in {member for step in steps for member in step.members}:
            insort(member_positions.setdefault(member, []), position)
    return TargetIamJoinIndex(
        items=tuple(items),
        always_positions=tuple(always_positions),
        positions_by_member={member: tuple(positions) for member, positions in member_positions.items()},
    )
