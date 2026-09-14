from __future__ import annotations

import re
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from tfstride.models import NormalizedResource
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.resource_utils import azure_reference_key, azure_resource_references
from tfstride.providers.resource_reference_index import (
    ResourceReferenceIndex,
    ResourceReferenceResolution,
    build_resource_reference_index,
)

_ARM_SCOPE_PATTERN = re.compile(
    r"^/subscriptions/(?P<subscription>[^/]+)"
    r"(?:/resourcegroups/(?P<resource_group>[^/]+))?(?:/|$)",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class AzureResourceReferenceView:
    """Resolve Azure references without discarding colliding native aliases."""

    _index: ResourceReferenceIndex
    _resource_types: frozenset[str] | None = None

    def resolve(
        self,
        reference: str | None,
        *,
        source: NormalizedResource | None = None,
        resource_types: Collection[str] | None = None,
    ) -> ResourceReferenceResolution:
        """Apply type and ARM-scope filtering before classifying candidates."""

        expected_types = self._expected_resource_types(resource_types)
        if expected_types == frozenset():
            return ResourceReferenceResolution(candidates=())

        resolution = self._index.resolve(
            reference,
            candidate_filter=(
                None if expected_types is None else lambda candidate: candidate.resource_type in expected_types
            ),
        )
        if not reference:
            return resolution

        reference_key = self._index.reference_key(reference)
        exact_candidates = tuple(
            candidate for candidate in resolution.candidates if azure_reference_key(candidate.address) == reference_key
        )
        if exact_candidates:
            return ResourceReferenceResolution(candidates=exact_candidates)

        strong_candidates = tuple(
            candidate
            for candidate in resolution.candidates
            if _azure_reference_is_strong_for_candidate(reference, candidate)
        )
        if strong_candidates:
            return ResourceReferenceResolution(candidates=strong_candidates)

        return ResourceReferenceResolution(
            candidates=_scope_candidates(resolution.candidates, source),
        )

    def get(
        self,
        reference: str | None,
        default: NormalizedResource | None = None,
        *,
        source: NormalizedResource | None = None,
        resource_types: Collection[str] | None = None,
    ) -> NormalizedResource | None:
        selected = self.resolve(
            reference,
            source=source,
            resource_types=resource_types,
        ).selected_candidate
        return selected if selected is not None else default

    def _expected_resource_types(
        self,
        resource_types: Collection[str] | None,
    ) -> frozenset[str] | None:
        requested = frozenset(resource_types) if resource_types is not None else None
        if self._resource_types is None:
            return requested
        if requested is None:
            return self._resource_types
        return self._resource_types.intersection(requested)


@dataclass(frozen=True, slots=True)
class AzureResourceIndex:
    resources_by_address: Mapping[str, NormalizedResource]
    resources_by_reference: AzureResourceReferenceView
    network_security_rules: tuple[NormalizedResource, ...]
    subnet_nsg_associations: tuple[NormalizedResource, ...]
    nic_nsg_associations: tuple[NormalizedResource, ...]

    def resolve(
        self,
        reference: str | None,
        *,
        source: NormalizedResource | None = None,
        resource_types: Collection[str] | None = None,
    ) -> NormalizedResource | None:
        return self.resources_by_reference.get(
            reference,
            source=source,
            resource_types=resource_types,
        )


@dataclass(slots=True)
class AzureDecorationContext:
    index: AzureResourceIndex


class AzureResourceIndexBuilder:
    def build(self, resources: list[NormalizedResource]) -> AzureResourceIndex:
        resource_tuple = tuple(resources)
        resources_by_address: dict[str, NormalizedResource] = {}
        network_security_rules: list[NormalizedResource] = []
        subnet_nsg_associations: list[NormalizedResource] = []
        nic_nsg_associations: list[NormalizedResource] = []

        for resource in resource_tuple:
            resources_by_address.setdefault(resource.address, resource)
            if resource.resource_type == AzureResourceType.NETWORK_SECURITY_RULE:
                network_security_rules.append(resource)
            elif resource.resource_type == AzureResourceType.SUBNET_NETWORK_SECURITY_GROUP_ASSOCIATION:
                subnet_nsg_associations.append(resource)
            elif resource.resource_type == AzureResourceType.NETWORK_INTERFACE_SECURITY_GROUP_ASSOCIATION:
                nic_nsg_associations.append(resource)

        reference_index = build_resource_reference_index(
            resource_tuple,
            references_for_resource=azure_resource_references,
            reference_key=azure_reference_key,
        )

        return AzureResourceIndex(
            resources_by_address=MappingProxyType(resources_by_address),
            resources_by_reference=AzureResourceReferenceView(
                _index=reference_index,
            ),
            network_security_rules=tuple(network_security_rules),
            subnet_nsg_associations=tuple(subnet_nsg_associations),
            nic_nsg_associations=tuple(nic_nsg_associations),
        )


def _azure_reference_is_strong_for_candidate(
    reference: str,
    candidate: NormalizedResource,
) -> bool:
    """Return whether an Azure reference identifies a resource across ARM scopes."""

    key = azure_reference_key(reference)
    if key == azure_reference_key(candidate.address):
        return True
    is_arm_id = _arm_scope_from_reference(key)[0] is not None
    is_absolute_uri = key.startswith(("https://", "http://"))
    if not is_arm_id and not is_absolute_uri:
        return False
    return key in azure_resource_references(candidate)


def _scope_candidates(
    candidates: tuple[NormalizedResource, ...],
    source: NormalizedResource | None,
) -> tuple[NormalizedResource, ...]:
    if source is None:
        return candidates
    subscription, resource_group = _resource_arm_scope(source)
    scoped = _candidates_in_scope(
        candidates,
        expected_scope=subscription,
        scope_for_resource=lambda resource: _resource_arm_scope(resource)[0],
    )
    if not scoped:
        return ()
    return _candidates_in_scope(
        scoped,
        expected_scope=resource_group,
        scope_for_resource=lambda resource: _resource_arm_scope(resource)[1],
    )


def _candidates_in_scope(
    candidates: tuple[NormalizedResource, ...],
    *,
    expected_scope: str | None,
    scope_for_resource: Callable[[NormalizedResource], str | None],
) -> tuple[NormalizedResource, ...]:
    if expected_scope is None:
        return candidates
    candidates_with_scope = tuple((candidate, scope_for_resource(candidate)) for candidate in candidates)
    if not any(scope == expected_scope for _candidate, scope in candidates_with_scope):
        return ()
    return tuple(candidate for candidate, scope in candidates_with_scope if scope is None or scope == expected_scope)


def _resource_arm_scope(
    resource: NormalizedResource,
) -> tuple[str | None, str | None]:
    scopes = {
        scope
        for reference in azure_resource_references(resource)
        if (scope := _arm_scope_from_reference(reference))[0] is not None
    }
    subscriptions = {subscription for subscription, _resource_group in scopes if subscription}
    if len(subscriptions) != 1:
        return None, None
    subscription = next(iter(subscriptions))
    resource_groups = {
        resource_group
        for candidate_subscription, resource_group in scopes
        if candidate_subscription == subscription and resource_group
    }
    return (
        subscription,
        next(iter(resource_groups)) if len(resource_groups) == 1 else None,
    )


def _arm_scope_from_reference(
    reference: str,
) -> tuple[str | None, str | None]:
    match = _ARM_SCOPE_PATTERN.match(azure_reference_key(reference))
    if match is None:
        return None, None
    subscription = match.group("subscription")
    resource_group = match.group("resource_group")
    return (
        subscription.casefold(),
        resource_group.casefold() if resource_group is not None else None,
    )
