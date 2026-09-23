from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from tfstride.models import NormalizedResource, TerraformReferenceProvenance, TerraformReferenceResolutionState
from tfstride.providers.resource_reference_index import ResourceReferenceResolution, ResourceReferenceResolutionState

NetworkScopeKey = tuple[str | None, ...]


@dataclass(frozen=True, slots=True)
class NetworkScopeResolution:
    """Provider-established network membership, not a packet-reachability decision.

    Unresolved scope and colliding candidates have no grouping key. Keep the
    reference result so consumers cannot turn ambiguous aliases into raw keys.
    A scoped, unmodeled network may have a key without a modeled candidate.
    """

    key: NetworkScopeKey | None
    reference_resolution: ResourceReferenceResolution
    reason: str

    @property
    def state(self) -> ResourceReferenceResolutionState:
        if self.key is not None:
            return "resolved"
        if self.reference_resolution.state == "ambiguous":
            return "ambiguous"
        return "unresolved"


def resolve_subnet_network_scope(
    subnet: NormalizedResource,
    *,
    attribute: str,
    reference_suffixes: tuple[str, ...],
    resolve: Callable[[str | None], NetworkScopeResolution],
) -> NetworkScopeResolution:
    """Use exact first-apply relationships without guessing from dependencies.

    The ingestion layer owns expression resolution. A concrete planned value
    remains authoritative; configuration evidence can replace an unknown value
    only when it establishes one symbolic target and an identity attribute.
    """
    symbolic = [
        item
        for item in subnet.reference_resolutions
        if item.path == (attribute,) and item.provenance == TerraformReferenceProvenance.CONFIGURATION_REFERENCE
    ]
    if not symbolic:
        return resolve(subnet.vpc_id)
    targets = {target for item in symbolic for target in item.targets}
    if len(symbolic) == 1 and symbolic[0].state == TerraformReferenceResolutionState.SYMBOLIC and len(targets) == 1:
        target = next(iter(targets))
        if target.reference.endswith(reference_suffixes):
            resolved = resolve(target.address)
            if resolved.reference_resolution.selected_candidate is not None:
                return resolved
    candidates = {
        candidate.address: candidate
        for target in targets
        for candidate in resolve(target.address).reference_resolution.candidates
    }
    return NetworkScopeResolution(
        None,
        ResourceReferenceResolution(tuple(candidates[address] for address in sorted(candidates))),
        "The Terraform network relationship is not an exact symbolic identity reference: "
        + ", ".join(sorted({item.state.value for item in symbolic})),
    )
