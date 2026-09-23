from __future__ import annotations

from collections.abc import Callable

from tfstride.analysis.boundaries.types import BoundaryContributionContext
from tfstride.analysis.resource_concepts import is_public_edge_resource, is_subnet_resource
from tfstride.models import BoundaryType, NormalizedResource
from tfstride.providers.network_scope import NetworkScopeKey, NetworkScopeResolution


class InternetToServiceBoundaryContributor:
    def contribute(self, context: BoundaryContributionContext) -> None:
        for resource in context.inventory.resources:
            if resource.direct_internet_reachable and is_public_edge_resource(resource):
                context.add_boundary(
                    BoundaryType.INTERNET_TO_SERVICE,
                    "internet",
                    resource.address,
                    f"Traffic can cross from the public internet to {resource.display_name}.",
                    "The resource is directly reachable or intentionally exposed to unauthenticated network clients.",
                )


class PublicPrivateSubnetBoundaryContributor:
    def __init__(self, resolve_network: Callable[[NormalizedResource], NetworkScopeResolution]) -> None:
        self._resolve_network = resolve_network

    def contribute(self, context: BoundaryContributionContext) -> None:
        public_subnets: list[tuple[NormalizedResource, NetworkScopeKey, str]] = []
        private_subnets_by_network: dict[NetworkScopeKey, list[NormalizedResource]] = {}
        subnets = (resource for resource in context.inventory.resources if is_subnet_resource(resource))
        for subnet in sorted(subnets, key=lambda resource: resource.address):
            network = self._resolve_network(subnet)
            if network.key is None:
                continue
            if subnet.is_public_subnet:
                public_subnets.append((subnet, network.key, network.reason))
            else:
                private_subnets_by_network.setdefault(network.key, []).append(subnet)
        for public_subnet, network_key, network_reason in public_subnets:
            for private_subnet in private_subnets_by_network.get(network_key, ()):
                context.add_boundary(
                    BoundaryType.PUBLIC_TO_PRIVATE,
                    public_subnet.address,
                    private_subnet.address,
                    f"{public_subnet.display_name} and {private_subnet.display_name} occupy separate trust zones in the same network.",
                    f"{network_reason} The network contains a publicly routable segment and a private trust zone. "
                    "Common network membership does not establish packet reachability; routes and traffic controls require separate evaluation.",
                )


def contribute_control_to_workload_boundary(
    context: BoundaryContributionContext,
    workload: NormalizedResource,
    attached_role: NormalizedResource | None,
) -> None:
    if attached_role is None:
        return
    context.add_boundary(
        BoundaryType.CONTROL_TO_WORKLOAD,
        attached_role.address,
        workload.address,
        f"{attached_role.display_name} governs actions performed by {workload.display_name}.",
        "IAM configuration acts as a control-plane boundary because the workload inherits whatever privileges the role carries.",
    )
