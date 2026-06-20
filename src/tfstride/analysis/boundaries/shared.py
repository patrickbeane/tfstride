from __future__ import annotations

from collections.abc import Sequence

from tfstride.analysis.boundaries.types import BoundaryContributionContext
from tfstride.analysis.resource_concepts import is_public_edge_resource, is_subnet_resource
from tfstride.models import BoundaryType, NormalizedResource


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
    def contribute(self, context: BoundaryContributionContext) -> None:
        resources = context.inventory.resources
        public_subnets = [
            resource for resource in resources if is_subnet_resource(resource) and resource.is_public_subnet
        ]
        private_subnets_by_vpc = _private_subnets_by_vpc(resources)
        for public_subnet in public_subnets:
            if not public_subnet.vpc_id:
                continue
            for private_subnet in private_subnets_by_vpc.get(public_subnet.vpc_id, ()):
                # Model segmentation at the trust-zone level rather than every possible route;
                # for review purposes, "public subnet can reach private subnet" is the key edge.
                context.add_boundary(
                    BoundaryType.PUBLIC_TO_PRIVATE,
                    public_subnet.address,
                    private_subnet.address,
                    f"Traffic can move from {public_subnet.display_name} toward {private_subnet.display_name}.",
                    "The VPC contains both publicly routable and private network segments that should be treated as separate trust zones.",
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


def _private_subnets_by_vpc(resources: Sequence[NormalizedResource]) -> dict[str, tuple[NormalizedResource, ...]]:
    grouped: dict[str, list[NormalizedResource]] = {}
    for resource in resources:
        if not is_subnet_resource(resource) or resource.is_public_subnet or not resource.vpc_id:
            continue
        grouped.setdefault(resource.vpc_id, []).append(resource)
    return {vpc_id: tuple(subnets) for vpc_id, subnets in grouped.items()}
