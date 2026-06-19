from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.aws.resource_mutations import aws_mutations
from tfstride.providers.aws.resource_utils import (
    route_table_has_internet_route,
    route_table_has_nat_gateway_route,
)


class DeriveSubnetPostureStage:
    name = "derive_subnet_posture"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        subnet_route_table_ids: dict[str, list[str]] = {}
        for association_resource in resources:
            if association_resource.resource_type != "aws_route_table_association":
                continue
            subnet_id = aws_facts(association_resource).subnet_id
            route_table_id = aws_facts(association_resource).route_table_id
            if not subnet_id or not route_table_id:
                continue
            subnet_route_table_ids.setdefault(str(subnet_id), []).append(str(route_table_id))

        public_subnet_ids: set[str] = set()
        for subnet in context.index.subnets.values():
            associated_route_table_ids = subnet_route_table_ids.get(
                subnet.identifier or "",
                [],
            )
            has_public_route = any(
                route_table_id in context.index.route_tables
                and route_table_has_internet_route(aws_facts(context.index.route_tables[route_table_id]).routes)
                for route_table_id in associated_route_table_ids
            )
            has_nat_route = any(
                route_table_id in context.index.route_tables
                and route_table_has_nat_gateway_route(
                    aws_facts(context.index.route_tables[route_table_id]).routes,
                    context.index.nat_gateway_ids,
                )
                for route_table_id in associated_route_table_ids
            )
            if associated_route_table_ids:
                # Prefer explicit associations when Terraform provides them because they are
                # more precise than inferring subnet posture from VPC-wide route presence.
                is_public = has_public_route
            else:
                # Fall back to the original heuristic when route table associations are absent.
                is_public = aws_facts(
                    subnet
                ).map_public_ip_on_launch and subnet.vpc_id in context.index.vpcs_with_igw.intersection(
                    context.index.vpcs_with_public_routes
                )
                has_nat_route = False
            aws_mutations(subnet).set_subnet_posture(
                is_public=is_public,
                route_table_ids=associated_route_table_ids,
                has_public_route=has_public_route,
                has_nat_gateway_egress=has_nat_route,
            )
            if is_public and subnet.identifier:
                public_subnet_ids.add(subnet.identifier)
        context.public_subnet_ids = public_subnet_ids


class InferVpcIdsStage:
    name = "infer_vpc_ids"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        for resource in resources:
            if resource.vpc_id:
                continue
            # Some Terraform resources omit a direct VPC reference, so infer it from the
            # attached subnet first and fall back to attached security groups.
            for subnet_id in resource.subnet_ids:
                subnet = context.index.subnets.get(subnet_id)
                if subnet and subnet.vpc_id:
                    aws_mutations(resource).infer_vpc_id(subnet.vpc_id)
                    break
            if resource.vpc_id:
                continue
            for security_group_id in resource.security_group_ids:
                security_group = context.index.security_groups.get(security_group_id)
                if security_group and security_group.vpc_id:
                    aws_mutations(resource).infer_vpc_id(security_group.vpc_id)
                    break
