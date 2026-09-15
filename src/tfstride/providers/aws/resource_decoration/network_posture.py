from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.aws.resource_mutations import aws_mutations
from tfstride.providers.aws.resource_utils import (
    AwsScopedReferenceKey,
    aws_scoped_reference_key,
    route_table_has_internet_route,
    route_table_has_nat_gateway_route,
)


class DeriveSubnetPostureStage:
    name = "derive_subnet_posture"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        subnet_route_table_references: dict[
            str,
            list[tuple[str, NormalizedResource]],
        ] = {}
        for association_resource in resources:
            if association_resource.resource_type != "aws_route_table_association":
                continue
            subnet_id = aws_facts(association_resource).subnet_id
            route_table_id = aws_facts(association_resource).route_table_id
            if not subnet_id or not route_table_id:
                continue
            subnet = context.index.subnets.get(str(subnet_id), source=association_resource)
            if subnet is None:
                continue
            subnet_route_table_references.setdefault(subnet.address, []).append(
                (str(route_table_id), association_resource)
            )

        public_subnet_ids: set[AwsScopedReferenceKey] = set()
        for subnet in context.index.subnets.resources:
            route_table_references = subnet_route_table_references.get(subnet.address, [])
            associated_route_table_ids = [route_table_id for route_table_id, _association in route_table_references]
            associated_route_tables = tuple(
                route_table
                for route_table_id, association in route_table_references
                if (
                    route_table := context.index.route_tables.get(
                        route_table_id,
                        source=association,
                    )
                )
                is not None
            )
            has_public_route = any(
                route_table_has_internet_route(aws_facts(route_table).routes) for route_table in associated_route_tables
            )
            has_nat_route = any(
                route_table_has_nat_gateway_route(
                    aws_facts(route_table).routes,
                    context.index.nat_gateway_ids,
                    provider_config_key=route_table.provider_config_key,
                )
                for route_table in associated_route_tables
            )
            if associated_route_table_ids:
                # Prefer explicit associations when Terraform provides them because they are
                # more precise than inferring subnet posture from VPC-wide route presence.
                is_public = has_public_route
            else:
                # Fall back to the original heuristic when route table associations are absent.
                scoped_vpc_key = aws_scoped_reference_key(
                    subnet.provider_config_key,
                    subnet.vpc_id,
                )
                is_public = aws_facts(subnet).map_public_ip_on_launch and scoped_vpc_key in (
                    context.index.vpcs_with_igw.intersection(context.index.vpcs_with_public_routes)
                )
                has_nat_route = False
            aws_mutations(subnet).set_subnet_posture(
                is_public=is_public,
                route_table_ids=associated_route_table_ids,
                has_public_route=has_public_route,
                has_nat_gateway_egress=has_nat_route,
            )
            scoped_subnet_key = aws_scoped_reference_key(
                subnet.provider_config_key,
                subnet.identifier,
            )
            if is_public and scoped_subnet_key is not None:
                public_subnet_ids.add(scoped_subnet_key)
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
                subnet = context.index.subnets.get(subnet_id, source=resource)
                if subnet and subnet.vpc_id:
                    aws_mutations(resource).infer_vpc_id(subnet.vpc_id)
                    break
            if resource.vpc_id:
                continue
            for security_group_id in resource.security_group_ids:
                security_group = context.index.security_groups.get(security_group_id, source=resource)
                if security_group and security_group.vpc_id:
                    aws_mutations(resource).infer_vpc_id(security_group.vpc_id)
                    break
