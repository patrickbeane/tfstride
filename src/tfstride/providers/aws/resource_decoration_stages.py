from __future__ import annotations

from typing import Protocol

from tfstride.models import NormalizedResource
from tfstride.providers.aws.resource_decoration.iam import (
    MergeRolePolicyResourcesStage,
    ResolveInstanceProfileRolesStage,
)
from tfstride.providers.aws.resource_decoration.resource_policies import (
    ApplyS3PublicAccessBlocksStage,
    MergeResourcePolicyResourcesStage,
)
from tfstride.providers.aws.resource_decoration.security_groups import (
    MergeStandaloneSecurityGroupRulesStage,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.aws.resource_mutations import aws_mutations
from tfstride.providers.aws.resource_utils import (
    route_table_has_internet_route,
    route_table_has_nat_gateway_route,
)
from tfstride.resource_helpers import describe_security_group_rule


class AwsDecorationStage(Protocol):
    name: str

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        """Apply one ordered AWS resource decoration step."""
        ...


class ResolveEcsServiceRelationshipsStage:
    name = "resolve_ecs_service_relationships"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        for ecs_service_resource in resources:
            if ecs_service_resource.resource_type != "aws_ecs_service":
                continue
            cluster_ref = aws_facts(ecs_service_resource).cluster_reference
            if cluster_ref:
                cluster = context.index.ecs_clusters.get(cluster_ref)
                if cluster is None:
                    aws_facts(ecs_service_resource).add_unresolved_cluster_reference(str(cluster_ref))
                else:
                    aws_facts(ecs_service_resource).add_resolved_cluster_address(cluster.address)

            task_definition_ref = aws_facts(ecs_service_resource).task_definition_reference
            if not task_definition_ref:
                continue
            task_definition = context.index.ecs_task_definitions.get(task_definition_ref)
            if task_definition is None:
                aws_facts(ecs_service_resource).add_unresolved_task_definition_reference(str(task_definition_ref))
                continue
            aws_facts(ecs_service_resource).add_resolved_task_definition_address(task_definition.address)
            aws_facts(ecs_service_resource).set_network_mode(aws_facts(task_definition).network_mode)
            aws_facts(ecs_service_resource).set_requires_compatibilities(aws_facts(task_definition).requires_compatibilities)
            task_role_arn = aws_facts(task_definition).task_role_arn
            execution_role_arn = aws_facts(task_definition).execution_role_arn
            if task_role_arn:
                aws_facts(ecs_service_resource).set_task_role_arn(task_role_arn)
                aws_mutations(ecs_service_resource).attach_role_arn(task_role_arn)
                task_role = context.index.role_index.get(task_role_arn)
                if task_role is not None:
                    aws_facts(ecs_service_resource).add_resolved_task_role_address(task_role.address)
                else:
                    aws_facts(ecs_service_resource).add_unresolved_task_role_arn(str(task_role_arn))
            if execution_role_arn:
                aws_facts(ecs_service_resource).set_execution_role_arn(execution_role_arn)
                execution_role = context.index.role_index.get(execution_role_arn)
                if execution_role is not None:
                    aws_facts(ecs_service_resource).add_resolved_execution_role_address(execution_role.address)
                else:
                    aws_facts(ecs_service_resource).add_unresolved_execution_role_arn(str(execution_role_arn))


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
            associated_route_table_ids = subnet_route_table_ids.get(subnet.identifier or "", [])
            has_public_route = any(
                route_table_id in context.index.route_tables
                and route_table_has_internet_route(
                    aws_facts(context.index.route_tables[route_table_id]).routes
                )
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
                is_public = (
                    aws_facts(subnet).map_public_ip_on_launch
                    and subnet.vpc_id
                    in context.index.vpcs_with_igw.intersection(context.index.vpcs_with_public_routes)
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


class DerivePublicExposureStage:
    name = "derive_public_exposure"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        for resource in resources:
            attached_security_groups = [
                context.index.security_groups[sg_id]
                for sg_id in resource.security_group_ids
                if sg_id in context.index.security_groups
            ]
            internet_ingress = any(
                rule.direction == "ingress" and rule.allows_internet()
                for security_group in attached_security_groups
                for rule in security_group.network_rules
            )
            mutations = aws_mutations(resource)
            mutations.ensure_public_reason_lists()
            mutations.sync_public_access_configured()
            mutations.set_internet_ingress(
                internet_ingress,
                _internet_ingress_reasons(attached_security_groups),
            )
            if resource.resource_type != "aws_subnet":
                mutations.set_in_public_subnet(
                    (
                        any(subnet_id in context.public_subnet_ids for subnet_id in resource.subnet_ids)
                        if resource.subnet_ids
                        else resource.in_public_subnet
                    )
                )
            mutations.set_nat_gateway_egress(
                (
                    any(
                        context.index.subnets[subnet_id].has_nat_gateway_egress
                        for subnet_id in resource.subnet_ids
                        if subnet_id in context.index.subnets
                    )
                    if resource.subnet_ids
                    else resource.has_nat_gateway_egress
                )
            )
            # Public exposure is inferred conservatively from network placement and ingress
            # rules so later detectors can reason over a normalized signal instead of
            # provider-specific fields.
            if resource.resource_type == "aws_instance":
                mutations.set_public_exposure(
                    bool(
                        resource.public_access_configured
                        and resource.in_public_subnet
                        and internet_ingress
                    )
                )
                if resource.public_exposure:
                    aws_facts(resource).add_public_exposure_reason(
                        "instance has a public IP path and attached security groups allow internet ingress"
                    )
            elif resource.resource_type == "aws_ecs_service":
                mutations.set_public_exposure(
                    bool(
                        resource.public_access_configured
                        and resource.in_public_subnet
                        and internet_ingress
                    )
                )
                if resource.public_exposure:
                    aws_facts(resource).add_public_exposure_reason(
                        "ECS service assigns public IPs in a public subnet and attached "
                        "security groups allow internet ingress"
                    )
            elif resource.resource_type == "aws_db_instance":
                mutations.set_public_exposure(
                    bool(resource.public_access_configured and (internet_ingress or not attached_security_groups))
                )
                if resource.public_exposure and internet_ingress:
                    aws_facts(resource).add_public_exposure_reason(
                        "database is marked publicly_accessible and attached security groups allow internet ingress"
                    )
                elif resource.public_exposure and not attached_security_groups:
                    aws_facts(resource).add_public_exposure_reason(
                        "database is marked publicly_accessible and no attached security "
                        "groups provide ingress evidence"
                    )
            elif resource.resource_type == "aws_lb":
                mutations.set_public_exposure(
                    bool(resource.public_access_configured and (internet_ingress or not attached_security_groups))
                )
                if resource.public_exposure and internet_ingress:
                    aws_facts(resource).add_public_exposure_reason(
                        "load balancer is internet-facing and attached security groups allow internet ingress"
                    )
                elif resource.public_exposure:
                    aws_facts(resource).add_public_exposure_reason(
                        "load balancer is configured as internet-facing"
                    )
            mutations.sync_direct_internet_reachable()


class MarkEcsLoadBalancerExposureStage:
    name = "mark_ecs_services_fronted_by_internet_facing_load_balancers"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        internet_facing_load_balancers_by_security_group: dict[str, list[NormalizedResource]] = {}
        for resource in resources:
            if resource.resource_type != "aws_lb" or not resource.public_exposure:
                continue
            for security_group_id in resource.security_group_ids:
                internet_facing_load_balancers_by_security_group.setdefault(security_group_id, []).append(resource)

        for resource in resources:
            if resource.resource_type != "aws_ecs_service":
                continue
            fronting_load_balancers: list[str] = []
            seen_load_balancers: set[str] = set()
            attached_security_groups = [
                context.index.security_groups[sg_id]
                for sg_id in resource.security_group_ids
                if sg_id in context.index.security_groups
            ]
            for security_group in attached_security_groups:
                for rule in security_group.network_rules:
                    if rule.direction != "ingress":
                        continue
                    for security_group_id in rule.referenced_security_group_ids:
                        for load_balancer in internet_facing_load_balancers_by_security_group.get(
                            security_group_id,
                            [],
                        ):
                            if load_balancer.address in seen_load_balancers:
                                continue
                            seen_load_balancers.add(load_balancer.address)
                            fronting_load_balancers.append(load_balancer.address)
            aws_facts(resource).set_fronted_by_internet_facing_load_balancer(bool(fronting_load_balancers))
            if fronting_load_balancers:
                aws_facts(resource).set_internet_facing_load_balancer_addresses(fronting_load_balancers)


def default_aws_decoration_stages() -> tuple[AwsDecorationStage, ...]:
    return (
        MergeStandaloneSecurityGroupRulesStage(),
        MergeRolePolicyResourcesStage(),
        ResolveInstanceProfileRolesStage(),
        ResolveEcsServiceRelationshipsStage(),
        MergeResourcePolicyResourcesStage(),
        ApplyS3PublicAccessBlocksStage(),
        DeriveSubnetPostureStage(),
        InferVpcIdsStage(),
        DerivePublicExposureStage(),
        MarkEcsLoadBalancerExposureStage(),
    )


def _internet_ingress_reasons(attached_security_groups: list[NormalizedResource]) -> list[str]:
    reasons: list[str] = []
    for security_group in attached_security_groups:
        for rule in security_group.network_rules:
            if rule.direction != "ingress" or not rule.allows_internet():
                continue
            reasons.append(describe_security_group_rule(security_group, rule))
    return reasons