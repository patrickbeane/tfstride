from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.aws.resource_mutations import aws_mutations
from tfstride.resource_helpers import describe_security_group_rule


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
                    
                        any(
                            subnet_id in context.public_subnet_ids
                            for subnet_id in resource.subnet_ids
                        )
                        if resource.subnet_ids
                        else resource.in_public_subnet
                    
                )
            mutations.set_nat_gateway_egress(
                
                    any(
                        context.index.subnets[subnet_id].has_nat_gateway_egress
                        for subnet_id in resource.subnet_ids
                        if subnet_id in context.index.subnets
                    )
                    if resource.subnet_ids
                    else resource.has_nat_gateway_egress
                
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
                    bool(
                        resource.public_access_configured
                        and (internet_ingress or not attached_security_groups)
                    )
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
                    bool(
                        resource.public_access_configured
                        and (internet_ingress or not attached_security_groups)
                    )
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


def _internet_ingress_reasons(attached_security_groups: list[NormalizedResource]) -> list[str]:
    reasons: list[str] = []
    for security_group in attached_security_groups:
        for rule in security_group.network_rules:
            if rule.direction != "ingress" or not rule.allows_internet():
                continue
            reasons.append(describe_security_group_rule(security_group, rule))
    return reasons