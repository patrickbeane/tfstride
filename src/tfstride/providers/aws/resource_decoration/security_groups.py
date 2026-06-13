from __future__ import annotations

from tfstride.models import NormalizedResource, SecurityGroupRule
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.aws.resource_mutations import aws_mutations


class MergeStandaloneSecurityGroupRulesStage:
    name = "merge_standalone_security_group_rules"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        # Standalone SG rule resources carry the same security meaning as inline rules, so fold
        # them into the parent security group before any exposure analysis runs.
        for rule_resource in resources:
            if rule_resource.resource_type != "aws_security_group_rule":
                continue
            security_group_id = aws_facts(rule_resource).security_group_id
            target_group = context.index.security_groups.get(security_group_id)
            if target_group is None:
                continue
            aws_mutations(target_group).merge_security_group_rules(
                _clone_security_group_rules(rule_resource.network_rules)
            )
            aws_facts(target_group).add_standalone_rule_address(rule_resource.address)


def _clone_security_group_rules(rules: list[SecurityGroupRule]) -> list[SecurityGroupRule]:
    return [
        SecurityGroupRule(
            direction=rule.direction,
            protocol=rule.protocol,
            from_port=rule.from_port,
            to_port=rule.to_port,
            cidr_blocks=list(rule.cidr_blocks),
            ipv6_cidr_blocks=list(rule.ipv6_cidr_blocks),
            referenced_security_group_ids=list(rule.referenced_security_group_ids),
            description=rule.description,
        )
        for rule in rules
    ]