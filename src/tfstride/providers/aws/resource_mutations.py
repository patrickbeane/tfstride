from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from tfstride.models import IAMPolicyStatement, NormalizedResource, SecurityGroupRule
from tfstride.providers.aws.resource_facts import aws_facts


@dataclass(frozen=True, slots=True)
class AwsResourceMutations:
    """AWS-owned write facade for normalized resource decoration."""

    resource: NormalizedResource

    def merge_security_group_rules(self, rules: Sequence[SecurityGroupRule]) -> None:
        self.resource.extend_network_rules(rules)

    def merge_policy_statements(self, statements: Sequence[IAMPolicyStatement]) -> None:
        self.resource.extend_policy_statements(statements)

    def attach_role_arn(self, role_arn: str | None) -> None:
        self.resource.add_attached_role_arn(role_arn)

    def infer_vpc_id(self, vpc_id: str | None) -> bool:
        if not vpc_id or self.resource.vpc_id:
            return False
        self.resource.vpc_id = vpc_id
        return True

    def set_subnet_posture(
        self,
        *,
        is_public: bool,
        route_table_ids: Sequence[str],
        has_public_route: bool,
        has_nat_gateway_egress: bool,
    ) -> None:
        self.resource.is_public_subnet = is_public
        aws_facts(self.resource).set_route_table_ids(list(route_table_ids))
        self.resource.has_public_route = has_public_route
        self.resource.has_nat_gateway_egress = has_nat_gateway_egress

    def ensure_public_reason_lists(self) -> None:
        facts = aws_facts(self.resource)
        if not facts.has_public_access_reasons():
            self.resource.public_access_reasons = []
        if not facts.has_public_exposure_reasons():
            self.resource.public_exposure_reasons = []

    def set_public_access_reasons(self, values: Sequence[str]) -> None:
        self.resource.public_access_reasons = list(values)

    def set_public_exposure_reasons(self, values: Sequence[str]) -> None:
        self.resource.public_exposure_reasons = list(values)

    def sync_public_access_configured(self) -> None:
        aws_facts(self.resource).set_public_access_configured(self.resource.public_access_configured)

    def set_internet_ingress(self, value: bool, reasons: Sequence[str]) -> None:
        aws_facts(self.resource).set_internet_ingress(value)
        self.resource.internet_ingress_capable = value
        self.resource.internet_ingress_reasons = list(reasons)

    def set_in_public_subnet(self, value: bool) -> None:
        self.resource.in_public_subnet = value

    def set_nat_gateway_egress(self, value: bool) -> None:
        self.resource.has_nat_gateway_egress = value

    def set_public_exposure(self, value: bool) -> None:
        self.resource.public_exposure = value

    def sync_direct_internet_reachable(self) -> None:
        self.resource.direct_internet_reachable = self.resource.public_exposure


def aws_mutations(resource: NormalizedResource) -> AwsResourceMutations:
    return AwsResourceMutations(resource)