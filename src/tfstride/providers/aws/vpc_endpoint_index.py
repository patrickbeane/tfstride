from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from tfstride.models import NormalizedResource, ResourceInventory
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.coercion import dedupe_strings

_S3 = "s3"
_SECRETS_MANAGER = "secretsmanager"
_KMS = "kms"
_INTERFACE = "interface"


@dataclass(frozen=True, slots=True)
class AwsVpcEndpointRecord:
    endpoint_address: str
    endpoint_id: str | None
    service_name: str | None
    service_family: str | None
    endpoint_type: str | None
    vpc_id: str | None
    route_table_ids: tuple[str, ...]
    subnet_ids: tuple[str, ...]
    security_group_ids: tuple[str, ...]
    private_dns_enabled: bool | None
    private_dns_enabled_state: str | None
    policy_document: Mapping[str, Any]
    dns_entries: tuple[Mapping[str, Any], ...]
    dns_names: tuple[str, ...]
    uncertainties: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AwsVpcEndpointCoverage:
    endpoints: tuple[AwsVpcEndpointRecord, ...]

    @property
    def has_endpoint(self) -> bool:
        return bool(self.endpoints)

    @property
    def endpoint_addresses(self) -> tuple[str, ...]:
        return tuple(dedupe_strings(endpoint.endpoint_address for endpoint in self.endpoints))

    @property
    def endpoint_ids(self) -> tuple[str, ...]:
        return tuple(dedupe_strings(endpoint.endpoint_id for endpoint in self.endpoints))

    @property
    def endpoint_types(self) -> tuple[str, ...]:
        return tuple(dedupe_strings(endpoint.endpoint_type for endpoint in self.endpoints))

    @property
    def route_table_ids(self) -> tuple[str, ...]:
        return tuple(
            dedupe_strings(route_table_id for endpoint in self.endpoints for route_table_id in endpoint.route_table_ids)
        )

    @property
    def subnet_ids(self) -> tuple[str, ...]:
        return tuple(dedupe_strings(subnet_id for endpoint in self.endpoints for subnet_id in endpoint.subnet_ids))

    @property
    def security_group_ids(self) -> tuple[str, ...]:
        return tuple(
            dedupe_strings(
                security_group_id for endpoint in self.endpoints for security_group_id in endpoint.security_group_ids
            )
        )

    @property
    def dns_names(self) -> tuple[str, ...]:
        return tuple(dedupe_strings(dns_name for endpoint in self.endpoints for dns_name in endpoint.dns_names))


@dataclass(frozen=True, slots=True)
class AwsVpcEndpointIndex:
    endpoints_by_vpc_and_service: Mapping[tuple[str, str], tuple[AwsVpcEndpointRecord, ...]]
    endpoints_by_vpc: Mapping[str, tuple[AwsVpcEndpointRecord, ...]]
    unresolved_service_name_endpoints: tuple[AwsVpcEndpointRecord, ...]
    unclassified_service_endpoints: tuple[AwsVpcEndpointRecord, ...]

    def coverage_for(
        self,
        vpc_id: str | None,
        service_family: str,
        *,
        endpoint_type: str | None = None,
    ) -> AwsVpcEndpointCoverage:
        if not vpc_id:
            return AwsVpcEndpointCoverage(())
        endpoints = self.endpoints_by_vpc_and_service.get((vpc_id, service_family), ())
        if endpoint_type:
            normalized_type = _normalized_endpoint_type(endpoint_type)
            endpoints = tuple(
                endpoint
                for endpoint in endpoints
                if _normalized_endpoint_type(endpoint.endpoint_type) == normalized_type
            )
        return AwsVpcEndpointCoverage(endpoints)

    def endpoints_for_vpc(self, vpc_id: str | None) -> tuple[AwsVpcEndpointRecord, ...]:
        if not vpc_id:
            return ()
        return self.endpoints_by_vpc.get(vpc_id, ())

    def has_s3_endpoint(self, vpc_id: str | None) -> bool:
        return self.coverage_for(vpc_id, _S3).has_endpoint

    def has_secrets_manager_interface_endpoint(self, vpc_id: str | None) -> bool:
        return self.coverage_for(vpc_id, _SECRETS_MANAGER, endpoint_type=_INTERFACE).has_endpoint

    def has_kms_endpoint(self, vpc_id: str | None) -> bool:
        return self.coverage_for(vpc_id, _KMS, endpoint_type=_INTERFACE).has_endpoint


def build_aws_vpc_endpoint_index(source: ResourceInventory | Iterable[NormalizedResource]) -> AwsVpcEndpointIndex:
    resources = tuple(source.resources if isinstance(source, ResourceInventory) else source)
    pending_by_vpc_and_service: dict[tuple[str, str], list[AwsVpcEndpointRecord]] = {}
    pending_by_vpc: dict[str, list[AwsVpcEndpointRecord]] = {}
    unresolved_service_name_endpoints: list[AwsVpcEndpointRecord] = []
    unclassified_service_endpoints: list[AwsVpcEndpointRecord] = []

    for resource in resources:
        if resource.resource_type != "aws_vpc_endpoint":
            continue
        record = _vpc_endpoint_record(resource)
        if record.vpc_id:
            pending_by_vpc.setdefault(record.vpc_id, []).append(record)
        if record.vpc_id and record.service_family:
            pending_by_vpc_and_service.setdefault((record.vpc_id, record.service_family), []).append(record)
        elif not record.service_name:
            unresolved_service_name_endpoints.append(record)
        else:
            unclassified_service_endpoints.append(record)

    return AwsVpcEndpointIndex(
        endpoints_by_vpc_and_service=MappingProxyType(
            {key: tuple(value) for key, value in sorted(pending_by_vpc_and_service.items())}
        ),
        endpoints_by_vpc=MappingProxyType({key: tuple(value) for key, value in sorted(pending_by_vpc.items())}),
        unresolved_service_name_endpoints=tuple(unresolved_service_name_endpoints),
        unclassified_service_endpoints=tuple(unclassified_service_endpoints),
    )


def _vpc_endpoint_record(resource: NormalizedResource) -> AwsVpcEndpointRecord:
    facts = aws_facts(resource)
    return AwsVpcEndpointRecord(
        endpoint_address=resource.address,
        endpoint_id=facts.vpc_endpoint_id,
        service_name=facts.vpc_endpoint_service_name,
        service_family=facts.vpc_endpoint_service_family,
        endpoint_type=facts.vpc_endpoint_type,
        vpc_id=facts.vpc_endpoint_vpc_id or resource.vpc_id,
        route_table_ids=tuple(facts.vpc_endpoint_route_table_ids),
        subnet_ids=tuple(facts.vpc_endpoint_subnet_ids),
        security_group_ids=tuple(facts.vpc_endpoint_security_group_ids),
        private_dns_enabled=facts.vpc_endpoint_private_dns_enabled,
        private_dns_enabled_state=facts.vpc_endpoint_private_dns_enabled_state,
        policy_document=MappingProxyType(dict(facts.vpc_endpoint_policy_document)),
        dns_entries=tuple(MappingProxyType(dict(entry)) for entry in facts.vpc_endpoint_dns_entries),
        dns_names=tuple(facts.vpc_endpoint_dns_names),
        uncertainties=tuple(facts.vpc_endpoint_posture_uncertainties),
    )


def _normalized_endpoint_type(endpoint_type: str | None) -> str | None:
    if endpoint_type is None:
        return None
    normalized = endpoint_type.strip().lower()
    return normalized or None
