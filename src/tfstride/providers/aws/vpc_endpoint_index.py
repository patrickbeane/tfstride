from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from tfstride.models import NormalizedResource, ResourceInventory
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_utils import AwsScopedReferenceKey, aws_scoped_reference_key
from tfstride.providers.coercion import dedupe_strings

_S3 = "s3"
_SECRETS_MANAGER = "secretsmanager"
_KMS = "kms"
_INTERFACE = "interface"


@dataclass(frozen=True, slots=True)
class AwsVpcEndpointRecord:
    endpoint_address: str
    provider_config_key: str | None
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
    endpoints_by_vpc_and_service: Mapping[
        tuple[AwsScopedReferenceKey, str],
        tuple[AwsVpcEndpointRecord, ...],
    ]
    endpoints_by_vpc: Mapping[AwsScopedReferenceKey, tuple[AwsVpcEndpointRecord, ...]]
    unresolved_service_name_endpoints: tuple[AwsVpcEndpointRecord, ...]
    unclassified_service_endpoints: tuple[AwsVpcEndpointRecord, ...]

    def coverage_for(
        self,
        vpc_id: str | None,
        service_family: str,
        *,
        source: NormalizedResource | None = None,
        endpoint_type: str | None = None,
    ) -> AwsVpcEndpointCoverage:
        scoped_vpc_key = aws_scoped_reference_key(
            source.provider_config_key if source is not None else None,
            vpc_id,
        )
        if scoped_vpc_key is None:
            return AwsVpcEndpointCoverage(())
        endpoints = self.endpoints_by_vpc_and_service.get((scoped_vpc_key, service_family), ())
        return AwsVpcEndpointCoverage(_filter_endpoint_type(endpoints, endpoint_type))

    def endpoints_for_vpc(
        self,
        vpc_id: str | None,
        *,
        source: NormalizedResource | None = None,
    ) -> tuple[AwsVpcEndpointRecord, ...]:
        scoped_vpc_key = aws_scoped_reference_key(
            source.provider_config_key if source is not None else None,
            vpc_id,
        )
        if scoped_vpc_key is None:
            return ()
        return self.endpoints_by_vpc.get(scoped_vpc_key, ())

    def has_uncertain_coverage(
        self,
        vpc_id: str | None,
        service_family: str,
        *,
        source: NormalizedResource,
        endpoint_type: str | None = None,
    ) -> bool:
        unscoped_vpc_key = aws_scoped_reference_key(None, vpc_id)
        if unscoped_vpc_key is None:
            return False
        vpc_reference = unscoped_vpc_key[1]
        for (candidate_vpc_key, candidate_service), endpoints in self.endpoints_by_vpc_and_service.items():
            if candidate_service != service_family or candidate_vpc_key[1] != vpc_reference:
                continue
            if not _provider_scope_is_uncertain(
                source.provider_config_key,
                candidate_vpc_key[0],
            ):
                continue
            if _filter_endpoint_type(endpoints, endpoint_type):
                return True
        return False

    def has_unresolved_service_name_endpoint(
        self,
        vpc_id: str | None,
        *,
        source: NormalizedResource,
    ) -> bool:
        unscoped_vpc_key = aws_scoped_reference_key(None, vpc_id)
        if unscoped_vpc_key is None:
            return False
        vpc_reference = unscoped_vpc_key[1]
        return any(
            aws_scoped_reference_key(None, endpoint.vpc_id) == (None, vpc_reference)
            and _provider_scope_may_match(
                source.provider_config_key,
                endpoint.provider_config_key,
            )
            for endpoint in self.unresolved_service_name_endpoints
        )

    def has_s3_endpoint(
        self,
        vpc_id: str | None,
        *,
        source: NormalizedResource | None = None,
    ) -> bool:
        return self.coverage_for(vpc_id, _S3, source=source).has_endpoint

    def has_secrets_manager_interface_endpoint(
        self,
        vpc_id: str | None,
        *,
        source: NormalizedResource | None = None,
    ) -> bool:
        return self.coverage_for(
            vpc_id,
            _SECRETS_MANAGER,
            source=source,
            endpoint_type=_INTERFACE,
        ).has_endpoint

    def has_kms_endpoint(
        self,
        vpc_id: str | None,
        *,
        source: NormalizedResource | None = None,
    ) -> bool:
        return self.coverage_for(
            vpc_id,
            _KMS,
            source=source,
            endpoint_type=_INTERFACE,
        ).has_endpoint


def build_aws_vpc_endpoint_index(source: ResourceInventory | Iterable[NormalizedResource]) -> AwsVpcEndpointIndex:
    resources = tuple(source.resources if isinstance(source, ResourceInventory) else source)
    pending_by_vpc_and_service: dict[
        tuple[AwsScopedReferenceKey, str],
        list[AwsVpcEndpointRecord],
    ] = {}
    pending_by_vpc: dict[AwsScopedReferenceKey, list[AwsVpcEndpointRecord]] = {}
    unresolved_service_name_endpoints: list[AwsVpcEndpointRecord] = []
    unclassified_service_endpoints: list[AwsVpcEndpointRecord] = []

    for resource in resources:
        if resource.resource_type != "aws_vpc_endpoint":
            continue
        record = _vpc_endpoint_record(resource)
        scoped_vpc_key = aws_scoped_reference_key(record.provider_config_key, record.vpc_id)
        if scoped_vpc_key is not None:
            pending_by_vpc.setdefault(scoped_vpc_key, []).append(record)
        if scoped_vpc_key is not None and record.service_family:
            pending_by_vpc_and_service.setdefault((scoped_vpc_key, record.service_family), []).append(record)
        elif not record.service_name:
            unresolved_service_name_endpoints.append(record)
        else:
            unclassified_service_endpoints.append(record)

    return AwsVpcEndpointIndex(
        endpoints_by_vpc_and_service=MappingProxyType(
            {
                key: tuple(value)
                for key, value in sorted(
                    pending_by_vpc_and_service.items(),
                    key=lambda item: (
                        item[0][0][0] or "",
                        item[0][0][1],
                        item[0][1],
                    ),
                )
            }
        ),
        endpoints_by_vpc=MappingProxyType(
            {
                key: tuple(value)
                for key, value in sorted(
                    pending_by_vpc.items(),
                    key=lambda item: (item[0][0] or "", item[0][1]),
                )
            }
        ),
        unresolved_service_name_endpoints=tuple(unresolved_service_name_endpoints),
        unclassified_service_endpoints=tuple(unclassified_service_endpoints),
    )


def _vpc_endpoint_record(resource: NormalizedResource) -> AwsVpcEndpointRecord:
    facts = aws_facts(resource)
    return AwsVpcEndpointRecord(
        endpoint_address=resource.address,
        provider_config_key=resource.provider_config_key,
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


def _filter_endpoint_type(
    endpoints: tuple[AwsVpcEndpointRecord, ...],
    endpoint_type: str | None,
) -> tuple[AwsVpcEndpointRecord, ...]:
    if endpoint_type is None:
        return endpoints
    normalized_type = _normalized_endpoint_type(endpoint_type)
    return tuple(
        endpoint for endpoint in endpoints if _normalized_endpoint_type(endpoint.endpoint_type) == normalized_type
    )


def _provider_scope_is_uncertain(
    source_provider_config_key: str | None,
    candidate_provider_config_key: str | None,
) -> bool:
    if source_provider_config_key is None:
        return candidate_provider_config_key is not None
    return candidate_provider_config_key is None


def _provider_scope_may_match(
    source_provider_config_key: str | None,
    candidate_provider_config_key: str | None,
) -> bool:
    return (
        source_provider_config_key is None
        or candidate_provider_config_key is None
        or source_provider_config_key == candidate_provider_config_key
    )


def _normalized_endpoint_type(endpoint_type: str | None) -> str | None:
    if endpoint_type is None:
        return None
    normalized = endpoint_type.strip().lower()
    return normalized or None
