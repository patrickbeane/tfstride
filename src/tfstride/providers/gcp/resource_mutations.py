from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_facts import gcp_facts


@dataclass(frozen=True, slots=True)
class GcpResourceMutations:
    """GCP-owned write facade for normalized resource decoration."""

    resource: NormalizedResource

    def infer_vpc_id(self, vpc_id: str | None) -> bool:
        if not vpc_id or self.resource.vpc_id:
            return False
        self.resource.vpc_id = vpc_id
        return True

    def set_subnetwork_route_posture(
        self,
        *,
        has_public_route: bool,
        has_nat_gateway_egress: bool,
    ) -> None:
        self.resource.has_public_route = has_public_route
        self.resource.is_public_subnet = has_public_route
        self.resource.has_nat_gateway_egress = has_nat_gateway_egress

    def set_instance_network_posture(
        self,
        *,
        in_public_subnet: bool,
        has_nat_gateway_egress: bool,
        has_public_route: bool,
    ) -> None:
        self.resource.in_public_subnet = in_public_subnet
        self.resource.has_nat_gateway_egress = has_nat_gateway_egress
        self.resource.has_public_route = has_public_route

    def set_public_endpoint_posture(
        self,
        *,
        direct_internet_reachable: bool,
        internet_ingress_capable: bool,
        internet_ingress_reasons: Sequence[str],
    ) -> None:
        self.resource.direct_internet_reachable = direct_internet_reachable
        self.resource.internet_ingress_capable = internet_ingress_capable
        self.resource.internet_ingress_reasons = list(internet_ingress_reasons)

    def set_compute_internet_ingress(
        self,
        *,
        internet_ingress_reasons: Sequence[str],
        firewall_addresses: Sequence[str],
    ) -> None:
        self.resource.internet_ingress_capable = bool(internet_ingress_reasons)
        self.resource.internet_ingress_reasons = list(internet_ingress_reasons)
        gcp_facts(self.resource).set(
            GcpResourceMetadata.INTERNET_INGRESS_FIREWALLS,
            list(firewall_addresses),
        )

    def set_public_access(self, *, configured: bool, reasons: Sequence[str]) -> None:
        self.resource.public_access_configured = configured
        self.resource.public_access_reasons = list(reasons)

    def set_public_access_reasons(self, reasons: Sequence[str]) -> None:
        self.resource.public_access_reasons = list(reasons)

    def set_publicly_accessible(self, value: bool) -> None:
        self.resource.publicly_accessible = value

    def set_storage_encrypted(self, value: bool) -> None:
        self.resource.storage_encrypted = value

    def set_public_exposure(
        self,
        value: bool,
        *,
        reasons: Sequence[str] | None = None,
    ) -> None:
        self.resource.public_exposure = value
        self.resource.direct_internet_reachable = value
        if reasons is not None:
            self.resource.public_exposure_reasons = list(reasons)

    def set_load_balancer_reachable_backends(self, backends: Sequence[Mapping[str, Any]]) -> None:
        gcp_facts(self.resource).set(
            GcpResourceMetadata.LOAD_BALANCER_REACHABLE_BACKENDS,
            _dedupe_dicts(backends),
        )

    def append_load_balancer_frontend(
        self,
        frontend: Mapping[str, Any],
        path: Sequence[str],
    ) -> None:
        entry = dict(frontend)
        entry["path"] = list(path)
        facts = gcp_facts(self.resource)
        frontends = facts.get(GcpResourceMetadata.LOAD_BALANCER_FRONTENDS)
        frontends.append(entry)
        facts.set(GcpResourceMetadata.LOAD_BALANCER_FRONTENDS, _dedupe_dicts(frontends))

    def mark_fronted_by_public_load_balancer(self, frontend: Mapping[str, Any]) -> None:
        forwarding_rule = frontend.get("forwarding_rule")
        if not forwarding_rule:
            return
        facts = gcp_facts(self.resource)
        facts.set(GcpResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER, True)
        facts.append(
            GcpResourceMetadata.INTERNET_FACING_LOAD_BALANCER_ADDRESSES,
            str(forwarding_rule),
        )

    def set_sensitive_resource_iam_bindings(
        self,
        *,
        bindings: Sequence[Mapping[str, Any]],
        source_addresses: Sequence[str],
    ) -> None:
        facts = gcp_facts(self.resource)
        if bindings:
            facts.set(GcpResourceMetadata.IAM_BINDINGS, [dict(binding) for binding in bindings])
        if source_addresses:
            facts.extend(GcpResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES, list(source_addresses))


def gcp_mutations(resource: NormalizedResource) -> GcpResourceMutations:
    return GcpResourceMutations(resource)


def _dedupe_dicts(values: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    for value in values:
        copied = dict(value)
        if copied in deduped:
            continue
        deduped.append(copied)
    return deduped
