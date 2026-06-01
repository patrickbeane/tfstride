from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.resource_helpers import describe_security_group_rule


_PUBLIC_GCP_IAM_MEMBERS = frozenset({"allUsers", "allAuthenticatedUsers"})


class GcpResourceDecorator:
    """Derive cross-resource GCP posture from normalized Terraform resources."""

    def decorate(self, resources: list[NormalizedResource]) -> None:
        index = _GcpResourceIndex.build(resources)
        for resource in resources:
            if resource.resource_type == "google_compute_instance":
                _infer_instance_vpc_id(resource, index)
                _derive_public_compute_exposure(resource, index)
            elif resource.resource_type == "google_storage_bucket":
                _derive_public_bucket_exposure(resource, index)


@dataclass(frozen=True, slots=True)
class _GcpResourceIndex:
    subnetworks_by_reference: Mapping[str, NormalizedResource]
    firewalls: tuple[NormalizedResource, ...]
    bucket_iam_resources: tuple[NormalizedResource, ...]

    @classmethod
    def build(cls, resources: list[NormalizedResource]) -> "_GcpResourceIndex":
        subnetworks_by_reference: dict[str, NormalizedResource] = {}
        firewalls: list[NormalizedResource] = []
        bucket_iam_resources: list[NormalizedResource] = []
        for resource in resources:
            if resource.resource_type == "google_compute_subnetwork":
                for reference in _resource_references(resource):
                    subnetworks_by_reference.setdefault(reference, resource)
            elif resource.resource_type == "google_compute_firewall":
                firewalls.append(resource)
            elif resource.resource_type in _GCS_BUCKET_IAM_RESOURCE_TYPES:
                bucket_iam_resources.append(resource)
        return cls(
            subnetworks_by_reference=MappingProxyType(subnetworks_by_reference),
            firewalls=tuple(firewalls),
            bucket_iam_resources=tuple(bucket_iam_resources),
        )


_GCS_BUCKET_IAM_RESOURCE_TYPES = frozenset(
    {
        "google_storage_bucket_iam_binding",
        "google_storage_bucket_iam_member",
        "google_storage_bucket_iam_policy",
    }
)


def _infer_instance_vpc_id(resource: NormalizedResource, index: _GcpResourceIndex) -> None:
    if resource.vpc_id:
        return
    for subnet_reference in resource.subnet_ids:
        subnetwork = index.subnetworks_by_reference.get(_reference_key(subnet_reference))
        if subnetwork is None or not subnetwork.vpc_id:
            continue
        resource.vpc_id = subnetwork.vpc_id
        return


def _derive_public_compute_exposure(resource: NormalizedResource, index: _GcpResourceIndex) -> None:
    matching_firewalls = [
        firewall
        for firewall in index.firewalls
        if _firewall_applies_to_instance(firewall, resource)
        and _internet_ingress_reasons(firewall)
    ]
    internet_ingress_reasons = [
        reason
        for firewall in matching_firewalls
        for reason in _internet_ingress_reasons(firewall)
    ]
    internet_ingress = bool(internet_ingress_reasons)
    resource.internet_ingress_capable = internet_ingress
    resource.internet_ingress_reasons = internet_ingress_reasons
    resource.set_metadata_field(
        GcpResourceMetadata.INTERNET_INGRESS_FIREWALLS,
        [firewall.address for firewall in matching_firewalls],
    )

    public_exposure = bool(resource.public_access_configured and internet_ingress)
    resource.public_exposure = public_exposure
    resource.direct_internet_reachable = public_exposure
    if public_exposure:
        resource.public_exposure_reasons = [
            "compute instance has an external access config and matching firewall rules allow internet ingress"
        ]


def _derive_public_bucket_exposure(bucket: NormalizedResource, index: _GcpResourceIndex) -> None:
    public_access_reasons = _bucket_public_access_reasons(bucket, index)
    bucket.public_access_configured = bool(public_access_reasons)
    bucket.public_access_reasons = public_access_reasons

    public_exposure = bool(public_access_reasons) and not _public_access_prevention_enforced(bucket)
    bucket.public_exposure = public_exposure
    bucket.direct_internet_reachable = public_exposure
    if public_exposure:
        bucket.public_exposure_reasons = public_access_reasons


def _bucket_public_access_reasons(bucket: NormalizedResource, index: _GcpResourceIndex) -> list[str]:
    reasons: list[str] = []
    bucket_references = set(_resource_references(bucket))
    for iam_resource in index.bucket_iam_resources:
        iam_bucket = iam_resource.get_metadata_field(GcpResourceMetadata.BUCKET_NAME)
        if not iam_bucket or _reference_key(iam_bucket) not in bucket_references:
            continue
        for binding in _iam_bindings(iam_resource):
            role = str(binding.get("role") or "unknown role")
            public_members = sorted(
                member
                for member in _binding_members(binding)
                if member in _PUBLIC_GCP_IAM_MEMBERS
            )
            for member in public_members:
                reasons.append(f"{iam_resource.address} grants {role} to {member}")
    return _dedupe(reasons)


def _iam_bindings(resource: NormalizedResource) -> list[dict[str, Any]]:
    bindings = resource.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS)
    if bindings:
        return bindings
    role = resource.get_metadata_field(GcpResourceMetadata.IAM_ROLE)
    member = resource.get_metadata_field(GcpResourceMetadata.IAM_MEMBER)
    if role and member:
        return [{"role": role, "members": [member]}]
    return []


def _binding_members(binding: Mapping[str, Any]) -> list[str]:
    members = binding.get("members")
    if isinstance(members, list):
        return [str(member) for member in members if member not in (None, "")]
    if members in (None, ""):
        return []
    return [str(members)]


def _public_access_prevention_enforced(bucket: NormalizedResource) -> bool:
    value = bucket.get_metadata_field(GcpResourceMetadata.PUBLIC_ACCESS_PREVENTION)
    return value is not None and value.strip().lower() == "enforced"


def _firewall_applies_to_instance(firewall: NormalizedResource, instance: NormalizedResource) -> bool:
    if firewall.metadata.get("disabled"):
        return False
    if str(firewall.metadata.get("direction") or "ingress").strip().lower() != "ingress":
        return False
    if not _same_network_reference(firewall.vpc_id, instance.vpc_id):
        return False

    target_tags = set(firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_TARGET_TAGS))
    if not target_tags:
        return True
    instance_tags = set(instance.get_metadata_field(GcpResourceMetadata.NETWORK_TAGS))
    return bool(target_tags.intersection(instance_tags))


def _internet_ingress_reasons(firewall: NormalizedResource) -> list[str]:
    return [
        describe_security_group_rule(firewall, rule)
        for rule in firewall.network_rules
        if rule.direction == "ingress" and rule.allows_internet()
    ]


def _resource_references(resource: NormalizedResource) -> tuple[str, ...]:
    references = {
        resource.address,
        f"{resource.address}.id",
        f"{resource.address}.name",
    }
    for reference in (
        resource.identifier,
        resource.get_metadata_field(GcpResourceMetadata.NAME),
        resource.get_metadata_field(GcpResourceMetadata.BUCKET_NAME),
        resource.get_metadata_field(GcpResourceMetadata.SELF_LINK),
    ):
        if reference:
            references.add(reference)
    return tuple(sorted(_reference_key(reference) for reference in references if reference))


def _same_network_reference(left: str | None, right: str | None) -> bool:
    if not left or not right:
        return False
    return _reference_key(left) == _reference_key(right)


def _reference_key(value: str) -> str:
    text = str(value).strip()
    for suffix in (".id", ".name", ".self_link"):
        if text.endswith(suffix):
            return text[: -len(suffix)]
    return text


def _dedupe(values: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        deduped.append(value)
        seen.add(value)
    return deduped