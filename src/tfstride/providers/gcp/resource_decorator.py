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
            if resource.resource_type == "google_compute_subnetwork":
                _derive_subnetwork_route_posture(resource, index)

        for resource in resources:
            if resource.resource_type == "google_compute_instance":
                _infer_instance_vpc_id(resource, index)
                _derive_instance_network_posture(resource, index)
                _derive_public_compute_exposure(resource, index)
            elif resource.resource_type in {"google_compute_forwarding_rule", "google_compute_global_forwarding_rule"}:
                _infer_instance_vpc_id(resource, index)
                _derive_instance_network_posture(resource, index)
            elif resource.resource_type in _SERVERLESS_WORKLOAD_RESOURCE_TYPES:
                _derive_public_serverless_exposure(resource, index)
            elif resource.resource_type == "google_secret_manager_secret":
                _derive_sensitive_resource_iam_bindings(resource, index.secret_iam_resources)
            elif resource.resource_type == "google_kms_crypto_key":
                _derive_sensitive_resource_iam_bindings(resource, index.kms_crypto_key_iam_resources)
            elif resource.resource_type == "google_storage_bucket":
                _derive_sensitive_resource_iam_bindings(resource, index.bucket_iam_resources)
                _derive_public_bucket_exposure(resource, index)


@dataclass(frozen=True, slots=True)
class _GcpResourceIndex:
    network_references: Mapping[str, str]
    subnetworks_by_reference: Mapping[str, NormalizedResource]
    routers_by_reference: Mapping[str, NormalizedResource]
    routes: tuple[NormalizedResource, ...]
    router_nats: tuple[NormalizedResource, ...]
    firewalls: tuple[NormalizedResource, ...]
    bucket_iam_resources: tuple[NormalizedResource, ...]
    secret_iam_resources: tuple[NormalizedResource, ...]
    kms_crypto_key_iam_resources: tuple[NormalizedResource, ...]
    cloud_run_iam_resources: tuple[NormalizedResource, ...]
    cloud_function_iam_resources: tuple[NormalizedResource, ...]

    @classmethod
    def build(cls, resources: list[NormalizedResource]) -> "_GcpResourceIndex":
        network_references: dict[str, str] = {}
        subnetworks_by_reference: dict[str, NormalizedResource] = {}
        routers_by_reference: dict[str, NormalizedResource] = {}
        routes: list[NormalizedResource] = []
        router_nats: list[NormalizedResource] = []
        firewalls: list[NormalizedResource] = []
        bucket_iam_resources: list[NormalizedResource] = []
        secret_iam_resources: list[NormalizedResource] = []
        kms_crypto_key_iam_resources: list[NormalizedResource] = []
        cloud_run_iam_resources: list[NormalizedResource] = []
        cloud_function_iam_resources: list[NormalizedResource] = []
        for resource in resources:
            if resource.resource_type == "google_compute_network":
                for reference in _resource_references(resource):
                    network_references.setdefault(reference, resource.address)
                    network_references.setdefault(_network_reference_key(reference), resource.address)
            elif resource.resource_type == "google_compute_subnetwork":
                for reference in _resource_references(resource):
                    subnetworks_by_reference.setdefault(reference, resource)
            elif resource.resource_type == "google_compute_router":
                for reference in _resource_references(resource):
                    routers_by_reference.setdefault(reference, resource)
            elif resource.resource_type == "google_compute_route":
                routes.append(resource)
            elif resource.resource_type == "google_compute_router_nat":
                router_nats.append(resource)
            elif resource.resource_type == "google_compute_firewall":
                firewalls.append(resource)
            elif resource.resource_type in _GCS_BUCKET_IAM_RESOURCE_TYPES:
                bucket_iam_resources.append(resource)
            elif resource.resource_type in _SECRET_IAM_RESOURCE_TYPES:
                secret_iam_resources.append(resource)
            elif resource.resource_type in _KMS_CRYPTO_KEY_IAM_RESOURCE_TYPES:
                kms_crypto_key_iam_resources.append(resource)
            elif resource.resource_type in _CLOUD_RUN_IAM_RESOURCE_TYPES:
                cloud_run_iam_resources.append(resource)
            elif resource.resource_type in _CLOUD_FUNCTION_IAM_RESOURCE_TYPES:
                cloud_function_iam_resources.append(resource)
        return cls(
            network_references=MappingProxyType(network_references),
            subnetworks_by_reference=MappingProxyType(subnetworks_by_reference),
            routers_by_reference=MappingProxyType(routers_by_reference),
            routes=tuple(routes),
            router_nats=tuple(router_nats),
            firewalls=tuple(firewalls),
            bucket_iam_resources=tuple(bucket_iam_resources),
            secret_iam_resources=tuple(secret_iam_resources),
            kms_crypto_key_iam_resources=tuple(kms_crypto_key_iam_resources),
            cloud_run_iam_resources=tuple(cloud_run_iam_resources),
            cloud_function_iam_resources=tuple(cloud_function_iam_resources),
        )


_SERVERLESS_WORKLOAD_RESOURCE_TYPES = frozenset(
    {
        "google_cloud_run_service",
        "google_cloud_run_v2_service",
        "google_cloudfunctions_function",
        "google_cloudfunctions2_function",
    }
)
_CLOUD_RUN_IAM_RESOURCE_TYPES = frozenset(
    {
        "google_cloud_run_service_iam_binding",
        "google_cloud_run_service_iam_member",
        "google_cloud_run_service_iam_policy",
        "google_cloud_run_v2_service_iam_binding",
        "google_cloud_run_v2_service_iam_member",
        "google_cloud_run_v2_service_iam_policy",
    }
)
_CLOUD_FUNCTION_IAM_RESOURCE_TYPES = frozenset(
    {
        "google_cloudfunctions_function_iam_binding",
        "google_cloudfunctions_function_iam_member",
        "google_cloudfunctions_function_iam_policy",
        "google_cloudfunctions2_function_iam_binding",
        "google_cloudfunctions2_function_iam_member",
        "google_cloudfunctions2_function_iam_policy",
    }
)
_SERVERLESS_PUBLIC_INVOKER_ROLES = frozenset({"roles/run.invoker", "roles/cloudfunctions.invoker"})

_GCS_BUCKET_IAM_RESOURCE_TYPES = frozenset(
    {
        "google_storage_bucket_iam_binding",
        "google_storage_bucket_iam_member",
        "google_storage_bucket_iam_policy",
    }
)
_SECRET_IAM_RESOURCE_TYPES = frozenset(
    {
        "google_secret_manager_secret_iam_binding",
        "google_secret_manager_secret_iam_member",
        "google_secret_manager_secret_iam_policy",
    }
)
_KMS_CRYPTO_KEY_IAM_RESOURCE_TYPES = frozenset(
    {
        "google_kms_crypto_key_iam_binding",
        "google_kms_crypto_key_iam_member",
        "google_kms_crypto_key_iam_policy",
    }
)


def _derive_subnetwork_route_posture(subnetwork: NormalizedResource, index: _GcpResourceIndex) -> None:
    has_public_route = any(
        _route_has_internet_gateway(route)
        and not route.get_metadata_field(GcpResourceMetadata.ROUTE_TAGS)
        and _same_network_reference(route.vpc_id, subnetwork.vpc_id, index)
        for route in index.routes
    )
    has_nat_egress = any(
        _nat_applies_to_subnetwork(router_nat, subnetwork, index)
        for router_nat in index.router_nats
    )
    subnetwork.has_public_route = has_public_route
    subnetwork.is_public_subnet = has_public_route
    subnetwork.has_nat_gateway_egress = has_nat_egress


def _derive_instance_network_posture(resource: NormalizedResource, index: _GcpResourceIndex) -> None:
    subnetworks = _resource_subnetworks(resource, index)
    resource.in_public_subnet = any(subnetwork.is_public_subnet for subnetwork in subnetworks)
    resource.has_nat_gateway_egress = any(subnetwork.has_nat_gateway_egress for subnetwork in subnetworks)
    resource.has_public_route = resource.in_public_subnet or any(
        _route_has_internet_gateway(route)
        and _route_tags_apply_to_instance(route, resource)
        and _same_network_reference(route.vpc_id, resource.vpc_id, index)
        for route in index.routes
    )


def _resource_subnetworks(resource: NormalizedResource, index: _GcpResourceIndex) -> list[NormalizedResource]:
    subnetworks: list[NormalizedResource] = []
    seen: set[str] = set()
    for subnet_reference in resource.subnet_ids:
        subnetwork = index.subnetworks_by_reference.get(_reference_key(subnet_reference))
        if subnetwork is None or subnetwork.address in seen:
            continue
        subnetworks.append(subnetwork)
        seen.add(subnetwork.address)
    return subnetworks


def _infer_instance_vpc_id(resource: NormalizedResource, index: _GcpResourceIndex) -> None:
    if resource.vpc_id:
        return
    for subnet_reference in resource.subnet_ids:
        subnetwork = index.subnetworks_by_reference.get(_reference_key(subnet_reference))
        if subnetwork is None or not subnetwork.vpc_id:
            continue
        resource.vpc_id = subnetwork.vpc_id
        return
    for network_reference in _instance_network_references(resource):
        resource.vpc_id = network_reference
        return


def _instance_network_references(resource: NormalizedResource) -> list[str]:
    references: list[str] = []
    for interface in resource.get_metadata_field(GcpResourceMetadata.NETWORK_INTERFACES):
        if not isinstance(interface, Mapping):
            continue
        network = interface.get("network")
        if network in (None, ""):
            continue
        references.append(str(network))
    return references


def _derive_public_compute_exposure(resource: NormalizedResource, index: _GcpResourceIndex) -> None:
    matching_firewalls = [
        firewall
        for firewall in index.firewalls
        if _firewall_applies_to_instance(firewall, resource, index)
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


def _derive_public_serverless_exposure(resource: NormalizedResource, index: _GcpResourceIndex) -> None:
    iam_resources = (
        index.cloud_run_iam_resources
        if resource.resource_type in {"google_cloud_run_service", "google_cloud_run_v2_service"}
        else index.cloud_function_iam_resources
    )
    public_access_reasons = _serverless_public_access_reasons(resource, iam_resources)
    if public_access_reasons:
        resource.public_access_reasons = public_access_reasons
    public_exposure = bool(resource.public_access_configured and public_access_reasons)
    resource.public_exposure = public_exposure
    resource.direct_internet_reachable = public_exposure
    if public_exposure:
        resource.public_exposure_reasons = public_access_reasons

    _derive_sensitive_resource_iam_bindings(resource, iam_resources)


def _derive_sensitive_resource_iam_bindings(
    resource: NormalizedResource,
    iam_resources: tuple[NormalizedResource, ...],
) -> None:
    resource_references = set(_resource_references(resource))
    bindings: list[dict[str, Any]] = []
    source_addresses: list[str] = []
    for iam_resource in iam_resources:
        target_reference = _resource_iam_target_reference(iam_resource)
        if not target_reference or _reference_key(target_reference) not in resource_references:
            continue
        for binding in _iam_bindings(iam_resource):
            bindings.append(
                {
                    "role": str(binding.get("role") or "unknown role"),
                    "members": _binding_members(binding),
                    "source": iam_resource.address,
                }
            )
            source_addresses.append(iam_resource.address)

    if bindings:
        resource.set_metadata_field(GcpResourceMetadata.IAM_BINDINGS, bindings)
    if source_addresses:
        resource.extend_metadata_field(GcpResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES, source_addresses)


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


def _serverless_public_access_reasons(
    resource: NormalizedResource,
    iam_resources: tuple[NormalizedResource, ...],
) -> list[str]:
    reasons: list[str] = []
    resource_references = set(_resource_references(resource))
    for iam_resource in iam_resources:
        target_reference = _resource_iam_target_reference(iam_resource)
        if not target_reference or _reference_key(target_reference) not in resource_references:
            continue
        for binding in _iam_bindings(iam_resource):
            role = str(binding.get("role") or "unknown role")
            if role not in _SERVERLESS_PUBLIC_INVOKER_ROLES:
                continue
            public_members = sorted(
                member
                for member in _binding_members(binding)
                if member in _PUBLIC_GCP_IAM_MEMBERS
            )
            for member in public_members:
                reasons.append(f"{iam_resource.address} grants {role} to {member}")
    return _dedupe(reasons)


def _resource_iam_target_reference(resource: NormalizedResource) -> str | None:
    bucket_name = resource.get_metadata_field(GcpResourceMetadata.BUCKET_NAME)
    if bucket_name:
        return bucket_name
    secret_reference = resource.get_metadata_field(GcpResourceMetadata.SECRET_REFERENCE)
    if secret_reference:
        return secret_reference
    cloud_run_reference = resource.get_metadata_field(GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE)
    if cloud_run_reference:
        return cloud_run_reference
    cloud_function_reference = resource.get_metadata_field(GcpResourceMetadata.CLOUD_FUNCTION_REFERENCE)
    if cloud_function_reference:
        return cloud_function_reference
    return resource.get_metadata_field(GcpResourceMetadata.KMS_CRYPTO_KEY_REFERENCE)


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


def _firewall_applies_to_instance(
    firewall: NormalizedResource,
    instance: NormalizedResource,
    index: _GcpResourceIndex,
) -> bool:
    if firewall.metadata.get("disabled"):
        return False
    if str(firewall.metadata.get("direction") or "ingress").strip().lower() != "ingress":
        return False
    if not _same_network_reference(firewall.vpc_id, instance.vpc_id, index):
        return False

    target_tags = set(firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_TARGET_TAGS))
    if target_tags:
        instance_tags = set(instance.get_metadata_field(GcpResourceMetadata.NETWORK_TAGS))
        if not target_tags.intersection(instance_tags):
            return False

    target_service_accounts = _service_account_reference_keys(
        firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_TARGET_SERVICE_ACCOUNTS)
    )
    if target_service_accounts:
        instance_service_accounts = _instance_service_account_keys(instance)
        if not target_service_accounts.intersection(instance_service_accounts):
            return False

    return True


def _internet_ingress_reasons(firewall: NormalizedResource) -> list[str]:
    return [
        describe_security_group_rule(firewall, rule)
        for rule in firewall.network_rules
        if rule.direction == "ingress" and rule.allows_internet()
    ]


def _route_has_internet_gateway(route: NormalizedResource) -> bool:
    dest_range = route.get_metadata_field(GcpResourceMetadata.ROUTE_DEST_RANGE)
    next_hop_gateway = route.get_metadata_field(GcpResourceMetadata.ROUTE_NEXT_HOP_GATEWAY)
    if dest_range not in {"0.0.0.0/0", "::/0"} or not next_hop_gateway:
        return False
    return "default-internet-gateway" in next_hop_gateway or "internet" in next_hop_gateway


def _route_tags_apply_to_instance(route: NormalizedResource, instance: NormalizedResource) -> bool:
    route_tags = set(route.get_metadata_field(GcpResourceMetadata.ROUTE_TAGS))
    if not route_tags:
        return False
    instance_tags = set(instance.get_metadata_field(GcpResourceMetadata.NETWORK_TAGS))
    return bool(route_tags.intersection(instance_tags))


def _nat_applies_to_subnetwork(
    router_nat: NormalizedResource,
    subnetwork: NormalizedResource,
    index: _GcpResourceIndex,
) -> bool:
    source_mode = str(router_nat.metadata.get("source_subnetwork_ip_ranges_to_nat") or "").upper()
    if source_mode.startswith("ALL_SUBNETWORKS"):
        return any(
            _same_network_reference(network_reference, subnetwork.vpc_id, index)
            for network_reference in _router_nat_network_references(router_nat, index)
        )

    subnetwork_references = set(_resource_references(subnetwork))
    for nat_subnetwork in router_nat.get_metadata_field(GcpResourceMetadata.NAT_SUBNETWORKS):
        reference = nat_subnetwork.get("name") if isinstance(nat_subnetwork, dict) else None
        if reference and _reference_key(str(reference)) in subnetwork_references:
            return True
    return False


def _router_nat_network_references(
    router_nat: NormalizedResource,
    index: _GcpResourceIndex,
) -> tuple[str, ...]:
    router_reference = router_nat.get_metadata_field(GcpResourceMetadata.ROUTER_REFERENCE)
    if not router_reference:
        return ()
    router = index.routers_by_reference.get(_reference_key(router_reference))
    if router is None or not router.vpc_id:
        return ()
    return (router.vpc_id,)


def _instance_service_account_keys(instance: NormalizedResource) -> set[str]:
    keys: set[str] = set()
    for account in instance.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNTS):
        if not isinstance(account, dict):
            continue
        keys.update(_service_account_reference_keys([account.get("email")]))
    return keys


def _service_account_reference_keys(values: list[object]) -> set[str]:
    keys: set[str] = set()
    for value in values:
        if value in (None, "", "default"):
            continue
        text = str(value).strip()
        if not text or text == "default":
            continue
        keys.add(text)
        if text.startswith("serviceAccount:"):
            keys.add(text.removeprefix("serviceAccount:"))
        else:
            keys.add(f"serviceAccount:{text}")
    return keys


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
        resource.get_metadata_field(GcpResourceMetadata.SECRET_ID),
        resource.get_metadata_field(GcpResourceMetadata.SECRET_REFERENCE),
        resource.get_metadata_field(GcpResourceMetadata.KMS_CRYPTO_KEY_REFERENCE),
        resource.get_metadata_field(GcpResourceMetadata.KMS_KEY_RING),
        resource.get_metadata_field(GcpResourceMetadata.SELF_LINK),
    ):
        if reference:
            references.add(reference)
    return tuple(sorted(_reference_key(reference) for reference in references if reference))


def _same_network_reference(
    left: str | None,
    right: str | None,
    index: _GcpResourceIndex | None = None,
) -> bool:
    if not left or not right:
        return False
    return _canonical_network_reference(left, index) == _canonical_network_reference(right, index)


def _canonical_network_reference(value: str, index: _GcpResourceIndex | None) -> str:
    reference_key = _reference_key(value)
    network_key = _network_reference_key(value)
    if index is not None:
        return (
            index.network_references.get(reference_key)
            or index.network_references.get(network_key)
            or network_key
        )
    return network_key


def _network_reference_key(value: str) -> str:
    text = _reference_key(value)
    for marker in ("/global/networks/", "/networks/"):
        if marker in text:
            return text.rsplit(marker, 1)[-1]
    return text


def _reference_key(value: str) -> str:
    text = str(value).strip()
    for suffix in (".id", ".name", ".secret_id", ".crypto_key_id", ".self_link"):
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