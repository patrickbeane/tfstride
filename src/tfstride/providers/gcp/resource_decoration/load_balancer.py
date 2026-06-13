from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_index import GcpDecorationContext, GcpResourceIndex
from tfstride.providers.gcp.resource_mutations import gcp_mutations
from tfstride.providers.gcp.resource_types import (
    GCP_LOAD_BALANCER_BACKEND_BUCKET_TYPES,
    GCP_LOAD_BALANCER_BACKEND_SERVICE_TYPES,
    GCP_LOAD_BALANCER_NEG_TYPES,
    GCP_LOAD_BALANCER_TARGET_PROXY_TYPES,
    GCP_LOAD_BALANCER_URL_MAP_TYPES,
)
from tfstride.providers.gcp.resource_utils import (
    GCP_NETWORK_REFERENCE_SUFFIXES,
    dedupe,
    gcp_reference_key,
)


class DeriveLoadBalancerReachabilityStage:
    name = "derive_load_balancer_reachability"

    def apply(self, resources: list[NormalizedResource], context: GcpDecorationContext) -> None:
        _derive_load_balancer_frontend_reachability(context.index)


def _derive_load_balancer_frontend_reachability(index: GcpResourceIndex) -> None:
    for forwarding_rule in index.forwarding_rules:
        if not forwarding_rule.public_access_configured:
            continue
        frontend = _load_balancer_frontend_entry(forwarding_rule)
        reachable_backends: list[dict[str, Any]] = []
        for reference in _forwarding_rule_next_hop_references(forwarding_rule):
            _traverse_load_balancer_reference(
                reference,
                index,
                frontend,
                reachable_backends,
                path=[forwarding_rule.address],
                visited={forwarding_rule.address},
            )
        if reachable_backends:
            gcp_mutations(forwarding_rule).set_load_balancer_reachable_backends(reachable_backends)


def _forwarding_rule_next_hop_references(forwarding_rule: NormalizedResource) -> list[str]:
    return dedupe(
        reference
        for reference in (
            forwarding_rule.get_metadata_field(GcpResourceMetadata.FORWARDING_RULE_TARGET),
            forwarding_rule.get_metadata_field(GcpResourceMetadata.FORWARDING_RULE_BACKEND_SERVICE),
        )
        if reference
    )


def _traverse_load_balancer_reference(
    reference: str,
    index: GcpResourceIndex,
    frontend: dict[str, Any],
    reachable_backends: list[dict[str, Any]],
    *,
    path: list[str],
    visited: set[str],
) -> None:
    resource = _resource_by_reference(reference, index)
    if resource is None or resource.address in visited:
        return

    next_path = [*path, resource.address]
    next_visited = {*visited, resource.address}
    _append_load_balancer_frontend(resource, frontend, next_path)

    if resource.resource_type in GCP_LOAD_BALANCER_TARGET_PROXY_TYPES:
        url_map_reference = resource.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_URL_MAP)
        if url_map_reference:
            _traverse_load_balancer_reference(
                url_map_reference,
                index,
                frontend,
                reachable_backends,
                path=next_path,
                visited=next_visited,
            )
        return

    if resource.resource_type in GCP_LOAD_BALANCER_URL_MAP_TYPES:
        for backend_reference in _url_map_backend_references(resource):
            _traverse_load_balancer_reference(
                backend_reference,
                index,
                frontend,
                reachable_backends,
                path=next_path,
                visited=next_visited,
            )
        return

    if resource.resource_type in GCP_LOAD_BALANCER_BACKEND_SERVICE_TYPES:
        _mark_fronted_by_public_load_balancer(resource, frontend)
        reachable_backends.append(_load_balancer_backend_entry(frontend, resource, next_path))
        for backend_reference in _backend_service_group_references(resource):
            _traverse_load_balancer_reference(
                backend_reference,
                index,
                frontend,
                reachable_backends,
                path=next_path,
                visited=next_visited,
            )
        return

    if resource.resource_type in GCP_LOAD_BALANCER_BACKEND_BUCKET_TYPES:
        _mark_fronted_by_public_load_balancer(resource, frontend)
        reachable_backends.append(_load_balancer_backend_entry(frontend, resource, next_path))
        bucket_reference = resource.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_BACKEND_BUCKET_NAME)
        if bucket_reference:
            _traverse_load_balancer_reference(
                bucket_reference,
                index,
                frontend,
                reachable_backends,
                path=next_path,
                visited=next_visited,
            )
        return

    if resource.resource_type in GCP_LOAD_BALANCER_NEG_TYPES:
        _mark_fronted_by_public_load_balancer(resource, frontend)
        reachable_backends.append(_load_balancer_backend_entry(frontend, resource, next_path))
        for endpoint_reference in _network_endpoint_group_target_references(resource):
            _traverse_load_balancer_reference(
                endpoint_reference,
                index,
                frontend,
                reachable_backends,
                path=next_path,
                visited=next_visited,
            )
        return

    _mark_fronted_by_public_load_balancer(resource, frontend)
    reachable_backends.append(_load_balancer_backend_entry(frontend, resource, next_path))


def _url_map_backend_references(url_map: NormalizedResource) -> list[str]:
    references: list[str] = []
    default_service = url_map.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_DEFAULT_SERVICE)
    if default_service:
        references.append(default_service)
    for path_matcher in url_map.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_PATH_MATCHERS):
        matcher_default = path_matcher.get("default_service")
        if matcher_default:
            references.append(str(matcher_default))
        for path_rule in path_matcher.get("path_rule") or []:
            if not isinstance(path_rule, Mapping):
                continue
            service = path_rule.get("service")
            if service:
                references.append(str(service))
    return dedupe(references)


def _backend_service_group_references(backend_service: NormalizedResource) -> list[str]:
    references: list[str] = []
    for backend in backend_service.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_BACKENDS):
        group = backend.get("group")
        if group:
            references.append(str(group))
    return dedupe(references)


def _network_endpoint_group_target_references(neg: NormalizedResource) -> list[str]:
    references: list[str] = []
    for endpoint in neg.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_SERVERLESS_ENDPOINTS):
        platform = str(endpoint.get("platform") or "").strip()
        if platform == "cloud_run" and endpoint.get("service"):
            references.append(str(endpoint["service"]))
        elif platform == "cloud_function" and endpoint.get("function"):
            references.append(str(endpoint["function"]))
    for endpoint in neg.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_NETWORK_ENDPOINTS):
        instance = endpoint.get("instance")
        if instance:
            references.append(str(instance))
    return dedupe(references)


def _resource_by_reference(reference: str, index: GcpResourceIndex) -> NormalizedResource | None:
    reference_key = gcp_reference_key(str(reference), GCP_NETWORK_REFERENCE_SUFFIXES)
    return index.resources_by_reference.get(reference_key)


def _load_balancer_frontend_entry(forwarding_rule: NormalizedResource) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "forwarding_rule": forwarding_rule.address,
        "load_balancing_scheme": forwarding_rule.get_metadata_field(
            GcpResourceMetadata.FORWARDING_RULE_LOAD_BALANCING_SCHEME
        ),
        "ip_address": forwarding_rule.get_metadata_field(GcpResourceMetadata.FORWARDING_RULE_IP_ADDRESS),
        "ports": forwarding_rule.get_metadata_field(GcpResourceMetadata.FORWARDING_RULE_PORTS),
    }
    return {key: value for key, value in entry.items() if value not in (None, "", [], {})}


def _load_balancer_backend_entry(
    frontend: dict[str, Any],
    backend: NormalizedResource,
    path: list[str],
) -> dict[str, Any]:
    entry = {
        "forwarding_rule": frontend["forwarding_rule"],
        "backend": backend.address,
        "backend_type": backend.resource_type,
        "path": list(path),
    }
    ip_address = frontend.get("ip_address")
    if ip_address:
        entry["ip_address"] = ip_address
    return entry


def _append_load_balancer_frontend(
    resource: NormalizedResource,
    frontend: dict[str, Any],
    path: list[str],
) -> None:
    gcp_mutations(resource).append_load_balancer_frontend(frontend, path)


def _mark_fronted_by_public_load_balancer(resource: NormalizedResource, frontend: dict[str, Any]) -> None:
    gcp_mutations(resource).mark_fronted_by_public_load_balancer(frontend)