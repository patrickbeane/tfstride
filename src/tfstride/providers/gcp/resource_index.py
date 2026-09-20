from __future__ import annotations

import re
from collections.abc import Callable, Collection, Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_types import (
    GCP_ARTIFACT_REGISTRY_REPOSITORY_IAM_RESOURCE_TYPES,
    GCP_BIGQUERY_DATASET_IAM_RESOURCE_TYPES,
    GCP_BIGQUERY_TABLE_IAM_RESOURCE_TYPES,
    GCP_CLOUD_FUNCTION_IAM_RESOURCE_TYPES,
    GCP_CLOUD_RUN_IAM_RESOURCE_TYPES,
    GCP_FORWARDING_RULE_RESOURCE_TYPES,
    GCP_KMS_CRYPTO_KEY_IAM_RESOURCE_TYPES,
    GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES,
    GCP_PUBSUB_SUBSCRIPTION_IAM_RESOURCE_TYPES,
    GCP_PUBSUB_TOPIC_IAM_RESOURCE_TYPES,
    GCP_SECRET_MANAGER_SECRET_IAM_RESOURCE_TYPES,
    GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES,
    GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.gcp.resource_utils import (
    GCP_NETWORK_REFERENCE_SUFFIXES,
    gcp_reference_key,
    is_gcp_terraform_resource_address,
    normalize_gcp_project,
)
from tfstride.providers.resource_reference_index import (
    ResourceReferenceIndex,
    ResourceReferenceResolution,
    build_resource_reference_index,
)

_PROJECT_PATH_PATTERN = re.compile(r"(?:^|/)projects/(?P<project>[^/]+)(?:/|$)")
_LOCATION_PATH_PATTERN = re.compile(r"(?:^|/)(?:locations|regions|zones)/(?P<location>[^/]+)(?:/|$)")
_GLOBAL_PATH_PATTERN = re.compile(r"(?:^|/)global(?:/|$)")
_GCP_LOCATION_SCOPED_RESOURCE_TYPES = frozenset(
    {
        GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY,
        GcpResourceType.CLOUD_RUN_SERVICE,
        GcpResourceType.CLOUD_RUN_V2_SERVICE,
        GcpResourceType.CLOUDFUNCTIONS_FUNCTION,
        GcpResourceType.CLOUDFUNCTIONS2_FUNCTION,
        GcpResourceType.COMPUTE_BACKEND_SERVICE,
        GcpResourceType.COMPUTE_FORWARDING_RULE,
        GcpResourceType.COMPUTE_NETWORK_ENDPOINT_GROUP,
        GcpResourceType.COMPUTE_REGION_BACKEND_SERVICE,
        GcpResourceType.COMPUTE_REGION_NETWORK_ENDPOINT_GROUP,
        GcpResourceType.COMPUTE_REGION_SECURITY_POLICY,
        GcpResourceType.COMPUTE_REGION_TARGET_HTTP_PROXY,
        GcpResourceType.COMPUTE_REGION_TARGET_HTTPS_PROXY,
        GcpResourceType.COMPUTE_REGION_URL_MAP,
        GcpResourceType.COMPUTE_ROUTER,
        GcpResourceType.COMPUTE_SUBNETWORK,
        GcpResourceType.KMS_CRYPTO_KEY,
        GcpResourceType.KMS_CRYPTO_KEY_VERSION,
        GcpResourceType.KMS_KEY_RING,
    }
)


@dataclass(frozen=True, slots=True)
class GcpResourceReferenceView:
    """Resolve GCP references without discarding colliding native aliases."""

    _index: ResourceReferenceIndex
    _resources_by_address: Mapping[str, NormalizedResource]
    _resource_types: frozenset[str] | None = None

    def resolve(
        self,
        reference: str | None,
        *,
        source: NormalizedResource | None = None,
        resource_types: Collection[str] | None = None,
        scope_reference: str | None = None,
    ) -> ResourceReferenceResolution:
        """Apply type and GCP scope filtering before classifying candidates."""

        expected_types = self._expected_resource_types(resource_types)
        if expected_types == frozenset():
            return ResourceReferenceResolution(candidates=())

        if reference:
            reference_key = self._index.reference_key(reference)
            exact = self._resources_by_address.get(reference_key)
            if exact is not None:
                if expected_types is None or exact.resource_type in expected_types:
                    return ResourceReferenceResolution(candidates=(exact,))
                return ResourceReferenceResolution(candidates=())

        resolution = self._index.resolve(
            reference,
            candidate_filter=(
                None if expected_types is None else lambda candidate: candidate.resource_type in expected_types
            ),
        )
        strong_candidates = tuple(
            candidate
            for candidate in resolution.candidates
            if reference is not None and _gcp_reference_is_strong_for_candidate(reference, candidate)
        )
        if strong_candidates:
            return ResourceReferenceResolution(candidates=strong_candidates)

        explicit_project, explicit_location = _scope_from_reference(scope_reference or reference or "")
        if explicit_project is not None or explicit_location is not None:
            candidates = _scope_candidates_for_values(
                resolution.candidates,
                project=explicit_project,
                location=explicit_location,
            )
        else:
            candidates = _scope_candidates(resolution.candidates, source)
        return ResourceReferenceResolution(candidates=candidates)

    def get(
        self,
        reference: str | None,
        default: NormalizedResource | None = None,
        *,
        source: NormalizedResource | None = None,
        resource_types: Collection[str] | None = None,
    ) -> NormalizedResource | None:
        selected = self.resolve(
            reference,
            source=source,
            resource_types=resource_types,
        ).selected_candidate
        return selected if selected is not None else default

    def _expected_resource_types(
        self,
        resource_types: Collection[str] | None,
    ) -> frozenset[str] | None:
        requested = frozenset(resource_types) if resource_types is not None else None
        if self._resource_types is None:
            return requested
        if requested is None:
            return self._resource_types
        return self._resource_types.intersection(requested)


@dataclass(frozen=True, slots=True)
class GcpNetworkReferenceView:
    """Expose canonical network addresses over scope-aware resource resolution."""

    _resources: GcpResourceReferenceView

    def resolve(
        self,
        reference: str | None,
        *,
        source: NormalizedResource | None = None,
    ) -> ResourceReferenceResolution:
        canonical_reference = _gcp_reference_key(reference) if reference else reference
        resolution = self._resources.resolve(canonical_reference, source=source)
        if resolution.state != "unresolved" or not reference:
            return resolution
        network_reference = gcp_network_reference_key(reference)
        if network_reference == canonical_reference:
            return resolution
        return self._resources.resolve(
            network_reference,
            source=source,
            scope_reference=canonical_reference,
        )

    def canonical_reference(
        self,
        reference: str | None,
        *,
        source: NormalizedResource | None = None,
    ) -> str | None:
        if not reference:
            return None
        resolution = self.resolve(reference, source=source)
        if resolution.selected_candidate is not None:
            return resolution.selected_candidate.address
        if resolution.state == "ambiguous":
            return None
        if source is not None and self.resolve(reference).state != "unresolved":
            return None
        return _unmodeled_network_reference_key(reference, source)

    def get(
        self,
        reference: str | None,
        default: str | None = None,
        *,
        source: NormalizedResource | None = None,
    ) -> str | None:
        selected = self.resolve(reference, source=source).selected_candidate
        return selected.address if selected is not None else default


@dataclass(frozen=True, slots=True)
class GcpResourceIndex:
    resources_by_reference: GcpResourceReferenceView
    network_references: GcpNetworkReferenceView
    subnetworks_by_reference: GcpResourceReferenceView
    routers_by_reference: GcpResourceReferenceView
    forwarding_rules: tuple[NormalizedResource, ...]
    routes: tuple[NormalizedResource, ...]
    router_nats: tuple[NormalizedResource, ...]
    firewalls: tuple[NormalizedResource, ...]
    firewall_policy_rules: tuple[NormalizedResource, ...]
    firewall_policy_associations: tuple[NormalizedResource, ...]
    bucket_iam_resources: tuple[NormalizedResource, ...]
    secret_iam_resources: tuple[NormalizedResource, ...]
    pubsub_topic_iam_resources: tuple[NormalizedResource, ...]
    pubsub_subscription_iam_resources: tuple[NormalizedResource, ...]
    bigquery_dataset_iam_resources: tuple[NormalizedResource, ...]
    bigquery_table_iam_resources: tuple[NormalizedResource, ...]
    kms_crypto_key_iam_resources: tuple[NormalizedResource, ...]
    kms_key_ring_iam_resources: tuple[NormalizedResource, ...]
    cloud_run_iam_resources: tuple[NormalizedResource, ...]
    cloud_function_iam_resources: tuple[NormalizedResource, ...]
    artifact_registry_iam_resources: tuple[NormalizedResource, ...]
    service_accounts: tuple[NormalizedResource, ...]
    service_account_iam_resources: tuple[NormalizedResource, ...]
    workload_identity_pools: tuple[NormalizedResource, ...]
    workload_identity_pool_providers: tuple[NormalizedResource, ...]


@dataclass(slots=True)
class GcpDecorationContext:
    index: GcpResourceIndex


class GcpResourceIndexBuilder:
    def build(self, resources: list[NormalizedResource]) -> GcpResourceIndex:
        resource_tuple = tuple(resources)
        resources_by_address: dict[str, NormalizedResource] = {}
        resources_by_type: dict[str, list[NormalizedResource]] = {}
        forwarding_rules: list[NormalizedResource] = []
        routes: list[NormalizedResource] = []
        router_nats: list[NormalizedResource] = []
        firewalls: list[NormalizedResource] = []
        firewall_policy_rules: list[NormalizedResource] = []
        firewall_policy_associations: list[NormalizedResource] = []
        bucket_iam_resources: list[NormalizedResource] = []
        secret_iam_resources: list[NormalizedResource] = []
        pubsub_topic_iam_resources: list[NormalizedResource] = []
        pubsub_subscription_iam_resources: list[NormalizedResource] = []
        bigquery_dataset_iam_resources: list[NormalizedResource] = []
        bigquery_table_iam_resources: list[NormalizedResource] = []
        kms_crypto_key_iam_resources: list[NormalizedResource] = []
        kms_key_ring_iam_resources: list[NormalizedResource] = []
        cloud_run_iam_resources: list[NormalizedResource] = []
        cloud_function_iam_resources: list[NormalizedResource] = []
        artifact_registry_iam_resources: list[NormalizedResource] = []
        service_accounts: list[NormalizedResource] = []
        service_account_iam_resources: list[NormalizedResource] = []
        workload_identity_pools: list[NormalizedResource] = []
        workload_identity_pool_providers: list[NormalizedResource] = []
        for resource in resource_tuple:
            resources_by_address.setdefault(resource.address, resource)
            resources_by_type.setdefault(resource.resource_type, []).append(resource)
            if resource.resource_type == GcpResourceType.COMPUTE_ROUTE:
                routes.append(resource)
            elif resource.resource_type == GcpResourceType.COMPUTE_ROUTER_NAT:
                router_nats.append(resource)
            elif resource.resource_type in GCP_FORWARDING_RULE_RESOURCE_TYPES:
                forwarding_rules.append(resource)
            elif resource.resource_type == GcpResourceType.COMPUTE_FIREWALL:
                firewalls.append(resource)
            elif resource.resource_type == GcpResourceType.COMPUTE_FIREWALL_POLICY_RULE:
                firewall_policy_rules.append(resource)
            elif resource.resource_type == GcpResourceType.COMPUTE_FIREWALL_POLICY_ASSOCIATION:
                firewall_policy_associations.append(resource)
            elif resource.resource_type == GcpResourceType.SERVICE_ACCOUNT:
                service_accounts.append(resource)
            elif resource.resource_type in GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES:
                service_account_iam_resources.append(resource)
            elif resource.resource_type == GcpResourceType.WORKLOAD_IDENTITY_POOL:
                workload_identity_pools.append(resource)
            elif resource.resource_type == GcpResourceType.WORKLOAD_IDENTITY_POOL_PROVIDER:
                workload_identity_pool_providers.append(resource)
            elif resource.resource_type in GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES:
                bucket_iam_resources.append(resource)
            elif resource.resource_type in GCP_SECRET_MANAGER_SECRET_IAM_RESOURCE_TYPES:
                secret_iam_resources.append(resource)
            elif resource.resource_type in GCP_PUBSUB_TOPIC_IAM_RESOURCE_TYPES:
                pubsub_topic_iam_resources.append(resource)
            elif resource.resource_type in GCP_PUBSUB_SUBSCRIPTION_IAM_RESOURCE_TYPES:
                pubsub_subscription_iam_resources.append(resource)
            elif resource.resource_type in GCP_BIGQUERY_DATASET_IAM_RESOURCE_TYPES:
                bigquery_dataset_iam_resources.append(resource)
            elif resource.resource_type in GCP_BIGQUERY_TABLE_IAM_RESOURCE_TYPES:
                bigquery_table_iam_resources.append(resource)
            elif resource.resource_type in GCP_KMS_CRYPTO_KEY_IAM_RESOURCE_TYPES:
                kms_crypto_key_iam_resources.append(resource)
            elif resource.resource_type in GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES:
                kms_key_ring_iam_resources.append(resource)
            elif resource.resource_type in GCP_CLOUD_RUN_IAM_RESOURCE_TYPES:
                cloud_run_iam_resources.append(resource)
            elif resource.resource_type in GCP_CLOUD_FUNCTION_IAM_RESOURCE_TYPES:
                cloud_function_iam_resources.append(resource)
            elif resource.resource_type in GCP_ARTIFACT_REGISTRY_REPOSITORY_IAM_RESOURCE_TYPES:
                artifact_registry_iam_resources.append(resource)

        frozen_resources_by_address = MappingProxyType(resources_by_address)
        reference_index = build_resource_reference_index(
            resource_tuple,
            references_for_resource=gcp_resource_references,
        )

        def view(resource_type: str) -> GcpResourceReferenceView:
            return GcpResourceReferenceView(
                _index=reference_index,
                _resources_by_address=frozen_resources_by_address,
                _resource_types=frozenset({resource_type}),
            )

        all_resources = GcpResourceReferenceView(
            _index=reference_index,
            _resources_by_address=frozen_resources_by_address,
        )
        return GcpResourceIndex(
            resources_by_reference=all_resources,
            network_references=build_gcp_network_reference_view(resource_tuple),
            subnetworks_by_reference=view(GcpResourceType.COMPUTE_SUBNETWORK),
            routers_by_reference=view(GcpResourceType.COMPUTE_ROUTER),
            forwarding_rules=tuple(forwarding_rules),
            routes=tuple(routes),
            router_nats=tuple(router_nats),
            firewalls=tuple(firewalls),
            firewall_policy_rules=tuple(firewall_policy_rules),
            firewall_policy_associations=tuple(firewall_policy_associations),
            bucket_iam_resources=tuple(bucket_iam_resources),
            secret_iam_resources=tuple(secret_iam_resources),
            pubsub_topic_iam_resources=tuple(pubsub_topic_iam_resources),
            pubsub_subscription_iam_resources=tuple(pubsub_subscription_iam_resources),
            bigquery_dataset_iam_resources=tuple(bigquery_dataset_iam_resources),
            bigquery_table_iam_resources=tuple(bigquery_table_iam_resources),
            kms_crypto_key_iam_resources=tuple(kms_crypto_key_iam_resources),
            kms_key_ring_iam_resources=tuple(kms_key_ring_iam_resources),
            cloud_run_iam_resources=tuple(cloud_run_iam_resources),
            cloud_function_iam_resources=tuple(cloud_function_iam_resources),
            artifact_registry_iam_resources=tuple(artifact_registry_iam_resources),
            service_accounts=tuple(service_accounts),
            service_account_iam_resources=tuple(service_account_iam_resources),
            workload_identity_pools=tuple(workload_identity_pools),
            workload_identity_pool_providers=tuple(workload_identity_pool_providers),
        )


def build_gcp_network_reference_view(
    resources: Iterable[NormalizedResource],
) -> GcpNetworkReferenceView:
    network_resources = tuple(
        resource for resource in resources if resource.resource_type == GcpResourceType.COMPUTE_NETWORK
    )
    resources_by_address = MappingProxyType({resource.address: resource for resource in network_resources})
    reference_index = build_resource_reference_index(
        network_resources,
        references_for_resource=_gcp_network_references,
    )
    return GcpNetworkReferenceView(
        GcpResourceReferenceView(
            _index=reference_index,
            _resources_by_address=resources_by_address,
            _resource_types=frozenset({GcpResourceType.COMPUTE_NETWORK}),
        )
    )


def gcp_resource_references(resource: NormalizedResource) -> tuple[str, ...]:
    references = {
        resource.address,
        f"{resource.address}.id",
        f"{resource.address}.name",
    }
    kms_key_ring = resource.get_metadata_field(GcpResourceMetadata.KMS_KEY_RING)
    kms_key_name = resource.get_metadata_field(GcpResourceMetadata.NAME)
    canonical_kms_key = (
        f"{kms_key_ring}/cryptoKeys/{kms_key_name}"
        if resource.resource_type == GcpResourceType.KMS_CRYPTO_KEY and kms_key_ring and kms_key_name
        else None
    )
    parent_references = (
        (
            resource.get_metadata_field(GcpResourceMetadata.KMS_CRYPTO_KEY_REFERENCE),
            resource.get_metadata_field(GcpResourceMetadata.KMS_KEY_RING),
        )
        if resource.resource_type != GcpResourceType.KMS_CRYPTO_KEY_VERSION
        else ()
    )
    for reference in (
        resource.identifier,
        canonical_kms_key,
        resource.get_metadata_field(GcpResourceMetadata.NAME),
        resource.get_metadata_field(GcpResourceMetadata.BUCKET_NAME),
        resource.get_metadata_field(GcpResourceMetadata.SECRET_ID),
        resource.get_metadata_field(GcpResourceMetadata.SECRET_REFERENCE),
        resource.get_metadata_field(GcpResourceMetadata.SECRET_MANAGER_VERSION_REFERENCE),
        resource.get_metadata_field(GcpResourceMetadata.SECRET_MANAGER_VERSION_SECRET_REFERENCE),
        resource.get_metadata_field(GcpResourceMetadata.PUBSUB_TOPIC_REFERENCE),
        resource.get_metadata_field(GcpResourceMetadata.PUBSUB_SUBSCRIPTION_REFERENCE),
        resource.get_metadata_field(GcpResourceMetadata.BIGQUERY_DATASET_ID),
        resource.get_metadata_field(GcpResourceMetadata.BIGQUERY_DATASET_REFERENCE),
        resource.get_metadata_field(GcpResourceMetadata.BIGQUERY_TABLE_ID),
        resource.get_metadata_field(GcpResourceMetadata.BIGQUERY_TABLE_REFERENCE),
        *parent_references,
        resource.get_metadata_field(GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_REFERENCE),
        resource.get_metadata_field(GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_NAME),
        resource.get_metadata_field(GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE),
        resource.get_metadata_field(GcpResourceMetadata.CLOUD_FUNCTION_REFERENCE),
        resource.get_metadata_field(GcpResourceMetadata.SELF_LINK),
        resource.get_metadata_field(GcpResourceMetadata.ARTIFACT_REGISTRY_REPOSITORY_PATH),
    ):
        if reference:
            references.add(reference)
    return tuple(sorted(_gcp_reference_key(reference) for reference in references if reference))


def gcp_network_reference_key(value: str) -> str:
    text = _gcp_reference_key(value)
    for marker in ("/global/networks/", "/networks/"):
        if marker in text:
            return text.rsplit(marker, 1)[-1]
    return text


def _gcp_reference_key(reference: str) -> str:
    return gcp_reference_key(reference, GCP_NETWORK_REFERENCE_SUFFIXES)


def _unmodeled_network_reference_key(
    reference: str,
    source: NormalizedResource | None,
) -> str | None:
    reference_key = _gcp_reference_key(reference)
    if is_gcp_terraform_resource_address(reference_key):
        return reference_key

    explicit_project, _location = _scope_from_reference(reference_key)
    project = normalize_gcp_project(explicit_project)
    if project is None and source is not None:
        project = _resource_project(source)
    network_name = gcp_network_reference_key(reference_key)
    if project is None or not network_name:
        return None
    return f"projects/{project}/global/networks/{network_name}"


def _gcp_network_references(resource: NormalizedResource) -> tuple[str, ...]:
    references: set[str] = set()
    for reference in gcp_resource_references(resource):
        references.add(reference)
        references.add(gcp_network_reference_key(reference))
    return tuple(sorted(references))


def _gcp_reference_is_strong_for_candidate(
    reference: str,
    candidate: NormalizedResource,
) -> bool:
    key = _gcp_reference_key(reference)
    if key == candidate.address:
        return True
    if candidate.resource_type == GcpResourceType.STORAGE_BUCKET:
        bucket_name = candidate.get_metadata_field(GcpResourceMetadata.BUCKET_NAME)
        if key in {candidate.identifier, bucket_name}:
            return True
    if _scope_from_reference(key) == (None, None):
        return False
    return key in gcp_resource_references(candidate)


def _scope_candidates(
    candidates: tuple[NormalizedResource, ...],
    source: NormalizedResource | None,
) -> tuple[NormalizedResource, ...]:
    if source is None:
        return candidates
    project, location = _resource_scope(source)
    return _scope_candidates_for_values(
        candidates,
        project=project,
        location=location,
    )


def _scope_candidates_for_values(
    candidates: tuple[NormalizedResource, ...],
    *,
    project: str | None,
    location: str | None,
) -> tuple[NormalizedResource, ...]:
    if not candidates:
        return candidates
    if project is None:
        if any(_resource_project(candidate) is not None for candidate in candidates):
            return _ambiguity_only(candidates)
        scoped = candidates
    else:
        scoped = _candidates_in_scope(candidates, project, _resource_project)
    if not scoped:
        return ()
    all_candidates_are_location_scoped = all(
        candidate.resource_type in _GCP_LOCATION_SCOPED_RESOURCE_TYPES for candidate in scoped
    )
    if location is None and all_candidates_are_location_scoped:
        if all(_resource_location(candidate) is None for candidate in scoped):
            return scoped
        return _ambiguity_only(scoped)
    if location is None or not all_candidates_are_location_scoped:
        return scoped
    return _candidates_in_location_scope(scoped, location)


def _ambiguity_only(
    candidates: tuple[NormalizedResource, ...],
) -> tuple[NormalizedResource, ...]:
    """Retain collision evidence without resolving a weak reference."""

    return candidates if len(candidates) > 1 else ()


def _candidates_in_scope(
    candidates: tuple[NormalizedResource, ...],
    expected_scope: str | None,
    scope_for_resource: Callable[[NormalizedResource], str | None],
) -> tuple[NormalizedResource, ...]:
    if expected_scope is None:
        return candidates
    candidates_with_scope = tuple((candidate, scope_for_resource(candidate)) for candidate in candidates)
    if not any(scope == expected_scope for _candidate, scope in candidates_with_scope):
        return ()
    return tuple(candidate for candidate, scope in candidates_with_scope if scope is None or scope == expected_scope)


def _candidates_in_location_scope(
    candidates: tuple[NormalizedResource, ...],
    expected_location: str,
) -> tuple[NormalizedResource, ...]:
    candidates_with_location = tuple((candidate, _resource_location(candidate)) for candidate in candidates)
    if not any(
        _locations_are_compatible(location, expected_location) for _candidate, location in candidates_with_location
    ):
        return ()
    return tuple(
        candidate
        for candidate, location in candidates_with_location
        if location is None or _locations_are_compatible(location, expected_location)
    )


def _locations_are_compatible(left: str | None, right: str | None) -> bool:
    if left is None or right is None:
        return False
    if left == right:
        return True
    return _zone_region(left) == right or _zone_region(right) == left


def _zone_region(location: str) -> str | None:
    region, separator, zone = location.rpartition("-")
    if separator and len(zone) == 1 and zone.isalpha() and any(character.isdigit() for character in region):
        return region
    return None


def _resource_scope(resource: NormalizedResource) -> tuple[str | None, str | None]:
    return _resource_project(resource), _resource_location(resource)


def _resource_project(resource: NormalizedResource) -> str | None:
    project = normalize_gcp_project(resource.get_metadata_field(GcpResourceMetadata.PROJECT))
    if project is not None:
        return project
    for reference in _resource_scope_references(resource):
        project, _location = _scope_from_reference(reference)
        if project is not None:
            return project
    return None


def _resource_location(resource: NormalizedResource) -> str | None:
    for field in (GcpResourceMetadata.REGION, GcpResourceMetadata.ZONE):
        location = _plain_scope_value(resource.get_metadata_field(field))
        if location is not None:
            return location
    for reference in _resource_scope_references(resource):
        _project, location = _scope_from_reference(reference)
        if location is not None:
            return location
    return None


def _resource_scope_references(resource: NormalizedResource) -> tuple[str, ...]:
    return tuple(
        reference
        for reference in (
            resource.identifier,
            resource.get_metadata_field(GcpResourceMetadata.SELF_LINK),
            resource.get_metadata_field(GcpResourceMetadata.KMS_KEY_RING),
            resource.get_metadata_field(GcpResourceMetadata.KMS_CRYPTO_KEY_REFERENCE),
            resource.get_metadata_field(GcpResourceMetadata.KMS_CRYPTO_KEY_VERSION_REFERENCE),
            resource.get_metadata_field(GcpResourceMetadata.ARTIFACT_REGISTRY_REPOSITORY_PATH),
            resource.get_metadata_field(GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE),
            resource.get_metadata_field(GcpResourceMetadata.CLOUD_FUNCTION_REFERENCE),
        )
        if reference
    )


def _scope_from_reference(reference: str) -> tuple[str | None, str | None]:
    text = reference.strip()
    project_match = _PROJECT_PATH_PATTERN.search(text)
    location_match = _LOCATION_PATH_PATTERN.search(text)
    location = location_match.group("location") if location_match else None
    if location is None and _GLOBAL_PATH_PATTERN.search(text):
        location = "global"
    return (
        project_match.group("project") if project_match else None,
        location,
    )


def _plain_scope_value(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or "/" in text or "${" in text or text.startswith("google_"):
        return None
    return text
