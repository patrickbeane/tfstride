from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Protocol

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.constants import PUBLIC_GCP_IAM_MEMBERS
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_decoration.load_balancer import DeriveLoadBalancerReachabilityStage
from tfstride.providers.gcp.resource_index import (
    GcpDecorationContext,
    GcpResourceIndex,
    gcp_network_reference_key,
    gcp_resource_references,
)
from tfstride.providers.gcp.resource_mutations import gcp_mutations
from tfstride.providers.gcp.resource_types import (
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    GCP_FORWARDING_RULE_RESOURCE_TYPES,
    GCP_SERVERLESS_WORKLOAD_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.gcp.resource_utils import (
    GCP_NETWORK_REFERENCE_SUFFIXES,
    binding_members,
    dedupe,
    gcp_reference_key,
)
from tfstride.resource_helpers import describe_security_group_rule


class GcpDecorationStage(Protocol):
    name: str

    def apply(self, resources: list[NormalizedResource], context: GcpDecorationContext) -> None:
        """Apply one ordered GCP resource decoration step."""
        ...


class DeriveNetworkPostureStage:
    name = "derive_network_posture"

    def apply(self, resources: list[NormalizedResource], context: GcpDecorationContext) -> None:
        index = context.index
        for resource in resources:
            if resource.resource_type == GcpResourceType.COMPUTE_SUBNETWORK:
                _derive_subnetwork_route_posture(resource, index)

        for resource in resources:
            is_network_posture_resource = (
                resource.resource_type == GcpResourceType.COMPUTE_INSTANCE
                or resource.resource_type in GCP_FORWARDING_RULE_RESOURCE_TYPES
            )
            if not is_network_posture_resource:
                continue
            _infer_instance_vpc_id(resource, index)
            _derive_instance_network_posture(resource, index)


class DerivePublicExposureStage:
    name = "derive_public_exposure"

    def apply(self, resources: list[NormalizedResource], context: GcpDecorationContext) -> None:
        index = context.index
        for resource in resources:
            if resource.resource_type == GcpResourceType.COMPUTE_INSTANCE:
                _derive_public_compute_exposure(resource, index)
            elif resource.resource_type in GCP_SERVERLESS_WORKLOAD_RESOURCE_TYPES:
                _derive_public_serverless_exposure(resource, index)
            elif resource.resource_type == GcpResourceType.STORAGE_BUCKET:
                _derive_public_bucket_exposure(resource, index)


class DecorateSensitiveIamBindingsStage:
    name = "decorate_sensitive_iam_bindings"

    def apply(self, resources: list[NormalizedResource], context: GcpDecorationContext) -> None:
        index = context.index
        for resource in resources:
            if resource.resource_type in GCP_SERVERLESS_WORKLOAD_RESOURCE_TYPES:
                _derive_sensitive_resource_iam_bindings(
                    resource,
                    _serverless_iam_resources(resource, index),
                )
            elif resource.resource_type == GcpResourceType.SECRET_MANAGER_SECRET:
                _derive_sensitive_resource_iam_bindings(resource, index.secret_iam_resources)
            elif resource.resource_type == GcpResourceType.PUBSUB_TOPIC:
                _derive_sensitive_resource_iam_bindings(resource, index.pubsub_topic_iam_resources)
            elif resource.resource_type == GcpResourceType.PUBSUB_SUBSCRIPTION:
                _derive_sensitive_resource_iam_bindings(resource, index.pubsub_subscription_iam_resources)
            elif resource.resource_type == GcpResourceType.BIGQUERY_DATASET:
                _derive_sensitive_resource_iam_bindings(resource, index.bigquery_dataset_iam_resources)
            elif resource.resource_type == GcpResourceType.BIGQUERY_TABLE:
                _derive_sensitive_resource_iam_bindings(resource, index.bigquery_table_iam_resources)
            elif resource.resource_type == GcpResourceType.KMS_CRYPTO_KEY:
                _derive_sensitive_resource_iam_bindings(
                    resource,
                    index.kms_crypto_key_iam_resources + index.kms_key_ring_iam_resources,
                )
            elif resource.resource_type == GcpResourceType.STORAGE_BUCKET:
                _derive_sensitive_resource_iam_bindings(resource, index.bucket_iam_resources)


def default_gcp_decoration_stages() -> tuple[GcpDecorationStage, ...]:
    return (
        DeriveLoadBalancerReachabilityStage(),
        DeriveNetworkPostureStage(),
        DerivePublicExposureStage(),
        DecorateSensitiveIamBindingsStage(),
    )


_GCP_NETWORK_NAME_PATTERN = re.compile(r"^[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$")
_TERRAFORM_REFERENCE_TOKEN_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_[]\"-"
)


_SERVERLESS_PUBLIC_INVOKER_ROLES = frozenset({"roles/run.invoker", "roles/cloudfunctions.invoker"})


def _derive_subnetwork_route_posture(subnetwork: NormalizedResource, index: GcpResourceIndex) -> None:
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
    gcp_mutations(subnetwork).set_subnetwork_route_posture(
        has_public_route=has_public_route,
        has_nat_gateway_egress=has_nat_egress,
    )


def _derive_instance_network_posture(resource: NormalizedResource, index: GcpResourceIndex) -> None:
    subnetworks = _resource_subnetworks(resource, index)
    in_public_subnet = any(subnetwork.is_public_subnet for subnetwork in subnetworks)
    has_nat_gateway_egress = any(subnetwork.has_nat_gateway_egress for subnetwork in subnetworks)
    has_public_route = in_public_subnet or any(
        _route_has_internet_gateway(route)
        and _route_tags_apply_to_instance(route, resource)
        and _resource_has_network_reference(resource, route.vpc_id, index)
        for route in index.routes
    )
    gcp_mutations(resource).set_instance_network_posture(
        in_public_subnet=in_public_subnet,
        has_nat_gateway_egress=has_nat_gateway_egress,
        has_public_route=has_public_route,
    )


def _resource_subnetworks(resource: NormalizedResource, index: GcpResourceIndex) -> list[NormalizedResource]:
    subnetworks: list[NormalizedResource] = []
    seen: set[str] = set()
    for subnet_reference in resource.subnet_ids:
        subnetwork = index.subnetworks_by_reference.get(
            gcp_reference_key(subnet_reference, GCP_NETWORK_REFERENCE_SUFFIXES)
        )
        if subnetwork is None or subnetwork.address in seen:
            continue
        subnetworks.append(subnetwork)
        seen.add(subnetwork.address)
    return subnetworks


def _infer_instance_vpc_id(resource: NormalizedResource, index: GcpResourceIndex) -> None:
    if resource.vpc_id:
        return
    subnet_network_reference = _unique_network_reference(_subnetwork_vpc_references(resource, index), index)
    if gcp_mutations(resource).infer_vpc_id(subnet_network_reference):
        return
    network_reference = _unique_network_reference(_instance_network_references(resource), index)
    gcp_mutations(resource).infer_vpc_id(network_reference)


def _subnetwork_vpc_references(resource: NormalizedResource, index: GcpResourceIndex) -> list[str]:
    references: list[str] = []
    for subnet_reference in resource.subnet_ids:
        subnetwork = index.subnetworks_by_reference.get(
            gcp_reference_key(subnet_reference, GCP_NETWORK_REFERENCE_SUFFIXES)
        )
        if subnetwork is None:
            continue
        network_reference = _validated_network_reference(subnetwork.vpc_id)
        if network_reference is not None:
            references.append(network_reference)
    return references


def _instance_network_references(resource: NormalizedResource) -> list[str]:
    references: list[str] = []
    for interface in resource.get_metadata_field(GcpResourceMetadata.NETWORK_INTERFACES):
        if not isinstance(interface, Mapping):
            continue
        network = interface.get("network")
        if network in (None, ""):
            continue
        network_reference = _validated_network_reference(network)
        if network_reference is not None:
            references.append(network_reference)
    return dedupe(references)


def _unique_network_reference(references: list[str], index: GcpResourceIndex) -> str | None:
    inferred_reference: str | None = None
    inferred_canonical_reference: str | None = None
    for reference in references:
        canonical_reference = _canonical_network_reference(reference, index)
        if inferred_reference is None:
            inferred_reference = reference
            inferred_canonical_reference = canonical_reference
            continue
        if canonical_reference != inferred_canonical_reference:
            return None
    return inferred_reference


def _resource_has_network_reference(
    resource: NormalizedResource,
    network_reference: str | None,
    index: GcpResourceIndex,
) -> bool:
    return any(
        _same_network_reference(candidate, network_reference, index)
        for candidate in _resource_network_references(resource, index)
    )


def _resource_network_references(resource: NormalizedResource, index: GcpResourceIndex) -> list[str]:
    references: list[str] = []
    direct_reference = _validated_network_reference(resource.vpc_id)
    if direct_reference is not None:
        references.append(direct_reference)
    references.extend(_subnetwork_vpc_references(resource, index))
    references.extend(_instance_network_references(resource))
    return dedupe(references)


def _derive_public_compute_exposure(resource: NormalizedResource, index: GcpResourceIndex) -> None:
    matching_firewalls = [
        firewall
        for firewall in index.firewalls
        if _firewall_applies_to_instance(firewall, resource, index)
        and _internet_ingress_reasons(firewall)
    ]
    matching_policy_rules = [
        policy_rule
        for policy_rule in index.firewall_policy_rules
        if _firewall_policy_rule_applies_to_instance(policy_rule, resource, index)
        and _internet_ingress_reasons(policy_rule)
    ]
    ingress_sources = [*matching_firewalls, *matching_policy_rules]
    internet_ingress_reasons = [
        reason
        for firewall in ingress_sources
        for reason in _internet_ingress_reasons(firewall)
    ]
    gcp_mutations(resource).set_compute_internet_ingress(
        internet_ingress_reasons=internet_ingress_reasons,
        firewall_addresses=[firewall.address for firewall in ingress_sources],
    )

    public_exposure = bool(resource.public_access_configured and internet_ingress_reasons)
    gcp_mutations(resource).set_public_exposure(
        public_exposure,
        reasons=[
            "compute instance has an external access config and matching firewall rules allow internet ingress"
        ] if public_exposure else None,
    )


def _derive_public_bucket_exposure(bucket: NormalizedResource, index: GcpResourceIndex) -> None:
    public_access_reasons = _bucket_public_access_reasons(bucket, index)
    gcp_mutations(bucket).set_public_access(
        configured=bool(public_access_reasons),
        reasons=public_access_reasons,
    )

    public_exposure = bool(public_access_reasons) and not _public_access_prevention_enforced(bucket)
    gcp_mutations(bucket).set_public_exposure(
        public_exposure,
        reasons=public_access_reasons if public_exposure else None,
    )


def _derive_public_serverless_exposure(resource: NormalizedResource, index: GcpResourceIndex) -> None:
    public_access_reasons = _serverless_public_access_reasons(
        resource,
        _serverless_iam_resources(resource, index),
    )
    if public_access_reasons:
        gcp_mutations(resource).set_public_access_reasons(public_access_reasons)
    public_exposure = bool(resource.public_access_configured and public_access_reasons)
    gcp_mutations(resource).set_public_exposure(
        public_exposure,
        reasons=public_access_reasons if public_exposure else None,
    )


def _serverless_iam_resources(
    resource: NormalizedResource,
    index: GcpResourceIndex,
) -> tuple[NormalizedResource, ...]:
    return (
        index.cloud_run_iam_resources
        if resource.resource_type in GCP_CLOUD_RUN_RESOURCE_TYPES
        else index.cloud_function_iam_resources
    )


def _derive_sensitive_resource_iam_bindings(
    resource: NormalizedResource,
    iam_resources: tuple[NormalizedResource, ...],
) -> None:
    resource_references = set(gcp_resource_references(resource))
    bindings: list[dict[str, Any]] = []
    source_addresses: list[str] = []
    for iam_resource in iam_resources:
        target_reference = _resource_iam_target_reference(iam_resource)
        if (
            not target_reference
            or gcp_reference_key(target_reference, GCP_NETWORK_REFERENCE_SUFFIXES)
            not in resource_references
        ):
            continue
        for binding in _iam_bindings(iam_resource):
            decorated_binding = {
                "role": str(binding.get("role") or "unknown role"),
                "members": binding_members(binding),
                "source": iam_resource.address,
            }
            condition = binding.get("condition")
            if condition:
                decorated_binding["condition"] = condition
            bindings.append(decorated_binding)
            source_addresses.append(iam_resource.address)

    gcp_mutations(resource).set_sensitive_resource_iam_bindings(
        bindings=bindings,
        source_addresses=source_addresses,
    )


def _bucket_public_access_reasons(bucket: NormalizedResource, index: GcpResourceIndex) -> list[str]:
    reasons: list[str] = []
    bucket_references = set(gcp_resource_references(bucket))
    for iam_resource in index.bucket_iam_resources:
        iam_bucket = iam_resource.get_metadata_field(GcpResourceMetadata.BUCKET_NAME)
        if not iam_bucket or gcp_reference_key(iam_bucket, GCP_NETWORK_REFERENCE_SUFFIXES) not in bucket_references:
            continue
        for binding in _iam_bindings(iam_resource):
            role = str(binding.get("role") or "unknown role")
            public_members = sorted(
                member
                for member in binding_members(binding)
                if member in PUBLIC_GCP_IAM_MEMBERS
            )
            for member in public_members:
                reasons.append(f"{iam_resource.address} grants {role} to {member}")
    return dedupe(reasons)


def _serverless_public_access_reasons(
    resource: NormalizedResource,
    iam_resources: tuple[NormalizedResource, ...],
) -> list[str]:
    reasons: list[str] = []
    resource_references = set(gcp_resource_references(resource))
    for iam_resource in iam_resources:
        target_reference = _resource_iam_target_reference(iam_resource)
        if (
            not target_reference
            or gcp_reference_key(target_reference, GCP_NETWORK_REFERENCE_SUFFIXES)
            not in resource_references
        ):
            continue
        for binding in _iam_bindings(iam_resource):
            role = str(binding.get("role") or "unknown role")
            if role not in _SERVERLESS_PUBLIC_INVOKER_ROLES:
                continue
            public_members = sorted(
                member
                for member in binding_members(binding)
                if member in PUBLIC_GCP_IAM_MEMBERS
            )
            for member in public_members:
                reasons.append(f"{iam_resource.address} grants {role} to {member}")
    return dedupe(reasons)


def _resource_iam_target_reference(resource: NormalizedResource) -> str | None:
    bucket_name = resource.get_metadata_field(GcpResourceMetadata.BUCKET_NAME)
    if bucket_name:
        return bucket_name
    secret_reference = resource.get_metadata_field(GcpResourceMetadata.SECRET_REFERENCE)
    if secret_reference:
        return secret_reference
    pubsub_topic_reference = resource.get_metadata_field(GcpResourceMetadata.PUBSUB_TOPIC_REFERENCE)
    if pubsub_topic_reference:
        return pubsub_topic_reference
    pubsub_subscription_reference = resource.get_metadata_field(GcpResourceMetadata.PUBSUB_SUBSCRIPTION_REFERENCE)
    if pubsub_subscription_reference:
        return pubsub_subscription_reference
    bigquery_table_reference = resource.get_metadata_field(GcpResourceMetadata.BIGQUERY_TABLE_REFERENCE)
    if bigquery_table_reference:
        return bigquery_table_reference
    bigquery_dataset_reference = resource.get_metadata_field(GcpResourceMetadata.BIGQUERY_DATASET_REFERENCE)
    if bigquery_dataset_reference:
        return bigquery_dataset_reference
    cloud_run_reference = resource.get_metadata_field(GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE)
    if cloud_run_reference:
        return cloud_run_reference
    cloud_function_reference = resource.get_metadata_field(GcpResourceMetadata.CLOUD_FUNCTION_REFERENCE)
    if cloud_function_reference:
        return cloud_function_reference
    crypto_key_reference = resource.get_metadata_field(GcpResourceMetadata.KMS_CRYPTO_KEY_REFERENCE)
    if crypto_key_reference:
        return crypto_key_reference
    return resource.get_metadata_field(GcpResourceMetadata.KMS_KEY_RING)


def _iam_bindings(resource: NormalizedResource) -> list[dict[str, Any]]:
    bindings = resource.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS)
    if bindings:
        return bindings
    role = resource.get_metadata_field(GcpResourceMetadata.IAM_ROLE)
    member = resource.get_metadata_field(GcpResourceMetadata.IAM_MEMBER)
    if role and member:
        binding: dict[str, Any] = {"role": role, "members": [member]}
        condition = resource.get_metadata_field(GcpResourceMetadata.IAM_CONDITION)
        if condition:
            binding["condition"] = condition
        return [binding]
    return []


def _public_access_prevention_enforced(bucket: NormalizedResource) -> bool:
    value = bucket.get_metadata_field(GcpResourceMetadata.PUBLIC_ACCESS_PREVENTION)
    return value is not None and value.strip().lower() == "enforced"


def _firewall_applies_to_instance(
    firewall: NormalizedResource,
    instance: NormalizedResource,
    index: GcpResourceIndex,
) -> bool:
    if firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_DISABLED):
        return False
    firewall_direction = str(
        firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_DIRECTION) or "ingress"
    ).strip().lower()
    if firewall_direction != "ingress":
        return False
    if not _resource_has_network_reference(instance, firewall.vpc_id, index):
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


def _firewall_policy_rule_applies_to_instance(
    policy_rule: NormalizedResource,
    instance: NormalizedResource,
    index: GcpResourceIndex,
) -> bool:
    if policy_rule.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_DISABLED):
        return False
    policy_action = str(
        policy_rule.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_ACTION) or ""
    ).strip().lower()
    if policy_action != "allow":
        return False
    policy_direction = str(
        policy_rule.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_DIRECTION) or ""
    ).strip().lower()
    if policy_direction != "ingress":
        return False

    target_resources = policy_rule.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_TARGET_RESOURCES)
    target_resource_applies = bool(target_resources) and any(
        _resource_has_network_reference(instance, target_resource, index)
        for target_resource in target_resources
    )
    if target_resources and not target_resource_applies:
        return False

    target_service_accounts = _service_account_reference_keys(
        policy_rule.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_TARGET_SERVICE_ACCOUNTS)
    )
    if target_service_accounts and not target_service_accounts.intersection(
        _instance_service_account_keys(instance)
    ):
        return False

    associations = _firewall_policy_associations_for_rule(policy_rule, index)
    if not associations:
        return target_resource_applies
    return any(
        _firewall_policy_association_applies_to_instance(association, instance, index)
        for association in associations
    )


def _firewall_policy_associations_for_rule(
    policy_rule: NormalizedResource,
    index: GcpResourceIndex,
) -> tuple[NormalizedResource, ...]:
    policy_references = _firewall_policy_reference_keys(policy_rule, index)
    if not policy_references:
        return ()
    return tuple(
        association
        for association in index.firewall_policy_associations
        if policy_references.intersection(_firewall_policy_reference_keys(association, index))
    )


def _firewall_policy_association_applies_to_instance(
    association: NormalizedResource,
    instance: NormalizedResource,
    index: GcpResourceIndex,
) -> bool:
    target = association.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_ATTACHMENT_TARGET)
    if not target:
        return False
    if _resource_has_network_reference(instance, target, index):
        return True

    project = _project_from_scope_reference(target)
    if project and project == _resource_project(instance):
        return True

    folder_id = _hierarchy_id_from_scope_reference(target, "folders")
    if folder_id and folder_id == _resource_folder_id(instance):
        return True

    organization_id = _hierarchy_id_from_scope_reference(target, "organizations")
    if organization_id and organization_id == _resource_organization_id(instance):
        return True

    return False


def _firewall_policy_reference_keys(
    resource: NormalizedResource,
    index: GcpResourceIndex | None = None,
) -> set[str]:
    references = {
        resource.address,
        f"{resource.address}.id",
        f"{resource.address}.name",
    }
    for reference in (
        resource.identifier,
        resource.get_metadata_field(GcpResourceMetadata.NAME),
        resource.get_metadata_field(GcpResourceMetadata.SELF_LINK),
        resource.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_REFERENCE),
    ):
        if reference:
            references.add(reference)
    keys = {gcp_reference_key(str(reference)) for reference in references if str(reference).strip()}
    if index is None:
        return keys

    expanded_keys = set(keys)
    for key in keys:
        policy = index.resources_by_reference.get(key)
        if policy is None or policy.resource_type != GcpResourceType.COMPUTE_FIREWALL_POLICY:
            continue
        expanded_keys.update(_firewall_policy_reference_keys(policy))
    return expanded_keys


def _resource_project(resource: NormalizedResource) -> str | None:
    project = resource.get_metadata_field(GcpResourceMetadata.PROJECT)
    if project:
        return project
    for reference in (
        resource.identifier,
        resource.get_metadata_field(GcpResourceMetadata.SELF_LINK),
        resource.vpc_id,
    ):
        project = _project_from_scope_reference(reference)
        if project:
            return project
    return None


def _resource_folder_id(resource: NormalizedResource) -> str | None:
    folder_id = resource.get_metadata_field(GcpResourceMetadata.FOLDER_ID)
    if folder_id:
        return _normalize_hierarchy_id(folder_id, "folders")
    for reference in (resource.identifier, resource.get_metadata_field(GcpResourceMetadata.SELF_LINK)):
        folder_id = _hierarchy_id_from_scope_reference(reference, "folders")
        if folder_id:
            return folder_id
    return None


def _resource_organization_id(resource: NormalizedResource) -> str | None:
    organization_id = resource.get_metadata_field(GcpResourceMetadata.ORGANIZATION_ID)
    if organization_id:
        return _normalize_hierarchy_id(organization_id, "organizations")
    for reference in (resource.identifier, resource.get_metadata_field(GcpResourceMetadata.SELF_LINK)):
        organization_id = _hierarchy_id_from_scope_reference(reference, "organizations")
        if organization_id:
            return organization_id
    return None


def _project_from_scope_reference(value: object) -> str | None:
    text = str(value or "").strip().rstrip("/")
    if not text:
        return None
    parts = [part for part in text.split("/") if part]
    for index, part in enumerate(parts[:-1]):
        if part == "projects":
            return parts[index + 1] or None
    return None


def _hierarchy_id_from_scope_reference(value: object, marker: str) -> str | None:
    text = str(value or "").strip().rstrip("/")
    if not text:
        return None
    parts = [part for part in text.split("/") if part]
    for index, part in enumerate(parts[:-1]):
        if part == marker:
            return _normalize_hierarchy_id(parts[index + 1], marker)
    return _normalize_hierarchy_id(text, marker) if text.startswith(f"{marker}/") else None


def _normalize_hierarchy_id(value: str | None, marker: str) -> str | None:
    text = str(value or "").strip().rstrip("/")
    if not text:
        return None
    prefix = f"{marker}/"
    if text.startswith(prefix):
        return text.removeprefix(prefix) or None
    return text


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
    index: GcpResourceIndex,
) -> bool:
    source_mode = str(router_nat.metadata.get("source_subnetwork_ip_ranges_to_nat") or "").upper()
    if source_mode.startswith("ALL_SUBNETWORKS"):
        return any(
            _same_network_reference(network_reference, subnetwork.vpc_id, index)
            for network_reference in _router_nat_network_references(router_nat, index)
        )

    subnetwork_references = set(gcp_resource_references(subnetwork))
    for nat_subnetwork in router_nat.get_metadata_field(GcpResourceMetadata.NAT_SUBNETWORKS):
        reference = nat_subnetwork.get("name") if isinstance(nat_subnetwork, dict) else None
        if reference and gcp_reference_key(str(reference), GCP_NETWORK_REFERENCE_SUFFIXES) in subnetwork_references:
            return True
    return False


def _router_nat_network_references(
    router_nat: NormalizedResource,
    index: GcpResourceIndex,
) -> tuple[str, ...]:
    router_reference = router_nat.get_metadata_field(GcpResourceMetadata.ROUTER_REFERENCE)
    if not router_reference:
        return ()
    router = index.routers_by_reference.get(gcp_reference_key(router_reference, GCP_NETWORK_REFERENCE_SUFFIXES))
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


def _same_network_reference(
    left: str | None,
    right: str | None,
    index: GcpResourceIndex | None = None,
) -> bool:
    if not left or not right:
        return False
    return _canonical_network_reference(left, index) == _canonical_network_reference(right, index)


def _canonical_network_reference(value: str, index: GcpResourceIndex | None) -> str:
    reference_key = gcp_reference_key(value, GCP_NETWORK_REFERENCE_SUFFIXES)
    network_key = gcp_network_reference_key(value)
    if index is not None:
        return (
            index.network_references.get(reference_key)
            or index.network_references.get(network_key)
            or network_key
        )
    return network_key


def _validated_network_reference(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or any(character.isspace() for character in text):
        return None
    network_key = gcp_network_reference_key(text)
    if _GCP_NETWORK_NAME_PATTERN.fullmatch(network_key):
        return text
    reference_key = gcp_reference_key(text, GCP_NETWORK_REFERENCE_SUFFIXES)
    if _is_terraform_network_reference(reference_key):
        return text
    return None


def _is_terraform_network_reference(value: str) -> bool:
    parts = value.split(".")
    for index, part in enumerate(parts[:-1]):
        if part != GcpResourceType.COMPUTE_NETWORK:
            continue
        resource_name = parts[index + 1]
        return bool(resource_name) and all(
            token and set(token) <= _TERRAFORM_REFERENCE_TOKEN_CHARS for token in parts
        )
    return False