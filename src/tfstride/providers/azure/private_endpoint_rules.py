from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.azure.private_endpoint_index import (
    AzurePrivateEndpointConnection,
    build_azure_private_endpoint_index,
)
from tfstride.providers.azure.public_network import (
    PUBLIC_NETWORK_FALLBACK_DISABLED,
    PUBLIC_NETWORK_FALLBACK_ENABLED,
    PUBLIC_NETWORK_FALLBACK_UNKNOWN,
)
from tfstride.providers.azure.resource_facts import AzureResourceFacts, azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.resource_utils import azure_reference_key, azure_resource_references

_PRIVATE_ENDPOINT_TARGET_TYPES = (
    AzureResourceType.STORAGE_ACCOUNT,
    AzureResourceType.KEY_VAULT,
    AzureResourceType.MSSQL_SERVER,
)
_STATE_CONFIGURED = "configured"
_STATE_NOT_CONFIGURED = "not_configured"
_STATE_UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class _PrivateDnsZoneLink:
    address: str
    zone_reference: str | None
    virtual_network_reference: str | None
    virtual_network_keys: tuple[str, ...]


class AzurePrivateEndpointPostureRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_storage_account_missing_private_endpoint(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_missing_private_endpoint(
            context,
            rule_id,
            resource_type=AzureResourceType.STORAGE_ACCOUNT,
            rationale=lambda resource: (
                f"{resource.display_name} does not have a resolved private endpoint and may remain reachable "
                "through public Azure Storage data-plane endpoints. Network rules can reduce exposure, but they "
                "are not equivalent to private-endpoint-only access unless public network fallback is disabled."
            ),
        )

    def detect_key_vault_missing_private_endpoint(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_missing_private_endpoint(
            context,
            rule_id,
            resource_type=AzureResourceType.KEY_VAULT,
            rationale=lambda resource: (
                f"{resource.display_name} does not have a resolved private endpoint and may allow public "
                "Key Vault data-plane access depending on firewall settings. This finding does not claim "
                "secret exposure; identity authorization is evaluated separately."
            ),
        )

    def detect_sql_server_missing_private_endpoint(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_missing_private_endpoint(
            context,
            rule_id,
            resource_type=AzureResourceType.MSSQL_SERVER,
            rationale=lambda resource: (
                f"{resource.display_name} does not have a resolved private endpoint and may expose database "
                "access through public Azure SQL endpoints when public network fallback is enabled or unknown."
            ),
        )

    def detect_private_endpoint_public_fallback(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        index = build_azure_private_endpoint_index(context.inventory)
        findings: list[Finding] = []
        for resource in context.inventory.by_type(*_PRIVATE_ENDPOINT_TARGET_TYPES):
            facts = azure_facts(resource)
            if facts.public_network_fallback_state == PUBLIC_NETWORK_FALLBACK_DISABLED:
                continue
            coverage = index.coverage_for(resource)
            if not coverage.has_private_endpoint:
                continue
            severity_reasoning = _private_endpoint_posture_severity(
                facts,
                has_private_endpoint=True,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses([resource.address, *coverage.private_endpoint_addresses]),
                    trust_boundary_id=None,
                    rationale=(
                        f"{resource.display_name} has a resolved private endpoint, but public network access is "
                        "still enabled or not explicitly disabled. Private Endpoint coverage does not guarantee "
                        "private-only access while public network fallback remains enabled or unknown."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(resource)),
                        evidence_item("public_network_fallback", _public_network_fallback_evidence(facts)),
                        evidence_item("private_endpoints", list(coverage.private_endpoint_addresses)),
                        evidence_item("private_endpoint_subresources", list(coverage.subresource_names)),
                        evidence_item("network_acl_posture", _network_acl_evidence(facts)),
                        evidence_item("fallback_uncertainty", _fallback_uncertainty_evidence(resource, facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_private_endpoint_dns_posture_incomplete(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        resources = tuple(context.inventory.resources)
        resource_by_reference = _resources_by_reference(resources)
        endpoint_by_address = {
            resource.address: resource
            for resource in resources
            if resource.resource_type == AzureResourceType.PRIVATE_ENDPOINT
        }
        links_by_zone_key = _private_dns_zone_links_by_zone_key(resources, resource_by_reference)
        index = build_azure_private_endpoint_index(context.inventory)
        severity_reasoning = _private_endpoint_dns_posture_severity()
        findings: list[Finding] = []

        for resource in context.inventory.by_type(*_PRIVATE_ENDPOINT_TARGET_TYPES):
            coverage = index.coverage_for(resource)
            if not coverage.has_private_endpoint:
                continue

            posture_evidence: list[str] = []
            dns_state_evidence: list[str] = []
            zone_group_evidence: list[str] = []
            link_evidence: list[str] = []
            endpoint_network_evidence: list[str] = []
            affected_resources = [resource.address]

            for connection in coverage.connections:
                endpoint = endpoint_by_address.get(connection.private_endpoint_address)
                (
                    connection_posture,
                    connection_state,
                    connection_links,
                    connection_network,
                ) = _private_endpoint_dns_posture_evidence(
                    connection,
                    endpoint,
                    links_by_zone_key,
                    resource_by_reference,
                )
                if not connection_posture:
                    continue
                affected_resources.append(connection.private_endpoint_address)
                posture_evidence.extend(connection_posture)
                dns_state_evidence.extend(connection_state)
                zone_group_evidence.extend(_private_dns_zone_group_evidence(connection))
                link_evidence.extend(connection_links)
                endpoint_network_evidence.extend(connection_network)

            if not posture_evidence:
                continue

            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(affected_resources),
                    trust_boundary_id=None,
                    rationale=(
                        f"{resource.display_name} has resolved Private Endpoint coverage, but one or more "
                        "Private Endpoints do not have complete private DNS posture represented in the Terraform "
                        "plan. Missing or unresolved Private DNS zone groups, or modeled zone links that do not "
                        "target the endpoint VNet, can leave clients relying on public service endpoints or manual "
                        "DNS configuration. This finding does not validate live DNS records."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(resource)),
                        evidence_item("private_endpoint_dns_posture", posture_evidence),
                        evidence_item("private_endpoint_dns_state", dns_state_evidence),
                        evidence_item("private_dns_zone_groups", zone_group_evidence),
                        evidence_item("private_dns_zone_links", link_evidence),
                        evidence_item("endpoint_network", endpoint_network_evidence),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def _detect_missing_private_endpoint(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
        *,
        resource_type: str,
        rationale: Callable[[NormalizedResource], str],
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        index = build_azure_private_endpoint_index(context.inventory)
        findings: list[Finding] = []
        for resource in context.inventory.by_type(resource_type):
            facts = azure_facts(resource)
            if facts.public_network_fallback_state == PUBLIC_NETWORK_FALLBACK_DISABLED:
                continue
            coverage = index.coverage_for(resource)
            if coverage.has_private_endpoint:
                continue
            severity_reasoning = _private_endpoint_posture_severity(
                facts,
                has_private_endpoint=False,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[resource.address],
                    trust_boundary_id=None,
                    rationale=rationale(resource),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(resource)),
                        evidence_item("public_network_fallback", _public_network_fallback_evidence(facts)),
                        evidence_item(
                            "private_endpoint_coverage",
                            ["no resolved private endpoint targets this resource"],
                        ),
                        evidence_item("network_acl_posture", _network_acl_evidence(facts)),
                        evidence_item("fallback_uncertainty", _fallback_uncertainty_evidence(resource, facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _private_endpoint_dns_posture_evidence(
    connection: AzurePrivateEndpointConnection,
    endpoint: NormalizedResource | None,
    links_by_zone_key: Mapping[str, tuple[_PrivateDnsZoneLink, ...]],
    resource_by_reference: Mapping[str, NormalizedResource],
) -> tuple[list[str], list[str], list[str], list[str]]:
    posture = _private_dns_zone_state_posture(connection)
    state_evidence = _private_dns_state_evidence(connection)
    link_evidence: list[str] = []
    network_evidence: list[str] = []

    link_gap, modeled_links, endpoint_network = _private_dns_zone_link_gap_evidence(
        connection,
        endpoint,
        links_by_zone_key,
        resource_by_reference,
    )
    posture.extend(link_gap)
    link_evidence.extend(modeled_links)
    network_evidence.extend(endpoint_network)
    return posture, state_evidence, link_evidence, network_evidence


def _private_dns_zone_state_posture(connection: AzurePrivateEndpointConnection) -> list[str]:
    address = connection.private_endpoint_address
    group_state = connection.private_dns_zone_group_state
    zone_ids_state = connection.private_dns_zone_ids_state

    if group_state == _STATE_NOT_CONFIGURED:
        return [f"{address}: no private_dns_zone_group blocks are represented"]
    if group_state == _STATE_UNKNOWN:
        return _private_dns_uncertainty_posture(connection) or [f"{address}: private_dns_zone_group state is unknown"]
    if zone_ids_state == _STATE_NOT_CONFIGURED:
        return [f"{address}: private_dns_zone_group does not include private_dns_zone_ids"]
    if zone_ids_state == _STATE_UNKNOWN:
        return _private_dns_uncertainty_posture(connection) or [f"{address}: private_dns_zone_ids state is unknown"]

    # Backward-compatible inference for manually constructed resources that predate the explicit DNS state facts.
    if group_state is None and zone_ids_state is None:
        return _legacy_private_dns_zone_posture(connection)
    return _private_dns_uncertainty_posture(connection)


def _legacy_private_dns_zone_posture(connection: AzurePrivateEndpointConnection) -> list[str]:
    if (
        not connection.private_dns_zone_group_names
        and not connection.private_dns_zone_ids
        and not connection.private_dns_zone_uncertainties
    ):
        return [f"{connection.private_endpoint_address}: no private_dns_zone_group blocks are represented"]
    if (
        connection.private_dns_zone_group_names
        and not connection.private_dns_zone_ids
        and not connection.private_dns_zone_uncertainties
    ):
        return [f"{connection.private_endpoint_address}: private_dns_zone_group does not include private_dns_zone_ids"]
    return _private_dns_uncertainty_posture(connection)


def _private_dns_uncertainty_posture(connection: AzurePrivateEndpointConnection) -> list[str]:
    return [
        f"{connection.private_endpoint_address}: {uncertainty}"
        for uncertainty in connection.private_dns_zone_uncertainties
    ]


def _private_dns_state_evidence(connection: AzurePrivateEndpointConnection) -> list[str]:
    return [
        f"{connection.private_endpoint_address}: private_dns_zone_group_state="
        f"{connection.private_dns_zone_group_state or 'unknown'}",
        f"{connection.private_endpoint_address}: private_dns_zone_ids_state="
        f"{connection.private_dns_zone_ids_state or 'unknown'}",
    ]


def _private_dns_zone_link_gap_evidence(
    connection: AzurePrivateEndpointConnection,
    endpoint: NormalizedResource | None,
    links_by_zone_key: Mapping[str, tuple[_PrivateDnsZoneLink, ...]],
    resource_by_reference: Mapping[str, NormalizedResource],
) -> tuple[list[str], list[str], list[str]]:
    if endpoint is None or not connection.private_dns_zone_ids:
        return [], [], []

    endpoint_vnet_keys, endpoint_network_evidence = _endpoint_virtual_network_keys(endpoint, resource_by_reference)
    if not endpoint_vnet_keys:
        return [], [], endpoint_network_evidence

    zone_keys = _expanded_reference_keys(connection.private_dns_zone_ids, resource_by_reference)
    relevant_links = _dedupe_links(link for zone_key in zone_keys for link in links_by_zone_key.get(zone_key, ()))
    known_vnet_links = tuple(link for link in relevant_links if link.virtual_network_keys)
    modeled_link_evidence = _private_dns_zone_link_evidence(relevant_links)
    if not known_vnet_links:
        return [], modeled_link_evidence, endpoint_network_evidence
    if any(_overlaps(link.virtual_network_keys, endpoint_vnet_keys) for link in known_vnet_links):
        return [], modeled_link_evidence, endpoint_network_evidence
    return (
        [
            f"{connection.private_endpoint_address}: private DNS zone links are modeled for the endpoint zones "
            "but none target the endpoint VNet"
        ],
        modeled_link_evidence,
        endpoint_network_evidence,
    )


def _private_dns_zone_group_evidence(connection: AzurePrivateEndpointConnection) -> list[str]:
    values: list[str] = []
    if connection.private_dns_zone_group_names:
        values.append(
            f"{connection.private_endpoint_address}: group_names={', '.join(connection.private_dns_zone_group_names)}"
        )
    if connection.private_dns_zone_ids:
        values.append(f"{connection.private_endpoint_address}: zone_ids={', '.join(connection.private_dns_zone_ids)}")
    return values


def _private_endpoint_dns_posture_severity():
    return build_severity_reasoning(
        internet_exposure=False,
        privilege_breadth=0,
        data_sensitivity=1,
        lateral_movement=0,
        blast_radius=1,
    )


def _resources_by_reference(resources: Iterable[NormalizedResource]) -> dict[str, NormalizedResource]:
    resources_by_reference: dict[str, NormalizedResource] = {}
    for resource in resources:
        for reference in azure_resource_references(resource):
            resources_by_reference.setdefault(reference, resource)
    return resources_by_reference


def _private_dns_zone_links_by_zone_key(
    resources: Iterable[NormalizedResource],
    resource_by_reference: Mapping[str, NormalizedResource],
) -> dict[str, tuple[_PrivateDnsZoneLink, ...]]:
    links_by_zone_key: dict[str, list[_PrivateDnsZoneLink]] = {}
    for resource in resources:
        if resource.resource_type != AzureResourceType.PRIVATE_DNS_ZONE_VIRTUAL_NETWORK_LINK:
            continue
        facts = azure_facts(resource)
        zone_keys = _expanded_reference_keys([facts.private_dns_zone_reference], resource_by_reference)
        if not zone_keys:
            continue
        link = _PrivateDnsZoneLink(
            address=resource.address,
            zone_reference=facts.private_dns_zone_reference,
            virtual_network_reference=facts.private_dns_zone_virtual_network_reference,
            virtual_network_keys=_expanded_reference_keys(
                [facts.private_dns_zone_virtual_network_reference],
                resource_by_reference,
            ),
        )
        for zone_key in zone_keys:
            links_by_zone_key.setdefault(zone_key, []).append(link)
    return {zone_key: tuple(links) for zone_key, links in links_by_zone_key.items()}


def _endpoint_virtual_network_keys(
    endpoint: NormalizedResource,
    resource_by_reference: Mapping[str, NormalizedResource],
) -> tuple[tuple[str, ...], list[str]]:
    references: list[str] = []
    evidence: list[str] = []
    if endpoint.vpc_id:
        references.append(endpoint.vpc_id)
        evidence.append(f"{endpoint.address}: vnet={endpoint.vpc_id}")
    for subnet_reference in endpoint.subnet_ids:
        evidence.append(f"{endpoint.address}: subnet={subnet_reference}")
        subnet = resource_by_reference.get(azure_reference_key(subnet_reference))
        if subnet is None:
            continue
        subnet_facts = azure_facts(subnet)
        for virtual_network_reference in (subnet.vpc_id, subnet_facts.virtual_network_reference):
            if virtual_network_reference:
                references.append(virtual_network_reference)
                evidence.append(f"{endpoint.address}: endpoint_vnet={virtual_network_reference}")
    return _expanded_reference_keys(references, resource_by_reference), _dedupe_strings(evidence)


def _expanded_reference_keys(
    references: Iterable[str | None],
    resource_by_reference: Mapping[str, NormalizedResource],
) -> tuple[str, ...]:
    keys: list[str] = []
    for reference in references:
        reference_key = azure_reference_key(reference)
        if not reference_key:
            continue
        keys.append(reference_key)
        resolved_resource = resource_by_reference.get(reference_key)
        if resolved_resource is not None:
            keys.extend(azure_resource_references(resolved_resource))
    return _dedupe_strings(keys)


def _private_dns_zone_link_evidence(links: Iterable[_PrivateDnsZoneLink]) -> list[str]:
    return _dedupe_strings(
        f"{link.address}: zone={link.zone_reference or 'unknown'}; "
        f"virtual_network={link.virtual_network_reference or 'unknown'}"
        for link in links
    )


def _dedupe_links(links: Iterable[_PrivateDnsZoneLink]) -> tuple[_PrivateDnsZoneLink, ...]:
    deduped: list[_PrivateDnsZoneLink] = []
    seen: set[str] = set()
    for link in links:
        if link.address in seen:
            continue
        seen.add(link.address)
        deduped.append(link)
    return tuple(deduped)


def _dedupe_strings(values: Iterable[str]) -> tuple[str, ...]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return tuple(deduped)


def _overlaps(left: Iterable[str], right: Iterable[str]) -> bool:
    return bool(set(left).intersection(right))


def _private_endpoint_posture_severity(
    facts: AzureResourceFacts,
    *,
    has_private_endpoint: bool,
):
    default_deny = _network_default_action_is_deny(facts.network_default_action)
    fallback_state = facts.public_network_fallback_state
    if has_private_endpoint:
        return build_severity_reasoning(
            internet_exposure=fallback_state == PUBLIC_NETWORK_FALLBACK_ENABLED and not default_deny,
            privilege_breadth=0,
            data_sensitivity=1,
            lateral_movement=0,
            blast_radius=1 if fallback_state == PUBLIC_NETWORK_FALLBACK_ENABLED and not default_deny else 0,
        )
    if fallback_state == PUBLIC_NETWORK_FALLBACK_ENABLED:
        return build_severity_reasoning(
            internet_exposure=not default_deny,
            privilege_breadth=0,
            data_sensitivity=2 if not default_deny else 1,
            lateral_movement=0,
            blast_radius=1 if not default_deny else 0,
        )
    return build_severity_reasoning(
        internet_exposure=False,
        privilege_breadth=0,
        data_sensitivity=2 if not default_deny else 1,
        lateral_movement=0,
        blast_radius=1 if not default_deny else 0,
    )


def _target_resource_evidence(resource: NormalizedResource) -> list[str]:
    return [f"address={resource.address}", f"type={resource.resource_type}"]


def _public_network_fallback_evidence(facts: AzureResourceFacts) -> list[str]:
    values = [f"public_network_fallback_state={facts.public_network_fallback_state}"]
    if facts.public_network_access_enabled is True:
        values.append("public_network_access_enabled is true")
    elif facts.public_network_access_enabled is False:
        values.append("public_network_access_enabled is false")
    else:
        values.append("public_network_access_enabled is unknown")
    return values


def _network_acl_evidence(facts: AzureResourceFacts) -> list[str]:
    values = []
    if facts.network_default_action:
        values.append(f"effective default_action is {facts.network_default_action}")
    if facts.network_rule_source_address:
        values.append(f"network rule source is {facts.network_rule_source_address}")
    return values


def _fallback_uncertainty_evidence(
    resource: NormalizedResource,
    facts: AzureResourceFacts,
) -> list[str]:
    if facts.public_network_fallback_state != PUBLIC_NETWORK_FALLBACK_UNKNOWN:
        return []
    uncertainties = [
        uncertainty
        for uncertainty in _posture_uncertainties(resource, facts)
        if "public_network_access_enabled" in uncertainty
    ]
    if uncertainties:
        return uncertainties
    return ["public_network_access_enabled is not represented in planned values"]


def _posture_uncertainties(
    resource: NormalizedResource,
    facts: AzureResourceFacts,
) -> list[str]:
    if resource.resource_type == AzureResourceType.STORAGE_ACCOUNT:
        return facts.storage_posture_uncertainties
    if resource.resource_type == AzureResourceType.KEY_VAULT:
        return facts.key_vault_network_uncertainties
    if resource.resource_type == AzureResourceType.MSSQL_SERVER:
        return facts.mssql_posture_uncertainties
    return []


def _network_default_action_is_deny(default_action: str | None) -> bool:
    return bool(default_action and default_action.strip().lower() == "deny")
