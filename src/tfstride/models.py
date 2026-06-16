from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import InitVar, dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, TypeVar

from tfstride.resource_metadata import (
    InventoryMetadata,
    MetadataField,
    ResourceMetadata,
    StringListMetadataField,
)

_MetadataValue = TypeVar("_MetadataValue")
_MetadataKey = str | MetadataField[Any]


def _normalized_metadata(metadata: Mapping[_MetadataKey, Any] | None) -> dict[str, Any]:
    if metadata is None:
        return {}
    normalized: dict[str, Any] = {}
    for key, value in metadata.items():
        if isinstance(key, MetadataField):
            if value is not None:
                key.set(normalized, value)
            continue
        normalized[str(key)] = deepcopy(value)
    return normalized


class ResourceCategory(str, Enum):
    NETWORK = "network"
    COMPUTE = "compute"
    DATA = "data"
    IAM = "iam"
    EDGE = "edge"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return tuple(type(self)).index(self)

    @classmethod
    def sort_key(cls, severity: Severity) -> int:
        return len(tuple(cls)) - severity.rank - 1


class StrideCategory(str, Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


class BoundaryType(str, Enum):
    INTERNET_TO_SERVICE = "internet-to-service"
    PUBLIC_TO_PRIVATE = "public-subnet-to-private-subnet"
    WORKLOAD_TO_DATA_STORE = "workload-to-data-store"
    CROSS_ACCOUNT_OR_ROLE = "cross-account-or-role-access"
    CONTROL_TO_WORKLOAD = "admin-to-workload-plane"


@dataclass(slots=True)
class TerraformResource:
    address: str
    mode: str
    resource_type: str
    name: str
    provider_name: str
    values: dict[str, Any]


@dataclass(slots=True)
class TerraformPlan:
    source_path: str
    terraform_version: str | None
    resources: list[TerraformResource]


@dataclass(slots=True)
class SecurityGroupRule:
    direction: str
    protocol: str
    from_port: int | None
    to_port: int | None
    cidr_blocks: list[str] = field(default_factory=list)
    ipv6_cidr_blocks: list[str] = field(default_factory=list)
    referenced_security_group_ids: list[str] = field(default_factory=list)
    description: str | None = None

    def allows_internet(self) -> bool:
        return "0.0.0.0/0" in self.cidr_blocks or "::/0" in self.ipv6_cidr_blocks

    def is_administrative_access(self) -> bool:
        ports = {22, 3389}
        if self.from_port is None or self.to_port is None:
            return False
        return any(self.from_port <= port <= self.to_port for port in ports)

    def is_all_ports(self) -> bool:
        if self.protocol == "-1":
            return True
        if self.from_port is None or self.to_port is None:
            return False
        return self.from_port == 0 and self.to_port >= 65535


@dataclass(slots=True)
class IAMPrincipal:
    kind: str
    value: str


@dataclass(slots=True)
class IAMPolicyStatement:
    effect: str
    actions: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    principals: list[str] = field(default_factory=list)
    principal_entries: list[IAMPrincipal] = field(default_factory=list)
    conditions: list[IAMPolicyCondition] = field(default_factory=list)

    def has_wildcard_action(self) -> bool:
        return any(action == "*" or action.endswith(":*") for action in self.actions)

    def has_wildcard_resource(self) -> bool:
        return any(resource == "*" for resource in self.resources)


@dataclass(slots=True)
class IAMPolicyCondition:
    operator: str
    key: str
    values: list[str] = field(default_factory=list)


@dataclass(slots=True)
class NormalizedResource:
    address: str
    provider: str
    resource_type: str
    name: str
    category: ResourceCategory
    identifier: str | None = None
    arn: str | None = None
    vpc_id: str | None = None
    subnet_ids: tuple[str, ...] = field(default_factory=tuple)
    security_group_ids: tuple[str, ...] = field(default_factory=tuple)
    attached_role_arns: list[str] = field(default_factory=list)
    network_rules: list[SecurityGroupRule] = field(default_factory=list)
    policy_statements: list[IAMPolicyStatement] = field(default_factory=list)
    public_access_configured: bool = False
    public_exposure: bool = False
    data_sensitivity: str = "standard"
    _metadata: dict[str, Any] = field(default_factory=dict, init=False, repr=False)
    metadata: InitVar[Mapping[_MetadataKey, Any] | None] = None

    def __post_init__(self, metadata: Mapping[_MetadataKey, Any] | None) -> None:
        self.subnet_ids = tuple(self.subnet_ids)
        self.security_group_ids = tuple(self.security_group_ids)
        self._metadata = _normalized_metadata(metadata)

    @property
    def display_name(self) -> str:
        return f"{self.resource_type}.{self.name}"

    def metadata_snapshot(self) -> dict[str, Any]:
        """Return a detached metadata copy for serialization boundaries."""
        return deepcopy(self._metadata)

    def get_metadata_field(self, field: MetadataField[_MetadataValue]) -> _MetadataValue:
        return field.get(self._metadata)

    def has_metadata_field(self, field: MetadataField[Any]) -> bool:
        return field.key in self._metadata

    def set_metadata_field(self, field: MetadataField[_MetadataValue], value: _MetadataValue) -> None:
        field.set(self._metadata, value)

    def append_metadata_field(self, field: StringListMetadataField, value: str | None) -> None:
        field.append_unique(self._metadata, value)

    def extend_metadata_field(self, field: StringListMetadataField, values: Sequence[str | None]) -> None:
        field.extend_unique(self._metadata, values)

    def add_attached_role_arn(self, role_arn: str | None) -> None:
        if not role_arn or role_arn in self.attached_role_arns:
            return
        self.attached_role_arns.append(role_arn)

    def extend_network_rules(self, rules: Sequence[SecurityGroupRule]) -> None:
        self.network_rules.extend(rules)

    def extend_policy_statements(self, statements: Sequence[IAMPolicyStatement]) -> None:
        self.policy_statements.extend(statements)

    def _metadata_view(self) -> Mapping[str, Any]:
        return MappingProxyType(deepcopy(self._metadata))

    @property
    def direct_internet_reachable(self) -> bool:
        return ResourceMetadata.DIRECT_INTERNET_REACHABLE.get(self._metadata)

    @direct_internet_reachable.setter
    def direct_internet_reachable(self, value: bool) -> None:
        ResourceMetadata.DIRECT_INTERNET_REACHABLE.set(self._metadata, value)

    @property
    def internet_ingress_capable(self) -> bool:
        return ResourceMetadata.INTERNET_INGRESS_CAPABLE.get(self._metadata)

    @internet_ingress_capable.setter
    def internet_ingress_capable(self, value: bool) -> None:
        ResourceMetadata.INTERNET_INGRESS_CAPABLE.set(self._metadata, value)

    @property
    def in_public_subnet(self) -> bool:
        return ResourceMetadata.IN_PUBLIC_SUBNET.get(self._metadata)

    @in_public_subnet.setter
    def in_public_subnet(self, value: bool) -> None:
        ResourceMetadata.IN_PUBLIC_SUBNET.set(self._metadata, value)

    @property
    def has_nat_gateway_egress(self) -> bool:
        return ResourceMetadata.HAS_NAT_GATEWAY_EGRESS.get(self._metadata)

    @has_nat_gateway_egress.setter
    def has_nat_gateway_egress(self, value: bool) -> None:
        ResourceMetadata.HAS_NAT_GATEWAY_EGRESS.set(self._metadata, value)

    @property
    def is_public_subnet(self) -> bool:
        return ResourceMetadata.IS_PUBLIC_SUBNET.get(self._metadata)

    @is_public_subnet.setter
    def is_public_subnet(self, value: bool) -> None:
        ResourceMetadata.IS_PUBLIC_SUBNET.set(self._metadata, value)

    @property
    def has_public_route(self) -> bool:
        return ResourceMetadata.HAS_PUBLIC_ROUTE.get(self._metadata)

    @has_public_route.setter
    def has_public_route(self, value: bool) -> None:
        ResourceMetadata.HAS_PUBLIC_ROUTE.set(self._metadata, value)

    @property
    def vpc_enabled(self) -> bool:
        return ResourceMetadata.VPC_ENABLED.get(self._metadata)

    @vpc_enabled.setter
    def vpc_enabled(self, value: bool) -> None:
        ResourceMetadata.VPC_ENABLED.set(self._metadata, value)

    @property
    def storage_encrypted(self) -> bool:
        return ResourceMetadata.STORAGE_ENCRYPTED.get(self._metadata)

    @storage_encrypted.setter
    def storage_encrypted(self, value: bool) -> None:
        ResourceMetadata.STORAGE_ENCRYPTED.set(self._metadata, value)

    @property
    def publicly_accessible(self) -> bool:
        return ResourceMetadata.PUBLICLY_ACCESSIBLE.get(self._metadata)

    @publicly_accessible.setter
    def publicly_accessible(self, value: bool) -> None:
        ResourceMetadata.PUBLICLY_ACCESSIBLE.set(self._metadata, value)

    @property
    def public_access_reasons(self) -> list[str]:
        return ResourceMetadata.PUBLIC_ACCESS_REASONS.get(self._metadata)

    @public_access_reasons.setter
    def public_access_reasons(self, values: list[str]) -> None:
        ResourceMetadata.PUBLIC_ACCESS_REASONS.set(self._metadata, values)

    @property
    def public_exposure_reasons(self) -> list[str]:
        return ResourceMetadata.PUBLIC_EXPOSURE_REASONS.get(self._metadata)

    @public_exposure_reasons.setter
    def public_exposure_reasons(self, values: list[str]) -> None:
        ResourceMetadata.PUBLIC_EXPOSURE_REASONS.set(self._metadata, values)

    @property
    def internet_ingress_reasons(self) -> list[str]:
        return ResourceMetadata.INTERNET_INGRESS_REASONS.get(self._metadata)

    @internet_ingress_reasons.setter
    def internet_ingress_reasons(self, values: list[str]) -> None:
        ResourceMetadata.INTERNET_INGRESS_REASONS.set(self._metadata, values)



# Assign after dataclass generation so InitVar keeps a clean metadata=None default.
NormalizedResource.metadata = property(
    NormalizedResource._metadata_view,
    doc="Read-only metadata view. Use typed properties or metadata field helpers to mutate.",
)


@dataclass(slots=True)
class ResourceInventory:
    provider: str
    resources: Sequence[NormalizedResource]
    unsupported_resources: list[str] = field(default_factory=list)
    _metadata: dict[str, Any] = field(default_factory=dict, init=False, repr=False)
    metadata: InitVar[Mapping[_MetadataKey, Any] | None] = None
    _resources_by_type: dict[str, tuple[NormalizedResource, ...]] = field(init=False, repr=False, default_factory=dict)
    _resources_by_address: dict[str, NormalizedResource] = field(init=False, repr=False, default_factory=dict)
    _resources_by_identifier: dict[str, NormalizedResource] = field(init=False, repr=False, default_factory=dict)
    _resource_positions: dict[int, int] = field(init=False, repr=False, default_factory=dict)

    def __post_init__(self, metadata: Mapping[_MetadataKey, Any] | None) -> None:
        self._metadata = _normalized_metadata(metadata)
        resources = tuple(self.resources)
        self.resources = resources
        resources_by_type: dict[str, list[NormalizedResource]] = {}
        resources_by_address: dict[str, NormalizedResource] = {}
        resources_by_identifier: dict[str, NormalizedResource] = {}
        resource_positions: dict[int, int] = {}

        for index, resource in enumerate(resources):
            resource_positions[id(resource)] = index
            resources_by_type.setdefault(resource.resource_type, []).append(resource)
            resources_by_address.setdefault(resource.address, resource)
            for key in (resource.identifier, resource.arn, resource.address):
                if key is None:
                    continue
                resources_by_identifier.setdefault(key, resource)

        self._resources_by_type = {
            resource_type: tuple(group)
            for resource_type, group in resources_by_type.items()
        }
        self._resources_by_address = resources_by_address
        self._resources_by_identifier = resources_by_identifier
        self._resource_positions = resource_positions

    @property
    def primary_account_id(self) -> str | None:
        return InventoryMetadata.PRIMARY_ACCOUNT_ID.get(self._metadata)

    @primary_account_id.setter
    def primary_account_id(self, value: str | None) -> None:
        InventoryMetadata.PRIMARY_ACCOUNT_ID.set(self._metadata, value)

    def metadata_snapshot(self) -> dict[str, Any]:
        """Return a detached metadata copy for serialization boundaries."""
        return deepcopy(self._metadata)

    def _metadata_view(self) -> Mapping[str, Any]:
        return MappingProxyType(deepcopy(self._metadata))

    def by_type(self, *resource_types: str) -> list[NormalizedResource]:
        if not resource_types:
            return []

        allowed = set(resource_types)
        if len(allowed) == 1:
            resource_type = next(iter(allowed))
            return list(self._resources_by_type.get(resource_type, ()))

        matches = [
            resource
            for resource_type in allowed
            for resource in self._resources_by_type.get(resource_type, ())
        ]
        matches.sort(key=lambda resource: self._resource_positions[id(resource)])
        return matches

    def get_by_address(self, address: str) -> NormalizedResource | None:
        return self._resources_by_address.get(address)

    def get_by_identifier(self, identifier: str) -> NormalizedResource | None:
        return self._resources_by_identifier.get(identifier)


# Assign after dataclass generation so InitVar keeps a clean metadata=None default.
ResourceInventory.metadata = property(
    ResourceInventory._metadata_view,
    doc="Read-only metadata view. Use typed properties or metadata_snapshot() for serialization.",
)


@dataclass(slots=True)
class TrustBoundary:
    identifier: str
    boundary_type: BoundaryType
    source: str
    target: str
    description: str
    rationale: str


@dataclass(slots=True)
class EvidenceItem:
    key: str
    values: list[str] = field(default_factory=list)


@dataclass(slots=True)
class SeverityReasoning:
    internet_exposure: int
    privilege_breadth: int
    data_sensitivity: int
    lateral_movement: int
    blast_radius: int
    final_score: int
    severity: Severity
    computed_severity: Severity | None = None


@dataclass(slots=True)
class Finding:
    title: str
    category: StrideCategory
    severity: Severity
    affected_resources: list[str]
    trust_boundary_id: str | None
    rationale: str
    recommended_mitigation: str
    rule_id: str
    evidence: list[EvidenceItem] = field(default_factory=list)
    severity_reasoning: SeverityReasoning | None = None


@dataclass(slots=True)
class Observation:
    title: str
    observation_id: str
    affected_resources: list[str]
    rationale: str
    evidence: list[EvidenceItem] = field(default_factory=list)
    category: str | None = None


@dataclass(slots=True)
class ResourceCoverage:
    total_resources: int = 0
    provider_resources: int = 0
    normalized_resources: int = 0
    unsupported_resources: int = 0
    unsupported_resource_types: dict[str, int] = field(default_factory=dict)


@dataclass(slots=True)
class RuleCoverage:
    registered_rule_count: int = 0
    enabled_rules: list[str] = field(default_factory=list)
    disabled_rules: list[str] = field(default_factory=list)
    severity_overrides: dict[str, Severity] = field(default_factory=dict)


@dataclass(slots=True)
class UnresolvedReference:
    resource: str
    references: dict[str, list[str]] = field(default_factory=dict)


@dataclass(slots=True)
class ReferenceCoverage:
    unresolved_reference_count: int = 0
    unresolved_references: list[UnresolvedReference] = field(default_factory=list)


@dataclass(slots=True)
class AnalysisCoverage:
    resources: ResourceCoverage = field(default_factory=ResourceCoverage)
    rules: RuleCoverage = field(default_factory=RuleCoverage)
    references: ReferenceCoverage = field(default_factory=ReferenceCoverage)


@dataclass(slots=True)
class AnalysisResult:
    title: str
    analyzed_file: str
    analyzed_path: str
    inventory: ResourceInventory
    trust_boundaries: list[TrustBoundary]
    findings: list[Finding]
    observations: list[Observation] = field(default_factory=list)
    suppressed_findings: list[Finding] = field(default_factory=list)
    baselined_findings: list[Finding] = field(default_factory=list)
    filter_summary: dict[str, Any] = field(default_factory=dict)
    analysis_coverage: AnalysisCoverage = field(default_factory=AnalysisCoverage)
    limitations: list[str] = field(default_factory=list)