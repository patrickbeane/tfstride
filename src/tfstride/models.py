from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import InitVar, dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any

from tfstride.resource_metadata import (
    InventoryMetadata,
    MetadataField,
    ResourceMetadata,
    StringListMetadataField,
)


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
        return self.RANK_ORDER.index(self)

    @classmethod
    def sort_key(cls, severity: "Severity") -> int:
        return len(cls.RANK_ORDER) - severity.rank - 1


Severity.RANK_ORDER = (Severity.LOW, Severity.MEDIUM, Severity.HIGH)


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
    conditions: list["IAMPolicyCondition"] = field(default_factory=list)

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
    subnet_ids: list[str] = field(default_factory=list)
    security_group_ids: list[str] = field(default_factory=list)
    attached_role_arns: list[str] = field(default_factory=list)
    network_rules: list[SecurityGroupRule] = field(default_factory=list)
    policy_statements: list[IAMPolicyStatement] = field(default_factory=list)
    public_access_configured: bool = False
    public_exposure: bool = False
    data_sensitivity: str = "standard"
    _metadata: dict[str, Any] = field(default_factory=dict, init=False, repr=False)
    metadata: InitVar[dict[str, Any] | None] = None

    def __post_init__(self, metadata: dict[str, Any] | None) -> None:
        self._metadata = deepcopy(metadata) if metadata is not None else {}

    @property
    def display_name(self) -> str:
        return f"{self.resource_type}.{self.name}"

    def metadata_snapshot(self) -> dict[str, Any]:
        """Return a detached metadata copy for serialization boundaries."""
        return deepcopy(self._metadata)

    def has_metadata_field(self, field: MetadataField[Any]) -> bool:
        return field.key in self._metadata

    def set_metadata_field(self, field: MetadataField[Any], value: Any) -> None:
        field.set(self._metadata, value)

    def append_metadata_field(self, field: StringListMetadataField, value: str | None) -> None:
        field.append_unique(self._metadata, value)

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

    @property
    def security_group_id(self) -> str | None:
        return ResourceMetadata.SECURITY_GROUP_ID.get(self._metadata)

    @security_group_id.setter
    def security_group_id(self, value: str | None) -> None:
        ResourceMetadata.SECURITY_GROUP_ID.set(self._metadata, value)

    @property
    def role_reference(self) -> str | None:
        return ResourceMetadata.ROLE_REFERENCE.get(self._metadata)

    @role_reference.setter
    def role_reference(self, value: str | None) -> None:
        ResourceMetadata.ROLE_REFERENCE.set(self._metadata, value)

    @property
    def role_references(self) -> list[str]:
        return ResourceMetadata.ROLE_REFERENCES.get(self._metadata)

    @role_references.setter
    def role_references(self, values: list[str]) -> None:
        ResourceMetadata.ROLE_REFERENCES.set(self._metadata, values)

    @property
    def resolved_role_references(self) -> list[str]:
        return ResourceMetadata.RESOLVED_ROLE_REFERENCES.get(self._metadata)

    @resolved_role_references.setter
    def resolved_role_references(self, values: list[str]) -> None:
        ResourceMetadata.RESOLVED_ROLE_REFERENCES.set(self._metadata, values)

    @property
    def iam_instance_profile(self) -> str | None:
        return ResourceMetadata.IAM_INSTANCE_PROFILE.get(self._metadata)

    @iam_instance_profile.setter
    def iam_instance_profile(self, value: str | None) -> None:
        ResourceMetadata.IAM_INSTANCE_PROFILE.set(self._metadata, value)

    @property
    def policy_arn(self) -> str | None:
        return ResourceMetadata.POLICY_ARN.get(self._metadata)

    @policy_arn.setter
    def policy_arn(self, value: str | None) -> None:
        ResourceMetadata.POLICY_ARN.set(self._metadata, value)

    @property
    def policy_name(self) -> str | None:
        return ResourceMetadata.POLICY_NAME.get(self._metadata)

    @policy_name.setter
    def policy_name(self, value: str | None) -> None:
        ResourceMetadata.POLICY_NAME.set(self._metadata, value)

    @property
    def cluster_reference(self) -> str | None:
        return ResourceMetadata.CLUSTER_REFERENCE.get(self._metadata)

    @cluster_reference.setter
    def cluster_reference(self, value: str | None) -> None:
        ResourceMetadata.CLUSTER_REFERENCE.set(self._metadata, value)

    @property
    def cluster_name(self) -> str | None:
        return ResourceMetadata.NAME.get(self._metadata)

    @cluster_name.setter
    def cluster_name(self, value: str | None) -> None:
        ResourceMetadata.NAME.set(self._metadata, value)

    @property
    def task_definition_reference(self) -> str | None:
        return ResourceMetadata.TASK_DEFINITION_REFERENCE.get(self._metadata)

    @task_definition_reference.setter
    def task_definition_reference(self, value: str | None) -> None:
        ResourceMetadata.TASK_DEFINITION_REFERENCE.set(self._metadata, value)

    @property
    def task_definition_family(self) -> str | None:
        return ResourceMetadata.TASK_DEFINITION_FAMILY.get(self._metadata)

    @task_definition_family.setter
    def task_definition_family(self, value: str | None) -> None:
        ResourceMetadata.TASK_DEFINITION_FAMILY.set(self._metadata, value)

    @property
    def task_definition_revision(self) -> int | None:
        return ResourceMetadata.TASK_DEFINITION_REVISION.get(self._metadata)

    @task_definition_revision.setter
    def task_definition_revision(self, value: int | None) -> None:
        ResourceMetadata.TASK_DEFINITION_REVISION.set(self._metadata, value)

    @property
    def network_mode(self) -> str | None:
        return ResourceMetadata.NETWORK_MODE.get(self._metadata)

    @network_mode.setter
    def network_mode(self, value: str | None) -> None:
        ResourceMetadata.NETWORK_MODE.set(self._metadata, value)

    @property
    def requires_compatibilities(self) -> list[str]:
        return ResourceMetadata.REQUIRES_COMPATIBILITIES.get(self._metadata)

    @requires_compatibilities.setter
    def requires_compatibilities(self, values: list[str]) -> None:
        ResourceMetadata.REQUIRES_COMPATIBILITIES.set(self._metadata, values)

    @property
    def task_role_arn(self) -> str | None:
        return ResourceMetadata.TASK_ROLE_ARN.get(self._metadata)

    @task_role_arn.setter
    def task_role_arn(self, value: str | None) -> None:
        ResourceMetadata.TASK_ROLE_ARN.set(self._metadata, value)

    @property
    def execution_role_arn(self) -> str | None:
        return ResourceMetadata.EXECUTION_ROLE_ARN.get(self._metadata)

    @execution_role_arn.setter
    def execution_role_arn(self, value: str | None) -> None:
        ResourceMetadata.EXECUTION_ROLE_ARN.set(self._metadata, value)

    @property
    def secret_arn(self) -> str | None:
        return ResourceMetadata.SECRET_ARN.get(self._metadata)

    @secret_arn.setter
    def secret_arn(self, value: str | None) -> None:
        ResourceMetadata.SECRET_ARN.set(self._metadata, value)

    @property
    def function_name(self) -> str | None:
        return ResourceMetadata.FUNCTION_NAME.get(self._metadata)

    @function_name.setter
    def function_name(self, value: str | None) -> None:
        ResourceMetadata.FUNCTION_NAME.set(self._metadata, value)

    @property
    def secret_name(self) -> str | None:
        return ResourceMetadata.NAME.get(self._metadata)

    @secret_name.setter
    def secret_name(self, value: str | None) -> None:
        ResourceMetadata.NAME.set(self._metadata, value)

    @property
    def route_table_id(self) -> str | None:
        return ResourceMetadata.ROUTE_TABLE_ID.get(self._metadata)

    @route_table_id.setter
    def route_table_id(self, value: str | None) -> None:
        ResourceMetadata.ROUTE_TABLE_ID.set(self._metadata, value)

    @property
    def subnet_id(self) -> str | None:
        return ResourceMetadata.SUBNET_ID.get(self._metadata)

    @subnet_id.setter
    def subnet_id(self, value: str | None) -> None:
        ResourceMetadata.SUBNET_ID.set(self._metadata, value)

    @property
    def routes(self) -> list[dict[str, Any]]:
        return ResourceMetadata.ROUTES.get(self._metadata)

    @routes.setter
    def routes(self, values: list[dict[str, Any]]) -> None:
        ResourceMetadata.ROUTES.set(self._metadata, values)

    @property
    def map_public_ip_on_launch(self) -> bool:
        return ResourceMetadata.MAP_PUBLIC_IP_ON_LAUNCH.get(self._metadata)

    @map_public_ip_on_launch.setter
    def map_public_ip_on_launch(self, value: bool) -> None:
        ResourceMetadata.MAP_PUBLIC_IP_ON_LAUNCH.set(self._metadata, value)

    @property
    def block_public_acls(self) -> bool:
        return ResourceMetadata.BLOCK_PUBLIC_ACLS.get(self._metadata)

    @block_public_acls.setter
    def block_public_acls(self, value: bool) -> None:
        ResourceMetadata.BLOCK_PUBLIC_ACLS.set(self._metadata, value)

    @property
    def block_public_policy(self) -> bool:
        return ResourceMetadata.BLOCK_PUBLIC_POLICY.get(self._metadata)

    @block_public_policy.setter
    def block_public_policy(self, value: bool) -> None:
        ResourceMetadata.BLOCK_PUBLIC_POLICY.set(self._metadata, value)

    @property
    def ignore_public_acls(self) -> bool:
        return ResourceMetadata.IGNORE_PUBLIC_ACLS.get(self._metadata)

    @ignore_public_acls.setter
    def ignore_public_acls(self, value: bool) -> None:
        ResourceMetadata.IGNORE_PUBLIC_ACLS.set(self._metadata, value)

    @property
    def restrict_public_buckets(self) -> bool:
        return ResourceMetadata.RESTRICT_PUBLIC_BUCKETS.get(self._metadata)

    @restrict_public_buckets.setter
    def restrict_public_buckets(self, value: bool) -> None:
        ResourceMetadata.RESTRICT_PUBLIC_BUCKETS.set(self._metadata, value)

    @property
    def trust_principals(self) -> list[str]:
        return ResourceMetadata.TRUST_PRINCIPALS.get(self._metadata)

    @trust_principals.setter
    def trust_principals(self, values: list[str]) -> None:
        ResourceMetadata.TRUST_PRINCIPALS.set(self._metadata, values)

    @property
    def trust_statements(self) -> list[dict[str, Any]]:
        return ResourceMetadata.TRUST_STATEMENTS.get(self._metadata)

    @trust_statements.setter
    def trust_statements(self, values: list[dict[str, Any]]) -> None:
        ResourceMetadata.TRUST_STATEMENTS.set(self._metadata, values)

    @property
    def resource_policy_source_addresses(self) -> list[str]:
        return ResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES.get(self._metadata)

    @resource_policy_source_addresses.setter
    def resource_policy_source_addresses(self, values: list[str]) -> None:
        ResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES.set(self._metadata, values)

    @property
    def policy_document(self) -> dict[str, Any]:
        return ResourceMetadata.POLICY_DOCUMENT.get(self._metadata)

    @policy_document.setter
    def policy_document(self, value: dict[str, Any] | None) -> None:
        ResourceMetadata.POLICY_DOCUMENT.set(self._metadata, value)

    @property
    def public_access_block(self) -> dict[str, bool] | None:
        return ResourceMetadata.PUBLIC_ACCESS_BLOCK.get(self._metadata)

    @public_access_block.setter
    def public_access_block(self, value: dict[str, bool] | None) -> None:
        ResourceMetadata.PUBLIC_ACCESS_BLOCK.set(self._metadata, value)

    @property
    def bucket_name(self) -> str | None:
        return ResourceMetadata.BUCKET_NAME.get(self._metadata)

    @bucket_name.setter
    def bucket_name(self, value: str | None) -> None:
        ResourceMetadata.BUCKET_NAME.set(self._metadata, value)

    @property
    def bucket_acl(self) -> str:
        return ResourceMetadata.BUCKET_ACL.get(self._metadata) or ""

    @bucket_acl.setter
    def bucket_acl(self, value: str | None) -> None:
        ResourceMetadata.BUCKET_ACL.set(self._metadata, value)

    @property
    def engine(self) -> str | None:
        return ResourceMetadata.ENGINE.get(self._metadata)

    @engine.setter
    def engine(self, value: str | None) -> None:
        ResourceMetadata.ENGINE.set(self._metadata, value)


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
    metadata: dict[str, Any] = field(default_factory=dict)
    _resources_by_type: dict[str, tuple[NormalizedResource, ...]] = field(init=False, repr=False, default_factory=dict)
    _resources_by_address: dict[str, NormalizedResource] = field(init=False, repr=False, default_factory=dict)
    _resources_by_identifier: dict[str, NormalizedResource] = field(init=False, repr=False, default_factory=dict)
    _resource_positions: dict[int, int] = field(init=False, repr=False, default_factory=dict)

    def __post_init__(self) -> None:
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
        return InventoryMetadata.PRIMARY_ACCOUNT_ID.get(self.metadata)

    @primary_account_id.setter
    def primary_account_id(self, value: str | None) -> None:
        InventoryMetadata.PRIMARY_ACCOUNT_ID.set(self.metadata, value)

    def metadata_snapshot(self) -> dict[str, Any]:
        """Return a detached metadata copy for serialization boundaries."""
        return deepcopy(self.metadata)

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