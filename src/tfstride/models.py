from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from tfstride.resource_metadata import (
    BoolDictMetadataField,
    BoolMetadataField,
    DictListMetadataField,
    DictMetadataField,
    InventoryMetadata,
    OptionalIntMetadataField,
    OptionalStringMetadataField,
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
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def display_name(self) -> str:
        return f"{self.resource_type}.{self.name}"

    # Keep high-traffic posture fields metadata-backed for report compatibility,
    # but route access through typed schema fields instead of raw keys.
    def _metadata_bool(self, field: BoolMetadataField) -> bool:
        return field.get(self.metadata)

    def _set_metadata_bool(self, field: BoolMetadataField, value: bool) -> None:
        field.set(self.metadata, value)

    def _metadata_string_list(self, field: StringListMetadataField) -> list[str]:
        return field.get(self.metadata)

    def _set_metadata_string_list(self, field: StringListMetadataField, values: list[str]) -> None:
        field.set(self.metadata, values)

    def _metadata_optional_string(self, field: OptionalStringMetadataField) -> str | None:
        return field.get(self.metadata)

    def _set_metadata_optional_string(self, field: OptionalStringMetadataField, value: str | None) -> None:
        field.set(self.metadata, value)

    def _metadata_optional_int(self, field: OptionalIntMetadataField) -> int | None:
        return field.get(self.metadata)

    def _set_metadata_optional_int(self, field: OptionalIntMetadataField, value: int | None) -> None:
        field.set(self.metadata, value)

    def _metadata_dict(self, field: DictMetadataField) -> dict[str, Any]:
        return field.get(self.metadata)

    def _set_metadata_dict(self, field: DictMetadataField, value: dict[str, Any] | None) -> None:
        field.set(self.metadata, value)

    def _metadata_dict_list(self, field: DictListMetadataField) -> list[dict[str, Any]]:
        return field.get(self.metadata)

    def _set_metadata_dict_list(self, field: DictListMetadataField, values: list[dict[str, Any]]) -> None:
        field.set(self.metadata, values)

    def _metadata_bool_dict(self, field: BoolDictMetadataField) -> dict[str, bool] | None:
        return field.get(self.metadata)

    def _set_metadata_bool_dict(self, field: BoolDictMetadataField, value: dict[str, bool] | None) -> None:
        field.set(self.metadata, value)

    @property
    def direct_internet_reachable(self) -> bool:
        return self._metadata_bool(ResourceMetadata.DIRECT_INTERNET_REACHABLE)

    @direct_internet_reachable.setter
    def direct_internet_reachable(self, value: bool) -> None:
        self._set_metadata_bool(ResourceMetadata.DIRECT_INTERNET_REACHABLE, value)

    @property
    def internet_ingress_capable(self) -> bool:
        return self._metadata_bool(ResourceMetadata.INTERNET_INGRESS_CAPABLE)

    @internet_ingress_capable.setter
    def internet_ingress_capable(self, value: bool) -> None:
        self._set_metadata_bool(ResourceMetadata.INTERNET_INGRESS_CAPABLE, value)

    @property
    def in_public_subnet(self) -> bool:
        return self._metadata_bool(ResourceMetadata.IN_PUBLIC_SUBNET)

    @in_public_subnet.setter
    def in_public_subnet(self, value: bool) -> None:
        self._set_metadata_bool(ResourceMetadata.IN_PUBLIC_SUBNET, value)

    @property
    def has_nat_gateway_egress(self) -> bool:
        return self._metadata_bool(ResourceMetadata.HAS_NAT_GATEWAY_EGRESS)

    @has_nat_gateway_egress.setter
    def has_nat_gateway_egress(self, value: bool) -> None:
        self._set_metadata_bool(ResourceMetadata.HAS_NAT_GATEWAY_EGRESS, value)

    @property
    def is_public_subnet(self) -> bool:
        return self._metadata_bool(ResourceMetadata.IS_PUBLIC_SUBNET)

    @is_public_subnet.setter
    def is_public_subnet(self, value: bool) -> None:
        self._set_metadata_bool(ResourceMetadata.IS_PUBLIC_SUBNET, value)

    @property
    def has_public_route(self) -> bool:
        return self._metadata_bool(ResourceMetadata.HAS_PUBLIC_ROUTE)

    @has_public_route.setter
    def has_public_route(self, value: bool) -> None:
        self._set_metadata_bool(ResourceMetadata.HAS_PUBLIC_ROUTE, value)

    @property
    def vpc_enabled(self) -> bool:
        return self._metadata_bool(ResourceMetadata.VPC_ENABLED)

    @vpc_enabled.setter
    def vpc_enabled(self, value: bool) -> None:
        self._set_metadata_bool(ResourceMetadata.VPC_ENABLED, value)

    @property
    def storage_encrypted(self) -> bool:
        return self._metadata_bool(ResourceMetadata.STORAGE_ENCRYPTED)

    @storage_encrypted.setter
    def storage_encrypted(self, value: bool) -> None:
        self._set_metadata_bool(ResourceMetadata.STORAGE_ENCRYPTED, value)

    @property
    def publicly_accessible(self) -> bool:
        return self._metadata_bool(ResourceMetadata.PUBLICLY_ACCESSIBLE)

    @publicly_accessible.setter
    def publicly_accessible(self, value: bool) -> None:
        self._set_metadata_bool(ResourceMetadata.PUBLICLY_ACCESSIBLE, value)

    @property
    def public_access_reasons(self) -> list[str]:
        return self._metadata_string_list(ResourceMetadata.PUBLIC_ACCESS_REASONS)

    @public_access_reasons.setter
    def public_access_reasons(self, values: list[str]) -> None:
        self._set_metadata_string_list(ResourceMetadata.PUBLIC_ACCESS_REASONS, values)

    @property
    def public_exposure_reasons(self) -> list[str]:
        return self._metadata_string_list(ResourceMetadata.PUBLIC_EXPOSURE_REASONS)

    @public_exposure_reasons.setter
    def public_exposure_reasons(self, values: list[str]) -> None:
        self._set_metadata_string_list(ResourceMetadata.PUBLIC_EXPOSURE_REASONS, values)

    @property
    def internet_ingress_reasons(self) -> list[str]:
        return self._metadata_string_list(ResourceMetadata.INTERNET_INGRESS_REASONS)

    @internet_ingress_reasons.setter
    def internet_ingress_reasons(self, values: list[str]) -> None:
        self._set_metadata_string_list(ResourceMetadata.INTERNET_INGRESS_REASONS, values)

    @property
    def security_group_id(self) -> str | None:
        return self._metadata_optional_string(ResourceMetadata.SECURITY_GROUP_ID)

    @security_group_id.setter
    def security_group_id(self, value: str | None) -> None:
        self._set_metadata_optional_string(ResourceMetadata.SECURITY_GROUP_ID, value)

    @property
    def role_reference(self) -> str | None:
        return self._metadata_optional_string(ResourceMetadata.ROLE_REFERENCE)

    @role_reference.setter
    def role_reference(self, value: str | None) -> None:
        self._set_metadata_optional_string(ResourceMetadata.ROLE_REFERENCE, value)

    @property
    def role_references(self) -> list[str]:
        return self._metadata_string_list(ResourceMetadata.ROLE_REFERENCES)

    @role_references.setter
    def role_references(self, values: list[str]) -> None:
        self._set_metadata_string_list(ResourceMetadata.ROLE_REFERENCES, values)

    @property
    def resolved_role_references(self) -> list[str]:
        return self._metadata_string_list(ResourceMetadata.RESOLVED_ROLE_REFERENCES)

    @resolved_role_references.setter
    def resolved_role_references(self, values: list[str]) -> None:
        self._set_metadata_string_list(ResourceMetadata.RESOLVED_ROLE_REFERENCES, values)

    @property
    def iam_instance_profile(self) -> str | None:
        return self._metadata_optional_string(ResourceMetadata.IAM_INSTANCE_PROFILE)

    @iam_instance_profile.setter
    def iam_instance_profile(self, value: str | None) -> None:
        self._set_metadata_optional_string(ResourceMetadata.IAM_INSTANCE_PROFILE, value)

    @property
    def policy_arn(self) -> str | None:
        return self._metadata_optional_string(ResourceMetadata.POLICY_ARN)

    @policy_arn.setter
    def policy_arn(self, value: str | None) -> None:
        self._set_metadata_optional_string(ResourceMetadata.POLICY_ARN, value)

    @property
    def policy_name(self) -> str | None:
        return self._metadata_optional_string(ResourceMetadata.POLICY_NAME)

    @policy_name.setter
    def policy_name(self, value: str | None) -> None:
        self._set_metadata_optional_string(ResourceMetadata.POLICY_NAME, value)

    @property
    def cluster_reference(self) -> str | None:
        return self._metadata_optional_string(ResourceMetadata.CLUSTER_REFERENCE)

    @cluster_reference.setter
    def cluster_reference(self, value: str | None) -> None:
        self._set_metadata_optional_string(ResourceMetadata.CLUSTER_REFERENCE, value)

    @property
    def cluster_name(self) -> str | None:
        return self._metadata_optional_string(ResourceMetadata.NAME)

    @cluster_name.setter
    def cluster_name(self, value: str | None) -> None:
        self._set_metadata_optional_string(ResourceMetadata.NAME, value)

    @property
    def task_definition_reference(self) -> str | None:
        return self._metadata_optional_string(ResourceMetadata.TASK_DEFINITION_REFERENCE)

    @task_definition_reference.setter
    def task_definition_reference(self, value: str | None) -> None:
        self._set_metadata_optional_string(ResourceMetadata.TASK_DEFINITION_REFERENCE, value)

    @property
    def task_definition_family(self) -> str | None:
        return self._metadata_optional_string(ResourceMetadata.TASK_DEFINITION_FAMILY)

    @task_definition_family.setter
    def task_definition_family(self, value: str | None) -> None:
        self._set_metadata_optional_string(ResourceMetadata.TASK_DEFINITION_FAMILY, value)

    @property
    def task_definition_revision(self) -> int | None:
        return self._metadata_optional_int(ResourceMetadata.TASK_DEFINITION_REVISION)

    @task_definition_revision.setter
    def task_definition_revision(self, value: int | None) -> None:
        self._set_metadata_optional_int(ResourceMetadata.TASK_DEFINITION_REVISION, value)

    @property
    def network_mode(self) -> str | None:
        return self._metadata_optional_string(ResourceMetadata.NETWORK_MODE)

    @network_mode.setter
    def network_mode(self, value: str | None) -> None:
        self._set_metadata_optional_string(ResourceMetadata.NETWORK_MODE, value)

    @property
    def requires_compatibilities(self) -> list[str]:
        return self._metadata_string_list(ResourceMetadata.REQUIRES_COMPATIBILITIES)

    @requires_compatibilities.setter
    def requires_compatibilities(self, values: list[str]) -> None:
        self._set_metadata_string_list(ResourceMetadata.REQUIRES_COMPATIBILITIES, values)

    @property
    def task_role_arn(self) -> str | None:
        return self._metadata_optional_string(ResourceMetadata.TASK_ROLE_ARN)

    @task_role_arn.setter
    def task_role_arn(self, value: str | None) -> None:
        self._set_metadata_optional_string(ResourceMetadata.TASK_ROLE_ARN, value)

    @property
    def execution_role_arn(self) -> str | None:
        return self._metadata_optional_string(ResourceMetadata.EXECUTION_ROLE_ARN)

    @execution_role_arn.setter
    def execution_role_arn(self, value: str | None) -> None:
        self._set_metadata_optional_string(ResourceMetadata.EXECUTION_ROLE_ARN, value)

    @property
    def secret_arn(self) -> str | None:
        return self._metadata_optional_string(ResourceMetadata.SECRET_ARN)

    @secret_arn.setter
    def secret_arn(self, value: str | None) -> None:
        self._set_metadata_optional_string(ResourceMetadata.SECRET_ARN, value)

    @property
    def function_name(self) -> str | None:
        return self._metadata_optional_string(ResourceMetadata.FUNCTION_NAME)

    @function_name.setter
    def function_name(self, value: str | None) -> None:
        self._set_metadata_optional_string(ResourceMetadata.FUNCTION_NAME, value)

    @property
    def secret_name(self) -> str | None:
        return self._metadata_optional_string(ResourceMetadata.NAME)

    @secret_name.setter
    def secret_name(self, value: str | None) -> None:
        self._set_metadata_optional_string(ResourceMetadata.NAME, value)

    @property
    def route_table_id(self) -> str | None:
        return self._metadata_optional_string(ResourceMetadata.ROUTE_TABLE_ID)

    @route_table_id.setter
    def route_table_id(self, value: str | None) -> None:
        self._set_metadata_optional_string(ResourceMetadata.ROUTE_TABLE_ID, value)

    @property
    def subnet_id(self) -> str | None:
        return self._metadata_optional_string(ResourceMetadata.SUBNET_ID)

    @subnet_id.setter
    def subnet_id(self, value: str | None) -> None:
        self._set_metadata_optional_string(ResourceMetadata.SUBNET_ID, value)

    @property
    def routes(self) -> list[dict[str, Any]]:
        return self._metadata_dict_list(ResourceMetadata.ROUTES)

    @routes.setter
    def routes(self, values: list[dict[str, Any]]) -> None:
        self._set_metadata_dict_list(ResourceMetadata.ROUTES, values)

    @property
    def map_public_ip_on_launch(self) -> bool:
        return self._metadata_bool(ResourceMetadata.MAP_PUBLIC_IP_ON_LAUNCH)

    @map_public_ip_on_launch.setter
    def map_public_ip_on_launch(self, value: bool) -> None:
        self._set_metadata_bool(ResourceMetadata.MAP_PUBLIC_IP_ON_LAUNCH, value)

    @property
    def block_public_acls(self) -> bool:
        return self._metadata_bool(ResourceMetadata.BLOCK_PUBLIC_ACLS)

    @block_public_acls.setter
    def block_public_acls(self, value: bool) -> None:
        self._set_metadata_bool(ResourceMetadata.BLOCK_PUBLIC_ACLS, value)

    @property
    def block_public_policy(self) -> bool:
        return self._metadata_bool(ResourceMetadata.BLOCK_PUBLIC_POLICY)

    @block_public_policy.setter
    def block_public_policy(self, value: bool) -> None:
        self._set_metadata_bool(ResourceMetadata.BLOCK_PUBLIC_POLICY, value)

    @property
    def ignore_public_acls(self) -> bool:
        return self._metadata_bool(ResourceMetadata.IGNORE_PUBLIC_ACLS)

    @ignore_public_acls.setter
    def ignore_public_acls(self, value: bool) -> None:
        self._set_metadata_bool(ResourceMetadata.IGNORE_PUBLIC_ACLS, value)

    @property
    def restrict_public_buckets(self) -> bool:
        return self._metadata_bool(ResourceMetadata.RESTRICT_PUBLIC_BUCKETS)

    @restrict_public_buckets.setter
    def restrict_public_buckets(self, value: bool) -> None:
        self._set_metadata_bool(ResourceMetadata.RESTRICT_PUBLIC_BUCKETS, value)

    @property
    def trust_principals(self) -> list[str]:
        return self._metadata_string_list(ResourceMetadata.TRUST_PRINCIPALS)

    @trust_principals.setter
    def trust_principals(self, values: list[str]) -> None:
        self._set_metadata_string_list(ResourceMetadata.TRUST_PRINCIPALS, values)

    @property
    def trust_statements(self) -> list[dict[str, Any]]:
        return self._metadata_dict_list(ResourceMetadata.TRUST_STATEMENTS)

    @trust_statements.setter
    def trust_statements(self, values: list[dict[str, Any]]) -> None:
        self._set_metadata_dict_list(ResourceMetadata.TRUST_STATEMENTS, values)

    @property
    def resource_policy_source_addresses(self) -> list[str]:
        return self._metadata_string_list(ResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES)

    @resource_policy_source_addresses.setter
    def resource_policy_source_addresses(self, values: list[str]) -> None:
        self._set_metadata_string_list(ResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES, values)

    @property
    def policy_document(self) -> dict[str, Any]:
        return self._metadata_dict(ResourceMetadata.POLICY_DOCUMENT)

    @policy_document.setter
    def policy_document(self, value: dict[str, Any] | None) -> None:
        self._set_metadata_dict(ResourceMetadata.POLICY_DOCUMENT, value)

    @property
    def public_access_block(self) -> dict[str, bool] | None:
        return self._metadata_bool_dict(ResourceMetadata.PUBLIC_ACCESS_BLOCK)

    @public_access_block.setter
    def public_access_block(self, value: dict[str, bool] | None) -> None:
        self._set_metadata_bool_dict(ResourceMetadata.PUBLIC_ACCESS_BLOCK, value)

    @property
    def bucket_name(self) -> str | None:
        return self._metadata_optional_string(ResourceMetadata.BUCKET_NAME)

    @bucket_name.setter
    def bucket_name(self, value: str | None) -> None:
        self._set_metadata_optional_string(ResourceMetadata.BUCKET_NAME, value)

    @property
    def bucket_acl(self) -> str:
        return self._metadata_optional_string(ResourceMetadata.BUCKET_ACL) or ""

    @bucket_acl.setter
    def bucket_acl(self, value: str | None) -> None:
        self._set_metadata_optional_string(ResourceMetadata.BUCKET_ACL, value)

    @property
    def engine(self) -> str | None:
        return self._metadata_optional_string(ResourceMetadata.ENGINE)

    @engine.setter
    def engine(self, value: str | None) -> None:
        self._set_metadata_optional_string(ResourceMetadata.ENGINE, value)


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
