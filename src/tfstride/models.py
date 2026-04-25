from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


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
class IAMPolicyStatement:
    effect: str
    actions: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    principals: list[str] = field(default_factory=list)
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
    # but expose them through typed accessors so analysis code stops depending on raw keys.
    def _metadata_bool(self, key: str, *, default: bool = False) -> bool:
        return bool(self.metadata.get(key, default))

    def _set_metadata_bool(self, key: str, value: bool) -> None:
        self.metadata[key] = bool(value)

    def _metadata_string_list(self, key: str) -> list[str]:
        values = self.metadata.get(key)
        if not isinstance(values, list):
            return []
        return [str(value) for value in values if value not in (None, "")]

    def _set_metadata_string_list(self, key: str, values: list[str]) -> None:
        self.metadata[key] = [str(value) for value in values if value not in (None, "")]

    def _metadata_optional_string(self, key: str) -> str | None:
	    value = self.metadata.get(key)
	    if value is None:
	        return None
	    text = str(value).strip()
	    return text or None
	
    def _set_metadata_optional_string(self, key: str, value: str | None) -> None:
	    if value is None or not str(value).strip():
	        self.metadata.pop(key, None)
	        return
	    self.metadata[key] = str(value).strip()

    def _metadata_optional_int(self, key: str) -> int | None:
	    value = self.metadata.get(key)
	    if value is None or value == "":
	        return None
	    try:
	        return int(value)
	    except (TypeError, ValueError):
	        return None
	
    def _set_metadata_optional_int(self, key: str, value: int | None) -> None:
	    if value is None:
	        self.metadata.pop(key, None)
	        return
	    self.metadata[key] = int(value)
	
    def _metadata_dict(self, key: str) -> dict[str, Any]:
	    value = self.metadata.get(key)
	    if not isinstance(value, dict):
	        return {}
	    return deepcopy(value)
	
    def _set_metadata_dict(self, key: str, value: dict[str, Any] | None) -> None:
	    if value is None:
	        self.metadata.pop(key, None)
	        return
	    self.metadata[key] = deepcopy(value)
	
    def _metadata_dict_list(self, key: str) -> list[dict[str, Any]]:
	    values = self.metadata.get(key)
	    if not isinstance(values, list):
	        return []
	    return [deepcopy(value) for value in values if isinstance(value, dict)]
	
    def _set_metadata_dict_list(self, key: str, values: list[dict[str, Any]]) -> None:
	    self.metadata[key] = [deepcopy(value) for value in values if isinstance(value, dict)]

    @property
    def direct_internet_reachable(self) -> bool:
        return self._metadata_bool("direct_internet_reachable")

    @direct_internet_reachable.setter
    def direct_internet_reachable(self, value: bool) -> None:
        self._set_metadata_bool("direct_internet_reachable", value)

    @property
    def internet_ingress_capable(self) -> bool:
        return self._metadata_bool("internet_ingress_capable")

    @internet_ingress_capable.setter
    def internet_ingress_capable(self, value: bool) -> None:
        self._set_metadata_bool("internet_ingress_capable", value)

    @property
    def in_public_subnet(self) -> bool:
        return self._metadata_bool("in_public_subnet")

    @in_public_subnet.setter
    def in_public_subnet(self, value: bool) -> None:
        self._set_metadata_bool("in_public_subnet", value)

    @property
    def has_nat_gateway_egress(self) -> bool:
        return self._metadata_bool("has_nat_gateway_egress")

    @has_nat_gateway_egress.setter
    def has_nat_gateway_egress(self, value: bool) -> None:
        self._set_metadata_bool("has_nat_gateway_egress", value)

    @property
    def is_public_subnet(self) -> bool:
        return self._metadata_bool("is_public_subnet")

    @is_public_subnet.setter
    def is_public_subnet(self, value: bool) -> None:
        self._set_metadata_bool("is_public_subnet", value)

    @property
    def has_public_route(self) -> bool:
        return self._metadata_bool("has_public_route")

    @has_public_route.setter
    def has_public_route(self, value: bool) -> None:
        self._set_metadata_bool("has_public_route", value)

    @property
    def vpc_enabled(self) -> bool:
        return self._metadata_bool("vpc_enabled", default=True)

    @vpc_enabled.setter
    def vpc_enabled(self, value: bool) -> None:
        self._set_metadata_bool("vpc_enabled", value)

    @property
    def storage_encrypted(self) -> bool:
        return self._metadata_bool("storage_encrypted")

    @storage_encrypted.setter
    def storage_encrypted(self, value: bool) -> None:
        self._set_metadata_bool("storage_encrypted", value)

    @property
    def publicly_accessible(self) -> bool:
        return self._metadata_bool("publicly_accessible")

    @publicly_accessible.setter
    def publicly_accessible(self, value: bool) -> None:
        self._set_metadata_bool("publicly_accessible", value)

    @property
    def public_access_reasons(self) -> list[str]:
        return self._metadata_string_list("public_access_reasons")

    @public_access_reasons.setter
    def public_access_reasons(self, values: list[str]) -> None:
        self._set_metadata_string_list("public_access_reasons", values)

    @property
    def public_exposure_reasons(self) -> list[str]:
        return self._metadata_string_list("public_exposure_reasons")

    @public_exposure_reasons.setter
    def public_exposure_reasons(self, values: list[str]) -> None:
        self._set_metadata_string_list("public_exposure_reasons", values)

    @property
    def internet_ingress_reasons(self) -> list[str]:
        return self._metadata_string_list("internet_ingress_reasons")

    @internet_ingress_reasons.setter
    def internet_ingress_reasons(self, values: list[str]) -> None:
        self._set_metadata_string_list("internet_ingress_reasons", values)

    @property
    def security_group_id(self) -> str | None:
	    return self._metadata_optional_string("security_group_id")
	
    @security_group_id.setter
    def security_group_id(self, value: str | None) -> None:
	    self._set_metadata_optional_string("security_group_id", value)

    @property
    def role_reference(self) -> str | None:
	    return self._metadata_optional_string("role")
	
    @role_reference.setter
    def role_reference(self, value: str | None) -> None:
	    self._set_metadata_optional_string("role", value)
	
    @property
    def role_references(self) -> list[str]:
	    return self._metadata_string_list("role_references")
	
    @role_references.setter
    def role_references(self, values: list[str]) -> None:
	    self._set_metadata_string_list("role_references", values)
	
    @property
    def resolved_role_references(self) -> list[str]:
	    return self._metadata_string_list("resolved_role_references")
	
    @resolved_role_references.setter
    def resolved_role_references(self, values: list[str]) -> None:
	    self._set_metadata_string_list("resolved_role_references", values)
	
    @property
    def iam_instance_profile(self) -> str | None:
	    return self._metadata_optional_string("iam_instance_profile")
	
    @iam_instance_profile.setter
    def iam_instance_profile(self, value: str | None) -> None:
	    self._set_metadata_optional_string("iam_instance_profile", value)
	
    @property
    def policy_arn(self) -> str | None:
	    return self._metadata_optional_string("policy_arn")
	
    @policy_arn.setter
    def policy_arn(self, value: str | None) -> None:
	    self._set_metadata_optional_string("policy_arn", value)
	
    @property
    def policy_name(self) -> str | None:
	    return self._metadata_optional_string("policy_name")
	
    @policy_name.setter
    def policy_name(self, value: str | None) -> None:
	    self._set_metadata_optional_string("policy_name", value)
	
    @property
    def cluster_reference(self) -> str | None:
	        return self._metadata_optional_string("cluster")
	
    @cluster_reference.setter
    def cluster_reference(self, value: str | None) -> None:
        self._set_metadata_optional_string("cluster", value)
	
    @property
    def cluster_name(self) -> str | None:
        return self._metadata_optional_string("name")
	
    @cluster_name.setter
    def cluster_name(self, value: str | None) -> None:
        self._set_metadata_optional_string("name", value)
	
    @property
    def task_definition_reference(self) -> str | None:
        return self._metadata_optional_string("task_definition")
	
    @task_definition_reference.setter
    def task_definition_reference(self, value: str | None) -> None:
        self._set_metadata_optional_string("task_definition", value)
	
    @property
    def task_definition_family(self) -> str | None:
        return self._metadata_optional_string("family")
	
    @task_definition_family.setter
    def task_definition_family(self, value: str | None) -> None:
        self._set_metadata_optional_string("family", value)
	
    @property
    def task_definition_revision(self) -> int | None:
        return self._metadata_optional_int("revision")
	
    @task_definition_revision.setter
    def task_definition_revision(self, value: int | None) -> None:
        self._set_metadata_optional_int("revision", value)
	
    @property
    def network_mode(self) -> str | None:
        return self._metadata_optional_string("network_mode")
	
    @network_mode.setter
    def network_mode(self, value: str | None) -> None:
        self._set_metadata_optional_string("network_mode", value)
	
    @property
    def requires_compatibilities(self) -> list[str]:
        return self._metadata_string_list("requires_compatibilities")
	
    @requires_compatibilities.setter
    def requires_compatibilities(self, values: list[str]) -> None:
	    self._set_metadata_string_list("requires_compatibilities", values)
	
    @property
    def task_role_arn(self) -> str | None:
	    return self._metadata_optional_string("task_role_arn")
	
    @task_role_arn.setter
    def task_role_arn(self, value: str | None) -> None:
	    self._set_metadata_optional_string("task_role_arn", value)
	
    @property
    def execution_role_arn(self) -> str | None:
	    return self._metadata_optional_string("execution_role_arn")
	
    @execution_role_arn.setter
    def execution_role_arn(self, value: str | None) -> None:
	    self._set_metadata_optional_string("execution_role_arn", value)
	
    @property
    def secret_arn(self) -> str | None:
	    return self._metadata_optional_string("secret_arn")
	
    @secret_arn.setter
    def secret_arn(self, value: str | None) -> None:
	    self._set_metadata_optional_string("secret_arn", value)
	
    @property
    def function_name(self) -> str | None:
	    return self._metadata_optional_string("function_name")
	
    @function_name.setter
    def function_name(self, value: str | None) -> None:
	    self._set_metadata_optional_string("function_name", value)
	
    @property
    def secret_name(self) -> str | None:
	    return self._metadata_optional_string("name")
	
    @secret_name.setter
    def secret_name(self, value: str | None) -> None:
	    self._set_metadata_optional_string("name", value)
	
    @property
    def route_table_id(self) -> str | None:
	    return self._metadata_optional_string("route_table_id")
	
    @route_table_id.setter
    def route_table_id(self, value: str | None) -> None:
	    self._set_metadata_optional_string("route_table_id", value)
	
    @property
    def subnet_id(self) -> str | None:
	    return self._metadata_optional_string("subnet_id")
	
    @subnet_id.setter
    def subnet_id(self, value: str | None) -> None:
	    self._set_metadata_optional_string("subnet_id", value)
	
    @property
    def routes(self) -> list[dict[str, Any]]:
	    return self._metadata_dict_list("routes")
	
    @routes.setter
    def routes(self, values: list[dict[str, Any]]) -> None:
	    self._set_metadata_dict_list("routes", values)
	
    @property
    def map_public_ip_on_launch(self) -> bool:
	    return self._metadata_bool("map_public_ip_on_launch")
	
    @map_public_ip_on_launch.setter
    def map_public_ip_on_launch(self, value: bool) -> None:
	    self._set_metadata_bool("map_public_ip_on_launch", value)
	
    @property
    def block_public_acls(self) -> bool:
	    return self._metadata_bool("block_public_acls")
	
    @block_public_acls.setter
    def block_public_acls(self, value: bool) -> None:
	    self._set_metadata_bool("block_public_acls", value)
	
    @property
    def block_public_policy(self) -> bool:
        return self._metadata_bool("block_public_policy")
	
    @block_public_policy.setter
    def block_public_policy(self, value: bool) -> None:
	    self._set_metadata_bool("block_public_policy", value)
	
    @property
    def ignore_public_acls(self) -> bool:
	    return self._metadata_bool("ignore_public_acls")
	
    @ignore_public_acls.setter
    def ignore_public_acls(self, value: bool) -> None:
        self._set_metadata_bool("ignore_public_acls", value)
	
    @property
    def restrict_public_buckets(self) -> bool:
	    return self._metadata_bool("restrict_public_buckets")
	
    @restrict_public_buckets.setter
    def restrict_public_buckets(self, value: bool) -> None:
	    self._set_metadata_bool("restrict_public_buckets", value)

    @property
    def trust_principals(self) -> list[str]:
	    return self._metadata_string_list("trust_principals")
	
    @trust_principals.setter
    def trust_principals(self, values: list[str]) -> None:
	    self._set_metadata_string_list("trust_principals", values)
	
    @property
    def trust_statements(self) -> list[dict[str, Any]]:
	    return self._metadata_dict_list("trust_statements")
	
    @trust_statements.setter
    def trust_statements(self, values: list[dict[str, Any]]) -> None:
	    self._set_metadata_dict_list("trust_statements", values)
	
    @property
    def resource_policy_source_addresses(self) -> list[str]:
        return self._metadata_string_list("resource_policy_source_addresses")
	
    @resource_policy_source_addresses.setter
    def resource_policy_source_addresses(self, values: list[str]) -> None:
        self._set_metadata_string_list("resource_policy_source_addresses", values)
	
    @property
    def policy_document(self) -> dict[str, Any]:
        return self._metadata_dict("policy_document")
	
    @policy_document.setter
    def policy_document(self, value: dict[str, Any] | None) -> None:
        self._set_metadata_dict("policy_document", value)
	
    @property
    def public_access_block(self) -> dict[str, bool] | None:
        value = self.metadata.get("public_access_block")
        if not isinstance(value, dict):
            return None
        return {str(key): bool(item) for key, item in value.items()}
	
    @public_access_block.setter
    def public_access_block(self, value: dict[str, bool] | None) -> None:
        if value is None:
            self.metadata.pop("public_access_block", None)
            return
        self.metadata["public_access_block"] = {str(key): bool(item) for key, item in value.items()}
	
    @property
    def bucket_name(self) -> str | None:
        return self._metadata_optional_string("bucket")
	
    @bucket_name.setter
    def bucket_name(self, value: str | None) -> None:
        self._set_metadata_optional_string("bucket", value)
	
    @property
    def bucket_acl(self) -> str:
        return self._metadata_optional_string("acl") or ""
	
    @bucket_acl.setter
    def bucket_acl(self, value: str | None) -> None:
        self._set_metadata_optional_string("acl", value)
	
    @property
    def engine(self) -> str | None:
        return self._metadata_optional_string("engine")
	
    @engine.setter
    def engine(self, value: str | None) -> None:
        self._set_metadata_optional_string("engine", value)


@dataclass(slots=True)
class ResourceInventory:
    provider: str
    resources: list[NormalizedResource]
    unsupported_resources: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    _resources_by_type: dict[str, tuple[NormalizedResource, ...]] = field(init=False, repr=False, default_factory=dict)
    _resources_by_address: dict[str, NormalizedResource] = field(init=False, repr=False, default_factory=dict)
    _resources_by_identifier: dict[str, NormalizedResource] = field(init=False, repr=False, default_factory=dict)
    _resource_positions: dict[int, int] = field(init=False, repr=False, default_factory=dict)
	
    def __post_init__(self) -> None:
	    resources_by_type: dict[str, list[NormalizedResource]] = {}
	    resources_by_address: dict[str, NormalizedResource] = {}
	    resources_by_identifier: dict[str, NormalizedResource] = {}
	    resource_positions: dict[int, int] = {}
	
	    for index, resource in enumerate(self.resources):
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
        value = self.metadata.get("primary_account_id")
        if value is None:
            return None
        text = str(value).strip()
        return text or None
	
    @primary_account_id.setter
    def primary_account_id(self, value: str | None) -> None:
        if value is None or not str(value).strip():
            self.metadata.pop("primary_account_id", None)
            return
        self.metadata["primary_account_id"] = str(value).strip()

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
    limitations: list[str] = field(default_factory=list)
