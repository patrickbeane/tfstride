from __future__ import annotations

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

    def has_wildcard_action(self) -> bool:
        return any(action == "*" or action.endswith(":*") for action in self.actions)

    def has_wildcard_resource(self) -> bool:
        return any(resource == "*" for resource in self.resources)


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
    public_exposure: bool = False
    data_sensitivity: str = "standard"
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def display_name(self) -> str:
        return f"{self.resource_type}.{self.name}"


@dataclass(slots=True)
class ResourceInventory:
    provider: str
    resources: list[NormalizedResource]
    unsupported_resources: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def by_type(self, *resource_types: str) -> list[NormalizedResource]:
        allowed = set(resource_types)
        return [resource for resource in self.resources if resource.resource_type in allowed]

    def get_by_address(self, address: str) -> NormalizedResource | None:
        for resource in self.resources:
            if resource.address == address:
                return resource
        return None

    def get_by_identifier(self, identifier: str) -> NormalizedResource | None:
        for resource in self.resources:
            if resource.identifier == identifier or resource.arn == identifier or resource.address == identifier:
                return resource
        return None


@dataclass(slots=True)
class TrustBoundary:
    identifier: str
    boundary_type: BoundaryType
    source: str
    target: str
    description: str
    rationale: str


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


@dataclass(slots=True)
class AnalysisResult:
    title: str
    analyzed_file: str
    inventory: ResourceInventory
    trust_boundaries: list[TrustBoundary]
    findings: list[Finding]
    limitations: list[str] = field(default_factory=list)
