from __future__ import annotations

from typing import Any

try:
    from typing_extensions import TypedDict
except ImportError:  # pragma: no cover
    from typing import TypedDict


class ToolInfoPayload(TypedDict):
    name: str
    version: str


class SeverityCountsPayload(TypedDict):
    high: int
    medium: int
    low: int


class ReportSummaryPayload(TypedDict):
    normalized_resources: int
    unsupported_resources: int
    trust_boundaries: int
    active_findings: int
    total_findings: int
    suppressed_findings: int
    baselined_findings: int
    severity_counts: SeverityCountsPayload


class FilteringSummaryPayload(TypedDict):
    total_findings: int
    active_findings: int
    suppressed_findings: int
    baselined_findings: int
    suppressions_path: str | None
    baseline_path: str | None


class ResourceCoveragePayload(TypedDict):
    total_resources: int
    provider_resources: int
    normalized_resources: int
    unsupported_resources: int
    unsupported_resource_types: dict[str, int]


class RuleCoveragePayload(TypedDict):
    registered_rule_count: int
    enabled_rules: list[str]
    disabled_rules: list[str]
    severity_overrides: dict[str, str]
    finding_counts_by_rule: dict[str, int]


class UnresolvedReferencePayload(TypedDict):
    resource: str
    references: dict[str, list[str]]


class ReferenceCoveragePayload(TypedDict):
    unresolved_reference_count: int
    unresolved_references: list[UnresolvedReferencePayload]


class AnalysisCoveragePayload(TypedDict):
    resources: ResourceCoveragePayload
    rules: RuleCoveragePayload
    references: ReferenceCoveragePayload


class SecurityGroupRulePayload(TypedDict):
    direction: str
    protocol: str
    from_port: int | None
    to_port: int | None
    cidr_blocks: list[str]
    ipv6_cidr_blocks: list[str]
    referenced_security_group_ids: list[str]
    description: str | None


class PolicyConditionPayload(TypedDict):
    operator: str
    key: str
    values: list[str]


class PrincipalPayload(TypedDict):
    kind: str
    value: str


class PolicyStatementPayload(TypedDict):
    effect: str
    actions: list[str]
    resources: list[str]
    principals: list[str]
    principal_entries: list[PrincipalPayload]
    conditions: list[PolicyConditionPayload]


class NormalizedResourcePayload(TypedDict):
    address: str
    provider: str
    resource_type: str
    name: str
    category: str
    identifier: str | None
    arn: str | None
    vpc_id: str | None
    subnet_ids: list[str]
    security_group_ids: list[str]
    attached_role_arns: list[str]
    network_rules: list[SecurityGroupRulePayload]
    policy_statements: list[PolicyStatementPayload]
    public_access_configured: bool
    public_exposure: bool
    data_sensitivity: str
    metadata: dict[str, Any]


class InventoryPayload(TypedDict):
    provider: str
    unsupported_resources: list[str]
    metadata: dict[str, Any]
    resources: list[NormalizedResourcePayload]


class TrustBoundaryPayload(TypedDict):
    identifier: str
    boundary_type: str
    source: str
    target: str
    description: str
    rationale: str


class EvidenceItemPayload(TypedDict):
    key: str
    values: list[str]


class SeverityReasoningPayload(TypedDict):
    internet_exposure: int
    privilege_breadth: int
    data_sensitivity: int
    lateral_movement: int
    blast_radius: int
    final_score: int
    severity: str
    computed_severity: str | None


class FindingPayload(TypedDict):
    fingerprint: str
    title: str
    rule_id: str
    category: str
    severity: str
    affected_resources: list[str]
    trust_boundary_id: str | None
    rationale: str
    recommended_mitigation: str
    evidence: list[EvidenceItemPayload]
    severity_reasoning: SeverityReasoningPayload | None


class ObservationPayload(TypedDict):
    title: str
    observation_id: str
    affected_resources: list[str]
    rationale: str
    category: str | None
    evidence: list[EvidenceItemPayload]


class TFSReportPayload(TypedDict):
    kind: str
    version: str
    tool: ToolInfoPayload
    title: str
    analyzed_file: str
    analyzed_path: str
    summary: ReportSummaryPayload
    filtering: FilteringSummaryPayload
    inventory: InventoryPayload
    analysis_coverage: AnalysisCoveragePayload
    trust_boundaries: list[TrustBoundaryPayload]
    findings: list[FindingPayload]
    suppressed_findings: list[FindingPayload]
    baselined_findings: list[FindingPayload]
    observations: list[ObservationPayload]
    limitations: list[str]
