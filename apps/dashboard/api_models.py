from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class DashboardApiErrorModel(BaseModel):
    kind: str = Field(description="Stable error kind for dashboard API failures.")
    message: str = Field(description="Human-readable error message.")


class ValidationDetailModel(BaseModel):
    loc: list[str | int] = Field(description="Location of the invalid or missing input.")
    msg: str = Field(description="Human-readable validation message.")
    type: str = Field(description="FastAPI or Pydantic validation error type.")
    input: Any | None = Field(default=None, description="Rejected input value when available.")
    ctx: dict[str, Any] | None = Field(default=None, description="Optional validation context.")


class ValidationErrorResponseModel(BaseModel):
    detail: list[ValidationDetailModel] = Field(description="One or more request validation issues.")


class HealthResponseModel(BaseModel):
    status: str = Field(description="Liveness status for the dashboard service.")


class ToolInfoModel(BaseModel):
    name: str = Field(description="Tool name.")
    version: str = Field(description="Tool version.")


class SeverityCountsModel(BaseModel):
    high: int = Field(description="Number of high-severity findings.")
    medium: int = Field(description="Number of medium-severity findings.")
    low: int = Field(description="Number of low-severity findings.")


class ReportSummaryModel(BaseModel):
    normalized_resources: int = Field(description="Count of normalized resources in the plan.")
    unsupported_resources: int = Field(description="Count of skipped unsupported resources.")
    trust_boundaries: int = Field(description="Count of derived trust boundaries.")
    active_findings: int = Field(description="Count of findings active after filtering.")
    total_findings: int = Field(description="Count of findings before filtering.")
    suppressed_findings: int = Field(description="Count of suppressed findings.")
    baselined_findings: int = Field(description="Count of baselined findings.")
    severity_counts: SeverityCountsModel = Field(description="Finding counts grouped by severity.")


class FilteringSummaryModel(BaseModel):
    total_findings: int = Field(description="Count of findings before filtering.")
    active_findings: int = Field(description="Count of findings after filtering.")
    suppressed_findings: int = Field(description="Count of suppressed findings.")
    baselined_findings: int = Field(description="Count of baselined findings.")
    suppressions_path: str | None = Field(default=None, description="Applied suppressions file, if any.")
    baseline_path: str | None = Field(default=None, description="Applied baseline file, if any.")


class SecurityGroupRuleModel(BaseModel):
    direction: str
    protocol: str
    from_port: int | None = None
    to_port: int | None = None
    cidr_blocks: list[str] = Field(default_factory=list)
    ipv6_cidr_blocks: list[str] = Field(default_factory=list)
    referenced_security_group_ids: list[str] = Field(default_factory=list)
    description: str | None = None


class PolicyConditionModel(BaseModel):
    operator: str
    key: str
    values: list[str] = Field(default_factory=list)


class PolicyStatementModel(BaseModel):
    effect: str
    actions: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    principals: list[str] = Field(default_factory=list)
    conditions: list[PolicyConditionModel] = Field(default_factory=list)


class NormalizedResourceModel(BaseModel):
    address: str
    provider: str
    resource_type: str
    name: str
    category: str
    identifier: str | None = None
    arn: str | None = None
    vpc_id: str | None = None
    subnet_ids: list[str] = Field(default_factory=list)
    security_group_ids: list[str] = Field(default_factory=list)
    attached_role_arns: list[str] = Field(default_factory=list)
    network_rules: list[SecurityGroupRuleModel] = Field(default_factory=list)
    policy_statements: list[PolicyStatementModel] = Field(default_factory=list)
    public_access_configured: bool = False
    public_exposure: bool = False
    data_sensitivity: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class InventoryModel(BaseModel):
    provider: str
    unsupported_resources: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    resources: list[NormalizedResourceModel] = Field(default_factory=list)


class TrustBoundaryModel(BaseModel):
    identifier: str
    boundary_type: str
    source: str
    target: str
    description: str
    rationale: str


class EvidenceItemModel(BaseModel):
    key: str
    values: list[str] = Field(default_factory=list)


class SeverityReasoningModel(BaseModel):
    internet_exposure: int
    privilege_breadth: int
    data_sensitivity: int
    lateral_movement: int
    blast_radius: int
    final_score: int
    severity: str
    computed_severity: str | None = None


class FindingModel(BaseModel):
    fingerprint: str
    title: str
    rule_id: str
    category: str
    severity: str
    affected_resources: list[str] = Field(default_factory=list)
    trust_boundary_id: str | None = None
    rationale: str
    recommended_mitigation: str
    evidence: list[EvidenceItemModel] = Field(default_factory=list)
    severity_reasoning: SeverityReasoningModel | None = None


class ObservationModel(BaseModel):
    title: str
    observation_id: str
    affected_resources: list[str] = Field(default_factory=list)
    rationale: str
    category: str | None = None
    evidence: list[EvidenceItemModel] = Field(default_factory=list)


class TfStrideReportModel(BaseModel):
    kind: str
    version: str
    tool: ToolInfoModel
    title: str
    analyzed_file: str
    analyzed_path: str
    summary: ReportSummaryModel
    filtering: FilteringSummaryModel
    inventory: InventoryModel
    trust_boundaries: list[TrustBoundaryModel] = Field(default_factory=list)
    findings: list[FindingModel] = Field(default_factory=list)
    suppressed_findings: list[FindingModel] = Field(default_factory=list)
    baselined_findings: list[FindingModel] = Field(default_factory=list)
    observations: list[ObservationModel] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
