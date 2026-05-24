from __future__ import annotations

from tfstride.models import EvidenceItem, Finding
from tfstride.reporting.report_contract import EvidenceItemPayload, SeverityReasoningPayload


def serialize_evidence(evidence: list[EvidenceItem]) -> list[EvidenceItemPayload]:
    return [{"key": item.key, "values": list(item.values)} for item in evidence]


def serialize_severity_reasoning(finding: Finding) -> SeverityReasoningPayload | None:
    if finding.severity_reasoning is None:
        return None
    return {
        "internet_exposure": finding.severity_reasoning.internet_exposure,
        "privilege_breadth": finding.severity_reasoning.privilege_breadth,
        "data_sensitivity": finding.severity_reasoning.data_sensitivity,
        "lateral_movement": finding.severity_reasoning.lateral_movement,
        "blast_radius": finding.severity_reasoning.blast_radius,
        "final_score": finding.severity_reasoning.final_score,
        "severity": finding.severity_reasoning.severity.value,
        "computed_severity": (
            finding.severity_reasoning.computed_severity.value
            if finding.severity_reasoning.computed_severity is not None
            else None
        ),
    }