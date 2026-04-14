from __future__ import annotations

import json
from pathlib import Path

from tfstride import __version__
from tfstride.analysis.rule_registry import get_rule
from tfstride.models import AnalysisResult, EvidenceItem, Finding, Severity


SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
SARIF_LEVELS = {
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}
SARIF_TAGS = ["terraform", "cloud", "threat-modeling"]


class SarifReportRenderer:
    def render(self, result: AnalysisResult) -> str:
        payload = self._build_sarif_log(result)
        return json.dumps(payload, indent=2) + "\n"

    def _build_sarif_log(self, result: AnalysisResult) -> dict[str, object]:
        rules = self._build_rules(result.findings)
        rule_indexes = {rule["id"]: index for index, rule in enumerate(rules)}
        return {
            "$schema": SARIF_SCHEMA_URI,
            "version": SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "tfstride",
                            "semanticVersion": __version__,
                            "rules": rules,
                        }
                    },
                    "results": [
                        self._build_result(finding, rule_indexes, result)
                        for finding in result.findings
                    ],
                }
            ],
        }

    def _build_rules(self, findings: list[Finding]) -> list[dict[str, object]]:
        findings_by_rule: dict[str, list[Finding]] = {}
        for finding in findings:
            findings_by_rule.setdefault(finding.rule_id, []).append(finding)

        rules: list[dict[str, object]] = []
        for rule_id in sorted(findings_by_rule):
            rule_findings = findings_by_rule[rule_id]
            representative = rule_findings[0]
            metadata = get_rule(rule_id)
            default_level = SARIF_LEVELS[_highest_severity(rule_findings)]
            rules.append(
                {
                    "id": rule_id,
                    "name": metadata.title,
                    "shortDescription": {"text": metadata.title},
                    "fullDescription": {"text": representative.rationale},
                    "help": {"text": metadata.recommended_mitigation},
                    "defaultConfiguration": {"level": default_level},
                    "properties": {
                        "tags": [
                            representative.category.value,
                            representative.severity.value,
                            *metadata.tags,
                            *SARIF_TAGS,
                        ],
                    },
                }
            )
        return rules

    def _build_result(
        self,
        finding: Finding,
        rule_indexes: dict[str, int],
        analysis: AnalysisResult,
    ) -> dict[str, object]:
        result: dict[str, object] = {
            "ruleId": finding.rule_id,
            "ruleIndex": rule_indexes[finding.rule_id],
            "level": SARIF_LEVELS[finding.severity],
            "message": {"text": finding.title},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": _artifact_uri(analysis.analyzed_path),
                        }
                    }
                }
            ],
            "properties": {
                "title": finding.title,
                "severity": finding.severity.value,
                "stride_category": finding.category.value,
                "affected_resources": finding.affected_resources,
                "trust_boundary_id": finding.trust_boundary_id,
                "rationale": finding.rationale,
                "recommended_mitigation": finding.recommended_mitigation,
                "evidence": _serialize_evidence(finding.evidence),
                "severity_reasoning": _serialize_severity_reasoning(finding),
            },
        }
        return result


def _artifact_uri(path: str) -> str:
    return Path(path).as_posix()


def _serialize_evidence(evidence: list[EvidenceItem]) -> list[dict[str, object]]:
    return [{"key": item.key, "values": list(item.values)} for item in evidence]


def _serialize_severity_reasoning(finding: Finding) -> dict[str, object] | None:
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


def _highest_severity(findings: list[Finding]) -> Severity:
    order = {
        Severity.HIGH: 2,
        Severity.MEDIUM: 1,
        Severity.LOW: 0,
    }
    return max((finding.severity for finding in findings), key=lambda severity: order[severity])
