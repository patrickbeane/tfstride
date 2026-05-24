from __future__ import annotations

import json
from pathlib import Path

from tfstride import __version__
from tfstride.analysis.rule_registry import default_rule_metadata
from tfstride.models import AnalysisResult, Finding, Severity
from tfstride.reporting.finding_serialization import serialize_evidence, serialize_severity_reasoning


SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
SARIF_LEVELS = {
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}
SARIF_TAGS = ["terraform", "cloud", "threat-modeling"]


def render_sarif(result: AnalysisResult) -> str:
    payload = _build_sarif_log(result)
    return json.dumps(payload, indent=2) + "\n"


def _build_sarif_log(result: AnalysisResult) -> dict[str, object]:
    rules = _build_rules(result.findings)
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
                    _build_result(finding, rule_indexes, result)
                    for finding in result.findings
                ],
            }
        ],
    }


def _build_rules(findings: list[Finding]) -> list[dict[str, object]]:
    findings_by_rule: dict[str, list[Finding]] = {}
    for finding in findings:
        findings_by_rule.setdefault(finding.rule_id, []).append(finding)

    rules: list[dict[str, object]] = []
    for rule_id in sorted(findings_by_rule):
        rule_findings = findings_by_rule[rule_id]
        representative = rule_findings[0]
        metadata = default_rule_metadata(rule_id)
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
            "evidence": serialize_evidence(finding.evidence),
            "severity_reasoning": serialize_severity_reasoning(finding),
        },
    }
    return result


def _artifact_uri(path: str) -> str:
    return Path(path).as_posix()


def _highest_severity(findings: list[Finding]) -> Severity:
    return max((finding.severity for finding in findings), key=lambda severity: severity.rank)