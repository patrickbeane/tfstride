from __future__ import annotations

import json
from collections import Counter
from typing import Any

from tfstride import __version__
from tfstride.filtering import finding_fingerprint
from tfstride.models import (
    AnalysisResult,
    EvidenceItem,
    Finding,
    IAMPolicyCondition,
    IAMPolicyStatement,
    NormalizedResource,
    Observation,
    ResourceInventory,
    SecurityGroupRule,
    Severity,
    TrustBoundary,
)

REPORT_KIND = "tfstride-threat-model-report"
REPORT_FORMAT_VERSION = "1.0"


class JsonReportRenderer:
    def render(self, result: AnalysisResult) -> str:
        payload = self._build_payload(result)
        return json.dumps(payload, indent=2) + "\n"

    def _build_payload(self, result: AnalysisResult) -> dict[str, Any]:
        filter_summary = result.filter_summary or {
            "total_findings": len(result.findings),
            "active_findings": len(result.findings),
            "suppressed_findings": 0,
            "baselined_findings": 0,
            "suppressions_path": None,
            "baseline_path": None,
        }
        severity_counts = Counter(finding.severity.value for finding in result.findings)
        return {
            "kind": REPORT_KIND,
            "version": REPORT_FORMAT_VERSION,
            "tool": {
                "name": "tfstride",
                "version": __version__,
            },
            "title": result.title,
            "analyzed_file": result.analyzed_file,
            "analyzed_path": result.analyzed_path,
            "summary": {
                "normalized_resources": len(result.inventory.resources),
                "unsupported_resources": len(result.inventory.unsupported_resources),
                "trust_boundaries": len(result.trust_boundaries),
                "active_findings": len(result.findings),
                "total_findings": filter_summary.get("total_findings", len(result.findings)),
                "suppressed_findings": filter_summary.get("suppressed_findings", 0),
                "baselined_findings": filter_summary.get("baselined_findings", 0),
                "severity_counts": {
                    "high": severity_counts.get(Severity.HIGH.value, 0),
                    "medium": severity_counts.get(Severity.MEDIUM.value, 0),
                    "low": severity_counts.get(Severity.LOW.value, 0),
                },
            },
            "filtering": dict(filter_summary),
            "inventory": _serialize_inventory(result.inventory),
            "trust_boundaries": [
                _serialize_trust_boundary(boundary)
                for boundary in sorted(result.trust_boundaries, key=lambda boundary: boundary.identifier)
            ],
            "findings": [_serialize_finding(finding) for finding in result.findings],
            "suppressed_findings": [_serialize_finding(finding) for finding in result.suppressed_findings],
            "baselined_findings": [_serialize_finding(finding) for finding in result.baselined_findings],
            "observations": [
                _serialize_observation(observation)
                for observation in sorted(
                    result.observations,
                    key=lambda observation: ((observation.category or ""), observation.title, observation.observation_id),
                )
            ],
            "limitations": list(result.limitations),
        }


def _serialize_inventory(inventory: ResourceInventory) -> dict[str, Any]:
    return {
        "provider": inventory.provider,
        "unsupported_resources": list(inventory.unsupported_resources),
        "metadata": dict(inventory.metadata),
        "resources": [_serialize_resource(resource) for resource in sorted(inventory.resources, key=lambda resource: resource.address)],
    }


def _serialize_resource(resource: NormalizedResource) -> dict[str, Any]:
    return {
        "address": resource.address,
        "provider": resource.provider,
        "resource_type": resource.resource_type,
        "name": resource.name,
        "category": resource.category.value,
        "identifier": resource.identifier,
        "arn": resource.arn,
        "vpc_id": resource.vpc_id,
        "subnet_ids": list(resource.subnet_ids),
        "security_group_ids": list(resource.security_group_ids),
        "attached_role_arns": list(resource.attached_role_arns),
        "network_rules": [_serialize_security_group_rule(rule) for rule in resource.network_rules],
        "policy_statements": [_serialize_policy_statement(statement) for statement in resource.policy_statements],
        "public_access_configured": resource.public_access_configured,
        "public_exposure": resource.public_exposure,
        "data_sensitivity": resource.data_sensitivity,
        "metadata": dict(resource.metadata),
    }


def _serialize_security_group_rule(rule: SecurityGroupRule) -> dict[str, Any]:
    return {
        "direction": rule.direction,
        "protocol": rule.protocol,
        "from_port": rule.from_port,
        "to_port": rule.to_port,
        "cidr_blocks": list(rule.cidr_blocks),
        "ipv6_cidr_blocks": list(rule.ipv6_cidr_blocks),
        "referenced_security_group_ids": list(rule.referenced_security_group_ids),
        "description": rule.description,
    }


def _serialize_policy_statement(statement: IAMPolicyStatement) -> dict[str, Any]:
    return {
        "effect": statement.effect,
        "actions": list(statement.actions),
        "resources": list(statement.resources),
        "principals": list(statement.principals),
        "conditions": [_serialize_policy_condition(condition) for condition in statement.conditions],
    }


def _serialize_policy_condition(condition: IAMPolicyCondition) -> dict[str, Any]:
    return {
        "operator": condition.operator,
        "key": condition.key,
        "values": list(condition.values),
    }


def _serialize_trust_boundary(boundary: TrustBoundary) -> dict[str, Any]:
    return {
        "identifier": boundary.identifier,
        "boundary_type": boundary.boundary_type.value,
        "source": boundary.source,
        "target": boundary.target,
        "description": boundary.description,
        "rationale": boundary.rationale,
    }


def _serialize_finding(finding: Finding) -> dict[str, Any]:
    return {
        "fingerprint": finding_fingerprint(finding),
        "title": finding.title,
        "rule_id": finding.rule_id,
        "category": finding.category.value,
        "severity": finding.severity.value,
        "affected_resources": list(finding.affected_resources),
        "trust_boundary_id": finding.trust_boundary_id,
        "rationale": finding.rationale,
        "recommended_mitigation": finding.recommended_mitigation,
        "evidence": _serialize_evidence(finding.evidence),
        "severity_reasoning": _serialize_severity_reasoning(finding),
    }


def _serialize_observation(observation: Observation) -> dict[str, Any]:
    return {
        "title": observation.title,
        "observation_id": observation.observation_id,
        "affected_resources": list(observation.affected_resources),
        "rationale": observation.rationale,
        "category": observation.category,
        "evidence": _serialize_evidence(observation.evidence),
    }


def _serialize_evidence(evidence: list[EvidenceItem]) -> list[dict[str, Any]]:
    return [{"key": item.key, "values": list(item.values)} for item in evidence]


def _serialize_severity_reasoning(finding: Finding) -> dict[str, Any] | None:
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
