from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Any

from tfstride.app import TfStride
from tfstride.reporting.json_report import render_json
from tfstride.reporting.report_contract import (
    EvidenceItemPayload,
    FindingPayload,
    ObservationPayload,
    PolicyConditionPayload,
    SeverityReasoningPayload,
    UnresolvedReferencePayload,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "fixtures" / "aws" / "sample_aws_plan.json"
GOLDEN_DIR = Path(__file__).resolve().parent / "golden"
REPORT_SCHEMA_PATH = GOLDEN_DIR / "sample_aws_report_schema.json"
REPORT_SNAPSHOT_PATH = GOLDEN_DIR / "sample_aws_report_snapshot.json"


def _sample_report_payload() -> dict[str, Any]:
    return json.loads(render_json(TfStride().analyze_plan(FIXTURE_PATH)))


def _key_schema(payload: dict[str, Any]) -> dict[str, list[str]]:
    resources = payload["inventory"]["resources"]
    policy_statements = [statement for resource in resources for statement in resource["policy_statements"]]
    network_rules = [rule for resource in resources for rule in resource["network_rules"]]
    policy_statement_with_principal = next(
        statement for statement in policy_statements if statement["principal_entries"]
    )
    finding_with_evidence = next(finding for finding in payload["findings"] if finding["evidence"])

    return {
        "root": list(payload),
        "tool": list(payload["tool"]),
        "summary": list(payload["summary"]),
        "summary.severity_counts": list(payload["summary"]["severity_counts"]),
        "filtering": list(payload["filtering"]),
        "analysis_coverage": list(payload["analysis_coverage"]),
        "analysis_coverage.resources": list(payload["analysis_coverage"]["resources"]),
        "analysis_coverage.rules": list(payload["analysis_coverage"]["rules"]),
        "analysis_coverage.references": list(payload["analysis_coverage"]["references"]),
        "analysis_coverage.references.unresolved_references[]": list(UnresolvedReferencePayload.__annotations__),
        "inventory": list(payload["inventory"]),
        "inventory.resources[]": list(resources[0]),
        "inventory.resources[].network_rules[]": list(network_rules[0]),
        "inventory.resources[].policy_statements[]": list(policy_statements[0]),
        "inventory.resources[].policy_statements[].principal_entries[]": list(
            policy_statement_with_principal["principal_entries"][0]
        ),
        "inventory.resources[].policy_statements[].conditions[]": list(PolicyConditionPayload.__annotations__),
        "trust_boundaries[]": list(payload["trust_boundaries"][0]),
        "findings[]": list(payload["findings"][0]),
        "findings[].evidence[]": list(finding_with_evidence["evidence"][0]),
        "findings[].severity_reasoning": list(SeverityReasoningPayload.__annotations__),
        "suppressed_findings[]": list(FindingPayload.__annotations__),
        "baselined_findings[]": list(FindingPayload.__annotations__),
        "observations[]": list(ObservationPayload.__annotations__),
        "observations[].evidence[]": list(EvidenceItemPayload.__annotations__),
    }


def _report_snapshot(payload: dict[str, Any]) -> dict[str, Any]:
    coverage = payload["analysis_coverage"]
    return {
        "kind": payload["kind"],
        "report_version": payload["version"],
        "tool_name": payload["tool"]["name"],
        "title": payload["title"],
        "analyzed_file": payload["analyzed_file"],
        "summary": payload["summary"],
        "filtering": payload["filtering"],
        "analysis_coverage": {
            "resources": coverage["resources"],
            "rules": {
                "registered_rule_count": coverage["rules"]["registered_rule_count"],
                "enabled_rules": coverage["rules"]["enabled_rules"],
                "disabled_rules": coverage["rules"]["disabled_rules"],
                "severity_overrides": coverage["rules"]["severity_overrides"],
                "finding_counts_by_rule": coverage["rules"]["finding_counts_by_rule"],
            },
            "references": coverage["references"],
        },
        "inventory": {
            "provider": payload["inventory"]["provider"],
            "unsupported_resources": payload["inventory"]["unsupported_resources"],
            "metadata": payload["inventory"]["metadata"],
            "resource_addresses": [resource["address"] for resource in payload["inventory"]["resources"]],
            "resource_types_by_address": {
                resource["address"]: resource["resource_type"] for resource in payload["inventory"]["resources"]
            },
        },
        "trust_boundaries": [
            {
                "identifier": boundary["identifier"],
                "boundary_type": boundary["boundary_type"],
                "source": boundary["source"],
                "target": boundary["target"],
            }
            for boundary in payload["trust_boundaries"]
        ],
        "findings": [
            {
                "rule_id": finding["rule_id"],
                "title": finding["title"],
                "category": finding["category"],
                "severity": finding["severity"],
                "affected_resources": finding["affected_resources"],
                "trust_boundary_id": finding["trust_boundary_id"],
            }
            for finding in payload["findings"]
        ],
        "observations": [
            {
                "observation_id": observation["observation_id"],
                "title": observation["title"],
                "category": observation["category"],
                "affected_resources": observation["affected_resources"],
            }
            for observation in payload["observations"]
        ],
        "limitations": payload["limitations"],
    }


def _read_golden(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


class JsonReportGoldenTests(unittest.TestCase):
    maxDiff = None

    def test_sample_aws_json_report_schema_matches_golden_contract(self) -> None:
        self.assertEqual(_key_schema(_sample_report_payload()), _read_golden(REPORT_SCHEMA_PATH))

    def test_sample_aws_json_report_snapshot_matches_golden_contract(self) -> None:
        self.assertEqual(_report_snapshot(_sample_report_payload()), _read_golden(REPORT_SNAPSHOT_PATH))


if __name__ == "__main__":
    unittest.main()
