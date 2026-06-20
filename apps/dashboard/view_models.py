from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from typing import Any

from fastapi import Request

from tfstride.reporting.report_contract import TFSReportPayload

_PROVIDER_DISPLAY_NAMES = {
    "aws": "AWS",
    "gcp": "GCP",
}


@dataclass(frozen=True, slots=True)
class DashboardAnalysis:
    payload: TFSReportPayload
    markdown_report: str


def _sanitize_dashboard_payload(payload: TFSReportPayload) -> TFSReportPayload:
    sanitized_payload = dict(payload)
    analyzed_file = sanitized_payload.get("analyzed_file")
    if isinstance(analyzed_file, str) and analyzed_file:
        sanitized_payload["analyzed_path"] = analyzed_file
    return sanitized_payload


def _base_context(
    request: Request,
    *,
    max_upload_bytes: int,
    page_title: str = "tfSTRIDE Dashboard",
    error: str | None = None,
    form_title: str = "tfSTRIDE Report",
    demo_scenarios: tuple[object, ...] = (),
    selected_provider: str = "aws",
) -> dict[str, object]:
    return {
        "request": request,
        "page_title": page_title,
        "error": error,
        "form_title": form_title,
        "max_upload_mebibytes": max_upload_bytes // (1024 * 1024),
        "demo_scenarios": demo_scenarios,
        "selected_provider": selected_provider,
    }


def _report_context(
    request: Request,
    analysis: DashboardAnalysis,
    *,
    scenario: object | None = None,
) -> dict[str, object]:
    payload = analysis.payload
    findings = payload["findings"]
    summary = payload["summary"]
    severity_counts = summary["severity_counts"]
    findings_by_severity = {
        severity: [finding for finding in findings if finding["severity"] == severity]
        for severity in ("high", "medium", "low")
    }
    summary_cards = [
        {"label": "Active findings", "value": summary["active_findings"]},
        {"label": "Trust boundaries", "value": summary["trust_boundaries"]},
        {"label": "Resources", "value": summary["normalized_resources"]},
        {"label": "Observations", "value": len(payload["observations"])},
    ]
    top_risks = [
        {"label": "High", "value": severity_counts["high"]},
        {"label": "Medium", "value": severity_counts["medium"]},
        {"label": "Low", "value": severity_counts["low"]},
    ]

    return {
        "request": request,
        "page_title": payload["title"],
        "payload": payload,
        "summary_cards": summary_cards,
        "top_risks": top_risks,
        "findings_by_severity": findings_by_severity,
        "unsupported_resources": payload["inventory"]["unsupported_resources"],
        **_coverage_context(payload),
        "raw_json": json.dumps(payload, indent=2),
        "raw_markdown": analysis.markdown_report,
        "scenario": scenario,
    }


def _coverage_context(payload: TFSReportPayload) -> dict[str, object]:
    analysis_coverage = _analysis_coverage_payload(payload)
    disabled_rules = list(analysis_coverage["rules"]["disabled_rules"])
    severity_overrides = [
        {"rule_id": rule_id, "severity": severity}
        for rule_id, severity in analysis_coverage["rules"]["severity_overrides"].items()
    ]
    unresolved_references = [
        {
            "resource": reference["resource"],
            "details": [
                {
                    "key": key,
                    "value_text": ", ".join(values),
                }
                for key, values in sorted(reference["references"].items())
            ],
        }
        for reference in analysis_coverage["references"]["unresolved_references"]
    ]
    return {
        "coverage_cards": [
            {"label": "Terraform resources", "value": analysis_coverage["resources"]["total_resources"]},
            {"label": "Unsupported", "value": analysis_coverage["resources"]["unsupported_resources"]},
            {"label": "Enabled rules", "value": len(analysis_coverage["rules"]["enabled_rules"])},
            {"label": "Unresolved refs", "value": analysis_coverage["references"]["unresolved_reference_count"]},
        ],
        "coverage_resource_stats": [
            {"label": "Provider resources considered", "value": analysis_coverage["resources"]["provider_resources"]},
            {"label": "Normalized resources", "value": analysis_coverage["resources"]["normalized_resources"]},
        ],
        "coverage_rule_stats": [
            {"label": "Registered rules", "value": analysis_coverage["rules"]["registered_rule_count"]},
            {"label": "Disabled rules", "value": len(disabled_rules)},
        ],
        "unsupported_resource_types": [
            {"resource_type": resource_type, "count": count}
            for resource_type, count in sorted(analysis_coverage["resources"]["unsupported_resource_types"].items())
        ],
        "unsupported_resource_types_empty_message": _unsupported_resource_types_empty_message(payload),
        "finding_counts_by_rule": [
            {"rule_id": rule_id, "count": count}
            for rule_id, count in analysis_coverage["rules"]["finding_counts_by_rule"].items()
            if count
        ],
        "disabled_rule_ids": disabled_rules,
        "severity_overrides": severity_overrides,
        "unresolved_references": unresolved_references,
    }


def _unsupported_resource_types_empty_message(payload: TFSReportPayload) -> str:
    provider = str(payload["inventory"].get("provider", "")).strip().lower()
    provider_display_name = _PROVIDER_DISPLAY_NAMES.get(provider)
    if provider_display_name is None:
        return "No unsupported resource types were encountered."
    return f"No unsupported {provider_display_name} resource types were encountered."


def _analysis_coverage_payload(payload: TFSReportPayload) -> dict[str, Any]:
    coverage = payload.get("analysis_coverage")
    if isinstance(coverage, dict):
        return coverage

    summary = payload["summary"]
    unsupported_resource_types = Counter(
        _resource_type_from_address(address) for address in payload["inventory"]["unsupported_resources"]
    )
    finding_counts_by_rule = Counter(
        str(finding["rule_id"])
        for finding in [
            *payload["findings"],
            *payload["suppressed_findings"],
            *payload["baselined_findings"],
        ]
        if finding.get("rule_id")
    )
    surfaced_rule_ids = sorted(finding_counts_by_rule)
    return {
        "resources": {
            "total_resources": summary["normalized_resources"] + summary["unsupported_resources"],
            "provider_resources": summary["normalized_resources"] + summary["unsupported_resources"],
            "normalized_resources": summary["normalized_resources"],
            "unsupported_resources": summary["unsupported_resources"],
            "unsupported_resource_types": dict(sorted(unsupported_resource_types.items())),
        },
        "rules": {
            "registered_rule_count": len(surfaced_rule_ids),
            "enabled_rules": surfaced_rule_ids,
            "disabled_rules": [],
            "severity_overrides": {},
            "finding_counts_by_rule": dict(sorted(finding_counts_by_rule.items())),
        },
        "references": {
            "unresolved_reference_count": 0,
            "unresolved_references": [],
        },
    }


def _resource_type_from_address(address: str) -> str:
    for segment in reversed(str(address).split(".")):
        if segment.startswith("aws_"):
            return segment
    return str(address)
