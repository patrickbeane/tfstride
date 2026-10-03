from __future__ import annotations

from collections import Counter

from tfstride.models import AnalysisResult, Finding, Severity
from tfstride.reporting.operation_gaps import render_operation_gaps

_PROVIDER_DISPLAY_NAMES = {
    "aws": "AWS",
    "gcp": "GCP",
    "azure": "Azure",
}


def render_markdown(result: AnalysisResult) -> str:
    findings_by_severity = _group_findings_by_severity(result)
    trust_boundary_label = "trust boundary" if len(result.trust_boundaries) == 1 else "trust boundaries"
    finding_label = "finding" if len(result.findings) == 1 else "findings"
    lines = [
        f"# {result.title}",
        "",
        f"- Analyzed file: `{result.analyzed_file}`",
        f"- Provider: `{result.inventory.provider}`",
        f"- Normalized resources: `{len(result.inventory.resources)}`",
        f"- Unsupported resources: `{len(result.inventory.unsupported_resources)}`",
        "",
        "## Summary",
        "",
        (
            f"This run identified **{len(result.trust_boundaries)} {trust_boundary_label}** and "
            f"**{len(result.findings)} {finding_label}** across "
            f"**{len(result.inventory.resources)} normalized resources**."
        ),
        "",
    ]

    filter_summary = result.filter_summary or {}
    suppressed_count = int(filter_summary.get("suppressed_findings", 0) or 0)
    baselined_count = int(filter_summary.get("baselined_findings", 0) or 0)
    lines.extend(
        [
            f"- High severity findings: `{len(findings_by_severity[Severity.HIGH])}`",
            f"- Medium severity findings: `{len(findings_by_severity[Severity.MEDIUM])}`",
            f"- Low severity findings: `{len(findings_by_severity[Severity.LOW])}`",
        ]
    )
    if suppressed_count or baselined_count:
        lines.extend(
            [
                f"- Active findings after filters: `{filter_summary.get('active_findings', len(result.findings))}`",
                f"- Suppressed findings: `{suppressed_count}`",
                f"- Baselined findings: `{baselined_count}`",
            ]
        )
        if filter_summary.get("suppressions_path"):
            lines.append(f"- Suppressions file: `{filter_summary['suppressions_path']}`")
        if filter_summary.get("baseline_path"):
            lines.append(f"- Baseline file: `{filter_summary['baseline_path']}`")
    lines.extend(["", "## Analysis Coverage", ""])
    lines.extend(_render_analysis_coverage(result))
    if result.operation_gaps.records:
        lines.extend(["", "## Analysis Gaps", ""])
        lines.extend(render_operation_gaps(result.operation_gaps))
    lines.extend(["", "## Discovered Trust Boundaries", ""])

    if result.trust_boundaries:
        for boundary in result.trust_boundaries:
            lines.extend(
                [
                    f"### `{boundary.boundary_type.value}`",
                    "",
                    f"- Source: `{boundary.source}`",
                    f"- Target: `{boundary.target}`",
                    f"- Description: {boundary.description}",
                    f"- Rationale: {boundary.rationale}",
                    "",
                ]
            )
    else:
        lines.extend(["No trust boundaries were discovered.", ""])

    lines.append("## Findings")
    lines.append("")
    for severity in (Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        severity_findings = findings_by_severity[severity]
        lines.append(f"### {severity.value.title()}")
        lines.append("")
        if not severity_findings:
            lines.append("No findings in this severity band.")
            lines.append("")
            continue
        for finding in severity_findings:
            lines.extend(
                [
                    f"#### {finding.title}",
                    "",
                    f"- STRIDE category: {finding.category.value}",
                    f"- Affected resources: {', '.join(f'`{resource}`' for resource in finding.affected_resources)}",
                    f"- Trust boundary: `{finding.trust_boundary_id or 'not-applicable'}`",
                    f"- Severity reasoning: {_format_severity_reasoning(finding)}",
                    f"- Rationale: {finding.rationale}",
                    f"- Recommended mitigation: {finding.recommended_mitigation}",
                ]
            )
            if finding.evidence:
                lines.append("- Evidence:")
                for evidence_item in finding.evidence:
                    label = evidence_item.key.replace("_", " ")
                    values = "; ".join(evidence_item.values)
                    lines.append(f"  - {label}: {values}")
            lines.append("")

    if result.observations:
        lines.extend(["## Controls Observed", ""])
        for observation in result.observations:
            lines.extend(
                [
                    f"### {observation.title}",
                    "",
                    f"- Category: `{observation.category or 'informational'}`",
                    f"- Affected resources: {', '.join(f'`{resource}`' for resource in observation.affected_resources)}",
                    f"- Rationale: {observation.rationale}",
                ]
            )
            if observation.evidence:
                lines.append("- Evidence:")
                for evidence_item in observation.evidence:
                    label = evidence_item.key.replace("_", " ")
                    values = "; ".join(evidence_item.values)
                    lines.append(f"  - {label}: {values}")
            lines.append("")

    lines.extend(
        [
            "## Limitations / Unsupported Resources",
            "",
        ]
    )
    for limitation in result.limitations:
        lines.append(f"- {limitation}")
    if result.inventory.unsupported_resources:
        for resource in result.inventory.unsupported_resources:
            lines.append(f"- Unsupported resource skipped: `{resource}`")
    elif not result.limitations:
        lines.append("- No additional limitations were recorded.")
    lines.append("")
    return "\n".join(lines)


def _group_findings_by_severity(result: AnalysisResult) -> dict[Severity, list[Finding]]:
    findings_by_severity: dict[Severity, list[Finding]] = {
        Severity.HIGH: [],
        Severity.MEDIUM: [],
        Severity.LOW: [],
    }
    for finding in result.findings:
        findings_by_severity[finding.severity].append(finding)
    return findings_by_severity


def _render_analysis_coverage(result: AnalysisResult) -> list[str]:
    coverage = result.analysis_coverage
    provider = result.inventory.provider.strip()
    provider_label = _PROVIDER_DISPLAY_NAMES.get(provider.lower(), provider)
    finding_counts = Counter(
        finding.rule_id
        for findings in (result.findings, result.suppressed_findings, result.baselined_findings)
        for finding in findings
    )
    lines = [
        f"- Terraform resources seen: `{coverage.resources.total_resources}`",
        f"- Provider resources considered: `{coverage.resources.provider_resources}`",
        f"- Normalized resources: `{coverage.resources.normalized_resources}`",
        f"- Unsupported resources: `{coverage.resources.unsupported_resources}`",
        f"- Resources with plan-time unknown values: `{coverage.resources.plan_time_unknown_resources}`",
        f"- Registered provider rules ({provider_label}): `{coverage.rules.registered_rule_count}`",
        f"- Enabled provider rules ({provider_label}): `{len(coverage.rules.enabled_rules)}`",
        f"- Disabled rules: `{len(coverage.rules.disabled_rules)}`",
        f"- Severity overrides: `{len(coverage.rules.severity_overrides)}`",
        (
            "- Configuration-reference resolution: "
            f"`{coverage.references.symbolically_resolved_relationships} symbolic`, "
            f"`{coverage.references.ambiguous_symbolic_relationships} ambiguous`, "
            f"`{coverage.references.unresolved_symbolic_relationships} unresolved`, "
            f"`{coverage.references.unsupported_symbolic_relationships} unsupported`"
        ),
        f"- Recorded unresolved modeled references: `{coverage.references.unresolved_reference_count}`",
    ]

    if coverage.resources.unsupported_resource_types:
        lines.append("- Unsupported resource types:")
        for resource_type, count in sorted(coverage.resources.unsupported_resource_types.items()):
            lines.append(f"  - `{resource_type}`: `{count}`")

    nonzero_finding_counts = {
        rule_id: finding_counts[rule_id] for rule_id in coverage.rules.enabled_rules if finding_counts[rule_id]
    }
    if nonzero_finding_counts:
        lines.append("- Findings by rule:")
        for rule_id, count in nonzero_finding_counts.items():
            lines.append(f"  - `{rule_id}`: `{count}`")

    if coverage.rules.disabled_rules:
        lines.append("- Disabled rule IDs:")
        for rule_id in coverage.rules.disabled_rules:
            lines.append(f"  - `{rule_id}`")

    if coverage.rules.severity_overrides:
        lines.append("- Severity override rules:")
        for rule_id, severity in coverage.rules.severity_overrides.items():
            lines.append(f"  - `{rule_id}`: `{severity.value}`")

    if coverage.references.unresolved_references:
        lines.append("- Unresolved references:")
        for reference in coverage.references.unresolved_references:
            reference_values = [
                f"{key}: {', '.join(f'`{value}`' for value in values)}"
                for key, values in sorted(reference.references.items())
            ]
            lines.append(f"  - `{reference.resource}`: {'; '.join(reference_values)}")

    return lines


def _format_severity_reasoning(finding) -> str:
    if finding.severity_reasoning is None:
        return finding.severity.value
    reasoning = finding.severity_reasoning
    summary = (
        f"internet_exposure +{reasoning.internet_exposure}, "
        f"privilege_breadth +{reasoning.privilege_breadth}, "
        f"data_sensitivity +{reasoning.data_sensitivity}, "
        f"lateral_movement +{reasoning.lateral_movement}, "
        f"blast_radius +{reasoning.blast_radius}, "
        f"final_score {reasoning.final_score} => {reasoning.severity.value}"
    )
    if reasoning.computed_severity and reasoning.computed_severity != reasoning.severity:
        summary += f" (computed as {reasoning.computed_severity.value}, overridden by config)"
    return summary
