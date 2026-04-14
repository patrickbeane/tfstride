from __future__ import annotations

from collections import Counter

from tfstride.models import AnalysisResult, Severity


class MarkdownReportRenderer:
    def render(self, result: AnalysisResult) -> str:
        severity_counts = Counter(finding.severity.value for finding in result.findings)
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
                f"This run identified **{len(result.trust_boundaries)} trust boundaries** and "
                f"**{len(result.findings)} findings** across **{len(result.inventory.resources)} normalized resources**."
            ),
            "",
        ]

        filter_summary = result.filter_summary or {}
        suppressed_count = int(filter_summary.get("suppressed_findings", 0) or 0)
        baselined_count = int(filter_summary.get("baselined_findings", 0) or 0)
        lines.extend(
            [
                f"- High severity findings: `{severity_counts.get('high', 0)}`",
                f"- Medium severity findings: `{severity_counts.get('medium', 0)}`",
                f"- Low severity findings: `{severity_counts.get('low', 0)}`",
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

        findings_by_severity = {
            Severity.HIGH: [finding for finding in result.findings if finding.severity == Severity.HIGH],
            Severity.MEDIUM: [finding for finding in result.findings if finding.severity == Severity.MEDIUM],
            Severity.LOW: [finding for finding in result.findings if finding.severity == Severity.LOW],
        }
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
