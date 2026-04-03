from __future__ import annotations

from collections import Counter

from cloud_threat_modeler.models import AnalysisResult, Severity


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
            f"- High severity findings: `{severity_counts.get('high', 0)}`",
            f"- Medium severity findings: `{severity_counts.get('medium', 0)}`",
            f"- Low severity findings: `{severity_counts.get('low', 0)}`",
            "",
            "## Discovered Trust Boundaries",
            "",
        ]

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
                        f"- Rationale: {finding.rationale}",
                        f"- Recommended mitigation: {finding.recommended_mitigation}",
                        "",
                    ]
                )

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
