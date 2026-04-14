from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tfstride import __version__
from tfstride.models import AnalysisResult, Finding, Severity


BASELINE_FORMAT_VERSION = "1.0"
SUPPRESSIONS_FORMAT_VERSION = "1.0"


class FindingFilterLoadError(ValueError):
    """Raised when a suppressions or baseline file cannot be parsed."""


@dataclass(slots=True)
class SuppressionRule:
    suppression_id: str
    reason: str
    fingerprint: str | None = None
    rule_id: str | None = None
    resource: str | None = None
    trust_boundary_id: str | None = None
    severity: Severity | None = None
    title: str | None = None

    def matches(self, finding: Finding, fingerprint: str) -> bool:
        if self.fingerprint and self.fingerprint != fingerprint:
            return False
        if self.rule_id and self.rule_id != finding.rule_id:
            return False
        if self.resource and self.resource not in finding.affected_resources:
            return False
        if self.trust_boundary_id and self.trust_boundary_id != finding.trust_boundary_id:
            return False
        if self.severity and self.severity != finding.severity:
            return False
        if self.title and self.title != finding.title:
            return False
        return True


def apply_finding_filters(
    result: AnalysisResult,
    *,
    suppressions_path: str | Path | None = None,
    baseline_path: str | Path | None = None,
) -> AnalysisResult:
    suppressions = load_suppressions(suppressions_path) if suppressions_path else []
    baseline_fingerprints = load_baseline_fingerprints(baseline_path) if baseline_path else set()

    active_findings: list[Finding] = []
    suppressed_findings: list[Finding] = []
    baselined_findings: list[Finding] = []

    for finding in result.findings:
        fingerprint = finding_fingerprint(finding)
        if any(rule.matches(finding, fingerprint) for rule in suppressions):
            suppressed_findings.append(finding)
            continue
        if fingerprint in baseline_fingerprints:
            baselined_findings.append(finding)
            continue
        active_findings.append(finding)

    return replace(
        result,
        findings=active_findings,
        suppressed_findings=suppressed_findings,
        baselined_findings=baselined_findings,
        filter_summary={
            "total_findings": len(result.findings),
            "active_findings": len(active_findings),
            "suppressed_findings": len(suppressed_findings),
            "baselined_findings": len(baselined_findings),
            "suppressions_path": str(suppressions_path) if suppressions_path else None,
            "baseline_path": str(baseline_path) if baseline_path else None,
        },
    )


def render_baseline(findings: list[Finding]) -> str:
    payload = build_baseline_payload(findings)
    return json.dumps(payload, indent=2) + "\n"


def build_baseline_payload(findings: list[Finding]) -> dict[str, Any]:
    entries_by_fingerprint: dict[str, dict[str, Any]] = {}
    for finding in findings:
        fingerprint = finding_fingerprint(finding)
        entries_by_fingerprint[fingerprint] = {
            "fingerprint": fingerprint,
            "rule_id": finding.rule_id,
            "title": finding.title,
            "severity": finding.severity.value,
            "affected_resources": sorted(set(finding.affected_resources)),
            "trust_boundary_id": finding.trust_boundary_id,
        }
    entries = sorted(entries_by_fingerprint.values(), key=lambda entry: (entry["rule_id"], entry["fingerprint"]))
    return {
        "version": BASELINE_FORMAT_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": {
            "name": "tfstride",
            "version": __version__,
        },
        "findings": entries,
    }


def load_baseline_fingerprints(path: str | Path) -> set[str]:
    payload = _load_json_object(path, label="baseline")
    findings = payload.get("findings")
    if not isinstance(findings, list):
        raise FindingFilterLoadError(f"Baseline file must contain a `findings` array: {path}")
    fingerprints: set[str] = set()
    for index, entry in enumerate(findings):
        if not isinstance(entry, dict):
            raise FindingFilterLoadError(f"Baseline finding at index {index} must be a JSON object: {path}")
        fingerprint = entry.get("fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint:
            raise FindingFilterLoadError(f"Baseline finding at index {index} is missing `fingerprint`: {path}")
        fingerprints.add(fingerprint)
    return fingerprints


def load_suppressions(path: str | Path) -> list[SuppressionRule]:
    payload = _load_json_object(path, label="suppressions")
    suppressions = payload.get("suppressions")
    if not isinstance(suppressions, list):
        raise FindingFilterLoadError(f"Suppressions file must contain a `suppressions` array: {path}")

    parsed: list[SuppressionRule] = []
    for index, entry in enumerate(suppressions):
        if not isinstance(entry, dict):
            raise FindingFilterLoadError(f"Suppression at index {index} must be a JSON object: {path}")
        reason = entry.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise FindingFilterLoadError(f"Suppression at index {index} is missing a non-empty `reason`: {path}")

        severity = entry.get("severity")
        parsed_severity = None
        if severity is not None:
            try:
                parsed_severity = Severity(str(severity))
            except ValueError as exc:
                raise FindingFilterLoadError(
                    f"Suppression at index {index} has invalid `severity` value `{severity}`: {path}"
                ) from exc

        rule = SuppressionRule(
            suppression_id=str(entry.get("id") or f"suppression-{index + 1}"),
            reason=reason.strip(),
            fingerprint=_as_optional_string(entry.get("fingerprint")),
            rule_id=_as_optional_string(entry.get("rule_id")),
            resource=_as_optional_string(entry.get("resource")),
            trust_boundary_id=_as_optional_string(entry.get("trust_boundary_id")),
            severity=parsed_severity,
            title=_as_optional_string(entry.get("title")),
        )
        if not any(
            (
                rule.fingerprint,
                rule.rule_id,
                rule.resource,
                rule.trust_boundary_id,
                rule.severity,
                rule.title,
            )
        ):
            raise FindingFilterLoadError(
                f"Suppression at index {index} must define at least one selector such as "
                f"`fingerprint`, `rule_id`, `resource`, `trust_boundary_id`, `severity`, or `title`: {path}"
            )
        parsed.append(rule)
    return parsed


def finding_fingerprint(finding: Finding) -> str:
    payload = json.dumps(_finding_identity(finding), sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _finding_identity(finding: Finding) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "trust_boundary_id": finding.trust_boundary_id,
        "affected_resources": sorted(set(finding.affected_resources)),
    }


def _load_json_object(path: str | Path, *, label: str) -> dict[str, Any]:
    file_path = Path(path)
    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FindingFilterLoadError(f"{label.title()} file not found: {file_path}") from exc
    except json.JSONDecodeError as exc:
        raise FindingFilterLoadError(f"Failed to parse {label} JSON in {file_path}: {exc.msg}") from exc

    if not isinstance(payload, dict):
        raise FindingFilterLoadError(f"{label.title()} file must contain a JSON object: {file_path}")
    return payload


def _as_optional_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
