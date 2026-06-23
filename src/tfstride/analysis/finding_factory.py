from __future__ import annotations

from tfstride.analysis.rule_registry import RuleRegistry, default_rule_registry
from tfstride.models import EvidenceItem, Finding, Severity, SeverityReasoning


class FindingFactory:
    def __init__(self, rule_registry: RuleRegistry | None = None) -> None:
        self._rule_registry = rule_registry if rule_registry is not None else default_rule_registry()

    def build(
        self,
        *,
        rule_id: str,
        severity: Severity,
        affected_resources: list[str],
        trust_boundary_id: str | None,
        rationale: str,
        evidence: list[EvidenceItem],
        severity_reasoning: SeverityReasoning | None = None,
    ) -> Finding:
        rule = self._rule_registry.get(rule_id)
        return Finding(
            title=rule.title,
            category=rule.category,
            severity=severity,
            affected_resources=affected_resources,
            trust_boundary_id=trust_boundary_id,
            rationale=rationale,
            recommended_mitigation=rule.recommended_mitigation,
            rule_id=rule.rule_id,
            evidence=evidence,
            severity_reasoning=severity_reasoning,
        )
