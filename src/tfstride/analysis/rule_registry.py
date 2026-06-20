from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from types import MappingProxyType

from tfstride.models import Finding, Severity, StrideCategory


@dataclass(frozen=True, slots=True)
class RuleMetadata:
    rule_id: str
    title: str
    category: StrideCategory
    recommended_mitigation: str
    tags: tuple[str, ...] = ()
    severity_factors: tuple[str, ...] = ()
    enabled_by_default: bool = True


@dataclass(frozen=True, slots=True)
class RulePolicy:
    enabled_rule_ids: frozenset[str] | None = None
    severity_overrides: Mapping[str, Severity] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "severity_overrides",
            MappingProxyType(dict(self.severity_overrides)),
        )

    def is_enabled(self, rule_id: str, registry: RuleRegistry) -> bool:
        if self.enabled_rule_ids is None:
            return registry.get(rule_id).enabled_by_default
        return rule_id in self.enabled_rule_ids


class RuleRegistry:
    def __init__(self, rules: list[RuleMetadata]) -> None:
        self._rules = tuple(rules)
        self._rules_by_id = {rule.rule_id: rule for rule in self._rules}
        if len(self._rules_by_id) != len(rules):
            raise ValueError("Duplicate rule IDs are not allowed in the rule registry.")

    def get(self, rule_id: str) -> RuleMetadata:
        try:
            return self._rules_by_id[rule_id]
        except KeyError as exc:
            raise KeyError(f"Unknown rule ID `{rule_id}`.") from exc

    def known_rule_ids(self) -> set[str]:
        return set(self._rules_by_id)

    def default_enabled_rule_ids(self) -> set[str]:
        return {rule.rule_id for rule in self._rules_by_id.values() if rule.enabled_by_default}

    def rules(self) -> tuple[RuleMetadata, ...]:
        return self._rules


def _default_rule_metadata() -> tuple[RuleMetadata, ...]:
    from tfstride.providers.catalog import default_provider_rule_metadata

    return default_provider_rule_metadata()


DEFAULT_RULE_METADATA = _default_rule_metadata()


DEFAULT_RULE_METADATA_BY_ID = {rule.rule_id: rule for rule in DEFAULT_RULE_METADATA}


def default_rule_registry() -> RuleRegistry:
    return RuleRegistry(list(DEFAULT_RULE_METADATA))


DEFAULT_RULE_REGISTRY = default_rule_registry()


def default_rule_metadata(rule_id: str) -> RuleMetadata:
    try:
        return DEFAULT_RULE_METADATA_BY_ID[rule_id]
    except KeyError as exc:
        raise KeyError(f"Unknown rule ID `{rule_id}`.") from exc


def apply_severity_overrides(
    findings: list[Finding],
    policy: RulePolicy | None,
) -> list[Finding]:
    if policy is None:
        return sort_findings(findings)

    adjusted_findings: list[Finding] = []
    for finding in findings:
        severity_override = policy.severity_overrides.get(finding.rule_id)
        if severity_override and severity_override != finding.severity:
            severity_reasoning = finding.severity_reasoning
            if severity_reasoning is not None:
                computed_severity = severity_reasoning.computed_severity or severity_reasoning.severity
                severity_reasoning = replace(
                    severity_reasoning,
                    severity=severity_override,
                    computed_severity=computed_severity,
                )
            finding = replace(
                finding,
                severity=severity_override,
                severity_reasoning=severity_reasoning,
            )
        adjusted_findings.append(finding)
    return sort_findings(adjusted_findings)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda finding: (Severity.sort_key(finding.severity), finding.title))
