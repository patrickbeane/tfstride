from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from tfstride.models import AnalysisCoverage


class CoverageCheck(str, Enum):
    NO_RESOURCES = "no-resources"
    UNSUPPORTED_RESOURCES = "unsupported-resources"
    UNRESOLVED_RELATIONSHIPS = "unresolved-relationships"


@dataclass(frozen=True, slots=True)
class CoveragePolicy:
    """Opt-in limits on how incomplete an analysis may be before it should fail a gate."""

    checks: frozenset[CoverageCheck] = field(default_factory=frozenset)
    allowed_unsupported_types: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True, slots=True)
class CoverageViolation:
    check: CoverageCheck
    message: str


def evaluate_coverage_policy(coverage: AnalysisCoverage, policy: CoveragePolicy) -> list[CoverageViolation]:
    violations: list[CoverageViolation] = []
    for check in CoverageCheck:
        if check not in policy.checks:
            continue
        message = _CHECKS[check](coverage, policy)
        if message is not None:
            violations.append(CoverageViolation(check=check, message=message))
    return violations


def _check_no_resources(coverage: AnalysisCoverage, policy: CoveragePolicy) -> str | None:
    if coverage.resources.normalized_resources > 0:
        return None
    return f"no resources were analyzed ({coverage.resources.total_resources} resource(s) in the plan)"


def _check_unsupported_resources(coverage: AnalysisCoverage, policy: CoveragePolicy) -> str | None:
    unsupported = {
        resource_type: count
        for resource_type, count in coverage.resources.unsupported_resource_types.items()
        if resource_type not in policy.allowed_unsupported_types
    }
    if not unsupported:
        return None
    listed = ", ".join(f"{resource_type} ({count})" for resource_type, count in sorted(unsupported.items()))
    return f"unsupported resource type(s) were not analyzed: {listed}"


def _check_unresolved_relationships(coverage: AnalysisCoverage, policy: CoveragePolicy) -> str | None:
    references = coverage.references
    unresolved = (
        references.unresolved_reference_count
        + references.ambiguous_symbolic_relationships
        + references.unresolved_symbolic_relationships
        + references.unsupported_symbolic_relationships
    )
    if not unresolved:
        return None
    return (
        f"{unresolved} modeled relationship(s) could not be resolved "
        f"({references.unresolved_reference_count} unresolved reference(s), "
        f"{references.ambiguous_symbolic_relationships} ambiguous, "
        f"{references.unresolved_symbolic_relationships} unresolved and "
        f"{references.unsupported_symbolic_relationships} unsupported symbolic relationship(s))"
    )


_CHECKS = {
    CoverageCheck.NO_RESOURCES: _check_no_resources,
    CoverageCheck.UNSUPPORTED_RESOURCES: _check_unsupported_resources,
    CoverageCheck.UNRESOLVED_RELATIONSHIPS: _check_unresolved_relationships,
}
