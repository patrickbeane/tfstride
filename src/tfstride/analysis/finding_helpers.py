from __future__ import annotations

from tfstride.models import EvidenceItem, IAMPolicyStatement, Severity, SeverityReasoning


def build_severity_reasoning(
    *,
    internet_exposure: bool,
    privilege_breadth: int,
    data_sensitivity: int,
    lateral_movement: int,
    blast_radius: int,
) -> SeverityReasoning:
    # The v1 model is intentionally additive and explainable: each detector supplies a few
    # concrete signals and the final banding stays easy to tune without hiding logic in ML.
    internet_exposure_score = 2 if internet_exposure else 0
    score = (
        internet_exposure_score
        + privilege_breadth
        + data_sensitivity
        + lateral_movement
        + blast_radius
    )
    if score >= 6:
        severity = Severity.HIGH
    elif score >= 3:
        severity = Severity.MEDIUM
    else:
        severity = Severity.LOW
    return SeverityReasoning(
        internet_exposure=internet_exposure_score,
        privilege_breadth=privilege_breadth,
        data_sensitivity=data_sensitivity,
        lateral_movement=lateral_movement,
        blast_radius=blast_radius,
        final_score=score,
        severity=severity,
    )


def collect_evidence(*items: EvidenceItem | None) -> list[EvidenceItem]:
    return [item for item in items if item is not None]


def evidence_item(key: str, values: list[str]) -> EvidenceItem | None:
    deduped_values: list[str] = []
    seen_values: set[str] = set()
    for value in values:
        if not value:
            continue
        text = str(value)
        if text in seen_values:
            continue
        seen_values.add(text)
        deduped_values.append(text)
    if not deduped_values:
        return None
    return EvidenceItem(key=key, values=deduped_values)


def dedupe_addresses(addresses: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for address in addresses:
        if not address or address in seen:
            continue
        deduped.append(address)
        seen.add(address)
    return deduped


def describe_policy_statement(statement: IAMPolicyStatement) -> str:
    actions = ", ".join(statement.actions) if statement.actions else "no actions"
    resources = ", ".join(statement.resources) if statement.resources else "no resources"
    if statement.conditions:
        conditions = "; ".join(
            f"{condition.operator} {condition.key}=[{', '.join(condition.values)}]"
            for condition in statement.conditions
        )
        return (
            f"{statement.effect} actions=[{actions}] "
            f"resources=[{resources}] conditions=[{conditions}]"
        )
    return f"{statement.effect} actions=[{actions}] resources=[{resources}]"