"""Provider-neutral operation gaps; neither findings nor authorization decisions.

Producers must explicitly select safe resource addresses and configuration field
paths. Raw expressions, policy documents, condition values, and arbitrary resource
metadata do not belong in this contract. Human explanations can be supplied by
reporters using stable reason codes rather than copying evaluator messages.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from enum import Enum


class OperationGapEvidenceState(str, Enum):
    MISSING = "missing"
    UNKNOWN = "unknown"
    AMBIGUOUS = "ambiguous"
    CONDITIONAL = "conditional"
    UNSUPPORTED = "unsupported"


class OperationGapEvidenceKind(str, Enum):
    PLANNED_VALUE = "planned_value"
    CONFIGURATION_REFERENCE = "configuration_reference"
    POLICY_DOCUMENT = "policy_document"
    MODELED_RELATIONSHIP = "modeled_relationship"


@dataclass(frozen=True, slots=True, order=True)
class OperationGapFamily:
    """A provider-owned analysis family, independent of finding rule enablement."""

    provider: str
    name: str

    def __post_init__(self) -> None:
        _validate_code(self.provider, "provider")
        _validate_code(self.name, "family name")


@dataclass(frozen=True, slots=True)
class OperationGapProvenance:
    """Location of evidence, without its value or a serialized resource snapshot.

    field_path contains producer-selected schema field names and sequence indexes,
    never arbitrary map keys or expression text. POLICY_DOCUMENT identifies the
    document's location; it does not carry document contents.
    """

    resource_address: str
    evidence_kind: OperationGapEvidenceKind
    field_path: tuple[str | int, ...] = ()

    def __post_init__(self) -> None:
        _validate_address(self.resource_address)
        object.__setattr__(self, "evidence_kind", OperationGapEvidenceKind(self.evidence_kind))
        path = tuple(self.field_path)
        for segment in path:
            if type(segment) is int and segment >= 0:
                continue
            if isinstance(segment, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", segment):
                continue
            raise ValueError("field_path must contain schema field names or nonnegative sequence indexes")
        object.__setattr__(self, "field_path", path)


@dataclass(frozen=True, slots=True)
class OperationGap:
    """One relationship whose operation analysis could not reach a conclusion.

    resource_address identifies the modeled resource being assessed; an optional
    target_address identifies a modeled target, not an unresolved policy literal.
    operation is an exact provider operation, or None when only the attempted
    relationship is known. relationship and reason_code are stable machine codes.
    scope is a producer-selected bounded resource namespace, not a raw grant.
    An unavailable or unrepresentable scope is None, with location provenance.
    Reason codes describe the missing prerequisite or unsupported semantics, not
    a denial. Fully evaluated denials and standing model limitations are not gaps.
    """

    family: OperationGapFamily
    resource_address: str
    relationship: str
    reason_code: str
    evidence_state: OperationGapEvidenceState
    operation: str | None = None
    target_address: str | None = None
    provenance: tuple[OperationGapProvenance, ...] = ()
    scope: str | None = None

    def __post_init__(self) -> None:
        _validate_address(self.resource_address)
        if self.target_address is not None:
            _validate_address(self.target_address)
        if self.scope is not None:
            if self.target_address is None:
                raise ValueError("an evaluated scope requires a modeled target")
            _validate_address(self.scope)
        _validate_code(self.relationship, "relationship")
        _validate_code(self.reason_code, "reason code")
        if self.operation is not None and (
            not self.operation or any(character.isspace() or character in "*?" for character in self.operation)
        ):
            raise ValueError("operation must be an exact provider operation or None")
        object.__setattr__(self, "evidence_state", OperationGapEvidenceState(self.evidence_state))
        object.__setattr__(self, "provenance", tuple(sorted(set(self.provenance), key=_provenance_key)))


@dataclass(frozen=True, slots=True)
class OperationGapResults:
    """Immutable gap results from the reporting families run in one invocation.

    reporting_families lists only producers actually run, including those that
    emitted no records. An absent family has no gap-reporting coverage. An empty
    records tuple means no gaps were reported by those producers, not that all
    resources, operations, or cloud authorization features were assessed.

    A fresh instance replaces the previous invocation's results; records must not
    be accumulated across evaluations. Duplicate gap identities merge provenance
    without collapsing different targets, operations, reasons, or evidence states.
    """

    reporting_families: tuple[OperationGapFamily, ...] = ()
    records: tuple[OperationGap, ...] = ()

    def __post_init__(self) -> None:
        families = tuple(sorted(set(self.reporting_families)))
        merged: dict[OperationGap, set[OperationGapProvenance]] = {}
        for gap in self.records:
            if gap.family not in families:
                raise ValueError(f"Gap family {gap.family} has no reporting coverage in this invocation")
            identity = replace(gap, provenance=())
            merged.setdefault(identity, set()).update(gap.provenance)
        records = tuple(replace(gap, provenance=tuple(merged[gap])) for gap in sorted(merged, key=_gap_key))
        object.__setattr__(self, "reporting_families", families)
        object.__setattr__(self, "records", records)


def _validate_code(value: str, label: str) -> None:
    if not isinstance(value, str) or re.fullmatch(r"[a-z][a-z0-9_]*(?:[.-][a-z0-9_]+)*", value) is None:
        raise ValueError(f"{label} must be a stable lowercase machine code")


def _validate_address(value: str) -> None:
    # Full Terraform address resolution is the producer's responsibility. Keep
    # this contract independent of the inventory and reject blank/multiline text.
    if not isinstance(value, str) or not value.strip() or value != value.strip() or "\n" in value or "\r" in value:
        raise ValueError("resource address must be a nonempty single-line modeled address")


def _provenance_key(value: OperationGapProvenance) -> tuple[str, str, tuple[tuple[int, str, int], ...]]:
    path = tuple((0, segment, 0) if isinstance(segment, str) else (1, "", segment) for segment in value.field_path)
    return value.resource_address, value.evidence_kind.value, path


def _gap_key(value: OperationGap) -> tuple[str, ...]:
    return (
        value.family.provider,
        value.family.name,
        value.resource_address,
        value.relationship,
        value.operation or "",
        value.target_address or "",
        value.scope or "",
        value.reason_code,
        value.evidence_state.value,
    )
