"""Typed evidence records for relationships established by provider analysis.

These records describe a provider evaluator's conclusion. They deliberately do
not implement provider authorization, routing, or precedence semantics.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from tfstride.models import (
    TerraformExpressionPath,
    TerraformReferenceProvenance,
    TerraformReferenceResolutionState,
)


class RelationshipKind(str, Enum):
    IDENTITY_ATTACHMENT = "identity_attachment"
    AUTHORIZATION = "authorization"
    NETWORK_PERMISSION = "network_permission"
    FORWARDING = "forwarding"
    EFFECTIVE_INGRESS = "effective_ingress"


class RelationshipOutcome(str, Enum):
    ESTABLISHED = "established"
    NOT_ESTABLISHED = "not_established"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class RelationshipTrafficScope:
    name: str
    transport_protocol: str | None = None
    application_protocol: str | None = None
    from_port: int | None = None
    to_port: int | None = None
    source_addresses: tuple[str, ...] = ()
    source_cidrs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (self.from_port is None) != (self.to_port is None):
            raise ValueError("traffic scope must provide both port bounds or neither")
        if self.from_port is not None and self.to_port is not None and not 0 <= self.from_port <= self.to_port <= 65535:
            raise ValueError("traffic scope port bounds must be ordered and between 0 and 65535")


@dataclass(frozen=True, slots=True)
class RelationshipResourceScope:
    resource_addresses: tuple[str, ...] = ()
    selectors: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RelationshipEvidenceSource:
    address: str
    evidence_type: str
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class RelationshipReferenceResolution:
    source_address: str
    target_addresses: tuple[str, ...]
    expression_path: TerraformExpressionPath
    state: TerraformReferenceResolutionState
    provenance: TerraformReferenceProvenance | None
    references: tuple[str, ...] = ()
    reason: str | None = None

    @property
    def establishes_identity(self) -> bool:
        """Whether this evidence identifies one target without guessing.

        An exact first-plan Terraform expression remains symbolic because its
        provider-generated value is not known yet, but it still identifies the
        referenced resource. Conditional or multi-target expressions do not.
        """
        if len(self.target_addresses) != 1:
            return False
        if self.state == TerraformReferenceResolutionState.RESOLVED:
            return True
        return (
            self.state == TerraformReferenceResolutionState.SYMBOLIC
            and self.provenance == TerraformReferenceProvenance.CONFIGURATION_REFERENCE
        )


@dataclass(frozen=True, slots=True)
class RelationshipPrerequisite:
    name: str
    outcome: RelationshipOutcome
    evidence: tuple[RelationshipEvidenceSource, ...] = ()
    conditions: tuple[str, ...] = ()
    uncertainties: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RelationshipAssessment:
    source_address: str
    target_address: str
    kind: RelationshipKind
    operation: str
    outcome: RelationshipOutcome
    traffic_scope: tuple[RelationshipTrafficScope, ...] = ()
    resource_scope: RelationshipResourceScope = RelationshipResourceScope()
    evidence_sources: tuple[RelationshipEvidenceSource, ...] = ()
    reference_resolutions: tuple[RelationshipReferenceResolution, ...] = ()
    prerequisites: tuple[RelationshipPrerequisite, ...] = ()
    remaining_conditions: tuple[str, ...] = ()
    uncertainties: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        names = [prerequisite.name for prerequisite in self.prerequisites]
        if len(names) != len(set(names)):
            raise ValueError("relationship prerequisite names must be unique")
