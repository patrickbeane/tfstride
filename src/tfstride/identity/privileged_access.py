from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import TypeVar


class PrincipalType(str, Enum):
    """Provider-neutral identity principal categories."""

    UNKNOWN = "unknown"
    ANY = "any-principal"
    HUMAN_USER = "human-user"
    GROUP = "group"
    SERVICE_ACCOUNT = "service-account"
    SERVICE_PRINCIPAL = "service-principal"
    MANAGED_IDENTITY = "managed-identity"
    ROLE = "role"
    WORKLOAD = "workload"


class AssignmentScopeKind(str, Enum):
    """Provider-neutral scope categories for privileged assignments."""

    UNKNOWN = "unknown"
    TENANT = "tenant"
    ORGANIZATION = "organization"
    FOLDER = "folder"
    ACCOUNT = "account"
    PROJECT = "project"
    SUBSCRIPTION = "subscription"
    RESOURCE_GROUP = "resource-group"
    RESOURCE = "resource"
    SERVICE = "service"
    WORKLOAD = "workload"


class PrivilegeCategory(str, Enum):
    """Provider-neutral buckets for high-impact privileges."""

    UNKNOWN = "unknown"
    FULL_ADMIN = "full-admin"
    IAM_ADMIN = "iam-admin"
    POLICY_ADMIN = "policy-admin"
    ROLE_ASSIGNMENT = "role-assignment"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DATA_ADMIN = "data-admin"
    SECRETS_ADMIN = "secrets-admin"
    KEY_ADMIN = "key-admin"
    COMPUTE_ADMIN = "compute-admin"
    NETWORK_ADMIN = "network-admin"
    AUDIT_ADMIN = "audit-admin"


class PrivilegeConfidence(str, Enum):
    """Confidence that a provider-local grant is privileged."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


_EnumT = TypeVar("_EnumT", bound=Enum)

_BROAD_SCOPE_KINDS = frozenset(
    {
        AssignmentScopeKind.TENANT,
        AssignmentScopeKind.ORGANIZATION,
        AssignmentScopeKind.FOLDER,
        AssignmentScopeKind.ACCOUNT,
        AssignmentScopeKind.PROJECT,
        AssignmentScopeKind.SUBSCRIPTION,
        AssignmentScopeKind.RESOURCE_GROUP,
    }
)


def _normalize_provider(provider: str) -> str:
    normalized = provider.strip().lower()
    if not normalized:
        raise ValueError("provider must not be empty")
    return normalized


def _dedupe_strings(values: Iterable[str | None]) -> tuple[str, ...]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if value is None:
            continue
        normalized = str(value).strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(normalized)
    return tuple(deduped)


def _dedupe_enum_values(values: Iterable[_EnumT | str], enum_type: type[_EnumT]) -> tuple[_EnumT, ...]:
    seen: set[_EnumT] = set()
    deduped: list[_EnumT] = []
    for value in values:
        enum_value = value if isinstance(value, enum_type) else enum_type(str(value))
        if enum_value in seen:
            continue
        seen.add(enum_value)
        deduped.append(enum_value)
    return tuple(deduped)


@dataclass(frozen=True, slots=True)
class PrivilegedPrincipal:
    """A provider-local identity principal mapped to shared vocabulary."""

    principal_type: PrincipalType | str
    identifier: str | None = None
    display_name: str | None = None
    source_address: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "principal_type", PrincipalType(self.principal_type))


@dataclass(frozen=True, slots=True)
class PrivilegedAssignmentScope:
    """A provider-local assignment scope mapped to shared vocabulary."""

    scope_kind: AssignmentScopeKind | str
    value: str | None = None
    source_address: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "scope_kind", AssignmentScopeKind(self.scope_kind))

    @property
    def is_broad(self) -> bool:
        return self.scope_kind in _BROAD_SCOPE_KINDS


@dataclass(frozen=True, slots=True)
class PrivilegedAccessGrant:
    """Provider-local privileged grant described with shared identity vocabulary."""

    provider: str
    principal: PrivilegedPrincipal
    assignment_scope: PrivilegedAssignmentScope
    privilege_categories: tuple[PrivilegeCategory | str, ...]
    confidence: PrivilegeConfidence | str = PrivilegeConfidence.HIGH
    assignment_source_address: str | None = None
    role_name: str | None = None
    role_id: str | None = None
    permission_patterns: tuple[str | None, ...] = field(default_factory=tuple)
    evidence: tuple[str | None, ...] = field(default_factory=tuple)
    uncertainties: tuple[str | None, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        categories = _dedupe_enum_values(self.privilege_categories, PrivilegeCategory)
        if not categories:
            raise ValueError("privilege_categories must not be empty")
        object.__setattr__(self, "provider", _normalize_provider(self.provider))
        object.__setattr__(self, "privilege_categories", categories)
        object.__setattr__(self, "confidence", PrivilegeConfidence(self.confidence))
        object.__setattr__(self, "permission_patterns", _dedupe_strings(self.permission_patterns))
        object.__setattr__(self, "evidence", _dedupe_strings(self.evidence))
        object.__setattr__(self, "uncertainties", _dedupe_strings(self.uncertainties))

    @property
    def has_uncertainty(self) -> bool:
        return bool(self.uncertainties)

    @property
    def has_broad_scope(self) -> bool:
        return self.assignment_scope.is_broad


@dataclass(frozen=True, slots=True)
class PrivilegedAccessPosture:
    """Provider-scoped collection of privileged access grants and unresolved evidence."""

    provider: str
    grants: tuple[PrivilegedAccessGrant, ...] = field(default_factory=tuple)
    unresolved_assignments: tuple[str | None, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        provider = _normalize_provider(self.provider)
        object.__setattr__(self, "provider", provider)
        object.__setattr__(self, "grants", tuple(self.grants))
        object.__setattr__(self, "unresolved_assignments", _dedupe_strings(self.unresolved_assignments))
        mismatched = tuple(grant.provider for grant in self.grants if grant.provider != provider)
        if mismatched:
            raise ValueError("all privileged access grants must match the posture provider")

    @property
    def has_privileged_grants(self) -> bool:
        return bool(self.grants)

    @property
    def has_unresolved_assignments(self) -> bool:
        return bool(self.unresolved_assignments)
