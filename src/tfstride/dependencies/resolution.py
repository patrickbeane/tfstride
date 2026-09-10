from __future__ import annotations

from collections.abc import Callable, Collection
from dataclasses import dataclass
from typing import Generic, Literal, Protocol, TypeVar

from tfstride.models import (
    TerraformExpressionPath,
    TerraformReferenceProvenance,
    TerraformReferenceResolution,
    TerraformReferenceResolutionState,
    TerraformReferenceTarget,
)

DependencyResolutionState = Literal[
    "resolved",
    "ambiguous",
    "unresolved",
    "unsupported",
]
DependencyReferenceProvenance = Literal[
    "planned_value",
    "configuration_reference",
]
DependencyResolutionCause = Literal[
    "multiple_candidates",
    "unsupported_reference",
    "unresolved_reference",
    "missing_reference",
    "conflicting_candidate_evidence",
    "conflicting_evidence",
]


class ConfigurationResolutionSource(Protocol):
    """A source retaining Terraform configuration-reference resolutions."""

    @property
    def reference_resolutions(self) -> tuple[TerraformReferenceResolution, ...]: ...


_ResourceT = TypeVar("_ResourceT", bound=ConfigurationResolutionSource)
_InputMetadataT = TypeVar("_InputMetadataT")
_CandidateT = TypeVar("_CandidateT")
_CandidateMetadataT = TypeVar("_CandidateMetadataT")
_SelectionT = TypeVar("_SelectionT")
_RecordT = TypeVar("_RecordT")


@dataclass(frozen=True, slots=True)
class DependencyInput(Generic[_ResourceT, _InputMetadataT]):
    """Provider-neutral dependency source and accepted configuration paths."""

    dependent: _ResourceT
    source: _ResourceT
    configuration_path: TerraformExpressionPath
    resolution_paths: tuple[TerraformExpressionPath, ...]
    configured_reference: str | None
    source_uncertainties: tuple[str, ...]
    adapter_data: _InputMetadataT


@dataclass(frozen=True, slots=True)
class DependencyCandidate(Generic[_CandidateT, _CandidateMetadataT]):
    """One stably keyed candidate and its adapter-owned relationship metadata."""

    address: str
    value: _CandidateT
    reference: str
    metadata: _CandidateMetadataT


@dataclass(frozen=True, slots=True)
class CandidateAssessment(Generic[_CandidateT, _CandidateMetadataT]):
    """Adapter assessment of one Terraform configuration target."""

    candidate: _CandidateT | None
    metadata: _CandidateMetadataT
    supported: bool
    details: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CandidateSelection(Generic[_SelectionT]):
    """Adapter decision after the core isolates one symbolic candidate."""

    state: DependencyResolutionState
    value: _SelectionT | None
    causes: tuple[DependencyResolutionCause, ...] = ()
    details: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DependencyResolution(Generic[_CandidateT, _CandidateMetadataT, _SelectionT]):
    """Typed resolution outcome with ordered candidates and adapter details."""

    state: DependencyResolutionState
    provenance: DependencyReferenceProvenance | None
    configured_reference: str | None
    candidates: tuple[DependencyCandidate[_CandidateT, _CandidateMetadataT], ...]
    selected_candidate: DependencyCandidate[_CandidateT, _CandidateMetadataT] | None
    selection: _SelectionT | None
    causes: tuple[DependencyResolutionCause, ...] = ()
    details: tuple[str, ...] = ()


class DependencyResolver(Generic[_ResourceT, _InputMetadataT, _CandidateT, _CandidateMetadataT, _SelectionT]):
    """Resolve native or symbolic dependencies through a small typed callback surface."""

    def __init__(
        self,
        *,
        resolve_native_reference: Callable[
            [DependencyInput[_ResourceT, _InputMetadataT], str],
            DependencyResolution[_CandidateT, _CandidateMetadataT, _SelectionT],
        ],
        assess_configuration_target: Callable[
            [DependencyInput[_ResourceT, _InputMetadataT], TerraformReferenceTarget],
            CandidateAssessment[_CandidateT, _CandidateMetadataT],
        ],
        resolve_configuration_candidate: Callable[
            [
                DependencyInput[_ResourceT, _InputMetadataT],
                DependencyCandidate[_CandidateT, _CandidateMetadataT],
                tuple[DependencyCandidate[_CandidateT, _CandidateMetadataT], ...],
            ],
            CandidateSelection[_SelectionT],
        ],
        reconcile_evidence: Callable[
            [
                DependencyInput[_ResourceT, _InputMetadataT],
                DependencyResolution[_CandidateT, _CandidateMetadataT, _SelectionT],
                DependencyResolution[_CandidateT, _CandidateMetadataT, _SelectionT],
            ],
            DependencyResolution[_CandidateT, _CandidateMetadataT, _SelectionT],
        ]
        | None = None,
    ) -> None:
        self._resolve_native_reference = resolve_native_reference
        self._assess_configuration_target = assess_configuration_target
        self._resolve_configuration_candidate = resolve_configuration_candidate
        self._reconcile_evidence = reconcile_evidence

    def resolve(
        self,
        dependency_input: DependencyInput[_ResourceT, _InputMetadataT],
    ) -> DependencyResolution[_CandidateT, _CandidateMetadataT, _SelectionT]:
        resolutions = matching_configuration_resolutions(
            dependency_input.source,
            dependency_input.resolution_paths,
        )
        configured_reference = dependency_input.configured_reference
        concrete_reference = bool(configured_reference) and not configured_reference_is_symbolic(
            configured_reference or "",
            resolutions,
        )
        if concrete_reference:
            assert configured_reference is not None
            native = self._resolve_native_reference(dependency_input, configured_reference)
            if self._reconcile_evidence is not None and resolutions and native.state == "resolved":
                symbolic = self._resolve_configuration_reference(dependency_input, resolutions)
                return self._reconcile_evidence(dependency_input, native, symbolic)
            return native
        if resolutions:
            return self._resolve_configuration_reference(dependency_input, resolutions)
        return DependencyResolution(
            state="unresolved",
            provenance=None,
            configured_reference=None,
            candidates=(),
            selected_candidate=None,
            selection=None,
            causes=("missing_reference",),
            details=_dedupe_strings(dependency_input.source_uncertainties),
        )

    def resolve_record(
        self,
        dependency_input: DependencyInput[_ResourceT, _InputMetadataT],
        *,
        render: Callable[
            [
                DependencyInput[_ResourceT, _InputMetadataT],
                DependencyResolution[_CandidateT, _CandidateMetadataT, _SelectionT],
                TerraformExpressionPath,
            ],
            _RecordT,
        ],
    ) -> _RecordT:
        resolution = self.resolve(dependency_input)
        return render(
            dependency_input,
            resolution,
            effective_configuration_path(dependency_input),
        )

    def _resolve_configuration_reference(
        self,
        dependency_input: DependencyInput[_ResourceT, _InputMetadataT],
        resolutions: tuple[TerraformReferenceResolution, ...],
    ) -> DependencyResolution[_CandidateT, _CandidateMetadataT, _SelectionT]:
        candidates_by_address: dict[
            str,
            DependencyCandidate[_CandidateT, _CandidateMetadataT],
        ] = {}
        details: list[str] = []
        ambiguous = False
        unsupported = False
        unresolved = False
        conflicting_candidate_evidence = False

        for resolution in resolutions:
            if resolution.state == TerraformReferenceResolutionState.AMBIGUOUS:
                ambiguous = True
            elif resolution.state == TerraformReferenceResolutionState.UNSUPPORTED:
                unsupported = True
            elif resolution.state == TerraformReferenceResolutionState.UNRESOLVED:
                unresolved = True
            elif resolution.state != TerraformReferenceResolutionState.SYMBOLIC:
                unsupported = True
            if resolution.reason:
                details.append(resolution.reason)

            for target in resolution.targets:
                assessment = self._assess_configuration_target(dependency_input, target)
                details.extend(assessment.details)
                if assessment.candidate is None or not assessment.supported:
                    unsupported = True
                if assessment.candidate is None:
                    continue
                candidate = DependencyCandidate(
                    address=target.address,
                    value=assessment.candidate,
                    reference=target.reference,
                    metadata=assessment.metadata,
                )
                existing = candidates_by_address.setdefault(target.address, candidate)
                if existing.metadata != candidate.metadata:
                    conflicting_candidate_evidence = True

        candidates = tuple(sorted(candidates_by_address.values(), key=lambda candidate: candidate.address))
        configured_reference = _symbolic_configured_reference(resolutions, candidates)
        classified_details = _dedupe_strings((*details, *dependency_input.source_uncertainties))
        if ambiguous or len(candidates) > 1:
            return _classified_resolution(
                "ambiguous",
                "multiple_candidates",
                configured_reference,
                candidates,
                classified_details,
            )
        if conflicting_candidate_evidence:
            return _classified_resolution(
                "unsupported",
                "conflicting_candidate_evidence",
                configured_reference,
                candidates,
                classified_details,
            )
        if unsupported:
            return _classified_resolution(
                "unsupported",
                "unsupported_reference",
                configured_reference,
                candidates,
                classified_details,
            )
        if unresolved or len(candidates) != 1:
            return _classified_resolution(
                "unresolved",
                "unresolved_reference",
                configured_reference,
                candidates,
                classified_details,
            )

        candidate = candidates[0]
        selected = self._resolve_configuration_candidate(
            dependency_input,
            candidate,
            candidates,
        )
        return DependencyResolution(
            state=selected.state,
            provenance="configuration_reference",
            configured_reference=configured_reference,
            candidates=candidates,
            selected_candidate=candidate if selected.state == "resolved" else None,
            selection=selected.value,
            causes=selected.causes,
            details=selected.details,
        )


def matching_configuration_resolutions(
    source: ConfigurationResolutionSource,
    accepted_paths: Collection[TerraformExpressionPath],
) -> tuple[TerraformReferenceResolution, ...]:
    """Return accepted configuration-reference resolutions in source order."""

    allowed_paths = frozenset(accepted_paths)
    return tuple(
        resolution
        for resolution in source.reference_resolutions
        if resolution.path in allowed_paths
        and resolution.provenance == TerraformReferenceProvenance.CONFIGURATION_REFERENCE
    )


def configured_reference_is_symbolic(
    configured_reference: str,
    resolutions: Collection[TerraformReferenceResolution],
) -> bool:
    """Whether a retained value is a spelling of one symbolic target."""

    normalized = configured_reference.strip()
    return any(
        normalized in {target.address, target.reference, f"${{{target.reference}}}"}
        for resolution in resolutions
        for target in resolution.targets
    )


def effective_configuration_path(
    dependency_input: DependencyInput[_ResourceT, _InputMetadataT],
) -> TerraformExpressionPath:
    """Use one exact retained path, otherwise the adapter's canonical path."""

    resolutions = matching_configuration_resolutions(
        dependency_input.source,
        dependency_input.resolution_paths,
    )
    return resolutions[0].path if len(resolutions) == 1 else dependency_input.configuration_path


def _symbolic_configured_reference(
    resolutions: tuple[TerraformReferenceResolution, ...],
    candidates: tuple[DependencyCandidate[_CandidateT, _CandidateMetadataT], ...],
) -> str | None:
    if len(candidates) == 1:
        return candidates[0].reference
    if len(resolutions) == 1 and len(resolutions[0].references) == 1:
        return resolutions[0].references[0]
    return None


def _classified_resolution(
    state: DependencyResolutionState,
    cause: DependencyResolutionCause,
    configured_reference: str | None,
    candidates: tuple[DependencyCandidate[_CandidateT, _CandidateMetadataT], ...],
    details: tuple[str, ...],
) -> DependencyResolution[_CandidateT, _CandidateMetadataT, _SelectionT]:
    return DependencyResolution(
        state=state,
        provenance="configuration_reference",
        configured_reference=configured_reference,
        candidates=candidates,
        selected_candidate=None,
        selection=None,
        causes=(cause,),
        details=details,
    )


def _dedupe_strings(values: Collection[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value))
