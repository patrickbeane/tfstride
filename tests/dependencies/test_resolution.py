from __future__ import annotations

import inspect
import unittest
from dataclasses import FrozenInstanceError, dataclass
from typing import get_args

from tfstride.dependencies import (
    CandidateAssessment,
    CandidateSelection,
    DependencyCandidate,
    DependencyInput,
    DependencyReferenceProvenance,
    DependencyResolution,
    DependencyResolutionCause,
    DependencyResolutionState,
    DependencyResolver,
    configured_reference_is_symbolic,
    effective_configuration_path,
    matching_configuration_resolutions,
)
from tfstride.dependencies import resolution as resolution_module
from tfstride.models import (
    TerraformExpressionPath,
    TerraformReferenceProvenance,
    TerraformReferenceResolution,
    TerraformReferenceResolutionState,
    TerraformReferenceTarget,
)

_PRIMARY_PATH = ("encryption", 0, "key_id")
_ALTERNATE_PATH = ("encryption", 0, "key_uri")


@dataclass(slots=True)
class _Resource:
    address: str
    reference_resolutions: tuple[TerraformReferenceResolution, ...] = ()


@dataclass(frozen=True, slots=True)
class _Candidate:
    address: str
    identity_known: bool = True


def _resolution(
    path: TerraformExpressionPath,
    targets: tuple[tuple[str, str], ...] = (),
    *,
    state: TerraformReferenceResolutionState = TerraformReferenceResolutionState.SYMBOLIC,
    provenance: TerraformReferenceProvenance | None = TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
    reason: str | None = None,
) -> TerraformReferenceResolution:
    references = tuple(reference for _, reference in targets)
    return TerraformReferenceResolution(
        path=path,
        state=state,
        provenance=provenance,
        references=references,
        targets=tuple(TerraformReferenceTarget(address=address, reference=reference) for address, reference in targets),
        reason=reason,
    )


def _input(
    source: _Resource,
    *,
    configured_reference: str | None = None,
    source_uncertainties: tuple[str, ...] = (),
    configuration_path: TerraformExpressionPath = _PRIMARY_PATH,
    resolution_paths: tuple[TerraformExpressionPath, ...] = (_PRIMARY_PATH,),
) -> DependencyInput[_Resource, None]:
    return DependencyInput(
        dependent=_Resource("workload.example"),
        source=source,
        configuration_path=configuration_path,
        resolution_paths=resolution_paths,
        configured_reference=configured_reference,
        source_uncertainties=source_uncertainties,
        adapter_data=None,
    )


def _resolver(
    candidates: dict[str, _Candidate],
    *,
    calls: list[str] | None = None,
    reconcile=None,
) -> DependencyResolver[_Resource, None, _Candidate, str, _Candidate]:
    observed_calls = calls if calls is not None else []

    def resolve_native(
        dependency_input: DependencyInput[_Resource, None],
        reference: str,
    ) -> DependencyResolution[_Candidate, str, _Candidate]:
        _ = dependency_input
        observed_calls.append(f"native:{reference}")
        address = reference.removeprefix("native:")
        candidate_value = candidates[address]
        candidate = DependencyCandidate(
            address=address,
            value=candidate_value,
            reference=reference,
            metadata="native",
        )
        return DependencyResolution(
            state="resolved",
            provenance="planned_value",
            configured_reference=reference,
            candidates=(candidate,),
            selected_candidate=candidate,
            selection=candidate_value,
        )

    def assess_target(
        dependency_input: DependencyInput[_Resource, None],
        target: TerraformReferenceTarget,
    ) -> CandidateAssessment[_Candidate, str]:
        _ = dependency_input
        observed_calls.append(f"assess:{target.reference}")
        candidate = candidates.get(target.address)
        if target.reference.endswith(".versionless_id"):
            metadata = "versionless"
            supported = candidate is not None
            details: tuple[str, ...] = ()
        elif target.reference.endswith(".id"):
            metadata = "versioned"
            supported = candidate is not None
            details = ()
        else:
            metadata = "unsupported"
            supported = False
            details = (f"unsupported target: {target.reference}",)
        if candidate is None:
            details = (*details, f"unknown target: {target.address}")
        return CandidateAssessment(
            candidate=candidate,
            metadata=metadata,
            supported=supported,
            details=details,
        )

    def select_candidate(
        dependency_input: DependencyInput[_Resource, None],
        candidate: DependencyCandidate[_Candidate, str],
        all_candidates: tuple[DependencyCandidate[_Candidate, str], ...],
    ) -> CandidateSelection[_Candidate]:
        _ = all_candidates
        observed_calls.append(f"select:{candidate.address}")
        if candidate.value.identity_known:
            return CandidateSelection(state="resolved", value=candidate.value)
        return CandidateSelection(
            state="unresolved",
            value=None,
            causes=("unresolved_reference",),
            details=(
                f"candidate identity unresolved: {candidate.address}",
                *dependency_input.source_uncertainties,
            ),
        )

    return DependencyResolver(
        resolve_native_reference=resolve_native,
        assess_configuration_target=assess_target,
        resolve_configuration_candidate=select_candidate,
        reconcile_evidence=reconcile,
    )


class DependencyResolutionTests(unittest.TestCase):
    def test_typed_vocabularies_are_complete(self) -> None:
        self.assertEqual(
            get_args(DependencyResolutionState),
            ("resolved", "ambiguous", "unresolved", "unsupported"),
        )
        self.assertEqual(
            get_args(DependencyReferenceProvenance),
            ("planned_value", "configuration_reference"),
        )
        self.assertEqual(
            get_args(DependencyResolutionCause),
            (
                "multiple_candidates",
                "unsupported_reference",
                "unresolved_reference",
                "missing_reference",
                "conflicting_candidate_evidence",
                "conflicting_evidence",
            ),
        )

    def test_matching_filters_paths_and_provenance_without_reordering(self) -> None:
        accepted_first = _resolution(_ALTERNATE_PATH)
        rejected_path = _resolution(("other",))
        rejected_provenance = _resolution(
            _PRIMARY_PATH,
            provenance=TerraformReferenceProvenance.PLANNED_VALUE,
        )
        accepted_second = _resolution(_PRIMARY_PATH)
        source = _Resource(
            "source.example",
            (
                accepted_first,
                rejected_path,
                rejected_provenance,
                accepted_second,
            ),
        )

        self.assertEqual(
            matching_configuration_resolutions(
                source,
                (_PRIMARY_PATH, _ALTERNATE_PATH),
            ),
            (accepted_first, accepted_second),
        )
        dependency_input = _input(
            source,
            configuration_path=("canonical",),
            resolution_paths=(_PRIMARY_PATH, _ALTERNATE_PATH),
        )
        self.assertEqual(
            effective_configuration_path(dependency_input),
            ("canonical",),
        )

    def test_one_matching_resolution_supplies_the_exact_configuration_path(self) -> None:
        source = _Resource("source.example", (_resolution(_ALTERNATE_PATH),))
        dependency_input = _input(
            source,
            configuration_path=("canonical",),
            resolution_paths=(_PRIMARY_PATH, _ALTERNATE_PATH),
        )

        self.assertEqual(
            effective_configuration_path(dependency_input),
            _ALTERNATE_PATH,
        )

    def test_native_reference_resolution_preserves_planned_value_provenance(self) -> None:
        candidate = _Candidate("key.primary")
        calls: list[str] = []
        resolution = _resolver({candidate.address: candidate}, calls=calls).resolve(
            _input(
                _Resource("source.example"),
                configured_reference="native:key.primary",
            )
        )

        self.assertEqual(resolution.state, "resolved")
        self.assertEqual(resolution.provenance, "planned_value")
        self.assertEqual(resolution.configured_reference, "native:key.primary")
        self.assertIs(resolution.selected_candidate.value, candidate)
        self.assertIs(resolution.selection, candidate)
        self.assertEqual(calls, ["native:native:key.primary"])

    def test_symbolic_spellings_use_configuration_resolution(self) -> None:
        candidate = _Candidate("key.primary")
        retained = _resolution(
            _PRIMARY_PATH,
            ((candidate.address, f"{candidate.address}.id"),),
        )
        for configured_reference in (
            candidate.address,
            f"{candidate.address}.id",
            f"${{{candidate.address}.id}}",
        ):
            with self.subTest(configured_reference=configured_reference):
                calls: list[str] = []
                dependency_input = _input(
                    _Resource("source.example", (retained,)),
                    configured_reference=configured_reference,
                )
                resolution = _resolver(
                    {candidate.address: candidate},
                    calls=calls,
                ).resolve(dependency_input)

                self.assertTrue(
                    configured_reference_is_symbolic(
                        configured_reference,
                        (retained,),
                    )
                )
                self.assertEqual(resolution.state, "resolved")
                self.assertEqual(
                    resolution.provenance,
                    "configuration_reference",
                )
                self.assertEqual(
                    resolution.configured_reference,
                    f"{candidate.address}.id",
                )
                self.assertEqual(
                    calls,
                    [
                        f"assess:{candidate.address}.id",
                        f"select:{candidate.address}",
                    ],
                )

    def test_candidates_are_sorted_deduplicated_and_not_selected_when_ambiguous(self) -> None:
        candidates = {address: _Candidate(address) for address in ("key.alpha", "key.beta")}
        retained = _resolution(
            _PRIMARY_PATH,
            (
                ("key.beta", "key.beta.id"),
                ("key.alpha", "key.alpha.id"),
                ("key.beta", "key.beta.id"),
            ),
            state=TerraformReferenceResolutionState.AMBIGUOUS,
        )
        calls: list[str] = []
        resolution = _resolver(candidates, calls=calls).resolve(
            _input(
                _Resource("source.example", (retained,)),
                source_uncertainties=("second", "first", "second"),
            )
        )

        self.assertEqual(resolution.state, "ambiguous")
        self.assertEqual(resolution.causes, ("multiple_candidates",))
        self.assertEqual(
            [candidate.address for candidate in resolution.candidates],
            ["key.alpha", "key.beta"],
        )
        self.assertEqual(resolution.details, ("second", "first"))
        self.assertIsNone(resolution.selected_candidate)
        self.assertFalse(any(call.startswith("select:") for call in calls))

    def test_unresolved_and_unsupported_states_fail_closed_before_selection(self) -> None:
        candidate = _Candidate("key.primary")
        cases = (
            (
                "unresolved",
                _resolution(
                    _PRIMARY_PATH,
                    ((candidate.address, f"{candidate.address}.id"),),
                    state=TerraformReferenceResolutionState.UNRESOLVED,
                    reason="configuration is unresolved",
                ),
                "unresolved_reference",
                ("configuration is unresolved", "source is uncertain"),
            ),
            (
                "unsupported",
                _resolution(
                    _PRIMARY_PATH,
                    ((candidate.address, f"{candidate.address}.name"),),
                ),
                "unsupported_reference",
                (
                    f"unsupported target: {candidate.address}.name",
                    "source is uncertain",
                ),
            ),
        )

        for state, retained, cause, details in cases:
            with self.subTest(state=state):
                calls: list[str] = []
                resolution = _resolver(
                    {candidate.address: candidate},
                    calls=calls,
                ).resolve(
                    _input(
                        _Resource("source.example", (retained,)),
                        source_uncertainties=("source is uncertain",),
                    )
                )

                self.assertEqual(resolution.state, state)
                self.assertEqual(resolution.causes, (cause,))
                self.assertEqual(resolution.details, details)
                self.assertEqual(
                    [item.address for item in resolution.candidates],
                    [candidate.address],
                )
                self.assertIsNone(resolution.selected_candidate)
                self.assertFalse(any(call.startswith("select:") for call in calls))

    def test_conflicting_candidate_metadata_is_unsupported(self) -> None:
        candidate = _Candidate("key.primary")
        retained = _resolution(
            _PRIMARY_PATH,
            (
                (candidate.address, f"{candidate.address}.id"),
                (candidate.address, f"{candidate.address}.versionless_id"),
            ),
        )
        resolution = _resolver({candidate.address: candidate}).resolve(_input(_Resource("source.example", (retained,))))

        self.assertEqual(resolution.state, "unsupported")
        self.assertEqual(
            resolution.causes,
            ("conflicting_candidate_evidence",),
        )
        self.assertEqual(len(resolution.candidates), 1)
        self.assertEqual(resolution.candidates[0].metadata, "versioned")
        self.assertIsNone(resolution.selected_candidate)

    def test_unique_candidate_with_unknown_identity_remains_unresolved(self) -> None:
        candidate = _Candidate("key.pending", identity_known=False)
        retained = _resolution(
            _PRIMARY_PATH,
            ((candidate.address, f"{candidate.address}.id"),),
        )
        resolution = _resolver({candidate.address: candidate}).resolve(
            _input(
                _Resource("source.example", (retained,)),
                source_uncertainties=("source is uncertain",),
            )
        )

        self.assertEqual(resolution.state, "unresolved")
        self.assertEqual(resolution.causes, ("unresolved_reference",))
        self.assertEqual(
            resolution.details,
            (
                f"candidate identity unresolved: {candidate.address}",
                "source is uncertain",
            ),
        )
        self.assertEqual(
            [item.address for item in resolution.candidates],
            [candidate.address],
        )
        self.assertIsNone(resolution.selected_candidate)
        self.assertIsNone(resolution.selection)

    def test_missing_reference_is_unresolved_without_fabricating_candidates(self) -> None:
        resolution = _resolver({}).resolve(
            _input(
                _Resource("source.example"),
                source_uncertainties=("reference is absent",),
            )
        )

        self.assertEqual(resolution.state, "unresolved")
        self.assertIsNone(resolution.provenance)
        self.assertEqual(resolution.causes, ("missing_reference",))
        self.assertEqual(resolution.details, ("reference is absent",))
        self.assertEqual(resolution.candidates, ())

    def test_optional_reconciler_can_fail_closed_on_conflicting_evidence(self) -> None:
        native_candidate = _Candidate("key.native")
        symbolic_candidate = _Candidate("key.symbolic")
        retained = _resolution(
            _PRIMARY_PATH,
            ((symbolic_candidate.address, f"{symbolic_candidate.address}.id"),),
        )
        reconciled: list[tuple[str, str]] = []

        def reconcile(
            dependency_input: DependencyInput[_Resource, None],
            native: DependencyResolution[_Candidate, str, _Candidate],
            symbolic: DependencyResolution[_Candidate, str, _Candidate],
        ) -> DependencyResolution[_Candidate, str, _Candidate]:
            _ = dependency_input
            reconciled.append((native.state, symbolic.state))
            candidates = tuple(
                sorted(
                    (*native.candidates, *symbolic.candidates),
                    key=lambda candidate: candidate.address,
                )
            )
            return DependencyResolution(
                state="ambiguous",
                provenance="planned_value",
                configured_reference=native.configured_reference,
                candidates=candidates,
                selected_candidate=None,
                selection=None,
                causes=("conflicting_evidence",),
            )

        resolution = _resolver(
            {
                native_candidate.address: native_candidate,
                symbolic_candidate.address: symbolic_candidate,
            },
            reconcile=reconcile,
        ).resolve(
            _input(
                _Resource("source.example", (retained,)),
                configured_reference=f"native:{native_candidate.address}",
            )
        )

        self.assertEqual(reconciled, [("resolved", "resolved")])
        self.assertEqual(resolution.state, "ambiguous")
        self.assertEqual(resolution.causes, ("conflicting_evidence",))
        self.assertEqual(
            [candidate.address for candidate in resolution.candidates],
            [native_candidate.address, symbolic_candidate.address],
        )

    def test_record_renderer_receives_resolution_and_exact_path(self) -> None:
        candidate = _Candidate("key.primary")
        retained = _resolution(
            _ALTERNATE_PATH,
            ((candidate.address, f"{candidate.address}.id"),),
        )
        dependency_input = _input(
            _Resource("source.example", (retained,)),
            configuration_path=("canonical",),
            resolution_paths=(_PRIMARY_PATH, _ALTERNATE_PATH),
        )

        record = _resolver({candidate.address: candidate}).resolve_record(
            dependency_input,
            render=lambda received_input, resolution, path: {
                "same_input": received_input is dependency_input,
                "state": resolution.state,
                "path": path,
            },
        )

        self.assertEqual(
            record,
            {
                "same_input": True,
                "state": "resolved",
                "path": _ALTERNATE_PATH,
            },
        )

    def test_envelopes_are_frozen_slotted_and_retain_exact_instances(self) -> None:
        dependent = _Resource("workload.example")
        source = _Resource("source.example")
        candidate_value = _Candidate("key.primary")
        adapter_data = object()
        dependency_input = DependencyInput(
            dependent=dependent,
            source=source,
            configuration_path=_PRIMARY_PATH,
            resolution_paths=(_PRIMARY_PATH,),
            configured_reference=None,
            source_uncertainties=(),
            adapter_data=adapter_data,
        )
        candidate = DependencyCandidate(
            address=candidate_value.address,
            value=candidate_value,
            reference=f"{candidate_value.address}.id",
            metadata="versioned",
        )
        resolution = DependencyResolution(
            state="resolved",
            provenance="configuration_reference",
            configured_reference=candidate.reference,
            candidates=(candidate,),
            selected_candidate=candidate,
            selection=candidate_value,
        )

        self.assertIs(dependency_input.dependent, dependent)
        self.assertIs(dependency_input.source, source)
        self.assertIs(dependency_input.adapter_data, adapter_data)
        self.assertIs(resolution.selected_candidate.value, candidate_value)
        for envelope in (dependency_input, candidate, resolution):
            with self.subTest(envelope=type(envelope).__name__):
                self.assertFalse(hasattr(envelope, "__dict__"))
        with self.assertRaises(FrozenInstanceError):
            resolution.state = "unresolved"  # pyright: ignore[reportAttributeAccessIssue]

    def test_module_has_no_provider_or_rule_dependencies(self) -> None:
        source = inspect.getsource(resolution_module)

        self.assertNotIn("tfstride.providers", source)
        self.assertNotIn("provider ==", source)
        self.assertNotIn("aws", source.casefold())
        self.assertNotIn("gcp", source.casefold())
        self.assertNotIn("azure", source.casefold())
        self.assertNotIn("arn", source.casefold())
        self.assertNotIn("resource_name", source)
        self.assertNotIn("urlsplit", source)
        self.assertNotIn("ResourceFacts", source)
        self.assertNotIn("FindingFactory", source)
        self.assertNotIn("SeverityReasoning", source)


if __name__ == "__main__":
    unittest.main()
