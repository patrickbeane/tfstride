from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, replace
from functools import partial
from urllib.parse import urlsplit

from tfstride.dependencies import (
    CandidateAssessment,
    CandidateSelection,
    DependencyCandidate,
    DependencyInput,
    DependencyResolution,
    DependencyResolutionCause,
    DependencyResolutionState,
    DependencyResolver,
    matching_configuration_resolutions,
)
from tfstride.models import (
    NormalizedResource,
    TerraformExpressionPath,
    TerraformReferenceTarget,
)
from tfstride.providers.azure.key_vault_dependency_evidence import (
    AzureKeyVaultDependencyReferenceKind,
    AzureKeyVaultDependencyTargetKind,
    AzureKeyVaultEncryptionDependency,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.resource_utils import azure_reference_key
from tfstride.providers.coercion import (
    STATE_CONFIGURED,
    STATE_NOT_CONFIGURED,
    STATE_UNKNOWN,
)
from tfstride.providers.resource_reference_index import (
    ResourceReferenceIndex,
    build_resource_reference_index,
)

_KEY = AzureResourceType.KEY_VAULT_KEY
_SUPPORTED_DEPENDENT_TYPES = frozenset(
    {
        AzureResourceType.CONTAINER_REGISTRY,
        AzureResourceType.COSMOSDB_ACCOUNT,
        AzureResourceType.KUBERNETES_CLUSTER,
        AzureResourceType.SERVICE_BUS_NAMESPACE,
        AzureResourceType.STORAGE_ACCOUNT,
    }
)
_URI_REFERENCE_KINDS: frozenset[AzureKeyVaultDependencyReferenceKind] = frozenset(
    {
        "versioned_uri",
        "versionless_uri",
    }
)
_VERSIONLESS_URI_REFERENCE_KINDS: frozenset[AzureKeyVaultDependencyReferenceKind] = frozenset(
    {
        "versionless_uri",
    }
)
_URI_REFERENCE_SUFFIXES = frozenset({".id", ".versionless_id"})
_VERSIONLESS_URI_REFERENCE_SUFFIXES = frozenset({".versionless_id"})
_KEY_VAULT_DNS_SUFFIXES = (
    ".vault.azure.net",
    ".vault.azure.cn",
    ".vault.usgovcloudapi.net",
)


@dataclass(frozen=True, slots=True)
class _AzureDependencyInputData:
    ownership_state: str | None
    allowed_reference_kinds: frozenset[AzureKeyVaultDependencyReferenceKind]
    allowed_reference_suffixes: frozenset[str]
    source_evidence_ambiguous: bool = False


_AzureCandidateMetadata = AzureKeyVaultDependencyTargetKind | None
_AzureDependencyInput = DependencyInput[NormalizedResource, _AzureDependencyInputData]
_AzureDependencyCandidate = DependencyCandidate[NormalizedResource, _AzureCandidateMetadata]
_AzureDependencyResolution = DependencyResolution[
    NormalizedResource,
    _AzureCandidateMetadata,
    NormalizedResource,
]
_AzureDependencyResolver = DependencyResolver[
    NormalizedResource,
    _AzureDependencyInputData,
    NormalizedResource,
    _AzureCandidateMetadata,
    NormalizedResource,
]
_AzureCandidateAssessment = CandidateAssessment[
    NormalizedResource,
    _AzureCandidateMetadata,
]


class ResolveAzureKeyVaultEncryptionDependenciesStage:
    name = "resolve_azure_key_vault_encryption_dependencies"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AzureDecorationContext,
    ) -> None:
        _ = context
        keys = tuple(resource for resource in resources if resource.resource_type == _KEY)
        native_index = build_resource_reference_index(
            keys,
            references_for_resource=_native_key_references,
            reference_key=azure_reference_key,
        )
        resources_by_address = {resource.address: resource for resource in resources}
        resolver = _dependency_resolver(
            native_index=native_index,
            resources_by_address=resources_by_address,
        )
        render_dependency = partial(
            _render_dependency_record,
            resources_by_address=resources_by_address,
        )

        dependencies_by_address: dict[str, list[AzureKeyVaultEncryptionDependency]] = {
            resource.address: []
            for resource in resources
            if resource.resource_type in _SUPPORTED_DEPENDENT_TYPES or resource.resource_type == _KEY
        }
        uncertainties_by_address: dict[str, list[str]] = {address: [] for address in dependencies_by_address}

        for dependent in resources:
            if dependent.resource_type not in _SUPPORTED_DEPENDENT_TYPES:
                continue
            inputs, uncovered_uncertainties = _dependency_inputs(
                dependent,
                resources_by_address=resources_by_address,
            )
            uncertainties_by_address[dependent.address].extend(
                f"{dependent.address}: {uncertainty}" for uncertainty in uncovered_uncertainties
            )
            for dependency_input in inputs:
                record = resolver.resolve_record(
                    dependency_input,
                    render=render_dependency,
                )
                dependencies_by_address[dependent.address].append(record)
                uncertainties_by_address[dependent.address].extend(
                    f"{dependent.address}: {uncertainty}" for uncertainty in record["posture_uncertainties"]
                )
                if record["resolution_state"] != "resolved":
                    continue
                key_address = record["key_address"]
                if key_address is not None:
                    dependencies_by_address.setdefault(key_address, []).append(record)

        for address, dependencies in dependencies_by_address.items():
            resource = resources_by_address.get(address)
            if resource is None:
                continue
            azure_facts(resource).set_key_vault_encryption_dependency_posture(
                dependencies=sorted(dependencies, key=_dependency_sort_key),
                uncertainties=_dedupe(uncertainties_by_address.get(address, [])),
            )


def _dependency_inputs(
    dependent: NormalizedResource,
    *,
    resources_by_address: Mapping[str, NormalizedResource],
) -> tuple[list[_AzureDependencyInput], list[str]]:
    facts = azure_facts(dependent)
    if dependent.resource_type == AzureResourceType.STORAGE_ACCOUNT:
        paths = (
            ("customer_managed_key", 0, "key_vault_key_id"),
            ("customer_managed_key", 0, "key_vault_key_uri"),
        )
        uncertainties = _matching_uncertainties(
            facts.storage_posture_uncertainties,
            ("customer_managed_key",),
        )
        return _alternate_dependency_inputs(
            dependent=dependent,
            source=dependent,
            fields=(
                (
                    ("customer_managed_key", 0, "key_vault_key_id"),
                    facts.storage_customer_managed_key_id_reference,
                ),
                (
                    ("customer_managed_key", 0, "key_vault_key_uri"),
                    facts.storage_customer_managed_key_uri_reference,
                ),
            ),
            ownership_state=_ownership_state(
                facts.storage_customer_managed_key_id,
                dependent,
                paths,
                uncertainties,
            ),
            uncertainties=uncertainties,
            allowed_reference_kinds=_URI_REFERENCE_KINDS,
            allowed_reference_suffixes=_URI_REFERENCE_SUFFIXES,
        )

    if dependent.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE:
        source_address = facts.service_bus_customer_managed_key_source_address
        source = resources_by_address.get(source_address) if source_address is not None else dependent
        if source is None:
            return [], [f"customer-managed key source {source_address} is not a modeled Azure resource"]
        source_facts = azure_facts(source)
        if source.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE_CUSTOMER_MANAGED_KEY:
            paths = (("key_vault_key_id",),)
            uncertainties = _matching_path_uncertainties(
                source_facts.service_bus_posture_uncertainties,
                paths[0],
            )
            return _single_dependency_inputs(
                dependent=dependent,
                source=source,
                configuration_path=paths[0],
                resolution_paths=paths,
                configured_reference=source_facts.service_bus_key_vault_key_id_reference,
                ownership_state=facts.service_bus_customer_managed_key_state,
                uncertainties=uncertainties,
                allowed_reference_kinds=_URI_REFERENCE_KINDS,
                allowed_reference_suffixes=_URI_REFERENCE_SUFFIXES,
            )
        if source.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE:
            return _alternate_dependency_inputs(
                dependent=dependent,
                source=source,
                fields=(
                    (
                        ("customer_managed_key", 0, "key_vault_key_id"),
                        source_facts.service_bus_key_vault_key_id_reference,
                    ),
                    (
                        ("customer_managed_key", 0, "key_vault_key_uri"),
                        source_facts.service_bus_key_vault_key_uri_reference,
                    ),
                ),
                ownership_state=facts.service_bus_customer_managed_key_state,
                uncertainties=source_facts.service_bus_posture_uncertainties,
                allowed_reference_kinds=_URI_REFERENCE_KINDS,
                allowed_reference_suffixes=_URI_REFERENCE_SUFFIXES,
            )
        return [], [f"customer-managed key source {source.address} has unsupported type {source.resource_type}"]

    if dependent.resource_type == AzureResourceType.COSMOSDB_ACCOUNT:
        paths = (("key_vault_key_id",),)
        uncertainties = _matching_uncertainties(
            facts.cosmosdb_posture_uncertainties,
            ("key_vault_key_id",),
        )
        return _single_dependency_inputs(
            dependent=dependent,
            source=dependent,
            configuration_path=paths[0],
            resolution_paths=paths,
            configured_reference=facts.cosmosdb_key_vault_key_id,
            ownership_state=facts.cosmosdb_customer_managed_key_state,
            uncertainties=uncertainties,
            allowed_reference_kinds=_VERSIONLESS_URI_REFERENCE_KINDS,
            allowed_reference_suffixes=_VERSIONLESS_URI_REFERENCE_SUFFIXES,
        )

    if dependent.resource_type == AzureResourceType.CONTAINER_REGISTRY:
        paths = (("encryption", 0, "key_vault_key_id"),)
        uncertainties = _matching_uncertainties(
            facts.container_registry_posture_uncertainties,
            ("encryption", "key_vault_key_id"),
        )
        return _single_dependency_inputs(
            dependent=dependent,
            source=dependent,
            configuration_path=paths[0],
            resolution_paths=paths,
            configured_reference=facts.container_registry_key_vault_key_id,
            ownership_state=facts.container_registry_customer_managed_key_state,
            uncertainties=uncertainties,
            allowed_reference_kinds=_URI_REFERENCE_KINDS,
            allowed_reference_suffixes=_URI_REFERENCE_SUFFIXES,
        )

    if dependent.resource_type == AzureResourceType.KUBERNETES_CLUSTER:
        paths = (("key_management_service", 0, "key_vault_key_id"),)
        uncertainties = _matching_uncertainties(
            facts.aks_posture_uncertainties,
            ("key_management_service", "key_vault_key_id"),
        )
        return _single_dependency_inputs(
            dependent=dependent,
            source=dependent,
            configuration_path=paths[0],
            resolution_paths=paths,
            configured_reference=facts.aks_kms_key_vault_key_id,
            ownership_state=facts.aks_kms_state,
            uncertainties=uncertainties,
            allowed_reference_kinds=_URI_REFERENCE_KINDS,
            allowed_reference_suffixes=_URI_REFERENCE_SUFFIXES,
        )

    return [], []


def _single_dependency_inputs(
    *,
    dependent: NormalizedResource,
    source: NormalizedResource,
    configuration_path: TerraformExpressionPath,
    resolution_paths: tuple[TerraformExpressionPath, ...],
    configured_reference: str | None,
    ownership_state: str | None,
    uncertainties: Sequence[str],
    allowed_reference_kinds: frozenset[AzureKeyVaultDependencyReferenceKind],
    allowed_reference_suffixes: frozenset[str],
) -> tuple[list[_AzureDependencyInput], list[str]]:
    dependency = _input_if_relevant(
        dependent=dependent,
        source=source,
        configuration_path=configuration_path,
        resolution_paths=resolution_paths,
        configured_reference=configured_reference,
        ownership_state=ownership_state,
        source_uncertainties=uncertainties,
        allowed_reference_kinds=allowed_reference_kinds,
        allowed_reference_suffixes=allowed_reference_suffixes,
    )
    if dependency is None:
        return [], list(uncertainties)
    return [dependency], [
        uncertainty for uncertainty in uncertainties if uncertainty not in dependency.source_uncertainties
    ]


def _alternate_dependency_inputs(
    *,
    dependent: NormalizedResource,
    source: NormalizedResource,
    fields: tuple[
        tuple[TerraformExpressionPath, str | None],
        tuple[TerraformExpressionPath, str | None],
    ],
    ownership_state: str | None,
    uncertainties: Sequence[str],
    allowed_reference_kinds: frozenset[AzureKeyVaultDependencyReferenceKind],
    allowed_reference_suffixes: frozenset[str],
) -> tuple[list[_AzureDependencyInput], list[str]]:
    inputs: list[_AzureDependencyInput] = []
    consumed_uncertainties: set[str] = set()
    for path, configured_reference in fields:
        path_uncertainties = _matching_path_uncertainties(uncertainties, path)
        dependency = _input_if_relevant(
            dependent=dependent,
            source=source,
            configuration_path=path,
            resolution_paths=(path,),
            configured_reference=configured_reference,
            ownership_state=ownership_state,
            source_uncertainties=path_uncertainties,
            allowed_reference_kinds=allowed_reference_kinds,
            allowed_reference_suffixes=allowed_reference_suffixes,
            unknown_ownership_establishes_relevance=False,
        )
        if dependency is None:
            continue
        inputs.append(dependency)
        consumed_uncertainties.update(path_uncertainties)

    if len(inputs) > 1:
        inputs = [
            replace(
                dependency,
                adapter_data=replace(dependency.adapter_data, source_evidence_ambiguous=True),
            )
            for dependency in inputs
        ]
    return inputs, [uncertainty for uncertainty in uncertainties if uncertainty not in consumed_uncertainties]


def _input_if_relevant(
    *,
    dependent: NormalizedResource,
    source: NormalizedResource,
    configuration_path: TerraformExpressionPath,
    resolution_paths: tuple[TerraformExpressionPath, ...],
    configured_reference: str | None,
    ownership_state: str | None,
    source_uncertainties: Sequence[str],
    allowed_reference_kinds: frozenset[AzureKeyVaultDependencyReferenceKind],
    allowed_reference_suffixes: frozenset[str],
    unknown_ownership_establishes_relevance: bool = True,
) -> _AzureDependencyInput | None:
    if (
        configured_reference is None
        and not matching_configuration_resolutions(source, resolution_paths)
        and not source_uncertainties
        and (ownership_state != STATE_UNKNOWN or not unknown_ownership_establishes_relevance)
    ):
        return None
    return DependencyInput(
        dependent=dependent,
        source=source,
        configuration_path=configuration_path,
        resolution_paths=resolution_paths,
        configured_reference=configured_reference,
        source_uncertainties=tuple(source_uncertainties),
        adapter_data=_AzureDependencyInputData(
            ownership_state=ownership_state,
            allowed_reference_kinds=allowed_reference_kinds,
            allowed_reference_suffixes=allowed_reference_suffixes,
        ),
    )


def _dependency_resolver(
    *,
    native_index: ResourceReferenceIndex,
    resources_by_address: Mapping[str, NormalizedResource],
) -> _AzureDependencyResolver:
    def resolve_native(
        dependency_input: _AzureDependencyInput,
        reference: str,
    ) -> _AzureDependencyResolution:
        return _resolve_native_reference(
            reference,
            dependency_input,
            native_index=native_index,
        )

    def assess_target(
        dependency_input: _AzureDependencyInput,
        target: TerraformReferenceTarget,
    ) -> _AzureCandidateAssessment:
        return _assess_configuration_target(
            target,
            dependency_input=dependency_input,
            resources_by_address=resources_by_address,
        )

    return DependencyResolver(
        resolve_native_reference=resolve_native,
        assess_configuration_target=assess_target,
        resolve_configuration_candidate=_resolve_configuration_candidate,
        reconcile_evidence=_reconcile_concrete_and_symbolic,
    )


def _render_dependency_record(
    dependency_input: _AzureDependencyInput,
    resolution: _AzureDependencyResolution,
    configuration_path: TerraformExpressionPath,
    *,
    resources_by_address: Mapping[str, NormalizedResource],
) -> AzureKeyVaultEncryptionDependency:
    resolution = _apply_source_evidence_ambiguity(
        resolution,
        dependency_input,
    )
    selected_key = resolution.selection
    key_facts = azure_facts(selected_key) if selected_key is not None else None
    key_vault_address = key_facts.resolved_key_vault_address if key_facts is not None else None
    vault = resources_by_address.get(key_vault_address) if key_vault_address is not None else None
    vault_facts = azure_facts(vault) if vault is not None else None
    key_versionless_uri = key_facts.key_vault_key_versionless_uri if key_facts is not None else None
    key_versionless_resource_id = key_facts.key_vault_key_versionless_resource_id if key_facts is not None else None
    configured_reference = resolution.configured_reference
    if resolution.provenance == "configuration_reference" and not resolution.candidates:
        configured_reference = None
    return {
        "dependent_address": dependency_input.dependent.address,
        "dependent_resource_type": dependency_input.dependent.resource_type,
        "dependency_source_address": dependency_input.source.address,
        "dependency_source_type": dependency_input.source.resource_type,
        "configuration_path": list(configuration_path),
        "configured_key_reference": configured_reference,
        "reference_provenance": resolution.provenance,
        "reference_kind": _resolution_reference_kind(resolution),
        "resolution_state": resolution.state,
        "customer_managed_key_state": dependency_input.adapter_data.ownership_state,
        "candidate_key_addresses": [candidate.address for candidate in resolution.candidates],
        "target_kind": _resolution_target_kind(resolution),
        "key_address": selected_key.address if selected_key is not None else None,
        "key_vault_address": key_vault_address,
        "key_vault_id": (
            (vault_facts.key_vault_id if vault_facts is not None else None)
            or _vault_id_from_key_resource_id(key_versionless_resource_id)
        ),
        "key_vault_uri": (
            (vault_facts.key_vault_uri if vault_facts is not None else None)
            or _vault_uri_from_key_uri(key_versionless_uri)
        ),
        "key_name": (key_facts.key_vault_key_name if key_facts is not None else None),
        "key_version": (key_facts.key_vault_key_version if key_facts is not None else None),
        "key_uri": (key_facts.key_vault_key_uri if key_facts is not None else None),
        "key_versionless_uri": key_versionless_uri,
        "key_resource_id": (key_facts.key_vault_key_resource_id if key_facts is not None else None),
        "key_versionless_resource_id": key_versionless_resource_id,
        "posture_uncertainties": list(_resolution_uncertainties(dependency_input, resolution)),
    }


def _resolve_native_reference(
    reference: str,
    dependency_input: _AzureDependencyInput,
    *,
    native_index: ResourceReferenceIndex,
) -> _AzureDependencyResolution:
    normalized = reference.strip()
    reference_kind = _native_reference_kind(normalized)
    target_kind = _target_kind_for_reference_kind(reference_kind)
    candidates: tuple[_AzureDependencyCandidate, ...] = tuple(
        DependencyCandidate(
            address=candidate.address,
            value=candidate,
            reference=normalized,
            metadata=target_kind,
        )
        for candidate in native_index.candidates(normalized)
        if candidate.resource_type == _KEY
    )
    if reference_kind is None or reference_kind not in dependency_input.adapter_data.allowed_reference_kinds:
        return _unselected_resolution(
            state="unsupported",
            cause="unsupported_reference",
            configured_reference=normalized,
            candidates=candidates,
            uncertainties=(
                f"Key Vault key reference {normalized} has an unsupported identity "
                f"shape for {dependency_input.source.resource_type}",
                *dependency_input.source_uncertainties,
            ),
        )
    if len(candidates) > 1:
        return _unselected_resolution(
            state="ambiguous",
            cause="multiple_candidates",
            configured_reference=normalized,
            candidates=candidates,
            uncertainties=(
                f"Key Vault key reference {normalized} matches multiple modeled keys",
                *dependency_input.source_uncertainties,
            ),
        )
    if not candidates:
        return _unselected_resolution(
            state="unresolved",
            cause="unresolved_reference",
            configured_reference=normalized,
            candidates=(),
            uncertainties=(
                f"Key Vault key reference {normalized} does not resolve to a modeled key",
                *dependency_input.source_uncertainties,
            ),
        )

    candidate = candidates[0]
    selection = _resolve_configuration_candidate(
        dependency_input,
        candidate,
        candidates,
    )
    return DependencyResolution(
        state=selection.state,
        provenance="planned_value",
        configured_reference=normalized,
        candidates=candidates,
        selected_candidate=(candidate if selection.state == "resolved" else None),
        selection=selection.value,
        causes=selection.causes,
        details=selection.details,
    )


def _assess_configuration_target(
    target: TerraformReferenceTarget,
    *,
    dependency_input: _AzureDependencyInput,
    resources_by_address: Mapping[str, NormalizedResource],
) -> _AzureCandidateAssessment:
    candidate = resources_by_address.get(target.address)
    if candidate is None or candidate.resource_type != _KEY:
        return CandidateAssessment(
            candidate=None,
            metadata=None,
            supported=False,
            details=(f"Terraform target {target.address} is not a modeled Key Vault key",),
        )

    target_kind = _target_kind_for_reference_suffix(target.reference)
    if not any(
        target.reference.endswith(suffix) for suffix in dependency_input.adapter_data.allowed_reference_suffixes
    ):
        return CandidateAssessment(
            candidate=candidate,
            metadata=target_kind,
            supported=False,
            details=(
                f"Terraform target reference {target.reference} is unsupported "
                f"for {dependency_input.source.resource_type}",
            ),
        )
    return CandidateAssessment(
        candidate=candidate,
        metadata=target_kind,
        supported=True,
    )


def _resolve_configuration_candidate(
    dependency_input: _AzureDependencyInput,
    candidate: _AzureDependencyCandidate,
    candidates: tuple[_AzureDependencyCandidate, ...],
) -> CandidateSelection[NormalizedResource]:
    _ = candidates
    target_kind = candidate.metadata
    facts = azure_facts(candidate.value)
    if facts.key_vault_key_identity_state != "resolved" or not _identity_for_target_kind(candidate.value, target_kind):
        return CandidateSelection(
            state="unresolved",
            value=None,
            causes=("unresolved_reference",),
            details=tuple(
                _dedupe(
                    (
                        f"{candidate.address} does not retain the exact provider-native "
                        f"{_target_kind_label(target_kind)} identity required by the dependency",
                        *dependency_input.source_uncertainties,
                    )
                )
            ),
        )
    return CandidateSelection(
        state="resolved",
        value=candidate.value,
        details=_applicability_uncertainties(dependency_input),
    )


def _reconcile_concrete_and_symbolic(
    dependency_input: _AzureDependencyInput,
    concrete: _AzureDependencyResolution,
    symbolic: _AzureDependencyResolution,
) -> _AzureDependencyResolution:
    if symbolic.state != "resolved" or symbolic.selected_candidate is None:
        return concrete
    if (
        concrete.selected_candidate is not None
        and concrete.selected_candidate.address == symbolic.selected_candidate.address
        and concrete.selected_candidate.metadata == symbolic.selected_candidate.metadata
    ):
        return concrete

    candidates = tuple(
        sorted(
            {candidate.address: candidate for candidate in (*concrete.candidates, *symbolic.candidates)}.values(),
            key=lambda candidate: candidate.address,
        )
    )
    return DependencyResolution(
        state="ambiguous",
        provenance="planned_value",
        configured_reference=concrete.configured_reference,
        candidates=candidates,
        selected_candidate=None,
        selection=None,
        causes=("conflicting_evidence",),
        details=tuple(
            _dedupe(
                (
                    "Concrete Key Vault key identity conflicts with symbolic "
                    f"configuration evidence at {list(dependency_input.configuration_path)}",
                    *concrete.details,
                    *symbolic.details,
                )
            )
        ),
    )


def _apply_source_evidence_ambiguity(
    resolution: _AzureDependencyResolution,
    dependency_input: _AzureDependencyInput,
) -> _AzureDependencyResolution:
    if not dependency_input.adapter_data.source_evidence_ambiguous:
        return resolution
    return replace(
        resolution,
        state="ambiguous",
        selected_candidate=None,
        selection=None,
        details=tuple(
            _dedupe(
                (
                    "Multiple alternate Key Vault key fields contain relationship "
                    "evidence; no exact source field is authoritative",
                    *resolution.details,
                )
            )
        ),
    )


def _unselected_resolution(
    *,
    state: DependencyResolutionState,
    cause: DependencyResolutionCause,
    configured_reference: str,
    candidates: tuple[_AzureDependencyCandidate, ...],
    uncertainties: Sequence[str],
) -> _AzureDependencyResolution:
    return DependencyResolution(
        state=state,
        provenance="planned_value",
        configured_reference=configured_reference,
        candidates=candidates,
        selected_candidate=None,
        selection=None,
        causes=(cause,),
        details=tuple(_dedupe(uncertainties)),
    )


def _resolution_reference_kind(
    resolution: _AzureDependencyResolution,
) -> AzureKeyVaultDependencyReferenceKind | None:
    if resolution.provenance == "configuration_reference":
        return "terraform_reference"
    if resolution.configured_reference is None:
        return None
    return _native_reference_kind(resolution.configured_reference)


def _resolution_target_kind(
    resolution: _AzureDependencyResolution,
) -> AzureKeyVaultDependencyTargetKind | None:
    if any(cause in {"conflicting_candidate_evidence", "conflicting_evidence"} for cause in resolution.causes):
        return None
    if resolution.provenance == "planned_value":
        return _target_kind_for_reference_kind(_resolution_reference_kind(resolution))
    target_kinds: set[AzureKeyVaultDependencyTargetKind] = {
        candidate.metadata for candidate in resolution.candidates if candidate.metadata is not None
    }
    return next(iter(target_kinds)) if len(target_kinds) == 1 else None


def _resolution_uncertainties(
    dependency_input: _AzureDependencyInput,
    resolution: _AzureDependencyResolution,
) -> tuple[str, ...]:
    if dependency_input.adapter_data.source_evidence_ambiguous:
        return resolution.details
    if resolution.state == "resolved":
        return resolution.details
    if resolution.provenance is None:
        return resolution.details or ("Key Vault key reference is unresolved",)
    if resolution.provenance == "planned_value":
        return resolution.details

    source_uncertainties = frozenset(dependency_input.source_uncertainties)
    specific_details = tuple(detail for detail in resolution.details if detail not in source_uncertainties)
    if resolution.state == "ambiguous":
        return tuple(
            _dedupe(
                (
                    "Terraform configuration reference has multiple modeled Key Vault key targets",
                    *resolution.details,
                )
            )
        )
    if specific_details:
        return resolution.details
    fallback = (
        "Terraform configuration reference uses unsupported Key Vault key relationship evidence"
        if resolution.state == "unsupported"
        else "Terraform configuration reference does not resolve to a modeled Key Vault key"
    )
    return tuple(
        _dedupe(
            (
                fallback,
                *dependency_input.source_uncertainties,
            )
        )
    )


def _native_key_references(
    resource: NormalizedResource,
) -> tuple[str | None, ...]:
    if resource.resource_type != _KEY:
        return ()
    facts = azure_facts(resource)
    if facts.key_vault_key_identity_state != "resolved":
        return ()
    return (
        facts.key_vault_key_uri,
        facts.key_vault_key_versionless_uri,
        facts.key_vault_key_resource_id,
        facts.key_vault_key_versionless_resource_id,
    )


def _native_reference_kind(
    reference: str,
) -> AzureKeyVaultDependencyReferenceKind | None:
    parsed_uri = _parse_key_uri(reference)
    if parsed_uri is not None:
        return "versioned_uri" if parsed_uri else "versionless_uri"
    parsed_resource_id = _parse_key_resource_id(reference)
    if parsed_resource_id is not None:
        return "versioned_resource_id" if parsed_resource_id else "versionless_resource_id"
    if reference.casefold().startswith("azurerm_key_vault_key."):
        return "terraform_reference"
    return None


def _parse_key_uri(reference: str) -> bool | None:
    parsed = urlsplit(reference.strip())
    host = parsed.hostname
    segments = [segment for segment in parsed.path.split("/") if segment]
    if (
        parsed.scheme.casefold() != "https"
        or host is None
        or parsed.netloc.casefold() != host.casefold()
        or parsed.query
        or parsed.fragment
        or len(segments) not in {2, 3}
        or segments[0].casefold() != "keys"
        or not all(_valid_path_segment(segment) for segment in segments[1:])
        or not _is_key_vault_host(host)
    ):
        return None
    return len(segments) == 3


def _parse_key_resource_id(reference: str) -> bool | None:
    segments = [segment for segment in reference.strip().split("/") if segment]
    if (
        len(segments) not in {10, 11}
        or segments[0].casefold() != "subscriptions"
        or segments[2].casefold() != "resourcegroups"
        or segments[4].casefold() != "providers"
        or segments[5].casefold() != "microsoft.keyvault"
        or segments[6].casefold() != "vaults"
        or segments[8].casefold() != "keys"
        or not all(segments[index] for index in (1, 3, 7, 9))
        or not _valid_path_segment(segments[9])
        or (len(segments) == 11 and not _valid_path_segment(segments[10]))
    ):
        return None
    return len(segments) == 11


def _is_key_vault_host(host: str) -> bool:
    normalized = host.casefold().rstrip(".")
    return any(
        normalized.endswith(suffix) and bool(normalized[: -len(suffix)]) and "." not in normalized[: -len(suffix)]
        for suffix in _KEY_VAULT_DNS_SUFFIXES
    )


def _valid_path_segment(value: str) -> bool:
    return bool(value) and all(character.isalnum() or character == "-" for character in value)


def _identity_for_target_kind(
    key: NormalizedResource,
    target_kind: AzureKeyVaultDependencyTargetKind | None,
) -> str | None:
    facts = azure_facts(key)
    if target_kind == "key_version":
        return facts.key_vault_key_uri
    if target_kind == "key":
        return facts.key_vault_key_versionless_uri
    return None


def _target_kind_for_reference_kind(
    reference_kind: AzureKeyVaultDependencyReferenceKind | None,
) -> AzureKeyVaultDependencyTargetKind | None:
    if reference_kind in {"versioned_uri", "versioned_resource_id"}:
        return "key_version"
    if reference_kind in {"versionless_uri", "versionless_resource_id"}:
        return "key"
    return None


def _target_kind_for_reference_suffix(
    reference: str,
) -> AzureKeyVaultDependencyTargetKind | None:
    if reference.endswith((".versionless_id", ".resource_versionless_id")):
        return "key"
    if reference.endswith((".id", ".resource_id")):
        return "key_version"
    return None


def _target_kind_label(
    target_kind: AzureKeyVaultDependencyTargetKind | None,
) -> str:
    if target_kind == "key_version":
        return "versioned Key Vault key"
    if target_kind == "key":
        return "versionless Key Vault key"
    return "Key Vault key"


def _vault_id_from_key_resource_id(reference: str | None) -> str | None:
    if reference is None:
        return None
    return reference.rsplit("/keys/", 1)[0]


def _vault_uri_from_key_uri(reference: str | None) -> str | None:
    if reference is None:
        return None
    return reference.rsplit("/keys/", 1)[0]


def _ownership_state(
    configured_reference: str | None,
    source: NormalizedResource,
    paths: Collection[TerraformExpressionPath],
    uncertainties: Sequence[str],
) -> str:
    if configured_reference is not None:
        return STATE_CONFIGURED
    if matching_configuration_resolutions(source, paths) or uncertainties:
        return STATE_UNKNOWN
    return STATE_NOT_CONFIGURED


def _applicability_uncertainties(
    dependency_input: _AzureDependencyInput,
) -> tuple[str, ...]:
    terminals = {
        path[-1].casefold() for path in dependency_input.resolution_paths if path and isinstance(path[-1], str)
    }
    return tuple(
        uncertainty
        for uncertainty in dependency_input.source_uncertainties
        if not (
            any(terminal in uncertainty.casefold() for terminal in terminals)
            and "unknown after planning" in uncertainty.casefold()
        )
    )


def _matching_path_uncertainties(
    uncertainties: Sequence[str],
    path: TerraformExpressionPath,
) -> list[str]:
    path_label = ".".join(segment for segment in path if isinstance(segment, str)).casefold()
    return [uncertainty for uncertainty in uncertainties if uncertainty.casefold().startswith(path_label)]


def _matching_uncertainties(
    uncertainties: Sequence[str],
    terms: Collection[str],
) -> list[str]:
    normalized_terms = tuple(term.casefold() for term in terms)
    return [
        uncertainty for uncertainty in uncertainties if any(term in uncertainty.casefold() for term in normalized_terms)
    ]


def _dependency_sort_key(
    dependency: AzureKeyVaultEncryptionDependency,
) -> tuple[str, str, str, str]:
    return (
        dependency["dependent_address"],
        dependency["dependency_source_address"],
        repr(dependency["configuration_path"]),
        dependency["configured_key_reference"] or "",
    )


def _dedupe(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))
