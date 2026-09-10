from __future__ import annotations

import re
from collections.abc import Collection, Mapping, Sequence

from tfstride.dependencies import (
    CandidateAssessment,
    CandidateSelection,
    DependencyCandidate,
    DependencyInput,
    DependencyReferenceProvenance,
    DependencyResolution,
    DependencyResolutionState,
    DependencyResolver,
    matching_configuration_resolutions,
)
from tfstride.models import (
    NormalizedResource,
    TerraformExpressionPath,
    TerraformReferenceTarget,
)
from tfstride.providers.coercion import (
    STATE_CONFIGURED,
    STATE_NOT_CONFIGURED,
    STATE_UNKNOWN,
)
from tfstride.providers.gcp.kms_dependency_evidence import (
    GcpKmsDependencyCandidate,
    GcpKmsDependencyReferenceKind,
    GcpKmsDependencyTargetKind,
    GcpKmsEncryptionDependency,
)
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext
from tfstride.providers.gcp.resource_types import GcpResourceType
from tfstride.providers.resource_reference_index import (
    ResourceReferenceIndex,
    build_resource_reference_index,
)

_KMS_KEY = GcpResourceType.KMS_CRYPTO_KEY
_KMS_KEY_VERSION = GcpResourceType.KMS_CRYPTO_KEY_VERSION
_SUPPORTED_DEPENDENT_TYPES = frozenset(
    {
        GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY,
        GcpResourceType.FIRESTORE_DATABASE,
        GcpResourceType.PUBSUB_TOPIC,
        GcpResourceType.SECRET_MANAGER_SECRET,
        GcpResourceType.STORAGE_BUCKET,
    }
)
_KEY_PATH_PATTERN = re.compile(
    r"^projects/(?P<project>[^/]+)/locations/(?P<location>[^/]+)/"
    r"keyRings/(?P<key_ring>[^/]+)/cryptoKeys/(?P<key>[^/]+)$"
)
_KEY_VERSION_PATH_PATTERN = re.compile(
    r"^(?P<key_path>projects/[^/]+/locations/[^/]+/keyRings/[^/]+/"
    r"cryptoKeys/[^/]+)/cryptoKeyVersions/(?P<version>[^/]+)$"
)
_KEY_RING_PATH_PATTERN = re.compile(r"^projects/[^/]+/locations/[^/]+/keyRings/[^/]+$")
_SECRET_AUTO_UNCERTAINTY_PATTERN = re.compile(
    r"^replication\.auto\.customer_managed_encryption\[(?P<key_index>\d+)\]"
    r"\.kms_key_name\b"
)
_SECRET_REPLICA_UNCERTAINTY_PATTERN = re.compile(
    r"^replication\.user_managed\.replicas\[(?P<replica_index>\d+)\]"
    r"\.customer_managed_encryption\[(?P<key_index>\d+)\]\.kms_key_name\b"
)


_GcpDependencyInput = DependencyInput[NormalizedResource, str | None]
_GcpDependencyCandidate = DependencyCandidate[
    NormalizedResource,
    GcpKmsDependencyTargetKind | None,
]
_GcpDependencyResolution = DependencyResolution[
    NormalizedResource,
    GcpKmsDependencyTargetKind | None,
    NormalizedResource,
]
_GcpDependencyResolver = DependencyResolver[
    NormalizedResource,
    str | None,
    NormalizedResource,
    GcpKmsDependencyTargetKind | None,
    NormalizedResource,
]


class ResolveGcpKmsEncryptionDependenciesStage:
    name = "resolve_gcp_kms_encryption_dependencies"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: GcpDecorationContext,
    ) -> None:
        _ = context
        targets = tuple(resource for resource in resources if resource.resource_type in {_KMS_KEY, _KMS_KEY_VERSION})
        native_index = build_resource_reference_index(
            targets,
            references_for_resource=_native_kms_references,
        )
        exact_resources_by_address = {resource.address: resource for resource in resources}
        resolver = _dependency_resolver(
            native_index=native_index,
            resources_by_address=exact_resources_by_address,
        )
        dependencies_by_address: dict[str, list[GcpKmsEncryptionDependency]] = {
            resource.address: []
            for resource in resources
            if resource.resource_type in _SUPPORTED_DEPENDENT_TYPES or resource.resource_type == _KMS_KEY
        }
        uncertainties_by_address: dict[str, list[str]] = {address: [] for address in dependencies_by_address}

        for dependent in resources:
            if dependent.resource_type not in _SUPPORTED_DEPENDENT_TYPES:
                continue
            inputs, uncovered_uncertainties = _dependency_inputs(dependent)
            uncertainties_by_address[dependent.address].extend(
                f"{dependent.address}: {uncertainty}" for uncertainty in uncovered_uncertainties
            )
            for dependency_input in inputs:
                record = resolver.resolve_record(
                    dependency_input,
                    render=_render_dependency_record,
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
            resource = exact_resources_by_address.get(address)
            if resource is None:
                continue
            gcp_facts(resource).set_kms_encryption_dependency_posture(
                dependencies=sorted(
                    dependencies,
                    key=_dependency_sort_key,
                ),
                uncertainties=_dedupe(uncertainties_by_address.get(address, [])),
            )


def _dependency_inputs(
    dependent: NormalizedResource,
) -> tuple[list[_GcpDependencyInput], list[str]]:
    facts = gcp_facts(dependent)
    if dependent.resource_type == GcpResourceType.STORAGE_BUCKET:
        paths = (("encryption", 0, "default_kms_key_name"),)
        encryption = dependent.get_metadata_field(GcpResourceMetadata.GCS_ENCRYPTION_CONFIGURATION)
        unresolved_key_field = facts.default_kms_key_name is None and "default_kms_key_name" in encryption
        state = (
            STATE_UNKNOWN
            if unresolved_key_field
            else _state_from_optional_bool(
                facts.customer_managed_encryption,
                has_symbolic_reference=bool(
                    matching_configuration_resolutions(
                        dependent,
                        paths,
                    )
                ),
            )
        )
        source_uncertainties = (
            ("encryption.default_kms_key_name is unknown after planning",) if unresolved_key_field else ()
        )
        dependency = _input_if_relevant(
            dependent=dependent,
            configuration_path=paths[0],
            resolution_paths=paths,
            configured_reference=facts.default_kms_key_name,
            ownership_state=state,
            source_uncertainties=source_uncertainties,
        )
        return ([dependency] if dependency is not None else []), []

    if dependent.resource_type == GcpResourceType.PUBSUB_TOPIC:
        uncertainties = _matching_uncertainties(
            facts.pubsub_posture_uncertainties,
            ("kms_key_name",),
        )
        return _single_dependency_inputs(
            dependent=dependent,
            configuration_path=("kms_key_name",),
            configured_reference=facts.pubsub_topic_kms_key_name,
            ownership_state=facts.pubsub_topic_cmek_state,
            uncertainties=uncertainties,
        )

    if dependent.resource_type == GcpResourceType.FIRESTORE_DATABASE:
        uncertainties = _matching_path_uncertainties(
            facts.firestore_posture_uncertainties,
            "cmek_config",
        )
        return _single_dependency_inputs(
            dependent=dependent,
            configuration_path=("cmek_config", 0, "kms_key_name"),
            configured_reference=facts.firestore_cmek_key_name,
            ownership_state=facts.firestore_cmek_state,
            uncertainties=uncertainties,
        )

    if dependent.resource_type == GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY:
        uncertainties = _matching_uncertainties(
            facts.artifact_registry_posture_uncertainties,
            ("kms_key_name",),
        )
        return _single_dependency_inputs(
            dependent=dependent,
            configuration_path=("kms_key_name",),
            configured_reference=facts.artifact_registry_kms_key_name,
            ownership_state=facts.artifact_registry_encryption_state,
            uncertainties=uncertainties,
        )

    if dependent.resource_type == GcpResourceType.SECRET_MANAGER_SECRET:
        return _secret_manager_dependency_inputs(dependent)

    return [], []


def _single_dependency_inputs(
    *,
    dependent: NormalizedResource,
    configuration_path: TerraformExpressionPath,
    configured_reference: str | None,
    ownership_state: str | None,
    uncertainties: Sequence[str],
) -> tuple[list[_GcpDependencyInput], list[str]]:
    dependency = _input_if_relevant(
        dependent=dependent,
        configuration_path=configuration_path,
        resolution_paths=(configuration_path,),
        configured_reference=configured_reference,
        ownership_state=ownership_state,
        source_uncertainties=uncertainties,
    )
    if dependency is None:
        return [], list(uncertainties)
    return [dependency], [
        uncertainty for uncertainty in uncertainties if uncertainty not in dependency.source_uncertainties
    ]


def _secret_manager_dependency_inputs(
    dependent: NormalizedResource,
) -> tuple[list[_GcpDependencyInput], list[str]]:
    facts = gcp_facts(dependent)
    replication = facts.secret_manager_replication
    uncertainties = facts.secret_manager_posture_uncertainties
    inputs: list[_GcpDependencyInput] = []

    if facts.secret_manager_replication_mode == "automatic":
        key_names = _record_string_list(replication, "kms_key_names")
        resolution_indexes = {
            resolution.path[5]
            for resolution in dependent.reference_resolutions
            if len(resolution.path) == 7
            and resolution.path[:5]
            == (
                "replication",
                0,
                "auto",
                0,
                "customer_managed_encryption",
            )
            and isinstance(resolution.path[5], int)
            and resolution.path[6] == "kms_key_name"
        }
        uncertainty_indexes = {
            int(match.group("key_index"))
            for uncertainty in uncertainties
            if (match := _SECRET_AUTO_UNCERTAINTY_PATTERN.match(uncertainty))
        }
        for index in sorted(set(range(len(key_names))) | resolution_indexes | uncertainty_indexes):
            path = (
                "replication",
                0,
                "auto",
                0,
                "customer_managed_encryption",
                index,
                "kms_key_name",
            )
            normalized_path = f"replication.auto.customer_managed_encryption[{index}].kms_key_name"
            source_uncertainties = _matching_path_uncertainties(
                uncertainties,
                normalized_path,
            )
            dependency = _input_if_relevant(
                dependent=dependent,
                configuration_path=path,
                resolution_paths=(path,),
                configured_reference=(key_names[index] if index < len(key_names) else None),
                ownership_state=(STATE_CONFIGURED if index < len(key_names) else STATE_UNKNOWN),
                source_uncertainties=source_uncertainties,
            )
            if dependency is not None:
                inputs.append(dependency)

    elif facts.secret_manager_replication_mode == "user_managed":
        replicas = _record_mapping_list(replication, "replicas")
        resolution_indexes = {
            (resolution.path[5], resolution.path[7])
            for resolution in dependent.reference_resolutions
            if len(resolution.path) == 9
            and resolution.path[:5]
            == (
                "replication",
                0,
                "user_managed",
                0,
                "replicas",
            )
            and isinstance(resolution.path[5], int)
            and resolution.path[6] == "customer_managed_encryption"
            and isinstance(resolution.path[7], int)
            and resolution.path[8] == "kms_key_name"
        }
        uncertainty_indexes = {
            (
                int(match.group("replica_index")),
                int(match.group("key_index")),
            )
            for uncertainty in uncertainties
            if (match := _SECRET_REPLICA_UNCERTAINTY_PATTERN.match(uncertainty))
        }
        configured_indexes = {
            (replica_index, key_index)
            for replica_index, replica in enumerate(replicas)
            for key_index, _ in enumerate(_record_string_list(replica, "kms_key_names"))
        }
        for replica_index, key_index in sorted(configured_indexes | resolution_indexes | uncertainty_indexes):
            replica = replicas[replica_index] if replica_index < len(replicas) else {}
            key_names = _record_string_list(replica, "kms_key_names")
            path = (
                "replication",
                0,
                "user_managed",
                0,
                "replicas",
                replica_index,
                "customer_managed_encryption",
                key_index,
                "kms_key_name",
            )
            normalized_path = (
                "replication.user_managed.replicas"
                f"[{replica_index}].customer_managed_encryption"
                f"[{key_index}].kms_key_name"
            )
            source_uncertainties = _matching_path_uncertainties(
                uncertainties,
                normalized_path,
            )
            dependency = _input_if_relevant(
                dependent=dependent,
                configuration_path=path,
                resolution_paths=(path,),
                configured_reference=(key_names[key_index] if key_index < len(key_names) else None),
                ownership_state=(STATE_CONFIGURED if key_index < len(key_names) else STATE_UNKNOWN),
                source_uncertainties=source_uncertainties,
            )
            if dependency is not None:
                inputs.append(dependency)

    covered = {uncertainty for dependency_input in inputs for uncertainty in dependency_input.source_uncertainties}
    uncovered = [
        uncertainty
        for uncertainty in uncertainties
        if "replication" in uncertainty.casefold() and uncertainty not in covered
    ]
    return inputs, uncovered


def _input_if_relevant(
    *,
    dependent: NormalizedResource,
    configuration_path: TerraformExpressionPath,
    resolution_paths: tuple[TerraformExpressionPath, ...],
    configured_reference: str | None,
    ownership_state: str | None,
    source_uncertainties: Sequence[str],
) -> _GcpDependencyInput | None:
    has_resolution = bool(
        matching_configuration_resolutions(
            dependent,
            resolution_paths,
        )
    )
    if (
        configured_reference is None
        and not has_resolution
        and not source_uncertainties
        and ownership_state != STATE_UNKNOWN
    ):
        return None
    return DependencyInput(
        dependent=dependent,
        source=dependent,
        configuration_path=configuration_path,
        resolution_paths=resolution_paths,
        configured_reference=configured_reference,
        source_uncertainties=tuple(source_uncertainties),
        adapter_data=ownership_state,
    )


def _dependency_resolver(
    *,
    native_index: ResourceReferenceIndex,
    resources_by_address: Mapping[str, NormalizedResource],
) -> _GcpDependencyResolver:
    def resolve_native(
        dependency_input: _GcpDependencyInput,
        reference: str,
    ) -> _GcpDependencyResolution:
        return _resolve_native_reference(
            reference,
            dependency_input,
            native_index=native_index,
        )

    def assess_target(
        dependency_input: _GcpDependencyInput,
        target: TerraformReferenceTarget,
    ) -> CandidateAssessment[NormalizedResource, GcpKmsDependencyTargetKind | None]:
        return _assess_configuration_target(
            target,
            dependency_input=dependency_input,
            resources_by_address=resources_by_address,
        )

    return DependencyResolver(
        resolve_native_reference=resolve_native,
        assess_configuration_target=assess_target,
        resolve_configuration_candidate=_resolve_configuration_candidate,
    )


def _render_dependency_record(
    dependency_input: _GcpDependencyInput,
    resolution: _GcpDependencyResolution,
    configuration_path: TerraformExpressionPath,
) -> GcpKmsEncryptionDependency:
    selected_key = resolution.selection
    key_resource_name = _key_resource_name(selected_key) if selected_key is not None else None
    key_match = _KEY_PATH_PATTERN.fullmatch(key_resource_name) if key_resource_name is not None else None
    key_facts = gcp_facts(selected_key) if selected_key is not None else None
    configured_reference = resolution.configured_reference
    if resolution.provenance == "configuration_reference" and not resolution.candidates:
        configured_reference = None
    reference_kind: GcpKmsDependencyReferenceKind | None = (
        "terraform_reference"
        if resolution.provenance == "configuration_reference"
        else _native_reference_kind(resolution.configured_reference)
        if resolution.configured_reference is not None
        else None
    )
    version_reference_is_explicit = reference_kind == "crypto_key_version_resource_name" or any(
        candidate.metadata == "crypto_key_version" for candidate in resolution.candidates
    )
    return {
        "dependent_address": dependency_input.dependent.address,
        "dependent_resource_type": dependency_input.dependent.resource_type,
        "dependency_source_address": dependency_input.source.address,
        "dependency_source_type": dependency_input.source.resource_type,
        "configuration_path": list(configuration_path),
        "configured_key_reference": configured_reference,
        "reference_provenance": resolution.provenance,
        "reference_kind": reference_kind,
        "resolution_state": resolution.state,
        "customer_managed_encryption_state": dependency_input.adapter_data,
        "candidate_targets": [_dependency_candidate(candidate) for candidate in resolution.candidates],
        "key_address": (selected_key.address if selected_key is not None else None),
        "key_resource_name": key_resource_name,
        "key_project": (key_match.group("project") if key_match is not None else None),
        "key_location": (key_match.group("location") if key_match is not None else None),
        "key_ring": (key_resource_name.rsplit("/cryptoKeys/", 1)[0] if key_resource_name is not None else None),
        "key_purpose": (key_facts.kms_purpose if key_facts is not None else None),
        "key_version_address": None,
        "key_version_resource_name": None,
        "version_reference_is_explicit": version_reference_is_explicit,
        "posture_uncertainties": list(_resolution_uncertainties(dependency_input, resolution)),
    }


def _resolve_native_reference(
    reference: str,
    dependency_input: _GcpDependencyInput,
    *,
    native_index: ResourceReferenceIndex,
) -> _GcpDependencyResolution:
    normalized = reference.strip()
    reference_kind = _native_reference_kind(normalized)
    candidates = tuple(
        _candidate(candidate, normalized)
        for candidate in native_index.candidates(normalized)
        if candidate.resource_type in {_KMS_KEY, _KMS_KEY_VERSION}
    )
    version_reference = reference_kind == "crypto_key_version_resource_name"
    if reference_kind != "crypto_key_resource_name":
        return _unselected_resolution(
            state="unsupported",
            provenance="planned_value",
            configured_reference=normalized,
            candidates=candidates,
            uncertainties=(
                f"Cloud KMS reference {normalized} is not an exact "
                "CryptoKey resource name supported by "
                f"{dependency_input.source.resource_type}",
                *dependency_input.source_uncertainties,
            ),
        )
    if len(candidates) > 1:
        return _unselected_resolution(
            state="ambiguous",
            provenance="planned_value",
            configured_reference=normalized,
            candidates=candidates,
            uncertainties=(
                f"Cloud KMS reference {normalized} matches multiple modeled CryptoKeys",
                *dependency_input.source_uncertainties,
            ),
        )
    if not candidates:
        return _unselected_resolution(
            state="unresolved",
            provenance="planned_value",
            configured_reference=normalized,
            candidates=(),
            uncertainties=(
                f"Cloud KMS reference {normalized} does not resolve to a modeled CryptoKey",
                *dependency_input.source_uncertainties,
            ),
        )
    candidate = candidates[0]
    if candidate.metadata == "crypto_key_version" or version_reference:
        return _unselected_resolution(
            state="unsupported",
            provenance="planned_value",
            configured_reference=normalized,
            candidates=candidates,
            uncertainties=(
                f"Cloud KMS reference {normalized} identifies a CryptoKeyVersion where a CryptoKey is required",
                *dependency_input.source_uncertainties,
            ),
        )
    return DependencyResolution(
        state="resolved",
        provenance="planned_value",
        configured_reference=normalized,
        candidates=candidates,
        selected_candidate=candidate,
        selection=candidate.value,
        details=_applicability_uncertainties(dependency_input),
    )


def _assess_configuration_target(
    target: TerraformReferenceTarget,
    *,
    dependency_input: _GcpDependencyInput,
    resources_by_address: Mapping[str, NormalizedResource],
) -> CandidateAssessment[NormalizedResource, GcpKmsDependencyTargetKind | None]:
    candidate = resources_by_address.get(target.address)
    if candidate is None or candidate.resource_type not in {_KMS_KEY, _KMS_KEY_VERSION}:
        return CandidateAssessment(
            candidate=None,
            metadata=None,
            supported=False,
            details=(f"Terraform target {target.address} is not a modeled Cloud KMS CryptoKey or CryptoKeyVersion",),
        )
    target_kind = _candidate_target_kind(candidate)
    if target_kind == "crypto_key_version":
        return CandidateAssessment(
            candidate=candidate,
            metadata=target_kind,
            supported=False,
            details=(
                f"Terraform target {target.reference} identifies a CryptoKeyVersion where a CryptoKey is required",
            ),
        )
    if not target.reference.endswith(".id"):
        return CandidateAssessment(
            candidate=candidate,
            metadata=target_kind,
            supported=False,
            details=(
                f"Terraform target reference {target.reference} "
                f"is unsupported for {dependency_input.source.resource_type}",
            ),
        )
    return CandidateAssessment(
        candidate=candidate,
        metadata=target_kind,
        supported=True,
    )


def _resolve_configuration_candidate(
    dependency_input: _GcpDependencyInput,
    candidate: _GcpDependencyCandidate,
    candidates: tuple[_GcpDependencyCandidate, ...],
) -> CandidateSelection[NormalizedResource]:
    _ = candidates
    key_resource_name = _key_resource_name(candidate.value)
    if key_resource_name is None:
        return CandidateSelection(
            state="unresolved",
            value=None,
            causes=("unresolved_reference",),
            details=tuple(
                _dedupe(
                    (
                        f"{candidate.address} does not retain an exact provider-native CryptoKey resource name",
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


def _unselected_resolution(
    *,
    state: DependencyResolutionState,
    provenance: DependencyReferenceProvenance | None,
    configured_reference: str | None,
    candidates: tuple[_GcpDependencyCandidate, ...],
    uncertainties: Sequence[str],
) -> _GcpDependencyResolution:
    return DependencyResolution(
        state=state,
        provenance=provenance,
        configured_reference=configured_reference,
        candidates=candidates,
        selected_candidate=None,
        selection=None,
        details=tuple(_dedupe(uncertainties)),
    )


def _candidate(
    resource: NormalizedResource,
    reference: str,
) -> _GcpDependencyCandidate:
    return DependencyCandidate(
        address=resource.address,
        value=resource,
        reference=reference,
        metadata=_candidate_target_kind(resource),
    )


def _candidate_target_kind(resource: NormalizedResource) -> GcpKmsDependencyTargetKind:
    return "crypto_key_version" if resource.resource_type == _KMS_KEY_VERSION else "crypto_key"


def _native_kms_references(
    resource: NormalizedResource,
) -> tuple[str | None, ...]:
    if resource.resource_type == _KMS_KEY:
        return (_key_resource_name(resource),)
    if resource.resource_type == _KMS_KEY_VERSION:
        return (_key_version_resource_name(resource),)
    return ()


def _key_resource_name(
    resource: NormalizedResource | None,
) -> str | None:
    if resource is None or resource.resource_type != _KMS_KEY:
        return None
    facts = gcp_facts(resource)
    for value in (
        facts.kms_crypto_key_reference,
        resource.identifier,
    ):
        if isinstance(value, str) and _KEY_PATH_PATTERN.fullmatch(value.strip()) is not None:
            return value.strip()

    key_ring = facts.kms_key_ring
    key_name = resource.get_metadata_field(GcpResourceMetadata.NAME)
    if (
        isinstance(key_ring, str)
        and _KEY_RING_PATH_PATTERN.fullmatch(key_ring.strip()) is not None
        and isinstance(key_name, str)
        and key_name
        and "/" not in key_name
    ):
        candidate = f"{key_ring.strip()}/cryptoKeys/{key_name}"
        if _KEY_PATH_PATTERN.fullmatch(candidate) is not None:
            return candidate
    return None


def _key_version_resource_name(
    resource: NormalizedResource | None,
) -> str | None:
    if resource is None or resource.resource_type != _KMS_KEY_VERSION:
        return None
    facts = gcp_facts(resource)
    for value in (
        facts.kms_crypto_key_version_reference,
        facts.kms_crypto_key_version_name,
        resource.identifier,
    ):
        if isinstance(value, str) and _KEY_VERSION_PATH_PATTERN.fullmatch(value.strip()) is not None:
            return value.strip()
    return None


def _native_reference_kind(
    reference: str,
) -> GcpKmsDependencyReferenceKind | None:
    if _KEY_PATH_PATTERN.fullmatch(reference) is not None:
        return "crypto_key_resource_name"
    if _KEY_VERSION_PATH_PATTERN.fullmatch(reference) is not None:
        return "crypto_key_version_resource_name"
    if reference.startswith("google_kms_") and "." in reference:
        return "terraform_reference"
    return None


def _dependency_candidate(
    candidate: _GcpDependencyCandidate,
) -> GcpKmsDependencyCandidate:
    target_kind = candidate.metadata
    assert target_kind is not None
    return {
        "address": candidate.address,
        "target_kind": target_kind,
    }


def _resolution_uncertainties(
    dependency_input: _GcpDependencyInput,
    resolution: _GcpDependencyResolution,
) -> tuple[str, ...]:
    if resolution.state == "resolved":
        return resolution.details
    if resolution.provenance is None:
        return resolution.details or ("Cloud KMS key reference is unresolved",)
    if resolution.provenance == "planned_value":
        return resolution.details

    source_uncertainties = frozenset(dependency_input.source_uncertainties)
    specific_details = tuple(detail for detail in resolution.details if detail not in source_uncertainties)
    if resolution.state == "ambiguous":
        return tuple(
            _dedupe(
                (
                    "Terraform configuration reference has multiple modeled Cloud KMS targets",
                    *resolution.details,
                )
            )
        )
    if specific_details:
        return resolution.details
    fallback = (
        "Terraform configuration reference uses unsupported Cloud KMS relationship evidence"
        if resolution.state == "unsupported"
        else "Terraform configuration reference does not resolve to a modeled Cloud KMS CryptoKey"
    )
    return tuple(_dedupe((fallback, *dependency_input.source_uncertainties)))


def _applicability_uncertainties(
    dependency_input: _GcpDependencyInput,
) -> tuple[str, ...]:
    terminal = dependency_input.configuration_path[-1]
    if not isinstance(terminal, str):
        return dependency_input.source_uncertainties
    return tuple(
        uncertainty
        for uncertainty in dependency_input.source_uncertainties
        if not (terminal.casefold() in uncertainty.casefold() and "unknown after planning" in uncertainty.casefold())
    )


def _state_from_optional_bool(
    value: bool | None,
    *,
    has_symbolic_reference: bool,
) -> str:
    if has_symbolic_reference:
        return STATE_UNKNOWN
    if value is True:
        return STATE_CONFIGURED
    if value is False:
        return STATE_NOT_CONFIGURED
    return STATE_UNKNOWN


def _matching_path_uncertainties(
    uncertainties: Sequence[str],
    path: str,
) -> list[str]:
    normalized_path = path.casefold()
    path_prefixes = (
        f"{normalized_path}.",
        f"{normalized_path}[",
        f"{normalized_path} ",
        f"{normalized_path}:",
    )
    return [
        uncertainty
        for uncertainty in uncertainties
        if (normalized := uncertainty.strip().casefold()) == normalized_path or normalized.startswith(path_prefixes)
    ]


def _matching_uncertainties(
    uncertainties: Sequence[str],
    terms: Collection[str],
) -> list[str]:
    normalized_terms = tuple(term.casefold() for term in terms)
    return [
        uncertainty for uncertainty in uncertainties if any(term in uncertainty.casefold() for term in normalized_terms)
    ]


def _record_string_list(
    record: Mapping[str, object],
    key: str,
) -> list[str]:
    value = record.get(key)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _record_mapping_list(
    record: Mapping[str, object],
    key: str,
) -> list[Mapping[str, object]]:
    value = record.get(key)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _dependency_sort_key(
    dependency: GcpKmsEncryptionDependency,
) -> tuple[str, str, str, str]:
    return (
        dependency["dependent_address"],
        dependency["dependency_source_address"],
        repr(dependency["configuration_path"]),
        dependency["configured_key_reference"] or "",
    )


def _dedupe(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))
