from __future__ import annotations

from collections.abc import Collection, Sequence
from dataclasses import dataclass
from functools import partial

from tfstride.dependencies import (
    CandidateAssessment,
    CandidateSelection,
    DependencyCandidate,
    DependencyInput,
    DependencyResolution,
    DependencyResolutionCause,
    DependencyResolutionState,
    DependencyResolver,
    dedupe_strings,
    dependency_record_sort_key,
    matching_configuration_resolutions,
)
from tfstride.models import (
    NormalizedResource,
    TerraformExpressionPath,
    TerraformReferenceResolutionState,
    TerraformReferenceTarget,
)
from tfstride.providers.aws.kms_dependency_evidence import (
    AwsKmsDependencyCandidate,
    AwsKmsDependencyReferenceKind,
    AwsKmsDependencyTargetKind,
    AwsKmsEncryptionDependency,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.coercion import STATE_DISABLED
from tfstride.providers.resource_reference_index import (
    ResourceReferenceIndex,
    build_resource_reference_index,
)

_KMS_KEY = "aws_kms_key"
_KMS_ALIAS = "aws_kms_alias"
_SUPPORTED_DEPENDENT_TYPES = frozenset(
    {
        "aws_cloudtrail",
        "aws_db_instance",
        "aws_dynamodb_table",
        "aws_ecr_repository",
        "aws_s3_bucket",
        "aws_secretsmanager_secret",
        "aws_sns_topic",
        "aws_sqs_queue",
    }
)
_KEY_ID_SUFFIXES = frozenset({".arn", ".id", ".key_id"})
_KEY_ARN_SUFFIXES = frozenset({".arn"})
_ALIAS_ID_SUFFIXES = frozenset({".arn", ".id", ".name"})
_ALIAS_ARN_SUFFIXES = frozenset({".arn"})
_KMS_S3_ALGORITHMS = frozenset({"aws:kms", "aws:kms:dsse"})
_PROVIDER_MANAGED_OWNERSHIP_STATES = frozenset(
    {
        "absent",
        "aws_managed_kms",
        "aws_owned",
        "not_configured",
        "service_managed",
    }
)


@dataclass(frozen=True, slots=True)
class _AwsDependencyInputData:
    ownership_state: str | None
    key_reference_suffixes: frozenset[str]
    alias_reference_suffixes: frozenset[str]


@dataclass(frozen=True, slots=True)
class _AwsDependencySelection:
    target: NormalizedResource
    key: NormalizedResource


_AwsCandidateMetadata = AwsKmsDependencyTargetKind | None
_AwsDependencyInput = DependencyInput[NormalizedResource, _AwsDependencyInputData]
_AwsDependencyCandidate = DependencyCandidate[NormalizedResource, _AwsCandidateMetadata]
_AwsDependencyResolution = DependencyResolution[
    NormalizedResource,
    _AwsCandidateMetadata,
    _AwsDependencySelection,
]
_AwsDependencyResolver = DependencyResolver[
    NormalizedResource,
    _AwsDependencyInputData,
    NormalizedResource,
    _AwsCandidateMetadata,
    _AwsDependencySelection,
]
_AwsCandidateAssessment = CandidateAssessment[
    NormalizedResource,
    _AwsCandidateMetadata,
]


class ResolveAwsKmsEncryptionDependenciesStage:
    name = "resolve_aws_kms_encryption_dependencies"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        targets = tuple(resource for resource in resources if resource.resource_type in {_KMS_KEY, _KMS_ALIAS})
        native_index = build_resource_reference_index(
            targets,
            references_for_resource=_native_kms_references,
        )
        resources_by_address = context.index.resources_by_address
        resolver = _dependency_resolver(
            native_index=native_index,
            resources_by_address=resources_by_address,
        )
        dependencies_by_address: dict[str, list[AwsKmsEncryptionDependency]] = {
            resource.address: []
            for resource in resources
            if resource.resource_type in _SUPPORTED_DEPENDENT_TYPES or resource.resource_type == _KMS_KEY
        }
        uncertainties_by_address: dict[str, list[str]] = {address: [] for address in dependencies_by_address}

        for dependent in resources:
            if dependent.resource_type not in _SUPPORTED_DEPENDENT_TYPES:
                continue
            inputs, uncovered_uncertainties = _dependency_inputs(
                dependent,
                resources_by_address,
            )
            uncertainties_by_address[dependent.address].extend(
                f"{dependent.address}: {uncertainty}" for uncertainty in uncovered_uncertainties
            )
            for dependency_input in inputs:
                configured_reference = dependency_input.configured_reference
                if configured_reference and _is_aws_managed_key_reference(configured_reference):
                    continue
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
            resource = resources_by_address.get(address)
            if resource is None:
                continue
            aws_facts(resource).set_kms_encryption_dependency_posture(
                dependencies=sorted(dependencies, key=dependency_record_sort_key),
                uncertainties=dedupe_strings(uncertainties_by_address.get(address, [])),
            )


def _dependency_inputs(
    dependent: NormalizedResource,
    resources_by_address: dict[str, NormalizedResource],
) -> tuple[list[_AwsDependencyInput], list[str]]:
    facts = aws_facts(dependent)
    inputs: list[_AwsDependencyInput] = []
    uncovered_uncertainties: list[str] = []

    if dependent.resource_type == "aws_cloudtrail":
        dependency = _input_if_relevant(
            dependent=dependent,
            source=dependent,
            configuration_path=("kms_key_id",),
            resolution_paths=(("kms_key_id",),),
            configured_reference=facts.cloudtrail_kms_key_id,
            ownership_state=(
                "customer_managed"
                if facts.cloudtrail_kms_key_id
                else _ownership_from_uncertainties(facts.audit_detection_posture_uncertainties)
            ),
            key_reference_suffixes=_KEY_ARN_SUFFIXES,
            alias_reference_suffixes=frozenset(),
            source_uncertainties=_matching_uncertainties(
                facts.audit_detection_posture_uncertainties,
                ("kms_key_id",),
            ),
        )
        if dependency is not None:
            inputs.append(dependency)

    elif dependent.resource_type == "aws_dynamodb_table":
        if facts.dynamodb_encryption_configuration_state != STATE_DISABLED:
            main_uncertainties = _matching_path_uncertainties(
                facts.dynamodb_posture_uncertainties,
                "server_side_encryption",
            )
            main = _input_if_relevant(
                dependent=dependent,
                source=dependent,
                configuration_path=("server_side_encryption", 0, "kms_key_arn"),
                resolution_paths=(
                    ("kms_key_arn",),
                    ("server_side_encryption", 0, "kms_key_arn"),
                ),
                configured_reference=facts.dynamodb_kms_key_arn,
                ownership_state=facts.dynamodb_encryption_ownership_state,
                key_reference_suffixes=_KEY_ARN_SUFFIXES,
                alias_reference_suffixes=_ALIAS_ARN_SUFFIXES,
                source_uncertainties=main_uncertainties,
            )
            if main is not None:
                inputs.append(main)
        inputs.extend(
            _record_dependencies(
                dependent=dependent,
                source=dependent,
                records=facts.dynamodb_replicas,
                block_name="replica",
                reference_field="kms_key_arn",
                key_reference_suffixes=_KEY_ARN_SUFFIXES,
                alias_reference_suffixes=_ALIAS_ARN_SUFFIXES,
                source_uncertainties=facts.dynamodb_posture_uncertainties,
            )
        )
        uncovered_uncertainties.extend(
            _uncovered_key_uncertainties(
                facts.dynamodb_posture_uncertainties,
                inputs,
                ("server_side_encryption", "kms_key_arn", "replica"),
            )
        )

    elif dependent.resource_type == "aws_db_instance":
        if dependent.storage_encrypted:
            dependency = _input_if_relevant(
                dependent=dependent,
                source=dependent,
                configuration_path=("kms_key_id",),
                resolution_paths=(("kms_key_id",),),
                configured_reference=facts.rds_kms_key_id,
                ownership_state=(
                    "customer_managed"
                    if facts.rds_kms_key_id
                    else _ownership_from_uncertainties(facts.rds_posture_uncertainties)
                ),
                key_reference_suffixes=_KEY_ARN_SUFFIXES,
                alias_reference_suffixes=_ALIAS_ARN_SUFFIXES,
                source_uncertainties=_matching_uncertainties(
                    facts.rds_posture_uncertainties,
                    ("kms_key_id",),
                ),
            )
            if dependency is not None:
                inputs.append(dependency)
        elif facts.rds_kms_key_id:
            uncovered_uncertainties.append("kms_key_id is configured while storage encryption is not enabled")

    elif dependent.resource_type == "aws_s3_bucket":
        source = (
            resources_by_address.get(facts.s3_encryption_source_address)
            if facts.s3_encryption_source_address
            else dependent
        ) or dependent
        algorithm = facts.s3_encryption_algorithm.strip().lower() if facts.s3_encryption_algorithm else None
        source_uncertainties = _matching_uncertainties(
            facts.s3_posture_uncertainties,
            ("encryption", "kms_master_key_id", "rule"),
        )
        has_key_resolution = bool(
            matching_configuration_resolutions(
                source,
                (("rule", 0, "apply_server_side_encryption_by_default", 0, "kms_master_key_id"),),
            )
        )
        if algorithm in _KMS_S3_ALGORITHMS or (
            algorithm is None and (facts.s3_kms_master_key_id or has_key_resolution)
        ):
            dependency = _input_if_relevant(
                dependent=dependent,
                source=source,
                configuration_path=(
                    "rule",
                    0,
                    "apply_server_side_encryption_by_default",
                    0,
                    "kms_master_key_id",
                ),
                resolution_paths=(
                    (
                        "rule",
                        0,
                        "apply_server_side_encryption_by_default",
                        0,
                        "kms_master_key_id",
                    ),
                ),
                configured_reference=facts.s3_kms_master_key_id,
                ownership_state=(
                    "customer_managed"
                    if facts.s3_kms_master_key_id or has_key_resolution
                    else ("unknown" if algorithm is None else "service_managed")
                ),
                key_reference_suffixes=_KEY_ID_SUFFIXES,
                alias_reference_suffixes=_ALIAS_ID_SUFFIXES,
                source_uncertainties=source_uncertainties,
            )
            if dependency is not None:
                inputs.append(dependency)
        uncovered_uncertainties.extend(
            _uncovered_key_uncertainties(
                source_uncertainties,
                inputs,
                ("kms_master_key_id",),
            )
        )

    elif dependent.resource_type == "aws_secretsmanager_secret":
        main_uncertainties = _matching_path_uncertainties(
            facts.secrets_manager_posture_uncertainties,
            "kms_key_id",
        )
        main = _input_if_relevant(
            dependent=dependent,
            source=dependent,
            configuration_path=("kms_key_id",),
            resolution_paths=(("kms_key_id",),),
            configured_reference=facts.secrets_manager_kms_key_id,
            ownership_state=(
                "customer_managed"
                if facts.secrets_manager_kms_key_id
                else _ownership_from_uncertainties(main_uncertainties)
            ),
            key_reference_suffixes=_KEY_ID_SUFFIXES,
            alias_reference_suffixes=_ALIAS_ID_SUFFIXES,
            source_uncertainties=main_uncertainties,
        )
        if main is not None:
            inputs.append(main)
        inputs.extend(
            _record_dependencies(
                dependent=dependent,
                source=dependent,
                records=facts.secrets_manager_replication,
                block_name="replica",
                reference_field="kms_key_id",
                key_reference_suffixes=_KEY_ID_SUFFIXES,
                alias_reference_suffixes=_ALIAS_ID_SUFFIXES,
                source_uncertainties=facts.secrets_manager_posture_uncertainties,
            )
        )
        uncovered_uncertainties.extend(
            _uncovered_key_uncertainties(
                facts.secrets_manager_posture_uncertainties,
                inputs,
                ("kms_key_id", "replica"),
            )
        )

    elif dependent.resource_type == "aws_sns_topic":
        dependency = _input_if_relevant(
            dependent=dependent,
            source=dependent,
            configuration_path=("kms_master_key_id",),
            resolution_paths=(("kms_master_key_id",),),
            configured_reference=facts.sns_kms_master_key_id,
            ownership_state=facts.sns_encryption_ownership_state,
            key_reference_suffixes=_KEY_ID_SUFFIXES,
            alias_reference_suffixes=_ALIAS_ID_SUFFIXES,
            source_uncertainties=_matching_uncertainties(
                facts.sns_posture_uncertainties,
                ("kms_master_key_id",),
            ),
        )
        if dependency is not None:
            inputs.append(dependency)

    elif dependent.resource_type == "aws_sqs_queue":
        dependency = _input_if_relevant(
            dependent=dependent,
            source=dependent,
            configuration_path=("kms_master_key_id",),
            resolution_paths=(("kms_master_key_id",),),
            configured_reference=facts.sqs_kms_master_key_id,
            ownership_state=facts.sqs_encryption_ownership_state,
            key_reference_suffixes=_KEY_ID_SUFFIXES,
            alias_reference_suffixes=_ALIAS_ID_SUFFIXES,
            source_uncertainties=_matching_uncertainties(
                facts.sqs_posture_uncertainties,
                ("kms_master_key_id",),
            ),
        )
        if dependency is not None:
            inputs.append(dependency)

    elif dependent.resource_type == "aws_ecr_repository":
        encryption_type = facts.ecr_encryption_type.strip().upper() if facts.ecr_encryption_type else None
        resolution_paths = (("encryption_configuration", 0, "kms_key"),)
        has_symbolic_reference = bool(
            matching_configuration_resolutions(
                dependent,
                resolution_paths,
            )
        )
        source_uncertainties = _matching_uncertainties(
            facts.ecr_posture_uncertainties,
            ("encryption_configuration", "kms_key"),
        )
        if encryption_type == "KMS" or (encryption_type is None and (facts.ecr_kms_key or has_symbolic_reference)):
            dependency = _input_if_relevant(
                dependent=dependent,
                source=dependent,
                configuration_path=("encryption_configuration", 0, "kms_key"),
                resolution_paths=resolution_paths,
                configured_reference=facts.ecr_kms_key,
                ownership_state=(
                    "customer_managed"
                    if facts.ecr_kms_key
                    else (
                        "unknown"
                        if has_symbolic_reference or source_uncertainties
                        else facts.ecr_encryption_ownership_state
                    )
                ),
                key_reference_suffixes=_KEY_ARN_SUFFIXES,
                alias_reference_suffixes=frozenset(),
                source_uncertainties=source_uncertainties,
            )
            if dependency is not None:
                inputs.append(dependency)

    return inputs, dedupe_strings(uncovered_uncertainties)


def _input_if_relevant(
    *,
    dependent: NormalizedResource,
    source: NormalizedResource,
    configuration_path: TerraformExpressionPath,
    resolution_paths: tuple[TerraformExpressionPath, ...],
    configured_reference: str | None,
    ownership_state: str | None,
    key_reference_suffixes: frozenset[str],
    alias_reference_suffixes: frozenset[str],
    source_uncertainties: Sequence[str],
) -> _AwsDependencyInput | None:
    if ownership_state in _PROVIDER_MANAGED_OWNERSHIP_STATES:
        return None
    if (
        configured_reference is None
        and not matching_configuration_resolutions(source, resolution_paths)
        and not source_uncertainties
    ):
        return None
    return DependencyInput(
        dependent=dependent,
        source=source,
        configuration_path=configuration_path,
        resolution_paths=resolution_paths,
        configured_reference=configured_reference,
        source_uncertainties=tuple(source_uncertainties),
        adapter_data=_AwsDependencyInputData(
            ownership_state=ownership_state,
            key_reference_suffixes=key_reference_suffixes,
            alias_reference_suffixes=alias_reference_suffixes,
        ),
    )


def _record_dependencies(
    *,
    dependent: NormalizedResource,
    source: NormalizedResource,
    records: Sequence[dict[str, object]],
    block_name: str,
    reference_field: str,
    key_reference_suffixes: frozenset[str],
    alias_reference_suffixes: frozenset[str],
    source_uncertainties: Sequence[str],
) -> list[_AwsDependencyInput]:
    dependencies: list[_AwsDependencyInput] = []
    resolution_indexes = {
        resolution.path[1]
        for resolution in source.reference_resolutions
        if len(resolution.path) == 3
        and resolution.path[0] == block_name
        and isinstance(resolution.path[1], int)
        and resolution.path[2] == reference_field
    }
    for index in sorted(set(range(len(records))) | resolution_indexes):
        record = records[index] if index < len(records) else {}
        configured_reference = _known_record_string(record, reference_field)
        unknown_fields = _record_string_list(record, "unknown_fields")
        relevant_uncertainties = _matching_uncertainties(
            source_uncertainties,
            (f"{block_name}[{index}].{reference_field}",),
        )
        if reference_field in unknown_fields and not relevant_uncertainties:
            relevant_uncertainties = [f"{block_name}[{index}].{reference_field} is unknown after planning"]
        ownership_state = (
            "customer_managed" if configured_reference else ("unknown" if relevant_uncertainties else "service_managed")
        )
        dependency = _input_if_relevant(
            dependent=dependent,
            source=source,
            configuration_path=(block_name, index, reference_field),
            resolution_paths=((block_name, index, reference_field),),
            configured_reference=configured_reference,
            ownership_state=ownership_state,
            key_reference_suffixes=key_reference_suffixes,
            alias_reference_suffixes=alias_reference_suffixes,
            source_uncertainties=relevant_uncertainties,
        )
        if dependency is not None:
            dependencies.append(dependency)
    return dependencies


def _dependency_resolver(
    *,
    native_index: ResourceReferenceIndex,
    resources_by_address: dict[str, NormalizedResource],
) -> _AwsDependencyResolver:
    return DependencyResolver(
        resolve_native_reference=partial(
            _resolve_native_reference,
            native_index=native_index,
            resources_by_address=resources_by_address,
        ),
        assess_configuration_target=partial(
            _assess_configuration_target,
            resources_by_address=resources_by_address,
        ),
        resolve_configuration_candidate=partial(
            _select_candidate,
            native_index=native_index,
            resources_by_address=resources_by_address,
        ),
    )


def _render_dependency_record(
    dependency_input: _AwsDependencyInput,
    resolution: _AwsDependencyResolution,
    configuration_path: TerraformExpressionPath,
) -> AwsKmsEncryptionDependency:
    selection = resolution.selection
    selected_target = selection.target if selection is not None else None
    selected_key = selection.key if selection is not None else None
    selected_alias = (
        selected_target if selected_target is not None and selected_target.resource_type == _KMS_ALIAS else None
    )
    key_facts = aws_facts(selected_key) if selected_key is not None else None
    alias_facts = aws_facts(selected_alias) if selected_alias is not None else None
    configured_reference = resolution.configured_reference
    if (
        resolution.provenance == "configuration_reference"
        and resolution.state != "unresolved"
        and not resolution.candidates
    ):
        configured_reference = None
    reference_kind: AwsKmsDependencyReferenceKind | None = (
        "terraform_reference"
        if resolution.provenance == "configuration_reference"
        else _native_reference_kind(resolution.configured_reference)
        if resolution.configured_reference is not None
        else None
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
        "encryption_ownership_state": dependency_input.adapter_data.ownership_state,
        "candidate_targets": [_dependency_candidate(candidate) for candidate in resolution.candidates],
        "key_address": selected_key.address if selected_key is not None else None,
        "key_arn": key_facts.kms_key_arn if key_facts is not None else None,
        "key_id": key_facts.kms_key_id if key_facts is not None else None,
        "alias_address": selected_alias.address if selected_alias is not None else None,
        "alias_name": alias_facts.kms_alias_name if alias_facts is not None else None,
        "alias_arn": alias_facts.kms_alias_arn if alias_facts is not None else None,
        "key_origin": key_facts.kms_key_origin if key_facts is not None else None,
        "multi_region_state": (key_facts.kms_multi_region_state if key_facts is not None else None),
        "posture_uncertainties": list(_resolution_uncertainties(dependency_input, resolution)),
    }


def _resolve_native_reference(
    dependency_input: _AwsDependencyInput,
    reference: str,
    *,
    native_index: ResourceReferenceIndex,
    resources_by_address: dict[str, NormalizedResource],
) -> _AwsDependencyResolution:
    candidates: tuple[_AwsDependencyCandidate, ...] = tuple(
        DependencyCandidate(
            address=candidate.address,
            value=candidate,
            reference=reference,
            metadata=_candidate_target_kind(candidate),
        )
        for candidate in native_index.candidates(reference)
        if candidate.resource_type in {_KMS_KEY, _KMS_ALIAS}
    )
    reference_kind = _native_reference_kind(reference)
    if not _native_reference_kind_is_supported(reference_kind, dependency_input):
        return _unselected_resolution(
            state="unsupported",
            configured_reference=reference,
            candidates=candidates,
            uncertainties=(
                f"KMS reference {reference} has an unsupported identity form for "
                f"{dependency_input.source.resource_type}",
            ),
        )
    if len(candidates) > 1:
        return _unselected_resolution(
            state="ambiguous",
            configured_reference=reference,
            candidates=candidates,
            uncertainties=(f"KMS reference {reference} matches multiple modeled keys or aliases",),
        )
    if not candidates:
        return _unselected_resolution(
            state="unresolved",
            configured_reference=reference,
            candidates=(),
            uncertainties=(f"KMS reference {reference} does not resolve to a modeled key or alias",),
        )

    candidate = candidates[0]
    selection = _select_candidate(
        dependency_input,
        candidate,
        candidates,
        native_index=native_index,
        resources_by_address=resources_by_address,
    )
    return DependencyResolution(
        state=selection.state,
        provenance="planned_value",
        configured_reference=reference,
        candidates=candidates,
        selected_candidate=(candidate if selection.state == "resolved" else None),
        selection=selection.value,
        causes=selection.causes,
        details=selection.details,
    )


def _assess_configuration_target(
    dependency_input: _AwsDependencyInput,
    target: TerraformReferenceTarget,
    *,
    resources_by_address: dict[str, NormalizedResource],
) -> _AwsCandidateAssessment:
    candidate = resources_by_address.get(target.address)
    if candidate is None or candidate.resource_type not in {_KMS_KEY, _KMS_ALIAS}:
        return CandidateAssessment(
            candidate=None,
            metadata=None,
            supported=False,
            details=(f"Terraform target {target.address} is not a modeled KMS key or alias",),
        )

    target_kind = _candidate_target_kind(candidate)
    expected_suffixes = (
        dependency_input.adapter_data.key_reference_suffixes
        if target_kind == "key"
        else dependency_input.adapter_data.alias_reference_suffixes
    )
    if not any(target.reference.endswith(suffix) for suffix in expected_suffixes):
        return CandidateAssessment(
            candidate=candidate,
            metadata=target_kind,
            supported=False,
            details=(
                f"Terraform target reference {target.reference} is unsupported for "
                f"{dependency_input.source.resource_type}",
            ),
        )
    return CandidateAssessment(
        candidate=candidate,
        metadata=target_kind,
        supported=True,
    )


def _select_candidate(
    dependency_input: _AwsDependencyInput,
    candidate: _AwsDependencyCandidate,
    candidates: tuple[_AwsDependencyCandidate, ...],
    *,
    native_index: ResourceReferenceIndex,
    resources_by_address: dict[str, NormalizedResource],
) -> CandidateSelection[_AwsDependencySelection]:
    _ = candidates
    target = candidate.value
    if not _target_identity_is_known(target, candidate.reference):
        return CandidateSelection(
            state="unresolved",
            value=None,
            causes=("unresolved_reference",),
            details=tuple(
                dedupe_strings(
                    (
                        f"{candidate.address} does not retain the provider-native "
                        f"identity required by {candidate.reference}",
                        *dependency_input.source_uncertainties,
                    )
                )
            ),
        )
    if target.resource_type == _KMS_KEY:
        return CandidateSelection(
            state="resolved",
            value=_AwsDependencySelection(target=target, key=target),
            details=_applicability_uncertainties(dependency_input),
        )

    key, alias_state, alias_uncertainties = _resolve_alias_key(
        target,
        native_index=native_index,
        resources_by_address=resources_by_address,
    )
    if key is None:
        return CandidateSelection(
            state=alias_state,
            value=None,
            causes=(_resolution_cause(alias_state),),
            details=tuple(
                dedupe_strings(
                    (
                        *alias_uncertainties,
                        *dependency_input.source_uncertainties,
                    )
                )
            ),
        )
    return CandidateSelection(
        state="resolved",
        value=_AwsDependencySelection(target=target, key=key),
        details=_applicability_uncertainties(dependency_input),
    )


def _unselected_resolution(
    *,
    state: DependencyResolutionState,
    configured_reference: str,
    candidates: tuple[_AwsDependencyCandidate, ...],
    uncertainties: Sequence[str],
) -> _AwsDependencyResolution:
    assert state != "resolved"
    return DependencyResolution(
        state=state,
        provenance="planned_value",
        configured_reference=configured_reference,
        candidates=candidates,
        selected_candidate=None,
        selection=None,
        causes=(_resolution_cause(state),),
        details=tuple(dedupe_strings(uncertainties)),
    )


def _resolution_cause(
    state: DependencyResolutionState,
) -> DependencyResolutionCause:
    assert state != "resolved"
    if state == "ambiguous":
        return "multiple_candidates"
    if state == "unsupported":
        return "unsupported_reference"
    return "unresolved_reference"


def _candidate_target_kind(
    candidate: NormalizedResource,
) -> AwsKmsDependencyTargetKind:
    return "alias" if candidate.resource_type == _KMS_ALIAS else "key"


def _dependency_candidate(
    candidate: _AwsDependencyCandidate,
) -> AwsKmsDependencyCandidate:
    target_kind = candidate.metadata
    assert target_kind is not None
    return {
        "address": candidate.address,
        "target_kind": target_kind,
    }


def _configuration_resolution_details(
    dependency_input: _AwsDependencyInput,
    resolution: _AwsDependencyResolution,
) -> tuple[str, ...]:
    details = list(resolution.details)
    inserted_details: list[str] = []
    for retained in matching_configuration_resolutions(
        dependency_input.source,
        dependency_input.resolution_paths,
    ):
        reason = retained.reason
        if retained.state == TerraformReferenceResolutionState.UNRESOLVED:
            if reason is None:
                inserted_details.append("Terraform configuration reference does not identify a modeled KMS target")
            continue
        if retained.state not in {
            TerraformReferenceResolutionState.AMBIGUOUS,
            TerraformReferenceResolutionState.UNSUPPORTED,
            TerraformReferenceResolutionState.SYMBOLIC,
        }:
            inserted_details.append(
                f"Terraform configuration reference state {retained.state.value} "
                "cannot establish a symbolic KMS dependency"
            )
        if reason is not None and reason in details:
            details.remove(reason)
    return tuple(dedupe_strings((*inserted_details, *details)))


def _resolution_uncertainties(
    dependency_input: _AwsDependencyInput,
    resolution: _AwsDependencyResolution,
) -> tuple[str, ...]:
    if resolution.state == "resolved":
        return resolution.details
    if resolution.provenance is None:
        return resolution.details or ("KMS key reference is unresolved",)
    if resolution.provenance == "planned_value":
        return resolution.details

    details = _configuration_resolution_details(
        dependency_input,
        resolution,
    )
    source_uncertainties = frozenset(dependency_input.source_uncertainties)
    specific_details = tuple(detail for detail in details if detail not in source_uncertainties)
    if resolution.state == "ambiguous":
        return tuple(
            dedupe_strings(
                (
                    "Terraform configuration reference has multiple modeled KMS targets",
                    *details,
                )
            )
        )
    if specific_details:
        return details
    fallback = (
        "Terraform configuration reference uses unsupported KMS relationship evidence"
        if resolution.state == "unsupported"
        else "Terraform configuration reference does not resolve to a modeled KMS target"
    )
    return tuple(
        dedupe_strings(
            (
                fallback,
                *dependency_input.source_uncertainties,
            )
        )
    )


def _resolve_alias_key(
    alias: NormalizedResource,
    *,
    native_index: ResourceReferenceIndex,
    resources_by_address: dict[str, NormalizedResource],
) -> tuple[
    NormalizedResource | None,
    DependencyResolutionState,
    tuple[str, ...],
]:
    facts = aws_facts(alias)
    candidates: dict[str, NormalizedResource] = {}
    unresolved_candidate_addresses: set[str] = set()
    has_unmatched_native_reference = False
    ambiguous = False
    unsupported = False
    unresolved = False
    uncertainties: list[str] = []

    for reference in (
        facts.kms_alias_target_key_arn,
        facts.kms_alias_target_key_id,
    ):
        if not reference or _looks_like_terraform_reference(reference):
            continue
        matches = tuple(
            candidate for candidate in native_index.candidates(reference) if candidate.resource_type == _KMS_KEY
        )
        if len(matches) > 1:
            ambiguous = True
        for candidate in matches:
            candidates.setdefault(candidate.address, candidate)
        if not matches:
            has_unmatched_native_reference = True
            uncertainties.append(f"{alias.address} target reference {reference} does not resolve to a modeled KMS key")

    for resolution in matching_configuration_resolutions(
        alias,
        (("target_key_id",), ("target_key_arn",)),
    ):
        if resolution.state == TerraformReferenceResolutionState.AMBIGUOUS:
            ambiguous = True
        elif resolution.state == TerraformReferenceResolutionState.UNSUPPORTED:
            unsupported = True
            uncertainties.append(resolution.reason or f"{alias.address} target key relationship is unsupported")
        elif resolution.state == TerraformReferenceResolutionState.UNRESOLVED:
            unresolved = True
            uncertainties.append(resolution.reason or f"{alias.address} target key relationship is unresolved")
        elif resolution.state != TerraformReferenceResolutionState.SYMBOLIC:
            unsupported = True
            uncertainties.append(
                f"{alias.address} target key relationship state {resolution.state.value} is unsupported"
            )
        for target in resolution.targets:
            candidate = resources_by_address.get(target.address)
            if candidate is None or candidate.resource_type != _KMS_KEY:
                unsupported = True
                continue
            expected_suffixes = _KEY_ARN_SUFFIXES if resolution.path == ("target_key_arn",) else _KEY_ID_SUFFIXES
            if not any(target.reference.endswith(suffix) for suffix in expected_suffixes):
                unsupported = True
                continue
            if not _target_identity_is_known(candidate, target.reference):
                unresolved_candidate_addresses.add(candidate.address)
                uncertainties.append(f"{candidate.address} target identity is unknown after planning")
                continue
            candidates.setdefault(candidate.address, candidate)

    ordered = tuple(sorted(candidates.values(), key=lambda candidate: candidate.address))
    if ambiguous or len(ordered) > 1:
        return (
            None,
            "ambiguous",
            (
                f"{alias.address} resolves to multiple modeled KMS keys",
                *uncertainties,
            ),
        )
    if unsupported:
        return (
            None,
            "unsupported",
            tuple(uncertainties or (f"{alias.address} uses unsupported target-key evidence",)),
        )
    if unresolved or has_unmatched_native_reference or unresolved_candidate_addresses:
        return (
            None,
            "unresolved",
            tuple(dedupe_strings(uncertainties or [f"{alias.address} target KMS key is unresolved"])),
        )
    if len(ordered) != 1:
        return (
            None,
            "unresolved",
            tuple(uncertainties or (f"{alias.address} target KMS key is unresolved",)),
        )
    key = ordered[0]
    key_facts = aws_facts(key)
    if key_facts.kms_key_arn is None and key_facts.kms_key_id is None:
        return (
            None,
            "unresolved",
            (f"{key.address} provider-native KMS key identity is unresolved",),
        )
    return key, "resolved", ()


def _native_kms_references(
    resource: NormalizedResource,
) -> tuple[str | None, ...]:
    facts = aws_facts(resource)
    if resource.resource_type == _KMS_KEY:
        return (
            resource.arn,
            facts.kms_key_arn,
            facts.kms_key_id,
            resource.identifier if resource.identifier != resource.address else None,
        )
    if resource.resource_type == _KMS_ALIAS:
        return (
            resource.arn,
            facts.kms_alias_arn,
            facts.kms_alias_name,
            resource.identifier if resource.identifier != resource.address else None,
        )
    return ()


def _target_identity_is_known(
    target: NormalizedResource,
    target_reference: str,
) -> bool:
    facts = aws_facts(target)
    if target.resource_type == _KMS_KEY:
        if target_reference.endswith(".arn"):
            return facts.kms_key_arn is not None
        if target_reference.endswith((".id", ".key_id")):
            return facts.kms_key_id is not None
        return facts.kms_key_arn is not None or facts.kms_key_id is not None
    if target.resource_type == _KMS_ALIAS:
        if target_reference.endswith(".arn"):
            return facts.kms_alias_arn is not None
        if target_reference.endswith((".id", ".name")):
            return facts.kms_alias_name is not None
        return facts.kms_alias_arn is not None or facts.kms_alias_name is not None
    return False


def _native_reference_kind(reference: str) -> AwsKmsDependencyReferenceKind:
    normalized = reference.strip()
    lowered = normalized.lower()
    if lowered.startswith("arn:") and ":alias/" in lowered:
        return "alias_arn"
    if lowered.startswith("alias/") or lowered.startswith("aws/"):
        return "alias_name"
    if lowered.startswith("arn:"):
        return "key_arn"
    if _looks_like_terraform_reference(normalized):
        return "terraform_reference"
    return "key_id"


def _native_reference_kind_is_supported(
    reference_kind: AwsKmsDependencyReferenceKind,
    dependency_input: _AwsDependencyInput,
) -> bool:
    adapter_data = dependency_input.adapter_data
    if reference_kind == "key_arn":
        return ".arn" in adapter_data.key_reference_suffixes
    if reference_kind == "key_id":
        return bool(adapter_data.key_reference_suffixes & {".id", ".key_id"})
    if reference_kind == "alias_arn":
        return ".arn" in adapter_data.alias_reference_suffixes
    if reference_kind == "alias_name":
        return bool(adapter_data.alias_reference_suffixes & {".id", ".name"})
    return False


def _is_aws_managed_key_reference(reference: str) -> bool:
    normalized = reference.strip().lower()
    return normalized.startswith("alias/aws/") or normalized.startswith("aws/") or ":alias/aws/" in normalized


def _looks_like_terraform_reference(value: str) -> bool:
    normalized = value.strip()
    return normalized.startswith("aws_kms_") and "." in normalized


def _applicability_uncertainties(
    dependency_input: _AwsDependencyInput,
) -> tuple[str, ...]:
    terminal = dependency_input.configuration_path[-1]
    if not isinstance(terminal, str):
        return dependency_input.source_uncertainties
    return tuple(
        uncertainty
        for uncertainty in dependency_input.source_uncertainties
        if not (terminal.casefold() in uncertainty.casefold() and "unknown after planning" in uncertainty.casefold())
    )


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


def _uncovered_key_uncertainties(
    uncertainties: Sequence[str],
    inputs: Sequence[_AwsDependencyInput],
    terms: Collection[str],
) -> list[str]:
    covered = {uncertainty for dependency_input in inputs for uncertainty in dependency_input.source_uncertainties}
    return [uncertainty for uncertainty in _matching_uncertainties(uncertainties, terms) if uncertainty not in covered]


def _ownership_from_uncertainties(
    uncertainties: Sequence[str],
) -> str:
    return "unknown" if uncertainties else "service_managed"


def _known_record_string(
    record: dict[str, object],
    key: str,
) -> str | None:
    value = record.get(key)
    return value if isinstance(value, str) and value else None


def _record_string_list(
    record: dict[str, object],
    key: str,
) -> list[str]:
    value = record.get(key)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]
