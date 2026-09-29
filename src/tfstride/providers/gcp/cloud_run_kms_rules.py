from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, TypedDict, cast

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, Finding, NormalizedResource
from tfstride.providers.gcp.constants import PUBLIC_GCP_IAM_MEMBERS
from tfstride.providers.gcp.custom_role_index import build_gcp_custom_role_index
from tfstride.providers.gcp.gcs_grant_evaluation import gcs_path_permissions
from tfstride.providers.gcp.kms_dependency_evidence import GcpKmsEncryptionDependency
from tfstride.providers.gcp.kms_evidence import (
    GcpCloudRunKmsManagementPath,
    GcpCloudRunKmsOperationPath,
    GcpKmsKeyVersionEvidence,
    GcpKmsManagementEffect,
    GcpKmsManagementOperationClass,
    GcpKmsManagementPermission,
    GcpKmsOperationClass,
    GcpKmsOperationPermission,
    GcpKmsScopeType,
)
from tfstride.providers.gcp.protected_data_evidence import (
    GcpCloudRunGcsAccessPath,
    GcpCloudRunGcsProtectedDataConvergence,
)
from tfstride.providers.gcp.resource_decoration.cloud_run_gcs_access_paths import current_cloud_run_gcs_access_paths
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import (
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    GCP_KMS_CRYPTO_KEY_IAM_RESOURCE_TYPES,
    GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.gcp.resource_utils import binding_members


class _PublicInvokerBinding(TypedDict):
    source: str
    role: str
    member: str


class _GcpDownstreamDependency(TypedDict):
    version_address: str
    version_resource_name: str
    key_address: str
    key_resource_name: str
    dependency: GcpKmsEncryptionDependency


@dataclass(frozen=True, slots=True)
class _GcpLogicalProtectedDataDependency:
    bucket_address: str
    bucket_name: str
    key_address: str
    key_resource_name: str
    dependency_source_address: str
    configuration_path: str
    proof_count: int
    authorization_scopes: tuple[str, ...]


_PathAddressKey = Literal["key_address", "iam_resource_address"]


_PUBLIC_INVOKER_ROLES = frozenset({"roles/run.invoker", "roles/run.servicesInvoker"})
_DECRYPT_OPERATION: GcpKmsOperationClass = "decrypt"
_SIGN_OPERATION: GcpKmsOperationClass = "sign"
_MAC_GENERATION_OPERATION: GcpKmsOperationClass = "mac_generation"
_SIGNING_OPERATIONS: frozenset[GcpKmsOperationClass] = frozenset({_SIGN_OPERATION, _MAC_GENERATION_OPERATION})
_OPERATION_PERMISSIONS: dict[GcpKmsOperationClass, GcpKmsOperationPermission] = {
    _DECRYPT_OPERATION: "cloudkms.cryptoKeyVersions.useToDecrypt",
    _SIGN_OPERATION: "cloudkms.cryptoKeyVersions.useToSign",
    _MAC_GENERATION_OPERATION: "cloudkms.cryptoKeyVersions.useToSign",
}
_OPERATION_PURPOSES: dict[GcpKmsOperationClass, str] = {
    _DECRYPT_OPERATION: "ENCRYPT_DECRYPT",
    _SIGN_OPERATION: "ASYMMETRIC_SIGN",
    _MAC_GENERATION_OPERATION: "MAC",
}
_KMS_KEY_PATH_PATTERN = re.compile(
    r"^projects/(?P<project>[^/]+)/locations/(?P<location>[^/]+)/"
    r"keyRings/(?P<key_ring>[^/]+)/cryptoKeys/(?P<key>[^/]+)$"
)
_PROJECT_IAM_TYPES = GCP_PROJECT_IAM_RESOURCE_TYPES
_KEY_RING_IAM_TYPES = GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES
_CRYPTO_KEY_IAM_TYPES = GCP_KMS_CRYPTO_KEY_IAM_RESOURCE_TYPES
_MANAGEMENT_OPERATION_DEFINITIONS: dict[
    GcpKmsManagementPermission,
    tuple[GcpKmsManagementOperationClass, GcpKmsManagementEffect],
] = {
    "cloudkms.cryptoKeyVersions.update": ("disruptive_administration", "disruption"),
    "cloudkms.cryptoKeyVersions.destroy": ("destructive_administration", "disruption"),
    "cloudkms.cryptoKeys.setIamPolicy": ("authorization_administration", "delegation"),
    "cloudkms.keyRings.setIamPolicy": ("authorization_administration", "delegation"),
}
_MANAGEMENT_OPERATION_ORDER = tuple(_MANAGEMENT_OPERATION_DEFINITIONS)
_VERSION_DESTROY_OPERATION: GcpKmsManagementPermission = "cloudkms.cryptoKeyVersions.destroy"
_KMS_KEY_RING_PATH_PATTERN = re.compile(
    r"^projects/(?P<project>[^/]+)/locations/(?P<location>[^/]+)/keyRings/(?P<key_ring>[^/]+)$"
)


class GcpCloudRunKmsOperationRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_cloud_run_kms_decrypt_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_public_operation_access(
            context,
            rule_id,
            frozenset({_DECRYPT_OPERATION}),
            disclosure=True,
        )

    def detect_public_cloud_run_kms_signing_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_public_operation_access(
            context,
            rule_id,
            _SIGNING_OPERATIONS,
            disclosure=False,
        )

    def detect_public_cloud_run_kms_key_disruption(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_public_management_access(context, rule_id, "disruption")

    def detect_public_cloud_run_kms_authorization_delegation(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_public_management_access(context, rule_id, "delegation")

    def _detect_public_management_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
        management_effect: GcpKmsManagementEffect,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for workload in context.inventory.by_type(*GCP_CLOUD_RUN_RESOURCE_TYPES):
            public_invokers = _unconditional_public_invokers(workload)
            invoker_iam_check_disabled = gcp_facts(workload).cloud_run_invoker_iam_disabled is True
            if not workload.public_exposure or (not public_invokers and not invoker_iam_check_disabled):
                continue

            paths: list[GcpCloudRunKmsManagementPath] = [
                path
                for path in gcp_facts(workload).cloud_run_kms_management_paths
                if path["management_effect"] == management_effect
                and _is_deterministic_management_path(path, workload, context, management_effect)
            ]
            if not paths:
                continue

            target_addresses = _management_target_addresses(paths)
            iam_resource_addresses = _management_iam_resource_addresses(paths)
            public_source_addresses = sorted({binding["source"] for binding in public_invokers})
            project_scope = any(path.get("scope_type") == "project" for path in paths)
            key_ring_scope = any(path.get("scope_type") == "key_ring" for path in paths)
            version_targets = (
                _deterministic_version_destruction_targets(paths, workload, context)
                if management_effect == "disruption"
                else set()
            )
            downstream_dependencies = (
                _resolved_downstream_dependencies(paths, workload, context) if management_effect == "disruption" else []
            )
            downstream_dependent_addresses = _downstream_dependent_addresses(downstream_dependencies)
            operations = _management_operations(paths)
            target_count = _management_target_count(paths)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2,
                data_sensitivity=1,
                lateral_movement=1,
                blast_radius=(2 if project_scope or key_ring_scope or len(downstream_dependent_addresses) > 1 else 1),
            )
            boundary = context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", workload.address))
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            workload.address,
                            *public_source_addresses,
                            *target_addresses,
                            *iam_resource_addresses,
                            *downstream_dependent_addresses,
                        ]
                    ),
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=_management_rationale(
                        workload,
                        operations,
                        target_count,
                        management_effect,
                        project_scope=project_scope,
                        key_ring_scope=key_ring_scope,
                        downstream_dependent_count=len(downstream_dependent_addresses),
                        downstream_dependency_count=len(downstream_dependencies),
                        version_destruction_target_count=len(version_targets),
                    ),
                    evidence=collect_evidence(
                        evidence_item("public_invoker_bindings", _public_invoker_evidence(public_invokers)),
                        evidence_item("public_exposure_reasons", workload.public_exposure_reasons),
                        evidence_item(
                            "public_exposure_configuration",
                            _public_exposure_configuration(workload),
                        ),
                        evidence_item("runtime_identity", _management_runtime_identity_evidence(paths)),
                        evidence_item("kms_management_paths", _management_path_evidence(paths)),
                        evidence_item(
                            "scope_breadth",
                            _management_scope_breadth_evidence(paths),
                        ),
                        evidence_item(
                            "authorization_scope",
                            _management_authorization_scope(
                                operations,
                                management_effect,
                                project_scope=project_scope,
                                key_ring_scope=key_ring_scope,
                            ),
                        ),
                        *(
                            [
                                evidence_item(
                                    "downstream_dependencies",
                                    _downstream_dependency_evidence(
                                        downstream_dependencies,
                                        version_target_count=len(version_targets),
                                    ),
                                )
                            ]
                            if management_effect == "disruption"
                            else []
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def _detect_public_operation_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
        operation_classes: frozenset[GcpKmsOperationClass],
        *,
        disclosure: bool,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for workload in context.inventory.by_type(*GCP_CLOUD_RUN_RESOURCE_TYPES):
            public_invokers = _unconditional_public_invokers(workload)
            invoker_iam_check_disabled = gcp_facts(workload).cloud_run_invoker_iam_disabled is True
            if not workload.public_exposure or (not public_invokers and not invoker_iam_check_disabled):
                continue

            paths: list[GcpCloudRunKmsOperationPath] = [
                path
                for path in gcp_facts(workload).cloud_run_kms_operation_paths
                if path["operation_class"] in operation_classes
                and _is_deterministic_operation_path(
                    path,
                    workload,
                    context,
                    path["operation_class"],
                )
            ]
            if not paths:
                continue

            key_addresses = _path_string_values(paths, "key_address")
            iam_resource_addresses = _path_string_values(paths, "iam_resource_address")
            public_source_addresses: list[str] = sorted({binding["source"] for binding in public_invokers})
            project_scope = any(path.get("scope_type") == "project" for path in paths)
            matched_operations = _path_operation_classes(paths)
            protected_data_convergences = (
                _resolved_protected_data_convergences(
                    paths,
                    workload,
                    context,
                )
                if disclosure
                else []
            )
            logical_protected_data_dependencies = (
                _logical_protected_data_dependencies(protected_data_convergences) if disclosure else []
            )
            protected_data_dependent_addresses = _protected_data_dependent_addresses(
                logical_protected_data_dependencies
            )
            protected_data_uncertainties = (
                gcp_facts(workload).cloud_run_gcs_protected_data_convergence_uncertainties if disclosure else []
            )
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=1,
                data_sensitivity=2 if disclosure else 1,
                lateral_movement=1,
                blast_radius=(2 if project_scope or len(protected_data_dependent_addresses) > 1 else 1),
            )
            boundary = context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", workload.address))
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            workload.address,
                            *public_source_addresses,
                            *key_addresses,
                            *iam_resource_addresses,
                            *protected_data_dependent_addresses,
                        ]
                    ),
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=_rationale(
                        workload,
                        matched_operations,
                        key_addresses,
                        project_scope=project_scope,
                        disclosure=disclosure,
                        downstream_dependent_count=len(protected_data_dependent_addresses),
                        downstream_dependency_count=len(logical_protected_data_dependencies),
                    ),
                    evidence=collect_evidence(
                        evidence_item("public_invoker_bindings", _public_invoker_evidence(public_invokers)),
                        evidence_item("public_exposure_reasons", workload.public_exposure_reasons),
                        evidence_item(
                            "public_exposure_configuration",
                            _public_exposure_configuration(workload),
                        ),
                        evidence_item("runtime_identity", _runtime_identity_evidence(paths)),
                        evidence_item("kms_operation_paths", _operation_path_evidence(paths)),
                        evidence_item("scope_breadth", _scope_breadth_evidence(paths)),
                        evidence_item(
                            "authorization_scope",
                            _authorization_scope(
                                matched_operations,
                                project_scope,
                            ),
                        ),
                        *(
                            [
                                evidence_item(
                                    "downstream_dependencies",
                                    _protected_data_dependency_evidence(
                                        logical_protected_data_dependencies,
                                    ),
                                ),
                                evidence_item(
                                    "downstream_dependency_uncertainties",
                                    protected_data_uncertainties,
                                ),
                            ]
                            if disclosure
                            else []
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _management_operations(
    paths: Sequence[GcpCloudRunKmsManagementPath],
) -> list[GcpKmsManagementPermission]:
    return [
        operation
        for operation in _MANAGEMENT_OPERATION_ORDER
        if any(path.get("operation") == operation for path in paths)
    ]


def _management_target_count(
    paths: Sequence[GcpCloudRunKmsManagementPath],
) -> int:
    return len(
        {
            (path.get("target_type"), path.get("target_resource_name"))
            for path in paths
            if _known_string(path.get("target_resource_name")) is not None
        }
    )


def _management_target_addresses(
    paths: Sequence[GcpCloudRunKmsManagementPath],
) -> list[str]:
    addresses: set[str] = set()
    for path in paths:
        addresses.update(_string_values(path.get("target_model_evidence_addresses")))
        for key in ("target_address", "crypto_key_address"):
            value = _known_string(path.get(key))
            if value is not None:
                addresses.add(value)
    return sorted(addresses)


def _management_iam_resource_addresses(
    paths: Sequence[GcpCloudRunKmsManagementPath],
) -> list[str]:
    return sorted({value for path in paths if (value := _known_string(path.get("iam_resource_address"))) is not None})


def _deterministic_version_destruction_targets(
    paths: Sequence[GcpCloudRunKmsManagementPath],
    workload: NormalizedResource,
    context: RuleEvaluationContext,
) -> set[tuple[str, str]]:
    return {
        (target_address, target_resource_name)
        for path in paths
        if _is_deterministic_version_destruction_path(path, workload, context)
        if (target_address := _known_string(path.get("target_address"))) is not None
        if (target_resource_name := _known_string(path.get("target_resource_name"))) is not None
    }


def _is_deterministic_version_destruction_path(
    path: GcpCloudRunKmsManagementPath,
    workload: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    if (
        path.get("operation") != _VERSION_DESTROY_OPERATION
        or path.get("target_type") != "crypto_key_version"
        or path.get("lifecycle_compatibility_state") != "compatible"
        or not _is_deterministic_management_path(path, workload, context, "disruption")
    ):
        return False

    version_address = _known_string(path.get("target_address"))
    version_resource_name = _known_string(path.get("target_resource_name"))
    key_address = _known_string(path.get("crypto_key_address"))
    key_resource_name = _known_string(path.get("crypto_key_resource_name"))
    if version_address is None or version_resource_name is None or key_address is None or key_resource_name is None:
        return False

    version = context.inventory.get_by_address(version_address)
    key = context.inventory.get_by_address(key_address)
    if (
        version is None
        or version.provider != "gcp"
        or version.resource_type != GcpResourceType.KMS_CRYPTO_KEY_VERSION
        or key is None
        or key.provider != "gcp"
        or key.resource_type != GcpResourceType.KMS_CRYPTO_KEY
        or _key_identity(key) != key_resource_name
    ):
        return False

    version_facts = gcp_facts(version)
    version_identity = _known_string(version_facts.kms_crypto_key_version_reference or version.identifier)
    version_evidence = path.get("key_version")
    return bool(
        version_identity == version_resource_name
        and version_facts.kms_crypto_key_version_resolved_key_address == key_address
        and isinstance(version_evidence, Mapping)
        and version_evidence.get("version_identity_state") == "resolved"
        and version_evidence.get("version_address") == version_address
        and version_evidence.get("version_resource_name") == version_resource_name
    )


def _resolved_downstream_dependencies(
    paths: Sequence[GcpCloudRunKmsManagementPath],
    workload: NormalizedResource,
    context: RuleEvaluationContext,
) -> list[_GcpDownstreamDependency]:
    dependencies: list[_GcpDownstreamDependency] = []
    seen: set[tuple[str, str, str, str]] = set()
    for path in paths:
        if not _is_deterministic_version_destruction_path(path, workload, context):
            continue

        version_address = _known_string(path.get("target_address"))
        version_resource_name = _known_string(path.get("target_resource_name"))
        key_address = _known_string(path.get("crypto_key_address"))
        key_resource_name = _known_string(path.get("crypto_key_resource_name"))
        if version_address is None or version_resource_name is None or key_address is None or key_resource_name is None:
            continue

        key = context.inventory.get_by_address(key_address)
        if key is None or key.provider != "gcp" or key.resource_type != GcpResourceType.KMS_CRYPTO_KEY:
            continue

        for dependency in gcp_facts(key).kms_encryption_dependencies:
            if (
                dependency.get("resolution_state") != "resolved"
                or dependency.get("key_address") != key_address
                or dependency.get("key_resource_name") != key_resource_name
                or dependency.get("version_reference_is_explicit") is not True
                or dependency.get("key_version_address") != version_address
                or dependency.get("key_version_resource_name") != version_resource_name
            ):
                continue

            if dependency.get("candidate_targets") != [
                {
                    "address": version_address,
                    "target_kind": "crypto_key_version",
                }
            ]:
                continue

            provenance = dependency.get("reference_provenance")
            reference_kind = dependency.get("reference_kind")
            configured_reference = dependency.get("configured_key_reference")
            if provenance == "planned_value":
                if (
                    reference_kind != "crypto_key_version_resource_name"
                    or configured_reference != version_resource_name
                ):
                    continue
            elif provenance == "configuration_reference":
                if reference_kind != "terraform_reference" or not isinstance(configured_reference, str):
                    continue
            else:
                continue

            dependent_address = dependency.get("dependent_address")
            source_address = dependency.get("dependency_source_address")
            configuration_path = repr(dependency.get("configuration_path"))
            if not isinstance(dependent_address, str) or not isinstance(source_address, str):
                continue
            dependent = context.inventory.get_by_address(dependent_address)
            source = context.inventory.get_by_address(source_address)
            if (
                dependent is None
                or source is None
                or dependent.provider != "gcp"
                or source.provider != "gcp"
                or dependency.get("dependent_resource_type") != dependent.resource_type
                or dependency.get("dependency_source_type") != source.resource_type
            ):
                continue

            fingerprint = (version_address, dependent_address, source_address, configuration_path)
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            dependencies.append(
                {
                    "version_address": version_address,
                    "version_resource_name": version_resource_name,
                    "key_address": key_address,
                    "key_resource_name": key_resource_name,
                    "dependency": dependency,
                }
            )

    return sorted(
        dependencies,
        key=lambda item: (
            str(item["dependency"].get("dependent_address")),
            str(item["dependency"].get("dependency_source_address")),
            item["version_address"],
            repr(item["dependency"].get("configuration_path")),
        ),
    )


def _downstream_dependent_addresses(
    dependencies: Sequence[_GcpDownstreamDependency],
) -> list[str]:
    return sorted(
        {
            value
            for item in dependencies
            if isinstance(value := item["dependency"].get("dependent_address"), str) and value
        }
    )


def _downstream_dependency_evidence(
    dependencies: Sequence[_GcpDownstreamDependency],
    *,
    version_target_count: int,
) -> list[str]:
    dependent_addresses = _downstream_dependent_addresses(dependencies)
    values = [
        (
            f"unique_dependency_count={len(dependencies)}; "
            f"unique_dependent_resource_count={len(dependent_addresses)}; "
            f"unique_version_target_count={version_target_count}; "
            "blast_radius_basis="
            f"{'downstream_encrypted_dependents' if dependent_addresses else 'no_resolved_downstream_dependents'}"
        )
    ]
    values.extend(
        "; ".join(
            (
                f"version_address={item['version_address']}",
                f"version_resource_name={item['version_resource_name']}",
                f"key_address={item['key_address']}",
                f"dependent_address={item['dependency'].get('dependent_address') or 'unknown'}",
                f"dependency_source={item['dependency'].get('dependency_source_address') or 'unknown'}",
                f"configuration_path={item['dependency'].get('configuration_path') or 'unknown'}",
                f"reference_kind={item['dependency'].get('reference_kind') or 'unknown'}",
            )
        )
        for item in dependencies
    )
    return values


def _management_scope_breadth_evidence(
    paths: Sequence[GcpCloudRunKmsManagementPath],
) -> list[str]:
    grants_by_scope: dict[GcpKmsScopeType, set[tuple[str, ...]]] = {
        scope_type: set() for scope_type in ("project", "key_ring", "crypto_key")
    }
    target_paths = len(paths)
    modeled_targets = {
        (path.get("target_type"), path.get("target_resource_name"))
        for path in paths
        if _known_string(path.get("target_resource_name")) is not None
    }
    modeled_keys = {value for path in paths if (value := _known_string(path.get("crypto_key_address"))) is not None}
    modeled_versions = {
        value
        for path in paths
        if path.get("target_type") == "crypto_key_version"
        and (value := _known_string(path.get("target_address"))) is not None
    }
    for path in paths:
        scope_type = path.get("scope_type")
        if scope_type not in grants_by_scope:
            continue
        grants_by_scope[scope_type].add(
            (
                path["iam_resource_address"],
                path["iam_resource_type"],
                path["role"],
                path["scope"],
                path["grant_basis"],
                path.get("role_definition_address") or "",
            )
        )
    blast_radius_basis = (
        "project_applicable_grant"
        if grants_by_scope["project"]
        else "key_ring_applicable_grant"
        if grants_by_scope["key_ring"]
        else "exact_key_grant"
    )
    return [
        (
            f"project_grants={len(grants_by_scope['project'])}; "
            f"key_ring_grants={len(grants_by_scope['key_ring'])}; "
            f"exact_key_grants={len(grants_by_scope['crypto_key'])}; "
            f"target_paths={target_paths}; "
            f"modeled_targets={len(modeled_targets)}; "
            f"modeled_keys={len(modeled_keys)}; "
            f"modeled_versions={len(modeled_versions)}; "
            f"blast_radius_basis={blast_radius_basis}"
        )
    ]


def _management_runtime_identity_evidence(
    paths: Sequence[GcpCloudRunKmsManagementPath],
) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"service_account={path['service_account_email']}",
                    f"member={path['service_account_member']}",
                    "identity_kind=cloud_run_service_account",
                    "credential_context=workload_runtime",
                )
            )
            for path in paths
        }
    )


def _management_path_evidence(
    paths: Sequence[GcpCloudRunKmsManagementPath],
) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"operation={path['operation']}",
                    f"operation_class={path['operation_class']}",
                    f"management_effect={path['management_effect']}",
                    f"target_type={path['target_type']}",
                    f"target_address={path.get('target_address') or 'implicit'}",
                    f"target_resource_name={path['target_resource_name']}",
                    f"target_model_evidence={','.join(path['target_model_evidence_addresses'])}",
                    f"crypto_key_address={path.get('crypto_key_address') or 'none'}",
                    f"iam_resource={path['iam_resource_address']}",
                    f"iam_resource_type={path['iam_resource_type']}",
                    f"role={path['role']}",
                    f"role_kind={path['role_kind']}",
                    f"role_resolution_state={path['role_resolution_state']}",
                    f"matched_permissions={','.join(path['matched_permissions'])}",
                    f"scope_effective_permissions={','.join(path['scope_effective_permissions'])}",
                    f"grant_members={','.join(path['grant_members'])}",
                    f"grant_basis={path['grant_basis']}",
                    f"scope_type={path['scope_type']}",
                    f"scope={path['scope']}",
                    f"management_mode={path['management_mode']}",
                    f"management_state={path['management_state']}",
                    f"condition_state={path['condition_state']}",
                    f"authorization_state={path['authorization_state']}",
                    f"lifecycle_compatibility={path['lifecycle_compatibility_state']}",
                    f"iam_scope_is_key_version={str(path['iam_scope_is_key_version']).lower()}",
                    f"key_version={_management_version_evidence(path.get('key_version')) or 'none'}",
                )
            )
            for path in paths
        }
    )


def _management_version_evidence(value: object) -> str:
    if not isinstance(value, Mapping):
        return ""
    version = cast(Mapping[str, object], value)
    return ";".join(
        (
            f"address={version.get('version_address') or 'unknown'}",
            f"name={version.get('version_resource_name') or 'unknown'}",
            f"state={version.get('state') or 'unknown'}",
            f"algorithm={version.get('algorithm') or 'unknown'}",
            f"protection_level={version.get('protection_level') or 'unknown'}",
            f"import_posture={version.get('import_posture') or 'unknown'}",
        )
    )


def _management_rationale(
    workload: NormalizedResource,
    operations: Sequence[GcpKmsManagementPermission],
    target_count: int,
    management_effect: GcpKmsManagementEffect,
    *,
    project_scope: bool,
    key_ring_scope: bool,
    downstream_dependent_count: int = 0,
    downstream_dependency_count: int = 0,
    version_destruction_target_count: int = 0,
) -> str:
    operation_text = _management_operation_text(operations)
    if management_effect == "disruption":
        capability = "deterministic Cloud KMS disruption authority"
        consequence = "could disrupt key or key-version management"
    else:
        capability = "deterministic Cloud KMS authorization-delegation authority"
        consequence = "could change Cloud KMS authorization or delegate further key authority"
    if project_scope:
        scope_text = "Project-applicable IAM grants have broader blast radius than key-ring or exact-key grants."
    elif key_ring_scope:
        scope_text = "Key-ring IAM grants have broader blast radius than exact-key grants."
    else:
        scope_text = "The modeled IAM grants are limited to exact CryptoKey scope."
    downstream_text = (
        f" {version_destruction_target_count} exact modeled CryptoKeyVersion destruction target(s) have "
        f"{downstream_dependent_count} "
        f"unique downstream encrypted dependent resource(s) across {downstream_dependency_count} unique "
        "dependency relationship(s) through their parent CryptoKey dependencies."
        if management_effect == "disruption" and version_destruction_target_count and downstream_dependent_count
        else (
            " No resolved downstream encrypted dependent resources are modeled for the exact version destruction "
            "targets in these paths."
            if management_effect == "disruption" and version_destruction_target_count
            else (
                " No deterministic CryptoKeyVersion destruction target is present in these management paths."
                if management_effect == "disruption"
                else ""
            )
        )
    )
    return (
        f"{workload.display_name} is publicly invokable and its Cloud Run runtime service account has "
        f"{capability} ({operation_text}) on {target_count} exact modeled Cloud KMS management target(s). "
        f"A compromise of the public workload {consequence}. {scope_text}{downstream_text} This establishes "
        "Cloud KMS management authority, not proof of successful operation completion, authority over out-of-plan "
        "keys or versions, or runtime impact beyond the modeled IAM, lifecycle, and scope evidence."
    )


def _management_authorization_scope(
    operations: Sequence[GcpKmsManagementPermission],
    management_effect: GcpKmsManagementEffect,
    *,
    project_scope: bool,
    key_ring_scope: bool,
) -> list[str]:
    effect_text = "key disruption" if management_effect == "disruption" else "authorization delegation"
    values = [
        (
            f"establishes=deterministic {_management_operation_text(operations)} authority with "
            f"{effect_text} effect for the Cloud Run runtime service account"
        ),
        "iam_scopes=project,key_ring,crypto_key; iam_scope_is_key_version=false",
        "target_granularity=crypto_key_version,crypto_key,key_ring",
        (
            "does_not_establish=successful operation completion, authority over keys or versions outside the "
            "modeled plan, or runtime impact beyond modeled IAM and lifecycle evidence"
        ),
    ]
    if project_scope:
        values.append("blast_radius=project-applicable grants are broader than key-ring or exact-key grants")
    elif key_ring_scope:
        values.append("blast_radius=key-ring grants are broader than exact-key grants")
    return values


def _management_operation_text(
    operations: Sequence[GcpKmsManagementPermission],
) -> str:
    labels = {
        "cloudkms.cryptoKeyVersions.update": "CryptoKeyVersion update",
        "cloudkms.cryptoKeyVersions.destroy": "CryptoKeyVersion destroy",
        "cloudkms.cryptoKeys.setIamPolicy": "CryptoKey IAM policy update",
        "cloudkms.keyRings.setIamPolicy": "key-ring IAM policy update",
    }
    values = [labels[operation] for operation in operations]
    if len(values) == 1:
        return values[0]
    if len(values) == 2:
        return f"{values[0]} and {values[1]}"
    return ", ".join(values[:-1]) + f", and {values[-1]}"


def _string_values(value: object) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _unconditional_public_invokers(
    resource: NormalizedResource,
) -> list[_PublicInvokerBinding]:
    invokers: list[_PublicInvokerBinding] = []
    for binding in gcp_facts(resource).bindings:
        role = _known_string(binding.get("role"))
        source = _known_string(binding.get("source"))
        if (
            role not in _PUBLIC_INVOKER_ROLES
            or source is None
            or binding.get("condition")
            or binding.get("condition_state") == "unknown"
        ):
            continue
        for member in binding_members(binding):
            if member in PUBLIC_GCP_IAM_MEMBERS:
                invokers.append({"source": source, "role": role, "member": member})
    return invokers


def _is_deterministic_management_path(
    path: GcpCloudRunKmsManagementPath,
    workload: NormalizedResource,
    context: RuleEvaluationContext,
    management_effect: GcpKmsManagementEffect,
) -> bool:
    operation = _known_string(path.get("operation"))
    if operation is None or operation not in _MANAGEMENT_OPERATION_DEFINITIONS:
        return False
    management_permission = cast(GcpKmsManagementPermission, operation)
    operation_definition = _MANAGEMENT_OPERATION_DEFINITIONS[management_permission]
    if (
        path.get("workload_address") != workload.address
        or path.get("workload_type") != workload.resource_type
        or path.get("identity_kind") != "cloud_run_service_account"
        or path.get("credential_context") != "workload_runtime"
        or path.get("authorization_model") != "cloud_kms_iam"
        or path.get("authorization_state") != "granted"
        or path.get("management_state") != "unambiguous"
        or path.get("condition_state") != "not_configured"
        or path.get("iam_scope_is_key_version") is not False
        or operation_definition is None
        or operation_definition != (path.get("operation_class"), path.get("management_effect"))
        or path.get("management_effect") != management_effect
        or path.get("lifecycle_compatibility_state") not in {"compatible", "not_applicable"}
    ):
        return False

    workload_member = gcp_facts(workload).service_account_member
    service_account_member = _known_string(path.get("service_account_member"))
    grant_members = _string_values(path.get("grant_members"))
    if (
        workload_member is None
        or service_account_member is None
        or service_account_member != workload_member
        or service_account_member not in grant_members
    ):
        return False

    iam_resource_address = _known_string(path.get("iam_resource_address"))
    iam_resource_type = _known_string(path.get("iam_resource_type"))
    if iam_resource_address is None or iam_resource_type is None:
        return False
    iam_resource = context.inventory.get_by_address(iam_resource_address)
    if iam_resource is None or iam_resource.resource_type != iam_resource_type:
        return False

    key_project = _known_string(path.get("key_project"))
    key_ring = _known_string(path.get("key_ring"))
    scope_type = _known_string(path.get("scope_type"))
    scope = _known_string(path.get("scope"))
    if key_project is None or key_ring is None or scope_type is None or scope is None:
        return False
    if scope_type == "project":
        if iam_resource_type not in _PROJECT_IAM_TYPES or scope != key_project:
            return False
    elif scope_type == "key_ring":
        if iam_resource_type not in _KEY_RING_IAM_TYPES or scope != key_ring:
            return False
    elif scope_type == "crypto_key":
        crypto_key_resource_name = _known_string(path.get("crypto_key_resource_name"))
        if (
            iam_resource_type not in _CRYPTO_KEY_IAM_TYPES
            or crypto_key_resource_name is None
            or scope != crypto_key_resource_name
        ):
            return False
    else:
        return False

    if path.get("grant_basis") not in {"project_iam", "key_ring_iam", "crypto_key_iam"}:
        return False
    if not _is_exact_management_target(path, context, key_project, key_ring):
        return False
    return True


def _is_exact_management_target(
    path: GcpCloudRunKmsManagementPath,
    context: RuleEvaluationContext,
    key_project: str,
    key_ring: str,
) -> bool:
    target_type = path.get("target_type")
    target_resource_name = _known_string(path.get("target_resource_name"))
    evidence_addresses = _string_values(path.get("target_model_evidence_addresses"))
    if target_resource_name is None or not evidence_addresses:
        return False

    evidence_resources = [context.inventory.get_by_address(address) for address in evidence_addresses]
    if any(resource is None for resource in evidence_resources):
        return False

    if target_type == "crypto_key":
        target_address = _known_string(path.get("target_address"))
        if target_address is None:
            return False
        target = context.inventory.get_by_address(target_address)
        target_identity = _key_identity(target) if target is not None else None
        return bool(
            target is not None
            and target.resource_type == GcpResourceType.KMS_CRYPTO_KEY
            and target_identity == target_resource_name
            and target_address in evidence_addresses
            and target_identity is not None
            and target_identity.startswith(f"projects/{key_project}/")
            and _key_ring(target_identity) == key_ring
        )

    if target_type == "crypto_key_version":
        target_address = _known_string(path.get("target_address"))
        if target_address is None:
            return False
        target = context.inventory.get_by_address(target_address)
        if target is None or target.resource_type != GcpResourceType.KMS_CRYPTO_KEY_VERSION:
            return False
        crypto_key_address = _known_string(path.get("crypto_key_address"))
        crypto_key_resource_name = _known_string(path.get("crypto_key_resource_name"))
        if crypto_key_address is None or crypto_key_resource_name is None:
            return False
        key = context.inventory.get_by_address(crypto_key_address)
        if key is None or key.resource_type != GcpResourceType.KMS_CRYPTO_KEY:
            return False
        key_version = path.get("key_version")
        version_facts = gcp_facts(target)
        version_identity = _known_string(version_facts.kms_crypto_key_version_reference or target.identifier)
        return bool(
            target_address in evidence_addresses
            and version_identity == target_resource_name
            and isinstance(key_version, Mapping)
            and key_version.get("version_identity_state") == "resolved"
            and key_version.get("version_address") == target_address
            and key_version.get("version_resource_name") == target_resource_name
            and _key_identity(key) == crypto_key_resource_name
            and crypto_key_resource_name.startswith(f"projects/{key_project}/")
            and _key_ring(crypto_key_resource_name) == key_ring
        )

    if target_type == "key_ring":
        if _KMS_KEY_RING_PATH_PATTERN.fullmatch(target_resource_name) is None:
            return False
        if not target_resource_name.startswith(f"projects/{key_project}/"):
            return False
        target_address = _known_string(path.get("target_address"))
        if target_address is not None:
            target = context.inventory.get_by_address(target_address)
            target_identity = _key_ring_identity(target) if target is not None else None
            return bool(
                target is not None
                and target.resource_type == GcpResourceType.KMS_KEY_RING
                and target_identity == target_resource_name
                and target_address in evidence_addresses
            )
        return any(
            resource is not None
            and resource.resource_type == GcpResourceType.KMS_CRYPTO_KEY
            and (identity := _key_identity(resource)) is not None
            and _key_ring(identity) == target_resource_name
            for resource in evidence_resources
        )

    return False


def _is_deterministic_operation_path(
    path: GcpCloudRunKmsOperationPath,
    workload: NormalizedResource,
    context: RuleEvaluationContext,
    operation_class: GcpKmsOperationClass,
) -> bool:
    if (
        path.get("workload_address") != workload.address
        or path.get("workload_type") != workload.resource_type
        or path.get("identity_kind") != "cloud_run_service_account"
        or path.get("credential_context") != "workload_runtime"
        or path.get("key_resource_type") != GcpResourceType.KMS_CRYPTO_KEY
        or path.get("authorization_model") != "cloud_kms_iam"
        or path.get("authorization_state") != "granted"
        or path.get("management_state") != "unambiguous"
        or path.get("condition_state") != "not_configured"
        or path.get("iam_scope_is_key_version") is not False
        or path.get("operation_class") != operation_class
    ):
        return False

    expected_permission = _OPERATION_PERMISSIONS[operation_class]
    expected_purpose = _OPERATION_PURPOSES[operation_class]
    if (
        path.get("operation") != expected_permission
        or path.get("matched_permissions") != [expected_permission]
        or path.get("key_purpose") != expected_purpose
    ):
        return False

    service_account_member = _known_string(path.get("service_account_member"))
    workload_member = gcp_facts(workload).service_account_member
    key_address = _known_string(path.get("key_address"))
    key_resource_name = _known_string(path.get("key_resource_name"))
    iam_resource_address = _known_string(path.get("iam_resource_address"))
    iam_resource_type = _known_string(path.get("iam_resource_type"))
    scope_type = _known_string(path.get("scope_type"))
    scope = _known_string(path.get("scope"))
    if (
        service_account_member is None
        or workload_member is None
        or key_address is None
        or key_resource_name is None
        or iam_resource_address is None
        or iam_resource_type is None
        or scope_type is None
        or scope is None
        or service_account_member != workload_member
    ):
        return False

    key = context.inventory.get_by_address(key_address)
    iam_resource = context.inventory.get_by_address(iam_resource_address)
    if (
        key is None
        or key.resource_type != GcpResourceType.KMS_CRYPTO_KEY
        or iam_resource is None
        or iam_resource.resource_type != iam_resource_type
    ):
        return False

    key_identity = _key_identity(key)
    if key_identity is None or key_identity != key_resource_name:
        return False

    key_match = _KMS_KEY_PATH_PATTERN.fullmatch(key_identity)
    if key_match is None:
        return False
    if path.get("key_project") != key_match.group("project") or path.get("key_ring") != _key_ring(key_identity):
        return False

    expected_scope_type, expected_scope = _expected_scope(
        iam_resource_type,
        key_identity,
        key_match.group("project"),
    )
    return (
        scope_type == expected_scope_type
        and scope == expected_scope
        and path.get("grant_basis") in {"project_iam", "key_ring_iam", "crypto_key_iam"}
    )


def _expected_scope(
    iam_resource_type: str,
    key_identity: str,
    project: str,
) -> tuple[GcpKmsScopeType | None, str | None]:
    if iam_resource_type in _PROJECT_IAM_TYPES:
        return "project", project
    if iam_resource_type in _KEY_RING_IAM_TYPES:
        return "key_ring", _key_ring(key_identity)
    if iam_resource_type in _CRYPTO_KEY_IAM_TYPES:
        return "crypto_key", key_identity
    return None, None


def _key_identity(resource: NormalizedResource) -> str | None:
    facts = gcp_facts(resource)
    for value in (facts.kms_crypto_key_reference, resource.identifier):
        text = _known_string(value)
        if text is not None and _KMS_KEY_PATH_PATTERN.fullmatch(text.rstrip("/")) is not None:
            return text.rstrip("/")
    return None


def _key_ring(key_identity: str) -> str:
    return key_identity.rsplit("/cryptoKeys/", 1)[0]


def _key_ring_identity(resource: NormalizedResource) -> str | None:
    facts = gcp_facts(resource)
    for value in (facts.kms_key_ring, resource.identifier):
        text = _known_string(value)
        if text is not None and _KMS_KEY_RING_PATH_PATTERN.fullmatch(text.rstrip("/")) is not None:
            return text.rstrip("/")
    return None


def _resolved_protected_data_convergences(
    paths: Sequence[GcpCloudRunKmsOperationPath],
    workload: NormalizedResource,
    context: RuleEvaluationContext,
) -> list[GcpCloudRunGcsProtectedDataConvergence]:
    valid_paths = tuple(
        path
        for path in paths
        if path["operation_class"] == _DECRYPT_OPERATION
        and _is_deterministic_operation_path(
            path,
            workload,
            context,
            _DECRYPT_OPERATION,
        )
    )
    convergences: list[GcpCloudRunGcsProtectedDataConvergence] = []
    current_gcs_paths = current_cloud_run_gcs_access_paths(
        workload, context.inventory.resources, build_gcp_custom_role_index(context.inventory.resources)
    )
    for convergence in gcp_facts(workload).cloud_run_gcs_protected_data_convergences:
        if _is_valid_protected_data_convergence(
            convergence,
            workload,
            context,
            valid_paths,
            current_gcs_paths,
        ):
            convergences.append(convergence)
    return sorted(
        convergences,
        key=lambda convergence: (
            convergence["bucket_address"],
            convergence["key_address"],
            convergence["key_operation_path"]["scope_type"],
            convergence["key_operation_path"]["scope"],
            convergence["key_operation_path"]["iam_resource_address"],
        ),
    )


def _is_valid_protected_data_convergence(
    convergence: GcpCloudRunGcsProtectedDataConvergence,
    workload: NormalizedResource,
    context: RuleEvaluationContext,
    valid_paths: Sequence[GcpCloudRunKmsOperationPath],
    current_gcs_paths: Sequence[GcpCloudRunGcsAccessPath],
) -> bool:
    if (
        convergence["convergence_state"] != "resolved"
        or convergence["workload_address"] != workload.address
        or convergence["workload_type"] != workload.resource_type
        or convergence["operation"] != "cloudkms.cryptoKeyVersions.useToDecrypt"
        or convergence["access_class"] != "read"
        or convergence["runtime_identity_match"] is not True
        or convergence["protected_resource_match"] is not True
        or convergence["key_identity_match"] is not True
    ):
        return False

    workload_facts = gcp_facts(workload)
    if (
        convergence["service_account_email"] != workload_facts.service_account_email
        or convergence["service_account_member"] != workload_facts.service_account_member
    ):
        return False

    access_path = convergence["access_path"]
    operation_path = convergence["key_operation_path"]
    if (
        access_path not in workload_facts.cloud_run_gcs_access_paths
        or operation_path not in valid_paths
        or access_path["bucket_address"] != convergence["bucket_address"]
        or operation_path["key_address"] != convergence["key_address"]
        or operation_path["key_resource_name"] != convergence["key_resource_name"]
        or operation_path["service_account_member"] != convergence["service_account_member"]
    ):
        return False

    bucket = context.inventory.get_by_address(convergence["bucket_address"])
    key = context.inventory.get_by_address(convergence["key_address"])
    if (
        bucket is None
        or bucket.provider != "gcp"
        or bucket.resource_type != GcpResourceType.STORAGE_BUCKET
        or convergence["bucket_name"] != (gcp_facts(bucket).bucket_name or bucket.name)
        or not _is_deterministic_gcs_access_path(
            access_path,
            workload,
            bucket,
            context,
            current_gcs_paths,
        )
        or key is None
        or key.provider != "gcp"
        or key.resource_type != GcpResourceType.KMS_CRYPTO_KEY
        or _key_identity(key) != convergence["key_resource_name"]
    ):
        return False

    dependency = convergence["encryption_dependency"]
    if dependency not in gcp_facts(bucket).kms_encryption_dependencies:
        return False
    source = context.inventory.get_by_address(dependency["dependency_source_address"])
    key_identity = _key_identity(key)
    return bool(
        dependency["resolution_state"] == "resolved"
        and dependency["customer_managed_encryption_state"] == "configured"
        and dependency["dependent_address"] == bucket.address
        and dependency["dependent_resource_type"] == bucket.resource_type
        and dependency["dependency_source_address"] == bucket.address
        and dependency["dependency_source_type"] == bucket.resource_type
        and dependency["configuration_path"]
        == [
            "encryption",
            0,
            "default_kms_key_name",
        ]
        and dependency["key_address"] == key.address
        and dependency["key_resource_name"] == key_identity
        and dependency["candidate_targets"]
        == [
            {
                "address": key.address,
                "target_kind": "crypto_key",
            }
        ]
        and dependency["version_reference_is_explicit"] is False
        and dependency["key_version_address"] is None
        and dependency["key_version_resource_name"] is None
        and source is bucket
        and _dependency_reference_is_coherent(dependency, key_identity)
    )


def _is_deterministic_gcs_access_path(
    path: GcpCloudRunGcsAccessPath,
    workload: NormalizedResource,
    bucket: NormalizedResource,
    context: RuleEvaluationContext,
    current_gcs_paths: Sequence[GcpCloudRunGcsAccessPath],
) -> bool:
    workload_facts = gcp_facts(workload)
    service_account_email = workload_facts.service_account_email
    service_account_member = workload_facts.service_account_member
    iam_resource_address = path["iam_resource_address"]
    iam_resource = (
        context.inventory.get_by_address(iam_resource_address) if isinstance(iam_resource_address, str) else None
    )
    if (
        not isinstance(service_account_email, str)
        or not service_account_email
        or service_account_member != f"serviceAccount:{service_account_email}"
        or path["workload_address"] != workload.address
        or path["workload_type"] != workload.resource_type
        or path["service_account_email"] != service_account_email
        or path["service_account_member"] != service_account_member
        or path["identity_kind"] != "cloud_run_service_account"
        or path["credential_context"] != "workload_runtime"
        or path["bucket_address"] != bucket.address
        or path["bucket_name"] != (gcp_facts(bucket).bucket_name or bucket.name)
        or path["grant_basis"] not in {"storage_bucket_iam", "storage_project_iam"}
        or path["resource_scope"] != "exact_bucket"
        or path["condition"] is not None
        or path["condition_state"] != "not_configured"
        or path["access_state"] != "granted"
        or "read" not in path["access_classes"]
        or not _gcs_path_has_payload_read(path)
        or iam_resource is None
        or iam_resource.provider != "gcp"
        or iam_resource.resource_type not in (GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES | GCP_PROJECT_IAM_RESOURCE_TYPES)
    ):
        return False
    return path in current_gcs_paths


def _gcs_path_has_payload_read(path: GcpCloudRunGcsAccessPath) -> bool:
    return "storage.objects.get" in gcs_path_permissions(path)


def _dependency_reference_is_coherent(
    dependency: GcpKmsEncryptionDependency,
    key_identity: str | None,
) -> bool:
    configured = dependency["configured_key_reference"]
    if key_identity is None or not isinstance(configured, str):
        return False
    if dependency["reference_provenance"] == "planned_value":
        return dependency["reference_kind"] == "crypto_key_resource_name" and configured == key_identity
    return (
        dependency["reference_provenance"] == "configuration_reference"
        and dependency["reference_kind"] == "terraform_reference"
        and configured == f"{dependency['key_address']}.id"
    )


def _logical_protected_data_dependencies(
    convergences: Sequence[GcpCloudRunGcsProtectedDataConvergence],
) -> list[_GcpLogicalProtectedDataDependency]:
    grouped: dict[
        tuple[str, str, str, str],
        list[GcpCloudRunGcsProtectedDataConvergence],
    ] = {}
    for convergence in convergences:
        dependency = convergence["encryption_dependency"]
        fingerprint = (
            convergence["bucket_address"],
            convergence["key_address"],
            dependency["dependency_source_address"],
            repr(dependency["configuration_path"]),
        )
        grouped.setdefault(fingerprint, []).append(convergence)

    logical: list[_GcpLogicalProtectedDataDependency] = []
    for (bucket_address, key_address, source_address, configuration_path), proofs in grouped.items():
        representative = proofs[0]
        scopes = tuple(
            sorted(
                {
                    f"{proof['key_operation_path']['scope_type']}:{proof['key_operation_path']['scope']}"
                    for proof in proofs
                }
            )
        )
        logical.append(
            _GcpLogicalProtectedDataDependency(
                bucket_address=bucket_address,
                bucket_name=representative["bucket_name"],
                key_address=key_address,
                key_resource_name=representative["key_resource_name"],
                dependency_source_address=source_address,
                configuration_path=configuration_path,
                proof_count=len(proofs),
                authorization_scopes=scopes,
            )
        )
    return sorted(
        logical,
        key=lambda item: (
            item.bucket_address,
            item.key_address,
            item.dependency_source_address,
            item.configuration_path,
        ),
    )


def _protected_data_dependent_addresses(
    dependencies: Sequence[_GcpLogicalProtectedDataDependency],
) -> list[str]:
    return sorted({dependency.bucket_address for dependency in dependencies})


def _protected_data_dependency_evidence(
    dependencies: Sequence[_GcpLogicalProtectedDataDependency],
) -> list[str]:
    dependent_addresses = _protected_data_dependent_addresses(dependencies)
    values = [
        (
            f"unique_dependency_count={len(dependencies)}; "
            f"unique_dependent_resource_count={len(dependent_addresses)}; "
            "downstream_dependency_state="
            f"{'resolved_dependents' if dependent_addresses else 'no_resolved_dependents'}"
        )
    ]
    values.extend(
        "; ".join(
            (
                f"bucket_address={dependency.bucket_address}",
                f"bucket_name={dependency.bucket_name}",
                f"key_address={dependency.key_address}",
                f"key_resource_name={dependency.key_resource_name}",
                f"dependency_source={dependency.dependency_source_address}",
                f"configuration_path={dependency.configuration_path}",
                f"authorization_proof_count={dependency.proof_count}",
                f"authorization_scopes={','.join(dependency.authorization_scopes)}",
            )
        )
        for dependency in dependencies
    )
    return values


def _rationale(
    workload: NormalizedResource,
    operation_classes: list[GcpKmsOperationClass],
    key_addresses: list[str],
    *,
    project_scope: bool,
    disclosure: bool,
    downstream_dependent_count: int = 0,
    downstream_dependency_count: int = 0,
) -> str:
    operation_text = _operation_text(operation_classes)
    if disclosure:
        capability = "could attempt Cloud KMS decrypt operations, creating information-disclosure potential"
    elif operation_classes == [_SIGN_OPERATION]:
        capability = "could generate Cloud KMS signatures, creating spoofing potential"
    elif operation_classes == [_MAC_GENERATION_OPERATION]:
        capability = "could generate Cloud KMS message authentication codes, creating spoofing potential"
    else:
        capability = "could generate Cloud KMS signatures or message authentication codes, creating spoofing potential"
    scope_text = (
        "At least one grant is project-applicable and can reach modeled CryptoKeys across the project, "
        "so its blast radius is broader than a key-ring- or exact-key-scoped grant."
        if project_scope
        else "The modeled grants are limited to key-ring or exact CryptoKey scopes."
    )
    downstream_text = (
        f" The exact decrypt evidence converges with {downstream_dependent_count} unique KMS-protected "
        f"GCS bucket(s) across {downstream_dependency_count} unique encryption dependency relationship(s)."
        if disclosure and downstream_dependent_count
        else (" No resolved KMS-protected GCS access convergence is modeled for these keys." if disclosure else "")
    )
    return (
        f"{workload.display_name} is publicly invokable and its Cloud Run runtime service account has "
        f"deterministic Cloud KMS {operation_text} authority on {len(key_addresses)} exact modeled CryptoKey(s). "
        f"A compromise of the public workload {capability}. {scope_text}{downstream_text} This establishes cryptographic-operation "
        "authority, not proof that the workload possesses useful ciphertext, can disclose plaintext, or can produce "
        "a signature or message authentication code accepted by a relying application. Cloud KMS IAM is modeled at "
        "project, key-ring, and CryptoKey scope; it is not treated as CryptoKeyVersion-scoped authority."
    )


def _authorization_scope(
    operation_classes: list[GcpKmsOperationClass],
    project_scope: bool,
) -> list[str]:
    permissions = sorted({_OPERATION_PERMISSIONS[operation] for operation in operation_classes})
    values = [
        (
            f"establishes=deterministic {','.join(permissions)} IAM authority for "
            f"Cloud KMS {_operation_text(operation_classes)} operations by the Cloud Run runtime service account"
        ),
        "iam_scopes=project,key_ring,crypto_key; iam_scope_is_key_version=false",
        "excludes=cloudkms.cryptoKeyVersions.useToDecryptViaDelegation for direct Cloud Run API use",
        (
            "does_not_establish=useful ciphertext, plaintext disclosure, accepted application signatures or MACs, "
            "or runtime success outside modeled IAM evidence"
        ),
    ]
    if project_scope:
        values.append("blast_radius=project-applicable grant is broader than key-ring or exact-key grants")
    return values


def _path_operation_classes(
    paths: Sequence[GcpCloudRunKmsOperationPath],
) -> list[GcpKmsOperationClass]:
    return [
        operation
        for operation in (
            _DECRYPT_OPERATION,
            _SIGN_OPERATION,
            _MAC_GENERATION_OPERATION,
        )
        if any(path.get("operation_class") == operation for path in paths)
    ]


def _operation_text(operation_classes: Sequence[GcpKmsOperationClass]) -> str:
    labels = {
        _DECRYPT_OPERATION: "decrypt",
        _SIGN_OPERATION: "sign",
        _MAC_GENERATION_OPERATION: "MAC-generation",
    }
    operations = [labels[operation] for operation in operation_classes]
    if len(operations) == 1:
        return operations[0]
    return " and ".join(operations)


def _scope_breadth_evidence(
    paths: Sequence[GcpCloudRunKmsOperationPath],
) -> list[str]:
    grants_by_scope: dict[GcpKmsScopeType, set[tuple[str, str, str]]] = {
        scope_type: {
            (
                path["iam_resource_address"],
                path["role"],
                path["scope"],
            )
            for path in paths
            if path.get("scope_type") == scope_type
        }
        for scope_type in ("project", "key_ring", "crypto_key")
    }
    modeled_keys: set[str] = {path["key_address"] for path in paths}
    return [
        (
            f"project_grants={len(grants_by_scope['project'])}; "
            f"key_ring_grants={len(grants_by_scope['key_ring'])}; "
            f"exact_key_grants={len(grants_by_scope['crypto_key'])}; "
            f"modeled_keys={len(modeled_keys)}; "
            f"blast_radius_basis={'project_applicable_grant' if grants_by_scope['project'] else 'key_ring_or_exact_key_grant'}"
        )
    ]


def _runtime_identity_evidence(paths: Sequence[GcpCloudRunKmsOperationPath]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"service_account={path.get('service_account_email') or 'unknown'}",
                    f"member={path.get('service_account_member') or 'unknown'}",
                    "identity_kind=cloud_run_service_account",
                    "credential_context=workload_runtime",
                )
            )
            for path in paths
        }
    )


def _operation_path_evidence(paths: Sequence[GcpCloudRunKmsOperationPath]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"key_address={path['key_address']}",
                    f"key_resource_name={path['key_resource_name']}",
                    f"key_project={path['key_project']}",
                    f"key_ring={path['key_ring']}",
                    f"key_purpose={path['key_purpose']}",
                    f"operation={path['operation']}",
                    f"operation_class={path['operation_class']}",
                    f"iam_resource={path['iam_resource_address']}",
                    f"iam_resource_type={path['iam_resource_type']}",
                    f"role={path.get('role') or 'unknown'}",
                    f"scope_type={path['scope_type']}",
                    f"scope={path['scope']}",
                    f"grant_basis={path.get('grant_basis') or 'unknown'}",
                    f"authorization_state={path['authorization_state']}",
                    f"management_state={path['management_state']}",
                    f"condition_state={path['condition_state']}",
                    f"iam_scope_is_key_version={str(path['iam_scope_is_key_version']).lower()}",
                    f"key_version_evidence_scope={path.get('key_version_evidence_scope') or 'none'}",
                    f"key_versions={_version_evidence(path.get('key_versions')) or 'none'}",
                )
            )
            for path in paths
        }
    )


def _version_evidence(
    versions: Sequence[GcpKmsKeyVersionEvidence],
) -> list[str]:
    records: list[str] = []
    for version in versions:
        records.append(
            ";".join(
                (
                    "address=" + version["version_address"],
                    "name=" + (version["version_resource_name"] or "unknown"),
                    "state=" + (version["state"] or "unknown"),
                    "algorithm=" + (version["algorithm"] or "unknown"),
                    "protection_level=" + (version["protection_level"] or "unknown"),
                    "import_posture=" + (version["import_posture"] or "unknown"),
                )
            )
        )
    return sorted(records)


def _public_exposure_configuration(resource: NormalizedResource) -> list[str]:
    if gcp_facts(resource).cloud_run_invoker_iam_disabled is not True:
        return []
    ingress = gcp_facts(resource).serverless_ingress or "unknown"
    return [f"invoker_iam_check=disabled; ingress={ingress}"]


def _public_invoker_evidence(invokers: Sequence[_PublicInvokerBinding]) -> list[str]:
    return sorted(
        {
            f"source={invoker['source']}; role={invoker['role']}; member={invoker['member']}; condition=none"
            for invoker in invokers
        }
    )


def _path_string_values(
    paths: Sequence[GcpCloudRunKmsOperationPath],
    key: _PathAddressKey,
) -> list[str]:
    return sorted({path[key] for path in paths})


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None
