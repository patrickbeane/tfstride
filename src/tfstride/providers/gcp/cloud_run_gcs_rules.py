from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, cast

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, Finding, NormalizedResource
from tfstride.providers.coercion import dedupe
from tfstride.providers.gcp.cloud_run_public_invocation import (
    cloud_run_public_exposure_configuration,
    cloud_run_public_invoker_evidence,
    current_cloud_run_public_exposure_reasons,
    current_cloud_run_public_invokers,
)
from tfstride.providers.gcp.custom_role_index import build_gcp_custom_role_index
from tfstride.providers.gcp.gcs_grant_ancestry import ancestor_iam_scope
from tfstride.providers.gcp.gcs_grant_evaluation import (
    GCS_ACCESS_IAM_TYPES_BY_BASIS,
    GcsGrantConstraintContext,
    evaluate_gcs_operation_constraints,
    gcs_path_permissions,
)
from tfstride.providers.gcp.iam_reference_utils import (
    custom_role_reference_keys,
    gcs_bucket_target_matches,
    normalize_gcp_project,
)
from tfstride.providers.gcp.object_storage_deletion_evidence import (
    GcpCloudRunGcsObjectDeletionPath,
    GcpGcsObjectDeletionRecoveryEvidence,
)
from tfstride.providers.gcp.resource_decoration.cloud_run_gcs_access_paths import current_cloud_run_gcs_access_paths
from tfstride.providers.gcp.resource_decoration.iam import iam_bindings
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import (
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    GCP_CUSTOM_ROLE_RESOURCE_TYPES,
    GCP_ORG_FOLDER_IAM_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.gcp.resource_utils import (
    GCP_ROLE_REFERENCE_SUFFIXES,
    binding_members,
    gcp_reference_key,
)

_MUTATION_ACCESS_CLASSES = frozenset({"write", "administrative"})
_MUTATING_ROLE_KINDS = frozenset({"creator", "user", "admin", "custom"})


class GcpCloudRunGcsAccessRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_cloud_run_gcs_object_disruption(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        current_resources = list(context.inventory.resources)
        grant_context = GcsGrantConstraintContext.build(current_resources)
        findings: list[Finding] = []
        for workload in context.inventory.by_type(*GCP_CLOUD_RUN_RESOURCE_TYPES):
            public_invokers = current_cloud_run_public_invokers(
                workload,
                current_resources,
            )
            invoker_iam_check_disabled = gcp_facts(workload).cloud_run_invoker_iam_disabled is True
            if not workload.public_access_configured or (not public_invokers and not invoker_iam_check_disabled):
                continue

            paths = [
                path
                for path in gcp_facts(workload).cloud_run_gcs_object_deletion_paths
                if _is_current_object_deletion_path(path, workload, context, grant_context)
            ]
            if not paths:
                continue

            bucket_addresses = _deletion_path_string_values(paths, "bucket_address")
            iam_resource_addresses = _deletion_path_string_values(paths, "iam_resource_address")
            public_source_addresses = sorted({binding["source"] for binding in public_invokers})
            operations = _deletion_operation_classes(paths)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2 if len(bucket_addresses) > 1 else 1,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=2 if len(bucket_addresses) > 1 else 1,
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
                            *bucket_addresses,
                            *iam_resource_addresses,
                        ]
                    ),
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=_deletion_rationale(workload, paths, operations),
                    evidence=collect_evidence(
                        evidence_item(
                            "public_invoker_bindings",
                            cloud_run_public_invoker_evidence(public_invokers),
                        ),
                        evidence_item(
                            "public_exposure_reasons",
                            current_cloud_run_public_exposure_reasons(
                                workload,
                                public_invokers,
                                invoker_iam_check_disabled=invoker_iam_check_disabled,
                            ),
                        ),
                        evidence_item(
                            "public_exposure_configuration",
                            cloud_run_public_exposure_configuration(workload),
                        ),
                        evidence_item(
                            "runtime_identity",
                            _deletion_runtime_identity_evidence(paths),
                        ),
                        evidence_item(
                            "gcs_object_deletion_paths",
                            _object_deletion_path_evidence(paths),
                        ),
                        evidence_item(
                            "recovery_posture",
                            _recovery_posture_evidence(paths),
                        ),
                        evidence_item(
                            "authorization_scope",
                            _deletion_authorization_scope_evidence(paths),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_public_cloud_run_gcs_mutation_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        current_resources = list(context.inventory.resources)
        custom_roles = build_gcp_custom_role_index(current_resources)
        findings: list[Finding] = []
        for workload in context.inventory.by_type(*GCP_CLOUD_RUN_RESOURCE_TYPES):
            public_invokers = current_cloud_run_public_invokers(
                workload,
                current_resources,
            )
            invoker_iam_check_disabled = gcp_facts(workload).cloud_run_invoker_iam_disabled is True
            if not workload.public_access_configured or (not public_invokers and not invoker_iam_check_disabled):
                continue

            current_paths = current_cloud_run_gcs_access_paths(workload, current_resources, custom_roles)
            mutation_paths = [
                path for path in current_paths if _is_deterministic_mutation_path(path, workload, context)
            ]
            if not mutation_paths:
                continue

            bucket_addresses = _path_string_values(mutation_paths, "bucket_address")
            iam_resource_addresses = _path_string_values(mutation_paths, "iam_resource_address")
            public_source_addresses = sorted({binding["source"] for binding in public_invokers})
            mutation_classes = _mutation_classes(mutation_paths)
            has_read_access = _has_deterministic_read_access(
                current_paths,
                set(bucket_addresses),
            )
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2 if "administrative" in mutation_classes else 1,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=2 if len(bucket_addresses) > 1 else 1,
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
                            *bucket_addresses,
                            *iam_resource_addresses,
                        ]
                    ),
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=_mutation_rationale(
                        workload,
                        mutation_classes,
                        bucket_addresses,
                        has_read_access=has_read_access,
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "public_invoker_bindings",
                            cloud_run_public_invoker_evidence(public_invokers),
                        ),
                        evidence_item(
                            "public_exposure_reasons",
                            current_cloud_run_public_exposure_reasons(
                                workload,
                                public_invokers,
                                invoker_iam_check_disabled=invoker_iam_check_disabled,
                            ),
                        ),
                        evidence_item(
                            "public_exposure_configuration",
                            cloud_run_public_exposure_configuration(workload),
                        ),
                        evidence_item(
                            "runtime_identity",
                            _runtime_identity_evidence(mutation_paths),
                        ),
                        evidence_item(
                            "gcs_mutation_paths",
                            _mutation_path_evidence(mutation_paths),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _is_deterministic_mutation_path(
    path: Mapping[str, Any],
    workload: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    if (
        path.get("workload_address") != workload.address
        or path.get("workload_type") != workload.resource_type
        or path.get("identity_kind") != "cloud_run_service_account"
        or path.get("credential_context") != "workload_runtime"
        or path.get("grant_basis") not in GCS_ACCESS_IAM_TYPES_BY_BASIS
        or path.get("resource_scope") != "exact_bucket"
        or path.get("access_state") != "granted"
        or path.get("condition_state") != "not_configured"
        or path.get("condition") is not None
        or path.get("role_kind") not in _MUTATING_ROLE_KINDS
        or not _path_mutation_classes(path)
    ):
        return False

    service_account_member = _known_string(path.get("service_account_member"))
    role = _known_string(path.get("role"))
    bucket_address = _known_string(path.get("bucket_address"))
    iam_resource_address = _known_string(path.get("iam_resource_address"))
    if not all((service_account_member, role, bucket_address, iam_resource_address)):
        return False

    assert bucket_address is not None
    assert iam_resource_address is not None
    bucket = context.inventory.get_by_address(bucket_address)
    iam_resource = context.inventory.get_by_address(iam_resource_address)
    if (
        bucket is None
        or bucket.resource_type != GcpResourceType.STORAGE_BUCKET
        or iam_resource is None
        or iam_resource.resource_type
        not in GCS_ACCESS_IAM_TYPES_BY_BASIS.get(str(path.get("grant_basis")), frozenset())
    ):
        return False

    if path.get("role_kind") == "custom" and not _string_values(path.get("matched_permissions")):
        return False
    return True


def _mutation_rationale(
    workload: NormalizedResource,
    mutation_classes: list[str],
    bucket_addresses: list[str],
    *,
    has_read_access: bool,
) -> str:
    rationale = (
        f"{workload.display_name} is publicly invokable and its Cloud Run runtime service account has "
        f"deterministic {', '.join(mutation_classes)} access to {len(bucket_addresses)} exact modeled GCS "
        f"bucket(s). A compromise of the public workload could tamper with stored data by "
        f"{_mutation_impact(mutation_classes)} within the modeled grants. "
        "This path does not mean that the GCS bucket itself is public."
    )
    if not has_read_access:
        rationale += (
            " The modeled grant is write-only: it represents tampering risk and does not establish read access "
            "or information disclosure."
        )
    return rationale


def _mutation_impact(mutation_classes: list[str]) -> str:
    impacts = {
        "write": "writing objects",
        "administrative": "changing object access controls",
    }
    values = [impacts[access_class] for access_class in mutation_classes]
    if len(values) == 1:
        return values[0]
    return ", ".join(values[:-1]) + f", or {values[-1]}"


def _has_deterministic_read_access(
    paths: Sequence[Mapping[str, Any]],
    bucket_addresses: set[str],
) -> bool:
    return any(
        path.get("bucket_address") in bucket_addresses
        and path.get("access_state") == "granted"
        and path.get("condition_state") == "not_configured"
        and "storage.objects.get" in gcs_path_permissions(path)
        for path in paths
    )


def _mutation_classes(paths: Sequence[Mapping[str, Any]]) -> list[str]:
    classes = {access_class for path in paths for access_class in _path_mutation_classes(path)}
    return [access_class for access_class in ("write", "administrative") if access_class in classes]


def _path_mutation_classes(path: Mapping[str, Any]) -> list[str]:
    permissions = gcs_path_permissions(path)
    return [
        access_class
        for access_class in _string_values(path.get("access_classes"))
        if access_class in _MUTATION_ACCESS_CLASSES
        and (
            access_class == "write"
            and any(
                permission in permissions
                for permission in (
                    "storage.objects.create",
                    "storage.objects.update",
                    "storage.objects.compose",
                    "storage.objects.move",
                    "storage.objects.restore",
                    "storage.objects.rewrite",
                )
            )
            or access_class == "administrative"
            and "storage.objects.setIamPolicy" in permissions
        )
    ]


def _path_string_values(paths: Sequence[Mapping[str, Any]], key: str) -> list[str]:
    return sorted({value for path in paths if (value := _known_string(path.get(key))) is not None})


def _runtime_identity_evidence(paths: Sequence[Mapping[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"service_account={path.get('service_account_email') or 'unknown'}",
                    f"member={path['service_account_member']}",
                    f"role={path['role']}",
                    f"role_kind={path['role_kind']}",
                    "credential_context=workload_runtime",
                )
            )
            for path in paths
        }
    )


def _mutation_path_evidence(paths: Sequence[Mapping[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"bucket_address={path['bucket_address']}",
                    f"bucket_name={path.get('bucket_name') or 'unknown'}",
                    f"iam_resource={path['iam_resource_address']}",
                    f"role={path['role']}",
                    f"role_kind={path['role_kind']}",
                    f"mutation_classes={','.join(_path_mutation_classes(path))}",
                    f"access_classes={','.join(_string_values(path.get('access_classes')))}",
                    f"operations={','.join(gcs_path_permissions(path))}",
                    f"matched_permissions={','.join(_string_values(path.get('matched_permissions'))) or 'built-in-role'}",
                    "resource_scope=exact_bucket",
                    "access_state=granted",
                    "condition_state=not_configured",
                    *(
                        (
                            f"grant_basis={path['grant_basis']}",
                            f"grant_project={path.get('grant_project')}",
                        )
                        if path.get("grant_basis") == "storage_project_iam"
                        else ()
                    ),
                    *(
                        (
                            f"grant_basis={path['grant_basis']}",
                            f"grant_scope={path.get('grant_scope')}",
                            f"grant_ancestry={','.join(path.get('grant_ancestry', []))}",
                        )
                        if path.get("grant_scope")
                        else ()
                    ),
                    *(
                        f"permission_constraint={constraint.get('policy_address')}:"
                        f"{constraint.get('permission')}:{constraint.get('state')}"
                        for raw_constraint in path.get("permission_constraints", [])
                        if isinstance(raw_constraint, Mapping)
                        for constraint in (cast(Mapping[str, object], raw_constraint),)
                    ),
                )
            )
            for path in paths
        }
    )


_DELETE_PERMISSION = "storage.objects.delete"
_DELETION_OPERATION = "storage.objects.delete"
_DELETION_SCOPE_PREFIX = "projects/_/buckets/"
_BUCKET_SCOPE_TYPE = "bucket"
_SOFT_DELETE_DISABLED_STATE = "disabled"
_DELETION_ROLE_KINDS = frozenset({"predefined", "custom"})
_DELETE_PREDEFINED_ROLES = frozenset(
    {
        "roles/storage.admin",
        "roles/storage.objectAdmin",
        "roles/storage.objectUser",
        "roles/storage.legacyBucketOwner",
        "roles/storage.legacyBucketWriter",
    }
)
_BUCKET_ONLY_DELETE_ROLES = frozenset(
    {
        "roles/storage.legacyBucketOwner",
        "roles/storage.legacyBucketWriter",
    }
)
_ACTIVE_CUSTOM_ROLE_STAGES = frozenset({"ALPHA", "BETA", "DEPRECATED", "EAP", "GA"})


def _is_current_object_deletion_path(
    path: GcpCloudRunGcsObjectDeletionPath,
    workload: NormalizedResource,
    context: RuleEvaluationContext,
    grant_context: GcsGrantConstraintContext,
) -> bool:
    if (
        path.get("workload_address") != workload.address
        or path.get("workload_type") != workload.resource_type
        or path.get("identity_kind") != "cloud_run_service_account"
        or path.get("credential_context") != "workload_runtime"
        or path.get("operation") != _DELETION_OPERATION
        or path.get("management_effect") != "disruption"
        or path.get("authorization_state") != "granted"
        or path.get("policy_complete") is not True
        or path.get("condition") is not None
        or path.get("condition_state") != "not_configured"
        or path.get("matched_permissions") != [_DELETE_PERMISSION]
    ):
        return False

    workload_facts = gcp_facts(workload)
    email = _known_string(workload_facts.service_account_email)
    member = _known_string(workload_facts.service_account_member)
    if not _is_exact_service_account_identity(email, member):
        return False
    assert email is not None
    assert member is not None
    if path.get("service_account_email") != email or path.get("service_account_member") != member:
        return False

    bucket_address = _known_string(path.get("bucket_address"))
    iam_resource_address = _known_string(path.get("iam_resource_address"))
    if bucket_address is None or iam_resource_address is None:
        return False
    bucket = context.inventory.get_by_address(bucket_address)
    source = context.inventory.get_by_address(iam_resource_address)
    if bucket is None or bucket.resource_type != GcpResourceType.STORAGE_BUCKET or source is None:
        return False

    bucket_facts = gcp_facts(bucket)
    bucket_name = _known_string(bucket_facts.bucket_name)
    bucket_project = normalize_gcp_project(bucket_facts.project)
    if (
        bucket_name is None
        or bucket_project is None
        or path.get("bucket_name") != bucket_name
        or path.get("bucket_project") != bucket_project
        or path.get("target_model_evidence_addresses") != [bucket.address]
        or not _target_scope_is_current(path, bucket_name)
    ):
        return False

    if not _iam_source_is_current(path, source, bucket, bucket_name, bucket_project, member, grant_context):
        return False
    if not _role_evidence_is_current(path, source, context):
        return False
    if not _recovery_evidence_is_current(path, bucket):
        return False
    return evaluate_gcs_operation_constraints(
        member, bucket, source.address, path["role"], _DELETE_PERMISSION, grant_context
    )[0]


def _is_exact_service_account_identity(email: str | None, member: str | None) -> bool:
    return bool(
        email
        and member
        and email.endswith(".gserviceaccount.com")
        and "${" not in email
        and member == f"serviceAccount:{email}"
        and "${" not in member
    )


def _target_scope_is_current(path: Mapping[str, object], bucket_name: str) -> bool:
    target_scope = path.get("target_scope")
    expected_scope = f"{_DELETION_SCOPE_PREFIX}{bucket_name}/objects/*"
    if target_scope != expected_scope:
        return False

    operation_class = path.get("operation_class")
    granularity = path.get("target_granularity")
    object_name = path.get("object_name")
    generation = path.get("generation")
    if operation_class == "logical_object_deletion":
        return granularity == "bucket_object_namespace" and object_name is None and generation is None
    if operation_class == "generation_deletion":
        return granularity == "bucket_generation_namespace" and object_name is None and generation is None
    return False


def _iam_source_is_current(
    path: Mapping[str, object],
    source: NormalizedResource,
    bucket: NormalizedResource,
    bucket_name: str,
    bucket_project: str,
    service_account_member: str,
    grant_context: GcsGrantConstraintContext,
) -> bool:
    bucket_address = bucket.address
    source_facts = gcp_facts(source)
    if source_facts.iam_scope_reference_state in {"unknown", "not_configured"}:
        return False
    if source.resource_type in GCP_ORG_FOLDER_IAM_RESOURCE_TYPES:
        expected_scope_type, expected_scope, match = ancestor_iam_scope(source, bucket, grant_context.index)
        if match is not True:
            return False
    elif source.resource_type in GCP_PROJECT_IAM_RESOURCE_TYPES:
        expected_scope_type = "project"
        expected_scope = bucket_project
        if normalize_gcp_project(source_facts.project) != bucket_project:
            return False
    elif source.resource_type in GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES:
        expected_scope_type = "bucket"
        expected_scope = f"{_DELETION_SCOPE_PREFIX}{bucket_name}"
        if not _iam_target_matches_bucket(source_facts.target_reference, bucket_address, bucket_name):
            return False
    else:
        return False

    if (
        path.get("iam_resource_type") != source.resource_type
        or path.get("scope_type") != expected_scope_type
        or path.get("scope") != expected_scope
        or path.get("grant_basis") != f"{expected_scope_type}_iam_{_iam_management_mode(source)}"
    ):
        return False
    if source.resource_type.endswith("_iam_policy") and source_facts.iam_policy_data_state != "configured":
        return False

    for binding in iam_bindings(source):
        if (
            _known_string(binding.get("role")) == _known_string(path.get("role"))
            and service_account_member in binding_members(binding)
            and binding.get("condition_state") != "unknown"
            and not binding.get("condition")
        ):
            return True
    return False


def _iam_target_matches_bucket(
    target_reference: str | None,
    bucket_address: str,
    bucket_name: str,
) -> bool:
    return gcs_bucket_target_matches(target_reference, bucket_address, bucket_name)


def _iam_management_mode(resource: NormalizedResource) -> str:
    if resource.resource_type.endswith("_iam_policy"):
        return "authoritative_policy"
    if resource.resource_type.endswith("_iam_binding"):
        return "authoritative_role_binding"
    return "additive_member"


def _role_evidence_is_current(
    path: Mapping[str, object],
    source: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    role = _known_string(path.get("role"))
    if role is None or path.get("role_kind") not in _DELETION_ROLE_KINDS:
        return False
    source_address = source.address
    source_addresses = path.get("iam_source_addresses")
    if not isinstance(source_addresses, list) or not all(isinstance(item, str) for item in source_addresses):
        return False
    if _looks_like_custom_role(role):
        if path.get("role_kind") != "custom" or len(source_addresses) != 2 or source_addresses[0] != source_address:
            return False
        role_definition = context.inventory.get_by_address(source_addresses[1])
        if role_definition is None or role_definition.resource_type not in GCP_CUSTOM_ROLE_RESOURCE_TYPES:
            return False
        role_key = gcp_reference_key(role, GCP_ROLE_REFERENCE_SUFFIXES)
        if role_key not in custom_role_reference_keys(role_definition):
            return False
        role_facts = gcp_facts(role_definition)
        stage = role_facts.custom_role_stage
        if (
            role_facts.custom_role_deleted is not False
            or stage is None
            or stage.upper() not in _ACTIVE_CUSTOM_ROLE_STAGES
            or role_facts.custom_role_permissions_state != "configured"
            or not _permissions_grant_delete(role_facts.custom_role_permissions)
            or path.get("custom_role_permissions") != sorted(set(role_facts.custom_role_permissions))
        ):
            return False
        return True

    if path.get("role_kind") != "predefined" or source_addresses != [source_address]:
        return False
    if role not in _DELETE_PREDEFINED_ROLES or role in {"roles/editor", "roles/owner"}:
        return False
    if role in _BUCKET_ONLY_DELETE_ROLES and path.get("scope_type") != _BUCKET_SCOPE_TYPE:
        return False
    return path.get("custom_role_permissions") == []


def _looks_like_custom_role(role: str) -> bool:
    return role.startswith(("projects/", "organizations/")) or "iam_custom_role." in role


def _permissions_grant_delete(permissions: Sequence[object]) -> bool:
    return any(
        permission in {"*", "storage.*", "storage.objects.*", _DELETE_PERMISSION}
        for permission in permissions
        if isinstance(permission, str)
    )


def _recovery_evidence_is_current(path: Mapping[str, object], bucket: NormalizedResource) -> bool:
    expected_lifecycle, expected_evidence = _expected_recovery_evidence(bucket)
    actual_evidence = path.get("recovery_evidence")
    if not isinstance(actual_evidence, Mapping):
        return False
    actual = cast(Mapping[str, object], actual_evidence)
    if any(actual.get(key) != value for key, value in expected_evidence.items()):
        return False
    return (
        path.get("lifecycle_compatibility_state") == expected_lifecycle
        and path.get("posture_uncertainties") == expected_evidence["uncertainties"]
    )


def _expected_recovery_evidence(
    bucket: NormalizedResource,
) -> tuple[str, GcpGcsObjectDeletionRecoveryEvidence]:
    facts = gcp_facts(bucket)
    uncertainties = dedupe(
        [
            *facts.gcs_versioning_uncertainties,
            *facts.gcs_soft_delete_policy_uncertainties,
            *facts.gcs_retention_policy_uncertainties,
        ]
    )
    raw_soft_delete_state = facts.gcs_soft_delete_state
    if raw_soft_delete_state == "enabled":
        soft_delete_state = "enabled"
    elif raw_soft_delete_state == _SOFT_DELETE_DISABLED_STATE:
        soft_delete_state = "disabled"
    elif raw_soft_delete_state == "not_observed":
        soft_delete_state = "not_observed"
    else:
        soft_delete_state = "unknown"
    if soft_delete_state == "not_observed":
        uncertainties = dedupe(
            [
                *uncertainties,
                f"{bucket.address}: soft-delete policy is not observed; the platform default is not inferred",
            ]
        )
    elif soft_delete_state == "unknown" and not facts.gcs_soft_delete_policy_uncertainties:
        uncertainties = dedupe([*uncertainties, f"{bucket.address}: soft-delete recovery posture is unresolved"])

    retention = facts.gcs_retention_period_seconds
    if facts.gcs_retention_policy_uncertainties:
        lifecycle = "unknown"
    elif retention is not None and retention > 0:
        lifecycle = "unknown"
        uncertainties = dedupe(
            [
                *uncertainties,
                f"{bucket.address}: retention policy does not establish the age of a targeted object or generation",
            ]
        )
    else:
        lifecycle = "compatible"

    evidence: GcpGcsObjectDeletionRecoveryEvidence = {
        "recovery_evidence_scope": "gcs_versioning_soft_delete_and_retention",
        "versioning_enabled": facts.versioning_enabled,
        "soft_delete_retention_duration_seconds": facts.gcs_soft_delete_retention_duration_seconds,
        "soft_delete_state": soft_delete_state,
        "retention_period_seconds": retention,
        "retention_policy_locked": facts.gcs_retention_policy_locked,
        "uncertainties": uncertainties,
    }
    return lifecycle, evidence


def _deletion_path_string_values(paths: Sequence[Mapping[str, object]], key: str) -> list[str]:
    return sorted({value for path in paths if (value := _known_string(path.get(key))) is not None})


def _deletion_operation_classes(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return [
        operation_class
        for operation_class in ("logical_object_deletion", "generation_deletion")
        if any(path.get("operation_class") == operation_class for path in paths)
    ]


def _operation_text(operations: Sequence[str]) -> str:
    if len(operations) == 1:
        return operations[0]
    if len(operations) == 2:
        return f"{operations[0]} and {operations[1]}"
    return ", ".join(operations[:-1]) + f", and {operations[-1]}"


def _deletion_rationale(
    workload: NormalizedResource,
    paths: Sequence[Mapping[str, object]],
    operation_classes: Sequence[str],
) -> str:
    buckets = _deletion_path_string_values(paths, "bucket_address")
    rationale = (
        f"{workload.display_name} is publicly invokable and its Cloud Run runtime service account has "
        f"deterministic GCS object-deletion authority ({_operation_text(list(operation_classes))}) across "
        f"{len(buckets)} exact modeled GCS bucket(s). A compromise of the public workload could disrupt "
        "object availability within the modeled IAM scopes."
    )
    recovery_states = {_recovery_state(path) for path in paths}
    if "soft_deleted_recoverable_during_retention" in recovery_states:
        rationale += " Soft-delete evidence supports recovery during the configured retention duration."
    if "live_generation_retained_as_noncurrent" in recovery_states:
        rationale += (
            " Object Versioning preserves the live generation as a noncurrent generation for logical deletion requests."
        )
    if "recovery_posture_unknown" in recovery_states or any(
        path.get("lifecycle_compatibility_state") == "unknown" for path in paths
    ):
        rationale += (
            " Recovery posture is partly unknown: recovery controls or the targeted object age are not fully "
            "modeled, but that uncertainty does not remove the deterministic deletion authority."
        )
    rationale += " This path does not establish that the GCS bucket itself is public or that deletion succeeds."
    return rationale


def _recovery_state(path: Mapping[str, object]) -> str:
    recovery = path.get("recovery_evidence")
    if not isinstance(recovery, Mapping):
        return "recovery_posture_unknown"
    recovery_map = cast(Mapping[str, object], recovery)
    soft_state = recovery_map.get("soft_delete_state")
    duration = recovery_map.get("soft_delete_retention_duration_seconds")
    operation_class = path.get("operation_class")
    versioning = recovery_map.get("versioning_enabled")
    if operation_class == "logical_object_deletion":
        if versioning is True:
            return "live_generation_retained_as_noncurrent"
        if versioning is None:
            return "recovery_posture_unknown"
        if soft_state == "enabled" and isinstance(duration, int) and duration > 0:
            return "soft_deleted_recoverable_during_retention"
        if soft_state == _SOFT_DELETE_DISABLED_STATE:
            return "recovery_control_not_observed"
    elif operation_class == "generation_deletion":
        if soft_state == "enabled" and isinstance(duration, int) and duration > 0:
            return "soft_deleted_recoverable_during_retention"
        if soft_state == _SOFT_DELETE_DISABLED_STATE:
            return "generation_not_protected_by_versioning"
    if soft_state in {"unknown", "not_observed"} or path.get("lifecycle_compatibility_state") == "unknown":
        return "recovery_posture_unknown"
    return "recovery_control_not_observed"


def _deletion_runtime_identity_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"service_account={path.get('service_account_email')}",
                    f"member={path.get('service_account_member')}",
                    "identity_kind=cloud_run_service_account",
                    "credential_context=workload_runtime",
                    "authorization_state=granted",
                )
            )
            for path in paths
        }
    )


def _object_deletion_path_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        recovery = path.get("recovery_evidence")
        recovery_map: Mapping[str, object] = (
            cast(Mapping[str, object], recovery) if isinstance(recovery, Mapping) else {}
        )
        values.add(
            "; ".join(
                (
                    f"bucket_address={path.get('bucket_address')}",
                    f"bucket_name={path.get('bucket_name')}",
                    f"operation={path.get('operation')}",
                    f"operation_class={path.get('operation_class')}",
                    f"target_granularity={path.get('target_granularity')}",
                    f"target_scope={path.get('target_scope')}",
                    f"iam_resource={path.get('iam_resource_address')}",
                    f"role={path.get('role')}",
                    f"scope_type={path.get('scope_type')}",
                    f"scope={path.get('scope')}",
                    f"grant_basis={path.get('grant_basis')}",
                    f"matched_permissions={','.join(_string_values(path.get('matched_permissions')))}",
                    "authorization_state=granted",
                    f"lifecycle_compatibility_state={path.get('lifecycle_compatibility_state')}",
                    f"soft_delete_state={recovery_map.get('soft_delete_state')}",
                    f"versioning_enabled={str(recovery_map.get('versioning_enabled')).lower()}",
                )
            )
        )
    return sorted(values)


def _retention_effect(path: Mapping[str, object], recovery: Mapping[str, object]) -> str:
    retention = recovery.get("retention_period_seconds")
    if isinstance(retention, int) and retention > 0:
        return "may_block_deletion_until_target_age_is_known"
    if path.get("lifecycle_compatibility_state") == "unknown":
        return "unknown"
    return "not_observed"


def _recovery_posture_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        recovery = path.get("recovery_evidence")
        if not isinstance(recovery, Mapping):
            continue
        recovery = cast(Mapping[str, object], recovery)
        values.add(
            "; ".join(
                (
                    f"bucket_address={path.get('bucket_address')}",
                    f"operation={path.get('operation')}",
                    f"operation_class={path.get('operation_class')}",
                    f"target_granularity={path.get('target_granularity')}",
                    f"recovery_state={_recovery_state(path)}",
                    f"soft_delete_state={recovery.get('soft_delete_state')}",
                    f"soft_delete_retention_duration_seconds={recovery.get('soft_delete_retention_duration_seconds')}",
                    f"versioning_enabled={str(recovery.get('versioning_enabled')).lower()}",
                    f"retention_period_seconds={recovery.get('retention_period_seconds')}",
                    f"retention_policy_locked={str(recovery.get('retention_policy_locked')).lower()}",
                    f"retention_effect={_retention_effect(path, recovery)}",
                    f"retention_compatibility={'unknown' if path.get('lifecycle_compatibility_state') == 'unknown' else 'compatible'}",
                    f"uncertainties={','.join(_string_values(recovery.get('uncertainties'))) or 'none'}",
                )
            )
        )
    return sorted(values)


def _deletion_authorization_scope_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"scope_type={path.get('scope_type')}",
                    f"scope={path.get('scope')}",
                    f"iam_resource={path.get('iam_resource_address')}",
                    f"role={path.get('role')}",
                    f"grant_basis={path.get('grant_basis')}",
                    f"iam_sources={','.join(_string_values(path.get('iam_source_addresses'))) or 'none'}",
                )
            )
            for path in paths
        }
    )


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None
