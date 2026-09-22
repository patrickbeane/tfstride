from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.aws.kms_dependency_evidence import (
    AwsKmsEncryptionDependency,
)
from tfstride.providers.aws.kms_evidence import AwsEcsKmsOperationPath
from tfstride.providers.aws.protected_data_evidence import (
    AwsEcsS3AccessPath,
    AwsEcsS3ProtectedDataConvergence,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.coercion import dedupe

_ECS_SERVICE = "aws_ecs_service"
_ECS_TASK_DEFINITION = "aws_ecs_task_definition"
_IAM_ROLE = "aws_iam_role"
_S3_BUCKET = "aws_s3_bucket"
_S3_ENCRYPTION_CONFIGURATION = "aws_s3_bucket_server_side_encryption_configuration"
_KMS_KEY = "aws_kms_key"
_KMS_ALIAS = "aws_kms_alias"
_AUTHORIZATION_BASIS_NAMES = {
    "direct_key_policy": "key_policy_direct",
    "iam_via_account_principal": "iam_via_key_policy",
    "kms_grant": "grant",
}
_AUTHORIZATION_BASES = frozenset(
    {
        "key_policy_direct",
        "iam_via_key_policy",
        "grant",
    }
)
_S3_PAYLOAD_READ_ACTIONS = frozenset(
    {
        "s3:GetObject",
        "s3:GetObjectVersion",
    }
)
_KMS_S3_ALGORITHMS = frozenset({"aws:kms", "aws:kms:dsse"})
_S3_OBJECT_SCOPES = frozenset(
    {
        "all_bucket_objects",
        "object_prefix",
        "exact_object",
    }
)


class ModelEcsS3ProtectedDataConvergenceStage:
    name = "model_ecs_s3_protected_data_convergence"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AwsDecorationContext,
    ) -> None:
        for service in resources:
            if service.resource_type != _ECS_SERVICE:
                continue
            convergences, uncertainties = _protected_data_convergences(
                service,
                context,
            )
            facts = aws_facts(service)
            facts.set_ecs_s3_protected_data_convergences(convergences)
            facts.extend_ecs_s3_protected_data_convergence_uncertainties(uncertainties)


def _protected_data_convergences(
    service: NormalizedResource,
    context: AwsDecorationContext,
) -> tuple[list[AwsEcsS3ProtectedDataConvergence], list[str]]:
    facts = aws_facts(service)
    uncertainties = [
        *facts.ecs_s3_access_path_uncertainties,
        *facts.ecs_kms_operation_path_uncertainties,
    ]
    convergences: list[AwsEcsS3ProtectedDataConvergence] = []

    for access_path in facts.ecs_s3_access_paths:
        if not _potential_payload_read(access_path):
            continue
        bucket = _access_path_bucket(access_path, service, context)
        if bucket is None:
            uncertainties.append(
                f"{service.address}: S3 access evidence does not retain an "
                "exact modeled bucket for protected-data convergence"
            )
            continue

        bucket_facts = aws_facts(bucket)
        dependencies = bucket_facts.kms_encryption_dependencies
        uncertainties.extend(
            f"{service.address}: {uncertainty}" for uncertainty in bucket_facts.kms_encryption_dependency_uncertainties
        )
        for dependency in dependencies:
            if dependency["resolution_state"] == "resolved":
                if dependency["encryption_ownership_state"] == "unknown":
                    uncertainties.append(
                        f"{service.address}: {bucket.address} KMS dependency has unresolved encryption ownership"
                    )
                continue
            if dependency["posture_uncertainties"]:
                uncertainties.extend(
                    f"{service.address}: {bucket.address} KMS dependency is "
                    f"{dependency['resolution_state']}: {uncertainty}"
                    for uncertainty in dependency["posture_uncertainties"]
                )
            else:
                uncertainties.append(
                    f"{service.address}: {bucket.address} KMS dependency is {dependency['resolution_state']}"
                )

        if not _deterministic_payload_read(
            access_path,
            service,
            bucket,
            context,
        ):
            if dependencies:
                uncertainties.append(
                    f"{service.address}: S3 payload-read authority to "
                    f"{bucket.address} is not deterministic for "
                    "protected-data convergence"
                )
            continue

        for dependency in dependencies:
            key = _dependency_key(
                dependency,
                bucket,
                context,
            )
            if key is None:
                continue
            for operation_path in facts.ecs_kms_operation_paths:
                if (
                    operation_path["operation"] == "kms:Decrypt"
                    and operation_path["workload_address"] == service.address
                    and operation_path["role_address"] == access_path["role_address"]
                    and operation_path["key_address"] == key.address
                    and _decrypt_constraint_requires_compatibility(operation_path)
                ):
                    uncertainties.append(
                        f"{service.address}: KMS decrypt constraint "
                        f"{operation_path['constraint_state']} on "
                        f"{key.address} is not proven compatible with "
                        f"S3 data in {bucket.address}"
                    )
                    continue
                if not _deterministic_decrypt_path(
                    operation_path,
                    service,
                    access_path,
                    key,
                    context,
                ):
                    continue
                if not _dependency_matches_decrypt_path(
                    dependency,
                    operation_path,
                    key,
                ):
                    continue
                convergences.append(
                    _convergence_record(
                        service,
                        access_path,
                        operation_path,
                        dependency,
                    )
                )

    return _dedupe_convergences(convergences), dedupe(uncertainties)


def _potential_payload_read(path: AwsEcsS3AccessPath) -> bool:
    return bool(
        _S3_PAYLOAD_READ_ACTIONS.intersection(path["matched_actions"])
        or _S3_PAYLOAD_READ_ACTIONS.intersection(path["unknown_actions"])
    )


def _deterministic_payload_read(
    path: AwsEcsS3AccessPath,
    service: NormalizedResource,
    bucket: NormalizedResource,
    context: AwsDecorationContext,
) -> bool:
    task_definition_address = path.get("task_definition_address")
    task_definition = (
        context.index.resources_by_address.get(task_definition_address)
        if isinstance(task_definition_address, str)
        else None
    )
    role = context.index.resources_by_address.get(path["role_address"])
    role_arn = path["role_arn"]
    return bool(
        path["workload_address"] == service.address
        and path["workload_type"] == _ECS_SERVICE
        and task_definition is not None
        and task_definition.resource_type == _ECS_TASK_DEFINITION
        and task_definition.address in aws_facts(service).resolved_task_definition_addresses
        and role is not None
        and role.resource_type == _IAM_ROLE
        and isinstance(role_arn, str)
        and bool(role_arn)
        and role.arn == role_arn
        and aws_facts(task_definition).task_role_arn == role_arn
        and path["role_kind"] == "ecs_task_role"
        and path["credential_context"] == "workload_runtime"
        and path["access_state"] == "allowed"
        and path["role_policy_complete"] is True
        and "read" in path["access_classes"]
        and path["bucket_policy_constraints_complete"] is True
        and bool(_S3_PAYLOAD_READ_ACTIONS.intersection(path["matched_actions"]))
        and bool(_S3_OBJECT_SCOPES.intersection(path["resource_scopes"]))
        and _has_unconditional_payload_read_statement(path)
        and path["bucket_address"] == bucket.address
        and path["bucket_arn"] == bucket.arn
    )


def _has_unconditional_payload_read_statement(
    path: AwsEcsS3AccessPath,
) -> bool:
    return any(
        statement["effect"] == "allow"
        and statement["conditional"] is False
        and bool(_S3_PAYLOAD_READ_ACTIONS.intersection(statement["matched_actions"]))
        and bool(_S3_OBJECT_SCOPES.intersection(statement["resource_scopes"]))
        for statement in path["policy_statements"]
    )


def _access_path_bucket(
    path: AwsEcsS3AccessPath,
    service: NormalizedResource,
    context: AwsDecorationContext,
) -> NormalizedResource | None:
    if path["workload_address"] != service.address or path["workload_type"] != _ECS_SERVICE:
        return None
    bucket = context.index.resources_by_address.get(path["bucket_address"])
    if (
        bucket is None
        or bucket.resource_type != _S3_BUCKET
        or not isinstance(bucket.arn, str)
        or path["bucket_arn"] != bucket.arn
    ):
        return None
    return bucket


def _dependency_key(
    dependency: AwsKmsEncryptionDependency,
    bucket: NormalizedResource,
    context: AwsDecorationContext,
) -> NormalizedResource | None:
    encryption_algorithm = aws_facts(bucket).s3_encryption_algorithm
    if (
        not isinstance(encryption_algorithm, str)
        or encryption_algorithm.strip().casefold() not in _KMS_S3_ALGORITHMS
        or dependency["resolution_state"] != "resolved"
        or dependency["encryption_ownership_state"] != "customer_managed"
        or dependency["dependent_address"] != bucket.address
        or dependency["dependent_resource_type"] != bucket.resource_type
        or not _s3_dependency_path(dependency["configuration_path"])
    ):
        return None

    source = context.index.resources_by_address.get(dependency["dependency_source_address"])
    if (
        source is None
        or source.provider != "aws"
        or source.resource_type != dependency["dependency_source_type"]
        or source.resource_type not in {_S3_BUCKET, _S3_ENCRYPTION_CONFIGURATION}
    ):
        return None
    expected_source_address = aws_facts(bucket).s3_encryption_source_address or bucket.address
    if source.address != expected_source_address:
        return None

    key_address = dependency["key_address"]
    key = context.index.resources_by_address.get(key_address) if isinstance(key_address, str) else None
    if key is None or key.resource_type != _KMS_KEY:
        return None
    key_arn = aws_facts(key).kms_key_arn or key.arn
    if (
        not _is_exact_kms_key_arn(key_arn)
        or dependency["key_arn"] != key_arn
        or not _dependency_candidate_is_coherent(
            dependency,
            key,
            context,
        )
    ):
        return None
    return key


def _dependency_candidate_is_coherent(
    dependency: AwsKmsEncryptionDependency,
    key: NormalizedResource,
    context: AwsDecorationContext,
) -> bool:
    candidates = dependency["candidate_targets"]
    if len(candidates) != 1:
        return False
    candidate = candidates[0]
    candidate_resource = context.index.resources_by_address.get(candidate["address"])
    if candidate_resource is None:
        return False
    alias_address = dependency["alias_address"]
    if alias_address is None:
        return bool(
            candidate["target_kind"] == "key"
            and candidate_resource.address == key.address
            and candidate_resource.resource_type == _KMS_KEY
            and _dependency_reference_is_coherent(
                dependency,
                candidate_resource,
                key,
            )
        )
    return bool(
        candidate["target_kind"] == "alias"
        and candidate_resource.address == alias_address
        and candidate_resource.resource_type == _KMS_ALIAS
        and aws_facts(candidate_resource).kms_alias_resolved_key_address == key.address
        and _dependency_reference_is_coherent(
            dependency,
            candidate_resource,
            key,
        )
    )


def _dependency_reference_is_coherent(
    dependency: AwsKmsEncryptionDependency,
    candidate: NormalizedResource,
    key: NormalizedResource,
) -> bool:
    provenance = dependency["reference_provenance"]
    reference_kind = dependency["reference_kind"]
    configured = dependency["configured_key_reference"]
    if provenance == "configuration_reference":
        if reference_kind != "terraform_reference" or configured is None:
            return False
        suffixes = (".arn", ".id", ".key_id") if candidate.resource_type == _KMS_KEY else (".arn", ".id", ".name")
        return configured.startswith(f"{candidate.address}.") and configured.endswith(suffixes)
    if provenance != "planned_value" or configured is None:
        return False
    if reference_kind == "key_arn":
        return configured == (aws_facts(key).kms_key_arn or key.arn)
    if reference_kind == "key_id":
        return configured == (aws_facts(key).kms_key_id or key.identifier)
    if candidate.resource_type != _KMS_ALIAS:
        return False
    alias_facts = aws_facts(candidate)
    if reference_kind == "alias_arn":
        return configured == alias_facts.kms_alias_arn
    if reference_kind == "alias_name":
        return configured == alias_facts.kms_alias_name
    return False


def _deterministic_decrypt_path(
    path: AwsEcsKmsOperationPath,
    service: NormalizedResource,
    access_path: AwsEcsS3AccessPath,
    key: NormalizedResource,
    context: AwsDecorationContext,
) -> bool:
    task_definition_address = path["task_definition_address"]
    task_definition = context.index.resources_by_address.get(task_definition_address)
    role = context.index.resources_by_address.get(path["role_address"])
    role_arn = path["role_arn"]
    key_arn = aws_facts(key).kms_key_arn or key.arn
    authorization_bases = path["authorization_bases"]
    authorization = path["authorization_record"]
    return bool(
        path["workload_address"] == service.address
        and path["workload_type"] == _ECS_SERVICE
        and task_definition is not None
        and task_definition.resource_type == _ECS_TASK_DEFINITION
        and task_definition.address == access_path.get("task_definition_address")
        and task_definition.address in aws_facts(service).resolved_task_definition_addresses
        and role is not None
        and role.resource_type == _IAM_ROLE
        and role.address == access_path["role_address"]
        and isinstance(role_arn, str)
        and bool(role_arn)
        and role.arn == role_arn
        and role_arn == access_path["role_arn"]
        and aws_facts(task_definition).task_role_arn == role_arn
        and path["role_kind"] == "ecs_task_role"
        and path["credential_context"] == "workload_runtime"
        and path["operation"] == "kms:Decrypt"
        and path["authorization_state"] == "allowed"
        and path["role_policy_complete"] is True
        and path["key_policy_complete"] is True
        and path["same_account"] is True
        and path["explicit_deny"] is False
        and path["conditional_evaluation_required"] is False
        and not _decrypt_constraint_requires_compatibility(path)
        and path["key_address"] == key.address
        and path["key_arn"] == key_arn
        and path["key_usage"] == "ENCRYPT_DECRYPT"
        and aws_facts(key).kms_key_usage == "ENCRYPT_DECRYPT"
        and bool(authorization_bases)
        and all(basis in _AUTHORIZATION_BASES for basis in authorization_bases)
        and authorization["operation"] == "kms:Decrypt"
        and authorization["operation_class"] == "cryptographic_use"
        and authorization["key_address"] == key.address
        and authorization["key_arn"] == key_arn
        and authorization["key_usage"] == "ENCRYPT_DECRYPT"
        and authorization["principal_address"] == role.address
        and authorization["principal_arn"] == role_arn
        and authorization["principal_kind"] == "iam_role"
        and authorization["authorization_state"] == "allowed"
        and authorization["key_policy_complete"] is True
        and authorization["identity_policy_complete"] is True
        and authorization["same_account"] is True
        and authorization["explicit_deny"] is False
        and authorization["authorization_requires_condition_evaluation"] is False
        and authorization["conditional_evaluation_required"] is False
        and _authorization_bases_match(path)
    )


def _authorization_bases_match(
    path: AwsEcsKmsOperationPath,
) -> bool:
    mapped_bases = [
        _AUTHORIZATION_BASIS_NAMES.get(basis) for basis in path["authorization_record"]["authorization_bases"]
    ]
    return bool(
        all(basis is not None for basis in mapped_bases) and set(path["authorization_bases"]) == set(mapped_bases)
    )


def _decrypt_constraint_requires_compatibility(
    path: AwsEcsKmsOperationPath,
) -> bool:
    if any(basis in {"key_policy_direct", "iam_via_key_policy"} for basis in path["authorization_bases"]):
        return False
    return path["constraint_state"] not in {
        "not_applicable",
        "unconstrained",
    }


def _dependency_matches_decrypt_path(
    dependency: AwsKmsEncryptionDependency,
    path: AwsEcsKmsOperationPath,
    key: NormalizedResource,
) -> bool:
    key_arn = aws_facts(key).kms_key_arn or key.arn
    return bool(
        dependency["key_address"] == key.address
        and dependency["key_arn"] == key_arn
        and path["key_address"] == key.address
        and path["key_arn"] == key_arn
    )


def _convergence_record(
    service: NormalizedResource,
    access_path: AwsEcsS3AccessPath,
    operation_path: AwsEcsKmsOperationPath,
    dependency: AwsKmsEncryptionDependency,
) -> AwsEcsS3ProtectedDataConvergence:
    task_definition_address = access_path.get("task_definition_address")
    role_arn = access_path["role_arn"]
    key_arn = dependency["key_arn"]
    assert isinstance(task_definition_address, str)
    assert isinstance(role_arn, str)
    assert isinstance(key_arn, str)
    return {
        "workload_address": service.address,
        "workload_type": service.resource_type,
        "task_definition_address": task_definition_address,
        "role_address": access_path["role_address"],
        "role_arn": role_arn,
        "bucket_address": access_path["bucket_address"],
        "bucket_arn": access_path["bucket_arn"],
        "key_address": operation_path["key_address"],
        "key_arn": key_arn,
        "operation": "kms:Decrypt",
        "access_class": "read",
        "runtime_identity_match": True,
        "protected_resource_match": True,
        "key_identity_match": True,
        "convergence_state": "resolved",
        "evaluation_basis": ("exact_s3_access_kms_dependency_and_decrypt_authority"),
        "access_path": access_path.copy(),
        "key_operation_path": operation_path.copy(),
        "encryption_dependency": dependency.copy(),
        "posture_uncertainties": dedupe(
            [
                *dependency["posture_uncertainties"],
                *operation_path["key_policy_uncertainties"],
                *operation_path["identity_policy_uncertainties"],
            ]
        ),
    }


def _s3_dependency_path(path: list[str | int]) -> bool:
    return bool(
        len(path) == 5
        and path[0] == "rule"
        and isinstance(path[1], int)
        and path[2] == "apply_server_side_encryption_by_default"
        and isinstance(path[3], int)
        and path[4] == "kms_master_key_id"
    )


def _is_exact_kms_key_arn(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("arn:"):
        return False
    parts = value.split(":", 5)
    return bool(
        len(parts) == 6
        and parts[0] == "arn"
        and parts[2] == "kms"
        and parts[3]
        and parts[4].isdigit()
        and len(parts[4]) == 12
        and parts[5].startswith("key/")
        and len(parts[5]) > len("key/")
        and "*" not in value
        and "?" not in value
    )


def _dedupe_convergences(
    values: list[AwsEcsS3ProtectedDataConvergence],
) -> list[AwsEcsS3ProtectedDataConvergence]:
    unique: dict[
        tuple[str, str, str, str, str, str],
        AwsEcsS3ProtectedDataConvergence,
    ] = {}
    for value in values:
        dependency = value["encryption_dependency"]
        fingerprint = (
            value["workload_address"],
            value["task_definition_address"],
            value["role_address"],
            value["bucket_address"],
            value["key_address"],
            (f"{dependency['dependency_source_address']}:{dependency['configuration_path']!r}"),
        )
        unique.setdefault(fingerprint, value)
    return [unique[key] for key in sorted(unique)]
