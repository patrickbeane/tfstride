from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import cast

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.aws.ecs_path_rule_helpers import (
    internet_boundary_id,
    path_string_values,
    verified_public_service_ingress,
)
from tfstride.providers.aws.object_storage_deletion_evidence import AwsEcsS3ObjectDeletionPath
from tfstride.providers.aws.resource_facts import AwsResourceFacts, aws_facts

_AWS_ECS_SERVICE = "aws_ecs_service"
_AWS_ECS_TASK_DEFINITION = "aws_ecs_task_definition"
_AWS_IAM_ROLE = "aws_iam_role"
_AWS_S3_BUCKET = "aws_s3_bucket"
_AWS_OPERATION_ORDER = ("s3:DeleteObject", "s3:DeleteObjectVersion")
_EXCLUDED_PROJECTION_FIELDS = frozenset(
    {
        "workload_address",
        "workload_type",
        "internet_facing_load_balancers",
    }
)


class AwsEcsS3ObjectDisruptionRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_service_disruption(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for service in context.inventory.by_type(_AWS_ECS_SERVICE):
            paths = [
                path
                for path in aws_facts(service).ecs_s3_object_deletion_paths
                if _is_current_deterministic_path(path, service, context)
            ]
            if not paths:
                continue

            ingress = verified_public_service_ingress(service, context)
            paths = ingress.current_workload_paths(paths)
            load_balancer_addresses = ingress.load_balancer_addresses
            if not load_balancer_addresses or not paths:
                continue

            task_definition_addresses = path_string_values(paths, "task_definition_address")
            role_addresses = path_string_values(paths, "role_address")
            bucket_addresses = path_string_values(paths, "bucket_address")
            operations = _operations(paths)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=2 if len(bucket_addresses) > 1 else 1,
            )
            affected_resources = [
                *ingress.resource_addresses,
                service.address,
                *task_definition_addresses,
                *role_addresses,
                *bucket_addresses,
            ]
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=list(dict.fromkeys(affected_resources)),
                    trust_boundary_id=internet_boundary_id(load_balancer_addresses, context),
                    rationale=_rationale(service, operations, len(bucket_addresses)),
                    evidence=collect_evidence(
                        evidence_item("network_path", ingress.network_path),
                        *ingress.evidence,
                        evidence_item(
                            "task_definitions",
                            [f"address={address}" for address in task_definition_addresses],
                        ),
                        evidence_item("task_roles", _task_role_evidence(paths)),
                        evidence_item("s3_object_deletion_paths", _deletion_path_evidence(paths)),
                        evidence_item("recovery_evidence", _recovery_evidence(paths)),
                        evidence_item("assessment_scope", _assessment_scope(operations)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _is_current_deterministic_path(
    path: AwsEcsS3ObjectDeletionPath,
    service: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    operation = path.get("operation")
    if operation not in _AWS_OPERATION_ORDER:
        return False

    task_definition_address = path.get("task_definition_address")
    role_address = path.get("role_address")
    bucket_address = path.get("bucket_address")
    task_definition = (
        context.inventory.get_by_address(task_definition_address) if isinstance(task_definition_address, str) else None
    )
    role = context.inventory.get_by_address(role_address) if isinstance(role_address, str) else None
    bucket = context.inventory.get_by_address(bucket_address) if isinstance(bucket_address, str) else None
    if (
        task_definition is None
        or role is None
        or bucket is None
        or task_definition.resource_type != _AWS_ECS_TASK_DEFINITION
        or role.resource_type != _AWS_IAM_ROLE
        or bucket.resource_type != _AWS_S3_BUCKET
    ):
        return False

    service_facts = aws_facts(service)
    task_facts = aws_facts(task_definition)
    bucket_facts = aws_facts(bucket)
    role_arn = role.arn
    bucket_arn = bucket.arn
    if not isinstance(role_arn, str) or not isinstance(bucket_arn, str):
        return False
    if (
        task_definition.address not in service_facts.resolved_task_definition_addresses
        or task_facts.task_role_arn != role_arn
        or path.get("workload_address") != service.address
        or path.get("workload_type") != service.resource_type
        or path.get("task_definition_address") != task_definition.address
        or path.get("role_address") != role.address
        or path.get("role_arn") != role_arn
        or path.get("bucket_address") != bucket.address
        or path.get("bucket_arn") != bucket_arn
        or not _is_exact_arn(role_arn, "iam")
        or not _is_exact_arn(bucket_arn, "s3")
        or path.get("role_kind") != "ecs_task_role"
        or path.get("credential_context") != "workload_runtime"
        or path.get("authorization_state") != "allowed"
        or path.get("identity_policy_complete") is not True
        or path.get("bucket_policy_complete") is not True
        or path.get("explicit_deny") is not False
        or path.get("conditional_evaluation_required") is not False
        or path.get("management_effect") != "disruption"
        or not _target_scope_is_coherent(path, bucket_arn)
        or not _recovery_evidence_is_current(path, bucket_facts)
        or not _matches_current_task_path(path, task_facts.ecs_s3_object_deletion_paths)
    ):
        return False

    return True


def _matches_current_task_path(
    projected_path: Mapping[str, object],
    current_paths: Sequence[Mapping[str, object]],
) -> bool:
    projected_keys = set(projected_path) - _EXCLUDED_PROJECTION_FIELDS
    for current_path in current_paths:
        current_keys = set(current_path) - _EXCLUDED_PROJECTION_FIELDS
        if projected_keys != current_keys:
            continue
        if all(projected_path[key] == current_path[key] for key in projected_keys):
            return True
    return False


def _target_scope_is_coherent(path: Mapping[str, object], bucket_arn: str) -> bool:
    operation = path.get("operation")
    granularity = path.get("target_granularity")
    object_key = path.get("object_key")
    object_version = path.get("object_version")
    if not isinstance(granularity, str):
        return False

    if operation == "s3:DeleteObject":
        if path.get("operation_class") != "logical_object_deletion" or object_version is not None:
            return False
        if granularity == "object" and isinstance(object_key, str) and object_key:
            expected_scope = f"{bucket_arn}/{object_key}"
        elif granularity == "object_prefix" and isinstance(object_key, str) and object_key:
            expected_scope = f"{bucket_arn}/{object_key}*"
        elif granularity == "bucket_object_namespace" and object_key is None:
            expected_scope = f"{bucket_arn}/*"
        else:
            return False
    elif operation == "s3:DeleteObjectVersion":
        if path.get("operation_class") != "object_version_deletion":
            return False
        if granularity in {"object_version", "object_version_namespace"} and isinstance(object_key, str) and object_key:
            if granularity == "object_version" and not isinstance(object_version, str):
                return False
            if granularity == "object_version_namespace" and object_version is not None:
                return False
            expected_scope = f"{bucket_arn}/{object_key}"
        elif granularity == "object_prefix_version_namespace" and isinstance(object_key, str) and object_key:
            if object_version is not None:
                return False
            expected_scope = f"{bucket_arn}/{object_key}*"
        elif granularity == "bucket_object_version_namespace" and object_key is None and object_version is None:
            expected_scope = f"{bucket_arn}/*"
        else:
            return False
    else:
        return False

    return path.get("target_scope") == expected_scope and path.get("matched_actions") == [operation]


def _recovery_evidence_is_current(path: Mapping[str, object], bucket_facts: AwsResourceFacts) -> bool:
    evidence = path.get("recovery_evidence")
    if not isinstance(evidence, Mapping):
        return False
    evidence = cast(Mapping[str, object], evidence)
    if (
        evidence.get("recovery_evidence_scope") != "s3_versioning_and_object_lock"
        or evidence.get("versioning_status") != bucket_facts.s3_versioning_status
        or evidence.get("versioning_enabled") != bucket_facts.s3_versioning_enabled
        or evidence.get("object_lock_enabled") != bucket_facts.s3_object_lock_enabled
        or evidence.get("object_lock_default_retention_mode") != bucket_facts.s3_object_lock_default_retention_mode
        or evidence.get("object_lock_default_retention_days") != bucket_facts.s3_object_lock_default_retention_days
        or evidence.get("object_lock_default_retention_years") != bucket_facts.s3_object_lock_default_retention_years
    ):
        return False

    operation = path.get("operation")
    lifecycle_state = path.get("lifecycle_compatibility_state")
    if operation == "s3:DeleteObject":
        status = (
            bucket_facts.s3_versioning_status.casefold() if isinstance(bucket_facts.s3_versioning_status, str) else None
        )
        expected_state = (
            "recoverable_delete_marker" if status == "enabled" else "compatible" if status == "disabled" else "unknown"
        )
    elif operation == "s3:DeleteObjectVersion":
        expected_state = "compatible" if bucket_facts.s3_object_lock_enabled is False else "unknown"
    else:
        return False
    return lifecycle_state == expected_state


def _is_exact_arn(value: str, service: str) -> bool:
    parts = value.split(":", 5)
    return bool(
        len(parts) == 6
        and parts[0] == "arn"
        and parts[1]
        and parts[2] == service
        and parts[5]
        and (service == "s3" or parts[4])
        and "*" not in value
        and "?" not in value
    )


def _operations(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return [
        operation for operation in _AWS_OPERATION_ORDER if any(path.get("operation") == operation for path in paths)
    ]


def _task_role_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"address={path.get('role_address')}",
                    f"arn={path.get('role_arn')}",
                    "role_kind=ecs_task_role",
                    "credential_context=workload_runtime",
                    "authorization_state=allowed",
                )
            )
            for path in paths
        }
    )


def _deletion_path_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"bucket_address={path.get('bucket_address')}",
                    f"bucket_arn={path.get('bucket_arn')}",
                    f"operation={path.get('operation')}",
                    f"operation_class={path.get('operation_class')}",
                    f"target_granularity={path.get('target_granularity')}",
                    f"target_scope={path.get('target_scope')}",
                    f"task_definition={path.get('task_definition_address')}",
                    f"task_role={path.get('role_address')}",
                    f"authorization_bases={','.join(_string_values(path.get('authorization_bases'))) or 'none'}",
                    f"authorization_sources={','.join(_string_values(path.get('authorization_source_addresses'))) or 'none'}",
                    "authorization_state=allowed",
                    "operation_evaluation=deterministic_allowed",
                )
            )
            for path in paths
        }
    )


def _recovery_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        operation = path.get("operation")
        evidence = path.get("recovery_evidence")
        if not isinstance(evidence, Mapping):
            continue
        evidence = cast(Mapping[str, object], evidence)
        if operation == "s3:DeleteObject":
            status = evidence.get("versioning_status")
            recovery_state = (
                "versioned_delete_marker"
                if status == "Enabled"
                else "unversioned_current_object_deletion"
                if status == "disabled"
                else "current_object_recovery_unknown"
            )
            values.add(
                "; ".join(
                    (
                        f"bucket_address={path.get('bucket_address')}",
                        f"operation={operation}",
                        f"target_scope={path.get('target_scope')}",
                        f"recovery_state={recovery_state}",
                        "permanent_deletion_not_established=true",
                    )
                )
            )
            continue

        lock_state = evidence.get("object_lock_enabled")
        bypass = evidence.get("bypass_governance_retention_authorized")
        compatibility = (
            "object_lock_target_compatibility=compatible"
            if lock_state is False
            else "object_lock_target_compatibility=unknown"
        )
        values.add(
            "; ".join(
                (
                    f"bucket_address={path.get('bucket_address')}",
                    f"operation={operation}",
                    f"target_scope={path.get('target_scope')}",
                    compatibility,
                    f"governance_bypass_authorized={str(bypass).lower() if bypass is not None else 'unknown'}",
                    "target_retention_or_legal_hold_is_not_established=true",
                    "permanent_deletion_not_established=true",
                )
            )
        )
    return sorted(values)


def _assessment_scope(operations: Sequence[str]) -> list[str]:
    return [
        (
            f"establishes=deterministic {_operation_text(operations)} authority "
            "for ECS task roles over exact modeled S3 object scopes with Denial of Service effect"
        ),
        (
            "does_not_establish=successful deletion, irreversible removal, effective target retention state, "
            "legal-hold state, or authority over objects outside the modeled scopes"
        ),
    ]


def _rationale(service: NormalizedResource, operations: Sequence[str], bucket_count: int) -> str:
    bucket_text = "bucket" if bucket_count == 1 else "buckets"
    return (
        f"{service.display_name} is reachable through an internet-facing load balancer and its ECS task role "
        f"has deterministic S3 object-deletion authority ({_operation_text(operations)}) across {bucket_count} "
        f"exact modeled S3 {bucket_text}. A compromise of the public workload could remove current-object "
        "state or targeted object versions and disrupt stored-data availability. Versioning, Object Lock, retention, "
        "and governance-bypass evidence are preserved as provider-native recovery evidence; this does not establish "
        "successful deletion, irreversible removal, or effective retention of a particular object version."
    )


def _operation_text(operations: Sequence[str]) -> str:
    if len(operations) == 1:
        return operations[0]
    if len(operations) == 2:
        return f"{operations[0]} and {operations[1]}"
    return ", ".join(operations[:-1]) + f", and {operations[-1]}"


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]
