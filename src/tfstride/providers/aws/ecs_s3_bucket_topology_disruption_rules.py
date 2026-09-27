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
from tfstride.providers.aws.object_storage_topology_destruction_evidence import (
    AwsEcsS3BucketTopologyDestructionPath,
)
from tfstride.providers.aws.resource_decoration.ecs_s3_bucket_topology_destruction_paths import (
    current_s3_bucket_topology_destruction_path,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import (
    AwsDecorationContext,
    AwsResourceIndexBuilder,
)

_AWS_ECS_SERVICE = "aws_ecs_service"
_AWS_ECS_TASK_DEFINITION = "aws_ecs_task_definition"
_AWS_IAM_ROLE = "aws_iam_role"
_AWS_S3_BUCKET = "aws_s3_bucket"
_DELETE_BUCKET = "s3:DeleteBucket"
_AUTHORIZATION_RELATIONSHIP_FIELDS = (
    "workload_address",
    "workload_type",
    "task_definition_address",
    "role_kind",
    "credential_context",
    "role_address",
    "role_arn",
    "same_account",
    "bucket_address",
    "bucket_arn",
    "operation",
    "operation_class",
    "internal_operation",
    "management_effect",
    "target_granularity",
    "target_scope",
    "authorization_bases",
)


class AwsEcsS3BucketTopologyDisruptionRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_service_topology_disruption(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        decoration_context = AwsDecorationContext(
            AwsResourceIndexBuilder().build(list(context.inventory.resources)),
        )
        findings: list[Finding] = []
        for service in context.inventory.by_type(_AWS_ECS_SERVICE):
            service_facts = aws_facts(service)
            paths: list[AwsEcsS3BucketTopologyDestructionPath] = []
            for cached_path in service_facts.ecs_s3_bucket_topology_destruction_paths:
                current_path = _current_deterministic_path(
                    cached_path,
                    service,
                    context,
                    decoration_context,
                )
                if current_path is not None:
                    paths.append(current_path)
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
                    rationale=_rationale(service, len(bucket_addresses)),
                    evidence=collect_evidence(
                        evidence_item("network_path", ingress.network_path),
                        *ingress.evidence,
                        evidence_item(
                            "task_definitions",
                            [f"address={address}" for address in task_definition_addresses],
                        ),
                        evidence_item("task_roles", _task_role_evidence(paths)),
                        evidence_item(
                            "s3_bucket_topology_destruction_paths",
                            _topology_path_evidence(paths),
                        ),
                        evidence_item(
                            "bucket_deletion_recovery_evidence",
                            _recovery_evidence(paths),
                        ),
                        evidence_item(
                            "s3_bucket_topology_destruction_path_uncertainties",
                            _current_path_uncertainties(paths),
                        ),
                        evidence_item("assessment_scope", _assessment_scope()),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _current_deterministic_path(
    cached_path: AwsEcsS3BucketTopologyDestructionPath,
    service: NormalizedResource,
    context: RuleEvaluationContext,
    decoration_context: AwsDecorationContext,
) -> AwsEcsS3BucketTopologyDestructionPath | None:
    task_definition = _resource_for_path(
        cached_path,
        "task_definition_address",
        _AWS_ECS_TASK_DEFINITION,
        context,
    )
    role = _resource_for_path(cached_path, "role_address", _AWS_IAM_ROLE, context)
    bucket = _resource_for_path(cached_path, "bucket_address", _AWS_S3_BUCKET, context)
    if task_definition is None or role is None or bucket is None:
        return None

    role_arn = role.arn
    bucket_arn = bucket.arn
    if not isinstance(role_arn, str) or not isinstance(bucket_arn, str):
        return None

    service_facts = aws_facts(service)
    if (
        task_definition.address not in service_facts.resolved_task_definition_addresses
        or cached_path.get("workload_address") != service.address
        or cached_path.get("workload_type") != service.resource_type
        or cached_path.get("task_definition_address") != task_definition.address
        or cached_path.get("role_kind") != "ecs_task_role"
        or cached_path.get("credential_context") != "workload_runtime"
        or cached_path.get("role_address") != role.address
        or cached_path.get("role_arn") != role_arn
        or cached_path.get("same_account") is not True
        or cached_path.get("bucket_address") != bucket.address
        or cached_path.get("bucket_arn") != bucket_arn
        or not _is_exact_iam_role_arn(role_arn)
        or not _is_exact_bucket_arn(bucket_arn)
        or cached_path.get("operation") != _DELETE_BUCKET
        or cached_path.get("operation_class") != "bucket_deletion"
        or cached_path.get("internal_operation") != "delete_bucket"
        or cached_path.get("management_effect") != "disruption"
        or cached_path.get("target_granularity") != "bucket_topology"
        or cached_path.get("target_scope") != "exact_s3_bucket"
        or cached_path.get("authorization_state") != "allowed"
        or cached_path.get("evaluation_basis") != "modeled_identity_and_bucket_policies"
        or cached_path.get("matched_actions") != [_DELETE_BUCKET]
        or cached_path.get("identity_policy_complete") is not True
        or cached_path.get("bucket_policy_complete") is not True
        or cached_path.get("explicit_deny") is not False
        or cached_path.get("conditional_evaluation_required") is not False
        or cached_path.get("lifecycle_compatibility_state") != "bucket_emptiness_not_established"
    ):
        return None

    current_task_path = current_s3_bucket_topology_destruction_path(
        task_definition,
        bucket,
        decoration_context,
    )
    if current_task_path is None:
        return None

    current_path = current_task_path.copy()
    current_path["workload_address"] = service.address
    current_path["workload_type"] = service.resource_type
    current_path["task_definition_address"] = task_definition.address
    current_path["task_definition_arn"] = task_definition.arn
    current_path["internet_facing_load_balancers"] = service_facts.internet_facing_load_balancer_addresses
    if not _authorization_relationship_matches(cached_path, current_path) or not _authorization_proof_identity_matches(
        cached_path, current_path
    ):
        return None
    return current_path


def _resource_for_path(
    path: Mapping[str, object],
    key: str,
    expected_type: str,
    context: RuleEvaluationContext,
) -> NormalizedResource | None:
    address = path.get(key)
    resource = context.inventory.get_by_address(address) if isinstance(address, str) else None
    if resource is None or resource.provider != "aws" or resource.resource_type != expected_type:
        return None
    return resource


def _authorization_relationship_matches(
    cached_path: Mapping[str, object],
    current_path: Mapping[str, object],
) -> bool:
    return all(cached_path.get(field) == current_path.get(field) for field in _AUTHORIZATION_RELATIONSHIP_FIELDS)


def _authorization_proof_identity_matches(
    cached_path: Mapping[str, object],
    current_path: Mapping[str, object],
) -> bool:
    cached_sources = _authorization_proof_sources(cached_path)
    current_sources = _authorization_proof_sources(current_path)
    return cached_sources is not None and cached_sources == current_sources


def _authorization_proof_sources(
    path: Mapping[str, object],
) -> frozenset[tuple[str, str]] | None:
    raw_statements = path.get("authorization_statements")
    if not isinstance(raw_statements, list) or not raw_statements:
        return None

    sources: set[tuple[str, str]] = set()
    for raw_statement in cast(list[object], raw_statements):
        if not isinstance(raw_statement, Mapping):
            return None
        statement = cast(Mapping[str, object], raw_statement)
        source_address = statement.get("source_address")
        source_kind = statement.get("source_kind")
        if not isinstance(source_address, str) or source_kind not in {
            "identity_policy",
            "bucket_policy",
        }:
            return None
        assert isinstance(source_kind, str)
        sources.add((source_address, source_kind))
    return frozenset(sources)


def _current_path_uncertainties(
    paths: Sequence[Mapping[str, object]],
) -> list[str]:
    return sorted({uncertainty for path in paths for uncertainty in _string_values(path.get("posture_uncertainties"))})


def _is_exact_iam_role_arn(value: str) -> bool:
    parts = value.split(":", 5)
    return bool(
        len(parts) == 6
        and parts[0] == "arn"
        and parts[1]
        and parts[2] == "iam"
        and not parts[3]
        and parts[4]
        and parts[5].startswith("role/")
        and len(parts[5]) > len("role/")
        and "*" not in value
        and "?" not in value
    )


def _is_exact_bucket_arn(value: str) -> bool:
    parts = value.split(":", 5)
    return bool(
        len(parts) == 6
        and parts[0] == "arn"
        and parts[1]
        and parts[2] == "s3"
        and not parts[3]
        and not parts[4]
        and parts[5]
        and "/" not in parts[5]
        and "*" not in value
        and "?" not in value
    )


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


def _topology_path_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"bucket_address={path.get('bucket_address')}",
                    f"bucket_name={path.get('bucket_name')}",
                    f"bucket_arn={path.get('bucket_arn')}",
                    f"operation={path.get('operation')}",
                    f"operation_class={path.get('operation_class')}",
                    f"target_granularity={path.get('target_granularity')}",
                    f"target_scope={path.get('target_scope')}",
                    f"task_definition={path.get('task_definition_address')}",
                    f"task_role={path.get('role_address')}",
                    f"authorization_bases={','.join(_string_values(path.get('authorization_bases'))) or 'none'}",
                    f"authorization_sources={','.join(_string_values(path.get('authorization_source_addresses'))) or 'none'}",
                    "same_account=true",
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
        evidence = path.get("recovery_evidence")
        if not isinstance(evidence, Mapping):
            continue
        evidence_map = cast(Mapping[str, object], evidence)
        values.add(
            "; ".join(
                (
                    f"bucket_address={path.get('bucket_address')}",
                    f"operation={path.get('operation')}",
                    f"bucket_emptiness_required={_display(evidence_map.get('bucket_emptiness_required'))}",
                    f"bucket_emptiness_state={_display(evidence_map.get('bucket_emptiness_state'))}",
                    f"versioning_status={_display(evidence_map.get('versioning_status'))}",
                    f"object_lock_enabled={_display(evidence_map.get('object_lock_enabled'))}",
                    f"attached_access_point_state={_display(evidence_map.get('attached_access_point_state'))}",
                    f"out_of_plan_object_inventory_evaluated={_display(evidence_map.get('out_of_plan_object_inventory_evaluated'))}",
                    f"bucket_recovery_state={_display(evidence_map.get('bucket_recovery_state'))}",
                    f"successful_deletion_observed={_display(evidence_map.get('successful_deletion_observed'))}",
                    f"recovery_observed={_display(evidence_map.get('recovery_observed'))}",
                )
            )
        )
    return sorted(values)


def _assessment_scope() -> list[str]:
    return [
        (
            "establishes=deterministic s3:DeleteBucket authority for an ECS task role over exact modeled "
            "S3 bucket topology with Denial of Service effect"
        ),
        (
            "does_not_establish=bucket emptiness, successful deletion, access-point compatibility, recovery, "
            "descendant impact, or authority over out-of-plan objects"
        ),
    ]


def _rationale(service: NormalizedResource, bucket_count: int) -> str:
    bucket_text = "bucket" if bucket_count == 1 else "buckets"
    return (
        f"{service.display_name} is reachable through an internet-facing load balancer and its ECS task role "
        f"has deterministic S3 bucket-topology deletion authority (s3:DeleteBucket) across {bucket_count} exact "
        f"modeled S3 {bucket_text}. A compromise of the public workload could request deletion of those bucket "
        "topologies, subject to provider-side bucket deletion prerequisites. This plan-local evidence does not "
        "establish bucket emptiness, successful deletion, access-point compatibility, recovery, or out-of-plan objects."
    )


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in cast(list[object], value) if isinstance(item, str)]


def _display(value: object) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)
