"""Current S3 operation gaps over modeled targets, independent of path caches."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace

from tfstride.analysis.operation_gaps import OperationGap, OperationGapEvidenceKind, OperationGapResults
from tfstride.models import NormalizedResource, ResourceInventory
from tfstride.providers.aws.ecs_s3_rules import is_s3_mutation_action
from tfstride.providers.aws.resource_decoration.ecs_s3_bucket_topology_destruction_paths import (
    collect_s3_bucket_topology_gaps,
)
from tfstride.providers.aws.resource_decoration.ecs_s3_object_deletion_paths import collect_s3_object_deletion_gaps
from tfstride.providers.aws.resource_decoration.kms_encryption_dependencies import current_kms_encryption_dependencies
from tfstride.providers.aws.resource_decoration.kms_operation_authorization import current_kms_operation_authorizations
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext, AwsResourceIndexBuilder
from tfstride.providers.aws.s3_bucket_policies import S3BucketPolicySources, prepare_s3_bucket_policy_sources
from tfstride.providers.aws.s3_gap_evidence import (
    S3_ACCESS,
    S3_BUCKET_TOPOLOGY,
    S3_GAP_FAMILIES,
    S3_MUTATION,
    S3_OBJECT_DELETION,
    S3_PROTECTED_DATA,
    S3GapCollector,
    conclusive_s3_deny,
)
from tfstride.providers.aws.s3_identity_authorization import (
    S3IdentityAuthorization,
    assess_s3_identity_policy,
    evaluate_s3_identity_authorization,
    modeled_s3_actions,
)
from tfstride.providers.aws.s3_object_scopes import is_exact_s3_bucket_arn, s3_resource_for_bucket

_PAYLOAD_READS = frozenset({"s3:GetObject", "s3:GetObjectVersion"})
_SCOPE_REASONS = {
    "conditional_allow": "policy_condition_unresolved",
    "conditional_deny": "policy_condition_unresolved",
    "partial_deny": "residual_scope_unrepresentable",
    "unsupported_resource_scope": "resource_scope_unsupported",
    "unresolved_deny_applicability": "deny_applicability_unresolved",
}


def collect_s3_operation_gaps(inventory: ResourceInventory) -> OperationGapResults:
    """Run S3 reporting families afresh; cached path/uncertainty lists are not inputs."""
    if inventory.provider != "aws":
        return OperationGapResults()
    resources = list(inventory.resources)
    context = AwsDecorationContext(AwsResourceIndexBuilder().build(resources))
    buckets = inventory.by_type("aws_s3_bucket")
    policies = prepare_s3_bucket_policy_sources(resources, context)
    records: list[OperationGap] = []
    for task in inventory.by_type("aws_ecs_task_definition"):
        access = S3GapCollector(task, S3_ACCESS)
        role_reference = aws_facts(task).task_role_arn
        if not role_reference and not aws_facts(task).unresolved_task_role_arns:
            continue  # No configured runtime identity is not an unassessed grant.
        resolution = context.index.role_index.resolve(role_reference, source=task)
        role = context.index.role_index.get(role_reference, source=task)
        if role is None:
            if buckets:
                access.add(
                    "runtime_identity_ambiguous" if len(resolution.candidates) > 1 else "runtime_identity_unresolved",
                    source=task,
                    field_path=("task_role_arn",),
                    kind=OperationGapEvidenceKind.CONFIGURATION_REFERENCE,
                )
                records.extend(_unknown_operation_families(access.records))
            continue
        identity = assess_s3_identity_policy(role)
        if not identity.complete and buckets:
            access.add(
                "identity_policy_document_unavailable"
                if aws_facts(role).unresolved_attached_policy_arns
                else "identity_policy_incomplete",
                source=role,
                kind=OperationGapEvidenceKind.POLICY_DOCUMENT,
            )
        if role.arn is None and buckets:
            access.add("runtime_identity_arn_unresolved", source=role, field_path=("arn",))
        _unbound_grants(role, buckets, context, access)
        for bucket in buckets:
            if not is_exact_s3_bucket_arn(bucket.arn):
                _unresolved_bucket(role, bucket, access)
                continue
            authorization = evaluate_s3_identity_authorization(
                identity,
                bucket,
                policies[bucket.address],
                account_relationship=context.index.account_identities.relationship(role, bucket),
            )
            start = len(access.records)
            if authorization is not None:
                _access_gaps(authorization, role, bucket, policies[bucket.address], context, access)
            if authorization is not None:
                records.extend(_protected_data_gaps(task, role, bucket, authorization, access.records[start:], context))
            if role.arn is not None:
                deletion = S3GapCollector(task, S3_OBJECT_DELETION)
                collect_s3_object_deletion_gaps(
                    role, bucket, context, deletion, policies[bucket.address].unresolved_sources
                )
                records.extend(deletion.records)
                topology = S3GapCollector(task, S3_BUCKET_TOPOLOGY)
                collect_s3_bucket_topology_gaps(
                    task, role, bucket, context, topology, policies[bucket.address].unresolved_sources
                )
                records.extend(topology.records)

        records.extend(access.records)
        records.extend(
            replace(gap, family=S3_MUTATION)
            for gap in access.records
            if gap.operation is None or is_s3_mutation_action(gap.operation)
        )
        # Unknown operation/target relationships are explicit, not expanded into imagined grants.
        for gap in access.records:
            if gap.operation is None:
                records.extend(replace(gap, family=family) for family in (S3_OBJECT_DELETION, S3_BUCKET_TOPOLOGY))
            elif gap.reason_code in {"target_ambiguous", "target_arn_unresolved", "target_not_modeled"}:
                family = (
                    S3_OBJECT_DELETION
                    if gap.operation in {"s3:DeleteObject", "s3:DeleteObjectVersion"}
                    else S3_BUCKET_TOPOLOGY
                    if gap.operation == "s3:DeleteBucket"
                    else None
                )
                if family is not None:
                    records.append(replace(gap, family=family))
    return OperationGapResults(S3_GAP_FAMILIES, tuple(records))


def _unknown_operation_families(gaps: list[OperationGap]) -> list[OperationGap]:
    return [
        replace(gap, family=family)
        for gap in gaps
        for family in (S3_ACCESS, S3_MUTATION, S3_OBJECT_DELETION, S3_BUCKET_TOPOLOGY)
    ]


def _access_gaps(
    authority: S3IdentityAuthorization,
    role: NormalizedResource,
    bucket: NormalizedResource,
    policies: S3BucketPolicySources,
    context: AwsDecorationContext,
    gaps: S3GapCollector,
) -> None:
    for evaluation in authority.assessment["scope_evaluations"]:
        if evaluation["modeled_access_state"] == "denied" or (
            evaluation["reason"] == "cross_account_not_authorized" and authority.bucket_constraints.complete
        ):
            continue
        operation, scope = evaluation["action"], evaluation["resource"]
        if conclusive_s3_deny(
            role,
            operation,
            resource=scope,
            bucket_sources=policies.sources if len(policies.source_addresses) <= 1 else (),
        ):
            continue
        if context.index.buckets.get(bucket.arn) is None:
            gaps.add("target_ambiguous", operation=operation, bucket=bucket, scope=scope, source=bucket)
            continue
        gaps.gates(
            role,
            bucket,
            context,
            operation=operation,
            scope=scope,
            identity_complete=authority.identity_policy.complete,
            bucket_complete=authority.bucket_constraints.complete,
        )
        reason = _SCOPE_REASONS.get(evaluation["reason"])
        if reason:
            relevant_denies = set(evaluation["overlapping_deny_resources"])
            addresses = {role.address}
            addresses.update(
                record["source_address"]
                for record in authority.bucket_constraints.records
                if operation in record["matched_actions"] and relevant_denies.intersection(record["matching_resources"])
            )
            if authority.account_relationship.same_account is False:
                addresses.update(
                    record["source_address"]
                    for record in authority.bucket_constraints.allow_records
                    if operation in record["matched_actions"] and record["conditional"]
                )
            for address in sorted(addresses):
                gaps.add(
                    reason,
                    operation=operation,
                    bucket=bucket,
                    scope=scope,
                    source_address=address,
                    kind=OperationGapEvidenceKind.POLICY_DOCUMENT,
                )
        # A complete cross-account policy without the required grant is not a gap.
        if not authority.bucket_constraints.complete:
            for source in (*policies.sources, *policies.unresolved_sources):
                gaps.add(
                    "bucket_policy_target_unresolved"
                    if source in policies.unresolved_sources
                    else "bucket_policy_sources_conflict"
                    if len(policies.source_addresses) > 1
                    else "bucket_policy_incomplete",
                    operation=operation,
                    bucket=bucket,
                    scope=scope,
                    source=source,
                    kind=OperationGapEvidenceKind.POLICY_DOCUMENT,
                )


def _unresolved_bucket(role: NormalizedResource, bucket: NormalizedResource, gaps: S3GapCollector) -> None:
    for statement in role.policy_statements:
        if statement.effect.lower() != "allow":
            continue
        if not any(
            resource == "*" or resource in {bucket.address, bucket.address + ".arn"} for resource in statement.resources
        ):
            continue
        for operation, _ in modeled_s3_actions(statement.actions):
            if conclusive_s3_deny(role, operation, resource=None):
                continue
            gaps.add("target_arn_unresolved", operation=operation, bucket=bucket, source=bucket, field_path=("arn",))


def _unbound_grants(
    role: NormalizedResource, buckets: Sequence[NormalizedResource], context: AwsDecorationContext, gaps: S3GapCollector
) -> None:
    for statement in role.policy_statements:
        if statement.effect.lower() != "allow":
            continue
        actions = modeled_s3_actions(statement.actions)
        for resource in statement.resources:
            if resource == "*":
                continue
            for operation, _ in actions:
                if conclusive_s3_deny(role, operation, resource=resource):
                    continue
                if any(
                    bucket.arn is not None
                    and is_exact_s3_bucket_arn(bucket.arn)
                    and any(
                        s3_resource_for_bucket(resource, bucket.arn, candidate_kind)
                        for candidate_kind in ("bucket_level", "object_level")
                    )
                    for bucket in buckets
                ):
                    continue
                # Wrong resource kinds are evaluated non-grants, not missing target evidence.
                marker = ":s3:::"
                if resource.startswith("arn:") and marker in resource and not any(c in resource for c in "*?${"):
                    bucket_arn = resource.split("/", 1)[0]
                    if context.index.buckets.get(bucket_arn) is not None:
                        continue
                    reason = "target_not_modeled"
                elif resource.startswith("arn:") and marker in resource and "${" not in resource:
                    # A supported wildcard selector can simply have no modeled match.
                    reason = "target_not_modeled"
                elif resource.startswith(("arn:", "aws_s3_bucket.", "module.", "${")):
                    reason = "resource_scope_unsupported"
                else:
                    continue
                gaps.add(reason, operation=operation, source=role, kind=OperationGapEvidenceKind.POLICY_DOCUMENT)


def _protected_data_gaps(
    task: NormalizedResource,
    role: NormalizedResource,
    bucket: NormalizedResource,
    authority: S3IdentityAuthorization,
    access_gaps: list[OperationGap],
    context: AwsDecorationContext,
) -> list[OperationGap]:
    reads = [
        scope
        for scope in authority.assessment["scope_evaluations"]
        if scope["action"] in _PAYLOAD_READS
        and scope["modeled_access_state"] != "denied"
        and not (scope["reason"] == "cross_account_not_authorized" and authority.bucket_constraints.complete)
    ]
    if not reads:
        return []
    dependencies, uncovered = current_kms_encryption_dependencies(bucket, context)
    if not dependencies and not uncovered:
        return []
    gaps = S3GapCollector(task, S3_PROTECTED_DATA)
    gaps.records.extend(
        replace(gap, family=S3_PROTECTED_DATA, relationship="runtime_identity_to_protected_data")
        for gap in access_gaps
        if gap.operation in _PAYLOAD_READS
    )
    for scope in reads:

        def add(
            reason: str,
            source: NormalizedResource,
            *,
            operation: str = scope["action"],
            resource_scope: str = scope["resource"],
        ) -> None:
            gaps.add(reason, operation=operation, bucket=bucket, scope=resource_scope, source=source)

        if uncovered:
            add("encryption_dependency_unresolved", bucket)
        for dependency in dependencies:
            source = context.index.resources_by_address.get(dependency["dependency_source_address"], bucket)
            if dependency["resolution_state"] != "resolved":
                add(
                    "encryption_dependency_ambiguous"
                    if dependency["resolution_state"] == "ambiguous"
                    else "encryption_dependency_unresolved",
                    source,
                )
                continue
            if dependency["encryption_ownership_state"] == "unknown":
                add("encryption_ownership_unresolved", source)
                continue
            key = context.index.resources_by_address.get(dependency["key_address"] or "")
            if key is None:
                add("encryption_dependency_unresolved", source)
                continue
            usage = aws_facts(key).kms_key_usage
            if usage is None:
                add("kms_key_usage_unresolved", key)
                continue
            if usage != "ENCRYPT_DECRYPT":
                continue
            authorizations, _ = current_kms_operation_authorizations(key, (role,), context)
            for authorization in authorizations:
                if authorization["operation"] != "kms:Decrypt" or authorization["authorization_state"] == "denied":
                    continue
                if authorization["authorization_state"] == "unknown":
                    add("kms_authorization_unresolved", key)
                elif authorization["authorization_state"] == "allowed" and (
                    not set(authorization["authorization_bases"]) & {"direct_key_policy", "iam_via_account_principal"}
                    and authorization["constraint_state"] not in {"not_applicable", "unconstrained"}
                ):
                    add("kms_s3_constraint_compatibility_unresolved", key)
    return gaps.records
