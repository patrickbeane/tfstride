from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, replace

from tfstride.models import NormalizedResource
from tfstride.providers.aws.iam_assignment_posture import (
    build_aws_privileged_access_posture,
    serialize_privileged_access_posture,
)
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.resource_decoration.policies import clone_policy_statements
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.aws.resource_mutations import aws_mutations


class MergeRolePolicyResourcesStage:
    name = "merge_role_policy_resources"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        _merge_role_policy_resources(
            resources, context, {role.address: role for role in context.index.role_index.resources}
        )


def _merge_role_policy_resources(
    resources: list[NormalizedResource],
    context: AwsDecorationContext,
    roles: Mapping[str, NormalizedResource],
) -> None:
    inputs: dict[str, int] = {}

    def remember_inputs(role: NormalizedResource) -> None:
        if role.address in inputs:
            return
        facts = aws_facts(role)
        count = len(role.policy_statements)
        inputs[role.address] = count
        facts.set(
            AwsResourceMetadata.IAM_ROLE_POLICY_INPUTS,
            {
                "inline_statement_count": count,
                "completeness_state": facts.iam_policy_completeness_state,
                "posture_uncertainties": facts.iam_policy_posture_uncertainties,
                "inline_policy_names": facts.inline_policy_names,
            },
        )

    # Inline role-policy resources extend a role's effective permissions in the same way as
    # inline policies declared directly on the role block.
    for role_policy_resource in resources:
        if role_policy_resource.resource_type != "aws_iam_role_policy":
            continue
        role_reference = aws_facts(role_policy_resource).role_reference
        role = context.index.role_index.get(role_reference, source=role_policy_resource) if role_reference else None
        if role is not None:
            role = roles.get(role.address)
        if role is None:
            continue
        remember_inputs(role)
        source_facts = aws_facts(role_policy_resource)
        role_facts = aws_facts(role)
        aws_mutations(role).merge_policy_statements(
            clone_policy_statements(list(role_policy_resource.policy_statements))
        )
        role_facts.add_inline_policy_resource_address(role_policy_resource.address)
        role_facts.add_inline_policy_name(source_facts.policy_name)
        if source_facts.iam_policy_completeness_state != "complete":
            role_facts.mark_iam_policy_incomplete(
                f"{role_policy_resource.address}: inline role policy evidence is incomplete"
            )
            role_facts.extend_iam_policy_posture_uncertainties(source_facts.iam_policy_posture_uncertainties)

    # Role-policy attachments change the workload's effective privileges, so merge any
    # in-plan customer-managed policy statements onto the target role.
    for attachment_resource in resources:
        if attachment_resource.resource_type != "aws_iam_role_policy_attachment":
            continue
        role_reference = aws_facts(attachment_resource).role_reference
        policy_arn = aws_facts(attachment_resource).policy_arn
        role = context.index.role_index.get(role_reference, source=attachment_resource) if role_reference else None
        policy = context.index.policy_index.get(policy_arn, source=attachment_resource) if policy_arn else None
        if role is not None:
            role = roles.get(role.address)
        if role is None:
            continue
        remember_inputs(role)
        role_facts = aws_facts(role)
        if policy is None:
            role_facts.add_unresolved_attached_policy_arn(str(policy_arn))
            role_facts.mark_iam_policy_incomplete(f"attached policy {policy_arn} is not modeled in the plan")
            continue
        policy_facts = aws_facts(policy)
        aws_mutations(role).merge_policy_statements(clone_policy_statements(list(policy.policy_statements)))
        role_facts.add_attached_policy_arn(policy.arn or policy.identifier or policy.address)
        role_facts.add_attached_policy_address(policy.address)
        if policy_facts.iam_policy_completeness_state != "complete":
            role_facts.mark_iam_policy_incomplete(f"{policy.address}: attached policy evidence is incomplete")
            role_facts.extend_iam_policy_posture_uncertainties(policy_facts.iam_policy_posture_uncertainties)

    for address, count in inputs.items():
        role = roles[address]
        facts = aws_facts(role)
        record = facts.get(AwsResourceMetadata.IAM_ROLE_POLICY_INPUTS)
        record["merged_statements"] = [asdict(statement) for statement in role.policy_statements[count:]]
        facts.set(AwsResourceMetadata.IAM_ROLE_POLICY_INPUTS, record)


def current_iam_role_policies(context: AwsDecorationContext) -> dict[str, NormalizedResource]:
    """Rebuild effective policies on detached roles using current policy sources.

    Decoration preserves the inline prefix and merged suffix's provenance.
    A replaced source is rejoined; an inconsistent aggregate stays uncertain.
    Callers must prepare this view again after changing inventory inputs.
    """
    roles: dict[str, NormalizedResource] = {}
    for role in context.index.role_index.resources:
        current = replace(role)
        facts = aws_facts(current)
        inputs = facts.get(AwsResourceMetadata.IAM_ROLE_POLICY_INPUTS)
        if inputs:
            count = inputs.get("inline_statement_count")
            if (
                isinstance(count, int)
                and 0 <= count <= len(role.policy_statements)
                and inputs.get("merged_statements")
                == [asdict(statement) for statement in role.policy_statements[count:]]
            ):
                current.policy_statements = role.policy_statements[:count]
                facts.set(AwsResourceMetadata.IAM_POLICY_COMPLETENESS_STATE, inputs.get("completeness_state"))
                facts.set(AwsResourceMetadata.IAM_POLICY_POSTURE_UNCERTAINTIES, inputs.get("posture_uncertainties", []))
                facts.set(AwsResourceMetadata.INLINE_POLICY_NAMES, inputs.get("inline_policy_names", []))
            else:
                facts.mark_iam_policy_incomplete("inline and merged role-policy provenance is inconsistent")
        elif facts.inline_policy_resource_addresses or facts.attached_policy_addresses:
            facts.mark_iam_policy_incomplete("inline role-policy inputs are unavailable for reevaluation")
        for field in (
            AwsResourceMetadata.INLINE_POLICY_RESOURCE_ADDRESSES,
            AwsResourceMetadata.ATTACHED_POLICY_ARNS,
            AwsResourceMetadata.ATTACHED_POLICY_ADDRESSES,
            AwsResourceMetadata.UNRESOLVED_ATTACHED_POLICY_ARNS,
        ):
            facts.set(field, [])
        roles[role.address] = current
    _merge_role_policy_resources(list(context.index.resources_by_address.values()), context, roles)
    return roles


class NormalizeIamAssignmentPostureStage:
    name = "normalize_iam_assignment_posture"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        for role in resources:
            if role.resource_type != "aws_iam_role":
                continue
            facts = aws_facts(role)
            posture = build_aws_privileged_access_posture(
                role,
                unresolved_assignments=facts.unresolved_attached_policy_arns,
            )
            facts.set_privileged_access_grants(serialize_privileged_access_posture(posture))
            facts.extend_iam_assignment_posture_uncertainties(posture.unresolved_assignments)


class ResolveInstanceProfileRolesStage:
    name = "resolve_instance_profile_roles"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        # Instance profiles are the normal way EC2 inherits role credentials, so resolve them
        # to attached roles before workload-risk and trust-boundary analysis runs.
        for instance_profile_resource in resources:
            if instance_profile_resource.resource_type != "aws_iam_instance_profile":
                continue
            resolved_role_refs: list[str] = []
            resolved_role_addresses: list[str] = []
            unresolved_role_refs: list[str] = []
            for role_ref in aws_facts(instance_profile_resource).role_references:
                role = context.index.role_index.get(role_ref, source=instance_profile_resource)
                if role is None:
                    unresolved_role_refs.append(role_ref)
                    continue
                resolved_role_ref = role.arn or role.identifier or role.address
                if resolved_role_ref:
                    resolved_role_refs.append(resolved_role_ref)
                resolved_role_addresses.append(role.address)
            aws_facts(instance_profile_resource).add_unresolved_role_references(unresolved_role_refs)
            aws_facts(instance_profile_resource).add_resolved_role_addresses(resolved_role_addresses)
            aws_facts(instance_profile_resource).set_resolved_role_references(resolved_role_refs)

        for workload_resource in resources:
            if workload_resource.resource_type != "aws_instance":
                continue
            instance_profile_ref = aws_facts(workload_resource).iam_instance_profile
            if not instance_profile_ref:
                continue
            instance_profile = context.index.instance_profile_index.get(instance_profile_ref, source=workload_resource)
            if instance_profile is None:
                aws_facts(workload_resource).add_unresolved_instance_profile(str(instance_profile_ref))
                continue
            aws_facts(workload_resource).add_resolved_instance_profile_address(instance_profile.address)
            for resolved_role_ref in aws_facts(instance_profile).resolved_role_references:
                aws_mutations(workload_resource).attach_role_arn(resolved_role_ref)
