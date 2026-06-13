from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.aws.resource_decoration.policies import clone_policy_statements
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.aws.resource_mutations import aws_mutations


class MergeRolePolicyResourcesStage:
    name = "merge_role_policy_resources"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        # Inline role-policy resources extend a role's effective permissions in the same way as
        # inline policies declared directly on the role block.
        for role_policy_resource in resources:
            if role_policy_resource.resource_type != "aws_iam_role_policy":
                continue
            role_reference = aws_facts(role_policy_resource).role_reference
            role = context.index.role_index.get(role_reference)
            if role is None:
                continue
            aws_mutations(role).merge_policy_statements(
                clone_policy_statements(role_policy_resource.policy_statements)
            )
            aws_facts(role).add_inline_policy_resource_address(role_policy_resource.address)
            aws_facts(role).add_inline_policy_name(aws_facts(role_policy_resource).policy_name)

        # Role-policy attachments change the workload's effective privileges, so merge any
        # in-plan customer-managed policy statements onto the target role.
        for attachment_resource in resources:
            if attachment_resource.resource_type != "aws_iam_role_policy_attachment":
                continue
            role_reference = aws_facts(attachment_resource).role_reference
            policy_arn = aws_facts(attachment_resource).policy_arn
            role = context.index.role_index.get(role_reference)
            policy = context.index.policy_index.get(policy_arn)
            if role is None:
                continue
            if policy is None:
                aws_facts(role).add_unresolved_attached_policy_arn(str(policy_arn))
                continue
            aws_mutations(role).merge_policy_statements(
                clone_policy_statements(policy.policy_statements)
            )
            aws_facts(role).add_attached_policy_arn(
                policy.arn or policy.identifier or policy.address
            )
            aws_facts(role).add_attached_policy_address(policy.address)


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
                role = context.index.role_index.get(role_ref)
                if role is None:
                    unresolved_role_refs.append(role_ref)
                    continue
                resolved_role_ref = role.arn or role.identifier or role.address
                if resolved_role_ref:
                    resolved_role_refs.append(resolved_role_ref)
                resolved_role_addresses.append(role.address)
            aws_facts(instance_profile_resource).add_unresolved_role_references(
                unresolved_role_refs
            )
            aws_facts(instance_profile_resource).add_resolved_role_addresses(
                resolved_role_addresses
            )
            aws_facts(instance_profile_resource).set_resolved_role_references(
                resolved_role_refs
            )

        for workload_resource in resources:
            if workload_resource.resource_type != "aws_instance":
                continue
            instance_profile_ref = aws_facts(workload_resource).iam_instance_profile
            if not instance_profile_ref:
                continue
            instance_profile = context.index.instance_profile_index.get(instance_profile_ref)
            if instance_profile is None:
                aws_facts(workload_resource).add_unresolved_instance_profile(
                    str(instance_profile_ref)
                )
                continue
            aws_facts(workload_resource).add_resolved_instance_profile_address(
                instance_profile.address
            )
            for resolved_role_ref in aws_facts(instance_profile).resolved_role_references:
                aws_mutations(workload_resource).attach_role_arn(resolved_role_ref)