from __future__ import annotations

from typing import Any, Protocol

from tfstride.models import (
    IAMPolicyCondition,
    IAMPolicyStatement,
    IAMPrincipal,
    NormalizedResource,
    SecurityGroupRule,
)
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.aws.resource_utils import (
    bucket_public_exposure_reasons,
    route_table_has_internet_route,
    route_table_has_nat_gateway_route,
)
from tfstride.resource_helpers import describe_security_group_rule, policy_allows_public_access
from tfstride.resource_metadata import ResourceMetadata


class AwsDecorationStage(Protocol):
    name: str

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        """Apply one ordered AWS resource decoration step."""
        ...


class MergeStandaloneSecurityGroupRulesStage:
    name = "merge_standalone_security_group_rules"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        # Standalone SG rule resources carry the same security meaning as inline rules, so fold
        # them into the parent security group before any exposure analysis runs.
        for rule_resource in resources:
            if rule_resource.resource_type != "aws_security_group_rule":
                continue
            target_group = context.index.security_groups.get(rule_resource.security_group_id)
            if target_group is None:
                continue
            target_group.network_rules.extend(_clone_security_group_rules(rule_resource.network_rules))
            ResourceMetadata.STANDALONE_RULE_ADDRESSES.append_unique(
                target_group.metadata,
                rule_resource.address,
            )


class MergeRolePolicyResourcesStage:
    name = "merge_role_policy_resources"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        # Inline role-policy resources extend a role's effective permissions in the same way as
        # inline policies declared directly on the role block.
        for role_policy_resource in resources:
            if role_policy_resource.resource_type != "aws_iam_role_policy":
                continue
            role = context.index.role_index.get(role_policy_resource.role_reference)
            if role is None:
                continue
            role.policy_statements.extend(_clone_policy_statements(role_policy_resource.policy_statements))
            ResourceMetadata.INLINE_POLICY_RESOURCE_ADDRESSES.append_unique(
                role.metadata,
                role_policy_resource.address,
            )
            ResourceMetadata.INLINE_POLICY_NAMES.append_unique(
                role.metadata,
                role_policy_resource.policy_name,
            )

        # Role-policy attachments change the workload's effective privileges, so merge any
        # in-plan customer-managed policy statements onto the target role.
        for attachment_resource in resources:
            if attachment_resource.resource_type != "aws_iam_role_policy_attachment":
                continue
            role = context.index.role_index.get(attachment_resource.role_reference)
            policy = context.index.policy_index.get(attachment_resource.policy_arn)
            if role is None:
                continue
            if policy is None:
                ResourceMetadata.UNRESOLVED_ATTACHED_POLICY_ARNS.append_unique(
                    role.metadata,
                    str(attachment_resource.policy_arn),
                )
                continue
            role.policy_statements.extend(_clone_policy_statements(policy.policy_statements))
            ResourceMetadata.ATTACHED_POLICY_ARNS.append_unique(
                role.metadata,
                policy.arn or policy.identifier or policy.address,
            )
            ResourceMetadata.ATTACHED_POLICY_ADDRESSES.append_unique(
                role.metadata,
                policy.address,
            )


class ResolveInstanceProfileRolesStage:
    name = "resolve_instance_profile_roles"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        # Instance profiles are the normal way EC2 inherits role credentials, so resolve them
        # to attached roles before workload-risk and trust-boundary analysis runs.
        for instance_profile_resource in resources:
            if instance_profile_resource.resource_type != "aws_iam_instance_profile":
                continue
            resolved_role_refs: list[str] = []
            for role_ref in instance_profile_resource.role_references:
                role = context.index.role_index.get(role_ref)
                if role is None:
                    ResourceMetadata.UNRESOLVED_ROLE_REFERENCES.append_unique(
                        instance_profile_resource.metadata,
                        role_ref,
                    )
                    continue
                resolved_role_ref = role.arn or role.identifier or role.address
                if resolved_role_ref:
                    resolved_role_refs.append(resolved_role_ref)
                ResourceMetadata.RESOLVED_ROLE_ADDRESSES.append_unique(
                    instance_profile_resource.metadata,
                    role.address,
                )
            instance_profile_resource.resolved_role_references = resolved_role_refs

        for workload_resource in resources:
            if workload_resource.resource_type != "aws_instance":
                continue
            instance_profile_ref = workload_resource.iam_instance_profile
            if not instance_profile_ref:
                continue
            instance_profile = context.index.instance_profile_index.get(instance_profile_ref)
            if instance_profile is None:
                ResourceMetadata.UNRESOLVED_INSTANCE_PROFILES.append_unique(
                    workload_resource.metadata,
                    str(instance_profile_ref),
                )
                continue
            ResourceMetadata.RESOLVED_INSTANCE_PROFILE_ADDRESSES.append_unique(
                workload_resource.metadata,
                instance_profile.address,
            )
            for resolved_role_ref in instance_profile.resolved_role_references:
                if resolved_role_ref not in workload_resource.attached_role_arns:
                    workload_resource.attached_role_arns.append(resolved_role_ref)


class ResolveEcsServiceRelationshipsStage:
    name = "resolve_ecs_service_relationships"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        for ecs_service_resource in resources:
            if ecs_service_resource.resource_type != "aws_ecs_service":
                continue
            cluster_ref = ecs_service_resource.cluster_reference
            if cluster_ref:
                cluster = context.index.ecs_clusters.get(cluster_ref)
                if cluster is None:
                    ResourceMetadata.UNRESOLVED_CLUSTER_REFERENCES.append_unique(
                        ecs_service_resource.metadata,
                        str(cluster_ref),
                    )
                else:
                    ResourceMetadata.RESOLVED_CLUSTER_ADDRESSES.append_unique(
                        ecs_service_resource.metadata,
                        cluster.address,
                    )

            task_definition_ref = ecs_service_resource.task_definition_reference
            if not task_definition_ref:
                continue
            task_definition = context.index.ecs_task_definitions.get(task_definition_ref)
            if task_definition is None:
                ResourceMetadata.UNRESOLVED_TASK_DEFINITION_REFERENCES.append_unique(
                    ecs_service_resource.metadata,
                    str(task_definition_ref),
                )
                continue
            ResourceMetadata.RESOLVED_TASK_DEFINITION_ADDRESSES.append_unique(
                ecs_service_resource.metadata,
                task_definition.address,
            )
            ecs_service_resource.network_mode = task_definition.network_mode
            ecs_service_resource.requires_compatibilities = task_definition.requires_compatibilities
            task_role_arn = task_definition.task_role_arn
            execution_role_arn = task_definition.execution_role_arn
            if task_role_arn:
                ecs_service_resource.task_role_arn = task_role_arn
                if task_role_arn not in ecs_service_resource.attached_role_arns:
                    ecs_service_resource.attached_role_arns.append(task_role_arn)
                task_role = context.index.role_index.get(task_role_arn)
                if task_role is not None:
                    ResourceMetadata.RESOLVED_TASK_ROLE_ADDRESSES.append_unique(
                        ecs_service_resource.metadata,
                        task_role.address,
                    )
                else:
                    ResourceMetadata.UNRESOLVED_TASK_ROLE_ARNS.append_unique(
                        ecs_service_resource.metadata,
                        str(task_role_arn),
                    )
            if execution_role_arn:
                ecs_service_resource.execution_role_arn = execution_role_arn
                execution_role = context.index.role_index.get(execution_role_arn)
                if execution_role is not None:
                    ResourceMetadata.RESOLVED_EXECUTION_ROLE_ADDRESSES.append_unique(
                        ecs_service_resource.metadata,
                        execution_role.address,
                    )
                else:
                    ResourceMetadata.UNRESOLVED_EXECUTION_ROLE_ARNS.append_unique(
                        ecs_service_resource.metadata,
                        str(execution_role_arn),
                    )


class MergeResourcePolicyResourcesStage:
    name = "merge_resource_policy_resources"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        # Resource-policy resources should flow into the target resource so later analysis can
        # reason over one consolidated policy surface.
        for bucket_policy_resource in resources:
            if bucket_policy_resource.resource_type != "aws_s3_bucket_policy":
                continue
            bucket = context.index.buckets.get(bucket_policy_resource.bucket_name)
            if bucket is None:
                ResourceMetadata.UNRESOLVED_BUCKET_REFERENCES.append_unique(
                    bucket_policy_resource.metadata,
                    bucket_policy_resource.bucket_name,
                )
                continue
            _merge_resource_policy(
                bucket,
                bucket_policy_resource.policy_statements,
                bucket_policy_resource.policy_document,
                bucket_policy_resource.address,
            )

        for secret_policy_resource in resources:
            if secret_policy_resource.resource_type != "aws_secretsmanager_secret_policy":
                continue
            secret = context.index.secrets.get(secret_policy_resource.secret_arn)
            if secret is None:
                ResourceMetadata.UNRESOLVED_SECRET_ARNS.append_unique(
                    secret_policy_resource.metadata,
                    secret_policy_resource.secret_arn,
                )
                continue
            _merge_resource_policy(
                secret,
                secret_policy_resource.policy_statements,
                secret_policy_resource.policy_document,
                secret_policy_resource.address,
            )

        for lambda_permission_resource in resources:
            if lambda_permission_resource.resource_type != "aws_lambda_permission":
                continue
            function_name = lambda_permission_resource.function_name
            target_function = context.index.lambda_functions.get(function_name)
            if target_function is None:
                ResourceMetadata.UNRESOLVED_FUNCTION_REFERENCES.append_unique(
                    lambda_permission_resource.metadata,
                    function_name,
                )
                continue
            _merge_resource_policy(
                target_function,
                lambda_permission_resource.policy_statements,
                {},
                lambda_permission_resource.address,
            )


class ApplyS3PublicAccessBlocksStage:
    name = "apply_s3_public_access_blocks"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        # Public access blocks can neutralize otherwise-public bucket ACLs or policies, so
        # recompute effective public exposure after the control is applied.
        for access_block_resource in resources:
            if access_block_resource.resource_type != "aws_s3_bucket_public_access_block":
                continue
            bucket = context.index.buckets.get(access_block_resource.bucket_name)
            if bucket is None:
                continue
            public_access_block = {
                "block_public_acls": access_block_resource.block_public_acls,
                "block_public_policy": access_block_resource.block_public_policy,
                "ignore_public_acls": access_block_resource.ignore_public_acls,
                "restrict_public_buckets": access_block_resource.restrict_public_buckets,
            }
            bucket.public_access_block = public_access_block
            public_via_acl = bucket.bucket_acl in {"public-read", "public-read-write", "website"}
            public_via_policy = policy_allows_public_access(bucket.policy_document)
            bucket.public_access_reasons = bucket_public_exposure_reasons(
                bucket.bucket_acl,
                public_policy=public_via_policy,
            )
            bucket.public_exposure = (
                public_via_acl
                and not (public_access_block["block_public_acls"] or public_access_block["ignore_public_acls"])
            ) or (
                public_via_policy
                and not (public_access_block["block_public_policy"] or public_access_block["restrict_public_buckets"])
            )
            bucket.public_exposure_reasons = bucket_public_exposure_reasons(
                bucket.bucket_acl,
                public_policy=public_via_policy,
                public_access_block=public_access_block,
            )


class DeriveSubnetPostureStage:
    name = "derive_subnet_posture"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        subnet_route_table_ids: dict[str, list[str]] = {}
        for association_resource in resources:
            if association_resource.resource_type != "aws_route_table_association":
                continue
            subnet_id = association_resource.subnet_id
            route_table_id = association_resource.route_table_id
            if not subnet_id or not route_table_id:
                continue
            subnet_route_table_ids.setdefault(str(subnet_id), []).append(str(route_table_id))

        public_subnet_ids: set[str] = set()
        for subnet in context.index.subnets.values():
            associated_route_table_ids = subnet_route_table_ids.get(subnet.identifier or "", [])
            has_public_route = any(
                route_table_id in context.index.route_tables
                and route_table_has_internet_route(context.index.route_tables[route_table_id].routes)
                for route_table_id in associated_route_table_ids
            )
            has_nat_route = any(
                route_table_id in context.index.route_tables
                and route_table_has_nat_gateway_route(
                    context.index.route_tables[route_table_id].routes,
                    context.index.nat_gateway_ids,
                )
                for route_table_id in associated_route_table_ids
            )
            if associated_route_table_ids:
                # Prefer explicit associations when Terraform provides them because they are
                # more precise than inferring subnet posture from VPC-wide route presence.
                is_public = has_public_route
            else:
                # Fall back to the original heuristic when route table associations are absent.
                is_public = (
                    subnet.map_public_ip_on_launch
                    and subnet.vpc_id
                    in context.index.vpcs_with_igw.intersection(context.index.vpcs_with_public_routes)
                )
                has_nat_route = False
            subnet.is_public_subnet = is_public
            ResourceMetadata.ROUTE_TABLE_IDS.set(subnet.metadata, associated_route_table_ids)
            subnet.has_public_route = has_public_route
            subnet.has_nat_gateway_egress = has_nat_route
            if is_public and subnet.identifier:
                public_subnet_ids.add(subnet.identifier)
        context.public_subnet_ids = public_subnet_ids


class InferVpcIdsStage:
    name = "infer_vpc_ids"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        for resource in resources:
            if resource.vpc_id:
                continue
            # Some Terraform resources omit a direct VPC reference, so infer it from the
            # attached subnet first and fall back to attached security groups.
            for subnet_id in resource.subnet_ids:
                subnet = context.index.subnets.get(subnet_id)
                if subnet and subnet.vpc_id:
                    resource.vpc_id = subnet.vpc_id
                    break
            if resource.vpc_id:
                continue
            for security_group_id in resource.security_group_ids:
                security_group = context.index.security_groups.get(security_group_id)
                if security_group and security_group.vpc_id:
                    resource.vpc_id = security_group.vpc_id
                    break


class DerivePublicExposureStage:
    name = "derive_public_exposure"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        for resource in resources:
            attached_security_groups = [
                context.index.security_groups[sg_id]
                for sg_id in resource.security_group_ids
                if sg_id in context.index.security_groups
            ]
            internet_ingress = any(
                rule.direction == "ingress" and rule.allows_internet()
                for security_group in attached_security_groups
                for rule in security_group.network_rules
            )
            if ResourceMetadata.PUBLIC_ACCESS_REASONS.key not in resource.metadata:
                resource.public_access_reasons = []
            if ResourceMetadata.PUBLIC_EXPOSURE_REASONS.key not in resource.metadata:
                resource.public_exposure_reasons = []
            ResourceMetadata.PUBLIC_ACCESS_CONFIGURED.set(
                resource.metadata,
                resource.public_access_configured,
            )
            ResourceMetadata.INTERNET_INGRESS.set(resource.metadata, internet_ingress)
            resource.internet_ingress_capable = internet_ingress
            resource.internet_ingress_reasons = _internet_ingress_reasons(attached_security_groups)
            if resource.resource_type != "aws_subnet":
                resource.in_public_subnet = (
                    any(subnet_id in context.public_subnet_ids for subnet_id in resource.subnet_ids)
                    if resource.subnet_ids
                    else resource.in_public_subnet
                )
            resource.has_nat_gateway_egress = (
                any(
                    context.index.subnets[subnet_id].has_nat_gateway_egress
                    for subnet_id in resource.subnet_ids
                    if subnet_id in context.index.subnets
                )
                if resource.subnet_ids
                else resource.has_nat_gateway_egress
            )
            # Public exposure is inferred conservatively from network placement and ingress
            # rules so later detectors can reason over a normalized signal instead of
            # provider-specific fields.
            if resource.resource_type == "aws_instance":
                resource.public_exposure = bool(
                    resource.public_access_configured
                    and resource.in_public_subnet
                    and internet_ingress
                )
                if resource.public_exposure:
                    ResourceMetadata.PUBLIC_EXPOSURE_REASONS.append_unique(
                        resource.metadata,
                        "instance has a public IP path and attached security groups allow internet ingress",
                    )
            elif resource.resource_type == "aws_ecs_service":
                resource.public_exposure = bool(
                    resource.public_access_configured
                    and resource.in_public_subnet
                    and internet_ingress
                )
                if resource.public_exposure:
                    ResourceMetadata.PUBLIC_EXPOSURE_REASONS.append_unique(
                        resource.metadata,
                        (
                            "ECS service assigns public IPs in a public subnet and attached "
                            "security groups allow internet ingress"
                        ),
                    )
            elif resource.resource_type == "aws_db_instance":
                resource.public_exposure = bool(
                    resource.public_access_configured and (internet_ingress or not attached_security_groups)
                )
                if resource.public_exposure and internet_ingress:
                    ResourceMetadata.PUBLIC_EXPOSURE_REASONS.append_unique(
                        resource.metadata,
                        "database is marked publicly_accessible and attached security groups allow internet ingress",
                    )
                elif resource.public_exposure and not attached_security_groups:
                    ResourceMetadata.PUBLIC_EXPOSURE_REASONS.append_unique(
                        resource.metadata,
                        (
                            "database is marked publicly_accessible and no attached security "
                            "groups provide ingress evidence"
                        ),
                    )
            elif resource.resource_type == "aws_lb":
                resource.public_exposure = bool(
                    resource.public_access_configured and (internet_ingress or not attached_security_groups)
                )
                if resource.public_exposure and internet_ingress:
                    ResourceMetadata.PUBLIC_EXPOSURE_REASONS.append_unique(
                        resource.metadata,
                        "load balancer is internet-facing and attached security groups allow internet ingress",
                    )
                elif resource.public_exposure:
                    ResourceMetadata.PUBLIC_EXPOSURE_REASONS.append_unique(
                        resource.metadata,
                        "load balancer is configured as internet-facing",
                    )
            resource.direct_internet_reachable = resource.public_exposure


class MarkEcsLoadBalancerExposureStage:
    name = "mark_ecs_services_fronted_by_internet_facing_load_balancers"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        internet_facing_load_balancers_by_security_group: dict[str, list[NormalizedResource]] = {}
        for resource in resources:
            if resource.resource_type != "aws_lb" or not resource.public_exposure:
                continue
            for security_group_id in resource.security_group_ids:
                internet_facing_load_balancers_by_security_group.setdefault(security_group_id, []).append(resource)

        for resource in resources:
            if resource.resource_type != "aws_ecs_service":
                continue
            fronting_load_balancers: list[str] = []
            attached_security_groups = [
                context.index.security_groups[sg_id]
                for sg_id in resource.security_group_ids
                if sg_id in context.index.security_groups
            ]
            for security_group in attached_security_groups:
                for rule in security_group.network_rules:
                    if rule.direction != "ingress":
                        continue
                    for security_group_id in rule.referenced_security_group_ids:
                        for load_balancer in internet_facing_load_balancers_by_security_group.get(
                            security_group_id,
                            [],
                        ):
                            if load_balancer.address not in fronting_load_balancers:
                                fronting_load_balancers.append(load_balancer.address)
            ResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER.set(
                resource.metadata,
                bool(fronting_load_balancers),
            )
            if fronting_load_balancers:
                ResourceMetadata.INTERNET_FACING_LOAD_BALANCER_ADDRESSES.set(
                    resource.metadata,
                    fronting_load_balancers,
                )


def default_aws_decoration_stages() -> tuple[AwsDecorationStage, ...]:
    return (
        MergeStandaloneSecurityGroupRulesStage(),
        MergeRolePolicyResourcesStage(),
        ResolveInstanceProfileRolesStage(),
        ResolveEcsServiceRelationshipsStage(),
        MergeResourcePolicyResourcesStage(),
        ApplyS3PublicAccessBlocksStage(),
        DeriveSubnetPostureStage(),
        InferVpcIdsStage(),
        DerivePublicExposureStage(),
        MarkEcsLoadBalancerExposureStage(),
    )


def _clone_security_group_rules(rules: list[SecurityGroupRule]) -> list[SecurityGroupRule]:
    return [
        SecurityGroupRule(
            direction=rule.direction,
            protocol=rule.protocol,
            from_port=rule.from_port,
            to_port=rule.to_port,
            cidr_blocks=list(rule.cidr_blocks),
            ipv6_cidr_blocks=list(rule.ipv6_cidr_blocks),
            referenced_security_group_ids=list(rule.referenced_security_group_ids),
            description=rule.description,
        )
        for rule in rules
    ]


def _clone_policy_statements(statements: list[IAMPolicyStatement]) -> list[IAMPolicyStatement]:
    return [
        IAMPolicyStatement(
            effect=statement.effect,
            actions=list(statement.actions),
            resources=list(statement.resources),
            principals=list(statement.principals),
            principal_entries=[
                IAMPrincipal(kind=principal.kind, value=principal.value)
                for principal in statement.principal_entries
            ],
            conditions=[
                IAMPolicyCondition(
                    operator=condition.operator,
                    key=condition.key,
                    values=list(condition.values),
                )
                for condition in statement.conditions
            ],
        )
        for statement in statements
    ]


def _merge_resource_policy(
    resource: NormalizedResource,
    policy_statements: list[IAMPolicyStatement],
    policy_document: dict[str, Any],
    source_address: str,
) -> None:
    resource.policy_statements.extend(_clone_policy_statements(policy_statements))
    resource_policy_source_addresses = resource.resource_policy_source_addresses
    if source_address not in resource_policy_source_addresses:
        resource.resource_policy_source_addresses = [*resource_policy_source_addresses, source_address]
    merged_document = _merge_policy_documents(resource.policy_document, policy_document)
    if merged_document:
        resource.policy_document = merged_document


def _merge_policy_documents(base_document: Any, extra_document: Any) -> dict[str, Any]:
    base = base_document if isinstance(base_document, dict) else {}
    extra = extra_document if isinstance(extra_document, dict) else {}
    base_statements = _as_list(base.get("Statement"))
    extra_statements = _as_list(extra.get("Statement"))
    merged_statements = [
        statement
        for statement in [*base_statements, *extra_statements]
        if isinstance(statement, dict)
    ]
    if not merged_statements:
        return base or extra
    merged_document = dict(base) if base else dict(extra)
    merged_document["Statement"] = merged_statements
    return merged_document


def _internet_ingress_reasons(attached_security_groups: list[NormalizedResource]) -> list[str]:
    reasons: list[str] = []
    for security_group in attached_security_groups:
        for rule in security_group.network_rules:
            if rule.direction != "ingress" or not rule.allows_internet():
                continue
            reasons.append(describe_security_group_rule(security_group, rule))
    return reasons


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]
