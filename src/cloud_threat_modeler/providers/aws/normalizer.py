from __future__ import annotations

import json
from collections import Counter
from typing import Any

from cloud_threat_modeler.models import (
    IAMPolicyCondition,
    IAMPolicyStatement,
    NormalizedResource,
    ResourceCategory,
    ResourceInventory,
    SecurityGroupRule,
    TerraformResource,
)
from cloud_threat_modeler.providers.base import ProviderNormalizer


SUPPORTED_AWS_TYPES = {
    "aws_instance",
    "aws_security_group",
    "aws_security_group_rule",
    "aws_nat_gateway",
    "aws_lb",
    "aws_db_instance",
    "aws_s3_bucket",
    "aws_s3_bucket_policy",
    "aws_s3_bucket_public_access_block",
    "aws_iam_role",
    "aws_iam_policy",
    "aws_iam_role_policy",
    "aws_iam_role_policy_attachment",
    "aws_iam_instance_profile",
    "aws_lambda_function",
    "aws_lambda_permission",
    "aws_kms_key",
    "aws_sns_topic",
    "aws_sqs_queue",
    "aws_secretsmanager_secret",
    "aws_secretsmanager_secret_policy",
    "aws_subnet",
    "aws_vpc",
    "aws_internet_gateway",
    "aws_route_table",
    "aws_route_table_association",
}

SUPPORTED_TRUST_NARROWING_CONDITION_KEYS = {
    "sts:ExternalId",
    "aws:SourceArn",
    "aws:SourceAccount",
}


class AwsNormalizer(ProviderNormalizer):
    provider = "aws"

    def normalize(self, resources: list[TerraformResource]) -> ResourceInventory:
        aws_resources = [
            resource
            for resource in resources
            if resource.provider_name.endswith("/aws") or resource.resource_type.startswith("aws_")
        ]
        unsupported = sorted(
            resource.address for resource in aws_resources if resource.resource_type not in SUPPORTED_AWS_TYPES
        )
        normalized = [
            self._normalize_resource(resource)
            for resource in aws_resources
            if resource.resource_type in SUPPORTED_AWS_TYPES
        ]
        self._decorate_resources(normalized)
        primary_account_id = _infer_primary_account_id(normalized)
        return ResourceInventory(
            provider=self.provider,
            resources=normalized,
            unsupported_resources=unsupported,
            metadata={
                "primary_account_id": primary_account_id,
                "supported_resource_types": sorted(SUPPORTED_AWS_TYPES),
            },
        )

    def _normalize_resource(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
        if resource.resource_type == "aws_vpc":
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.NETWORK,
                identifier=values.get("id"),
                metadata={"cidr_block": values.get("cidr_block"), "tags": values.get("tags", {})},
            )
        if resource.resource_type == "aws_subnet":
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.NETWORK,
                identifier=values.get("id"),
                vpc_id=values.get("vpc_id"),
                metadata={
                    "cidr_block": values.get("cidr_block"),
                    "availability_zone": values.get("availability_zone"),
                    "map_public_ip_on_launch": bool(values.get("map_public_ip_on_launch", False)),
                    "tags": values.get("tags", {}),
                },
            )
        if resource.resource_type == "aws_internet_gateway":
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.NETWORK,
                identifier=values.get("id"),
                vpc_id=values.get("vpc_id"),
            )
        if resource.resource_type == "aws_route_table":
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.NETWORK,
                identifier=values.get("id"),
                vpc_id=values.get("vpc_id"),
                metadata={"routes": _as_list(values.get("route") or values.get("routes"))},
            )
        if resource.resource_type == "aws_route_table_association":
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.NETWORK,
                identifier=values.get("id") or resource.address,
                metadata={
                    "route_table_id": values.get("route_table_id"),
                    "subnet_id": values.get("subnet_id"),
                    "gateway_id": values.get("gateway_id"),
                },
            )
        if resource.resource_type == "aws_security_group":
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.NETWORK,
                identifier=values.get("id"),
                vpc_id=values.get("vpc_id"),
                network_rules=_parse_security_group_rules(values),
                metadata={
                    "description": values.get("description"),
                    "group_name": values.get("name"),
                },
            )
        if resource.resource_type == "aws_security_group_rule":
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.NETWORK,
                identifier=values.get("id") or resource.address,
                network_rules=[_parse_standalone_security_group_rule(values)],
                metadata={"security_group_id": values.get("security_group_id")},
            )
        if resource.resource_type == "aws_nat_gateway":
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.NETWORK,
                identifier=values.get("id"),
                subnet_ids=_compact([values.get("subnet_id")]),
                metadata={
                    "allocation_id": values.get("allocation_id"),
                    "connectivity_type": values.get("connectivity_type", "public"),
                },
            )
        if resource.resource_type == "aws_instance":
            public_ip_requested = bool(values.get("associate_public_ip_address", False))
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.COMPUTE,
                identifier=values.get("id"),
                arn=values.get("arn"),
                subnet_ids=_compact([values.get("subnet_id")]),
                security_group_ids=_as_list(values.get("vpc_security_group_ids")),
                public_access_configured=public_ip_requested,
                metadata={
                    "ami": values.get("ami"),
                    "instance_type": values.get("instance_type"),
                    "associate_public_ip_address": public_ip_requested,
                    "iam_instance_profile": values.get("iam_instance_profile"),
                    "public_access_reasons": (
                        ["instance requests an associated public IP address"]
                        if public_ip_requested
                        else []
                    ),
                    "public_exposure_reasons": [],
                    "tags": values.get("tags", {}),
                },
            )
        if resource.resource_type == "aws_lb":
            internet_facing = not bool(values.get("internal", False))
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.EDGE,
                identifier=values.get("id"),
                arn=values.get("arn"),
                subnet_ids=_as_list(values.get("subnets")),
                security_group_ids=_as_list(values.get("security_groups")),
                public_access_configured=internet_facing,
                metadata={
                    "internal": not internet_facing,
                    "load_balancer_type": values.get("load_balancer_type"),
                    "public_access_reasons": (
                        ["load balancer is configured as internet-facing"]
                        if internet_facing
                        else []
                    ),
                    "public_exposure_reasons": [],
                },
            )
        if resource.resource_type == "aws_db_instance":
            publicly_accessible = bool(values.get("publicly_accessible", False))
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.DATA,
                identifier=values.get("id") or values.get("identifier"),
                arn=values.get("arn"),
                security_group_ids=_as_list(values.get("vpc_security_group_ids")),
                public_access_configured=publicly_accessible,
                data_sensitivity="sensitive",
                metadata={
                    "engine": values.get("engine"),
                    "publicly_accessible": publicly_accessible,
                    "public_access_reasons": (
                        ["database instance is marked publicly_accessible"]
                        if publicly_accessible
                        else []
                    ),
                    "public_exposure_reasons": [],
                    "storage_encrypted": bool(values.get("storage_encrypted", False)),
                    "db_subnet_group_name": values.get("db_subnet_group_name"),
                },
            )
        if resource.resource_type == "aws_s3_bucket":
            policy_document = _load_json_document(values.get("policy"))
            bucket_acl = values.get("acl", "")
            public_policy = _policy_allows_public_access(policy_document)
            public_access_configured = bucket_acl in {"public-read", "public-read-write", "website"} or public_policy
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.DATA,
                identifier=values.get("bucket") or values.get("id"),
                arn=values.get("arn"),
                public_access_configured=public_access_configured,
                public_exposure=public_access_configured,
                data_sensitivity="sensitive",
                policy_statements=_parse_policy_statements(policy_document),
                metadata={
                    "bucket": values.get("bucket"),
                    "acl": bucket_acl,
                    "policy_document": policy_document,
                    "public_access_reasons": _bucket_public_exposure_reasons(
                        bucket_acl,
                        public_policy=public_policy,
                    ),
                    "public_exposure_reasons": _bucket_public_exposure_reasons(
                        bucket_acl,
                        public_policy=public_policy,
                    ),
                },
            )
        if resource.resource_type == "aws_s3_bucket_policy":
            policy_document = _load_json_document(values.get("policy"))
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.DATA,
                identifier=values.get("id") or resource.address,
                policy_statements=_parse_policy_statements(policy_document),
                metadata={
                    "bucket": values.get("bucket"),
                    "policy_document": policy_document,
                },
            )
        if resource.resource_type == "aws_s3_bucket_public_access_block":
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.DATA,
                identifier=values.get("id") or values.get("bucket") or resource.address,
                metadata={
                    "bucket": values.get("bucket"),
                    "block_public_acls": bool(values.get("block_public_acls", False)),
                    "block_public_policy": bool(values.get("block_public_policy", False)),
                    "ignore_public_acls": bool(values.get("ignore_public_acls", False)),
                    "restrict_public_buckets": bool(values.get("restrict_public_buckets", False)),
                },
            )
        if resource.resource_type == "aws_iam_role":
            assume_role_policy = _load_json_document(values.get("assume_role_policy"))
            inline_policies = _as_list(values.get("inline_policy"))
            statements = []
            for inline_policy in inline_policies:
                statements.extend(_parse_policy_statements(_load_json_document(inline_policy.get("policy"))))
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.IAM,
                identifier=values.get("name") or values.get("id"),
                arn=values.get("arn"),
                policy_statements=statements,
                metadata={
                    "assume_role_policy": assume_role_policy,
                    "trust_principals": _extract_principals(assume_role_policy),
                    "trust_statements": _extract_trust_statements(assume_role_policy),
                    "inline_policy_names": [policy.get("name") for policy in inline_policies],
                },
            )
        if resource.resource_type == "aws_iam_policy":
            policy_document = _load_json_document(values.get("policy"))
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.IAM,
                identifier=values.get("name") or values.get("id"),
                arn=values.get("arn"),
                policy_statements=_parse_policy_statements(policy_document),
                metadata={"policy_document": policy_document},
            )
        if resource.resource_type == "aws_iam_role_policy":
            policy_document = _load_json_document(values.get("policy"))
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.IAM,
                identifier=values.get("id") or resource.address,
                policy_statements=_parse_policy_statements(policy_document),
                metadata={
                    "role": values.get("role"),
                    "policy_document": policy_document,
                    "policy_name": values.get("name"),
                },
            )
        if resource.resource_type == "aws_iam_role_policy_attachment":
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.IAM,
                identifier=values.get("id") or resource.address,
                metadata={
                    "role": values.get("role"),
                    "policy_arn": values.get("policy_arn"),
                },
            )
        if resource.resource_type == "aws_iam_instance_profile":
            role_references = _compact(_as_list(values.get("roles")) + [values.get("role")])
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.IAM,
                identifier=values.get("name") or values.get("id"),
                arn=values.get("arn"),
                metadata={
                    "role_references": role_references,
                },
            )
        if resource.resource_type == "aws_lambda_function":
            vpc_config = _first_item(values.get("vpc_config"))
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.COMPUTE,
                identifier=values.get("function_name") or values.get("id"),
                arn=values.get("arn"),
                subnet_ids=_as_list(vpc_config.get("subnet_ids") if vpc_config else []),
                security_group_ids=_as_list(vpc_config.get("security_group_ids") if vpc_config else []),
                attached_role_arns=_compact([values.get("role")]),
                metadata={
                    "runtime": values.get("runtime"),
                    "handler": values.get("handler"),
                    "vpc_enabled": bool(vpc_config),
                },
            )
        if resource.resource_type == "aws_lambda_permission":
            function_name = values.get("function_name") or values.get("function_arn")
            source_arn = values.get("source_arn")
            source_account = values.get("source_account")
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.COMPUTE,
                identifier=values.get("statement_id") or values.get("id") or resource.address,
                policy_statements=[
                    IAMPolicyStatement(
                        effect="Allow",
                        actions=_compact([values.get("action")]),
                        resources=_compact([function_name]),
                        principals=_compact([values.get("principal")]),
                        conditions=_compact_condition_entries(
                            [
                                _condition_entry(
                                    operator="ArnLike",
                                    key="aws:SourceArn",
                                    values=_compact([source_arn]),
                                ),
                                _condition_entry(
                                    operator="StringEquals",
                                    key="aws:SourceAccount",
                                    values=_compact([source_account]),
                                ),
                            ]
                        ),
                    )
                ],
                metadata={
                    "function_name": function_name,
                    "source_arn": source_arn,
                    "source_account": source_account,
                },
            )
        if resource.resource_type == "aws_kms_key":
            policy_document = _load_json_document(values.get("policy"))
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.DATA,
                identifier=values.get("key_id") or values.get("id"),
                arn=values.get("arn"),
                policy_statements=_parse_policy_statements(policy_document),
                data_sensitivity="sensitive",
                metadata={
                    "policy_document": policy_document,
                    "key_usage": values.get("key_usage"),
                    "enable_key_rotation": bool(values.get("enable_key_rotation", False)),
                },
            )
        if resource.resource_type == "aws_sns_topic":
            policy_document = _load_json_document(values.get("policy"))
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.EDGE,
                identifier=values.get("name") or values.get("id"),
                arn=values.get("arn"),
                policy_statements=_parse_policy_statements(policy_document),
                metadata={
                    "policy_document": policy_document,
                    "display_name": values.get("display_name"),
                },
            )
        if resource.resource_type == "aws_sqs_queue":
            policy_document = _load_json_document(values.get("policy"))
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.DATA,
                identifier=values.get("name") or values.get("id"),
                arn=values.get("arn"),
                policy_statements=_parse_policy_statements(policy_document),
                metadata={
                    "policy_document": policy_document,
                    "queue_url": values.get("url"),
                },
            )
        if resource.resource_type == "aws_secretsmanager_secret":
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.DATA,
                identifier=values.get("name") or values.get("id"),
                arn=values.get("arn"),
                data_sensitivity="sensitive",
                metadata={
                    "name": values.get("name"),
                    "kms_key_id": values.get("kms_key_id"),
                },
            )
        if resource.resource_type == "aws_secretsmanager_secret_policy":
            policy_document = _load_json_document(values.get("policy"))
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.DATA,
                identifier=values.get("id") or resource.address,
                policy_statements=_parse_policy_statements(policy_document),
                metadata={
                    "secret_arn": values.get("secret_arn"),
                    "policy_document": policy_document,
                },
            )
        raise ValueError(f"Unsupported resource type reached normalizer: {resource.resource_type}")

    def _decorate_resources(self, resources: list[NormalizedResource]) -> None:
        subnets = {resource.identifier: resource for resource in resources if resource.resource_type == "aws_subnet"}
        security_groups = {
            resource.identifier: resource for resource in resources if resource.resource_type == "aws_security_group"
        }
        route_tables = {
            resource.identifier: resource for resource in resources if resource.resource_type == "aws_route_table"
        }
        buckets = {
            key: resource
            for resource in resources
            if resource.resource_type == "aws_s3_bucket"
            for key in (resource.identifier, resource.address, resource.arn)
            if key
        }
        secrets = {
            key: resource
            for resource in resources
            if resource.resource_type == "aws_secretsmanager_secret"
            for key in (resource.identifier, resource.address, resource.arn, resource.metadata.get("name"))
            if key
        }
        lambda_functions = {
            key: resource
            for resource in resources
            if resource.resource_type == "aws_lambda_function"
            for key in (resource.identifier, resource.address, resource.arn)
            if key
        }
        role_index = {
            key: resource
            for resource in resources
            if resource.resource_type == "aws_iam_role"
            for key in (resource.identifier, resource.address, resource.arn)
            if key
        }
        instance_profile_index = {
            key: resource
            for resource in resources
            if resource.resource_type == "aws_iam_instance_profile"
            for key in (resource.identifier, resource.address, resource.arn)
            if key
        }
        policy_index = {
            key: resource
            for resource in resources
            if resource.resource_type == "aws_iam_policy"
            for key in (resource.identifier, resource.address, resource.arn)
            if key
        }
        vpcs_with_igw = {
            resource.vpc_id for resource in resources if resource.resource_type == "aws_internet_gateway" and resource.vpc_id
        }
        vpcs_with_public_routes = {
            resource.vpc_id
            for resource in resources
            if resource.resource_type == "aws_route_table" and _has_internet_route(resource.metadata.get("routes", []))
        }
        nat_gateway_ids = {
            resource.identifier
            for resource in resources
            if resource.resource_type == "aws_nat_gateway" and resource.identifier
        }

        # Standalone SG rule resources carry the same security meaning as inline rules, so fold
        # them into the parent security group before any exposure analysis runs.
        for rule_resource in resources:
            if rule_resource.resource_type != "aws_security_group_rule":
                continue
            target_group = security_groups.get(rule_resource.metadata.get("security_group_id"))
            if target_group is None:
                continue
            target_group.network_rules.extend(_clone_security_group_rules(rule_resource.network_rules))
            _append_unique(target_group.metadata, "standalone_rule_addresses", rule_resource.address)

        # Inline role-policy resources extend a role's effective permissions in the same way as
        # inline policies declared directly on the role block.
        for role_policy_resource in resources:
            if role_policy_resource.resource_type != "aws_iam_role_policy":
                continue
            role = role_index.get(role_policy_resource.metadata.get("role"))
            if role is None:
                continue
            role.policy_statements.extend(_clone_policy_statements(role_policy_resource.policy_statements))
            _append_unique(role.metadata, "inline_policy_resource_addresses", role_policy_resource.address)
            _append_unique(role.metadata, "inline_policy_names", role_policy_resource.metadata.get("policy_name"))

        # Role-policy attachments change the workload's effective privileges, so merge any
        # in-plan customer-managed policy statements onto the target role.
        for attachment_resource in resources:
            if attachment_resource.resource_type != "aws_iam_role_policy_attachment":
                continue
            role = role_index.get(attachment_resource.metadata.get("role"))
            policy = policy_index.get(attachment_resource.metadata.get("policy_arn"))
            if role is None:
                continue
            if policy is None:
                _append_unique(
                    role.metadata,
                    "unresolved_attached_policy_arns",
                    str(attachment_resource.metadata.get("policy_arn")),
                )
                continue
            role.policy_statements.extend(_clone_policy_statements(policy.policy_statements))
            _append_unique(role.metadata, "attached_policy_arns", policy.arn or policy.identifier or policy.address)
            _append_unique(role.metadata, "attached_policy_addresses", policy.address)

        # Instance profiles are the normal way EC2 inherits role credentials, so resolve them
        # to attached roles before workload-risk and trust-boundary analysis runs.
        for instance_profile_resource in resources:
            if instance_profile_resource.resource_type != "aws_iam_instance_profile":
                continue
            resolved_role_refs: list[str] = []
            for role_ref in instance_profile_resource.metadata.get("role_references", []):
                role = role_index.get(role_ref)
                if role is None:
                    _append_unique(instance_profile_resource.metadata, "unresolved_role_references", role_ref)
                    continue
                resolved_role_ref = role.arn or role.identifier or role.address
                if resolved_role_ref:
                    resolved_role_refs.append(resolved_role_ref)
                _append_unique(instance_profile_resource.metadata, "resolved_role_addresses", role.address)
            instance_profile_resource.metadata["resolved_role_references"] = resolved_role_refs

        for workload_resource in resources:
            if workload_resource.resource_type != "aws_instance":
                continue
            instance_profile_ref = workload_resource.metadata.get("iam_instance_profile")
            if not instance_profile_ref:
                continue
            instance_profile = instance_profile_index.get(instance_profile_ref)
            if instance_profile is None:
                _append_unique(workload_resource.metadata, "unresolved_instance_profiles", str(instance_profile_ref))
                continue
            _append_unique(workload_resource.metadata, "resolved_instance_profile_addresses", instance_profile.address)
            for resolved_role_ref in instance_profile.metadata.get("resolved_role_references", []):
                if resolved_role_ref not in workload_resource.attached_role_arns:
                    workload_resource.attached_role_arns.append(resolved_role_ref)

        # Resource-policy resources should flow into the target resource so later analysis can
        # reason over one consolidated policy surface.
        for bucket_policy_resource in resources:
            if bucket_policy_resource.resource_type != "aws_s3_bucket_policy":
                continue
            bucket = buckets.get(bucket_policy_resource.metadata.get("bucket"))
            if bucket is None:
                continue
            _merge_resource_policy(
                bucket,
                bucket_policy_resource.policy_statements,
                bucket_policy_resource.metadata.get("policy_document", {}),
                bucket_policy_resource.address,
            )

        for secret_policy_resource in resources:
            if secret_policy_resource.resource_type != "aws_secretsmanager_secret_policy":
                continue
            secret = secrets.get(secret_policy_resource.metadata.get("secret_arn"))
            if secret is None:
                continue
            _merge_resource_policy(
                secret,
                secret_policy_resource.policy_statements,
                secret_policy_resource.metadata.get("policy_document", {}),
                secret_policy_resource.address,
            )

        for lambda_permission_resource in resources:
            if lambda_permission_resource.resource_type != "aws_lambda_permission":
                continue
            function_name = lambda_permission_resource.metadata.get("function_name")
            target_function = lambda_functions.get(function_name)
            if target_function is None:
                continue
            _merge_resource_policy(
                target_function,
                lambda_permission_resource.policy_statements,
                {},
                lambda_permission_resource.address,
            )

        # Public access blocks can neutralize otherwise-public bucket ACLs or policies, so
        # recompute effective public exposure after the control is applied.
        for access_block_resource in resources:
            if access_block_resource.resource_type != "aws_s3_bucket_public_access_block":
                continue
            bucket = buckets.get(access_block_resource.metadata.get("bucket"))
            if bucket is None:
                continue
            public_access_block = {
                "block_public_acls": bool(access_block_resource.metadata.get("block_public_acls")),
                "block_public_policy": bool(access_block_resource.metadata.get("block_public_policy")),
                "ignore_public_acls": bool(access_block_resource.metadata.get("ignore_public_acls")),
                "restrict_public_buckets": bool(access_block_resource.metadata.get("restrict_public_buckets")),
            }
            bucket.metadata["public_access_block"] = public_access_block
            public_via_acl = bucket.metadata.get("acl") in {"public-read", "public-read-write", "website"}
            public_via_policy = _policy_allows_public_access(bucket.metadata.get("policy_document", {}))
            bucket.metadata["public_access_reasons"] = _bucket_public_exposure_reasons(
                bucket.metadata.get("acl", ""),
                public_policy=public_via_policy,
            )
            bucket.public_exposure = (
                public_via_acl and not (public_access_block["block_public_acls"] or public_access_block["ignore_public_acls"])
            ) or (
                public_via_policy
                and not (public_access_block["block_public_policy"] or public_access_block["restrict_public_buckets"])
            )
            bucket.metadata["public_exposure_reasons"] = _bucket_public_exposure_reasons(
                bucket.metadata.get("acl", ""),
                public_policy=public_via_policy,
                public_access_block=public_access_block,
            )

        subnet_route_table_ids: dict[str, list[str]] = {}
        for association_resource in resources:
            if association_resource.resource_type != "aws_route_table_association":
                continue
            subnet_id = association_resource.metadata.get("subnet_id")
            route_table_id = association_resource.metadata.get("route_table_id")
            if not subnet_id or not route_table_id:
                continue
            subnet_route_table_ids.setdefault(str(subnet_id), []).append(str(route_table_id))

        public_subnet_ids = set()
        for subnet in subnets.values():
            associated_route_table_ids = subnet_route_table_ids.get(subnet.identifier or "", [])
            has_public_route = any(
                route_table_id in route_tables and _has_internet_route(route_tables[route_table_id].metadata.get("routes", []))
                for route_table_id in associated_route_table_ids
            )
            has_nat_route = any(
                route_table_id in route_tables
                and _has_nat_gateway_route(route_tables[route_table_id].metadata.get("routes", []), nat_gateway_ids)
                for route_table_id in associated_route_table_ids
            )
            if associated_route_table_ids:
                # Prefer explicit associations when Terraform provides them because they are
                # more precise than inferring subnet posture from VPC-wide route presence.
                is_public = has_public_route
            else:
                # Fall back to the original heuristic when route table associations are absent.
                is_public = bool(subnet.metadata.get("map_public_ip_on_launch")) and subnet.vpc_id in vpcs_with_igw.intersection(
                    vpcs_with_public_routes
                )
                has_nat_route = False
            subnet.metadata["is_public_subnet"] = is_public
            subnet.metadata["route_table_ids"] = associated_route_table_ids
            subnet.metadata["has_public_route"] = has_public_route
            subnet.metadata["has_nat_gateway_egress"] = has_nat_route
            if is_public and subnet.identifier:
                public_subnet_ids.add(subnet.identifier)

        for resource in resources:
            if not resource.vpc_id:
                # Some Terraform resources omit a direct VPC reference, so infer it from the
                # attached subnet first and fall back to attached security groups.
                for subnet_id in resource.subnet_ids:
                    subnet = subnets.get(subnet_id)
                    if subnet and subnet.vpc_id:
                        resource.vpc_id = subnet.vpc_id
                        break
                if not resource.vpc_id:
                    for security_group_id in resource.security_group_ids:
                        security_group = security_groups.get(security_group_id)
                        if security_group and security_group.vpc_id:
                            resource.vpc_id = security_group.vpc_id
                            break

        for resource in resources:
            attached_security_groups = [security_groups[sg_id] for sg_id in resource.security_group_ids if sg_id in security_groups]
            internet_ingress = any(
                rule.direction == "ingress" and rule.allows_internet()
                for security_group in attached_security_groups
                for rule in security_group.network_rules
            )
            resource.metadata.setdefault("public_access_reasons", [])
            resource.metadata.setdefault("public_exposure_reasons", [])
            resource.metadata["public_access_configured"] = resource.public_access_configured
            resource.metadata["internet_ingress"] = internet_ingress
            resource.metadata["internet_ingress_capable"] = internet_ingress
            resource.metadata["internet_ingress_reasons"] = _internet_ingress_reasons(attached_security_groups)
            resource.metadata["public_subnet"] = (
                any(subnet_id in public_subnet_ids for subnet_id in resource.subnet_ids)
                if resource.subnet_ids
                else resource.metadata.get("public_subnet", False)
            )
            resource.metadata["has_nat_gateway_egress"] = (
                any(
                    subnets[subnet_id].metadata.get("has_nat_gateway_egress")
                    for subnet_id in resource.subnet_ids
                    if subnet_id in subnets
                )
                if resource.subnet_ids
                else resource.metadata.get("has_nat_gateway_egress", False)
            )
            # Public exposure is inferred conservatively from network placement and ingress
            # rules so later detectors can reason over a normalized signal instead of
            # provider-specific fields.
            if resource.resource_type == "aws_instance":
                resource.public_exposure = bool(
                    resource.public_access_configured
                    and resource.metadata["public_subnet"]
                    and internet_ingress
                )
                if resource.public_exposure:
                    _append_unique(
                        resource.metadata,
                        "public_exposure_reasons",
                        "instance has a public IP path and attached security groups allow internet ingress",
                    )
            elif resource.resource_type == "aws_db_instance":
                resource.public_exposure = bool(
                    resource.public_access_configured and (internet_ingress or not attached_security_groups)
                )
                if resource.public_exposure and internet_ingress:
                    _append_unique(
                        resource.metadata,
                        "public_exposure_reasons",
                        "database is marked publicly_accessible and attached security groups allow internet ingress",
                    )
                elif resource.public_exposure and not attached_security_groups:
                    _append_unique(
                        resource.metadata,
                        "public_exposure_reasons",
                        "database is marked publicly_accessible and no attached security groups provide ingress evidence",
                    )
            elif resource.resource_type == "aws_lb":
                resource.public_exposure = bool(
                    resource.public_access_configured and (internet_ingress or not attached_security_groups)
                )
                if resource.public_exposure and internet_ingress:
                    _append_unique(
                        resource.metadata,
                        "public_exposure_reasons",
                        "load balancer is internet-facing and attached security groups allow internet ingress",
                    )
                elif resource.public_exposure:
                    _append_unique(
                        resource.metadata,
                        "public_exposure_reasons",
                        "load balancer is configured as internet-facing",
                    )
            resource.metadata["direct_internet_reachable"] = resource.public_exposure


def _parse_security_group_rules(values: dict[str, Any]) -> list[SecurityGroupRule]:
    rules: list[SecurityGroupRule] = []
    for direction in ("ingress", "egress"):
        for rule in _as_list(values.get(direction)):
            rules.append(
                SecurityGroupRule(
                    direction=direction,
                    protocol=str(rule.get("protocol", "-1")),
                    from_port=_as_optional_int(rule.get("from_port")),
                    to_port=_as_optional_int(rule.get("to_port")),
                    cidr_blocks=_as_list(rule.get("cidr_blocks")),
                    ipv6_cidr_blocks=_as_list(rule.get("ipv6_cidr_blocks")),
                    referenced_security_group_ids=_as_list(rule.get("security_groups")),
                    description=rule.get("description"),
                )
            )
    return rules


def _parse_standalone_security_group_rule(values: dict[str, Any]) -> SecurityGroupRule:
    referenced_security_group_ids = _compact([values.get("source_security_group_id")])
    if values.get("self") and values.get("security_group_id"):
        referenced_security_group_ids.append(str(values["security_group_id"]))
    return SecurityGroupRule(
        direction=str(values.get("type", "ingress")),
        protocol=str(values.get("protocol", "-1")),
        from_port=_as_optional_int(values.get("from_port")),
        to_port=_as_optional_int(values.get("to_port")),
        cidr_blocks=_as_list(values.get("cidr_blocks")),
        ipv6_cidr_blocks=_as_list(values.get("ipv6_cidr_blocks")),
        referenced_security_group_ids=referenced_security_group_ids,
        description=values.get("description"),
    )


def _parse_policy_statements(policy_document: dict[str, Any]) -> list[IAMPolicyStatement]:
    statements: list[IAMPolicyStatement] = []
    for statement in _as_list(policy_document.get("Statement")):
        principals = _extract_principal_values(statement.get("Principal"))
        statements.append(
            IAMPolicyStatement(
                effect=str(statement.get("Effect", "Allow")),
                actions=_as_list(statement.get("Action")),
                resources=_as_list(statement.get("Resource")),
                principals=principals,
                conditions=_parse_condition_entries(statement.get("Condition")),
            )
        )
    return statements


def _extract_principals(policy_document: dict[str, Any]) -> list[str]:
    principals: list[str] = []
    for statement in _parse_policy_statements(policy_document):
        principals.extend(statement.principals)
    return sorted(set(principals))


def _extract_trust_statements(policy_document: dict[str, Any]) -> list[dict[str, Any]]:
    trust_statements: list[dict[str, Any]] = []
    for statement in _as_list(policy_document.get("Statement")):
        if str(statement.get("Effect", "Allow")) != "Allow":
            continue
        principals = sorted(set(_extract_principal_values(statement.get("Principal"))))
        if not principals:
            continue
        narrowing_condition_keys = _extract_supported_trust_narrowing_condition_keys(statement.get("Condition"))
        trust_statements.append(
            {
                "principals": principals,
                "narrowing_condition_keys": narrowing_condition_keys,
                "has_narrowing_conditions": bool(narrowing_condition_keys),
            }
        )
    return trust_statements


def _extract_supported_trust_narrowing_condition_keys(raw_condition: Any) -> list[str]:
    found_keys: set[str] = set()
    _collect_supported_trust_narrowing_condition_keys(raw_condition, found_keys)
    return sorted(found_keys)


def _collect_supported_trust_narrowing_condition_keys(raw_condition: Any, found_keys: set[str]) -> None:
    if isinstance(raw_condition, dict):
        for key, value in raw_condition.items():
            if key in SUPPORTED_TRUST_NARROWING_CONDITION_KEYS:
                found_keys.add(key)
            _collect_supported_trust_narrowing_condition_keys(value, found_keys)
        return
    if isinstance(raw_condition, list):
        for item in raw_condition:
            _collect_supported_trust_narrowing_condition_keys(item, found_keys)


def _extract_principal_values(raw_principal: Any) -> list[str]:
    if raw_principal is None:
        return []
    if isinstance(raw_principal, str):
        return [raw_principal]
    if isinstance(raw_principal, dict):
        values: list[str] = []
        for principal_value in raw_principal.values():
            values.extend(_as_list(principal_value))
        return values
    if isinstance(raw_principal, list):
        return [str(item) for item in raw_principal]
    return []


def _policy_allows_public_access(policy_document: dict[str, Any]) -> bool:
    for statement in _parse_policy_statements(policy_document):
        if statement.effect != "Allow":
            continue
        if "*" in statement.principals:
            return True
    return False


def _bucket_public_exposure_reasons(
    bucket_acl: str,
    *,
    public_policy: bool,
    public_access_block: dict[str, bool] | None = None,
) -> list[str]:
    reasons: list[str] = []
    access_block = public_access_block or {}
    acl_is_public = bucket_acl in {"public-read", "public-read-write", "website"}
    if acl_is_public and not (access_block.get("block_public_acls") or access_block.get("ignore_public_acls")):
        reasons.append(f"bucket ACL `{bucket_acl}` grants public access")
    if public_policy and not (access_block.get("block_public_policy") or access_block.get("restrict_public_buckets")):
        reasons.append("bucket policy allows anonymous access")
    return reasons


def _has_internet_route(routes: list[dict[str, Any]]) -> bool:
    for route in routes:
        destination = route.get("cidr_block") or route.get("destination_cidr_block")
        gateway_id = route.get("gateway_id")
        if destination == "0.0.0.0/0" and isinstance(gateway_id, str) and gateway_id.startswith("igw-"):
            return True
    return False


def _has_nat_gateway_route(routes: list[dict[str, Any]], nat_gateway_ids: set[str]) -> bool:
    for route in routes:
        destination = route.get("cidr_block") or route.get("destination_cidr_block")
        nat_gateway_id = route.get("nat_gateway_id")
        gateway_id = route.get("gateway_id")
        if destination != "0.0.0.0/0":
            continue
        if isinstance(nat_gateway_id, str) and nat_gateway_id in nat_gateway_ids:
            return True
        if isinstance(gateway_id, str) and gateway_id in nat_gateway_ids:
            return True
    return False


def _load_json_document(raw_document: Any) -> dict[str, Any]:
    if isinstance(raw_document, dict):
        return raw_document
    if isinstance(raw_document, str) and raw_document.strip():
        try:
            loaded = json.loads(raw_document)
        except json.JSONDecodeError:
            return {}
        if isinstance(loaded, dict):
            return loaded
    return {}


def _infer_primary_account_id(resources: list[NormalizedResource]) -> str | None:
    accounts = Counter(
        account_id for account_id in (_parse_account_id(resource.arn) for resource in resources) if account_id
    )
    if not accounts:
        return None
    return accounts.most_common(1)[0][0]


def _parse_account_id(arn: str | None) -> str | None:
    if not arn:
        return None
    parts = arn.split(":")
    if len(parts) < 5:
        return None
    return parts[4] or None


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
    _append_unique(resource.metadata, "resource_policy_source_addresses", source_address)
    merged_document = _merge_policy_documents(resource.metadata.get("policy_document", {}), policy_document)
    if merged_document:
        resource.metadata["policy_document"] = merged_document


def _merge_policy_documents(base_document: Any, extra_document: Any) -> dict[str, Any]:
    base = base_document if isinstance(base_document, dict) else {}
    extra = extra_document if isinstance(extra_document, dict) else {}
    base_statements = _as_list(base.get("Statement"))
    extra_statements = _as_list(extra.get("Statement"))
    merged_statements = [statement for statement in [*base_statements, *extra_statements] if isinstance(statement, dict)]
    if not merged_statements:
        return base or extra
    merged_document = dict(base) if base else dict(extra)
    merged_document["Statement"] = merged_statements
    return merged_document


def _append_unique(metadata: dict[str, Any], key: str, value: str | None) -> None:
    if not value:
        return
    values = metadata.setdefault(key, [])
    if value not in values:
        values.append(value)


def _internet_ingress_reasons(attached_security_groups: list[NormalizedResource]) -> list[str]:
    reasons: list[str] = []
    for security_group in attached_security_groups:
        for rule in security_group.network_rules:
            if rule.direction != "ingress" or not rule.allows_internet():
                continue
            reasons.append(_describe_security_group_rule(security_group, rule))
    return reasons


def _describe_security_group_rule(security_group: NormalizedResource, rule: SecurityGroupRule) -> str:
    port_range = _format_port_range(rule)
    sources = list(rule.cidr_blocks) + list(rule.ipv6_cidr_blocks)
    if rule.referenced_security_group_ids:
        sources.extend(rule.referenced_security_group_ids)
    source_text = ", ".join(sorted(sources)) if sources else "unspecified sources"
    description = f"{security_group.address} {rule.direction} {rule.protocol} {port_range} from {source_text}"
    if rule.description:
        return f"{description} ({rule.description})"
    return description


def _format_port_range(rule: SecurityGroupRule) -> str:
    if rule.protocol == "-1":
        return "all ports"
    if rule.from_port is None or rule.to_port is None:
        return "unspecified ports"
    if rule.from_port == rule.to_port:
        return str(rule.from_port)
    return f"{rule.from_port}-{rule.to_port}"


def _compact(values: list[Any]) -> list[str]:
    return [str(value) for value in values if value not in (None, "", [])]


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _first_item(value: Any) -> dict[str, Any] | None:
    items = _as_list(value)
    if not items:
        return None
    first = items[0]
    if isinstance(first, dict):
        return first
    return None


def _as_optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_condition_entries(raw_condition: Any) -> list[IAMPolicyCondition]:
    if not isinstance(raw_condition, dict):
        return []

    entries: list[IAMPolicyCondition] = []
    for operator in sorted(raw_condition):
        keyed_values = raw_condition.get(operator)
        if not isinstance(keyed_values, dict):
            continue
        for key in sorted(keyed_values):
            entry = _condition_entry(
                operator=str(operator),
                key=str(key),
                values=_normalize_condition_values(keyed_values.get(key)),
            )
            if entry is not None:
                entries.append(entry)
    return entries


def _condition_entry(*, operator: str, key: str, values: list[str]) -> IAMPolicyCondition | None:
    if not operator or not key or not values:
        return None
    return IAMPolicyCondition(operator=operator, key=key, values=values)


def _compact_condition_entries(
    entries: list[IAMPolicyCondition | None],
) -> list[IAMPolicyCondition]:
    return [entry for entry in entries if entry is not None]


def _normalize_condition_values(value: Any) -> list[str]:
    raw_values = _as_list(value)
    normalized: list[str] = []
    for raw_value in raw_values:
        if raw_value in (None, "", []):
            continue
        if isinstance(raw_value, dict):
            text = json.dumps(raw_value, sort_keys=True)
        else:
            text = str(raw_value)
        if text not in normalized:
            normalized.append(text)
    return normalized
