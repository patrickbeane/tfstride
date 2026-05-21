from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from typing import Any

from tfstride.models import (
    IAMPolicyStatement,
    NormalizedResource,
    ResourceCategory,
    ResourceInventory,
    SecurityGroupRule,
    TerraformResource,
)
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.aws.coercion import as_bool, as_list, as_optional_int, compact, first_item
from tfstride.providers.aws.policy_documents import (
    compact_condition_entries,
    condition_entry,
    extract_principals,
    extract_trust_statements,
    lambda_permission_principal_entries,
    load_json_document,
    parse_policy_statements,
)
from tfstride.providers.aws.resource_decorator import AwsResourceDecorator
from tfstride.providers.aws.resource_utils import bucket_public_exposure_reasons, ecs_task_definition_identifier
from tfstride.resource_helpers import policy_allows_public_access


_AWS_RESOURCE_NORMALIZER_METHODS = {
    "aws_db_instance": "_normalize_db_instance",
    "aws_ecs_cluster": "_normalize_ecs_cluster",
    "aws_ecs_service": "_normalize_ecs_service",
    "aws_ecs_task_definition": "_normalize_ecs_task_definition",
    "aws_iam_instance_profile": "_normalize_iam_instance_profile",
    "aws_iam_policy": "_normalize_iam_policy",
    "aws_iam_role": "_normalize_iam_role",
    "aws_iam_role_policy": "_normalize_iam_role_policy",
    "aws_iam_role_policy_attachment": "_normalize_iam_role_policy_attachment",
    "aws_instance": "_normalize_instance",
    "aws_internet_gateway": "_normalize_internet_gateway",
    "aws_kms_key": "_normalize_kms_key",
    "aws_lambda_function": "_normalize_lambda_function",
    "aws_lambda_permission": "_normalize_lambda_permission",
    "aws_lb": "_normalize_load_balancer",
    "aws_nat_gateway": "_normalize_nat_gateway",
    "aws_route_table": "_normalize_route_table",
    "aws_route_table_association": "_normalize_route_table_association",
    "aws_s3_bucket": "_normalize_s3_bucket",
    "aws_s3_bucket_policy": "_normalize_s3_bucket_policy",
    "aws_s3_bucket_public_access_block": "_normalize_s3_bucket_public_access_block",
    "aws_secretsmanager_secret": "_normalize_secretsmanager_secret",
    "aws_secretsmanager_secret_policy": "_normalize_secretsmanager_secret_policy",
    "aws_security_group": "_normalize_security_group",
    "aws_security_group_rule": "_normalize_security_group_rule",
    "aws_sns_topic": "_normalize_sns_topic",
    "aws_sqs_queue": "_normalize_sqs_queue",
    "aws_subnet": "_normalize_subnet",
    "aws_vpc": "_normalize_vpc",
}
SUPPORTED_AWS_TYPES = set(_AWS_RESOURCE_NORMALIZER_METHODS)


class AwsNormalizer(ProviderNormalizer):
    provider = "aws"

    def __init__(self, resource_decorator: AwsResourceDecorator | None = None) -> None:
        self._resource_decorator = resource_decorator or AwsResourceDecorator()
        self._resource_normalizers: dict[str, Callable[[TerraformResource], NormalizedResource]] = {
            resource_type: getattr(self, method_name)
            for resource_type, method_name in _AWS_RESOURCE_NORMALIZER_METHODS.items()
        }

    def normalize(self, resources: list[TerraformResource]) -> ResourceInventory:
        aws_resources = [
            resource
            for resource in resources
            if resource.provider_name.endswith("/aws") or resource.resource_type.startswith("aws_")
        ]
        unsupported_resource_types = Counter(
            resource.resource_type
            for resource in aws_resources
            if resource.resource_type not in SUPPORTED_AWS_TYPES
        )
        unsupported = sorted(
            resource.address for resource in aws_resources if resource.resource_type not in SUPPORTED_AWS_TYPES
        )
        normalized = [
            self._normalize_resource(resource)
            for resource in aws_resources
            if resource.resource_type in SUPPORTED_AWS_TYPES
        ]
        self._resource_decorator.decorate(normalized)
        primary_account_id = _infer_primary_account_id(normalized)
        return ResourceInventory(
            provider=self.provider,
            resources=normalized,
            unsupported_resources=unsupported,
            metadata={
                "primary_account_id": primary_account_id,
                "supported_resource_types": sorted(SUPPORTED_AWS_TYPES),
                "total_input_resources": len(resources),
                "provider_resource_count": len(aws_resources),
                "normalized_resource_count": len(normalized),
                "unsupported_resource_types": dict(sorted(unsupported_resource_types.items())),
            },
        )

    def _normalize_resource(self, resource: TerraformResource) -> NormalizedResource:
        try:
            normalizer = self._resource_normalizers[resource.resource_type]
        except KeyError as exc:
            raise ValueError(f"Unsupported resource type reached normalizer: {resource.resource_type}") from exc
        return normalizer(resource)

    def _normalize_vpc(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
        return NormalizedResource(
            address=resource.address,
            provider=self.provider,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.NETWORK,
            identifier=values.get("id"),
            metadata={"cidr_block": values.get("cidr_block"), "tags": values.get("tags", {})},
        )

    def _normalize_subnet(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
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

    def _normalize_internet_gateway(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
        return NormalizedResource(
            address=resource.address,
            provider=self.provider,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.NETWORK,
            identifier=values.get("id"),
            vpc_id=values.get("vpc_id"),
        )

    def _normalize_route_table(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
        return NormalizedResource(
            address=resource.address,
            provider=self.provider,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.NETWORK,
            identifier=values.get("id"),
            vpc_id=values.get("vpc_id"),
            metadata={"routes": as_list(values.get("route") or values.get("routes"))},
        )

    def _normalize_route_table_association(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
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

    def _normalize_security_group(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
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

    def _normalize_security_group_rule(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
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

    def _normalize_nat_gateway(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
        return NormalizedResource(
            address=resource.address,
            provider=self.provider,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.NETWORK,
            identifier=values.get("id"),
            subnet_ids=compact([values.get("subnet_id")]),
            metadata={
                "allocation_id": values.get("allocation_id"),
                "connectivity_type": values.get("connectivity_type", "public"),
            },
        )

    def _normalize_instance(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
        public_ip_requested = bool(values.get("associate_public_ip_address", False))
        return NormalizedResource(
            address=resource.address,
            provider=self.provider,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.COMPUTE,
            identifier=values.get("id"),
            arn=values.get("arn"),
            subnet_ids=compact([values.get("subnet_id")]),
            security_group_ids=as_list(values.get("vpc_security_group_ids")),
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

    def _normalize_ecs_cluster(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
        return NormalizedResource(
            address=resource.address,
            provider=self.provider,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.COMPUTE,
            identifier=values.get("name") or values.get("id"),
            arn=values.get("arn"),
            metadata={
                "name": values.get("name"),
                "capacity_providers": as_list(values.get("capacity_providers")),
            },
        )

    def _normalize_ecs_task_definition(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
        family = values.get("family")
        revision = as_optional_int(values.get("revision"))
        return NormalizedResource(
            address=resource.address,
            provider=self.provider,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.COMPUTE,
            identifier=ecs_task_definition_identifier(family, revision) or values.get("id") or family,
            arn=values.get("arn"),
            metadata={
                "family": family,
                "revision": revision,
                "network_mode": values.get("network_mode"),
                "requires_compatibilities": compact(as_list(values.get("requires_compatibilities"))),
                "task_role_arn": values.get("task_role_arn"),
                "execution_role_arn": values.get("execution_role_arn"),
            },
        )

    def _normalize_ecs_service(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
        network_configuration = first_item(values.get("network_configuration"))
        assign_public_ip = as_bool(network_configuration.get("assign_public_ip")) if network_configuration else False
        return NormalizedResource(
            address=resource.address,
            provider=self.provider,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.COMPUTE,
            identifier=values.get("name") or values.get("id"),
            arn=values.get("arn"),
            subnet_ids=compact(network_configuration.get("subnets", []) if network_configuration else []),
            security_group_ids=compact(network_configuration.get("security_groups", []) if network_configuration else []),
            public_access_configured=assign_public_ip,
            metadata={
                "cluster": values.get("cluster"),
                "task_definition": values.get("task_definition"),
                "desired_count": as_optional_int(values.get("desired_count")),
                "launch_type": values.get("launch_type"),
                "platform_version": values.get("platform_version"),
                "assign_public_ip": assign_public_ip,
                "load_balancers": as_list(values.get("load_balancer")),
                "public_access_reasons": (
                    ["ECS service assigns public IPs to tasks"]
                    if assign_public_ip
                    else []
                ),
                "public_exposure_reasons": [],
            },
        )

    def _normalize_load_balancer(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
        internet_facing = not bool(values.get("internal", False))
        return NormalizedResource(
            address=resource.address,
            provider=self.provider,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.EDGE,
            identifier=values.get("id"),
            arn=values.get("arn"),
            subnet_ids=as_list(values.get("subnets")),
            security_group_ids=as_list(values.get("security_groups")),
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

    def _normalize_db_instance(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
        publicly_accessible = bool(values.get("publicly_accessible", False))
        return NormalizedResource(
            address=resource.address,
            provider=self.provider,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.DATA,
            identifier=values.get("id") or values.get("identifier"),
            arn=values.get("arn"),
            security_group_ids=as_list(values.get("vpc_security_group_ids")),
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

    def _normalize_s3_bucket(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
        policy_document = load_json_document(values.get("policy"))
        bucket_acl = values.get("acl", "")
        public_policy = policy_allows_public_access(policy_document)
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
            policy_statements=parse_policy_statements(policy_document),
            metadata={
                "bucket": values.get("bucket"),
                "acl": bucket_acl,
                "policy_document": policy_document,
                "public_access_reasons": bucket_public_exposure_reasons(
                    bucket_acl,
                    public_policy=public_policy,
                ),
                "public_exposure_reasons": bucket_public_exposure_reasons(
                    bucket_acl,
                    public_policy=public_policy,
                ),
            },
        )

    def _normalize_s3_bucket_policy(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
        policy_document = load_json_document(values.get("policy"))
        return NormalizedResource(
            address=resource.address,
            provider=self.provider,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.DATA,
            identifier=values.get("id") or resource.address,
            policy_statements=parse_policy_statements(policy_document),
            metadata={
                "bucket": values.get("bucket"),
                "policy_document": policy_document,
            },
        )

    def _normalize_s3_bucket_public_access_block(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
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

    def _normalize_iam_role(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
        assume_role_policy = load_json_document(values.get("assume_role_policy"))
        inline_policies = as_list(values.get("inline_policy"))
        statements = []
        for inline_policy in inline_policies:
            statements.extend(parse_policy_statements(load_json_document(inline_policy.get("policy"))))
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
                "trust_principals": extract_principals(assume_role_policy),
                "trust_statements": extract_trust_statements(assume_role_policy),
                "inline_policy_names": [policy.get("name") for policy in inline_policies],
            },
        )

    def _normalize_iam_policy(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
        policy_document = load_json_document(values.get("policy"))
        return NormalizedResource(
            address=resource.address,
            provider=self.provider,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.IAM,
            identifier=values.get("name") or values.get("id"),
            arn=values.get("arn"),
            policy_statements=parse_policy_statements(policy_document),
            metadata={"policy_document": policy_document},
        )

    def _normalize_iam_role_policy(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
        policy_document = load_json_document(values.get("policy"))
        return NormalizedResource(
            address=resource.address,
            provider=self.provider,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.IAM,
            identifier=values.get("id") or resource.address,
            policy_statements=parse_policy_statements(policy_document),
            metadata={
                "role": values.get("role"),
                "policy_document": policy_document,
                "policy_name": values.get("name"),
            },
        )

    def _normalize_iam_role_policy_attachment(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
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

    def _normalize_iam_instance_profile(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
        role_references = compact(as_list(values.get("roles")) + [values.get("role")])
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

    def _normalize_lambda_function(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
        vpc_config = first_item(values.get("vpc_config"))
        return NormalizedResource(
            address=resource.address,
            provider=self.provider,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.COMPUTE,
            identifier=values.get("function_name") or values.get("id"),
            arn=values.get("arn"),
            subnet_ids=as_list(vpc_config.get("subnet_ids") if vpc_config else []),
            security_group_ids=as_list(vpc_config.get("security_group_ids") if vpc_config else []),
            attached_role_arns=compact([values.get("role")]),
            metadata={
                "runtime": values.get("runtime"),
                "handler": values.get("handler"),
                "vpc_enabled": bool(vpc_config),
            },
        )

    def _normalize_lambda_permission(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
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
                    actions=compact([values.get("action")]),
                    resources=compact([function_name]),
                    principals=compact([values.get("principal")]),
                    principal_entries=lambda_permission_principal_entries(values.get("principal")),
                    conditions=compact_condition_entries(
                        [
                            condition_entry(
                                operator="ArnLike",
                                key="aws:SourceArn",
                                values=compact([source_arn]),
                            ),
                            condition_entry(
                                operator="StringEquals",
                                key="aws:SourceAccount",
                                values=compact([source_account]),
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

    def _normalize_kms_key(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
        policy_document = load_json_document(values.get("policy"))
        return NormalizedResource(
            address=resource.address,
            provider=self.provider,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.DATA,
            identifier=values.get("key_id") or values.get("id"),
            arn=values.get("arn"),
            policy_statements=parse_policy_statements(policy_document),
            data_sensitivity="sensitive",
            metadata={
                "policy_document": policy_document,
                "key_usage": values.get("key_usage"),
                "enable_key_rotation": bool(values.get("enable_key_rotation", False)),
            },
        )

    def _normalize_sns_topic(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
        policy_document = load_json_document(values.get("policy"))
        return NormalizedResource(
            address=resource.address,
            provider=self.provider,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.EDGE,
            identifier=values.get("name") or values.get("id"),
            arn=values.get("arn"),
            policy_statements=parse_policy_statements(policy_document),
            metadata={
                "policy_document": policy_document,
                "display_name": values.get("display_name"),
            },
        )

    def _normalize_sqs_queue(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
        policy_document = load_json_document(values.get("policy"))
        return NormalizedResource(
            address=resource.address,
            provider=self.provider,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.DATA,
            identifier=values.get("name") or values.get("id"),
            arn=values.get("arn"),
            policy_statements=parse_policy_statements(policy_document),
            metadata={
                "policy_document": policy_document,
                "queue_url": values.get("url"),
            },
        )

    def _normalize_secretsmanager_secret(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
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

    def _normalize_secretsmanager_secret_policy(self, resource: TerraformResource) -> NormalizedResource:
        values = resource.values
        policy_document = load_json_document(values.get("policy"))
        return NormalizedResource(
            address=resource.address,
            provider=self.provider,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.DATA,
            identifier=values.get("id") or resource.address,
            policy_statements=parse_policy_statements(policy_document),
            metadata={
                "secret_arn": values.get("secret_arn"),
                "policy_document": policy_document,
            },
        )


def _parse_security_group_rules(values: dict[str, Any]) -> list[SecurityGroupRule]:
    rules: list[SecurityGroupRule] = []
    for direction in ("ingress", "egress"):
        for rule in as_list(values.get(direction)):
            rules.append(
                SecurityGroupRule(
                    direction=direction,
                    protocol=str(rule.get("protocol", "-1")),
                    from_port=as_optional_int(rule.get("from_port")),
                    to_port=as_optional_int(rule.get("to_port")),
                    cidr_blocks=as_list(rule.get("cidr_blocks")),
                    ipv6_cidr_blocks=as_list(rule.get("ipv6_cidr_blocks")),
                    referenced_security_group_ids=as_list(rule.get("security_groups")),
                    description=rule.get("description"),
                )
            )
    return rules


def _parse_standalone_security_group_rule(values: dict[str, Any]) -> SecurityGroupRule:
    referenced_security_group_ids = compact([values.get("source_security_group_id")])
    if values.get("self") and values.get("security_group_id"):
        referenced_security_group_ids.append(str(values["security_group_id"]))
    return SecurityGroupRule(
        direction=str(values.get("type", "ingress")),
        protocol=str(values.get("protocol", "-1")),
        from_port=as_optional_int(values.get("from_port")),
        to_port=as_optional_int(values.get("to_port")),
        cidr_blocks=as_list(values.get("cidr_blocks")),
        ipv6_cidr_blocks=as_list(values.get("ipv6_cidr_blocks")),
        referenced_security_group_ids=referenced_security_group_ids,
        description=values.get("description"),
    )


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
