from __future__ import annotations

import json
from collections import Counter
from typing import Any

from tfstride.models import (
    IAMPolicyCondition,
    IAMPolicyStatement,
    IAMPrincipal,
    NormalizedResource,
    ResourceCategory,
    ResourceInventory,
    SecurityGroupRule,
    TerraformResource,
)
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.aws.resource_decorator import AwsResourceDecorator
from tfstride.providers.aws.resource_utils import bucket_public_exposure_reasons, ecs_task_definition_identifier
from tfstride.resource_helpers import policy_allows_public_access


SUPPORTED_AWS_TYPES = {
    "aws_instance",
    "aws_ecs_service",
    "aws_ecs_task_definition",
    "aws_ecs_cluster",
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

SUPPORTED_TRUST_NARROWING_CONDITIONS = {
    "sts:ExternalId": {
        "StringEquals",
        "StringLike",
        "ForAnyValue:StringEquals",
        "ForAnyValue:StringLike",
    },
    "aws:SourceArn": {
        "ArnEquals",
        "ArnLike",
        "StringEquals",
        "StringLike",
        "ForAnyValue:ArnEquals",
        "ForAnyValue:ArnLike",
    },
    "aws:SourceAccount": {
        "StringEquals",
        "StringLike",
        "ForAnyValue:StringEquals",
        "ForAnyValue:StringLike",
    },
}


class AwsNormalizer(ProviderNormalizer):
    provider = "aws"

    def __init__(self, resource_decorator: AwsResourceDecorator | None = None) -> None:
	    self._resource_decorator = resource_decorator or AwsResourceDecorator()

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
        if resource.resource_type == "aws_ecs_cluster":
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
                    "capacity_providers": _as_list(values.get("capacity_providers")),
                },
            )
        if resource.resource_type == "aws_ecs_task_definition":
            family = values.get("family")
            revision = _as_optional_int(values.get("revision"))
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
                    "requires_compatibilities": _compact(_as_list(values.get("requires_compatibilities"))),
                    "task_role_arn": values.get("task_role_arn"),
                    "execution_role_arn": values.get("execution_role_arn"),
                },
            )
        if resource.resource_type == "aws_ecs_service":
            network_configuration = _first_item(values.get("network_configuration"))
            assign_public_ip = _as_bool(network_configuration.get("assign_public_ip")) if network_configuration else False
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.COMPUTE,
                identifier=values.get("name") or values.get("id"),
                arn=values.get("arn"),
                subnet_ids=_compact(network_configuration.get("subnets", []) if network_configuration else []),
                security_group_ids=_compact(network_configuration.get("security_groups", []) if network_configuration else []),
                public_access_configured=assign_public_ip,
                metadata={
                    "cluster": values.get("cluster"),
                    "task_definition": values.get("task_definition"),
                    "desired_count": _as_optional_int(values.get("desired_count")),
                    "launch_type": values.get("launch_type"),
                    "platform_version": values.get("platform_version"),
                    "assign_public_ip": assign_public_ip,
                    "load_balancers": _as_list(values.get("load_balancer")),
                    "public_access_reasons": (
                        ["ECS service assigns public IPs to tasks"]
                        if assign_public_ip
                        else []
                    ),
                    "public_exposure_reasons": [],
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
                policy_statements=_parse_policy_statements(policy_document),
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
                        principal_entries=_lambda_permission_principal_entries(values.get("principal")),
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
        statements.append(_parse_policy_statement(statement))
    return statements


def _parse_policy_statement(statement: Any) -> IAMPolicyStatement:
    statement_dict = statement if isinstance(statement, dict) else {}
    principal_entries = _extract_principal_entries(statement_dict.get("Principal"))
    return IAMPolicyStatement(
        effect=str(statement_dict.get("Effect", "Allow")),
        actions=_as_list(statement_dict.get("Action")),
        resources=_as_list(statement_dict.get("Resource")),
        principals=[entry.value for entry in principal_entries],
        principal_entries=principal_entries,
        conditions=_parse_condition_entries(statement_dict.get("Condition")),
    )


def _extract_principals(policy_document: dict[str, Any]) -> list[str]:
    principals: list[str] = []
    for statement in _parse_policy_statements(policy_document):
        principals.extend(statement.principals)
    return sorted(set(principals))


def _extract_trust_statements(policy_document: dict[str, Any]) -> list[dict[str, Any]]:
    trust_statements: list[dict[str, Any]] = []
    for raw_statement in _as_list(policy_document.get("Statement")):
        statement = _parse_policy_statement(raw_statement)
        if statement.effect != "Allow":
            continue
        principals = sorted(set(statement.principals))
        if not principals:
            continue
        principal_entries = sorted(
            (
                {"kind": entry.kind, "value": entry.value}
                for entry in statement.principal_entries
            ),
            key=lambda entry: (entry["kind"], entry["value"]),
        )
        narrowing_conditions = _extract_supported_trust_narrowing_conditions(statement.conditions)
        trust_statements.append(
            {
                "principals": principals,
                "principal_entries": principal_entries,
                "narrowing_condition_keys": sorted({condition.key for condition in narrowing_conditions}),
                "narrowing_conditions": [
                    {
                        "operator": condition.operator,
                        "key": condition.key,
                        "values": list(condition.values),
                    }
                    for condition in narrowing_conditions
                ],
                "has_narrowing_conditions": bool(narrowing_conditions),
            }
        )
    return trust_statements


def _extract_supported_trust_narrowing_conditions(
    conditions: list[IAMPolicyCondition],
) -> list[IAMPolicyCondition]:
    supported: list[IAMPolicyCondition] = []
    for condition in conditions:
        supported_operators = SUPPORTED_TRUST_NARROWING_CONDITIONS.get(condition.key)
        if supported_operators is None or condition.operator not in supported_operators:
            continue
        supported.append(
            IAMPolicyCondition(
                operator=condition.operator,
                key=condition.key,
                values=list(condition.values),
            )
        )
    return supported


def _extract_principal_entries(raw_principal: Any) -> list[IAMPrincipal]:
    if raw_principal is None:
        return []
    if isinstance(raw_principal, str):
        return [IAMPrincipal(kind="unknown", value=raw_principal)]
    if isinstance(raw_principal, dict):
        entries: list[IAMPrincipal] = []
        for principal_kind, principal_value in raw_principal.items():
            entries.extend(
                IAMPrincipal(kind=str(principal_kind), value=str(value))
                for value in _as_list(principal_value)
                if value not in (None, "")
            )
        return entries
    if isinstance(raw_principal, list):
        return [IAMPrincipal(kind="unknown", value=str(item)) for item in raw_principal]
    return []


def _lambda_permission_principal_entries(raw_principal: Any) -> list[IAMPrincipal]:
    principals = _compact([raw_principal])
    entries: list[IAMPrincipal] = []
    for principal in principals:
        kind = "Service" if principal.endswith(".amazonaws.com") else "AWS"
        entries.append(IAMPrincipal(kind=kind, value=principal))
    return entries


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


def _compact(values: list[Any]) -> list[str]:
    return [str(value) for value in values if value not in (None, "", [])]


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "enabled", "yes"}:
            return True
        if normalized in {"false", "disabled", "no"}:
            return False
    return bool(value)


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
