from __future__ import annotations

import json
from collections import Counter
from typing import Any

from cloud_threat_modeler.models import (
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
    "aws_lb",
    "aws_db_instance",
    "aws_s3_bucket",
    "aws_s3_bucket_public_access_block",
    "aws_iam_role",
    "aws_iam_policy",
    "aws_iam_role_policy_attachment",
    "aws_lambda_function",
    "aws_subnet",
    "aws_vpc",
    "aws_internet_gateway",
    "aws_route_table",
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
        if resource.resource_type == "aws_instance":
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
                public_exposure=bool(values.get("associate_public_ip_address", False)),
                metadata={
                    "ami": values.get("ami"),
                    "instance_type": values.get("instance_type"),
                    "associate_public_ip_address": bool(values.get("associate_public_ip_address", False)),
                    "tags": values.get("tags", {}),
                },
            )
        if resource.resource_type == "aws_lb":
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
                public_exposure=not bool(values.get("internal", False)),
                metadata={
                    "internal": bool(values.get("internal", False)),
                    "load_balancer_type": values.get("load_balancer_type"),
                },
            )
        if resource.resource_type == "aws_db_instance":
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.DATA,
                identifier=values.get("id") or values.get("identifier"),
                arn=values.get("arn"),
                security_group_ids=_as_list(values.get("vpc_security_group_ids")),
                public_exposure=bool(values.get("publicly_accessible", False)),
                data_sensitivity="sensitive",
                metadata={
                    "engine": values.get("engine"),
                    "publicly_accessible": bool(values.get("publicly_accessible", False)),
                    "storage_encrypted": bool(values.get("storage_encrypted", False)),
                    "db_subnet_group_name": values.get("db_subnet_group_name"),
                },
            )
        if resource.resource_type == "aws_s3_bucket":
            policy_document = _load_json_document(values.get("policy"))
            bucket_acl = values.get("acl", "")
            public_policy = _policy_allows_public_access(policy_document)
            return NormalizedResource(
                address=resource.address,
                provider=self.provider,
                resource_type=resource.resource_type,
                name=resource.name,
                category=ResourceCategory.DATA,
                identifier=values.get("bucket") or values.get("id"),
                arn=values.get("arn"),
                public_exposure=bucket_acl in {"public-read", "public-read-write", "website"} or public_policy,
                data_sensitivity="sensitive",
                metadata={
                    "bucket": values.get("bucket"),
                    "acl": bucket_acl,
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
        raise ValueError(f"Unsupported resource type reached normalizer: {resource.resource_type}")

    def _decorate_resources(self, resources: list[NormalizedResource]) -> None:
        subnets = {resource.identifier: resource for resource in resources if resource.resource_type == "aws_subnet"}
        security_groups = {
            resource.identifier: resource for resource in resources if resource.resource_type == "aws_security_group"
        }
        buckets = {
            key: resource
            for resource in resources
            if resource.resource_type == "aws_s3_bucket"
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
            bucket.public_exposure = (
                public_via_acl and not (public_access_block["block_public_acls"] or public_access_block["ignore_public_acls"])
            ) or (
                public_via_policy
                and not (public_access_block["block_public_policy"] or public_access_block["restrict_public_buckets"])
            )

        public_subnet_ids = set()
        for subnet in subnets.values():
            # v1 intentionally uses a simple heuristic: a subnet is "public" when it both
            # auto-assigns public IPs and lives in a VPC that has an IGW-backed default route.
            is_public = bool(subnet.metadata.get("map_public_ip_on_launch")) and subnet.vpc_id in vpcs_with_igw.intersection(
                vpcs_with_public_routes
            )
            subnet.metadata["is_public_subnet"] = is_public
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
            resource.metadata["internet_ingress"] = internet_ingress
            resource.metadata["public_subnet"] = any(subnet_id in public_subnet_ids for subnet_id in resource.subnet_ids)
            # Public exposure is inferred conservatively from network placement and ingress
            # rules so later detectors can reason over a normalized signal instead of
            # provider-specific fields.
            if resource.resource_type == "aws_instance":
                resource.public_exposure = resource.public_exposure or (
                    resource.metadata["public_subnet"] and internet_ingress
                )
            elif resource.resource_type == "aws_db_instance":
                resource.public_exposure = resource.public_exposure or internet_ingress


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
            )
        )
    return statements


def _extract_principals(policy_document: dict[str, Any]) -> list[str]:
    principals: list[str] = []
    for statement in _parse_policy_statements(policy_document):
        principals.extend(statement.principals)
    return sorted(set(principals))


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


def _has_internet_route(routes: list[dict[str, Any]]) -> bool:
    for route in routes:
        destination = route.get("cidr_block") or route.get("destination_cidr_block")
        gateway_id = route.get("gateway_id")
        if destination == "0.0.0.0/0" and isinstance(gateway_id, str) and gateway_id.startswith("igw-"):
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
        )
        for statement in statements
    ]


def _append_unique(metadata: dict[str, Any], key: str, value: str | None) -> None:
    if not value:
        return
    values = metadata.setdefault(key, [])
    if value not in values:
        values.append(value)


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
