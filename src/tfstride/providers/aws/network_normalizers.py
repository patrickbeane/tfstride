from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, SecurityGroupRule, TerraformResource
from tfstride.providers.aws.coercion import as_list, as_optional_int, compact
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.resource_mutations import aws_mutations
from tfstride.providers.coercion import (
    attribute_unknown,
    bool_state,
    dedupe,
    first_mapping,
    known_block_bool,
    known_block_string,
    known_block_strings,
    known_bool,
    known_string,
    known_string_list,
    unknown_block_at,
)
from tfstride.providers.json_documents import load_json_document

AWS_PROVIDER = "aws"


def normalize_vpc(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=values.get("id"),
        metadata={AwsResourceMetadata.CIDR_BLOCK: values.get("cidr_block"), "tags": values.get("tags", {})},
    )


def normalize_subnet(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=values.get("id"),
        vpc_id=values.get("vpc_id"),
        metadata={
            AwsResourceMetadata.CIDR_BLOCK: values.get("cidr_block"),
            "availability_zone": values.get("availability_zone"),
            "map_public_ip_on_launch": bool(values.get("map_public_ip_on_launch", False)),
            "tags": values.get("tags", {}),
        },
    )


def normalize_internet_gateway(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=values.get("id"),
        vpc_id=values.get("vpc_id"),
    )


def normalize_route_table(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=values.get("id"),
        vpc_id=values.get("vpc_id"),
        metadata={"routes": as_list(values.get("route") or values.get("routes"))},
    )


def normalize_route_table_association(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
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


def normalize_security_group(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=values.get("id"),
        vpc_id=values.get("vpc_id"),
        network_rules=parse_security_group_rules(values),
        metadata={
            "description": values.get("description"),
            "group_name": values.get("name"),
        },
    )


def normalize_security_group_rule(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=values.get("id") or resource.address,
        network_rules=[parse_standalone_security_group_rule(values)],
        metadata={"security_group_id": values.get("security_group_id")},
    )


def normalize_nat_gateway(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=values.get("id"),
        subnet_ids=tuple(compact([values.get("subnet_id")])),
        metadata={
            "allocation_id": values.get("allocation_id"),
            "connectivity_type": values.get("connectivity_type", "public"),
        },
    )


def normalize_flow_log(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []

    flow_log_id = known_string(values, unknown_values, "id", uncertainties)
    target_type, target_id = _flow_log_target(values, unknown_values, uncertainties)

    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=flow_log_id or target_id or resource.address,
        vpc_id=target_id if target_type == "vpc" else None,
        metadata={
            AwsResourceMetadata.NAME: resource.name,
            AwsResourceMetadata.FLOW_LOG_ID: flow_log_id,
            AwsResourceMetadata.FLOW_LOG_TARGET_TYPE: target_type,
            AwsResourceMetadata.FLOW_LOG_TARGET_ID: target_id,
            AwsResourceMetadata.FLOW_LOG_TRAFFIC_TYPE: known_string(
                values, unknown_values, "traffic_type", uncertainties
            ),
            AwsResourceMetadata.FLOW_LOG_DESTINATION_TYPE: known_string(
                values, unknown_values, "log_destination_type", uncertainties
            ),
            AwsResourceMetadata.FLOW_LOG_DESTINATION: known_string(
                values, unknown_values, "log_destination", uncertainties
            ),
            AwsResourceMetadata.FLOW_LOG_LOG_GROUP_NAME: known_string(
                values, unknown_values, "log_group_name", uncertainties
            ),
            AwsResourceMetadata.FLOW_LOG_IAM_ROLE_ARN: known_string(
                values, unknown_values, "iam_role_arn", uncertainties
            ),
            AwsResourceMetadata.FLOW_LOG_MAX_AGGREGATION_INTERVAL: _known_int(
                values, unknown_values, "max_aggregation_interval", uncertainties
            ),
            AwsResourceMetadata.FLOW_LOG_DESTINATION_OPTIONS: _flow_log_destination_options(
                values, unknown_values, uncertainties
            ),
            AwsResourceMetadata.FLOW_LOG_POSTURE_UNCERTAINTIES: uncertainties,
            "tags": values.get("tags", {}),
        },
    )


def normalize_vpc_endpoint(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []

    endpoint_id = known_string(values, unknown_values, "id", uncertainties)
    service_name = known_string(values, unknown_values, "service_name", uncertainties)
    endpoint_type = known_string(values, unknown_values, "vpc_endpoint_type", uncertainties)
    vpc_id = known_string(values, unknown_values, "vpc_id", uncertainties)
    private_dns_enabled = known_bool(
        values,
        unknown_values,
        "private_dns_enabled",
        uncertainties,
        allow_string=False,
    )
    route_table_ids = known_string_list(values, unknown_values, "route_table_ids", uncertainties)
    subnet_ids = known_string_list(values, unknown_values, "subnet_ids", uncertainties)
    security_group_ids = known_string_list(values, unknown_values, "security_group_ids", uncertainties)
    policy_document = _vpc_endpoint_policy_document(values, unknown_values, uncertainties)
    dns_entries = _vpc_endpoint_dns_entries(values, unknown_values, uncertainties)

    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=endpoint_id or service_name or resource.address,
        vpc_id=vpc_id,
        subnet_ids=tuple(subnet_ids),
        security_group_ids=tuple(security_group_ids),
        metadata={
            AwsResourceMetadata.VPC_ENDPOINT_ID: endpoint_id,
            AwsResourceMetadata.VPC_ENDPOINT_SERVICE_NAME: service_name,
            AwsResourceMetadata.VPC_ENDPOINT_SERVICE_FAMILY: _vpc_endpoint_service_family(service_name),
            AwsResourceMetadata.VPC_ENDPOINT_TYPE: endpoint_type,
            AwsResourceMetadata.VPC_ENDPOINT_VPC_ID: vpc_id,
            AwsResourceMetadata.VPC_ENDPOINT_ROUTE_TABLE_IDS: route_table_ids,
            AwsResourceMetadata.VPC_ENDPOINT_SUBNET_IDS: subnet_ids,
            AwsResourceMetadata.VPC_ENDPOINT_SECURITY_GROUP_IDS: security_group_ids,
            AwsResourceMetadata.VPC_ENDPOINT_PRIVATE_DNS_ENABLED_STATE: bool_state(private_dns_enabled),
            AwsResourceMetadata.VPC_ENDPOINT_POLICY_DOCUMENT: policy_document,
            AwsResourceMetadata.VPC_ENDPOINT_DNS_ENTRIES: dns_entries,
            AwsResourceMetadata.VPC_ENDPOINT_DNS_NAMES: compact(entry.get("dns_name") for entry in dns_entries),
            AwsResourceMetadata.VPC_ENDPOINT_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_cloudfront_distribution(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []

    distribution_id = known_string(values, unknown_values, "id", uncertainties)
    arn = known_string(values, unknown_values, "arn", uncertainties)
    domain_name = known_string(values, unknown_values, "domain_name", uncertainties)
    enabled = known_bool(values, unknown_values, "enabled", uncertainties, allow_string=False)
    ipv6_enabled = known_bool(values, unknown_values, "is_ipv6_enabled", uncertainties, allow_string=False)
    aliases = known_string_list(values, unknown_values, "aliases", uncertainties)
    default_cache_behavior = _cloudfront_default_cache_behavior(values, unknown_values, uncertainties)
    ordered_cache_behaviors = _cloudfront_ordered_cache_behaviors(values, unknown_values, uncertainties)
    origins = _cloudfront_origins(values, unknown_values, uncertainties)
    viewer_certificate = _cloudfront_viewer_certificate(values, unknown_values, uncertainties)
    logging_config, logging_state = _cloudfront_logging_config(values, unknown_values, uncertainties)

    is_enabled = enabled is True
    normalized = NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=distribution_id or arn or domain_name or resource.address,
        arn=arn,
        public_access_configured=is_enabled,
        public_exposure=is_enabled,
        metadata={
            AwsResourceMetadata.NAME: known_string(values, unknown_values, "comment", uncertainties) or resource.name,
            AwsResourceMetadata.CLOUDFRONT_DISTRIBUTION_ID: distribution_id,
            AwsResourceMetadata.CLOUDFRONT_DISTRIBUTION_ARN: arn,
            AwsResourceMetadata.CLOUDFRONT_DOMAIN_NAME: domain_name,
            AwsResourceMetadata.CLOUDFRONT_ENABLED_STATE: bool_state(enabled),
            AwsResourceMetadata.CLOUDFRONT_IPV6_ENABLED_STATE: bool_state(ipv6_enabled),
            AwsResourceMetadata.CLOUDFRONT_HTTP_VERSION: known_string(
                values, unknown_values, "http_version", uncertainties
            ),
            AwsResourceMetadata.CLOUDFRONT_DEFAULT_ROOT_OBJECT: known_string(
                values, unknown_values, "default_root_object", uncertainties
            ),
            AwsResourceMetadata.CLOUDFRONT_ALIASES: aliases,
            AwsResourceMetadata.CLOUDFRONT_WEB_ACL_ID: known_string(
                values, unknown_values, "web_acl_id", uncertainties
            ),
            AwsResourceMetadata.CLOUDFRONT_ORIGINS: origins,
            AwsResourceMetadata.CLOUDFRONT_ORIGIN_IDS: compact(origin.get("origin_id") for origin in origins),
            AwsResourceMetadata.CLOUDFRONT_ORIGIN_DOMAIN_NAMES: compact(
                origin.get("domain_name") for origin in origins
            ),
            AwsResourceMetadata.CLOUDFRONT_DEFAULT_CACHE_BEHAVIOR: default_cache_behavior,
            AwsResourceMetadata.CLOUDFRONT_DEFAULT_VIEWER_PROTOCOL_POLICY: default_cache_behavior.get(
                "viewer_protocol_policy"
            ),
            AwsResourceMetadata.CLOUDFRONT_DEFAULT_ALLOWED_METHODS: default_cache_behavior.get("allowed_methods", []),
            AwsResourceMetadata.CLOUDFRONT_DEFAULT_CACHED_METHODS: default_cache_behavior.get("cached_methods", []),
            AwsResourceMetadata.CLOUDFRONT_ORDERED_CACHE_BEHAVIORS: ordered_cache_behaviors,
            AwsResourceMetadata.CLOUDFRONT_ORDERED_VIEWER_PROTOCOL_POLICIES: compact(
                behavior.get("viewer_protocol_policy") for behavior in ordered_cache_behaviors
            ),
            AwsResourceMetadata.CLOUDFRONT_VIEWER_CERTIFICATE: viewer_certificate,
            AwsResourceMetadata.CLOUDFRONT_VIEWER_CERTIFICATE_SOURCE: viewer_certificate.get("certificate_source"),
            AwsResourceMetadata.CLOUDFRONT_DEFAULT_CERTIFICATE_STATE: viewer_certificate.get(
                "cloudfront_default_certificate_state"
            ),
            AwsResourceMetadata.CLOUDFRONT_MINIMUM_PROTOCOL_VERSION: viewer_certificate.get("minimum_protocol_version"),
            AwsResourceMetadata.CLOUDFRONT_SSL_SUPPORT_METHOD: viewer_certificate.get("ssl_support_method"),
            AwsResourceMetadata.CLOUDFRONT_ACM_CERTIFICATE_ARN: viewer_certificate.get("acm_certificate_arn"),
            AwsResourceMetadata.CLOUDFRONT_IAM_CERTIFICATE_ID: viewer_certificate.get("iam_certificate_id"),
            AwsResourceMetadata.CLOUDFRONT_LOGGING_STATE: logging_state,
            AwsResourceMetadata.CLOUDFRONT_LOGGING_CONFIG: logging_config,
            AwsResourceMetadata.CLOUDFRONT_LOGGING_BUCKET: logging_config.get("bucket_name"),
            AwsResourceMetadata.CLOUDFRONT_LOGGING_PREFIX: logging_config.get("prefix"),
            AwsResourceMetadata.CLOUDFRONT_POSTURE_UNCERTAINTIES: uncertainties,
            "tags": values.get("tags", {}),
        },
    )
    reasons = ["CloudFront distribution is enabled"] if is_enabled else []
    mutations = aws_mutations(normalized)
    mutations.set_public_access_reasons(reasons)
    mutations.set_public_exposure_reasons(reasons)
    return normalized


def normalize_load_balancer(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    internet_facing = not bool(values.get("internal", False))
    public_access_reasons = ["load balancer is configured as internet-facing"] if internet_facing else []
    normalized = NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=values.get("id"),
        arn=values.get("arn"),
        subnet_ids=tuple(as_list(values.get("subnets"))),
        security_group_ids=tuple(as_list(values.get("security_groups"))),
        public_access_configured=internet_facing,
        metadata={
            "internal": not internet_facing,
            AwsResourceMetadata.LOAD_BALANCER_TYPE: values.get("load_balancer_type"),
        },
    )
    mutations = aws_mutations(normalized)
    mutations.set_public_access_reasons(public_access_reasons)
    mutations.set_public_exposure_reasons([])
    return normalized


def normalize_load_balancer_listener(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    protocol = known_string(values, unknown_values, "protocol", uncertainties)
    certificate_arn = known_string(values, unknown_values, "certificate_arn", uncertainties)
    ssl_policy = known_string(values, unknown_values, "ssl_policy", uncertainties)
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=values.get("id") or values.get("arn"),
        arn=values.get("arn"),
        metadata={
            AwsResourceMetadata.LOAD_BALANCER_ARN: values.get("load_balancer_arn"),
            AwsResourceMetadata.LOAD_BALANCER_TARGET_GROUP_ARNS: _load_balancer_action_target_group_arns(
                values.get("default_action")
            ),
            "port": as_optional_int(values.get("port")),
            "protocol": protocol,
            AwsResourceMetadata.LOAD_BALANCER_LISTENER_PROTOCOL: protocol,
            AwsResourceMetadata.LOAD_BALANCER_LISTENER_CERTIFICATE_ARN: certificate_arn,
            AwsResourceMetadata.LOAD_BALANCER_LISTENER_SSL_POLICY: ssl_policy,
            AwsResourceMetadata.LOAD_BALANCER_LISTENER_TLS_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_load_balancer_listener_rule(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=values.get("id") or values.get("arn"),
        arn=values.get("arn"),
        metadata={
            AwsResourceMetadata.LISTENER_ARN: values.get("listener_arn"),
            AwsResourceMetadata.LOAD_BALANCER_TARGET_GROUP_ARNS: _load_balancer_action_target_group_arns(
                values.get("action")
            ),
            "listener_rule_priority": as_optional_int(values.get("priority")),
        },
    )


def normalize_load_balancer_target_group(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=values.get("id") or values.get("arn") or values.get("name"),
        arn=values.get("arn"),
        vpc_id=values.get("vpc_id"),
        metadata={
            "name": values.get("name"),
            "port": as_optional_int(values.get("port")),
            "protocol": values.get("protocol"),
            "target_type": values.get("target_type"),
        },
    )


def normalize_wafv2_web_acl(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []

    web_acl_id = known_string(values, unknown_values, "id", uncertainties)
    name = known_string(values, unknown_values, "name", uncertainties) or resource.name
    arn = known_string(values, unknown_values, "arn", uncertainties)
    scope = known_string(values, unknown_values, "scope", uncertainties)
    default_action, default_action_evidence = _web_acl_default_action(values, unknown_values, uncertainties)
    rules = _web_acl_rules(values, unknown_values, uncertainties)

    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=arn or web_acl_id or name or resource.address,
        arn=arn,
        metadata={
            AwsResourceMetadata.WEB_ACL_ID: web_acl_id,
            AwsResourceMetadata.WEB_ACL_NAME: name,
            AwsResourceMetadata.WEB_ACL_ARN: arn,
            AwsResourceMetadata.WEB_ACL_SCOPE: scope,
            AwsResourceMetadata.WEB_ACL_DEFAULT_ACTION: default_action,
            AwsResourceMetadata.WEB_ACL_DEFAULT_ACTION_EVIDENCE: default_action_evidence,
            AwsResourceMetadata.WEB_ACL_RULES: rules,
            AwsResourceMetadata.WEB_ACL_RULE_NAMES: compact(rule.get("name") for rule in rules),
            AwsResourceMetadata.EDGE_PROTECTION_POSTURE_UNCERTAINTIES: uncertainties,
            "tags": values.get("tags", {}),
        },
    )


def normalize_wafv2_web_acl_association(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []

    resource_arn = known_string(values, unknown_values, "resource_arn", uncertainties)
    web_acl_arn = known_string(values, unknown_values, "web_acl_arn", uncertainties)
    association_id = known_string(values, unknown_values, "id", uncertainties)

    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=association_id or resource_arn or resource.address,
        metadata={
            AwsResourceMetadata.WEB_ACL_ASSOCIATION_RESOURCE_ARN: resource_arn,
            AwsResourceMetadata.WEB_ACL_ASSOCIATION_WEB_ACL_ARN: web_acl_arn,
            AwsResourceMetadata.EDGE_PROTECTION_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def _web_acl_default_action(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    uncertainties: list[str],
) -> tuple[str | None, dict[str, Any]]:
    if attribute_unknown(unknown_values, "default_action"):
        uncertainties.append("default_action is unknown after planning")
        return "unknown", {}
    action = first_mapping(values.get("default_action"), expand_tuples=True, scan_all=True)
    if action is None:
        return None, {}
    evidence = dict(action)
    if action.get("allow") not in (None, [], {}):
        return "allow", evidence
    if action.get("block") not in (None, [], {}):
        return "block", evidence
    return "unknown", evidence


def _web_acl_rules(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    uncertainties: list[str],
) -> list[dict[str, Any]]:
    if attribute_unknown(unknown_values, "rule"):
        uncertainties.append("rule is unknown after planning")
        return []
    rules: list[dict[str, Any]] = []
    for rule in as_list(values.get("rule")):
        if isinstance(rule, Mapping):
            rules.append(dict(rule))
    return rules


def _cloudfront_default_cache_behavior(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    uncertainties: list[str],
) -> dict[str, Any]:
    behavior, unknown_block = _first_cloudfront_block(values, unknown_values, "default_cache_behavior", uncertainties)
    if behavior is None:
        return {}
    return _compact_record(
        {
            "target_origin_id": known_block_string(
                behavior, unknown_block, "target_origin_id", uncertainties, path="default_cache_behavior"
            ),
            "viewer_protocol_policy": known_block_string(
                behavior, unknown_block, "viewer_protocol_policy", uncertainties, path="default_cache_behavior"
            ),
            "cache_policy_id": known_block_string(
                behavior, unknown_block, "cache_policy_id", uncertainties, path="default_cache_behavior"
            ),
            "origin_request_policy_id": known_block_string(
                behavior, unknown_block, "origin_request_policy_id", uncertainties, path="default_cache_behavior"
            ),
            "response_headers_policy_id": known_block_string(
                behavior, unknown_block, "response_headers_policy_id", uncertainties, path="default_cache_behavior"
            ),
            "allowed_methods": known_block_strings(
                behavior, unknown_block, "allowed_methods", uncertainties, path="default_cache_behavior"
            ),
            "cached_methods": known_block_strings(
                behavior, unknown_block, "cached_methods", uncertainties, path="default_cache_behavior"
            ),
        }
    )


def _cloudfront_ordered_cache_behaviors(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    uncertainties: list[str],
) -> list[dict[str, Any]]:
    unknown_collection = _unknown_value(unknown_values, "ordered_cache_behavior")
    if unknown_collection is True:
        uncertainties.append("ordered_cache_behavior is unknown after planning")
        return []
    behaviors: list[dict[str, Any]] = []
    for index, behavior in enumerate(as_list(values.get("ordered_cache_behavior"))):
        if not isinstance(behavior, Mapping):
            uncertainties.append("ordered_cache_behavior has an unrecognized value shape")
            continue
        unknown_block = unknown_block_at(unknown_collection, index)
        record = _compact_record(
            {
                "path_pattern": known_block_string(
                    behavior, unknown_block, "path_pattern", uncertainties, path="ordered_cache_behavior"
                ),
                "target_origin_id": known_block_string(
                    behavior, unknown_block, "target_origin_id", uncertainties, path="ordered_cache_behavior"
                ),
                "viewer_protocol_policy": known_block_string(
                    behavior, unknown_block, "viewer_protocol_policy", uncertainties, path="ordered_cache_behavior"
                ),
                "cache_policy_id": known_block_string(
                    behavior, unknown_block, "cache_policy_id", uncertainties, path="ordered_cache_behavior"
                ),
                "allowed_methods": known_block_strings(
                    behavior, unknown_block, "allowed_methods", uncertainties, path="ordered_cache_behavior"
                ),
                "cached_methods": known_block_strings(
                    behavior, unknown_block, "cached_methods", uncertainties, path="ordered_cache_behavior"
                ),
            }
        )
        if record:
            behaviors.append(record)
    return behaviors


def _cloudfront_origins(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    uncertainties: list[str],
) -> list[dict[str, Any]]:
    unknown_collection = _unknown_value(unknown_values, "origin")
    if unknown_collection is True:
        uncertainties.append("origin is unknown after planning")
        return []
    origins: list[dict[str, Any]] = []
    for index, origin in enumerate(as_list(values.get("origin"))):
        if not isinstance(origin, Mapping):
            uncertainties.append("origin has an unrecognized value shape")
            continue
        unknown_block = unknown_block_at(unknown_collection, index)
        record = _compact_record(
            {
                "origin_id": known_block_string(origin, unknown_block, "origin_id", uncertainties, path="origin"),
                "domain_name": known_block_string(origin, unknown_block, "domain_name", uncertainties, path="origin"),
                "origin_path": known_block_string(origin, unknown_block, "origin_path", uncertainties, path="origin"),
            }
        )
        custom_origin_config = first_mapping(origin.get("custom_origin_config"), expand_tuples=True)
        if custom_origin_config is not None:
            record["custom_origin_config"] = dict(custom_origin_config)
        s3_origin_config = first_mapping(origin.get("s3_origin_config"), expand_tuples=True)
        if s3_origin_config is not None:
            record["s3_origin_config"] = dict(s3_origin_config)
        if record:
            origins.append(record)
    return origins


def _cloudfront_viewer_certificate(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    uncertainties: list[str],
) -> dict[str, Any]:
    certificate, unknown_block = _first_cloudfront_block(values, unknown_values, "viewer_certificate", uncertainties)
    if certificate is None:
        return {}
    unknown_fields: list[str] = []
    default_certificate = known_block_bool(
        certificate,
        unknown_block,
        "cloudfront_default_certificate",
        uncertainties,
        path="viewer_certificate",
        unknown_fields=unknown_fields,
    )
    acm_certificate_arn = known_block_string(
        certificate,
        unknown_block,
        "acm_certificate_arn",
        uncertainties,
        path="viewer_certificate",
        unknown_fields=unknown_fields,
    )
    iam_certificate_id = known_block_string(
        certificate,
        unknown_block,
        "iam_certificate_id",
        uncertainties,
        path="viewer_certificate",
        unknown_fields=unknown_fields,
    )
    minimum_protocol_version = known_block_string(
        certificate,
        unknown_block,
        "minimum_protocol_version",
        uncertainties,
        path="viewer_certificate",
        unknown_fields=unknown_fields,
    )
    ssl_support_method = known_block_string(
        certificate,
        unknown_block,
        "ssl_support_method",
        uncertainties,
        path="viewer_certificate",
        unknown_fields=unknown_fields,
    )
    default_certificate_state = bool_state(default_certificate)
    return _compact_record(
        {
            "certificate_source": _cloudfront_certificate_source(
                default_certificate, acm_certificate_arn, iam_certificate_id, unknown_fields
            ),
            "cloudfront_default_certificate_state": default_certificate_state,
            "acm_certificate_arn": acm_certificate_arn,
            "iam_certificate_id": iam_certificate_id,
            "minimum_protocol_version": minimum_protocol_version,
            "ssl_support_method": ssl_support_method,
        }
    )


def _cloudfront_logging_config(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    uncertainties: list[str],
) -> tuple[dict[str, Any], str]:
    logging_config, unknown_block = _first_cloudfront_block(values, unknown_values, "logging_config", uncertainties)
    if unknown_block is True:
        return {}, "unknown"
    if logging_config is None:
        return {}, "not_configured"
    unknown_fields: list[str] = []
    bucket = known_block_string(
        logging_config,
        unknown_block,
        "bucket",
        uncertainties,
        path="logging_config",
        unknown_fields=unknown_fields,
    )
    prefix = known_block_string(
        logging_config,
        unknown_block,
        "prefix",
        uncertainties,
        path="logging_config",
        unknown_fields=unknown_fields,
    )
    include_cookies = known_block_bool(
        logging_config,
        unknown_block,
        "include_cookies",
        uncertainties,
        path="logging_config",
        unknown_fields=unknown_fields,
    )
    state = "configured" if bucket else "unknown" if "bucket" in unknown_fields else "not_configured"
    return (
        _compact_record(
            {
                "bucket_name": bucket,
                "prefix": prefix,
                "include_cookies": include_cookies,
            }
        ),
        state,
    )


def _cloudfront_certificate_source(
    default_certificate: bool | None,
    acm_certificate_arn: str | None,
    iam_certificate_id: str | None,
    unknown_fields: list[str],
) -> str | None:
    if default_certificate is True:
        return "cloudfront_default"
    if acm_certificate_arn:
        return "acm"
    if iam_certificate_id:
        return "iam"
    if unknown_fields:
        return "unknown"
    return None


def _first_cloudfront_block(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    key: str,
    uncertainties: list[str],
) -> tuple[Mapping[str, Any] | None, Any]:
    unknown_value = _unknown_value(unknown_values, key)
    if unknown_value is True:
        uncertainties.append(f"{key} is unknown after planning")
        return None, unknown_value
    raw = values.get(key)
    unknown_block = unknown_block_at(unknown_value, 0)
    if raw in (None, [], {}):
        if unknown_block not in (None, False, [], {}):
            return {}, unknown_block
        return None, unknown_block
    block = first_mapping(raw, expand_tuples=True)
    if block is None:
        uncertainties.append(f"{key} has an unrecognized value shape")
    return block, unknown_block_at(unknown_value, 0)


def _unknown_value(unknown_values: Mapping[str, Any] | None, key: str) -> Any:
    return unknown_values.get(key) if isinstance(unknown_values, Mapping) else None


def _compact_record(values: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in values.items() if value not in (None, "", [], {})}


_FLOW_LOG_TARGET_FIELDS = (
    ("vpc", "vpc_id"),
    ("subnet", "subnet_id"),
    ("network_interface", "eni_id"),
    ("transit_gateway", "transit_gateway_id"),
    ("transit_gateway_attachment", "transit_gateway_attachment_id"),
)


def _flow_log_target(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    uncertainties: list[str],
) -> tuple[str | None, str | None]:
    targets: list[tuple[str, str]] = []
    for target_type, key in _FLOW_LOG_TARGET_FIELDS:
        target_id = known_string(values, unknown_values, key, uncertainties)
        if target_id:
            targets.append((target_type, target_id))

    if len(targets) > 1:
        configured_fields = ", ".join(key for _, key in _FLOW_LOG_TARGET_FIELDS if values.get(key))
        uncertainties.append(f"multiple Flow Log target fields are configured: {configured_fields}")
    return targets[0] if targets else (None, None)


def _flow_log_destination_options(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    uncertainties: list[str],
) -> dict[str, Any]:
    if attribute_unknown(unknown_values, "destination_options"):
        uncertainties.append("destination_options is unknown after planning")
        return {}
    for option in as_list(values.get("destination_options")):
        if isinstance(option, Mapping):
            return dict(option)
    return {}


def _known_int(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    key: str,
    uncertainties: list[str],
) -> int | None:
    if attribute_unknown(unknown_values, key):
        uncertainties.append(f"{key} is unknown after planning")
        return None
    value = values.get(key)
    if value is None or value == "":
        return None
    parsed = as_optional_int(value)
    if parsed is None:
        uncertainties.append(f"{key} has an unrecognized value shape")
    return parsed


def _vpc_endpoint_policy_document(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    uncertainties: list[str],
) -> dict[str, Any]:
    if attribute_unknown(unknown_values, "policy"):
        uncertainties.append("policy is unknown after planning")
        return {}
    return load_json_document(values.get("policy"))


def _vpc_endpoint_dns_entries(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    uncertainties: list[str],
) -> list[dict[str, Any]]:
    if attribute_unknown(unknown_values, "dns_entry"):
        uncertainties.append("dns_entry is unknown after planning")
        return []
    entries: list[dict[str, Any]] = []
    for entry in as_list(values.get("dns_entry")):
        if isinstance(entry, Mapping):
            entries.append(dict(entry))
    return entries


def _vpc_endpoint_service_family(service_name: str | None) -> str | None:
    if not service_name:
        return None
    parts = [part for part in service_name.strip().lower().split(".") if part]
    if not parts:
        return None
    last = parts[-1]
    if last == "s3":
        return "s3"
    if last == "secretsmanager":
        return "secretsmanager"
    if last == "kms":
        return "kms"
    if "ecr" in parts:
        return "ecr"
    if last == "sts":
        return "sts"
    if last in {"logs", "monitoring"}:
        return "cloudwatch"
    return None


def parse_security_group_rules(values: dict[str, Any]) -> list[SecurityGroupRule]:
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


def parse_standalone_security_group_rule(values: dict[str, Any]) -> SecurityGroupRule:
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


def _load_balancer_action_target_group_arns(actions: Any) -> list[str]:
    target_group_arns: list[str] = []
    for action in as_list(actions):
        if not isinstance(action, dict):
            continue
        target_group_arn = action.get("target_group_arn")
        if target_group_arn:
            target_group_arns.append(str(target_group_arn))
        for forward in as_list(action.get("forward")):
            if not isinstance(forward, dict):
                continue
            for target_group in as_list(forward.get("target_group")):
                if not isinstance(target_group, dict):
                    continue
                target_group_arn = target_group.get("arn")
                if target_group_arn:
                    target_group_arns.append(str(target_group_arn))
    return dedupe(target_group_arns)
