from __future__ import annotations

from tfstride.resource_metadata import (
    BoolDictMetadataField,
    BoolMetadataField,
    DictListMetadataField,
    DictMetadataField,
    OptionalIntMetadataField,
    OptionalStringMetadataField,
    ResourceMetadata,
    StringListMetadataField,
)

AWS_SHARED_CORE_METADATA_FIELD_NAMES = frozenset(
    {
        "PUBLIC_ACCESS_CONFIGURED",
        "PUBLIC_ACCESS_REASONS",
        "PUBLIC_EXPOSURE_REASONS",
    }
)


class AwsResourceMetadata:
    """AWS-owned metadata fields plus shared core fields used by AWS decorators."""

    INTERNET_INGRESS = BoolMetadataField("internet_ingress")
    FRONTED_BY_INTERNET_FACING_LOAD_BALANCER = BoolMetadataField("fronted_by_internet_facing_load_balancer")
    MAP_PUBLIC_IP_ON_LAUNCH = BoolMetadataField("map_public_ip_on_launch")
    BLOCK_PUBLIC_ACLS = BoolMetadataField("block_public_acls")
    BLOCK_PUBLIC_POLICY = BoolMetadataField("block_public_policy")
    IGNORE_PUBLIC_ACLS = BoolMetadataField("ignore_public_acls")
    RESTRICT_PUBLIC_BUCKETS = BoolMetadataField("restrict_public_buckets")

    ROUTE_TABLE_IDS = StringListMetadataField("route_table_ids")
    INTERNET_FACING_LOAD_BALANCER_ADDRESSES = StringListMetadataField("internet_facing_load_balancer_addresses")
    ROLE_REFERENCES = StringListMetadataField("role_references")
    RESOLVED_ROLE_REFERENCES = StringListMetadataField("resolved_role_references")
    RESOLVED_ROLE_ADDRESSES = StringListMetadataField("resolved_role_addresses")
    STANDALONE_RULE_ADDRESSES = StringListMetadataField("standalone_rule_addresses")
    INLINE_POLICY_RESOURCE_ADDRESSES = StringListMetadataField("inline_policy_resource_addresses")
    INLINE_POLICY_NAMES = StringListMetadataField("inline_policy_names")
    UNRESOLVED_ATTACHED_POLICY_ARNS = StringListMetadataField("unresolved_attached_policy_arns")
    ATTACHED_POLICY_ARNS = StringListMetadataField("attached_policy_arns")
    ATTACHED_POLICY_ADDRESSES = StringListMetadataField("attached_policy_addresses")
    UNRESOLVED_ROLE_REFERENCES = StringListMetadataField("unresolved_role_references")
    UNRESOLVED_INSTANCE_PROFILES = StringListMetadataField("unresolved_instance_profiles")
    RESOLVED_INSTANCE_PROFILE_ADDRESSES = StringListMetadataField("resolved_instance_profile_addresses")
    UNRESOLVED_CLUSTER_REFERENCES = StringListMetadataField("unresolved_cluster_references")
    RESOLVED_CLUSTER_ADDRESSES = StringListMetadataField("resolved_cluster_addresses")
    UNRESOLVED_TASK_DEFINITION_REFERENCES = StringListMetadataField("unresolved_task_definition_references")
    RESOLVED_TASK_DEFINITION_ADDRESSES = StringListMetadataField("resolved_task_definition_addresses")
    RESOLVED_TASK_ROLE_ADDRESSES = StringListMetadataField("resolved_task_role_addresses")
    UNRESOLVED_TASK_ROLE_ARNS = StringListMetadataField("unresolved_task_role_arns")
    RESOLVED_EXECUTION_ROLE_ADDRESSES = StringListMetadataField("resolved_execution_role_addresses")
    UNRESOLVED_EXECUTION_ROLE_ARNS = StringListMetadataField("unresolved_execution_role_arns")
    UNRESOLVED_BUCKET_REFERENCES = StringListMetadataField("unresolved_bucket_references")
    UNRESOLVED_SECRET_ARNS = StringListMetadataField("unresolved_secret_arns")
    UNRESOLVED_FUNCTION_REFERENCES = StringListMetadataField("unresolved_function_references")
    REQUIRES_COMPATIBILITIES = StringListMetadataField("requires_compatibilities")
    TRUST_PRINCIPALS = StringListMetadataField("trust_principals")
    RESOURCE_POLICY_SOURCE_ADDRESSES = StringListMetadataField("resource_policy_source_addresses")

    SECURITY_GROUP_ID = OptionalStringMetadataField("security_group_id")
    ROLE_REFERENCE = OptionalStringMetadataField("role")
    IAM_INSTANCE_PROFILE = OptionalStringMetadataField("iam_instance_profile")
    POLICY_ARN = OptionalStringMetadataField("policy_arn")
    POLICY_NAME = OptionalStringMetadataField("policy_name")
    CLUSTER_REFERENCE = OptionalStringMetadataField("cluster")
    NAME = OptionalStringMetadataField("name")
    TASK_DEFINITION_REFERENCE = OptionalStringMetadataField("task_definition")
    TASK_DEFINITION_FAMILY = OptionalStringMetadataField("family")
    NETWORK_MODE = OptionalStringMetadataField("network_mode")
    TASK_ROLE_ARN = OptionalStringMetadataField("task_role_arn")
    EXECUTION_ROLE_ARN = OptionalStringMetadataField("execution_role_arn")
    SECRET_ARN = OptionalStringMetadataField("secret_arn")
    FUNCTION_NAME = OptionalStringMetadataField("function_name")
    ROUTE_TABLE_ID = OptionalStringMetadataField("route_table_id")
    SUBNET_ID = OptionalStringMetadataField("subnet_id")
    BUCKET_NAME = OptionalStringMetadataField("bucket")
    BUCKET_ACL = OptionalStringMetadataField("acl")
    ENGINE = OptionalStringMetadataField("engine")

    TASK_DEFINITION_REVISION = OptionalIntMetadataField("revision")

    POLICY_DOCUMENT = DictMetadataField("policy_document")
    ROUTES = DictListMetadataField("routes")
    TRUST_STATEMENTS = DictListMetadataField("trust_statements")
    PUBLIC_ACCESS_BLOCK = BoolDictMetadataField("public_access_block")

    PUBLIC_ACCESS_CONFIGURED = ResourceMetadata.PUBLIC_ACCESS_CONFIGURED
    PUBLIC_ACCESS_REASONS = ResourceMetadata.PUBLIC_ACCESS_REASONS
    PUBLIC_EXPOSURE_REASONS = ResourceMetadata.PUBLIC_EXPOSURE_REASONS
