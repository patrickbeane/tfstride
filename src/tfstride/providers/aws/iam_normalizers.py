from __future__ import annotations

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.aws.coercion import as_list, compact
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.network_normalizers import AWS_PROVIDER
from tfstride.providers.aws.policy_documents import (
    extract_principals,
    extract_trust_statements,
    load_json_document,
    parse_policy_statements,
)


def normalize_iam_role(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    assume_role_policy = load_json_document(values.get("assume_role_policy"))
    inline_policies = as_list(values.get("inline_policy"))
    statements = []
    for inline_policy in inline_policies:
        statements.extend(parse_policy_statements(load_json_document(inline_policy.get("policy"))))
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=values.get("name") or values.get("id"),
        arn=values.get("arn"),
        policy_statements=statements,
        metadata={
            "assume_role_policy": assume_role_policy,
            "trust_principals": extract_principals(assume_role_policy),
            AwsResourceMetadata.TRUST_STATEMENTS: extract_trust_statements(assume_role_policy),
            "inline_policy_names": [policy.get("name") for policy in inline_policies],
        },
    )


def normalize_iam_policy(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    policy_document = load_json_document(values.get("policy"))
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=values.get("name") or values.get("id"),
        arn=values.get("arn"),
        policy_statements=parse_policy_statements(policy_document),
        metadata={AwsResourceMetadata.POLICY_DOCUMENT: policy_document},
    )


def normalize_iam_role_policy(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    policy_document = load_json_document(values.get("policy"))
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=values.get("id") or resource.address,
        policy_statements=parse_policy_statements(policy_document),
        metadata={
            "role": values.get("role"),
            AwsResourceMetadata.POLICY_DOCUMENT: policy_document,
            "policy_name": values.get("name"),
        },
    )


def normalize_iam_role_policy_attachment(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=values.get("id") or resource.address,
        metadata={
            "role": values.get("role"),
            "policy_arn": values.get("policy_arn"),
        },
    )


def normalize_iam_instance_profile(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    role_references = compact(as_list(values.get("roles")) + [values.get("role")])
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=values.get("name") or values.get("id"),
        arn=values.get("arn"),
        metadata={
            "role_references": role_references,
        },
    )
