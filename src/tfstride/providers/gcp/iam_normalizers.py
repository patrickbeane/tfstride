from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.gcp.coercion import as_list, compact
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.network_normalizers import GCP_PROVIDER
from tfstride.providers.gcp.resource_utils import first_non_empty, load_json_document


def normalize_project_iam_member(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    role = first_non_empty(values.get("role"))
    member = first_non_empty(values.get("member"))
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(values.get("id"), role and member and f"{role}:{member}", resource.address),
        metadata={
            GcpResourceMetadata.PROJECT.key: values.get("project"),
            GcpResourceMetadata.IAM_ROLE.key: role,
            GcpResourceMetadata.IAM_MEMBER.key: member,
            "condition": values.get("condition"),
        },
    )


def normalize_storage_bucket_iam_member(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    bucket = first_non_empty(values.get("bucket"))
    role = first_non_empty(values.get("role"))
    member = first_non_empty(values.get("member"))
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(values.get("id"), _binding_identifier(bucket, role, [member]), resource.address),
        metadata={
            GcpResourceMetadata.BUCKET_NAME.key: bucket,
            GcpResourceMetadata.IAM_ROLE.key: role,
            GcpResourceMetadata.IAM_MEMBER.key: member,
            GcpResourceMetadata.IAM_MEMBERS.key: compact([member]),
            GcpResourceMetadata.IAM_BINDINGS.key: _iam_bindings(role, compact([member])),
            "condition": values.get("condition"),
        },
    )


def normalize_storage_bucket_iam_binding(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    bucket = first_non_empty(values.get("bucket"))
    role = first_non_empty(values.get("role"))
    members = compact(as_list(values.get("members")))
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(values.get("id"), _binding_identifier(bucket, role, members), resource.address),
        metadata={
            GcpResourceMetadata.BUCKET_NAME.key: bucket,
            GcpResourceMetadata.IAM_ROLE.key: role,
            GcpResourceMetadata.IAM_MEMBERS.key: members,
            GcpResourceMetadata.IAM_BINDINGS.key: _iam_bindings(role, members),
            "condition": values.get("condition"),
        },
    )


def normalize_storage_bucket_iam_policy(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    bucket = first_non_empty(values.get("bucket"))
    policy_document = load_json_document(values.get("policy_data"))
    bindings = _policy_bindings(policy_document)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(values.get("id"), bucket, resource.address),
        metadata={
            GcpResourceMetadata.BUCKET_NAME.key: bucket,
            GcpResourceMetadata.IAM_BINDINGS.key: bindings,
            "policy_document": policy_document,
        },
    )


def _policy_bindings(policy_document: dict[str, Any]) -> list[dict[str, Any]]:
    bindings: list[dict[str, Any]] = []
    for binding in as_list(policy_document.get("bindings")):
        if not isinstance(binding, dict):
            continue
        role = first_non_empty(binding.get("role"))
        members = compact(as_list(binding.get("members")))
        bindings.extend(_iam_bindings(role, members))
    return bindings


def _iam_bindings(role: str | None, members: list[str]) -> list[dict[str, Any]]:
    if not role or not members:
        return []
    return [{"role": role, "members": list(members)}]


def _binding_identifier(bucket: str | None, role: str | None, members: list[str | None]) -> str | None:
    normalized_members = compact(list(members))
    if not bucket or not role or not normalized_members:
        return None
    return f"{bucket}:{role}:{','.join(normalized_members)}"