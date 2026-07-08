from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.gcp.attributes import GcpAttr, GcpAttribute, GcpValues
from tfstride.providers.gcp.coercion import compact
from tfstride.providers.gcp.iam_normalizer_utils import (
    _binding_identifier,
    _condition,
    _iam_bindings,
    _policy_bindings,
    _target_reference,
)
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer_common import GCP_PROVIDER
from tfstride.providers.gcp.resource_utils import first_non_empty
from tfstride.providers.json_documents import load_json_document


def normalize_organization_iam_member(resource: TerraformResource) -> NormalizedResource:
    return _normalize_scope_iam_member(
        resource,
        scope_field=GcpResourceMetadata.ORGANIZATION_ID,
        scope_keys=(GcpAttr.ORG_ID, GcpAttr.ORGANIZATION_ID, GcpAttr.ORGANIZATION),
    )


def normalize_organization_iam_binding(resource: TerraformResource) -> NormalizedResource:
    return _normalize_scope_iam_binding(
        resource,
        scope_field=GcpResourceMetadata.ORGANIZATION_ID,
        scope_keys=(GcpAttr.ORG_ID, GcpAttr.ORGANIZATION_ID, GcpAttr.ORGANIZATION),
    )


def normalize_organization_iam_policy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_scope_iam_policy(
        resource,
        scope_field=GcpResourceMetadata.ORGANIZATION_ID,
        scope_keys=(GcpAttr.ORG_ID, GcpAttr.ORGANIZATION_ID, GcpAttr.ORGANIZATION),
    )


def normalize_folder_iam_member(resource: TerraformResource) -> NormalizedResource:
    return _normalize_scope_iam_member(
        resource,
        scope_field=GcpResourceMetadata.FOLDER_ID,
        scope_keys=(GcpAttr.FOLDER, GcpAttr.FOLDER_ID),
    )


def normalize_folder_iam_binding(resource: TerraformResource) -> NormalizedResource:
    return _normalize_scope_iam_binding(
        resource,
        scope_field=GcpResourceMetadata.FOLDER_ID,
        scope_keys=(GcpAttr.FOLDER, GcpAttr.FOLDER_ID),
    )


def normalize_folder_iam_policy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_scope_iam_policy(
        resource,
        scope_field=GcpResourceMetadata.FOLDER_ID,
        scope_keys=(GcpAttr.FOLDER, GcpAttr.FOLDER_ID),
    )


def _normalize_scope_iam_member(
    resource: TerraformResource,
    *,
    scope_field: Any,
    scope_keys: tuple[GcpAttribute[Any], ...],
) -> NormalizedResource:
    values = GcpValues(resource.values)
    scope_reference = _target_reference(values, scope_keys)
    role = first_non_empty(values.get(GcpAttr.ROLE))
    member = first_non_empty(values.get(GcpAttr.MEMBER))
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(
            values.get(GcpAttr.ID), _binding_identifier(scope_reference, role, [member]), resource.address
        ),
        metadata={
            scope_field: scope_reference,
            GcpResourceMetadata.IAM_ROLE: role,
            GcpResourceMetadata.IAM_MEMBER: member,
            GcpResourceMetadata.IAM_MEMBERS: compact([member]),
            GcpResourceMetadata.IAM_CONDITION: _condition(values.raw(GcpAttr.CONDITION)),
            GcpResourceMetadata.IAM_BINDINGS: _iam_bindings(
                role, compact([member]), condition=values.raw(GcpAttr.CONDITION)
            ),
        },
    )


def _normalize_scope_iam_binding(
    resource: TerraformResource,
    *,
    scope_field: Any,
    scope_keys: tuple[GcpAttribute[Any], ...],
) -> NormalizedResource:
    values = GcpValues(resource.values)
    scope_reference = _target_reference(values, scope_keys)
    role = first_non_empty(values.get(GcpAttr.ROLE))
    members = values.get(GcpAttr.MEMBERS)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(
            values.get(GcpAttr.ID), _binding_identifier(scope_reference, role, members), resource.address
        ),
        metadata={
            scope_field: scope_reference,
            GcpResourceMetadata.IAM_ROLE: role,
            GcpResourceMetadata.IAM_MEMBERS: members,
            GcpResourceMetadata.IAM_CONDITION: _condition(values.raw(GcpAttr.CONDITION)),
            GcpResourceMetadata.IAM_BINDINGS: _iam_bindings(role, members, condition=values.raw(GcpAttr.CONDITION)),
        },
    )


def _normalize_scope_iam_policy(
    resource: TerraformResource,
    *,
    scope_field: Any,
    scope_keys: tuple[GcpAttribute[Any], ...],
) -> NormalizedResource:
    values = GcpValues(resource.values)
    scope_reference = _target_reference(values, scope_keys)
    policy_document = load_json_document(values.raw(GcpAttr.POLICY_DATA))
    bindings = _policy_bindings(policy_document)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(values.get(GcpAttr.ID), scope_reference, resource.address),
        metadata={
            scope_field: scope_reference,
            GcpResourceMetadata.IAM_BINDINGS: bindings,
            GcpResourceMetadata.POLICY_DOCUMENT: policy_document,
        },
    )
