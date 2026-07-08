from __future__ import annotations

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.gcp.attributes import GcpAttr, GcpValues
from tfstride.providers.gcp.coercion import compact
from tfstride.providers.gcp.iam_normalizer_utils import _binding_identifier, _condition, _iam_bindings, _policy_bindings
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer_common import GCP_PROVIDER
from tfstride.providers.gcp.resource_utils import first_non_empty, service_account_member
from tfstride.providers.json_documents import load_json_document


def normalize_service_account(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    account_id = first_non_empty(values.get(GcpAttr.ACCOUNT_ID))
    email = first_non_empty(values.get(GcpAttr.EMAIL))
    member = first_non_empty(values.get(GcpAttr.MEMBER), service_account_member(email))
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(
            email, values.get(GcpAttr.NAME), values.get(GcpAttr.ID), account_id, resource.address
        ),
        metadata={
            GcpResourceMetadata.NAME: first_non_empty(values.get(GcpAttr.NAME), account_id, resource.name),
            GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
            GcpResourceMetadata.SERVICE_ACCOUNT_ACCOUNT_ID: account_id,
            GcpResourceMetadata.SERVICE_ACCOUNT_EMAIL: email,
            GcpResourceMetadata.SERVICE_ACCOUNT_MEMBER: member,
            GcpResourceMetadata.SERVICE_ACCOUNT_UNIQUE_ID: values.get(GcpAttr.UNIQUE_ID),
            GcpResourceMetadata.SERVICE_ACCOUNT_DISABLED: values.get(GcpAttr.DISABLED),
            "display_name": values.get(GcpAttr.DISPLAY_NAME),
            "description": values.get(GcpAttr.DESCRIPTION),
        },
    )


def normalize_service_account_key(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    service_account_reference = first_non_empty(
        values.get(GcpAttr.SERVICE_ACCOUNT_ID), values.get(GcpAttr.SERVICE_ACCOUNT)
    )
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(
            values.get(GcpAttr.ID), values.get(GcpAttr.NAME), service_account_reference, resource.address
        ),
        metadata={
            GcpResourceMetadata.NAME: first_non_empty(values.get(GcpAttr.NAME), resource.name),
            GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
            GcpResourceMetadata.SERVICE_ACCOUNT_ID: service_account_reference,
            GcpResourceMetadata.SERVICE_ACCOUNT_REFERENCE: service_account_reference,
            GcpResourceMetadata.SERVICE_ACCOUNT_KEY_ALGORITHM: values.get(GcpAttr.KEY_ALGORITHM),
            GcpResourceMetadata.SERVICE_ACCOUNT_PUBLIC_KEY_TYPE: values.get(GcpAttr.PUBLIC_KEY_TYPE),
            GcpResourceMetadata.SERVICE_ACCOUNT_KEY_VALID_AFTER: values.get(GcpAttr.VALID_AFTER),
            GcpResourceMetadata.SERVICE_ACCOUNT_KEY_VALID_BEFORE: values.get(GcpAttr.VALID_BEFORE),
            GcpResourceMetadata.SERVICE_ACCOUNT_KEY_KEEPERS: values.get(GcpAttr.KEEPERS),
        },
    )


def normalize_service_account_iam_member(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    service_account_reference = first_non_empty(
        values.get(GcpAttr.SERVICE_ACCOUNT_ID), values.get(GcpAttr.SERVICE_ACCOUNT)
    )
    role = first_non_empty(values.get(GcpAttr.ROLE))
    member = first_non_empty(values.get(GcpAttr.MEMBER))
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(
            values.get(GcpAttr.ID),
            _binding_identifier(service_account_reference, role, [member]),
            resource.address,
        ),
        metadata={
            GcpResourceMetadata.SERVICE_ACCOUNT_REFERENCE: service_account_reference,
            GcpResourceMetadata.IAM_ROLE: role,
            GcpResourceMetadata.IAM_MEMBER: member,
            GcpResourceMetadata.IAM_MEMBERS: compact([member]),
            GcpResourceMetadata.IAM_CONDITION: _condition(values.raw(GcpAttr.CONDITION)),
            GcpResourceMetadata.IAM_BINDINGS: _iam_bindings(
                role, compact([member]), condition=values.raw(GcpAttr.CONDITION)
            ),
        },
    )


def normalize_service_account_iam_binding(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    service_account_reference = first_non_empty(
        values.get(GcpAttr.SERVICE_ACCOUNT_ID), values.get(GcpAttr.SERVICE_ACCOUNT)
    )
    role = first_non_empty(values.get(GcpAttr.ROLE))
    members = values.get(GcpAttr.MEMBERS)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(
            values.get(GcpAttr.ID),
            _binding_identifier(service_account_reference, role, members),
            resource.address,
        ),
        metadata={
            GcpResourceMetadata.SERVICE_ACCOUNT_REFERENCE: service_account_reference,
            GcpResourceMetadata.IAM_ROLE: role,
            GcpResourceMetadata.IAM_MEMBERS: members,
            GcpResourceMetadata.IAM_CONDITION: _condition(values.raw(GcpAttr.CONDITION)),
            GcpResourceMetadata.IAM_BINDINGS: _iam_bindings(role, members, condition=values.raw(GcpAttr.CONDITION)),
        },
    )


def normalize_service_account_iam_policy(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    service_account_reference = first_non_empty(
        values.get(GcpAttr.SERVICE_ACCOUNT_ID), values.get(GcpAttr.SERVICE_ACCOUNT)
    )
    policy_document = load_json_document(values.raw(GcpAttr.POLICY_DATA))
    bindings = _policy_bindings(policy_document)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(values.get(GcpAttr.ID), service_account_reference, resource.address),
        metadata={
            GcpResourceMetadata.SERVICE_ACCOUNT_REFERENCE: service_account_reference,
            GcpResourceMetadata.IAM_BINDINGS: bindings,
            GcpResourceMetadata.POLICY_DOCUMENT: policy_document,
        },
    )
