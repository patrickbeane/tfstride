from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.gcp.attributes import GcpAttr, GcpAttribute, GcpValues
from tfstride.providers.gcp.coercion import as_list, compact
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.network_normalizers import GCP_PROVIDER
from tfstride.providers.gcp.resource_utils import first_non_empty, load_json_document, service_account_member


def normalize_project_iam_member(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    role = first_non_empty(values.get(GcpAttr.ROLE))
    member = first_non_empty(values.get(GcpAttr.MEMBER))
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(values.get(GcpAttr.ID), role and member and f"{role}:{member}", resource.address),
        metadata={
            GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
            GcpResourceMetadata.IAM_ROLE: role,
            GcpResourceMetadata.IAM_MEMBER: member,
            GcpResourceMetadata.IAM_MEMBERS: compact([member]),
            GcpResourceMetadata.IAM_CONDITION: _condition(values.raw(GcpAttr.CONDITION)),
            GcpResourceMetadata.IAM_BINDINGS: _iam_bindings(
                role, compact([member]), condition=values.raw(GcpAttr.CONDITION)
            ),
        },
    )


def normalize_project_iam_binding(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
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
            _binding_identifier(values.get(GcpAttr.PROJECT), role, members),
            resource.address,
        ),
        metadata={
            GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
            GcpResourceMetadata.IAM_ROLE: role,
            GcpResourceMetadata.IAM_MEMBERS: members,
            GcpResourceMetadata.IAM_CONDITION: _condition(values.raw(GcpAttr.CONDITION)),
            GcpResourceMetadata.IAM_BINDINGS: _iam_bindings(role, members, condition=values.raw(GcpAttr.CONDITION)),
        },
    )


def normalize_project_iam_policy(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    policy_document = load_json_document(values.raw(GcpAttr.POLICY_DATA))
    bindings = _policy_bindings(policy_document)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(values.get(GcpAttr.ID), values.get(GcpAttr.PROJECT), resource.address),
        metadata={
            GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
            GcpResourceMetadata.IAM_BINDINGS: bindings,
            GcpResourceMetadata.POLICY_DOCUMENT: policy_document,
        },
    )


def normalize_project_iam_custom_role(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    role_id = first_non_empty(values.get(GcpAttr.ROLE_ID), resource.name)
    project = first_non_empty(values.get(GcpAttr.PROJECT))
    name = first_non_empty(values.get(GcpAttr.NAME), _project_custom_role_name(project, role_id))
    return _normalize_custom_role(
        resource,
        identifier=first_non_empty(values.get(GcpAttr.ID), name, role_id, resource.address),
        role_id=role_id,
        name=name,
        project=project,
        organization_id=None,
    )


def normalize_organization_iam_custom_role(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    role_id = first_non_empty(values.get(GcpAttr.ROLE_ID), resource.name)
    organization_id = first_non_empty(values.get(GcpAttr.ORG_ID), values.get(GcpAttr.ORGANIZATION_ID))
    name = first_non_empty(values.get(GcpAttr.NAME), _organization_custom_role_name(organization_id, role_id))
    return _normalize_custom_role(
        resource,
        identifier=first_non_empty(values.get(GcpAttr.ID), name, role_id, resource.address),
        role_id=role_id,
        name=name,
        project=None,
        organization_id=organization_id,
    )


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
        identifier=first_non_empty(email, values.get(GcpAttr.NAME), values.get(GcpAttr.ID), account_id, resource.address),
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
    service_account_reference = first_non_empty(values.get(GcpAttr.SERVICE_ACCOUNT_ID), values.get(GcpAttr.SERVICE_ACCOUNT))
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(values.get(GcpAttr.ID), values.get(GcpAttr.NAME), service_account_reference, resource.address),
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
    service_account_reference = first_non_empty(values.get(GcpAttr.SERVICE_ACCOUNT_ID), values.get(GcpAttr.SERVICE_ACCOUNT))
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
    service_account_reference = first_non_empty(values.get(GcpAttr.SERVICE_ACCOUNT_ID), values.get(GcpAttr.SERVICE_ACCOUNT))
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
    service_account_reference = first_non_empty(values.get(GcpAttr.SERVICE_ACCOUNT_ID), values.get(GcpAttr.SERVICE_ACCOUNT))
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


def normalize_storage_bucket_iam_member(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    bucket = first_non_empty(values.get(GcpAttr.BUCKET))
    role = first_non_empty(values.get(GcpAttr.ROLE))
    member = first_non_empty(values.get(GcpAttr.MEMBER))
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(values.get(GcpAttr.ID), _binding_identifier(bucket, role, [member]), resource.address),
        metadata={
            GcpResourceMetadata.BUCKET_NAME: bucket,
            GcpResourceMetadata.IAM_ROLE: role,
            GcpResourceMetadata.IAM_MEMBER: member,
            GcpResourceMetadata.IAM_MEMBERS: compact([member]),
            GcpResourceMetadata.IAM_CONDITION: _condition(values.raw(GcpAttr.CONDITION)),
            GcpResourceMetadata.IAM_BINDINGS: _iam_bindings(
                role, compact([member]), condition=values.raw(GcpAttr.CONDITION)
            ),
        },
    )


def normalize_storage_bucket_iam_binding(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    bucket = first_non_empty(values.get(GcpAttr.BUCKET))
    role = first_non_empty(values.get(GcpAttr.ROLE))
    members = values.get(GcpAttr.MEMBERS)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(values.get(GcpAttr.ID), _binding_identifier(bucket, role, members), resource.address),
        metadata={
            GcpResourceMetadata.BUCKET_NAME: bucket,
            GcpResourceMetadata.IAM_ROLE: role,
            GcpResourceMetadata.IAM_MEMBERS: members,
            GcpResourceMetadata.IAM_CONDITION: _condition(values.raw(GcpAttr.CONDITION)),
            GcpResourceMetadata.IAM_BINDINGS: _iam_bindings(role, members, condition=values.raw(GcpAttr.CONDITION)),
        },
    )


def normalize_storage_bucket_iam_policy(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    bucket = first_non_empty(values.get(GcpAttr.BUCKET))
    policy_document = load_json_document(values.raw(GcpAttr.POLICY_DATA))
    bindings = _policy_bindings(policy_document)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(values.get(GcpAttr.ID), bucket, resource.address),
        metadata={
            GcpResourceMetadata.BUCKET_NAME: bucket,
            GcpResourceMetadata.IAM_BINDINGS: bindings,
            GcpResourceMetadata.POLICY_DOCUMENT: policy_document,
        },
    )


def normalize_secret_manager_secret_iam_member(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_member(
        resource,
        target_field=GcpResourceMetadata.SECRET_REFERENCE,
        target_keys=(GcpAttr.SECRET_ID, GcpAttr.SECRET),
    )


def normalize_secret_manager_secret_iam_binding(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_binding(
        resource,
        target_field=GcpResourceMetadata.SECRET_REFERENCE,
        target_keys=(GcpAttr.SECRET_ID, GcpAttr.SECRET),
    )


def normalize_secret_manager_secret_iam_policy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_policy(
        resource,
        target_field=GcpResourceMetadata.SECRET_REFERENCE,
        target_keys=(GcpAttr.SECRET_ID, GcpAttr.SECRET),
    )


def normalize_pubsub_topic_iam_member(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_member(
        resource,
        target_field=GcpResourceMetadata.PUBSUB_TOPIC_REFERENCE,
        target_keys=(GcpAttr.TOPIC, GcpAttr.TOPIC_ID),
    )


def normalize_pubsub_topic_iam_binding(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_binding(
        resource,
        target_field=GcpResourceMetadata.PUBSUB_TOPIC_REFERENCE,
        target_keys=(GcpAttr.TOPIC, GcpAttr.TOPIC_ID),
    )


def normalize_pubsub_topic_iam_policy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_policy(
        resource,
        target_field=GcpResourceMetadata.PUBSUB_TOPIC_REFERENCE,
        target_keys=(GcpAttr.TOPIC, GcpAttr.TOPIC_ID),
    )


def normalize_pubsub_subscription_iam_member(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_member(
        resource,
        target_field=GcpResourceMetadata.PUBSUB_SUBSCRIPTION_REFERENCE,
        target_keys=(GcpAttr.SUBSCRIPTION, GcpAttr.SUBSCRIPTION_ID),
    )


def normalize_pubsub_subscription_iam_binding(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_binding(
        resource,
        target_field=GcpResourceMetadata.PUBSUB_SUBSCRIPTION_REFERENCE,
        target_keys=(GcpAttr.SUBSCRIPTION, GcpAttr.SUBSCRIPTION_ID),
    )


def normalize_pubsub_subscription_iam_policy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_policy(
        resource,
        target_field=GcpResourceMetadata.PUBSUB_SUBSCRIPTION_REFERENCE,
        target_keys=(GcpAttr.SUBSCRIPTION, GcpAttr.SUBSCRIPTION_ID),
    )


def normalize_bigquery_dataset_iam_member(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_member(
        resource,
        target_field=GcpResourceMetadata.BIGQUERY_DATASET_REFERENCE,
        target_keys=(GcpAttr.DATASET_ID, GcpAttr.DATASET),
    )


def normalize_bigquery_dataset_iam_binding(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_binding(
        resource,
        target_field=GcpResourceMetadata.BIGQUERY_DATASET_REFERENCE,
        target_keys=(GcpAttr.DATASET_ID, GcpAttr.DATASET),
    )


def normalize_bigquery_dataset_iam_policy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_policy(
        resource,
        target_field=GcpResourceMetadata.BIGQUERY_DATASET_REFERENCE,
        target_keys=(GcpAttr.DATASET_ID, GcpAttr.DATASET),
    )


def normalize_bigquery_table_iam_member(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_member(
        resource,
        target_field=GcpResourceMetadata.BIGQUERY_TABLE_REFERENCE,
        target_keys=(GcpAttr.TABLE_ID, GcpAttr.TABLE),
    )


def normalize_bigquery_table_iam_binding(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_binding(
        resource,
        target_field=GcpResourceMetadata.BIGQUERY_TABLE_REFERENCE,
        target_keys=(GcpAttr.TABLE_ID, GcpAttr.TABLE),
    )


def normalize_bigquery_table_iam_policy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_policy(
        resource,
        target_field=GcpResourceMetadata.BIGQUERY_TABLE_REFERENCE,
        target_keys=(GcpAttr.TABLE_ID, GcpAttr.TABLE),
    )


def normalize_kms_crypto_key_iam_member(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_member(
        resource,
        target_field=GcpResourceMetadata.KMS_CRYPTO_KEY_REFERENCE,
        target_keys=(GcpAttr.CRYPTO_KEY_ID, GcpAttr.CRYPTO_KEY),
    )


def normalize_kms_crypto_key_iam_binding(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_binding(
        resource,
        target_field=GcpResourceMetadata.KMS_CRYPTO_KEY_REFERENCE,
        target_keys=(GcpAttr.CRYPTO_KEY_ID, GcpAttr.CRYPTO_KEY),
    )


def normalize_kms_crypto_key_iam_policy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_policy(
        resource,
        target_field=GcpResourceMetadata.KMS_CRYPTO_KEY_REFERENCE,
        target_keys=(GcpAttr.CRYPTO_KEY_ID, GcpAttr.CRYPTO_KEY),
    )


def normalize_kms_key_ring_iam_member(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_member(
        resource,
        target_field=GcpResourceMetadata.KMS_KEY_RING,
        target_keys=(GcpAttr.KEY_RING_ID, GcpAttr.KEY_RING),
    )


def normalize_kms_key_ring_iam_binding(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_binding(
        resource,
        target_field=GcpResourceMetadata.KMS_KEY_RING,
        target_keys=(GcpAttr.KEY_RING_ID, GcpAttr.KEY_RING),
    )


def normalize_kms_key_ring_iam_policy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_policy(
        resource,
        target_field=GcpResourceMetadata.KMS_KEY_RING,
        target_keys=(GcpAttr.KEY_RING_ID, GcpAttr.KEY_RING),
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
        identifier=first_non_empty(values.get(GcpAttr.ID), _binding_identifier(scope_reference, role, [member]), resource.address),
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
        identifier=first_non_empty(values.get(GcpAttr.ID), _binding_identifier(scope_reference, role, members), resource.address),
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


def _normalize_custom_role(
    resource: TerraformResource,
    *,
    identifier: str | None,
    role_id: str | None,
    name: str | None,
    project: str | None,
    organization_id: str | None,
) -> NormalizedResource:
    values = GcpValues(resource.values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(identifier, resource.address),
        metadata={
            GcpResourceMetadata.NAME: name,
            GcpResourceMetadata.PROJECT: project,
            GcpResourceMetadata.ORGANIZATION_ID: organization_id,
            GcpResourceMetadata.CUSTOM_ROLE_ID: role_id,
            GcpResourceMetadata.CUSTOM_ROLE_PERMISSIONS: values.get(GcpAttr.PERMISSIONS),
            GcpResourceMetadata.CUSTOM_ROLE_STAGE: values.get(GcpAttr.STAGE),
            "title": values.get(GcpAttr.TITLE),
            "description": values.get(GcpAttr.DESCRIPTION),
            "deleted": values.get(GcpAttr.DELETED),
        },
    )


def _project_custom_role_name(project: str | None, role_id: str | None) -> str | None:
    if not project or not role_id:
        return None
    return f"projects/{project}/roles/{role_id}"


def _organization_custom_role_name(organization_id: str | None, role_id: str | None) -> str | None:
    if not organization_id or not role_id:
        return None
    return f"organizations/{organization_id}/roles/{role_id}"


def _normalize_target_iam_member(
    resource: TerraformResource,
    *,
    target_field: Any,
    target_keys: tuple[GcpAttribute[Any], ...],
) -> NormalizedResource:
    values = GcpValues(resource.values)
    target_reference = _target_reference(values, target_keys)
    role = first_non_empty(values.get(GcpAttr.ROLE))
    member = first_non_empty(values.get(GcpAttr.MEMBER))
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(values.get(GcpAttr.ID), _binding_identifier(target_reference, role, [member]), resource.address),
        metadata={
            target_field: target_reference,
            GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
            GcpResourceMetadata.IAM_ROLE: role,
            GcpResourceMetadata.IAM_MEMBER: member,
            GcpResourceMetadata.IAM_MEMBERS: compact([member]),
            GcpResourceMetadata.IAM_CONDITION: _condition(values.raw(GcpAttr.CONDITION)),
            GcpResourceMetadata.IAM_BINDINGS: _iam_bindings(
                role, compact([member]), condition=values.raw(GcpAttr.CONDITION)
            ),
        },
    )


def _normalize_target_iam_binding(
    resource: TerraformResource,
    *,
    target_field: Any,
    target_keys: tuple[GcpAttribute[Any], ...],
) -> NormalizedResource:
    values = GcpValues(resource.values)
    target_reference = _target_reference(values, target_keys)
    role = first_non_empty(values.get(GcpAttr.ROLE))
    members = values.get(GcpAttr.MEMBERS)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(values.get(GcpAttr.ID), _binding_identifier(target_reference, role, members), resource.address),
        metadata={
            target_field: target_reference,
            GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
            GcpResourceMetadata.IAM_ROLE: role,
            GcpResourceMetadata.IAM_MEMBERS: members,
            GcpResourceMetadata.IAM_CONDITION: _condition(values.raw(GcpAttr.CONDITION)),
            GcpResourceMetadata.IAM_BINDINGS: _iam_bindings(role, members, condition=values.raw(GcpAttr.CONDITION)),
        },
    )


def _normalize_target_iam_policy(
    resource: TerraformResource,
    *,
    target_field: Any,
    target_keys: tuple[GcpAttribute[Any], ...],
) -> NormalizedResource:
    values = GcpValues(resource.values)
    target_reference = _target_reference(values, target_keys)
    policy_document = load_json_document(values.raw(GcpAttr.POLICY_DATA))
    bindings = _policy_bindings(policy_document)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(values.get(GcpAttr.ID), target_reference, resource.address),
        metadata={
            target_field: target_reference,
            GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
            GcpResourceMetadata.IAM_BINDINGS: bindings,
            GcpResourceMetadata.POLICY_DOCUMENT: policy_document,
        },
    )


def _target_reference(values: GcpValues, keys: tuple[GcpAttribute[Any], ...]) -> str | None:
    return first_non_empty(*(values.get(key) for key in keys))


def _policy_bindings(policy_document: dict[str, Any]) -> list[dict[str, Any]]:
    bindings: list[dict[str, Any]] = []
    for binding in as_list(policy_document.get("bindings")):
        if not isinstance(binding, dict):
            continue
        role = first_non_empty(binding.get("role"))
        members = compact(as_list(binding.get("members")))
        bindings.extend(_iam_bindings(role, members, condition=binding.get("condition")))
    return bindings


def _iam_bindings(
    role: str | None,
    members: list[str],
    *,
    condition: Any = None,
) -> list[dict[str, Any]]:
    if not role or not members:
        return []
    binding: dict[str, Any] = {"role": role, "members": list(members)}
    normalized_condition = _condition(condition)
    if normalized_condition:
        binding["condition"] = normalized_condition
    return [binding]


def _condition(value: Any) -> dict[str, Any]:
    if isinstance(value, list):
        value = value[0] if value and isinstance(value[0], dict) else {}
    if not isinstance(value, dict):
        return {}
    return {
        str(key): raw_value
        for key, raw_value in value.items()
        if raw_value not in (None, "", [])
    }


def _binding_identifier(target: str | None, role: str | None, members: list[str | None]) -> str | None:
    normalized_members = compact(list(members))
    if not target or not role or not normalized_members:
        return None
    return f"{target}:{role}:{','.join(normalized_members)}"