from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.coercion import attribute_unknown, known_string, known_string_list
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


def normalize_artifact_registry_repository_iam_member(resource: TerraformResource) -> NormalizedResource:
    _values, target_reference, project, role, member, members, condition, uncertainties = _artifact_registry_iam_values(
        resource
    )
    members = compact([member])
    return _normalize_artifact_registry_iam_resource(
        resource,
        target_reference=target_reference,
        project=project,
        role=role,
        member=member,
        members=members,
        condition=condition,
        bindings=_iam_bindings(role, members, condition=condition),
        uncertainties=uncertainties,
    )


def normalize_artifact_registry_repository_iam_binding(resource: TerraformResource) -> NormalizedResource:
    _values, target_reference, project, role, _, members, condition, uncertainties = _artifact_registry_iam_values(
        resource
    )
    return _normalize_artifact_registry_iam_resource(
        resource,
        target_reference=target_reference,
        project=project,
        role=role,
        member=None,
        members=members,
        condition=condition,
        bindings=_iam_bindings(role, members, condition=condition),
        uncertainties=uncertainties,
    )


def normalize_artifact_registry_repository_iam_policy(resource: TerraformResource) -> NormalizedResource:
    values, target_reference, project, _, _, _, _, uncertainties = _artifact_registry_iam_values(resource)
    if attribute_unknown(resource.unknown_values, GcpAttr.POLICY_DATA.key):
        uncertainties.append("policy_data is unknown after planning")
    policy_document = load_json_document(values.raw(GcpAttr.POLICY_DATA))
    return _normalize_artifact_registry_iam_resource(
        resource,
        target_reference=target_reference,
        project=project,
        role=None,
        member=None,
        members=[],
        condition={},
        bindings=_policy_bindings(policy_document),
        policy_document=policy_document,
        uncertainties=uncertainties,
    )


def _artifact_registry_iam_values(
    resource: TerraformResource,
) -> tuple[GcpValues, str | None, str | None, str | None, str | None, list[str], dict[str, Any], list[str]]:
    values = GcpValues(resource.values)
    uncertainties: list[str] = []
    target_reference = None
    for target_attribute in (GcpAttr.REPOSITORY, GcpAttr.REPOSITORY_ID):
        target_reference = known_string(
            resource.values,
            resource.unknown_values,
            target_attribute.key,
            uncertainties,
        )
        if target_reference:
            break
    project = known_string(resource.values, resource.unknown_values, GcpAttr.PROJECT.key, uncertainties)
    role = known_string(resource.values, resource.unknown_values, GcpAttr.ROLE.key, uncertainties)
    member = known_string(resource.values, resource.unknown_values, GcpAttr.MEMBER.key, uncertainties)
    members = known_string_list(resource.values, resource.unknown_values, GcpAttr.MEMBERS.key, uncertainties)
    condition = _artifact_registry_iam_condition(resource, uncertainties)
    return values, target_reference, project, role, member, members, condition, uncertainties


def _artifact_registry_iam_condition(
    resource: TerraformResource,
    uncertainties: list[str],
) -> dict[str, Any]:
    if attribute_unknown(resource.unknown_values, GcpAttr.CONDITION.key):
        uncertainties.append("condition is unknown after planning")
        return {}
    return _condition(resource.values.get(GcpAttr.CONDITION.key))


def _normalize_artifact_registry_iam_resource(
    resource: TerraformResource,
    *,
    target_reference: str | None,
    project: str | None,
    role: str | None,
    member: str | None,
    members: list[str],
    condition: dict[str, Any],
    bindings: list[dict[str, Any]],
    uncertainties: list[str],
    policy_document: dict[str, Any] | None = None,
) -> NormalizedResource:
    metadata: dict[Any, Any] = {
        GcpResourceMetadata.ARTIFACT_REGISTRY_REPOSITORY_REFERENCE: target_reference,
        GcpResourceMetadata.PROJECT: project,
        GcpResourceMetadata.IAM_ROLE: role,
        GcpResourceMetadata.IAM_MEMBER: member,
        GcpResourceMetadata.IAM_MEMBERS: members,
        GcpResourceMetadata.IAM_CONDITION: condition,
        GcpResourceMetadata.IAM_BINDINGS: bindings,
        GcpResourceMetadata.ARTIFACT_REGISTRY_IAM_POSTURE_UNCERTAINTIES: uncertainties,
    }
    if policy_document is not None:
        metadata[GcpResourceMetadata.POLICY_DOCUMENT] = policy_document
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(
            resource.values.get(GcpAttr.ID.key),
            _binding_identifier(target_reference, role, members),
            target_reference,
            resource.address,
        ),
        metadata=metadata,
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
        identifier=first_non_empty(
            values.get(GcpAttr.ID), _binding_identifier(bucket, role, [member]), resource.address
        ),
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
        identifier=first_non_empty(
            values.get(GcpAttr.ID), _binding_identifier(bucket, role, members), resource.address
        ),
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
        identifier=first_non_empty(
            values.get(GcpAttr.ID), _binding_identifier(target_reference, role, [member]), resource.address
        ),
        metadata={
            target_field: target_reference,
            GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
            GcpResourceMetadata.IAM_ROLE: role,
            GcpResourceMetadata.IAM_MEMBER: member,
            GcpResourceMetadata.IAM_MEMBERS: compact([member]),
            GcpResourceMetadata.IAM_CONDITION: _condition(values.raw(GcpAttr.CONDITION)),
            GcpResourceMetadata.IAM_BINDINGS: _iam_bindings(
                role,
                compact([member]),
                condition=values.raw(GcpAttr.CONDITION),
                condition_unknown=attribute_unknown(resource.unknown_values, GcpAttr.CONDITION.key),
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
        identifier=first_non_empty(
            values.get(GcpAttr.ID), _binding_identifier(target_reference, role, members), resource.address
        ),
        metadata={
            target_field: target_reference,
            GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
            GcpResourceMetadata.IAM_ROLE: role,
            GcpResourceMetadata.IAM_MEMBERS: members,
            GcpResourceMetadata.IAM_CONDITION: _condition(values.raw(GcpAttr.CONDITION)),
            GcpResourceMetadata.IAM_BINDINGS: _iam_bindings(
                role,
                members,
                condition=values.raw(GcpAttr.CONDITION),
                condition_unknown=attribute_unknown(resource.unknown_values, GcpAttr.CONDITION.key),
            ),
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
