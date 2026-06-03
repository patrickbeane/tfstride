from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.gcp.coercion import as_bool, as_list, compact
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
            GcpResourceMetadata.IAM_MEMBERS.key: compact([member]),
            GcpResourceMetadata.IAM_BINDINGS.key: _iam_bindings(role, compact([member])),
            "condition": values.get("condition"),
        },
    )


def normalize_project_iam_binding(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    role = first_non_empty(values.get("role"))
    members = compact(as_list(values.get("members")))
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(
            values.get("id"),
            _binding_identifier(values.get("project"), role, members),
            resource.address,
        ),
        metadata={
            GcpResourceMetadata.PROJECT.key: values.get("project"),
            GcpResourceMetadata.IAM_ROLE.key: role,
            GcpResourceMetadata.IAM_MEMBERS.key: members,
            GcpResourceMetadata.IAM_BINDINGS.key: _iam_bindings(role, members),
            "condition": values.get("condition"),
        },
    )


def normalize_project_iam_policy(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    policy_document = load_json_document(values.get("policy_data"))
    bindings = _policy_bindings(policy_document)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(values.get("id"), values.get("project"), resource.address),
        metadata={
            GcpResourceMetadata.PROJECT.key: values.get("project"),
            GcpResourceMetadata.IAM_BINDINGS.key: bindings,
            "policy_document": policy_document,
        },
    )


def normalize_service_account(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    account_id = first_non_empty(values.get("account_id"))
    email = first_non_empty(values.get("email"))
    member = first_non_empty(values.get("member"), _service_account_member(email))
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(email, values.get("name"), values.get("id"), account_id, resource.address),
        metadata={
            GcpResourceMetadata.NAME.key: first_non_empty(values.get("name"), account_id, resource.name),
            GcpResourceMetadata.PROJECT.key: values.get("project"),
            GcpResourceMetadata.SERVICE_ACCOUNT_ACCOUNT_ID.key: account_id,
            GcpResourceMetadata.SERVICE_ACCOUNT_EMAIL.key: email,
            GcpResourceMetadata.SERVICE_ACCOUNT_MEMBER.key: member,
            GcpResourceMetadata.SERVICE_ACCOUNT_UNIQUE_ID.key: values.get("unique_id"),
            GcpResourceMetadata.SERVICE_ACCOUNT_DISABLED.key: as_bool(values.get("disabled", False)),
            "display_name": values.get("display_name"),
            "description": values.get("description"),
        },
    )


def normalize_service_account_key(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    service_account_reference = first_non_empty(values.get("service_account_id"), values.get("service_account"))
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(values.get("id"), values.get("name"), service_account_reference, resource.address),
        metadata={
            GcpResourceMetadata.NAME.key: first_non_empty(values.get("name"), resource.name),
            GcpResourceMetadata.PROJECT.key: values.get("project"),
            GcpResourceMetadata.SERVICE_ACCOUNT_REFERENCE.key: service_account_reference,
            GcpResourceMetadata.SERVICE_ACCOUNT_KEY_ALGORITHM.key: values.get("key_algorithm"),
            GcpResourceMetadata.SERVICE_ACCOUNT_PUBLIC_KEY_TYPE.key: values.get("public_key_type"),
            "valid_after": values.get("valid_after"),
            "valid_before": values.get("valid_before"),
            "keepers": values.get("keepers") or {},
        },
    )


def normalize_service_account_iam_member(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    service_account_reference = first_non_empty(values.get("service_account_id"), values.get("service_account"))
    role = first_non_empty(values.get("role"))
    member = first_non_empty(values.get("member"))
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(
            values.get("id"),
            _binding_identifier(service_account_reference, role, [member]),
            resource.address,
        ),
        metadata={
            GcpResourceMetadata.SERVICE_ACCOUNT_REFERENCE.key: service_account_reference,
            GcpResourceMetadata.IAM_ROLE.key: role,
            GcpResourceMetadata.IAM_MEMBER.key: member,
            GcpResourceMetadata.IAM_MEMBERS.key: compact([member]),
            GcpResourceMetadata.IAM_BINDINGS.key: _iam_bindings(role, compact([member])),
            "condition": values.get("condition"),
        },
    )


def normalize_service_account_iam_binding(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    service_account_reference = first_non_empty(values.get("service_account_id"), values.get("service_account"))
    role = first_non_empty(values.get("role"))
    members = compact(as_list(values.get("members")))
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(
            values.get("id"),
            _binding_identifier(service_account_reference, role, members),
            resource.address,
        ),
        metadata={
            GcpResourceMetadata.SERVICE_ACCOUNT_REFERENCE.key: service_account_reference,
            GcpResourceMetadata.IAM_ROLE.key: role,
            GcpResourceMetadata.IAM_MEMBERS.key: members,
            GcpResourceMetadata.IAM_BINDINGS.key: _iam_bindings(role, members),
            "condition": values.get("condition"),
        },
    )


def normalize_service_account_iam_policy(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    service_account_reference = first_non_empty(values.get("service_account_id"), values.get("service_account"))
    policy_document = load_json_document(values.get("policy_data"))
    bindings = _policy_bindings(policy_document)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(values.get("id"), service_account_reference, resource.address),
        metadata={
            GcpResourceMetadata.SERVICE_ACCOUNT_REFERENCE.key: service_account_reference,
            GcpResourceMetadata.IAM_BINDINGS.key: bindings,
            "policy_document": policy_document,
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


def normalize_secret_manager_secret_iam_member(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_member(
        resource,
        target_field=GcpResourceMetadata.SECRET_REFERENCE,
        target_keys=("secret_id", "secret"),
    )


def normalize_secret_manager_secret_iam_binding(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_binding(
        resource,
        target_field=GcpResourceMetadata.SECRET_REFERENCE,
        target_keys=("secret_id", "secret"),
    )


def normalize_secret_manager_secret_iam_policy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_policy(
        resource,
        target_field=GcpResourceMetadata.SECRET_REFERENCE,
        target_keys=("secret_id", "secret"),
    )


def normalize_kms_crypto_key_iam_member(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_member(
        resource,
        target_field=GcpResourceMetadata.KMS_CRYPTO_KEY_REFERENCE,
        target_keys=("crypto_key_id", "crypto_key"),
    )


def normalize_kms_crypto_key_iam_binding(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_binding(
        resource,
        target_field=GcpResourceMetadata.KMS_CRYPTO_KEY_REFERENCE,
        target_keys=("crypto_key_id", "crypto_key"),
    )


def normalize_kms_crypto_key_iam_policy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_policy(
        resource,
        target_field=GcpResourceMetadata.KMS_CRYPTO_KEY_REFERENCE,
        target_keys=("crypto_key_id", "crypto_key"),
    )


def normalize_kms_key_ring_iam_member(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_member(
        resource,
        target_field=GcpResourceMetadata.KMS_KEY_RING,
        target_keys=("key_ring_id", "key_ring"),
    )


def normalize_kms_key_ring_iam_binding(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_binding(
        resource,
        target_field=GcpResourceMetadata.KMS_KEY_RING,
        target_keys=("key_ring_id", "key_ring"),
    )


def normalize_kms_key_ring_iam_policy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_iam_policy(
        resource,
        target_field=GcpResourceMetadata.KMS_KEY_RING,
        target_keys=("key_ring_id", "key_ring"),
    )


def _normalize_target_iam_member(
    resource: TerraformResource,
    *,
    target_field: Any,
    target_keys: tuple[str, ...],
) -> NormalizedResource:
    values = resource.values
    target_reference = _target_reference(values, target_keys)
    role = first_non_empty(values.get("role"))
    member = first_non_empty(values.get("member"))
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(values.get("id"), _binding_identifier(target_reference, role, [member]), resource.address),
        metadata={
            target_field.key: target_reference,
            GcpResourceMetadata.PROJECT.key: values.get("project"),
            GcpResourceMetadata.IAM_ROLE.key: role,
            GcpResourceMetadata.IAM_MEMBER.key: member,
            GcpResourceMetadata.IAM_MEMBERS.key: compact([member]),
            GcpResourceMetadata.IAM_BINDINGS.key: _iam_bindings(role, compact([member])),
            "condition": values.get("condition"),
        },
    )


def _normalize_target_iam_binding(
    resource: TerraformResource,
    *,
    target_field: Any,
    target_keys: tuple[str, ...],
) -> NormalizedResource:
    values = resource.values
    target_reference = _target_reference(values, target_keys)
    role = first_non_empty(values.get("role"))
    members = compact(as_list(values.get("members")))
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(values.get("id"), _binding_identifier(target_reference, role, members), resource.address),
        metadata={
            target_field.key: target_reference,
            GcpResourceMetadata.PROJECT.key: values.get("project"),
            GcpResourceMetadata.IAM_ROLE.key: role,
            GcpResourceMetadata.IAM_MEMBERS.key: members,
            GcpResourceMetadata.IAM_BINDINGS.key: _iam_bindings(role, members),
            "condition": values.get("condition"),
        },
    )


def _normalize_target_iam_policy(
    resource: TerraformResource,
    *,
    target_field: Any,
    target_keys: tuple[str, ...],
) -> NormalizedResource:
    values = resource.values
    target_reference = _target_reference(values, target_keys)
    policy_document = load_json_document(values.get("policy_data"))
    bindings = _policy_bindings(policy_document)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(values.get("id"), target_reference, resource.address),
        metadata={
            target_field.key: target_reference,
            GcpResourceMetadata.PROJECT.key: values.get("project"),
            GcpResourceMetadata.IAM_BINDINGS.key: bindings,
            "policy_document": policy_document,
        },
    )


def _target_reference(values: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    return first_non_empty(*(values.get(key) for key in keys))


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


def _binding_identifier(target: str | None, role: str | None, members: list[str | None]) -> str | None:
    normalized_members = compact(list(members))
    if not target or not role or not normalized_members:
        return None
    return f"{target}:{role}:{','.join(normalized_members)}"


def _service_account_member(email: str | None) -> str | None:
    if not email:
        return None
    return f"serviceAccount:{email}"