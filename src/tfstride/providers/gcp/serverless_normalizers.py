from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.gcp.coercion import as_bool, as_list, compact, first_item
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.network_normalizers import GCP_PROVIDER
from tfstride.providers.gcp.resource_utils import (
    first_non_empty,
    resource_identifier,
    resource_name,
    service_account_member,
)


def normalize_cloud_run_service(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    metadata = first_item(values.get("metadata")) or {}
    annotations = metadata.get("annotations") if isinstance(metadata.get("annotations"), dict) else {}
    template = first_item(values.get("template")) or {}
    spec = first_item(template.get("spec")) or {}
    service_account = first_non_empty(spec.get("service_account_name"))
    ingress = first_non_empty(annotations.get("run.googleapis.com/ingress"), values.get("ingress"))
    public_access_configured = _cloud_run_ingress_allows_internet(ingress)
    return _serverless_workload(
        resource,
        service_account_email=service_account,
        public_access_configured=public_access_configured,
        vpc_enabled=_has_vpc_attachment(spec.get("vpc_access")),
        extra_metadata={
            GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE.key: _serverless_reference(values, resource),
            GcpResourceMetadata.REGION.key: values.get("location"),
            GcpResourceMetadata.SERVERLESS_INGRESS.key: ingress,
            "url": _cloud_run_v1_url(values),
            "metadata": metadata,
        },
    )


def normalize_cloud_run_v2_service(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    template = first_item(values.get("template")) or {}
    service_account = first_non_empty(template.get("service_account"))
    ingress = first_non_empty(values.get("ingress"))
    public_access_configured = _cloud_run_ingress_allows_internet(ingress)
    return _serverless_workload(
        resource,
        service_account_email=service_account,
        public_access_configured=public_access_configured,
        vpc_enabled=_has_vpc_attachment(template.get("vpc_access")),
        extra_metadata={
            GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE.key: _serverless_reference(values, resource),
            GcpResourceMetadata.REGION.key: values.get("location"),
            GcpResourceMetadata.SERVERLESS_INGRESS.key: ingress,
            "uri": values.get("uri"),
            "template": template,
        },
    )


def normalize_cloudfunctions_function(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    service_account = first_non_empty(values.get("service_account_email"))
    trigger_http = as_bool(values.get("trigger_http", False))
    return _serverless_workload(
        resource,
        service_account_email=service_account,
        public_access_configured=trigger_http,
        vpc_enabled=_has_vpc_attachment(values.get("vpc_connector")),
        extra_metadata={
            GcpResourceMetadata.CLOUD_FUNCTION_REFERENCE.key: _serverless_reference(values, resource),
            GcpResourceMetadata.REGION.key: values.get("region"),
            GcpResourceMetadata.SERVERLESS_INGRESS.key: values.get("ingress_settings"),
            "runtime": values.get("runtime"),
            "trigger_http": trigger_http,
            "https_trigger_url": values.get("https_trigger_url"),
        },
    )


def normalize_cloudfunctions2_function(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    service_config = first_item(values.get("service_config")) or {}
    service_account = first_non_empty(service_config.get("service_account_email"))
    trigger_http = bool(service_config.get("uri") or values.get("url") or service_config.get("service"))
    return _serverless_workload(
        resource,
        service_account_email=service_account,
        public_access_configured=trigger_http,
        vpc_enabled=_has_vpc_attachment(service_config.get("vpc_connector")),
        extra_metadata={
            GcpResourceMetadata.CLOUD_FUNCTION_REFERENCE.key: _serverless_reference(values, resource),
            GcpResourceMetadata.REGION.key: values.get("location"),
            GcpResourceMetadata.SERVERLESS_INGRESS.key: service_config.get("ingress_settings"),
            "service_config": service_config,
            "build_config": first_item(values.get("build_config")) or {},
            "uri": service_config.get("uri"),
        },
    )


def normalize_cloud_run_service_iam_member(resource: TerraformResource) -> NormalizedResource:
    return _normalize_serverless_iam_member(
        resource,
        target_field=GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE,
        target_keys=("service", "name"),
    )


def normalize_cloud_run_service_iam_binding(resource: TerraformResource) -> NormalizedResource:
    return _normalize_serverless_iam_binding(
        resource,
        target_field=GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE,
        target_keys=("service", "name"),
    )


def normalize_cloud_run_service_iam_policy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_serverless_iam_policy(
        resource,
        target_field=GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE,
        target_keys=("service", "name"),
    )


def normalize_cloud_run_v2_service_iam_member(resource: TerraformResource) -> NormalizedResource:
    return normalize_cloud_run_service_iam_member(resource)


def normalize_cloud_run_v2_service_iam_binding(resource: TerraformResource) -> NormalizedResource:
    return normalize_cloud_run_service_iam_binding(resource)


def normalize_cloud_run_v2_service_iam_policy(resource: TerraformResource) -> NormalizedResource:
    return normalize_cloud_run_service_iam_policy(resource)


def normalize_cloudfunctions_function_iam_member(resource: TerraformResource) -> NormalizedResource:
    return _normalize_serverless_iam_member(
        resource,
        target_field=GcpResourceMetadata.CLOUD_FUNCTION_REFERENCE,
        target_keys=("cloud_function", "function", "name"),
    )


def normalize_cloudfunctions_function_iam_binding(resource: TerraformResource) -> NormalizedResource:
    return _normalize_serverless_iam_binding(
        resource,
        target_field=GcpResourceMetadata.CLOUD_FUNCTION_REFERENCE,
        target_keys=("cloud_function", "function", "name"),
    )


def normalize_cloudfunctions_function_iam_policy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_serverless_iam_policy(
        resource,
        target_field=GcpResourceMetadata.CLOUD_FUNCTION_REFERENCE,
        target_keys=("cloud_function", "function", "name"),
    )


def normalize_cloudfunctions2_function_iam_member(resource: TerraformResource) -> NormalizedResource:
    return normalize_cloudfunctions_function_iam_member(resource)


def normalize_cloudfunctions2_function_iam_binding(resource: TerraformResource) -> NormalizedResource:
    return normalize_cloudfunctions_function_iam_binding(resource)


def normalize_cloudfunctions2_function_iam_policy(resource: TerraformResource) -> NormalizedResource:
    return normalize_cloudfunctions_function_iam_policy(resource)


def _serverless_workload(
    resource: TerraformResource,
    *,
    service_account_email: str | None,
    public_access_configured: bool,
    vpc_enabled: bool,
    extra_metadata: dict[str, object],
) -> NormalizedResource:
    values = resource.values
    public_access_reasons = ["serverless service has public ingress configured"] if public_access_configured else []
    metadata = {
        GcpResourceMetadata.NAME.key: resource_name(resource),
        GcpResourceMetadata.SELF_LINK.key: values.get("self_link"),
        GcpResourceMetadata.PROJECT.key: values.get("project"),
        GcpResourceMetadata.SERVICE_ACCOUNT_EMAIL.key: service_account_email,
        GcpResourceMetadata.SERVICE_ACCOUNT_MEMBER.key: service_account_member(service_account_email),
        GcpResourceMetadata.SERVICE_ACCOUNTS.key: _service_account_entries(service_account_email),
        GcpResourceMetadata.LABELS.key: values.get("labels") or {},
        "vpc_enabled": vpc_enabled,
        "public_access_reasons": public_access_reasons,
        "public_exposure_reasons": [],
        "provider_managed_egress": True,
    }
    metadata.update(extra_metadata)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.COMPUTE,
        identifier=resource_identifier(resource),
        public_access_configured=public_access_configured,
        metadata=metadata,
    )


def _normalize_serverless_iam_member(
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
        identifier=first_non_empty(
            values.get("id"),
            _binding_identifier(target_reference, role, [member]),
            resource.address,
        ),
        metadata={
            target_field.key: target_reference,
            GcpResourceMetadata.PROJECT.key: values.get("project"),
            GcpResourceMetadata.REGION.key: first_non_empty(values.get("location"), values.get("region")),
            GcpResourceMetadata.IAM_ROLE.key: role,
            GcpResourceMetadata.IAM_MEMBER.key: member,
            GcpResourceMetadata.IAM_MEMBERS.key: compact([member]),
            GcpResourceMetadata.IAM_BINDINGS.key: _iam_bindings(role, compact([member])),
            "condition": values.get("condition"),
        },
    )


def _normalize_serverless_iam_binding(
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
        identifier=first_non_empty(
            values.get("id"),
            _binding_identifier(target_reference, role, members),
            resource.address,
        ),
        metadata={
            target_field.key: target_reference,
            GcpResourceMetadata.PROJECT.key: values.get("project"),
            GcpResourceMetadata.REGION.key: first_non_empty(values.get("location"), values.get("region")),
            GcpResourceMetadata.IAM_ROLE.key: role,
            GcpResourceMetadata.IAM_MEMBERS.key: members,
            GcpResourceMetadata.IAM_BINDINGS.key: _iam_bindings(role, members),
            "condition": values.get("condition"),
        },
    )


def _normalize_serverless_iam_policy(
    resource: TerraformResource,
    *,
    target_field: Any,
    target_keys: tuple[str, ...],
) -> NormalizedResource:
    from tfstride.providers.gcp.resource_utils import load_json_document

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
            GcpResourceMetadata.REGION.key: first_non_empty(values.get("location"), values.get("region")),
            GcpResourceMetadata.IAM_BINDINGS.key: bindings,
            "policy_document": policy_document,
        },
    )


def _target_reference(values: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    return first_non_empty(*[values.get(key) for key in keys])


def _binding_identifier(target_reference: str | None, role: str | None, members: list[str | None]) -> str | None:
    compact_members = compact(members)
    if not target_reference or not role or not compact_members:
        return None
    return f"{target_reference}:{role}:{','.join(compact_members)}"


def _iam_bindings(role: str | None, members: list[str]) -> list[dict[str, object]]:
    if not role or not members:
        return []
    return [{"role": role, "members": members}]


def _policy_bindings(policy_document: dict[str, Any]) -> list[dict[str, object]]:
    bindings = policy_document.get("bindings")
    if not isinstance(bindings, list):
        return []
    normalized: list[dict[str, object]] = []
    for binding in bindings:
        if not isinstance(binding, dict):
            continue
        role = first_non_empty(binding.get("role"))
        members = compact(as_list(binding.get("members")))
        if role and members:
            normalized.append({"role": role, "members": members})
    return normalized


def _has_vpc_attachment(*values: object) -> bool:
    for value in values:
        if value in (None, "", [], {}):
            continue
        if isinstance(value, list):
            if any(_has_vpc_attachment(item) for item in value):
                return True
            continue
        if isinstance(value, dict):
            vpc_keys = ("connector", "network", "subnet", "network_interfaces")
            if any(value.get(key) not in (None, "", [], {}) for key in vpc_keys):
                return True
            continue
        return True
    return False


def _cloud_run_ingress_allows_internet(value: str | None) -> bool:
    if value is None:
        return True
    normalized = value.strip().upper()
    return normalized in {"ALL", "INGRESS_TRAFFIC_ALL"}


def _cloud_run_v1_url(values: dict[str, Any]) -> object:
    status = first_item(values.get("status")) or {}
    return values.get("url") or status.get("url")


def _serverless_reference(values: dict[str, Any], resource: TerraformResource) -> str | None:
    return first_non_empty(values.get("name"), values.get("id"), resource.name, resource.address)


def _service_account_entries(email: str | None) -> list[dict[str, str]]:
    if not email:
        return []
    return [{"email": email}]