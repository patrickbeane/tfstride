from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.gcp.attributes import GcpAttr, GcpAttribute, GcpValues
from tfstride.providers.gcp.coercion import as_list, compact, first_item
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.network_normalizers import GCP_PROVIDER
from tfstride.providers.gcp.resource_mutations import gcp_mutations
from tfstride.providers.gcp.resource_utils import (
    first_non_empty,
    load_json_document,
    resource_identifier,
    resource_name,
    service_account_member,
)


def normalize_cloud_run_service(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    metadata_values = _first_block(values, GcpAttr.METADATA_BLOCKS)
    metadata = GcpValues(metadata_values)
    annotations = GcpValues(metadata.get(GcpAttr.ANNOTATIONS))
    template = GcpValues(_first_block(values, GcpAttr.TEMPLATE))
    spec = GcpValues(_first_block(template, GcpAttr.SPEC))
    service_account = first_non_empty(spec.get(GcpAttr.SERVICE_ACCOUNT_NAME))
    ingress = first_non_empty(annotations.get(GcpAttr.RUN_INGRESS_ANNOTATION), values.get(GcpAttr.INGRESS))
    public_access_configured = _cloud_run_ingress_allows_internet(ingress)
    return _serverless_workload(
        resource,
        service_account_email=service_account,
        public_access_configured=public_access_configured,
        vpc_enabled=_has_vpc_attachment(spec.get(GcpAttr.VPC_ACCESS)),
        extra_metadata={
            GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE: _serverless_reference(values, resource),
            GcpResourceMetadata.REGION: values.get(GcpAttr.LOCATION),
            GcpResourceMetadata.SERVERLESS_INGRESS: ingress,
            "url": _cloud_run_v1_url(values),
            "metadata": metadata_values,
        },
    )


def normalize_cloud_run_v2_service(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    template_values = _first_block(values, GcpAttr.TEMPLATE)
    template = GcpValues(template_values)
    service_account = first_non_empty(template.get(GcpAttr.SERVICE_ACCOUNT))
    ingress = first_non_empty(values.get(GcpAttr.INGRESS))
    public_access_configured = _cloud_run_ingress_allows_internet(ingress)
    return _serverless_workload(
        resource,
        service_account_email=service_account,
        public_access_configured=public_access_configured,
        vpc_enabled=_has_vpc_attachment(template.get(GcpAttr.VPC_ACCESS)),
        extra_metadata={
            GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE: _serverless_reference(values, resource),
            GcpResourceMetadata.REGION: values.get(GcpAttr.LOCATION),
            GcpResourceMetadata.SERVERLESS_INGRESS: ingress,
            "uri": values.get(GcpAttr.URI),
            "template": template_values,
        },
    )


def normalize_cloudfunctions_function(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    service_account = first_non_empty(values.get(GcpAttr.SERVICE_ACCOUNT_EMAIL))
    trigger_http = values.get(GcpAttr.TRIGGER_HTTP)
    return _serverless_workload(
        resource,
        service_account_email=service_account,
        public_access_configured=trigger_http,
        vpc_enabled=_has_vpc_attachment(values.get(GcpAttr.VPC_CONNECTOR)),
        extra_metadata={
            GcpResourceMetadata.CLOUD_FUNCTION_REFERENCE: _serverless_reference(values, resource),
            GcpResourceMetadata.REGION: values.get(GcpAttr.REGION),
            GcpResourceMetadata.SERVERLESS_INGRESS: values.get(GcpAttr.INGRESS_SETTINGS),
            "runtime": values.get(GcpAttr.RUNTIME),
            "trigger_http": trigger_http,
            "https_trigger_url": values.get(GcpAttr.HTTPS_TRIGGER_URL),
        },
    )


def normalize_cloudfunctions2_function(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    service_config_values = _first_block(values, GcpAttr.SERVICE_CONFIG)
    service_config = GcpValues(service_config_values)
    service_account = first_non_empty(service_config.get(GcpAttr.SERVICE_ACCOUNT_EMAIL))
    trigger_http = bool(
        service_config.get(GcpAttr.URI) or values.get(GcpAttr.URL) or service_config.get(GcpAttr.SERVICE)
    )
    return _serverless_workload(
        resource,
        service_account_email=service_account,
        public_access_configured=trigger_http,
        vpc_enabled=_has_vpc_attachment(service_config.get(GcpAttr.VPC_CONNECTOR)),
        extra_metadata={
            GcpResourceMetadata.CLOUD_FUNCTION_REFERENCE: _serverless_reference(values, resource),
            GcpResourceMetadata.REGION: values.get(GcpAttr.LOCATION),
            GcpResourceMetadata.SERVERLESS_INGRESS: service_config.get(GcpAttr.INGRESS_SETTINGS),
            "service_config": service_config_values,
            "build_config": _first_block(values, GcpAttr.BUILD_CONFIG),
            "uri": service_config.get(GcpAttr.URI),
        },
    )


def normalize_cloud_run_service_iam_member(resource: TerraformResource) -> NormalizedResource:
    return _normalize_serverless_iam_member(
        resource,
        target_field=GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE,
        target_keys=(GcpAttr.SERVICE, GcpAttr.NAME),
    )


def normalize_cloud_run_service_iam_binding(resource: TerraformResource) -> NormalizedResource:
    return _normalize_serverless_iam_binding(
        resource,
        target_field=GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE,
        target_keys=(GcpAttr.SERVICE, GcpAttr.NAME),
    )


def normalize_cloud_run_service_iam_policy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_serverless_iam_policy(
        resource,
        target_field=GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE,
        target_keys=(GcpAttr.SERVICE, GcpAttr.NAME),
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
        target_keys=(GcpAttr.CLOUD_FUNCTION, GcpAttr.FUNCTION, GcpAttr.NAME),
    )


def normalize_cloudfunctions_function_iam_binding(resource: TerraformResource) -> NormalizedResource:
    return _normalize_serverless_iam_binding(
        resource,
        target_field=GcpResourceMetadata.CLOUD_FUNCTION_REFERENCE,
        target_keys=(GcpAttr.CLOUD_FUNCTION, GcpAttr.FUNCTION, GcpAttr.NAME),
    )


def normalize_cloudfunctions_function_iam_policy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_serverless_iam_policy(
        resource,
        target_field=GcpResourceMetadata.CLOUD_FUNCTION_REFERENCE,
        target_keys=(GcpAttr.CLOUD_FUNCTION, GcpAttr.FUNCTION, GcpAttr.NAME),
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
    values = GcpValues(resource.values)
    public_access_reasons = ["serverless service has public ingress configured"] if public_access_configured else []
    metadata = {
        GcpResourceMetadata.NAME: resource_name(resource),
        GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
        GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
        GcpResourceMetadata.SERVICE_ACCOUNT_EMAIL: service_account_email,
        GcpResourceMetadata.SERVICE_ACCOUNT_MEMBER: service_account_member(service_account_email),
        GcpResourceMetadata.SERVICE_ACCOUNTS: _service_account_entries(service_account_email),
        GcpResourceMetadata.LABELS: values.get(GcpAttr.LABELS),
        "vpc_enabled": vpc_enabled,
        "provider_managed_egress": True,
    }
    metadata.update(extra_metadata)
    normalized = NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.COMPUTE,
        identifier=resource_identifier(resource),
        public_access_configured=public_access_configured,
        metadata=metadata,
    )
    gcp_mutations(normalized).set_public_access(
        configured=public_access_configured,
        reasons=public_access_reasons,
    )
    return normalized


def _normalize_serverless_iam_member(
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
            values.get(GcpAttr.ID),
            _binding_identifier(target_reference, role, [member]),
            resource.address,
        ),
        metadata={
            target_field: target_reference,
            GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
            GcpResourceMetadata.REGION: first_non_empty(values.get(GcpAttr.LOCATION), values.get(GcpAttr.REGION)),
            GcpResourceMetadata.IAM_ROLE: role,
            GcpResourceMetadata.IAM_MEMBER: member,
            GcpResourceMetadata.IAM_MEMBERS: compact([member]),
            GcpResourceMetadata.IAM_CONDITION: _condition(values.raw(GcpAttr.CONDITION)),
            GcpResourceMetadata.IAM_BINDINGS: _iam_bindings(
                role, compact([member]), condition=values.raw(GcpAttr.CONDITION)
            ),
        },
    )


def _normalize_serverless_iam_binding(
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
            values.get(GcpAttr.ID),
            _binding_identifier(target_reference, role, members),
            resource.address,
        ),
        metadata={
            target_field: target_reference,
            GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
            GcpResourceMetadata.REGION: first_non_empty(values.get(GcpAttr.LOCATION), values.get(GcpAttr.REGION)),
            GcpResourceMetadata.IAM_ROLE: role,
            GcpResourceMetadata.IAM_MEMBERS: members,
            GcpResourceMetadata.IAM_CONDITION: _condition(values.raw(GcpAttr.CONDITION)),
            GcpResourceMetadata.IAM_BINDINGS: _iam_bindings(role, members, condition=values.raw(GcpAttr.CONDITION)),
        },
    )


def _normalize_serverless_iam_policy(
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
            GcpResourceMetadata.REGION: first_non_empty(values.get(GcpAttr.LOCATION), values.get(GcpAttr.REGION)),
            GcpResourceMetadata.IAM_BINDINGS: bindings,
            GcpResourceMetadata.POLICY_DOCUMENT: policy_document,
        },
    )


def _target_reference(values: GcpValues, keys: tuple[GcpAttribute[Any], ...]) -> str | None:
    return first_non_empty(*(values.get(key) for key in keys))


def _binding_identifier(target_reference: str | None, role: str | None, members: list[str | None]) -> str | None:
    compact_members = compact(members)
    if not target_reference or not role or not compact_members:
        return None
    return f"{target_reference}:{role}:{','.join(compact_members)}"


def _iam_bindings(
    role: str | None,
    members: list[str],
    *,
    condition: Any = None,
) -> list[dict[str, object]]:
    if not role or not members:
        return []
    binding: dict[str, object] = {"role": role, "members": members}
    normalized_condition = _condition(condition)
    if normalized_condition:
        binding["condition"] = normalized_condition
    return [binding]


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
            normalized.extend(_iam_bindings(role, members, condition=binding.get("condition")))
    return normalized


def _condition(value: Any) -> dict[str, Any]:
    if isinstance(value, list):
        value = value[0] if value and isinstance(value[0], dict) else {}
    if not isinstance(value, dict):
        return {}
    return {str(key): raw_value for key, raw_value in value.items() if raw_value not in (None, "", [])}


def _first_block(values: GcpValues, attribute: GcpAttribute[Any]) -> dict[str, Any]:
    return first_item(values.get(attribute)) or {}


def _has_vpc_attachment(*values: object) -> bool:
    for value in values:
        if value in (None, "", [], {}):
            continue
        if isinstance(value, list):
            if any(_has_vpc_attachment(item) for item in value):
                return True
            continue
        if isinstance(value, dict):
            item = GcpValues(value)
            vpc_fields = (GcpAttr.CONNECTOR, GcpAttr.NETWORK, GcpAttr.SUBNET, GcpAttr.NETWORK_INTERFACES)
            if any(item.raw(field) not in (None, "", [], {}) for field in vpc_fields):
                return True
            continue
        return True
    return False


def _cloud_run_ingress_allows_internet(value: str | None) -> bool:
    if value is None:
        return True
    normalized = value.strip().upper()
    return normalized in {"ALL", "INGRESS_TRAFFIC_ALL"}


def _cloud_run_v1_url(values: GcpValues) -> object:
    status = GcpValues(_first_block(values, GcpAttr.STATUS))
    return values.get(GcpAttr.URL) or status.get(GcpAttr.URL)


def _serverless_reference(values: GcpValues, resource: TerraformResource) -> str | None:
    return first_non_empty(values.get(GcpAttr.NAME), values.get(GcpAttr.ID), resource.name, resource.address)


def _service_account_entries(email: str | None) -> list[dict[str, str]]:
    if not email:
        return []
    return [{"email": email}]
