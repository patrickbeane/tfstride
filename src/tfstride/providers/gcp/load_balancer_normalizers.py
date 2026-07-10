from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.coercion import known_string
from tfstride.providers.gcp.attributes import GcpAttr, GcpValues
from tfstride.providers.gcp.coercion import compact, first_item
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.network_normalizer_utils import _dict_list, _known_dict_list, _string_from_raw
from tfstride.providers.gcp.normalizer_common import GCP_PROVIDER
from tfstride.providers.gcp.resource_mutations import gcp_mutations
from tfstride.providers.gcp.resource_utils import first_non_empty, resource_identifier, resource_name


def normalize_compute_forwarding_rule(resource: TerraformResource) -> NormalizedResource:
    return _normalize_forwarding_rule(resource)


def normalize_compute_global_forwarding_rule(resource: TerraformResource) -> NormalizedResource:
    return _normalize_forwarding_rule(resource)


def normalize_compute_url_map(resource: TerraformResource) -> NormalizedResource:
    return _normalize_url_map(resource)


def normalize_compute_region_url_map(resource: TerraformResource) -> NormalizedResource:
    return _normalize_url_map(resource)


def normalize_compute_target_http_proxy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_proxy(resource)


def normalize_compute_target_https_proxy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_proxy(resource)


def normalize_compute_security_policy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_security_policy(resource)


def normalize_compute_region_security_policy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_security_policy(resource)


def normalize_compute_ssl_policy(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=resource_identifier(resource),
        metadata=_load_balancer_metadata(
            values,
            {
                GcpResourceMetadata.SSL_POLICY_NAME: first_non_empty(values.get(GcpAttr.NAME), resource.name),
                GcpResourceMetadata.SSL_POLICY_MIN_TLS_VERSION: values.get(GcpAttr.MIN_TLS_VERSION),
                GcpResourceMetadata.SSL_POLICY_PROFILE: values.get(GcpAttr.PROFILE),
                GcpResourceMetadata.SSL_POLICY_CUSTOM_FEATURES: values.get(GcpAttr.CUSTOM_FEATURES),
                GcpResourceMetadata.SSL_POLICY_ENABLED_FEATURES: values.get(GcpAttr.ENABLED_FEATURES),
            },
        ),
    )


def normalize_compute_managed_ssl_certificate(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    managed = first_item(values.get(GcpAttr.MANAGED)) or {}
    managed_values = GcpValues(managed)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=resource_identifier(resource),
        metadata=_load_balancer_metadata(
            values,
            {
                GcpResourceMetadata.MANAGED_SSL_CERTIFICATE_NAME: first_non_empty(
                    values.get(GcpAttr.NAME), resource.name
                ),
                GcpResourceMetadata.MANAGED_SSL_CERTIFICATE_DOMAINS: managed_values.get(GcpAttr.DOMAINS),
                GcpResourceMetadata.MANAGED_SSL_CERTIFICATE_STATUS: managed_values.get(GcpAttr.STATUS_TEXT),
            },
        ),
    )


def normalize_compute_region_target_http_proxy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_proxy(resource)


def normalize_compute_region_target_https_proxy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_proxy(resource)


def normalize_compute_backend_service(resource: TerraformResource) -> NormalizedResource:
    return _normalize_backend_service(resource)


def normalize_compute_region_backend_service(resource: TerraformResource) -> NormalizedResource:
    return _normalize_backend_service(resource)


def normalize_compute_backend_bucket(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=resource_identifier(resource),
        metadata=_load_balancer_metadata(
            values,
            {
                GcpResourceMetadata.LOAD_BALANCER_BACKEND_BUCKET_NAME: values.get(GcpAttr.BUCKET_NAME),
            },
        ),
    )


def normalize_compute_network_endpoint_group(resource: TerraformResource) -> NormalizedResource:
    return _normalize_network_endpoint_group(resource)


def normalize_compute_region_network_endpoint_group(resource: TerraformResource) -> NormalizedResource:
    return _normalize_network_endpoint_group(resource)


def _normalize_url_map(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=resource_identifier(resource),
        metadata=_load_balancer_metadata(
            values,
            {
                GcpResourceMetadata.LOAD_BALANCER_DEFAULT_SERVICE: values.get(GcpAttr.DEFAULT_SERVICE),
                GcpResourceMetadata.LOAD_BALANCER_HOST_RULES: _dict_list(values.get(GcpAttr.HOST_RULE)),
                GcpResourceMetadata.LOAD_BALANCER_PATH_MATCHERS: _dict_list(values.get(GcpAttr.PATH_MATCHER)),
            },
        ),
    )


def _normalize_target_proxy(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=resource_identifier(resource),
        metadata=_load_balancer_metadata(
            values,
            {
                GcpResourceMetadata.LOAD_BALANCER_URL_MAP: values.get(GcpAttr.URL_MAP),
                GcpResourceMetadata.LOAD_BALANCER_SSL_CERTIFICATES: values.get(GcpAttr.SSL_CERTIFICATES),
                GcpResourceMetadata.LOAD_BALANCER_SSL_POLICY: values.get(GcpAttr.SSL_POLICY),
                GcpResourceMetadata.LOAD_BALANCER_CERTIFICATE_MAP: values.get(GcpAttr.CERTIFICATE_MAP),
            },
        ),
    )


def _normalize_backend_service(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    edge_protection_uncertainties: list[str] = []
    security_policy = known_string(
        resource.values, resource.unknown_values, GcpAttr.SECURITY_POLICY.key, edge_protection_uncertainties
    )
    edge_security_policy = known_string(
        resource.values, resource.unknown_values, GcpAttr.EDGE_SECURITY_POLICY.key, edge_protection_uncertainties
    )
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=resource_identifier(resource),
        metadata=_load_balancer_metadata(
            values,
            {
                GcpResourceMetadata.LOAD_BALANCER_BACKEND_SERVICE_PROTOCOL: values.get(GcpAttr.PROTOCOL),
                GcpResourceMetadata.LOAD_BALANCER_BACKEND_SERVICE_LOAD_BALANCING_SCHEME: values.get(
                    GcpAttr.LOAD_BALANCING_SCHEME
                ),
                GcpResourceMetadata.LOAD_BALANCER_BACKENDS: _dict_list(values.get(GcpAttr.BACKEND)),
                GcpResourceMetadata.LOAD_BALANCER_BACKEND_SERVICE_SECURITY_POLICY: security_policy,
                GcpResourceMetadata.LOAD_BALANCER_BACKEND_SERVICE_EDGE_SECURITY_POLICY: edge_security_policy,
                GcpResourceMetadata.EDGE_PROTECTION_POSTURE_UNCERTAINTIES: edge_protection_uncertainties,
            },
        ),
    )


def _normalize_security_policy(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    name = known_string(values, unknown_values, GcpAttr.NAME.key, uncertainties) or resource.name
    self_link = known_string(values, unknown_values, GcpAttr.SELF_LINK.key, uncertainties)
    policy_type = known_string(values, unknown_values, GcpAttr.TYPE.key, uncertainties)
    default_action = known_string(values, unknown_values, GcpAttr.DEFAULT_ACTION.key, uncertainties)
    rules = _known_dict_list(values, unknown_values, GcpAttr.RULE.key, uncertainties)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=first_non_empty(self_link, name, resource.address),
        metadata=_load_balancer_metadata(
            GcpValues(values),
            {
                GcpResourceMetadata.SECURITY_POLICY_NAME: name,
                GcpResourceMetadata.SECURITY_POLICY_TYPE: policy_type,
                GcpResourceMetadata.SECURITY_POLICY_DEFAULT_ACTION: default_action
                or _security_policy_default_rule_action(rules),
                GcpResourceMetadata.SECURITY_POLICY_RULES: rules,
                GcpResourceMetadata.SECURITY_POLICY_RULE_ACTIONS: _security_policy_rule_actions(rules),
                GcpResourceMetadata.EDGE_PROTECTION_POSTURE_UNCERTAINTIES: uncertainties,
            },
        ),
    )


def _normalize_network_endpoint_group(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=resource_identifier(resource),
        vpc_id=values.get(GcpAttr.NETWORK),
        subnet_ids=tuple(compact([values.get(GcpAttr.SUBNETWORK)])),
        metadata=_load_balancer_metadata(
            values,
            {
                GcpResourceMetadata.NETWORK: values.get(GcpAttr.NETWORK),
                GcpResourceMetadata.SUBNETWORK: values.get(GcpAttr.SUBNETWORK),
                GcpResourceMetadata.LOAD_BALANCER_NETWORK_ENDPOINT_TYPE: values.get(GcpAttr.NETWORK_ENDPOINT_TYPE),
                GcpResourceMetadata.LOAD_BALANCER_SERVERLESS_ENDPOINTS: _serverless_neg_endpoints(values),
                GcpResourceMetadata.LOAD_BALANCER_NETWORK_ENDPOINTS: _dict_list(values.get(GcpAttr.NETWORK_ENDPOINT)),
            },
        ),
    )


def _load_balancer_metadata(values: GcpValues, metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        GcpResourceMetadata.NAME: first_non_empty(values.get(GcpAttr.NAME)),
        GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
        GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
        GcpResourceMetadata.REGION: values.get(GcpAttr.REGION),
        GcpResourceMetadata.ZONE: values.get(GcpAttr.ZONE),
        **metadata,
    }


def _serverless_neg_endpoints(values: GcpValues) -> list[dict[str, Any]]:
    endpoints: list[dict[str, Any]] = []
    endpoints.extend(_serverless_neg_endpoint("cloud_run", item) for item in _dict_list(values.get(GcpAttr.CLOUD_RUN)))
    endpoints.extend(
        _serverless_neg_endpoint("cloud_function", item)
        for item in _dict_list(values.get(GcpAttr.CLOUD_FUNCTION_BLOCKS))
    )
    endpoints.extend(
        _serverless_neg_endpoint("app_engine", item) for item in _dict_list(values.get(GcpAttr.APP_ENGINE))
    )
    return [endpoint for endpoint in endpoints if len(endpoint) > 1]


def _serverless_neg_endpoint(platform: str, values: dict[str, Any]) -> dict[str, Any]:
    endpoint_values = GcpValues(values)
    endpoint = {
        "platform": platform,
        "service": endpoint_values.get(GcpAttr.SERVICE),
        "function": endpoint_values.get(GcpAttr.FUNCTION),
        "version": endpoint_values.get(GcpAttr.VERSION),
        "tag": endpoint_values.get(GcpAttr.TAG),
        "url_mask": endpoint_values.get(GcpAttr.URL_MASK),
    }
    return {key: value for key, value in endpoint.items() if value not in (None, "", [], {})}


def _normalize_forwarding_rule(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    public_access_configured = _forwarding_rule_is_public(values)
    public_reasons = ["forwarding rule uses an external load balancing scheme"] if public_access_configured else []
    normalized = NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=resource_identifier(resource),
        vpc_id=values.get(GcpAttr.NETWORK),
        subnet_ids=tuple(compact([values.get(GcpAttr.SUBNETWORK)])),
        public_access_configured=public_access_configured,
        public_exposure=public_access_configured,
        metadata={
            GcpResourceMetadata.NAME: resource_name(resource),
            GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
            GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
            GcpResourceMetadata.REGION: values.get(GcpAttr.REGION),
            GcpResourceMetadata.NETWORK: values.get(GcpAttr.NETWORK),
            GcpResourceMetadata.SUBNETWORK: values.get(GcpAttr.SUBNETWORK),
            GcpResourceMetadata.FORWARDING_RULE_IP_ADDRESS: values.get(GcpAttr.IP_ADDRESS),
            GcpResourceMetadata.FORWARDING_RULE_LOAD_BALANCING_SCHEME: values.get(GcpAttr.LOAD_BALANCING_SCHEME),
            GcpResourceMetadata.FORWARDING_RULE_TARGET: values.get(GcpAttr.TARGET),
            GcpResourceMetadata.FORWARDING_RULE_BACKEND_SERVICE: values.get(GcpAttr.BACKEND_SERVICE),
            GcpResourceMetadata.PSC_CONNECTION_ID: _string_from_raw(values.raw(GcpAttr.PSC_CONNECTION_ID)),
            GcpResourceMetadata.PSC_CONNECTION_STATUS: values.get(GcpAttr.PSC_CONNECTION_STATUS),
            GcpResourceMetadata.PSC_SERVICE_LABEL: values.get(GcpAttr.SERVICE_LABEL),
            GcpResourceMetadata.PSC_SERVICE_NAME: values.get(GcpAttr.SERVICE_NAME),
            GcpResourceMetadata.FORWARDING_RULE_PORTS: values.get(GcpAttr.PORTS),
            GcpResourceMetadata.FORWARDING_RULE_SOURCE_IP_RANGES: values.get(GcpAttr.SOURCE_IP_RANGES),
            "ip_protocol": values.get(GcpAttr.IP_PROTOCOL),
            "port_range": values.get(GcpAttr.PORT_RANGE),
            "all_ports": values.get(GcpAttr.ALL_PORTS),
            "allow_global_access": values.get(GcpAttr.ALLOW_GLOBAL_ACCESS),
        },
    )
    mutations = gcp_mutations(normalized)
    mutations.set_public_access(configured=public_access_configured, reasons=public_reasons)
    mutations.set_public_endpoint_posture(
        direct_internet_reachable=public_access_configured,
        internet_ingress_capable=public_access_configured,
        internet_ingress_reasons=public_reasons,
    )
    mutations.set_public_exposure(public_access_configured, reasons=public_reasons)
    return normalized


def _forwarding_rule_is_public(values: GcpValues) -> bool:
    scheme = str(values.get(GcpAttr.LOAD_BALANCING_SCHEME) or "EXTERNAL").strip().upper()
    return scheme in {"EXTERNAL", "EXTERNAL_MANAGED"}


def _security_policy_rule_actions(rules: list[dict[str, Any]]) -> list[str]:
    actions: list[str] = []
    for rule in rules:
        action = rule.get("action")
        if action in (None, ""):
            continue
        text = str(action).strip()
        if text and text not in actions:
            actions.append(text)
    return actions


def _security_policy_default_rule_action(rules: list[dict[str, Any]]) -> str | None:
    for rule in rules:
        if _security_policy_rule_priority(rule) == 2147483647:
            action = rule.get("action")
            return str(action).strip() if action not in (None, "") else None
    return None


def _security_policy_rule_priority(rule: dict[str, Any]) -> int | None:
    value = rule.get("priority")
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
