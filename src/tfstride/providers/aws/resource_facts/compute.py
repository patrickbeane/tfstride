from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.resource_facts.base import AwsBaseFacts, _bool_from_state
from tfstride.resource_metadata import DictListMetadataField


class AwsComputeFacts(AwsBaseFacts):
    __slots__ = ()

    @property
    def ecs_load_balancers(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.ECS_LOAD_BALANCERS)

    @property
    def cluster_reference(self) -> str | None:
        return self.get(AwsResourceMetadata.CLUSTER_REFERENCE)

    @property
    def task_definition_reference(self) -> str | None:
        return self.get(AwsResourceMetadata.TASK_DEFINITION_REFERENCE)

    @property
    def task_definition_family(self) -> str | None:
        return self.get(AwsResourceMetadata.TASK_DEFINITION_FAMILY)

    @property
    def task_definition_revision(self) -> int | None:
        return self.get(AwsResourceMetadata.TASK_DEFINITION_REVISION)

    @property
    def network_mode(self) -> str | None:
        return self.get(AwsResourceMetadata.NETWORK_MODE)

    @property
    def requires_compatibilities(self) -> list[str]:
        return self.get(AwsResourceMetadata.REQUIRES_COMPATIBILITIES)

    @property
    def task_role_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.TASK_ROLE_ARN)

    @property
    def execution_role_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.EXECUTION_ROLE_ARN)

    @property
    def function_name(self) -> str | None:
        return self.get(AwsResourceMetadata.FUNCTION_NAME)

    @property
    def lambda_package_type(self) -> str | None:
        return self.get(AwsResourceMetadata.LAMBDA_PACKAGE_TYPE)

    @property
    def container_image_references(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.CONTAINER_IMAGE_REFERENCES)

    @property
    def container_image_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.CONTAINER_IMAGE_POSTURE_UNCERTAINTIES)

    @property
    def ecs_secret_references(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.ECS_SECRET_REFERENCES)

    @property
    def ecs_secret_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.ECS_SECRET_POSTURE_UNCERTAINTIES)

    @property
    def ecs_network_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.ECS_NETWORK_POSTURE_UNCERTAINTIES)

    @property
    def ecs_security_group_reference_state(self) -> str | None:
        return self.get(AwsResourceMetadata.ECS_SECURITY_GROUP_REFERENCE_STATE)

    @property
    def ecs_secret_access_paths(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.ECS_SECRET_ACCESS_PATHS)

    @property
    def ecs_secret_access_path_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.ECS_SECRET_ACCESS_PATH_UNCERTAINTIES)

    @property
    def ecr_write_paths(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.ECR_WRITE_PATHS)

    @property
    def ecr_write_path_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.ECR_WRITE_PATH_UNCERTAINTIES)

    @property
    def lambda_function_url_function_reference(self) -> str | None:
        return self.function_name

    @property
    def lambda_function_url(self) -> str | None:
        return self.get(AwsResourceMetadata.LAMBDA_FUNCTION_URL)

    @property
    def lambda_function_url_authorization_type(self) -> str | None:
        return self.get(AwsResourceMetadata.LAMBDA_FUNCTION_URL_AUTHORIZATION_TYPE)

    @property
    def lambda_function_url_qualifier(self) -> str | None:
        return self.get(AwsResourceMetadata.LAMBDA_FUNCTION_URL_QUALIFIER)

    @property
    def lambda_function_url_invoke_mode(self) -> str | None:
        return self.get(AwsResourceMetadata.LAMBDA_FUNCTION_URL_INVOKE_MODE)

    @property
    def lambda_function_url_cors(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.LAMBDA_FUNCTION_URL_CORS)

    @property
    def lambda_function_url_cors_allow_credentials_state(self) -> str | None:
        return self.get(AwsResourceMetadata.LAMBDA_FUNCTION_URL_CORS_ALLOW_CREDENTIALS_STATE)

    @property
    def lambda_function_url_cors_allow_credentials(self) -> bool | None:
        return _bool_from_state(self.lambda_function_url_cors_allow_credentials_state)

    @property
    def lambda_function_url_cors_allow_headers(self) -> list[str]:
        return self.get(AwsResourceMetadata.LAMBDA_FUNCTION_URL_CORS_ALLOW_HEADERS)

    @property
    def lambda_function_url_cors_allow_methods(self) -> list[str]:
        return self.get(AwsResourceMetadata.LAMBDA_FUNCTION_URL_CORS_ALLOW_METHODS)

    @property
    def lambda_function_url_cors_allow_origins(self) -> list[str]:
        return self.get(AwsResourceMetadata.LAMBDA_FUNCTION_URL_CORS_ALLOW_ORIGINS)

    @property
    def lambda_function_url_cors_expose_headers(self) -> list[str]:
        return self.get(AwsResourceMetadata.LAMBDA_FUNCTION_URL_CORS_EXPOSE_HEADERS)

    @property
    def lambda_function_url_cors_max_age(self) -> int | None:
        return self.get(AwsResourceMetadata.LAMBDA_FUNCTION_URL_CORS_MAX_AGE)

    @property
    def lambda_function_url_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.LAMBDA_FUNCTION_URL_POSTURE_UNCERTAINTIES)

    @property
    def api_gateway_api_id(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_API_ID)

    @property
    def api_gateway_name(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_NAME)

    @property
    def api_gateway_description(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_DESCRIPTION)

    @property
    def api_gateway_protocol_type(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_PROTOCOL_TYPE)

    @property
    def api_gateway_api_endpoint(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_API_ENDPOINT)

    @property
    def api_gateway_execution_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_EXECUTION_ARN)

    @property
    def api_gateway_endpoint_types(self) -> list[str]:
        return self.get(AwsResourceMetadata.API_GATEWAY_ENDPOINT_TYPES)

    @property
    def api_gateway_vpc_endpoint_ids(self) -> list[str]:
        return self.get(AwsResourceMetadata.API_GATEWAY_VPC_ENDPOINT_IDS)

    @property
    def api_gateway_endpoint_configuration(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.API_GATEWAY_ENDPOINT_CONFIGURATION)

    @property
    def api_gateway_execute_api_endpoint_state(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_EXECUTE_API_ENDPOINT_STATE)

    @property
    def api_gateway_public_endpoint_state(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_PUBLIC_ENDPOINT_STATE)

    @property
    def api_gateway_route_selection_expression(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_ROUTE_SELECTION_EXPRESSION)

    @property
    def api_gateway_route_key(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_ROUTE_KEY)

    @property
    def api_gateway_openapi_body_state(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_OPENAPI_BODY_STATE)

    @property
    def api_gateway_cors_configuration(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.API_GATEWAY_CORS_CONFIGURATION)

    @property
    def api_gateway_parent_api_address(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_PARENT_API_ADDRESS)

    @property
    def api_gateway_method_resource_id(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_METHOD_RESOURCE_ID)

    @property
    def api_gateway_method_http_method(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_METHOD_HTTP_METHOD)

    @property
    def api_gateway_authorization_type(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_AUTHORIZATION_TYPE)

    @property
    def api_gateway_authorizer_id(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_AUTHORIZER_ID)

    @property
    def api_gateway_authorization_scopes(self) -> list[str]:
        return self.get(AwsResourceMetadata.API_GATEWAY_AUTHORIZATION_SCOPES)

    @property
    def api_gateway_stage_name(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_STAGE_NAME)

    @property
    def api_gateway_access_log_destination_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_ACCESS_LOG_DESTINATION_ARN)

    @property
    def api_gateway_access_log_format(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_ACCESS_LOG_FORMAT)

    @property
    def api_gateway_authorizer_name(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_AUTHORIZER_NAME)

    @property
    def api_gateway_authorizer_type(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_AUTHORIZER_TYPE)

    @property
    def api_gateway_authorizer_uri(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_AUTHORIZER_URI)

    @property
    def api_gateway_authorizer_credentials(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_AUTHORIZER_CREDENTIALS)

    @property
    def api_gateway_identity_source(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_IDENTITY_SOURCE)

    @property
    def api_gateway_identity_validation_expression(self) -> str | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_IDENTITY_VALIDATION_EXPRESSION)

    @property
    def api_gateway_authorizer_provider_arns(self) -> list[str]:
        return self.get(AwsResourceMetadata.API_GATEWAY_AUTHORIZER_PROVIDER_ARNS)

    @property
    def api_gateway_authorizer_result_ttl(self) -> int | None:
        return self.get(AwsResourceMetadata.API_GATEWAY_AUTHORIZER_RESULT_TTL)

    @property
    def api_gateway_methods(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.API_GATEWAY_METHODS)

    @property
    def api_gateway_stages(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.API_GATEWAY_STAGES)

    @property
    def api_gateway_authorizers(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.API_GATEWAY_AUTHORIZERS)

    @property
    def api_gateway_routes(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.API_GATEWAY_ROUTES)

    @property
    def unresolved_api_gateway_api_ids(self) -> list[str]:
        return self.get(AwsResourceMetadata.UNRESOLVED_API_GATEWAY_API_IDS)

    @property
    def api_gateway_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.API_GATEWAY_POSTURE_UNCERTAINTIES)

    def set_api_gateway_parent_api_address(self, address: str) -> None:
        self.set(AwsResourceMetadata.API_GATEWAY_PARENT_API_ADDRESS, address)

    def add_unresolved_api_gateway_api_id(self, api_id: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_API_GATEWAY_API_IDS, api_id)

    def extend_api_gateway_posture_uncertainties(self, uncertainties: list[str]) -> None:
        self.extend(AwsResourceMetadata.API_GATEWAY_POSTURE_UNCERTAINTIES, uncertainties)

    def add_api_gateway_method(self, method: dict[str, Any]) -> None:
        self._append_api_gateway_record(AwsResourceMetadata.API_GATEWAY_METHODS, method)

    def add_api_gateway_stage(self, stage: dict[str, Any]) -> None:
        self._append_api_gateway_record(AwsResourceMetadata.API_GATEWAY_STAGES, stage)

    def add_api_gateway_authorizer(self, authorizer: dict[str, Any]) -> None:
        self._append_api_gateway_record(AwsResourceMetadata.API_GATEWAY_AUTHORIZERS, authorizer)

    def add_api_gateway_route(self, route: dict[str, Any]) -> None:
        self._append_api_gateway_record(AwsResourceMetadata.API_GATEWAY_ROUTES, route)

    def _append_api_gateway_record(self, field: DictListMetadataField, record: dict[str, Any]) -> None:
        existing = self.get(field)
        if record not in existing:
            existing.append(record)
            self.set(field, existing)

    @property
    def eks_cluster_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_CLUSTER_ARN)

    @property
    def eks_cluster_role_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_CLUSTER_ROLE_ARN)

    @property
    def eks_kubernetes_version(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_KUBERNETES_VERSION)

    @property
    def eks_endpoint_public_access_state(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_ENDPOINT_PUBLIC_ACCESS_STATE)

    @property
    def eks_endpoint_private_access_state(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_ENDPOINT_PRIVATE_ACCESS_STATE)

    @property
    def eks_public_access_cidrs(self) -> list[str]:
        return self.get(AwsResourceMetadata.EKS_PUBLIC_ACCESS_CIDRS)

    @property
    def eks_public_access_cidrs_state(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_PUBLIC_ACCESS_CIDRS_STATE)

    @property
    def eks_subnet_ids(self) -> list[str]:
        return self.get(AwsResourceMetadata.EKS_SUBNET_IDS)

    @property
    def eks_security_group_ids(self) -> list[str]:
        return self.get(AwsResourceMetadata.EKS_SECURITY_GROUP_IDS)

    @property
    def eks_cluster_security_group_id(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_CLUSTER_SECURITY_GROUP_ID)

    @property
    def eks_vpc_config(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.EKS_VPC_CONFIG)

    @property
    def eks_enabled_cluster_log_types(self) -> list[str]:
        return self.get(AwsResourceMetadata.EKS_ENABLED_CLUSTER_LOG_TYPES)

    @property
    def eks_control_plane_logging_state(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_CONTROL_PLANE_LOGGING_STATE)

    @property
    def eks_encryption_config(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.EKS_ENCRYPTION_CONFIG)

    @property
    def eks_encryption_config_state(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_ENCRYPTION_CONFIG_STATE)

    @property
    def eks_secrets_encryption_state(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_SECRETS_ENCRYPTION_STATE)

    @property
    def eks_encryption_key_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_ENCRYPTION_KEY_ARN)

    @property
    def eks_encryption_resources(self) -> list[str]:
        return self.get(AwsResourceMetadata.EKS_ENCRYPTION_RESOURCES)

    @property
    def eks_access_config_state(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_ACCESS_CONFIG_STATE)

    @property
    def eks_authentication_mode(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_AUTHENTICATION_MODE)

    @property
    def eks_bootstrap_cluster_creator_admin_permissions_state(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_BOOTSTRAP_CLUSTER_CREATOR_ADMIN_PERMISSIONS_STATE)

    @property
    def eks_access_config(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.EKS_ACCESS_CONFIG)

    @property
    def eks_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.EKS_POSTURE_UNCERTAINTIES)

    @property
    def eks_addon_name(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_ADDON_NAME)

    @property
    def eks_addon_cluster_name(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_ADDON_CLUSTER_NAME)

    @property
    def eks_addon_version(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_ADDON_VERSION)

    @property
    def eks_addon_configuration_values(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_ADDON_CONFIGURATION_VALUES)

    @property
    def eks_addon_configuration_keys(self) -> list[str]:
        return self.get(AwsResourceMetadata.EKS_ADDON_CONFIGURATION_KEYS)

    @property
    def eks_addon_preserve_state(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_ADDON_PRESERVE_STATE)

    @property
    def eks_addon_preserve(self) -> bool | None:
        return _bool_from_state(self.eks_addon_preserve_state)

    @property
    def eks_addon_service_account_role_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_ADDON_SERVICE_ACCOUNT_ROLE_ARN)

    @property
    def eks_addon_target_class(self) -> str | None:
        return self.get(AwsResourceMetadata.EKS_ADDON_TARGET_CLASS)

    def set_network_mode(self, value: str | None) -> None:
        self.set(AwsResourceMetadata.NETWORK_MODE, value)

    def set_requires_compatibilities(self, values: list[str]) -> None:
        self.set(AwsResourceMetadata.REQUIRES_COMPATIBILITIES, values)

    def set_task_role_arn(self, value: str | None) -> None:
        self.set(AwsResourceMetadata.TASK_ROLE_ARN, value)

    def set_execution_role_arn(self, value: str | None) -> None:
        self.set(AwsResourceMetadata.EXECUTION_ROLE_ARN, value)

    def set_ecr_write_paths(self, values: list[dict[str, Any]]) -> None:
        self.set(AwsResourceMetadata.ECR_WRITE_PATHS, values)

    def set_ecs_secret_access_paths(self, values: list[dict[str, Any]]) -> None:
        self.set(AwsResourceMetadata.ECS_SECRET_ACCESS_PATHS, values)

    def extend_ecs_secret_access_path_uncertainties(self, values: Sequence[str | None]) -> None:
        self.extend(AwsResourceMetadata.ECS_SECRET_ACCESS_PATH_UNCERTAINTIES, values)

    def extend_ecr_write_path_uncertainties(self, values: Sequence[str | None]) -> None:
        self.extend(AwsResourceMetadata.ECR_WRITE_PATH_UNCERTAINTIES, values)

    def add_unresolved_cluster_reference(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_CLUSTER_REFERENCES, value)

    def add_resolved_cluster_address(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.RESOLVED_CLUSTER_ADDRESSES, value)

    def add_unresolved_task_definition_reference(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_TASK_DEFINITION_REFERENCES, value)

    def add_resolved_task_definition_address(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.RESOLVED_TASK_DEFINITION_ADDRESSES, value)

    def add_resolved_task_role_address(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.RESOLVED_TASK_ROLE_ADDRESSES, value)

    def add_unresolved_task_role_arn(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_TASK_ROLE_ARNS, value)

    def add_resolved_execution_role_address(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.RESOLVED_EXECUTION_ROLE_ADDRESSES, value)

    def add_unresolved_execution_role_arn(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_EXECUTION_ROLE_ARNS, value)

    def add_unresolved_function_reference(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_FUNCTION_REFERENCES, value)
