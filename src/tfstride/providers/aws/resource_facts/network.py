from __future__ import annotations

from typing import Any

from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.resource_facts.base import _bool_from_state


class AwsNetworkFacts:
    __slots__ = ()

    @property
    def security_group_id(self) -> str | None:
        return self.get(AwsResourceMetadata.SECURITY_GROUP_ID)

    @property
    def route_table_id(self) -> str | None:
        return self.get(AwsResourceMetadata.ROUTE_TABLE_ID)

    @property
    def subnet_id(self) -> str | None:
        return self.get(AwsResourceMetadata.SUBNET_ID)

    @property
    def routes(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.ROUTES)

    @property
    def map_public_ip_on_launch(self) -> bool:
        return self.get(AwsResourceMetadata.MAP_PUBLIC_IP_ON_LAUNCH)

    @property
    def vpc_endpoint_id(self) -> str | None:
        return self.get(AwsResourceMetadata.VPC_ENDPOINT_ID)

    @property
    def vpc_endpoint_service_name(self) -> str | None:
        return self.get(AwsResourceMetadata.VPC_ENDPOINT_SERVICE_NAME)

    @property
    def vpc_endpoint_service_family(self) -> str | None:
        return self.get(AwsResourceMetadata.VPC_ENDPOINT_SERVICE_FAMILY)

    @property
    def vpc_endpoint_type(self) -> str | None:
        return self.get(AwsResourceMetadata.VPC_ENDPOINT_TYPE)

    @property
    def vpc_endpoint_vpc_id(self) -> str | None:
        return self.get(AwsResourceMetadata.VPC_ENDPOINT_VPC_ID)

    @property
    def vpc_endpoint_route_table_ids(self) -> list[str]:
        return self.get(AwsResourceMetadata.VPC_ENDPOINT_ROUTE_TABLE_IDS)

    @property
    def vpc_endpoint_subnet_ids(self) -> list[str]:
        return self.get(AwsResourceMetadata.VPC_ENDPOINT_SUBNET_IDS)

    @property
    def vpc_endpoint_security_group_ids(self) -> list[str]:
        return self.get(AwsResourceMetadata.VPC_ENDPOINT_SECURITY_GROUP_IDS)

    @property
    def vpc_endpoint_private_dns_enabled_state(self) -> str | None:
        return self.get(AwsResourceMetadata.VPC_ENDPOINT_PRIVATE_DNS_ENABLED_STATE)

    @property
    def vpc_endpoint_private_dns_enabled(self) -> bool | None:
        return _bool_from_state(self.vpc_endpoint_private_dns_enabled_state)

    @property
    def vpc_endpoint_policy_document(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.VPC_ENDPOINT_POLICY_DOCUMENT)

    @property
    def vpc_endpoint_dns_entries(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.VPC_ENDPOINT_DNS_ENTRIES)

    @property
    def vpc_endpoint_dns_names(self) -> list[str]:
        return self.get(AwsResourceMetadata.VPC_ENDPOINT_DNS_NAMES)

    @property
    def vpc_endpoint_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.VPC_ENDPOINT_POSTURE_UNCERTAINTIES)

    @property
    def flow_log_id(self) -> str | None:
        return self.get(AwsResourceMetadata.FLOW_LOG_ID)

    @property
    def flow_log_target_type(self) -> str | None:
        return self.get(AwsResourceMetadata.FLOW_LOG_TARGET_TYPE)

    @property
    def flow_log_target_id(self) -> str | None:
        return self.get(AwsResourceMetadata.FLOW_LOG_TARGET_ID)

    @property
    def flow_log_traffic_type(self) -> str | None:
        return self.get(AwsResourceMetadata.FLOW_LOG_TRAFFIC_TYPE)

    @property
    def flow_log_destination_type(self) -> str | None:
        return self.get(AwsResourceMetadata.FLOW_LOG_DESTINATION_TYPE)

    @property
    def flow_log_destination(self) -> str | None:
        return self.get(AwsResourceMetadata.FLOW_LOG_DESTINATION)

    @property
    def flow_log_log_group_name(self) -> str | None:
        return self.get(AwsResourceMetadata.FLOW_LOG_LOG_GROUP_NAME)

    @property
    def flow_log_iam_role_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.FLOW_LOG_IAM_ROLE_ARN)

    @property
    def flow_log_max_aggregation_interval(self) -> int | None:
        return self.get(AwsResourceMetadata.FLOW_LOG_MAX_AGGREGATION_INTERVAL)

    @property
    def flow_log_destination_options(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.FLOW_LOG_DESTINATION_OPTIONS)

    @property
    def flow_log_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.FLOW_LOG_POSTURE_UNCERTAINTIES)

    def set_route_table_ids(self, values: list[str]) -> None:
        self.set(AwsResourceMetadata.ROUTE_TABLE_IDS, values)

    def set_internet_ingress(self, value: bool) -> None:
        self.set(AwsResourceMetadata.INTERNET_INGRESS, value)

    def set_public_access_configured(self, value: bool) -> None:
        self.set(AwsResourceMetadata.PUBLIC_ACCESS_CONFIGURED, value)

    def has_public_access_reasons(self) -> bool:
        return self.resource.has_metadata_field(AwsResourceMetadata.PUBLIC_ACCESS_REASONS)

    def has_public_exposure_reasons(self) -> bool:
        return self.resource.has_metadata_field(AwsResourceMetadata.PUBLIC_EXPOSURE_REASONS)

    def add_public_exposure_reason(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.PUBLIC_EXPOSURE_REASONS, value)

    def set_fronted_by_internet_facing_load_balancer(self, value: bool) -> None:
        self.set(AwsResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER, value)

    def set_internet_facing_load_balancer_addresses(self, values: list[str]) -> None:
        self.set(AwsResourceMetadata.INTERNET_FACING_LOAD_BALANCER_ADDRESSES, values)

    def add_standalone_rule_address(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.STANDALONE_RULE_ADDRESSES, value)
