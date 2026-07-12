from __future__ import annotations

from typing import Any

from tfstride.providers.gcp.metadata import GcpResourceMetadata


class GcpNetworkFacts:
    __slots__ = ()

    @property
    def private_connectivity_purpose(self) -> str | None:
        return self.get(GcpResourceMetadata.PRIVATE_CONNECTIVITY_PURPOSE)

    @property
    def private_connectivity_address_type(self) -> str | None:
        return self.get(GcpResourceMetadata.PRIVATE_CONNECTIVITY_ADDRESS_TYPE)

    @property
    def private_connectivity_address(self) -> str | None:
        return self.get(GcpResourceMetadata.PRIVATE_CONNECTIVITY_ADDRESS)

    @property
    def private_connectivity_prefix_length(self) -> int | None:
        return self.get(GcpResourceMetadata.PRIVATE_CONNECTIVITY_PREFIX_LENGTH)

    @property
    def private_connectivity_service(self) -> str | None:
        return self.get(GcpResourceMetadata.PRIVATE_CONNECTIVITY_SERVICE)

    @property
    def private_connectivity_reserved_ranges(self) -> list[str]:
        return self.get(GcpResourceMetadata.PRIVATE_CONNECTIVITY_RESERVED_RANGES)

    @property
    def private_connectivity_peering(self) -> str | None:
        return self.get(GcpResourceMetadata.PRIVATE_CONNECTIVITY_PEERING)

    @property
    def private_connectivity_target_service(self) -> str | None:
        return self.get(GcpResourceMetadata.PRIVATE_CONNECTIVITY_TARGET_SERVICE)

    @property
    def private_connectivity_nat_subnets(self) -> list[str]:
        return self.get(GcpResourceMetadata.PRIVATE_CONNECTIVITY_NAT_SUBNETS)

    @property
    def private_connectivity_subnetworks(self) -> list[str]:
        return self.get(GcpResourceMetadata.PRIVATE_CONNECTIVITY_SUBNETWORKS)

    @property
    def private_connectivity_domain_names(self) -> list[str]:
        return self.get(GcpResourceMetadata.PRIVATE_CONNECTIVITY_DOMAIN_NAMES)

    @property
    def private_connectivity_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.PRIVATE_CONNECTIVITY_UNCERTAINTIES)

    @property
    def private_ip_google_access(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.PRIVATE_IP_GOOGLE_ACCESS)

    @property
    def subnetwork_flow_log_state(self) -> str | None:
        return self.get(GcpResourceMetadata.SUBNETWORK_FLOW_LOG_STATE)

    @property
    def subnetwork_flow_log_config(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.SUBNETWORK_FLOW_LOG_CONFIG)

    @property
    def subnetwork_flow_log_aggregation_interval(self) -> str | None:
        return self.get(GcpResourceMetadata.SUBNETWORK_FLOW_LOG_AGGREGATION_INTERVAL)

    @property
    def subnetwork_flow_log_sampling(self) -> str | None:
        return self.get(GcpResourceMetadata.SUBNETWORK_FLOW_LOG_SAMPLING)

    @property
    def subnetwork_flow_log_metadata(self) -> str | None:
        return self.get(GcpResourceMetadata.SUBNETWORK_FLOW_LOG_METADATA)

    @property
    def subnetwork_flow_log_metadata_fields(self) -> list[str]:
        return self.get(GcpResourceMetadata.SUBNETWORK_FLOW_LOG_METADATA_FIELDS)

    @property
    def subnetwork_flow_log_filter_expr(self) -> str | None:
        return self.get(GcpResourceMetadata.SUBNETWORK_FLOW_LOG_FILTER_EXPR)

    @property
    def network_telemetry_posture_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.NETWORK_TELEMETRY_POSTURE_UNCERTAINTIES)

    @property
    def psc_connection_id(self) -> str | None:
        return self.get(GcpResourceMetadata.PSC_CONNECTION_ID)

    @property
    def psc_connection_status(self) -> str | None:
        return self.get(GcpResourceMetadata.PSC_CONNECTION_STATUS)

    @property
    def psc_connection_preference(self) -> str | None:
        return self.get(GcpResourceMetadata.PSC_CONNECTION_PREFERENCE)

    @property
    def psc_service_label(self) -> str | None:
        return self.get(GcpResourceMetadata.PSC_SERVICE_LABEL)

    @property
    def psc_service_name(self) -> str | None:
        return self.get(GcpResourceMetadata.PSC_SERVICE_NAME)

    @property
    def psc_service_class(self) -> str | None:
        return self.get(GcpResourceMetadata.PSC_SERVICE_CLASS)

    @property
    def psc_config(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.PSC_CONFIG)

    @property
    def psc_consumer_accept_list(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.PSC_CONSUMER_ACCEPT_LIST)

    @property
    def psc_consumer_reject_list(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.PSC_CONSUMER_REJECT_LIST)
