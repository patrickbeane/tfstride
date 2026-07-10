from __future__ import annotations

from typing import Any

from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_facts.base import GcpBaseFacts


class GcpAuditFacts(GcpBaseFacts):
    __slots__ = ()

    @property
    def audit_security_posture_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.AUDIT_SECURITY_POSTURE_UNCERTAINTIES)

    @property
    def logging_sink_name(self) -> str | None:
        return self.get(GcpResourceMetadata.LOGGING_SINK_NAME)

    @property
    def logging_sink_destination(self) -> str | None:
        return self.get(GcpResourceMetadata.LOGGING_SINK_DESTINATION)

    @property
    def logging_sink_filter(self) -> str | None:
        return self.get(GcpResourceMetadata.LOGGING_SINK_FILTER)

    @property
    def logging_sink_writer_identity(self) -> str | None:
        return self.get(GcpResourceMetadata.LOGGING_SINK_WRITER_IDENTITY)

    @property
    def logging_sink_scope_type(self) -> str | None:
        return self.get(GcpResourceMetadata.LOGGING_SINK_SCOPE_TYPE)

    @property
    def logging_sink_scope(self) -> str | None:
        return self.get(GcpResourceMetadata.LOGGING_SINK_SCOPE)

    @property
    def logging_sink_include_children(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.LOGGING_SINK_INCLUDE_CHILDREN)

    @property
    def logging_sink_unique_writer_identity(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.LOGGING_SINK_UNIQUE_WRITER_IDENTITY)

    @property
    def logging_exclusion_name(self) -> str | None:
        return self.get(GcpResourceMetadata.LOGGING_EXCLUSION_NAME)

    @property
    def logging_exclusion_description(self) -> str | None:
        return self.get(GcpResourceMetadata.LOGGING_EXCLUSION_DESCRIPTION)

    @property
    def logging_exclusion_filter(self) -> str | None:
        return self.get(GcpResourceMetadata.LOGGING_EXCLUSION_FILTER)

    @property
    def logging_exclusion_scope_type(self) -> str | None:
        return self.get(GcpResourceMetadata.LOGGING_EXCLUSION_SCOPE_TYPE)

    @property
    def logging_exclusion_scope(self) -> str | None:
        return self.get(GcpResourceMetadata.LOGGING_EXCLUSION_SCOPE)

    @property
    def logging_exclusion_disabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.LOGGING_EXCLUSION_DISABLED)

    @property
    def scc_organization(self) -> str | None:
        return self.get(GcpResourceMetadata.SCC_ORGANIZATION)

    @property
    def scc_enable_asset_discovery(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.SCC_ENABLE_ASSET_DISCOVERY)

    @property
    def scc_asset_discovery_state(self) -> str | None:
        return self.get(GcpResourceMetadata.SCC_ASSET_DISCOVERY_STATE)

    @property
    def scc_asset_discovery_inclusion_mode(self) -> str | None:
        return self.get(GcpResourceMetadata.SCC_ASSET_DISCOVERY_INCLUSION_MODE)

    @property
    def scc_asset_discovery_project_ids(self) -> list[str]:
        return self.get(GcpResourceMetadata.SCC_ASSET_DISCOVERY_PROJECT_IDS)

    @property
    def scc_asset_discovery_folder_ids(self) -> list[str]:
        return self.get(GcpResourceMetadata.SCC_ASSET_DISCOVERY_FOLDER_IDS)

    @property
    def scc_asset_discovery_config(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.SCC_ASSET_DISCOVERY_CONFIG)
