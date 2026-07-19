from __future__ import annotations

from typing import Any

from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_facts.base import GcpBaseFacts


class GcpComputeFacts(GcpBaseFacts):
    __slots__ = ()

    @property
    def os_login_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.OS_LOGIN_ENABLED)

    @property
    def network_tags(self) -> list[str]:
        return self.get(GcpResourceMetadata.NETWORK_TAGS)

    @property
    def internet_ingress_firewalls(self) -> list[str]:
        return self.get(GcpResourceMetadata.INTERNET_INGRESS_FIREWALLS)

    @property
    def fronted_by_internet_facing_load_balancer(self) -> bool:
        return self.get(GcpResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER)

    @property
    def internet_facing_load_balancer_addresses(self) -> list[str]:
        return self.get(GcpResourceMetadata.INTERNET_FACING_LOAD_BALANCER_ADDRESSES)

    @property
    def container_image_references(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.CONTAINER_IMAGE_REFERENCES)

    @property
    def container_image_posture_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.CONTAINER_IMAGE_POSTURE_UNCERTAINTIES)

    @property
    def cloud_run_secret_references(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_SECRET_REFERENCES)

    @property
    def cloud_run_secret_posture_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_SECRET_POSTURE_UNCERTAINTIES)

    @property
    def cloud_run_secret_access_paths(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_SECRET_ACCESS_PATHS)

    @property
    def cloud_run_secret_access_path_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.CLOUD_RUN_SECRET_ACCESS_PATH_UNCERTAINTIES)

    @property
    def artifact_registry_write_paths(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.ARTIFACT_REGISTRY_WRITE_PATHS)

    @property
    def artifact_registry_write_path_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.ARTIFACT_REGISTRY_WRITE_PATH_UNCERTAINTIES)

    def set_cloud_run_secret_access_paths(self, values: list[dict[str, Any]]) -> None:
        self.set(GcpResourceMetadata.CLOUD_RUN_SECRET_ACCESS_PATHS, values)

    def extend_cloud_run_secret_access_path_uncertainties(self, values: list[str]) -> None:
        self.extend(GcpResourceMetadata.CLOUD_RUN_SECRET_ACCESS_PATH_UNCERTAINTIES, values)

    def set_artifact_registry_write_paths(self, values: list[dict[str, Any]]) -> None:
        self.set(GcpResourceMetadata.ARTIFACT_REGISTRY_WRITE_PATHS, values)

    def extend_artifact_registry_write_path_uncertainties(self, values: list[str]) -> None:
        self.extend(GcpResourceMetadata.ARTIFACT_REGISTRY_WRITE_PATH_UNCERTAINTIES, values)
