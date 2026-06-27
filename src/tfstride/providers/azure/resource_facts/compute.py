from __future__ import annotations

from collections.abc import Sequence

from tfstride.providers.azure.metadata import AzureResourceMetadata


class AzureComputeFacts:
    __slots__ = ()

    @property
    def public_compute_exposure_paths(self) -> list[dict]:
        return self.get(AzureResourceMetadata.PUBLIC_COMPUTE_EXPOSURE_PATHS)

    @property
    def vm_size(self) -> str | None:
        return self.get(AzureResourceMetadata.VM_SIZE)

    @property
    def os_type(self) -> str | None:
        return self.get(AzureResourceMetadata.OS_TYPE)

    def set_public_compute_exposure(self, paths: list[dict], reasons: Sequence[str]) -> None:
        exposed = bool(paths)
        self.set(AzureResourceMetadata.PUBLIC_COMPUTE_EXPOSURE_PATHS, paths)
        self.resource.internet_ingress_capable = exposed
        self.resource.public_exposure = exposed
        self.resource.publicly_accessible = exposed
        self.resource.direct_internet_reachable = exposed
        self.resource.internet_ingress_reasons = [
            rule for path in paths for rule in path.get("network_security_rules", []) if rule
        ]
        self.resource.public_exposure_reasons = list(reasons) if exposed else []
