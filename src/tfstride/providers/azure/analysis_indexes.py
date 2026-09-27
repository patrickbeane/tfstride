from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from tfstride.models import ResourceInventory
from tfstride.providers.azure.app_service_access import evaluate_app_service_access
from tfstride.providers.azure.resource_types import AZURE_APP_SERVICE_RESOURCE_TYPES


@dataclass(frozen=True, slots=True)
class AzureAnalysisIndexes:
    app_service_ingress: Mapping[str, dict[str, Any]]


def build_azure_analysis_indexes(inventory: ResourceInventory) -> AzureAnalysisIndexes:
    # Rebuild once per evaluation from current inputs, never from cached decoration.
    return AzureAnalysisIndexes(
        app_service_ingress=MappingProxyType(
            {
                app.address: evaluate_app_service_access(app)
                for app in inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES)
            }
        )
    )
