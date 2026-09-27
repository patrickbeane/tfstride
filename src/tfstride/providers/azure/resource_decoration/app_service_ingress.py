from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.azure.app_service_access import evaluate_app_service_access
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import AZURE_APP_SERVICE_RESOURCE_TYPES


class EvaluateAppServiceIngressStage:
    name = "evaluate_app_service_ingress"

    def apply(self, resources: list[NormalizedResource], context: AzureDecorationContext) -> None:
        for resource in resources:
            if resource.resource_type in AZURE_APP_SERVICE_RESOURCE_TYPES:
                azure_facts(resource).set_app_service_effective_ingress(evaluate_app_service_access(resource))
