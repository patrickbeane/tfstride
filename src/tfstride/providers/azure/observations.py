from __future__ import annotations

from tfstride.analysis.finding_helpers import collect_evidence, evidence_item
from tfstride.models import Observation, ResourceInventory
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_STORAGE_POSTURE_RESOURCE_TYPES = (
    AzureResourceType.STORAGE_ACCOUNT,
    AzureResourceType.STORAGE_CONTAINER,
)


def observe_azure_storage_uncertainty(inventory: ResourceInventory) -> list[Observation]:
    if inventory.provider != "azure":
        return []

    observations: list[Observation] = []
    for resource in inventory.by_type(*_STORAGE_POSTURE_RESOURCE_TYPES):
        uncertainties = azure_facts(resource).storage_posture_uncertainties
        if not uncertainties:
            continue
        observations.append(
            Observation(
                title="Azure Storage exposure posture contains unresolved plan values",
                observation_id="azure-storage-exposure-posture-unknown",
                category="analysis-uncertainty",
                affected_resources=[resource.address],
                rationale=(
                    f"{resource.display_name} has computed storage exposure attributes that are not known in "
                    "this Terraform plan. tfSTRIDE does not infer public access from those unresolved values."
                ),
                evidence=collect_evidence(
                    evidence_item("unknown_storage_posture", uncertainties),
                    evidence_item(
                        "analysis_effect",
                        ["public exposure findings are emitted only for known-positive posture signals"],
                    ),
                ),
            )
        )
    return observations
