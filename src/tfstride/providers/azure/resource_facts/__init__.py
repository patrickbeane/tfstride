from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.azure.resource_facts.aks import AzureAksFacts
from tfstride.providers.azure.resource_facts.app_service import AzureAppServiceFacts
from tfstride.providers.azure.resource_facts.audit import AzureAuditFacts
from tfstride.providers.azure.resource_facts.base import AzureBaseFacts
from tfstride.providers.azure.resource_facts.compute import AzureComputeFacts
from tfstride.providers.azure.resource_facts.identity import AzureIdentityFacts
from tfstride.providers.azure.resource_facts.key_vault import AzureKeyVaultFacts
from tfstride.providers.azure.resource_facts.network import AzureNetworkFacts
from tfstride.providers.azure.resource_facts.postgresql import AzurePostgresqlFacts
from tfstride.providers.azure.resource_facts.private_endpoint import AzurePrivateEndpointFacts
from tfstride.providers.azure.resource_facts.rbac import AzureRbacFacts
from tfstride.providers.azure.resource_facts.sql import AzureSqlFacts
from tfstride.providers.azure.resource_facts.storage import AzureStorageFacts


class AzureResourceFacts(
    AzureStorageFacts,
    AzureAksFacts,
    AzureAppServiceFacts,
    AzureKeyVaultFacts,
    AzureIdentityFacts,
    AzureRbacFacts,
    AzureSqlFacts,
    AzurePostgresqlFacts,
    AzurePrivateEndpointFacts,
    AzureAuditFacts,
    AzureNetworkFacts,
    AzureComputeFacts,
    AzureBaseFacts,
):
    __slots__ = ()


def azure_facts(resource: NormalizedResource) -> AzureResourceFacts:
    return AzureResourceFacts(resource)


__all__ = ["AzureResourceFacts", "azure_facts"]
