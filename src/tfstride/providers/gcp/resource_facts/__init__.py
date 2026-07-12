from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.resource_facts.audit import GcpAuditFacts
from tfstride.providers.gcp.resource_facts.base import GcpBaseFacts
from tfstride.providers.gcp.resource_facts.cloud_sql import GcpCloudSqlFacts
from tfstride.providers.gcp.resource_facts.compute import GcpComputeFacts
from tfstride.providers.gcp.resource_facts.edge import GcpEdgeFacts
from tfstride.providers.gcp.resource_facts.gke import GcpGkeFacts
from tfstride.providers.gcp.resource_facts.iam import GcpIamFacts
from tfstride.providers.gcp.resource_facts.identity import GcpIdentityFacts
from tfstride.providers.gcp.resource_facts.kms import GcpKmsFacts
from tfstride.providers.gcp.resource_facts.network import GcpNetworkFacts
from tfstride.providers.gcp.resource_facts.secret_manager import GcpSecretManagerFacts
from tfstride.providers.gcp.resource_facts.storage import GcpStorageFacts


class GcpResourceFacts(
    GcpStorageFacts,
    GcpSecretManagerFacts,
    GcpKmsFacts,
    GcpIamFacts,
    GcpIdentityFacts,
    GcpNetworkFacts,
    GcpCloudSqlFacts,
    GcpComputeFacts,
    GcpGkeFacts,
    GcpAuditFacts,
    GcpEdgeFacts,
    GcpBaseFacts,
):
    __slots__ = ()


def gcp_facts(resource: NormalizedResource) -> GcpResourceFacts:
    return GcpResourceFacts(resource)


__all__ = ["GcpResourceFacts", "gcp_facts"]
