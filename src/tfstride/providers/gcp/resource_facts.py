from __future__ import annotations

from dataclasses import dataclass

from tfstride.models import NormalizedResource
from tfstride.providers.resource_facts import NeutralProviderResourceFacts


@dataclass(frozen=True, slots=True)
class GcpResourceFacts(NeutralProviderResourceFacts):
    """Neutral GCP facts until provider-specific analysis facts are modeled."""


def gcp_facts(resource: NormalizedResource) -> GcpResourceFacts:
    return GcpResourceFacts(resource)