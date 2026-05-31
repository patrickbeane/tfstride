from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.aws.resource_facts import AwsResourceFacts, aws_facts


@dataclass(frozen=True, slots=True)
class AnalysisResourceFacts:
    """Read facade for metadata-backed facts used by shared analysis."""

    resource: NormalizedResource

    def _aws_facts(self) -> AwsResourceFacts | None:
        if self.resource.provider != "aws":
            return None
        return aws_facts(self.resource)

    @property
    def bucket_name(self) -> str | None:
        facts = self._aws_facts()
        return facts.bucket_name if facts is not None else None

    @property
    def bucket_acl(self) -> str:
        facts = self._aws_facts()
        return facts.bucket_acl if facts is not None else ""

    @property
    def public_access_block(self) -> dict[str, bool] | None:
        facts = self._aws_facts()
        return facts.public_access_block if facts is not None else None

    @property
    def policy_document(self) -> dict[str, Any]:
        facts = self._aws_facts()
        return facts.policy_document if facts is not None else {}

    @property
    def trust_statements(self) -> list[dict[str, Any]]:
        facts = self._aws_facts()
        return facts.trust_statements if facts is not None else []

    @property
    def database_engine(self) -> str | None:
        facts = self._aws_facts()
        return facts.engine if facts is not None else None

    @property
    def resource_policy_source_addresses(self) -> list[str]:
        facts = self._aws_facts()
        return facts.resource_policy_source_addresses if facts is not None else []


def analysis_facts(resource: NormalizedResource) -> AnalysisResourceFacts:
    return AnalysisResourceFacts(resource)