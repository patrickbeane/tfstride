from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal

from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import EvidenceItem, NormalizedResource
from tfstride.providers.azure.analysis_indexes import AzureAnalysisIndexes
from tfstride.providers.azure.resource_facts import azure_facts


def app_service_ingress(
    app: NormalizedResource, context: RuleEvaluationContext, *, site: Literal["main", "scm"] = "main"
) -> AppServiceIngress:
    indexes = context.analysis_indexes
    assert indexes is not None
    assessment = indexes.require_provider_extension(AzureAnalysisIndexes).app_service_ingress.get(app.address, {})
    return AppServiceIngress(app, site, assessment.get(site, {}))


@dataclass(frozen=True, slots=True)
class AppServiceIngress:
    app: NormalizedResource
    site: str
    assessment: dict[str, Any]

    @property
    def is_public(self) -> bool:
        # A definite surviving external subset is sufficient even if other
        # subsets remain uncertain. Authentication does not change reachability.
        return self.assessment.get("external_access") == "allowed"

    @property
    def evidence(self) -> list[EvidenceItem]:
        facts = azure_facts(self.app)
        return [
            EvidenceItem(
                key="public_endpoint",
                values=[
                    f"address={self.app.address}",
                    f"type={self.app.resource_type}",
                    f"site={self.site}",
                    f"public_network_access_enabled={str(facts.public_network_access_enabled).lower()}",
                    "assessment_scope=default_endpoint_access_restrictions",
                ],
            ),
            EvidenceItem(
                key="effective_public_ingress",
                values=[
                    f"workload={self.app.address}; site={self.site}",
                    f"state={self.assessment.get('state', 'unresolved')}",
                    f"external_access={self.assessment.get('external_access', 'unknown')}",
                    f"allowed_source_cidrs={_json(self.assessment.get('allowed_source_cidrs', []))}",
                    f"default_action={self.assessment.get('default_action') or 'unknown'}",
                    f"default_action_source={self.assessment.get('default_action_source', 'unknown')}",
                    # Link source subsets/request witnesses to their winning
                    # rules or default, including remaining uncertainty.
                    f"decision={_json(self.assessment)}",
                ],
            ),
            EvidenceItem(
                key="app_service_authentication",
                values=[
                    f"workload={self.app.address}",
                    f"auth_settings_v2={_json(facts.app_service_auth_settings_v2)}",
                    f"auth_settings={_json(facts.app_service_auth_settings)}",
                    "Authentication qualifies request access independently of network reachability; "
                    "application-level authentication is not established by this plan.",
                ],
            ),
        ]


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))
