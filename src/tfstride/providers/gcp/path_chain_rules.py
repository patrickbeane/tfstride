from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, Finding, NormalizedResource, TrustBoundary
from tfstride.providers.gcp.resource_facts import gcp_facts


class GcpPathChainRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_workload_sensitive_data_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        inventory = context.inventory
        paths_by_workload: dict[str, list[tuple[NormalizedResource, TrustBoundary]]] = {}

        for boundary in context.boundary_index.values():
            if boundary.boundary_type != BoundaryType.WORKLOAD_TO_DATA_STORE:
                continue
            workload = inventory.get_by_address(boundary.source)
            data_store = inventory.get_by_address(boundary.target)
            if workload is None or data_store is None:
                continue
            if workload.provider != "gcp" or data_store.provider != "gcp":
                continue
            if not workload.public_exposure or data_store.data_sensitivity != "sensitive":
                continue
            paths_by_workload.setdefault(workload.address, []).append((data_store, boundary))

        for workload_address in sorted(paths_by_workload):
            workload = inventory.get_by_address(workload_address)
            if workload is None:
                continue
            data_paths = sorted(
                paths_by_workload[workload_address],
                key=lambda item: item[0].address,
            )
            data_store_addresses = [data_store.address for data_store, _ in data_paths]
            policy_sources = [
                source
                for data_store, _ in data_paths
                for source in gcp_facts(data_store).resource_policy_source_addresses
            ]
            workload_identities = gcp_facts(workload).identity_members
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2 if len(data_store_addresses) > 1 else 1,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=2 if len(data_store_addresses) > 1 else 1,
            )
            trust_boundary_id = data_paths[0][1].identifier if len(data_paths) == 1 else None
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=list(dict.fromkeys([workload.address, *data_store_addresses, *policy_sources])),
                    trust_boundary_id=trust_boundary_id,
                    rationale=(
                        f"{workload.display_name} is internet-exposed and runs with GCP workload identity "
                        f"{', '.join(workload_identities) or 'unknown service account'}. That identity can access "
                        f"{', '.join(data_store.display_name for data_store, _ in data_paths)}. A compromise of the "
                        "public workload can therefore become direct access to sensitive GCP data services."
                    ),
                    evidence=collect_evidence(
                        evidence_item("public_exposure_reasons", workload.public_exposure_reasons),
                        evidence_item("workload_identity", workload_identities),
                        evidence_item(
                            "workload_identity_scopes",
                            gcp_facts(workload).identity_scopes,
                        ),
                        evidence_item(
                            "data_access_path",
                            [f"{workload.address} reaches {data_store.address}" for data_store, _ in data_paths],
                        ),
                        evidence_item(
                            "boundary_rationale",
                            [boundary.rationale for _, boundary in data_paths],
                        ),
                        evidence_item("resource_policy_sources", policy_sources),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings
