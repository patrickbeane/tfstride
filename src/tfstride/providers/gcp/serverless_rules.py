from __future__ import annotations

from tfstride.analysis.finding_helpers import collect_evidence, dedupe_addresses, evidence_item
from tfstride.analysis.gcp.iam_access import (
    gcp_iam_condition_evidence_values,
    gcp_iam_condition_limited_score,
)
from tfstride.analysis.gcp.indexes import gcp_org_policy_guardrail_index
from tfstride.analysis.gcp.org_policy_evidence import organization_guardrail_evidence
from tfstride.analysis.gcp.org_policy_guardrails import ORG_POLICY_ALLOWED_MEMBER_DOMAINS
from tfstride.analysis.gcp.org_policy_severity import guardrail_adjusted_severity_reasoning
from tfstride.analysis.gcp.resource_types import (
    GCP_CLOUD_FUNCTION_RESOURCE_TYPES,
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    PUBLIC_GCP_IAM_MEMBERS,
)
from tfstride.analysis.gcp.resource_utils import binding_members
from tfstride.analysis.resource_facts import analysis_facts
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, Finding, NormalizedResource

_CLOUD_RUN_PUBLIC_INVOKER_ROLES = frozenset({"roles/run.invoker"})
_CLOUD_FUNCTION_PUBLIC_INVOKER_ROLES = frozenset({"roles/cloudfunctions.invoker"})


class GcpServerlessRuleDetectors:
    def detect_cloud_run_public_invoker(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for service in context.inventory.by_type(*GCP_CLOUD_RUN_RESOURCE_TYPES):
            public_invokers = _cloud_run_public_invoker_bindings(service)
            if not service.public_exposure or not public_invokers:
                continue
            condition = _public_invoker_condition(public_invokers)
            severity_reasoning = guardrail_adjusted_severity_reasoning(
                gcp_org_policy_guardrail_index(context.analysis_indexes),
                service,
                constraints=(ORG_POLICY_ALLOWED_MEMBER_DOMAINS,),
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=0,
                blast_radius=gcp_iam_condition_limited_score(1, condition, floor=0),
            )
            boundary = context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", service.address))
            affected_resources = dedupe_addresses([service.address, *[source for source, _, _, _ in public_invokers]])
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=affected_resources,
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{service.display_name} allows public ingress and grants Cloud Run invoke "
                        "permission to public GCP principals. Unauthenticated internet clients can reach "
                        "the service entry point without an organization-owned identity boundary."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "public_invoker_bindings",
                            [
                                f"source={source}; role={role}; member={member}"
                                for source, role, member, _ in public_invokers
                            ],
                        ),
                        evidence_item("iam_condition", gcp_iam_condition_evidence_values(condition)),
                        evidence_item("public_access_reasons", service.public_access_reasons),
                        evidence_item("public_exposure_reasons", service.public_exposure_reasons),
                        organization_guardrail_evidence(
                            gcp_org_policy_guardrail_index(context.analysis_indexes),
                            service,
                            ORG_POLICY_ALLOWED_MEMBER_DOMAINS,
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_cloud_function_public_invoker(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for function in context.inventory.by_type(*GCP_CLOUD_FUNCTION_RESOURCE_TYPES):
            public_invokers = _cloud_function_public_invoker_bindings(function)
            if not function.public_exposure or not public_invokers:
                continue
            condition = _public_invoker_condition(public_invokers)
            severity_reasoning = guardrail_adjusted_severity_reasoning(
                gcp_org_policy_guardrail_index(context.analysis_indexes),
                function,
                constraints=(ORG_POLICY_ALLOWED_MEMBER_DOMAINS,),
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=0,
                blast_radius=gcp_iam_condition_limited_score(1, condition, floor=0),
            )
            boundary = context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", function.address))
            affected_resources = dedupe_addresses([function.address, *[source for source, _, _, _ in public_invokers]])
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=affected_resources,
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{function.display_name} allows public HTTP access and grants Cloud Functions "
                        "invoke permission to public GCP principals. Unauthenticated internet clients can "
                        "reach the function entry point without an organization-owned identity boundary."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "public_invoker_bindings",
                            [
                                f"source={source}; role={role}; member={member}"
                                for source, role, member, _ in public_invokers
                            ],
                        ),
                        evidence_item("iam_condition", gcp_iam_condition_evidence_values(condition)),
                        evidence_item("public_access_reasons", function.public_access_reasons),
                        evidence_item("public_exposure_reasons", function.public_exposure_reasons),
                        organization_guardrail_evidence(
                            gcp_org_policy_guardrail_index(context.analysis_indexes),
                            function,
                            ORG_POLICY_ALLOWED_MEMBER_DOMAINS,
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _cloud_run_public_invoker_bindings(resource: NormalizedResource) -> list[tuple[str, str, str, dict | None]]:
    return _public_invoker_bindings(resource, _CLOUD_RUN_PUBLIC_INVOKER_ROLES)


def _cloud_function_public_invoker_bindings(resource: NormalizedResource) -> list[tuple[str, str, str, dict | None]]:
    return _public_invoker_bindings(resource, _CLOUD_FUNCTION_PUBLIC_INVOKER_ROLES)


def _public_invoker_bindings(
    resource: NormalizedResource,
    invoker_roles: frozenset[str],
) -> list[tuple[str, str, str, dict | None]]:
    bindings: list[tuple[str, str, str, dict | None]] = []
    for binding in analysis_facts(resource).iam.bindings:
        role = str(binding.get("role") or "").strip()
        if role not in invoker_roles:
            continue
        source = str(binding.get("source") or "").strip()
        for member in binding_members(binding):
            if member in PUBLIC_GCP_IAM_MEMBERS:
                condition = binding.get("condition") if isinstance(binding.get("condition"), dict) else None
                bindings.append((source, role, member, condition))
    return bindings


def _public_invoker_condition(
    bindings: list[tuple[str, str, str, dict | None]],
) -> dict | None:
    matched_condition: dict | None = None
    for _, _, _, condition in bindings:
        if not condition:
            return None
        if matched_condition is not None and condition != matched_condition:
            return None
        matched_condition = condition
    return matched_condition
