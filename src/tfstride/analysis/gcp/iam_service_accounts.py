from __future__ import annotations

from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.gcp.iam_access import (
    assess_gcp_broad_iam_member,
    gcp_iam_condition_evidence_values,
    gcp_iam_condition_limited_score,
    iam_binding_condition,
    iam_resource_binding_members,
)
from tfstride.analysis.gcp.indexes import gcp_org_policy_guardrail_index
from tfstride.analysis.gcp.org_policy_evidence import organization_guardrail_evidence
from tfstride.analysis.gcp.org_policy_guardrails import (
    ORG_POLICY_ALLOWED_MEMBER_DOMAINS,
)
from tfstride.analysis.gcp.org_policy_severity import guardrail_adjusted_severity_reasoning
from tfstride.analysis.gcp.resource_types import GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES
from tfstride.analysis.gcp.resource_utils import gcp_reference_key
from tfstride.analysis.resource_facts import analysis_facts
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource, ResourceInventory

HIGH_RISK_SERVICE_ACCOUNT_ROLES: dict[str, str] = {
    "roles/iam.serviceAccountAdmin": "service account administration and IAM policy control",
    "roles/iam.serviceAccountTokenCreator": "service account token minting and impersonation",
    "roles/iam.serviceAccountUser": "service account attachment and workload impersonation",
}


class GcpServiceAccountIamDetectors:
    def detect_service_account_iam_broad_principal(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        inventory = context.inventory
        for binding in inventory.by_type(*GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES):
            target = service_account_iam_target(binding, inventory)
            for role, member in iam_resource_binding_members(binding):
                assessment = assess_gcp_broad_iam_member(member)
                if assessment is None:
                    continue
                condition = iam_binding_condition(binding, role, member)
                severity_reasoning = guardrail_adjusted_severity_reasoning(
                    gcp_org_policy_guardrail_index(context.analysis_indexes),
                    binding,
                    constraints=(ORG_POLICY_ALLOWED_MEMBER_DOMAINS,),
                    internet_exposure=assessment.is_public,
                    privilege_breadth=gcp_iam_condition_limited_score(2, condition, floor=1),
                    data_sensitivity=0,
                    lateral_movement=1,
                    blast_radius=gcp_iam_condition_limited_score(2 if assessment.is_public else 1, condition, floor=0),
                )
                affected_resources = dedupe_addresses([target.address if target else "", binding.address])
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=affected_resources,
                        trust_boundary_id=None,
                        rationale=(
                            f"{binding.display_name} grants `{role}` on a GCP service account to "
                            f"`{member}`. Public or broad principals can cross the service-account "
                            "identity boundary and may gain workload impersonation paths."
                        ),
                        evidence=collect_evidence(
                            evidence_item(
                                "iam_binding",
                                [
                                    f"source={binding.address}",
                                    f"member={member}",
                                    f"role={role}",
                                ],
                            ),
                            evidence_item("trust_scope", [assessment.scope_description]),
                            evidence_item("iam_condition", gcp_iam_condition_evidence_values(condition)),
                            evidence_item(
                                "service_account_reference",
                                [analysis_facts(binding).iam.service_account_reference or ""],
                            ),
                            organization_guardrail_evidence(
                                gcp_org_policy_guardrail_index(context.analysis_indexes),
                                binding,
                                ORG_POLICY_ALLOWED_MEMBER_DOMAINS,
                            ),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings

    def detect_service_account_iam_privileged_role(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        inventory = context.inventory
        for binding in inventory.by_type(*GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES):
            target = service_account_iam_target(binding, inventory)
            for role, member in iam_resource_binding_members(binding):
                role_risk = high_risk_service_account_role_risk(role)
                if role_risk is None:
                    continue
                broad_assessment = assess_gcp_broad_iam_member(member)
                condition = iam_binding_condition(binding, role, member)
                severity_reasoning = build_severity_reasoning(
                    internet_exposure=bool(broad_assessment and broad_assessment.is_public),
                    privilege_breadth=gcp_iam_condition_limited_score(2, condition, floor=1),
                    data_sensitivity=0,
                    lateral_movement=2,
                    blast_radius=gcp_iam_condition_limited_score(2, condition, floor=1),
                )
                affected_resources = dedupe_addresses([target.address if target else "", binding.address])
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=affected_resources,
                        trust_boundary_id=None,
                        rationale=(
                            f"{binding.display_name} grants the high-impact service account role `{role}` "
                            f"to `{member}`. That role enables {role_risk}, expanding privilege if the "
                            "principal is compromised or mis-scoped."
                        ),
                        evidence=collect_evidence(
                            evidence_item(
                                "iam_binding",
                                [
                                    f"source={binding.address}",
                                    f"member={member}",
                                    f"role={role}",
                                ],
                            ),
                            evidence_item("role_risk", [role_risk]),
                            evidence_item("iam_condition", gcp_iam_condition_evidence_values(condition)),
                            evidence_item(
                                "service_account_reference",
                                [analysis_facts(binding).iam.service_account_reference or ""],
                            ),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings


def high_risk_service_account_role_risk(role: str | None) -> str | None:
    if not role:
        return None
    normalized_role = role.strip()
    return HIGH_RISK_SERVICE_ACCOUNT_ROLES.get(normalized_role)


def service_account_iam_target(
    iam_resource: NormalizedResource,
    inventory: ResourceInventory,
) -> NormalizedResource | None:
    target_reference = analysis_facts(iam_resource).iam.service_account_reference
    if not target_reference:
        return None
    target_key = gcp_reference_key(target_reference)
    for service_account in inventory.by_type("google_service_account"):
        if target_key in _service_account_reference_keys(service_account):
            return service_account
    return None


def _service_account_reference_keys(resource: NormalizedResource) -> set[str]:
    facts = analysis_facts(resource).iam
    values = [
        resource.address,
        f"{resource.address}.id",
        f"{resource.address}.name",
        f"{resource.address}.email",
        resource.identifier,
        facts.service_account_email,
        facts.service_account_member,
        facts.resource_name,
    ]
    keys: set[str] = set()
    for value in values:
        if value in (None, ""):
            continue
        text = str(value).strip()
        if not text:
            continue
        keys.add(gcp_reference_key(text))
        if text.startswith("serviceAccount:"):
            keys.add(gcp_reference_key(text.removeprefix("serviceAccount:")))
        else:
            keys.add(gcp_reference_key(f"serviceAccount:{text}"))
    return keys
