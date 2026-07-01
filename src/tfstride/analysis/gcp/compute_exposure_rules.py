from __future__ import annotations

from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.gcp.org_policy_evidence import organization_guardrail_evidence
from tfstride.analysis.gcp.org_policy_guardrails import (
    ORG_POLICY_REQUIRE_OS_LOGIN,
    ORG_POLICY_VM_EXTERNAL_IP_ACCESS,
)
from tfstride.analysis.gcp.org_policy_severity import guardrail_adjusted_severity_reasoning
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import (
    BoundaryType,
    Finding,
    NormalizedResource,
    ResourceInventory,
    SecurityGroupRule,
    TrustBoundary,
)
from tfstride.providers.gcp.analysis_indexes import gcp_org_policy_guardrail_index
from tfstride.providers.gcp.constants import (
    GCP_CLOUD_FUNCTION_RESOURCE_TYPES,
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    GCP_GKE_RESOURCE_TYPES,
)
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.resource_helpers import describe_security_group_rule

_GCP_LOAD_BALANCED_EXPOSURE_RESOURCE_TYPES = (
    "google_compute_instance",
    "google_compute_backend_service",
    "google_compute_region_backend_service",
    "google_storage_bucket",
    *GCP_CLOUD_RUN_RESOURCE_TYPES,
    *GCP_CLOUD_FUNCTION_RESOURCE_TYPES,
    *GCP_GKE_RESOURCE_TYPES,
)


class GcpComputeExposureRuleDetectors:
    def detect_public_compute_broad_ingress(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        inventory = context.inventory
        for instance in inventory.by_type("google_compute_instance"):
            risky_rules = _risky_public_firewall_rules(instance, inventory)
            if not risky_rules:
                continue

            severity_reasoning = guardrail_adjusted_severity_reasoning(
                gcp_org_policy_guardrail_index(context.analysis_indexes),
                instance,
                constraints=(ORG_POLICY_VM_EXTERNAL_IP_ACCESS,),
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=1,
            )
            boundary = context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", instance.address))
            affected_resources = dedupe_addresses(
                [instance.address, *[firewall.address for firewall, _ in risky_rules]]
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=affected_resources,
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=_public_compute_broad_ingress_rationale(instance),
                    evidence=collect_evidence(
                        evidence_item(
                            "firewall_rules",
                            [describe_security_group_rule(firewall, rule) for firewall, rule in risky_rules],
                        ),
                        evidence_item("network_tags", gcp_facts(instance).network_tags),
                        evidence_item("internet_ingress_reasons", instance.internet_ingress_reasons),
                        evidence_item("public_exposure_reasons", instance.public_exposure_reasons),
                        organization_guardrail_evidence(
                            gcp_org_policy_guardrail_index(context.analysis_indexes),
                            instance,
                            ORG_POLICY_VM_EXTERNAL_IP_ACCESS,
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_public_load_balanced_workload(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for resource in context.inventory.by_type(*_GCP_LOAD_BALANCED_EXPOSURE_RESOURCE_TYPES):
            resource_facts = gcp_facts(resource)
            if not resource_facts.fronted_by_internet_facing_load_balancer:
                continue
            frontends = resource_facts.load_balancer_frontends
            frontend_addresses = resource_facts.internet_facing_load_balancer_addresses
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=_load_balanced_resource_data_sensitivity(resource),
                lateral_movement=_load_balanced_resource_lateral_movement(resource),
                blast_radius=1,
            )
            boundary = _load_balancer_frontend_boundary(context, frontends)
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses([resource.address, *frontend_addresses]),
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=_public_load_balanced_resource_rationale(resource),
                    evidence=collect_evidence(
                        evidence_item("frontend_load_balancers", frontend_addresses),
                        evidence_item("load_balancer_paths", _load_balancer_path_evidence(frontends)),
                        evidence_item("direct_public_exposure", [str(resource.public_exposure).lower()]),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_compute_os_login_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for instance in context.inventory.by_type("google_compute_instance"):
            instance_facts = gcp_facts(instance)
            if instance_facts.os_login_enabled is not False:
                continue
            severity_reasoning = guardrail_adjusted_severity_reasoning(
                gcp_org_policy_guardrail_index(context.analysis_indexes),
                instance,
                constraints=(ORG_POLICY_REQUIRE_OS_LOGIN,),
                internet_exposure=instance.public_exposure,
                privilege_breadth=1,
                data_sensitivity=0,
                lateral_movement=1 if instance.public_exposure else 0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[instance.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{instance.display_name} explicitly disables OS Login. SSH access can therefore "
                        "fall back to instance or project metadata keys instead of centralized IAM-backed "
                        "login and audit controls."
                    ),
                    evidence=collect_evidence(
                        evidence_item("os_login_posture", ["metadata.enable-oslogin is false"]),
                        evidence_item("public_exposure_reasons", instance.public_exposure_reasons),
                        organization_guardrail_evidence(
                            gcp_org_policy_guardrail_index(context.analysis_indexes),
                            instance,
                            ORG_POLICY_REQUIRE_OS_LOGIN,
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _load_balancer_frontend_boundary(
    context: RuleEvaluationContext,
    frontends: list[dict[str, object]],
) -> TrustBoundary | None:
    for frontend in frontends:
        forwarding_rule = str(frontend.get("forwarding_rule") or "").strip()
        if not forwarding_rule:
            continue
        boundary = context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", forwarding_rule))
        if boundary is not None:
            return boundary
    return None


def _load_balancer_path_evidence(frontends: list[dict[str, object]]) -> list[str]:
    values: list[str] = []
    for frontend in frontends:
        parts = []
        forwarding_rule = frontend.get("forwarding_rule")
        if forwarding_rule:
            parts.append(f"forwarding_rule={forwarding_rule}")
        scheme = frontend.get("load_balancing_scheme")
        if scheme:
            parts.append(f"scheme={scheme}")
        ip_address = frontend.get("ip_address")
        if ip_address:
            parts.append(f"ip_address={ip_address}")
        ports = frontend.get("ports")
        if isinstance(ports, list) and ports:
            parts.append(f"ports={','.join(str(port) for port in ports)}")
        path = frontend.get("path")
        if isinstance(path, list) and path:
            parts.append("path=" + " -> ".join(str(item) for item in path))
        if parts:
            values.append("; ".join(parts))
    return values


def _load_balanced_resource_data_sensitivity(resource: NormalizedResource) -> int:
    if resource.data_sensitivity == "sensitive":
        return 2
    if resource.resource_type == "google_storage_bucket":
        return 1
    return 0


def _load_balanced_resource_lateral_movement(resource: NormalizedResource) -> int:
    if resource.resource_type in {"google_compute_instance", *GCP_GKE_RESOURCE_TYPES}:
        return 1
    return 0


def _public_load_balanced_resource_rationale(resource: NormalizedResource) -> str:
    if resource.resource_type == "google_storage_bucket":
        return (
            f"{resource.display_name} is reachable through a public GCP load balancer backend path. "
            "The bucket is not directly public through GCS IAM, but public edge routing can still expose "
            "objects served by the backend bucket."
        )
    if resource.resource_type in GCP_CLOUD_RUN_RESOURCE_TYPES:
        return (
            f"{resource.display_name} is reachable through a public GCP load balancer frontend. "
            "This is distinct from a public Cloud Run invoker grant: the service is exposed through "
            "load-balancer routing rather than direct anonymous invoke IAM."
        )
    if resource.resource_type in GCP_CLOUD_FUNCTION_RESOURCE_TYPES:
        return (
            f"{resource.display_name} is reachable through a public GCP load balancer frontend. "
            "This is distinct from a public Cloud Functions invoker grant and should be reviewed as "
            "edge-routed exposure."
        )
    if resource.resource_type in GCP_GKE_RESOURCE_TYPES:
        return (
            f"{resource.display_name} is behind a public GCP load balancer frontend. Public edge routing "
            "to cluster workloads increases exposure even when the control plane is not directly public."
        )
    if resource.resource_type in {"google_compute_backend_service", "google_compute_region_backend_service"}:
        return (
            f"{resource.display_name} is a backend service reached by a public GCP load balancer frontend. "
            "Backend service exposure should be reviewed with its downstream groups, NEGs, and serverless "
            "targets."
        )
    return (
        f"{resource.display_name} is reachable through a public GCP load balancer frontend. This is "
        "LB-fronted exposure, not direct public exposure from the workload resource itself."
    )


def _public_compute_broad_ingress_rationale(instance: NormalizedResource) -> str:
    if instance.public_exposure:
        return (
            f"{instance.display_name} has an external access config and matching GCP firewall "
            "rules allow administrative access or all ports from the public internet. That broad "
            "ingress raises the chance of unauthenticated probing and credential attacks."
        )
    return (
        f"{instance.display_name} is targeted by GCP firewall rules that allow administrative access "
        "or all ports from internet-wide source ranges. Even when the plan does not show a direct "
        "internet boundary, broad SSH/RDP ingress increases exposure if an external address, peering path, "
        "or forwarding path is later attached."
    )


def _risky_public_firewall_rules(
    instance: NormalizedResource,
    inventory: ResourceInventory,
) -> list[tuple[NormalizedResource, SecurityGroupRule]]:
    firewall_addresses = gcp_facts(instance).internet_ingress_firewalls
    risky_rules: list[tuple[NormalizedResource, SecurityGroupRule]] = []
    for firewall_address in firewall_addresses:
        firewall = inventory.get_by_address(firewall_address)
        if firewall is None:
            continue
        for rule in firewall.network_rules:
            if (
                rule.direction == "ingress"
                and rule.allows_internet()
                and (rule.is_administrative_access() or rule.is_all_ports())
            ):
                risky_rules.append((firewall, rule))
    return risky_rules
