from __future__ import annotations

from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.gcp.iam_access import (
    gcp_iam_condition_evidence_values,
    gcp_iam_condition_limited_score,
)
from tfstride.analysis.gcp.org_policy_evidence import organization_guardrail_evidence
from tfstride.analysis.gcp.org_policy_guardrails import (
    ORG_POLICY_ALLOWED_MEMBER_DOMAINS,
    ORG_POLICY_REQUIRE_OS_LOGIN,
    ORG_POLICY_VM_EXTERNAL_IP_ACCESS,
)
from tfstride.analysis.gcp.org_policy_severity import guardrail_adjusted_severity_reasoning
from tfstride.analysis.resource_facts import analysis_facts
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import (
    BoundaryType,
    Finding,
    NormalizedResource,
    ResourceInventory,
    SecurityGroupRule,
    TrustBoundary,
)
from tfstride.providers.gcp.constants import (
    GCP_CLOUD_FUNCTION_RESOURCE_TYPES,
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    GCP_GKE_RESOURCE_TYPES,
    PUBLIC_GCP_IAM_MEMBERS,
)
from tfstride.providers.gcp.resource_utils import binding_members
from tfstride.resource_helpers import describe_security_group_rule

_CLOUD_RUN_PUBLIC_INVOKER_ROLES = frozenset({"roles/run.invoker"})
_CLOUD_FUNCTION_PUBLIC_INVOKER_ROLES = frozenset({"roles/cloudfunctions.invoker"})
_GKE_BROAD_OAUTH_SCOPES = frozenset(
    {
        "https://www.googleapis.com/auth/cloud-platform",
        "https://www.googleapis.com/auth/compute",
        "https://www.googleapis.com/auth/devstorage.full_control",
    }
)
_GCP_LOAD_BALANCED_EXPOSURE_RESOURCE_TYPES = (
    "google_compute_instance",
    "google_compute_backend_service",
    "google_compute_region_backend_service",
    "google_storage_bucket",
    *GCP_CLOUD_RUN_RESOURCE_TYPES,
    *GCP_CLOUD_FUNCTION_RESOURCE_TYPES,
    *GCP_GKE_RESOURCE_TYPES,
)


class GcpComputeRuleDetectors:
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
                context.analysis_indexes.gcp_org_policy_guardrails,
                instance,
                constraints=(ORG_POLICY_VM_EXTERNAL_IP_ACCESS,),
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=1,
            )
            boundary = context.boundary_index.get(
                (BoundaryType.INTERNET_TO_SERVICE, "internet", instance.address)
            )
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
                            [
                                describe_security_group_rule(firewall, rule)
                                for firewall, rule in risky_rules
                            ],
                        ),
                        evidence_item("network_tags", analysis_facts(instance).compute.network_tags),
                        evidence_item("internet_ingress_reasons", instance.internet_ingress_reasons),
                        evidence_item("public_exposure_reasons", instance.public_exposure_reasons),
                        organization_guardrail_evidence(
                            context.analysis_indexes.gcp_org_policy_guardrails,
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
            resource_facts = analysis_facts(resource)
            if not resource_facts.compute.fronted_by_internet_facing_load_balancer:
                continue
            frontends = resource_facts.compute.load_balancer_frontends
            frontend_addresses = resource_facts.compute.internet_facing_load_balancer_addresses
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
            instance_facts = analysis_facts(instance)
            if instance_facts.compute.os_login_enabled is not False:
                continue
            severity_reasoning = guardrail_adjusted_severity_reasoning(
                context.analysis_indexes.gcp_org_policy_guardrails,
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
                            context.analysis_indexes.gcp_org_policy_guardrails,
                            instance,
                            ORG_POLICY_REQUIRE_OS_LOGIN,
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_gke_public_control_plane(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type("google_container_cluster"):
            cluster_facts = analysis_facts(cluster)
            if not cluster.public_access_configured:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=1,
            )
            boundary = context.boundary_index.get(
                (BoundaryType.INTERNET_TO_SERVICE, "internet", cluster.address)
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[cluster.address],
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{cluster.display_name} exposes a public GKE control-plane endpoint. "
                        "Public API server reachability increases dependence on IAM, Kubernetes RBAC, "
                        "and authorized network configuration to protect cluster administration."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "control_plane_endpoint",
                            [cluster_facts.gke.endpoint or "public endpoint configured"],
                        ),
                        evidence_item("public_access_reasons", cluster.public_access_reasons),
                        evidence_item("public_exposure_reasons", cluster.public_exposure_reasons),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_gke_broad_authorized_networks(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type("google_container_cluster"):
            cluster_facts = analysis_facts(cluster)
            if not cluster.public_access_configured:
                continue
            broad_networks = _gke_broad_authorized_networks(cluster)
            if not broad_networks:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=2,
                blast_radius=1,
            )
            boundary = context.boundary_index.get(
                (BoundaryType.INTERNET_TO_SERVICE, "internet", cluster.address)
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[cluster.address],
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{cluster.display_name} exposes the GKE control plane without narrow master "
                        "authorized networks. Internet-wide or unset CIDR controls leave the Kubernetes API "
                        "server reachable from untrusted client networks."
                    ),
                    evidence=collect_evidence(
                        evidence_item("authorized_networks", broad_networks),
                        evidence_item(
                            "configured_authorized_network_count",
                            [str(len(cluster_facts.gke.master_authorized_networks))],
                        ),
                        evidence_item("public_exposure_reasons", cluster.public_exposure_reasons),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_gke_workload_identity_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type("google_container_cluster"):
            cluster_facts = analysis_facts(cluster)
            if cluster_facts.gke.workload_identity_enabled is True:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=cluster.public_exposure,
                privilege_breadth=1,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[cluster.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{cluster.display_name} does not enable GKE Workload Identity. Pods are more likely "
                        "to depend on node service-account credentials, which weakens workload-level identity "
                        "boundaries and can expand blast radius after pod compromise."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "workload_identity_posture",
                            [
                                (
                                    "workload_identity_enabled is "
                                    f"{_bool_status(cluster_facts.gke.workload_identity_enabled)}"
                                ),
                                f"workload_pool is {cluster_facts.gke.workload_identity_pool or 'unset'}",
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_gke_legacy_metadata_endpoints_enabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for resource in context.inventory.by_type(*GCP_GKE_RESOURCE_TYPES):
            resource_facts = analysis_facts(resource)
            if resource_facts.gke.legacy_metadata_endpoints_enabled is not True:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=1,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[resource.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{resource.display_name} allows legacy or broad node metadata exposure. Workloads "
                        "on the node may be able to reach metadata credentials outside the intended GKE "
                        "metadata server controls."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "node_metadata_posture",
                            [
                                "legacy metadata endpoints are enabled",
                                f"metadata mode is {resource_facts.gke.node_metadata_mode or 'unset'}",
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_gke_broad_node_service_account(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for resource in context.inventory.by_type(*GCP_GKE_RESOURCE_TYPES):
            resource_facts = analysis_facts(resource)
            risk_descriptions = _gke_node_identity_risks(resource)
            if not risk_descriptions:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=2,
                data_sensitivity=0,
                lateral_movement=2,
                blast_radius=2,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[resource.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{resource.display_name} uses broad GKE node identity settings. Default or broadly "
                        "scoped node service accounts can turn a node or pod compromise into wider GCP API "
                        "access."
                    ),
                    evidence=collect_evidence(
                        evidence_item("node_identity_risks", risk_descriptions),
                        evidence_item("node_service_account", [resource_facts.gke.node_service_account or "unset"]),
                        evidence_item("oauth_scopes", resource_facts.gke.node_oauth_scopes),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

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
                context.analysis_indexes.gcp_org_policy_guardrails,
                service,
                constraints=(ORG_POLICY_ALLOWED_MEMBER_DOMAINS,),
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=0,
                blast_radius=gcp_iam_condition_limited_score(1, condition, floor=0),
            )
            boundary = context.boundary_index.get(
                (BoundaryType.INTERNET_TO_SERVICE, "internet", service.address)
            )
            affected_resources = dedupe_addresses(
                [service.address, *[source for source, _, _, _ in public_invokers]]
            )
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
                            context.analysis_indexes.gcp_org_policy_guardrails,
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
                context.analysis_indexes.gcp_org_policy_guardrails,
                function,
                constraints=(ORG_POLICY_ALLOWED_MEMBER_DOMAINS,),
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=0,
                blast_radius=gcp_iam_condition_limited_score(1, condition, floor=0),
            )
            boundary = context.boundary_index.get(
                (BoundaryType.INTERNET_TO_SERVICE, "internet", function.address)
            )
            affected_resources = dedupe_addresses(
                [function.address, *[source for source, _, _, _ in public_invokers]]
            )
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
                            context.analysis_indexes.gcp_org_policy_guardrails,
                            function,
                            ORG_POLICY_ALLOWED_MEMBER_DOMAINS,
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


def _bool_status(value: bool | None) -> str:
    if value is None:
        return "unset"
    return str(value).lower()


def _gke_broad_authorized_networks(cluster: NormalizedResource) -> list[str]:
    facts = analysis_facts(cluster)
    if not facts.gke.master_authorized_networks:
        return ["master authorized networks are not configured"]
    descriptions: list[str] = []
    for network in facts.gke.master_authorized_networks:
        cidr = str(network.get("cidr_block") or "").strip()
        if cidr not in {"0.0.0.0/0", "::/0"}:
            continue
        name = str(network.get("display_name") or network.get("name") or "unnamed").strip() or "unnamed"
        descriptions.append(f"{name} ({cidr})")
    return descriptions


def _gke_node_identity_risks(resource: NormalizedResource) -> list[str]:
    facts = analysis_facts(resource)
    risks: list[str] = []
    service_account = str(facts.gke.node_service_account or "").strip()
    if not service_account and not facts.gke.node_oauth_scopes:
        if facts.gke.legacy_metadata_endpoints_enabled is None:
            return []
    if not service_account or service_account == "default":
        risks.append("node service account is unset or default")
    elif service_account.endswith("-compute@developer.gserviceaccount.com"):
        risks.append(f"node service account uses default Compute Engine identity `{service_account}`")
    broad_scopes = [scope for scope in facts.gke.node_oauth_scopes if _gke_scope_is_broad(scope)]
    if broad_scopes:
        risks.extend(f"node OAuth scope is broad: {scope}" for scope in broad_scopes)
    return risks


def _gke_scope_is_broad(scope: str) -> bool:
    normalized = str(scope).strip().lower()
    return normalized in _GKE_BROAD_OAUTH_SCOPES or normalized.endswith("/auth/cloud-platform")


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


def _risky_public_firewall_rules(
    instance: NormalizedResource,
    inventory: ResourceInventory,
) -> list[tuple[NormalizedResource, SecurityGroupRule]]:
    firewall_addresses = analysis_facts(instance).compute.internet_ingress_firewalls
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