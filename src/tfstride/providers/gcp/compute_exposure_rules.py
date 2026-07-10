from __future__ import annotations

from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
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
from tfstride.providers.gcp.indexes import gcp_org_policy_guardrail_index
from tfstride.providers.gcp.org_policy_evidence import organization_guardrail_evidence
from tfstride.providers.gcp.org_policy_guardrails import (
    ORG_POLICY_REQUIRE_OS_LOGIN,
    ORG_POLICY_VM_EXTERNAL_IP_ACCESS,
)
from tfstride.providers.gcp.org_policy_severity import guardrail_adjusted_severity_reasoning
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import (
    GCP_CLOUD_FUNCTION_RESOURCE_TYPES,
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    GCP_GKE_RESOURCE_TYPES,
)
from tfstride.resource_helpers import describe_security_group_rule

_GCP_FORWARDING_RULE_RESOURCE_TYPES = ("google_compute_forwarding_rule", "google_compute_global_forwarding_rule")
_GCP_HTTP_TARGET_PROXY_RESOURCE_TYPES = (
    "google_compute_target_http_proxy",
    "google_compute_region_target_http_proxy",
)
_GCP_HTTPS_TARGET_PROXY_RESOURCE_TYPES = (
    "google_compute_target_https_proxy",
    "google_compute_region_target_https_proxy",
)
_GCP_SSL_POLICY_REFERENCE_SUFFIXES = (".id", ".name", ".self_link")
_WEAK_GCP_SSL_POLICY_MIN_TLS_VERSIONS = frozenset(
    {
        "tls_1_0",
        "tls1_0",
        "tlsv1_0",
        "tls10",
        "tls_1_1",
        "tls1_1",
        "tlsv1_1",
        "tls11",
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
                        evidence_item("network_tags", analysis_facts(instance).compute.network_tags),
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
            resource_facts = analysis_facts(resource).compute
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

    def detect_public_load_balancer_http_frontend(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for forwarding_rule, target_proxy in _public_forwarding_rule_target_proxies(
            context.inventory,
            _GCP_HTTP_TARGET_PROXY_RESOURCE_TYPES,
        ):
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=1,
            )
            boundary = _forwarding_rule_boundary(context, forwarding_rule)
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses([forwarding_rule.address, target_proxy.address]),
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{forwarding_rule.display_name} is public and targets {target_proxy.display_name}, "
                        "an HTTP target proxy. Public load balancer frontends should terminate HTTPS or "
                        "redirect HTTP to HTTPS so clients do not rely on cleartext transport."
                    ),
                    evidence=collect_evidence(
                        evidence_item("frontend_forwarding_rule", _forwarding_rule_evidence(forwarding_rule)),
                        evidence_item("target_proxy", _target_proxy_evidence(target_proxy)),
                        evidence_item("proxy_transport", _http_proxy_transport_evidence(target_proxy)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_public_load_balancer_ssl_policy_missing_or_weak(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for forwarding_rule, target_proxy in _public_forwarding_rule_target_proxies(
            context.inventory,
            _GCP_HTTPS_TARGET_PROXY_RESOURCE_TYPES,
        ):
            policy_state, ssl_policy = _target_proxy_ssl_policy_state(context.inventory, target_proxy)
            if policy_state in {"configured", "unresolved", "unknown"}:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=0,
                blast_radius=1,
            )
            boundary = _forwarding_rule_boundary(context, forwarding_rule)
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [forwarding_rule.address, target_proxy.address, ssl_policy.address if ssl_policy else ""]
                    ),
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=_ssl_policy_rationale(target_proxy, ssl_policy, policy_state),
                    evidence=collect_evidence(
                        evidence_item("frontend_forwarding_rule", _forwarding_rule_evidence(forwarding_rule)),
                        evidence_item("target_proxy", _target_proxy_evidence(target_proxy)),
                        evidence_item(
                            "ssl_policy_posture", _ssl_policy_evidence(target_proxy, ssl_policy, policy_state)
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_public_load_balancer_edge_protection_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for backend_service in context.inventory.by_type(
            "google_compute_backend_service",
            "google_compute_region_backend_service",
        ):
            backend_facts = analysis_facts(backend_service).compute
            if not backend_facts.fronted_by_internet_facing_load_balancer:
                continue
            policy_state = _backend_service_edge_protection_state(backend_service)
            if policy_state in {"configured", "unknown"}:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=1,
            )
            boundary = _load_balancer_frontend_boundary(context, backend_facts.load_balancer_frontends)
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [backend_service.address, *backend_facts.internet_facing_load_balancer_addresses]
                    ),
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{backend_service.display_name} is reached by a public GCP load balancer path, but the "
                        "Terraform plan does not show a deterministic Cloud Armor security_policy or "
                        "edge_security_policy attached to the backend service. Public edge traffic can reach "
                        "the backend without a modeled edge protection policy."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_backend_service", _backend_service_edge_evidence(backend_service)),
                        evidence_item(
                            "frontend_load_balancers",
                            backend_facts.internet_facing_load_balancer_addresses,
                        ),
                        evidence_item(
                            "load_balancer_paths",
                            _load_balancer_path_evidence(backend_facts.load_balancer_frontends),
                        ),
                        evidence_item(
                            "edge_protection_policy",
                            _backend_service_edge_protection_evidence(backend_service, policy_state),
                        ),
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
            instance_facts = analysis_facts(instance).compute
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


def _public_forwarding_rule_target_proxies(
    inventory: ResourceInventory,
    target_proxy_types: tuple[str, ...],
) -> list[tuple[NormalizedResource, NormalizedResource]]:
    matches: list[tuple[NormalizedResource, NormalizedResource]] = []
    for forwarding_rule in inventory.by_type(*_GCP_FORWARDING_RULE_RESOURCE_TYPES):
        if not forwarding_rule.public_access_configured:
            continue
        target_reference = analysis_facts(forwarding_rule).compute.forwarding_rule_target
        if not target_reference:
            continue
        target_proxy = _resolve_inventory_reference(inventory, target_reference)
        if target_proxy is not None and target_proxy.resource_type in target_proxy_types:
            matches.append((forwarding_rule, target_proxy))
    return matches


def _resolve_inventory_reference(inventory: ResourceInventory, reference: str) -> NormalizedResource | None:
    for candidate in _reference_candidates(reference):
        resource = inventory.get_by_address(candidate) or inventory.get_by_identifier(candidate)
        if resource is not None:
            return resource
    return None


def _reference_candidates(reference: str) -> list[str]:
    text = str(reference).strip()
    candidates = [text]
    for suffix in _GCP_SSL_POLICY_REFERENCE_SUFFIXES:
        if text.endswith(suffix):
            candidates.append(text[: -len(suffix)])
    return dedupe_addresses(candidates)


def _forwarding_rule_boundary(
    context: RuleEvaluationContext,
    forwarding_rule: NormalizedResource,
) -> TrustBoundary | None:
    return context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", forwarding_rule.address))


def _forwarding_rule_evidence(forwarding_rule: NormalizedResource) -> list[str]:
    facts = analysis_facts(forwarding_rule).compute
    values = [f"address={forwarding_rule.address}", f"type={forwarding_rule.resource_type}"]
    if facts.forwarding_rule_load_balancing_scheme:
        values.append(f"scheme={facts.forwarding_rule_load_balancing_scheme}")
    if facts.forwarding_rule_ip_address:
        values.append(f"ip_address={facts.forwarding_rule_ip_address}")
    if facts.forwarding_rule_ports:
        values.append("ports=" + ",".join(facts.forwarding_rule_ports))
    if facts.forwarding_rule_target:
        values.append(f"target={facts.forwarding_rule_target}")
    values.append("public_exposure=true")
    values.extend(forwarding_rule.public_exposure_reasons)
    return values


def _target_proxy_evidence(target_proxy: NormalizedResource) -> list[str]:
    facts = analysis_facts(target_proxy).compute
    values = [f"address={target_proxy.address}", f"type={target_proxy.resource_type}"]
    if facts.load_balancer_ssl_policy:
        values.append(f"ssl_policy={facts.load_balancer_ssl_policy}")
    if facts.load_balancer_certificate_map:
        values.append(f"certificate_map={facts.load_balancer_certificate_map}")
    return values


def _http_proxy_transport_evidence(target_proxy: NormalizedResource) -> list[str]:
    return [f"target_proxy_type={target_proxy.resource_type}", "HTTP target proxy does not terminate TLS"]


def _target_proxy_ssl_policy_state(
    inventory: ResourceInventory,
    target_proxy: NormalizedResource,
) -> tuple[str, NormalizedResource | None]:
    ssl_policy_reference = analysis_facts(target_proxy).compute.load_balancer_ssl_policy
    if not ssl_policy_reference:
        return "missing", None
    ssl_policy = _resolve_inventory_reference(inventory, ssl_policy_reference)
    if ssl_policy is None:
        return "unresolved", None
    min_tls_state = _ssl_policy_min_tls_state(ssl_policy)
    if min_tls_state == "weak":
        return "weak", ssl_policy
    return min_tls_state, ssl_policy


def _ssl_policy_min_tls_state(ssl_policy: NormalizedResource) -> str:
    min_tls_version = analysis_facts(ssl_policy).compute.ssl_policy_min_tls_version
    if not min_tls_version:
        return "unknown"
    normalized = min_tls_version.strip().lower().replace("-", "_").replace(".", "_")
    if normalized in _WEAK_GCP_SSL_POLICY_MIN_TLS_VERSIONS:
        return "weak"
    return "configured"


def _ssl_policy_evidence(
    target_proxy: NormalizedResource,
    ssl_policy: NormalizedResource | None,
    policy_state: str,
) -> list[str]:
    proxy_facts = analysis_facts(target_proxy).compute
    values = [f"ssl_policy_state={policy_state}"]
    if proxy_facts.load_balancer_ssl_policy:
        values.append(f"ssl_policy_reference={proxy_facts.load_balancer_ssl_policy}")
    else:
        values.append("ssl_policy is unset")
    if ssl_policy is not None:
        policy_facts = analysis_facts(ssl_policy).compute
        values.append(f"ssl_policy_resource={ssl_policy.address}")
        if policy_facts.ssl_policy_min_tls_version:
            values.append(f"min_tls_version={policy_facts.ssl_policy_min_tls_version}")
        if policy_facts.ssl_policy_profile:
            values.append(f"profile={policy_facts.ssl_policy_profile}")
        if policy_facts.ssl_policy_custom_features:
            values.append("custom_features=" + ",".join(policy_facts.ssl_policy_custom_features))
        if policy_facts.ssl_policy_enabled_features:
            values.append("enabled_features=" + ",".join(policy_facts.ssl_policy_enabled_features))
    return values


def _ssl_policy_rationale(
    target_proxy: NormalizedResource,
    ssl_policy: NormalizedResource | None,
    policy_state: str,
) -> str:
    if policy_state == "weak" and ssl_policy is not None:
        min_tls_version = analysis_facts(ssl_policy).compute.ssl_policy_min_tls_version or "an older TLS version"
        return (
            f"{target_proxy.display_name} uses {ssl_policy.display_name}, whose minimum TLS version is "
            f"`{min_tls_version}`. Public HTTPS load balancers should require TLS 1.2 or newer."
        )
    return (
        f"{target_proxy.display_name} is on a public HTTPS load balancer path but does not attach an explicit "
        "GCP SSL policy. tfSTRIDE cannot prove the public frontend enforces a modern minimum TLS version from "
        "the available plan data."
    )


def _backend_service_edge_protection_state(backend_service: NormalizedResource) -> str:
    facts = gcp_facts(backend_service)
    if facts.load_balancer_backend_service_security_policy or facts.load_balancer_backend_service_edge_security_policy:
        return "configured"
    if facts.edge_protection_posture_uncertainties:
        return "unknown"
    return "missing"


def _backend_service_edge_evidence(backend_service: NormalizedResource) -> list[str]:
    facts = gcp_facts(backend_service)
    values = [f"address={backend_service.address}", f"type={backend_service.resource_type}"]
    if facts.load_balancer_backend_service_protocol:
        values.append(f"protocol={facts.load_balancer_backend_service_protocol}")
    if facts.load_balancer_backend_service_load_balancing_scheme:
        values.append(f"scheme={facts.load_balancer_backend_service_load_balancing_scheme}")
    values.append("fronted_by_internet_facing_load_balancer=true")
    return values


def _backend_service_edge_protection_evidence(
    backend_service: NormalizedResource,
    policy_state: str,
) -> list[str]:
    facts = gcp_facts(backend_service)
    values = [f"edge_protection_state={policy_state}"]
    if facts.load_balancer_backend_service_security_policy:
        values.append(f"security_policy={facts.load_balancer_backend_service_security_policy}")
    else:
        values.append("security_policy is unset")
    if facts.load_balancer_backend_service_edge_security_policy:
        values.append(f"edge_security_policy={facts.load_balancer_backend_service_edge_security_policy}")
    else:
        values.append("edge_security_policy is unset")
    values.extend(facts.edge_protection_posture_uncertainties)
    return values


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
