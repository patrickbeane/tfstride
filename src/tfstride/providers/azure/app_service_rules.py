from __future__ import annotations

from collections.abc import Mapping
from typing import NamedTuple

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.azure.public_network import PUBLIC_NETWORK_FALLBACK_DISABLED
from tfstride.providers.azure.resource_facts import AzureResourceFacts, azure_facts
from tfstride.providers.azure.resource_types import AZURE_APP_SERVICE_RESOURCE_TYPES
from tfstride.providers.azure.resource_utils import tls_version_below_1_2
from tfstride.providers.coercion import STATE_DISABLED, STATE_ENABLED, STATE_NOT_CONFIGURED
from tfstride.providers.kubernetes import is_broad_public_range


class _PlatformAuthentication(NamedTuple):
    source: str
    enabled_state: str | None
    unauthenticated_action: str | None
    default_provider: str | None
    require_authentication_state: str | None


class AzureAppServiceRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_network_access_not_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            facts = azure_facts(app)
            if facts.public_network_fallback_state == PUBLIC_NETWORK_FALLBACK_DISABLED:
                continue
            public_enabled = facts.public_network_access_enabled is True
            severity_reasoning = build_severity_reasoning(
                internet_exposure=public_enabled,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[app.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{app.display_name} does not explicitly disable public network access. App Service "
                        "public endpoint reachability depends on this setting and any additional platform access "
                        "controls; leave it disabled unless the app intentionally accepts public traffic."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(app)),
                        evidence_item("network_posture", _public_network_evidence(facts)),
                        evidence_item("posture_uncertainty", _public_network_uncertainty_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_platform_authentication_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            facts = azure_facts(app)
            authentication = _effective_platform_authentication(facts)
            if facts.public_network_access_enabled is not True:
                continue
            if authentication is None or authentication.enabled_state != STATE_DISABLED:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=1,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[app.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{app.display_name} has public network access enabled and its {authentication.source} "
                        "configuration explicitly disables Azure platform authentication. The application may "
                        "still enforce its own authentication outside Terraform, but tfSTRIDE cannot verify "
                        "that control from this plan."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(app)),
                        evidence_item("network_posture", _public_network_evidence(facts)),
                        evidence_item(
                            "platform_authentication",
                            _platform_authentication_evidence(authentication),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_anonymous_platform_access_allowed(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            facts = azure_facts(app)
            authentication = _effective_platform_authentication(facts)
            if facts.public_network_access_enabled is not True:
                continue
            if authentication is None or authentication.enabled_state != STATE_ENABLED:
                continue
            if not _allows_anonymous_platform_access(authentication.unauthenticated_action):
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=1,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[app.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{app.display_name} has public network access enabled and its {authentication.source} "
                        "configuration explicitly allows anonymous requests. The application may still enforce "
                        "its own authentication outside Terraform, but tfSTRIDE cannot verify that control "
                        "from this plan."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(app)),
                        evidence_item("network_posture", _public_network_evidence(facts)),
                        evidence_item(
                            "platform_authentication",
                            _platform_authentication_evidence(authentication),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_minimum_tls_below_1_2(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            facts = azure_facts(app)
            tls_version = facts.min_tls_version
            if not tls_version_below_1_2(tls_version):
                continue
            public_enabled = facts.public_network_access_enabled is True
            severity_reasoning = build_severity_reasoning(
                internet_exposure=public_enabled,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[app.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{app.display_name} accepts `{tls_version}` as its minimum TLS version. Deprecated TLS "
                        "versions weaken transport protection for App Service and Function App endpoint traffic."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(app)),
                        evidence_item("transport_posture", [f"minimum_tls_version is {tls_version}"]),
                        evidence_item("network_posture", _public_network_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_minimum_tls_unknown(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            facts = azure_facts(app)
            if facts.min_tls_version is not None:
                continue
            public_enabled = facts.public_network_access_enabled is True
            severity_reasoning = build_severity_reasoning(
                internet_exposure=public_enabled,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[app.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{app.display_name} does not expose a deterministic minimum TLS version in the Terraform "
                        "plan. tfSTRIDE cannot prove the app enforces TLS 1.2 or newer from the available data."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(app)),
                        evidence_item("transport_posture", _tls_unknown_evidence(facts)),
                        evidence_item("network_posture", _public_network_evidence(facts)),
                        evidence_item("posture_uncertainty", _tls_uncertainty_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_managed_identity_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            facts = azure_facts(app)
            if facts.has_system_assigned_identity or facts.has_user_assigned_identity:
                continue
            if _identity_is_unknown(facts):
                continue
            public_enabled = facts.public_network_access_enabled is True
            severity_reasoning = build_severity_reasoning(
                internet_exposure=public_enabled,
                privilege_breadth=1,
                data_sensitivity=0,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[app.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{app.display_name} does not configure a managed identity. App Service workloads without "
                        "managed identity commonly fall back to static credentials or deployment-time secrets for "
                        "Azure resource access."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(app)),
                        evidence_item("identity_posture", _identity_posture_evidence(facts)),
                        evidence_item("network_posture", _public_network_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_vnet_integration_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            facts = azure_facts(app)
            if facts.app_service_vnet_integration_subnet_id:
                continue
            if _vnet_integration_is_unknown(facts):
                continue
            public_enabled = facts.public_network_access_enabled is True
            severity_reasoning = build_severity_reasoning(
                internet_exposure=public_enabled,
                privilege_breadth=0,
                data_sensitivity=1,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[app.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{app.display_name} does not have VNet integration configured, so outbound access to "
                        "private Azure resources may rely on public endpoints or service-level firewall exceptions."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(app)),
                        evidence_item("vnet_integration", _vnet_integration_evidence(facts)),
                        evidence_item("network_posture", _public_network_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_access_restrictions_not_default_deny(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            facts = azure_facts(app)
            if not _public_network_fallback_may_allow_access(facts):
                continue
            if not _main_site_access_restrictions_are_not_default_deny(facts):
                continue
            public_enabled = facts.public_network_access_enabled is True
            severity_reasoning = build_severity_reasoning(
                internet_exposure=public_enabled,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[app.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{app.display_name} has a public App Service endpoint but does not configure a "
                        "deterministic default-deny access restriction posture for the main site. Public app "
                        "traffic may reach the workload unless another front-door control blocks it."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(app)),
                        evidence_item("network_posture", _public_network_evidence(facts)),
                        evidence_item("access_restrictions", _main_access_restriction_evidence(facts)),
                        evidence_item(
                            "posture_uncertainty",
                            _access_restriction_uncertainty_evidence(facts, ("ip_restriction",)),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_broad_access_restriction_allow(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            facts = azure_facts(app)
            if not _public_network_fallback_may_allow_access(facts):
                continue
            broad_rules = _broad_allow_records(facts.app_service_access_restrictions)
            if not broad_rules:
                continue
            public_enabled = facts.public_network_access_enabled is True
            severity_reasoning = build_severity_reasoning(
                internet_exposure=public_enabled,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[app.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{app.display_name} has an App Service access restriction allow rule with a broad "
                        "public source. The rule does not narrow internet-origin traffic to trusted clients."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(app)),
                        evidence_item("network_posture", _public_network_evidence(facts)),
                        evidence_item("access_restrictions", _main_access_restriction_evidence(facts)),
                        evidence_item("broad_allow_rules", _restriction_records_evidence(broad_rules)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_scm_access_unrestricted(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            facts = azure_facts(app)
            if not _public_network_fallback_may_allow_access(facts):
                continue
            scm_posture = _scm_unrestricted_posture_evidence(facts)
            if not scm_posture:
                continue
            public_enabled = facts.public_network_access_enabled is True
            severity_reasoning = build_severity_reasoning(
                internet_exposure=public_enabled,
                privilege_breadth=1,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[app.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{app.display_name} does not configure deterministic SCM/Kudu access restrictions. "
                        "The deployment endpoint can expose privileged application management operations if it "
                        "remains reachable from public networks."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(app)),
                        evidence_item("network_posture", _public_network_evidence(facts)),
                        evidence_item("scm_access_posture", scm_posture),
                        evidence_item("scm_access_restrictions", _scm_access_restriction_evidence(facts)),
                        evidence_item(
                            "posture_uncertainty",
                            _access_restriction_uncertainty_evidence(
                                facts,
                                ("scm_ip_restriction", "scm_use_main_ip_restriction"),
                            ),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _target_resource_evidence(app: NormalizedResource) -> list[str]:
    return [f"address={app.address}", f"type={app.resource_type}"]


def _public_network_evidence(facts: AzureResourceFacts) -> list[str]:
    values = [f"public_network_fallback_state={facts.public_network_fallback_state}"]
    if facts.public_network_access_enabled is True:
        values.append("public_network_access_enabled is true")
    elif facts.public_network_access_enabled is False:
        values.append("public_network_access_enabled is false")
    else:
        values.append("public_network_access_enabled is unknown")
    return values


def _effective_platform_authentication(facts: AzureResourceFacts) -> _PlatformAuthentication | None:
    if facts.app_service_auth_v2_enabled_state != STATE_NOT_CONFIGURED:
        return _PlatformAuthentication(
            source="auth_settings_v2",
            enabled_state=facts.app_service_auth_v2_enabled_state,
            unauthenticated_action=facts.app_service_auth_v2_unauthenticated_action,
            default_provider=facts.app_service_auth_v2_default_provider,
            require_authentication_state=facts.app_service_auth_v2_require_authentication_state,
        )
    if facts.app_service_legacy_auth_enabled_state != STATE_NOT_CONFIGURED:
        return _PlatformAuthentication(
            source="auth_settings",
            enabled_state=facts.app_service_legacy_auth_enabled_state,
            unauthenticated_action=facts.app_service_legacy_unauthenticated_action,
            default_provider=facts.app_service_legacy_default_provider,
            require_authentication_state=None,
        )
    return None


def _allows_anonymous_platform_access(unauthenticated_action: str | None) -> bool:
    return bool(unauthenticated_action and unauthenticated_action.strip().lower() == "allowanonymous")


def _platform_authentication_evidence(authentication: _PlatformAuthentication) -> list[str]:
    values = [
        f"configuration_source={authentication.source}",
        f"platform_authentication_state={authentication.enabled_state or 'unknown'}",
    ]
    if authentication.require_authentication_state is not None:
        values.append(f"require_authentication_state={authentication.require_authentication_state}")
    if authentication.unauthenticated_action:
        values.append(f"unauthenticated_action={authentication.unauthenticated_action}")
    if authentication.default_provider:
        values.append(f"default_provider={authentication.default_provider}")
    values.append("application-level authentication is not represented in Terraform")
    return values


def _public_network_uncertainty_evidence(facts: AzureResourceFacts) -> list[str]:
    if facts.public_network_access_enabled is not None:
        return []
    uncertainties = [
        uncertainty
        for uncertainty in facts.app_service_posture_uncertainties
        if "public_network_access_enabled" in uncertainty
    ]
    return uncertainties or ["public_network_access_enabled is not represented in planned values"]


def _tls_unknown_evidence(facts: AzureResourceFacts) -> list[str]:
    uncertainties = _tls_uncertainty_evidence(facts)
    if uncertainties:
        return ["minimum_tls_version is unknown"]
    return ["minimum_tls_version is not represented in planned values"]


def _tls_uncertainty_evidence(facts: AzureResourceFacts) -> list[str]:
    return [
        uncertainty
        for uncertainty in facts.app_service_posture_uncertainties
        if "minimum_tls_version" in uncertainty or "site_config is unknown" in uncertainty
    ]


def _identity_posture_evidence(facts: AzureResourceFacts) -> list[str]:
    if facts.identity_type:
        return [f"identity_type is {facts.identity_type}"]
    return ["identity block is absent"]


def _identity_is_unknown(facts: AzureResourceFacts) -> bool:
    return any("identity" in uncertainty for uncertainty in facts.managed_identity_uncertainties)


def _vnet_integration_evidence(facts: AzureResourceFacts) -> list[str]:
    if facts.app_service_vnet_integration_subnet_id:
        return [f"virtual_network_subnet_id is {facts.app_service_vnet_integration_subnet_id}"]
    return ["virtual_network_subnet_id is not configured"]


def _vnet_integration_is_unknown(facts: AzureResourceFacts) -> bool:
    return any("virtual_network_subnet_id" in uncertainty for uncertainty in facts.app_service_posture_uncertainties)


def _public_network_fallback_may_allow_access(facts: AzureResourceFacts) -> bool:
    return facts.public_network_fallback_state != PUBLIC_NETWORK_FALLBACK_DISABLED


def _main_site_access_restrictions_are_not_default_deny(facts: AzureResourceFacts) -> bool:
    default_action = facts.app_service_ip_restriction_default_action
    if _default_action_is_deny(default_action):
        return False
    if _default_action_is_allow(default_action):
        return True
    return not facts.app_service_access_restrictions


def _main_access_restriction_evidence(facts: AzureResourceFacts) -> list[str]:
    values = _access_restriction_default_action_evidence(
        "ip_restriction_default_action",
        facts.app_service_ip_restriction_default_action,
    )
    values.append(f"ip_restriction_count={len(facts.app_service_access_restrictions)}")
    values.extend(_restriction_records_evidence(facts.app_service_access_restrictions))
    return values


def _scm_access_restriction_evidence(facts: AzureResourceFacts) -> list[str]:
    values: list[str] = []
    if facts.app_service_scm_use_main_ip_restriction is True:
        values.append("scm_use_main_ip_restriction is true")
    elif facts.app_service_scm_use_main_ip_restriction is False:
        values.append("scm_use_main_ip_restriction is false")
    else:
        values.append("scm_use_main_ip_restriction is not represented")
    values.extend(
        _access_restriction_default_action_evidence(
            "scm_ip_restriction_default_action",
            facts.app_service_scm_ip_restriction_default_action,
        )
    )
    values.append(f"scm_ip_restriction_count={len(facts.app_service_scm_access_restrictions)}")
    values.extend(_restriction_records_evidence(facts.app_service_scm_access_restrictions))
    return values


def _access_restriction_default_action_evidence(field_name: str, default_action: str | None) -> list[str]:
    if default_action:
        return [f"{field_name} is {default_action}"]
    return [f"{field_name} is not represented"]


def _scm_unrestricted_posture_evidence(facts: AzureResourceFacts) -> list[str]:
    if facts.app_service_scm_use_main_ip_restriction is True:
        if _broad_allow_records(facts.app_service_access_restrictions):
            return ["SCM inherits a broad main-site allow rule"]
        if _main_site_access_restrictions_are_not_default_deny(facts):
            return ["SCM inherits main-site restrictions that are not default-deny"]
        return []

    broad_scm_rules = _broad_allow_records(facts.app_service_scm_access_restrictions)
    if broad_scm_rules:
        return ["SCM access restriction includes a broad allow rule"]

    scm_default_action = facts.app_service_scm_ip_restriction_default_action
    if _default_action_is_allow(scm_default_action):
        return ["scm_ip_restriction_default_action is Allow"]
    if _default_action_is_deny(scm_default_action):
        return []

    if facts.app_service_scm_use_main_ip_restriction is False and not facts.app_service_scm_access_restrictions:
        return ["scm_use_main_ip_restriction is false", "scm access restrictions are not configured"]

    return []


def _broad_allow_records(records: list[dict[str, object]]) -> list[dict[str, object]]:
    broad_records: list[dict[str, object]] = []
    for record in records:
        action = str(record.get("action") or "").strip().lower()
        if action != "allow":
            continue
        if _broad_sources(record):
            broad_records.append(record)
    return broad_records


def _broad_sources(record: Mapping[str, object]) -> list[str]:
    broad_sources: list[str] = []
    for key in ("ip_address", "service_tag"):
        value = record.get(key)
        if is_broad_public_range(value):
            broad_sources.append(f"{key}={value}")
    return broad_sources


def _restriction_records_evidence(records: list[dict[str, object]]) -> list[str]:
    return [_restriction_record_evidence(record) for record in records]


def _restriction_record_evidence(record: Mapping[str, object]) -> str:
    parts: list[str] = []
    for key in (
        "name",
        "action",
        "priority",
        "ip_address",
        "service_tag",
        "virtual_network_subnet_id",
        "description",
    ):
        value = record.get(key)
        if value not in (None, "", []):
            parts.append(f"{key}={value}")
    broad_sources = _broad_sources(record)
    if broad_sources:
        joined_sources = ", ".join(broad_sources)
        parts.append(f"broad_sources=[{joined_sources}]")
    unknown_fields = record.get("unknown_fields")
    if isinstance(unknown_fields, list) and unknown_fields:
        joined_unknown_fields = ", ".join(str(field) for field in unknown_fields)
        parts.append(f"unknown_fields=[{joined_unknown_fields}]")
    return "rule " + " ".join(parts) if parts else "rule has no deterministic fields"


def _access_restriction_uncertainty_evidence(
    facts: AzureResourceFacts,
    field_markers: tuple[str, ...],
) -> list[str]:
    return [
        uncertainty
        for uncertainty in facts.app_service_posture_uncertainties
        if any(marker in uncertainty for marker in field_markers)
    ]


def _default_action_is_allow(default_action: str | None) -> bool:
    return bool(default_action and default_action.strip().lower() == "allow")


def _default_action_is_deny(default_action: str | None) -> bool:
    return bool(default_action and default_action.strip().lower() == "deny")
