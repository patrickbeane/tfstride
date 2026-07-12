from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding
from tfstride.providers.aws.resource_facts import AwsResourceFacts, aws_facts
from tfstride.providers.coercion import (
    STATE_CONFIGURED,
    STATE_DISABLED,
    STATE_ENABLED,
    STATE_NOT_CONFIGURED,
    STATE_UNKNOWN,
)
from tfstride.providers.kubernetes import is_broad_public_range, uncertainty_evidence

_AWS_EKS_CLUSTER = "aws_eks_cluster"
_AWS_EKS_ADDON = "aws_eks_addon"
_REQUIRED_SECURITY_LOG_TYPES = ("api", "audit", "authenticator")
_WEAK_AUTHENTICATION_MODES = frozenset({"config_map"})
_VPC_CNI_ADDON_NAME = "vpc-cni"
_NETWORK_POLICY_CONFIG_KEYS = frozenset({"enablenetworkpolicy", "enable_network_policy"})


@dataclass(frozen=True, slots=True)
class _NetworkPolicyConfigValue:
    path: str
    value: str


@dataclass(frozen=True, slots=True)
class _PublicAccessRestriction:
    state: str
    broad_ranges: tuple[str, ...] = ()

    @property
    def broad_or_missing_or_unknown(self) -> bool:
        return self.state in {"broad", STATE_NOT_CONFIGURED, STATE_UNKNOWN}


class AwsEksRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_api_endpoint_unrestricted(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type(_AWS_EKS_CLUSTER):
            facts = aws_facts(cluster)
            restriction = _public_access_restriction(facts)
            if facts.eks_endpoint_public_access_state not in {STATE_ENABLED, STATE_UNKNOWN}:
                continue
            if not restriction.broad_or_missing_or_unknown:
                continue

            explicit_broad = facts.eks_endpoint_public_access_state == STATE_ENABLED and restriction.state in {
                "broad",
                STATE_NOT_CONFIGURED,
            }
            severity_reasoning = build_severity_reasoning(
                internet_exposure=explicit_broad,
                privilege_breadth=1,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=2 if explicit_broad else 1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[cluster.address],
                    trust_boundary_id=None,
                    rationale=_public_api_rationale(cluster.display_name, explicit_broad),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(cluster, facts)),
                        evidence_item("api_endpoint_posture", _api_endpoint_evidence(facts, restriction)),
                        evidence_item(
                            "posture_uncertainty",
                            uncertainty_evidence(
                                facts.eks_posture_uncertainties,
                                (
                                    "vpc_config.endpoint_public_access",
                                    "vpc_config.public_access_cidrs",
                                ),
                            ),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_private_endpoint_not_enabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type(_AWS_EKS_CLUSTER):
            facts = aws_facts(cluster)
            if facts.eks_endpoint_private_access_state != STATE_DISABLED:
                continue
            if _public_endpoint_unrestricted(facts):
                continue

            severity_reasoning = build_severity_reasoning(
                internet_exposure=facts.eks_endpoint_public_access_state == STATE_ENABLED,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[cluster.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{cluster.display_name} does not enable the EKS private Kubernetes API endpoint. "
                        "Control-plane access may rely on the public endpoint even when public CIDRs are restricted."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(cluster, facts)),
                        evidence_item(
                            "api_endpoint_posture", _api_endpoint_evidence(facts, _public_access_restriction(facts))
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_secrets_encryption_not_configured(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type(_AWS_EKS_CLUSTER):
            facts = aws_facts(cluster)
            if facts.eks_secrets_encryption_state == STATE_ENABLED:
                continue

            unknown = facts.eks_secrets_encryption_state == STATE_UNKNOWN
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=1 if unknown else 2,
                lateral_movement=0,
                blast_radius=0 if unknown else 1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[cluster.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{cluster.display_name} does not show deterministic EKS secrets encryption with a KMS key "
                        "for Kubernetes secrets in the Terraform plan."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(cluster, facts)),
                        evidence_item("secrets_encryption_posture", _secrets_encryption_evidence(facts)),
                        evidence_item(
                            "posture_uncertainty",
                            uncertainty_evidence(facts.eks_posture_uncertainties, ("encryption_config",)),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_control_plane_logging_incomplete(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type(_AWS_EKS_CLUSTER):
            facts = aws_facts(cluster)
            missing_logs = _missing_security_log_types(facts)
            if facts.eks_control_plane_logging_state == STATE_CONFIGURED and not missing_logs:
                continue

            unknown = facts.eks_control_plane_logging_state == STATE_UNKNOWN
            disabled = facts.eks_control_plane_logging_state == STATE_NOT_CONFIGURED
            incomplete = facts.eks_control_plane_logging_state == STATE_CONFIGURED and bool(missing_logs)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=2 if disabled or incomplete else 1,
                blast_radius=1 if not unknown else 0,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[cluster.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{cluster.display_name} does not deterministically enable the key EKS control-plane logs "
                        "needed for security investigation and Kubernetes API auditability."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(cluster, facts)),
                        evidence_item("control_plane_logging", _control_plane_logging_evidence(facts, missing_logs)),
                        evidence_item(
                            "posture_uncertainty",
                            uncertainty_evidence(facts.eks_posture_uncertainties, ("enabled_cluster_log_types",)),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_authentication_mode_weak_or_unknown(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type(_AWS_EKS_CLUSTER):
            facts = aws_facts(cluster)
            state = _authentication_mode_state(facts)
            if state == STATE_CONFIGURED:
                continue

            weak = state == "legacy_config_map"
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=2 if weak else 1,
                data_sensitivity=0,
                lateral_movement=0,
                blast_radius=1 if weak else 0,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[cluster.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{cluster.display_name} does not clearly use the newer EKS access management model. "
                        "tfSTRIDE reports this as an authentication posture finding without inferring runtime access."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(cluster, facts)),
                        evidence_item("authentication_posture", _authentication_evidence(facts, state)),
                        evidence_item(
                            "posture_uncertainty",
                            uncertainty_evidence(
                                facts.eks_posture_uncertainties, ("access_config.authentication_mode",)
                            ),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_vpc_cni_network_policy_not_enabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for addon in context.inventory.by_type(_AWS_EKS_ADDON):
            facts = aws_facts(addon)
            disabled_config = _vpc_cni_disabled_network_policy_config(facts)
            if disabled_config is None:
                continue

            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=2,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[addon.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{addon.display_name} explicitly configures EKS VPC CNI network policy support as "
                        "disabled. EKS network policy enforcement is implementation-dependent, so tfSTRIDE "
                        "reports only the deterministic add-on configuration represented in Terraform."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _addon_target_resource_evidence(addon, facts)),
                        evidence_item(
                            "network_policy_posture", _vpc_cni_network_policy_evidence(facts, disabled_config)
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _target_resource_evidence(cluster, facts: AwsResourceFacts) -> list[str]:
    values = [f"address={cluster.address}", f"type={cluster.resource_type}"]
    if facts.resource_name:
        values.append(f"cluster_name={facts.resource_name}")
    if facts.eks_cluster_arn:
        values.append(f"cluster_arn={facts.eks_cluster_arn}")
    if facts.eks_kubernetes_version:
        values.append(f"kubernetes_version={facts.eks_kubernetes_version}")
    return values


def _public_api_rationale(display_name: str, explicit_broad: bool) -> str:
    if explicit_broad:
        return (
            f"{display_name} enables the public EKS Kubernetes API endpoint without narrow public access CIDRs. "
            "The control plane is publicly reachable from broad or unspecified source ranges."
        )
    return (
        f"{display_name} does not provide enough deterministic Terraform plan evidence to prove the EKS Kubernetes "
        "API endpoint is private or restricted to narrow public access CIDRs."
    )


def _api_endpoint_evidence(facts: AwsResourceFacts, restriction: _PublicAccessRestriction) -> list[str]:
    values = [
        f"endpoint_public_access_state={facts.eks_endpoint_public_access_state or STATE_UNKNOWN}",
        f"endpoint_private_access_state={facts.eks_endpoint_private_access_state or STATE_UNKNOWN}",
    ]
    if facts.eks_public_access_cidrs:
        values.append(f"public_access_cidrs=[{', '.join(facts.eks_public_access_cidrs)}]")
    else:
        values.append(f"public_access_cidrs_state={facts.eks_public_access_cidrs_state or STATE_UNKNOWN}")
    if restriction.broad_ranges:
        values.append(f"broad_public_access_cidrs=[{', '.join(restriction.broad_ranges)}]")
    if facts.eks_cluster_security_group_id:
        values.append(f"cluster_security_group_id={facts.eks_cluster_security_group_id}")
    if facts.eks_subnet_ids:
        values.append(f"subnet_ids=[{', '.join(facts.eks_subnet_ids)}]")
    if facts.eks_security_group_ids:
        values.append(f"security_group_ids=[{', '.join(facts.eks_security_group_ids)}]")
    return values


def _secrets_encryption_evidence(facts: AwsResourceFacts) -> list[str]:
    values = [
        f"encryption_config_state={facts.eks_encryption_config_state or STATE_UNKNOWN}",
        f"secrets_encryption_state={facts.eks_secrets_encryption_state or STATE_UNKNOWN}",
    ]
    if facts.eks_encryption_resources:
        values.append(f"encrypted_resources=[{', '.join(facts.eks_encryption_resources)}]")
    else:
        values.append("encrypted_resources=[]")
    if facts.eks_encryption_key_arn:
        values.append(f"kms_key_arn={facts.eks_encryption_key_arn}")
    else:
        values.append("kms_key_arn is not configured")
    return values


def _control_plane_logging_evidence(facts: AwsResourceFacts, missing_logs: tuple[str, ...]) -> list[str]:
    values = [f"control_plane_logging_state={facts.eks_control_plane_logging_state or STATE_UNKNOWN}"]
    if facts.eks_enabled_cluster_log_types:
        values.append(f"enabled_cluster_log_types=[{', '.join(facts.eks_enabled_cluster_log_types)}]")
    else:
        values.append("enabled_cluster_log_types=[]")
    if missing_logs:
        values.append(f"missing_security_log_types=[{', '.join(missing_logs)}]")
    values.append(f"expected_security_log_types=[{', '.join(_REQUIRED_SECURITY_LOG_TYPES)}]")
    return values


def _authentication_evidence(facts: AwsResourceFacts, state: str) -> list[str]:
    values = [
        f"authentication_mode_state={state}",
        f"access_config_state={facts.eks_access_config_state or STATE_UNKNOWN}",
    ]
    if facts.eks_authentication_mode:
        values.append(f"authentication_mode={facts.eks_authentication_mode}")
    else:
        values.append("authentication_mode is not represented in planned values")
    if facts.eks_bootstrap_cluster_creator_admin_permissions_state:
        values.append(
            "bootstrap_cluster_creator_admin_permissions_state="
            f"{facts.eks_bootstrap_cluster_creator_admin_permissions_state}"
        )
    return values


def _addon_target_resource_evidence(addon, facts: AwsResourceFacts) -> list[str]:
    values = [f"address={addon.address}", f"type={addon.resource_type}"]
    if facts.eks_addon_name:
        values.append(f"addon_name={facts.eks_addon_name}")
    if facts.eks_addon_cluster_name:
        values.append(f"cluster_name={facts.eks_addon_cluster_name}")
    if facts.eks_addon_version:
        values.append(f"addon_version={facts.eks_addon_version}")
    if facts.eks_addon_target_class:
        values.append(f"target_class={facts.eks_addon_target_class}")
    if facts.eks_addon_service_account_role_arn:
        values.append(f"service_account_role_arn={facts.eks_addon_service_account_role_arn}")
    return values


def _vpc_cni_network_policy_evidence(
    facts: AwsResourceFacts,
    disabled_config: _NetworkPolicyConfigValue,
) -> list[str]:
    values = [
        f"addon_name={facts.eks_addon_name or STATE_UNKNOWN}",
        f"configuration_path={disabled_config.path}",
        f"configured_value={disabled_config.value}",
    ]
    if facts.eks_addon_configuration_keys:
        values.append(f"configuration_keys=[{', '.join(facts.eks_addon_configuration_keys)}]")
    return values


def _public_endpoint_unrestricted(facts: AwsResourceFacts) -> bool:
    restriction = _public_access_restriction(facts)
    return facts.eks_endpoint_public_access_state == STATE_ENABLED and restriction.state in {
        "broad",
        STATE_NOT_CONFIGURED,
    }


def _public_access_restriction(facts: AwsResourceFacts) -> _PublicAccessRestriction:
    if facts.eks_public_access_cidrs_state == STATE_UNKNOWN:
        return _PublicAccessRestriction(STATE_UNKNOWN)
    if not facts.eks_public_access_cidrs:
        return _PublicAccessRestriction(STATE_NOT_CONFIGURED)
    broad_ranges = tuple(value for value in facts.eks_public_access_cidrs if is_broad_public_range(value))
    if broad_ranges:
        return _PublicAccessRestriction("broad", broad_ranges)
    return _PublicAccessRestriction("narrow")


def _missing_security_log_types(facts: AwsResourceFacts) -> tuple[str, ...]:
    enabled = {value.strip().lower() for value in facts.eks_enabled_cluster_log_types}
    return tuple(log_type for log_type in _REQUIRED_SECURITY_LOG_TYPES if log_type not in enabled)


def _authentication_mode_state(facts: AwsResourceFacts) -> str:
    mode = facts.eks_authentication_mode
    if facts.eks_access_config_state == STATE_UNKNOWN or uncertainty_evidence(
        facts.eks_posture_uncertainties,
        ("access_config.authentication_mode",),
    ):
        return STATE_UNKNOWN
    if not mode:
        return STATE_UNKNOWN
    normalized = mode.strip().lower()
    if normalized in _WEAK_AUTHENTICATION_MODES:
        return "legacy_config_map"
    return STATE_CONFIGURED


def _vpc_cni_disabled_network_policy_config(facts: AwsResourceFacts) -> _NetworkPolicyConfigValue | None:
    if (facts.eks_addon_name or "").strip().lower() != _VPC_CNI_ADDON_NAME:
        return None
    configuration_values = facts.eks_addon_configuration_values
    if not configuration_values:
        return None
    try:
        parsed = json.loads(configuration_values)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None

    for path, value in _iter_config_values(parsed):
        key = _normalized_config_key(path[-1]) if path else ""
        if key not in _NETWORK_POLICY_CONFIG_KEYS:
            continue
        state = _config_bool_state(value)
        if state is False:
            return _NetworkPolicyConfigValue(".".join(path), _display_config_value(value))
    return None


def _iter_config_values(value: Any, path: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _iter_config_values(child, (*path, str(key)))
        return
    if path:
        yield path, value


def _normalized_config_key(value: str) -> str:
    return "".join(character for character in value.strip().lower() if character.isalnum() or character == "_")


def _config_bool_state(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "enabled", "yes", "on", "1"}:
            return True
        if normalized in {"false", "disabled", "no", "off", "0"}:
            return False
    return None


def _display_config_value(value: Any) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)
