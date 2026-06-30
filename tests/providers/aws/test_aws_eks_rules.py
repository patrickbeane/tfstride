from __future__ import annotations

import unittest
from typing import Any

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS

_EKS_RULE_IDS = (
    "aws-eks-api-endpoint-public-unrestricted",
    "aws-eks-private-endpoint-not-enabled",
    "aws-eks-secrets-encryption-not-configured",
    "aws-eks-control-plane-logging-incomplete",
    "aws-eks-authentication-mode-weak-or-unknown",
    "aws-eks-vpc-cni-network-policy-not-enabled",
)
_MISSING = object()
_KMS_KEY_ARN = "arn:aws:kms:us-east-1:111122223333:key/eks"


def _cluster(
    *,
    name: str = "cluster",
    endpoint_public_access: object = _MISSING,
    endpoint_private_access: object = _MISSING,
    public_access_cidrs: object = _MISSING,
    enabled_cluster_log_types: object = _MISSING,
    encryption_resources: object = _MISSING,
    encryption_key_arn: object = _MISSING,
    authentication_mode: object = _MISSING,
    bootstrap_admin: object = _MISSING,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "name": name,
        "arn": f"arn:aws:eks:us-east-1:111122223333:cluster/{name}",
        "role_arn": "arn:aws:iam::111122223333:role/eks-control-plane",
        "version": "1.29",
    }
    vpc_config: dict[str, Any] = {}
    if any(value is not _MISSING for value in (endpoint_public_access, endpoint_private_access, public_access_cidrs)):
        vpc_config.update(
            {
                "subnet_ids": ["subnet-a", "subnet-b"],
                "security_group_ids": ["sg-client"],
                "cluster_security_group_id": "sg-cluster",
            }
        )
    if endpoint_public_access is not _MISSING:
        vpc_config["endpoint_public_access"] = endpoint_public_access
    if endpoint_private_access is not _MISSING:
        vpc_config["endpoint_private_access"] = endpoint_private_access
    if public_access_cidrs is not _MISSING:
        vpc_config["public_access_cidrs"] = public_access_cidrs
    if vpc_config:
        values["vpc_config"] = [vpc_config]
    if enabled_cluster_log_types is not _MISSING:
        values["enabled_cluster_log_types"] = enabled_cluster_log_types
    if encryption_resources is not _MISSING or encryption_key_arn is not _MISSING:
        encryption: dict[str, Any] = {}
        if encryption_key_arn is not _MISSING:
            encryption["provider"] = [{"key_arn": encryption_key_arn}]
        if encryption_resources is not _MISSING:
            encryption["resources"] = encryption_resources
        values["encryption_config"] = [encryption]
    if authentication_mode is not _MISSING or bootstrap_admin is not _MISSING:
        access_config: dict[str, Any] = {}
        if authentication_mode is not _MISSING:
            access_config["authentication_mode"] = authentication_mode
        if bootstrap_admin is not _MISSING:
            access_config["bootstrap_cluster_creator_admin_permissions"] = bootstrap_admin
        values["access_config"] = [access_config]
    return TerraformResource(
        address=f"aws_eks_cluster.{name}",
        mode="managed",
        resource_type="aws_eks_cluster",
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _addon(
    *,
    name: str = "vpc_cni",
    addon_name: object = "vpc-cni",
    cluster_name: object = "app",
    addon_version: object = "v1.18.1-eksbuild.1",
    configuration_values: object = _MISSING,
    service_account_role_arn: object = _MISSING,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {}
    if addon_name is not _MISSING:
        values["addon_name"] = addon_name
    if cluster_name is not _MISSING:
        values["cluster_name"] = cluster_name
    if addon_version is not _MISSING:
        values["addon_version"] = addon_version
    if configuration_values is not _MISSING:
        values["configuration_values"] = configuration_values
    if service_account_role_arn is not _MISSING:
        values["service_account_role_arn"] = service_account_role_arn
    return TerraformResource(
        address=f"aws_eks_addon.{name}",
        mode="managed",
        resource_type="aws_eks_addon",
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _safe_cluster(*, name: str = "safe", **overrides: object) -> TerraformResource:
    defaults: dict[str, object] = {
        "name": name,
        "endpoint_public_access": False,
        "endpoint_private_access": True,
        "public_access_cidrs": ["198.51.100.10/32"],
        "enabled_cluster_log_types": ["api", "audit", "authenticator"],
        "encryption_resources": ["secrets"],
        "encryption_key_arn": _KMS_KEY_ARN,
        "authentication_mode": "API_AND_CONFIG_MAP",
        "bootstrap_admin": False,
    }
    defaults.update(overrides)
    return _cluster(**defaults)


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = AwsNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AwsEksControlPlaneRuleTests(unittest.TestCase):
    def test_public_unrestricted_cluster_emits_endpoint_encryption_and_logging_findings(self) -> None:
        findings = _evaluate(
            [
                _cluster(
                    name="public",
                    endpoint_public_access=True,
                    endpoint_private_access=False,
                    public_access_cidrs=["0.0.0.0/0"],
                    enabled_cluster_log_types=[],
                    authentication_mode="API_AND_CONFIG_MAP",
                )
            ],
            *_EKS_RULE_IDS,
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [
                "aws-eks-api-endpoint-public-unrestricted",
                "aws-eks-secrets-encryption-not-configured",
                "aws-eks-control-plane-logging-incomplete",
            ],
        )
        findings_by_rule = {finding.rule_id: finding for finding in findings}
        self.assertEqual(findings_by_rule["aws-eks-api-endpoint-public-unrestricted"].severity.value, "high")
        self.assertEqual(findings_by_rule["aws-eks-secrets-encryption-not-configured"].severity.value, "medium")
        self.assertEqual(findings_by_rule["aws-eks-control-plane-logging-incomplete"].severity.value, "medium")
        endpoint_evidence = _evidence_by_key(findings_by_rule["aws-eks-api-endpoint-public-unrestricted"])
        self.assertEqual(
            endpoint_evidence["api_endpoint_posture"],
            [
                "endpoint_public_access_state=enabled",
                "endpoint_private_access_state=disabled",
                "public_access_cidrs=[0.0.0.0/0]",
                "broad_public_access_cidrs=[0.0.0.0/0]",
                "cluster_security_group_id=sg-cluster",
                "subnet_ids=[subnet-a, subnet-b]",
                "security_group_ids=[sg-client]",
            ],
        )
        self.assertNotIn("aws-eks-private-endpoint-not-enabled", {finding.rule_id for finding in findings})

    def test_restricted_private_cluster_has_no_eks_control_plane_posture_findings(self) -> None:
        findings = _evaluate([_safe_cluster()], *_EKS_RULE_IDS)

        self.assertEqual(findings, [])

    def test_public_cluster_with_narrow_cidrs_and_private_endpoint_is_not_broad_public(self) -> None:
        findings = _evaluate(
            [_safe_cluster(endpoint_public_access=True, public_access_cidrs=["198.51.100.10/32"])],
            "aws-eks-api-endpoint-public-unrestricted",
            "aws-eks-private-endpoint-not-enabled",
        )

        self.assertEqual(findings, [])

    def test_public_cluster_with_narrow_cidrs_without_private_endpoint_emits_private_endpoint_only(self) -> None:
        findings = _evaluate(
            [
                _safe_cluster(
                    endpoint_public_access=True,
                    endpoint_private_access=False,
                    public_access_cidrs=["198.51.100.10/32"],
                )
            ],
            "aws-eks-api-endpoint-public-unrestricted",
            "aws-eks-private-endpoint-not-enabled",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["aws-eks-private-endpoint-not-enabled"])
        self.assertEqual(findings[0].severity.value, "medium")
        self.assertIn("public_access_cidrs=[198.51.100.10/32]", _evidence_by_key(findings[0])["api_endpoint_posture"])

    def test_partial_logging_cluster_reports_missing_security_log_types(self) -> None:
        findings = _evaluate(
            [_safe_cluster(enabled_cluster_log_types=["api"])],
            "aws-eks-control-plane-logging-incomplete",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["aws-eks-control-plane-logging-incomplete"])
        self.assertEqual(findings[0].severity.value, "medium")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["control_plane_logging"],
            [
                "control_plane_logging_state=configured",
                "enabled_cluster_log_types=[api]",
                "missing_security_log_types=[audit, authenticator]",
                "expected_security_log_types=[api, audit, authenticator]",
            ],
        )

    def test_legacy_config_map_authentication_mode_is_detected(self) -> None:
        findings = _evaluate(
            [_safe_cluster(authentication_mode="CONFIG_MAP")],
            "aws-eks-authentication-mode-weak-or-unknown",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["aws-eks-authentication-mode-weak-or-unknown"])
        self.assertEqual(findings[0].severity.value, "medium")
        evidence = _evidence_by_key(findings[0])
        self.assertIn("authentication_mode_state=legacy_config_map", evidence["authentication_posture"])
        self.assertIn("authentication_mode=CONFIG_MAP", evidence["authentication_posture"])

    def test_unknown_minimal_cluster_emits_uncertain_findings_without_disabled_endpoint_claim(self) -> None:
        findings = _evaluate([_cluster(name="minimal")], *_EKS_RULE_IDS)

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [
                "aws-eks-api-endpoint-public-unrestricted",
                "aws-eks-secrets-encryption-not-configured",
                "aws-eks-control-plane-logging-incomplete",
                "aws-eks-authentication-mode-weak-or-unknown",
            ],
        )
        self.assertEqual([finding.severity.value for finding in findings], ["medium", "medium", "medium", "low"])
        endpoint_evidence = _evidence_by_key(findings[0])
        self.assertIn("endpoint_public_access_state=unknown", endpoint_evidence["api_endpoint_posture"])
        self.assertIn("endpoint_private_access_state=unknown", endpoint_evidence["api_endpoint_posture"])
        self.assertIn("public_access_cidrs_state=unknown", endpoint_evidence["api_endpoint_posture"])
        auth_evidence = _evidence_by_key(findings[-1])
        self.assertIn("authentication_mode_state=unknown", auth_evidence["authentication_posture"])
        self.assertIn(
            "authentication_mode is not represented in planned values", auth_evidence["authentication_posture"]
        )

    def test_unresolved_values_include_uncertainty_evidence(self) -> None:
        findings = _evaluate(
            [
                _cluster(
                    name="unknown",
                    endpoint_public_access=None,
                    endpoint_private_access=None,
                    public_access_cidrs=[],
                    enabled_cluster_log_types=[],
                    encryption_resources=[],
                    encryption_key_arn=None,
                    unknown_values={
                        "vpc_config": [
                            {
                                "endpoint_public_access": True,
                                "endpoint_private_access": True,
                                "public_access_cidrs": True,
                            }
                        ],
                        "enabled_cluster_log_types": True,
                        "encryption_config": [{"provider": [{"key_arn": True}], "resources": True}],
                        "access_config": [{"authentication_mode": True}],
                    },
                )
            ],
            *_EKS_RULE_IDS,
        )

        findings_by_rule = {finding.rule_id: finding for finding in findings}
        self.assertEqual(
            _evidence_by_key(findings_by_rule["aws-eks-api-endpoint-public-unrestricted"])["posture_uncertainty"],
            [
                "vpc_config.public_access_cidrs is unknown after planning",
                "vpc_config.endpoint_public_access is unknown after planning",
            ],
        )
        self.assertEqual(
            _evidence_by_key(findings_by_rule["aws-eks-secrets-encryption-not-configured"])["posture_uncertainty"],
            [
                "encryption_config[0].provider.key_arn is unknown after planning",
                "encryption_config[0].resources is unknown after planning",
            ],
        )
        self.assertEqual(
            _evidence_by_key(findings_by_rule["aws-eks-control-plane-logging-incomplete"])["posture_uncertainty"],
            ["enabled_cluster_log_types is unknown after planning"],
        )
        self.assertEqual(
            _evidence_by_key(findings_by_rule["aws-eks-authentication-mode-weak-or-unknown"])["posture_uncertainty"],
            ["access_config.authentication_mode is unknown after planning"],
        )

    def test_vpc_cni_network_policy_rule_detects_explicit_disabled_config(self) -> None:
        findings = _evaluate(
            [
                _addon(
                    configuration_values=(
                        '{"env":{"ENABLE_NETWORK_POLICY":"false"},"resources":{"limits":{"cpu":"100m"}}}'
                    ),
                    service_account_role_arn="arn:aws:iam::111122223333:role/eks-vpc-cni",
                )
            ],
            "aws-eks-vpc-cni-network-policy-not-enabled",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["aws-eks-vpc-cni-network-policy-not-enabled"])
        self.assertEqual(findings[0].severity.value, "medium")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["target_resource"],
            [
                "address=aws_eks_addon.vpc_cni",
                "type=aws_eks_addon",
                "addon_name=vpc-cni",
                "cluster_name=app",
                "addon_version=v1.18.1-eksbuild.1",
                "target_class=networking",
                "service_account_role_arn=arn:aws:iam::111122223333:role/eks-vpc-cni",
            ],
        )
        self.assertEqual(
            evidence["network_policy_posture"],
            [
                "addon_name=vpc-cni",
                "configuration_path=env.ENABLE_NETWORK_POLICY",
                "configured_value=false",
                "configuration_keys=[env, resources]",
            ],
        )

    def test_vpc_cni_network_policy_rule_ignores_enabled_missing_unknown_and_other_addons(self) -> None:
        scenarios = {
            "enabled": _addon(configuration_values='{ "env": { "ENABLE_NETWORK_POLICY": "true" } }'),
            "missing_config_key": _addon(configuration_values='{ "env": { "WARM_IP_TARGET": "3" } }'),
            "invalid_config_shape": _addon(configuration_values="[1, 2, 3]"),
            "unknown_config": _addon(
                configuration_values=None,
                unknown_values={"configuration_values": True},
            ),
            "other_addon": _addon(
                addon_name="coredns", configuration_values='{ "env": { "ENABLE_NETWORK_POLICY": "false" } }'
            ),
        }

        for name, resource in scenarios.items():
            with self.subTest(name=name):
                findings = _evaluate([resource], "aws-eks-vpc-cni-network-policy-not-enabled")
                self.assertEqual(findings, [])

    def test_eks_rule_ids_are_registered_with_aws_rule_group(self) -> None:
        registered = tuple(rule_id for group in AWS_RULE_GROUP_IDS for rule_id in group)

        for rule_id in _EKS_RULE_IDS:
            with self.subTest(rule_id=rule_id):
                self.assertIn(rule_id, registered)


if __name__ == "__main__":
    unittest.main()
