from __future__ import annotations

import unittest
from typing import Any

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.aws.eks_normalizers import normalize_eks_addon, normalize_eks_cluster
from tfstride.providers.aws.normalizer import SUPPORTED_AWS_TYPES, AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts


def _cluster(
    values: dict[str, Any],
    *,
    name: str = "cluster",
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
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
    values: dict[str, Any],
    *,
    name: str = "vpc_cni",
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"aws_eks_addon.{name}",
        mode="managed",
        resource_type="aws_eks_addon",
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _aws_findings(resources: list[TerraformResource]):
    inventory = AwsNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(inventory, [], rule_policy=RulePolicy(enabled_rule_ids=frozenset()))


class AwsEksNormalizerTests(unittest.TestCase):
    def test_public_unrestricted_cluster_normalizes_endpoint_logging_and_encryption_absence(self) -> None:
        normalized = normalize_eks_cluster(
            _cluster(
                {
                    "id": "public",
                    "name": "public",
                    "arn": "arn:aws:eks:us-east-1:111122223333:cluster/public",
                    "version": "1.29",
                    "role_arn": "arn:aws:iam::111122223333:role/eks-control-plane",
                    "vpc_config": [
                        {
                            "endpoint_public_access": True,
                            "endpoint_private_access": False,
                            "public_access_cidrs": ["0.0.0.0/0"],
                            "subnet_ids": ["subnet-public-a", "subnet-public-b"],
                            "security_group_ids": ["sg-client"],
                            "cluster_security_group_id": "sg-cluster",
                        }
                    ],
                    "enabled_cluster_log_types": [],
                },
                name="public",
            )
        )
        facts = aws_facts(normalized)

        self.assertEqual(normalized.identifier, "public")
        self.assertEqual(normalized.arn, "arn:aws:eks:us-east-1:111122223333:cluster/public")
        self.assertTrue(normalized.public_access_configured)
        self.assertEqual(normalized.subnet_ids, ("subnet-public-a", "subnet-public-b"))
        self.assertEqual(normalized.security_group_ids, ("sg-client",))
        self.assertEqual(normalized.attached_role_arns, ["arn:aws:iam::111122223333:role/eks-control-plane"])
        self.assertEqual(facts.resource_name, "public")
        self.assertEqual(facts.eks_cluster_arn, "arn:aws:eks:us-east-1:111122223333:cluster/public")
        self.assertEqual(facts.eks_cluster_role_arn, "arn:aws:iam::111122223333:role/eks-control-plane")
        self.assertEqual(facts.eks_kubernetes_version, "1.29")
        self.assertEqual(facts.eks_endpoint_public_access_state, "enabled")
        self.assertEqual(facts.eks_endpoint_private_access_state, "disabled")
        self.assertEqual(facts.eks_public_access_cidrs, ["0.0.0.0/0"])
        self.assertEqual(facts.eks_public_access_cidrs_state, "configured")
        self.assertEqual(facts.eks_subnet_ids, ["subnet-public-a", "subnet-public-b"])
        self.assertEqual(facts.eks_security_group_ids, ["sg-client"])
        self.assertEqual(facts.eks_cluster_security_group_id, "sg-cluster")
        self.assertEqual(facts.eks_control_plane_logging_state, "not_configured")
        self.assertEqual(facts.eks_enabled_cluster_log_types, [])
        self.assertEqual(facts.eks_encryption_config_state, "not_configured")
        self.assertEqual(facts.eks_secrets_encryption_state, "disabled")
        self.assertEqual(facts.eks_encryption_config, [])
        self.assertEqual(facts.eks_posture_uncertainties, [])
        self.assertEqual(
            _aws_findings([_cluster({"name": "public", "vpc_config": [{"endpoint_public_access": True}]})]), []
        )

    def test_restricted_private_cluster_normalizes_safer_posture_values(self) -> None:
        key_arn = "arn:aws:kms:us-east-1:111122223333:key/eks"
        normalized = normalize_eks_cluster(
            _cluster(
                {
                    "name": "restricted",
                    "arn": "arn:aws:eks:us-east-1:111122223333:cluster/restricted",
                    "role_arn": "arn:aws:iam::111122223333:role/eks-control-plane",
                    "vpc_config": [
                        {
                            "endpoint_public_access": False,
                            "endpoint_private_access": True,
                            "public_access_cidrs": ["198.51.100.10/32"],
                            "subnet_ids": ["subnet-private-a", "subnet-private-b"],
                            "security_group_ids": ["sg-clients"],
                            "cluster_security_group_id": "sg-cluster",
                        }
                    ],
                    "enabled_cluster_log_types": ["api", "audit", "authenticator"],
                    "encryption_config": [
                        {
                            "provider": [{"key_arn": key_arn}],
                            "resources": ["secrets"],
                        }
                    ],
                },
                name="restricted",
            )
        )
        facts = aws_facts(normalized)

        self.assertFalse(normalized.public_access_configured)
        self.assertEqual(facts.eks_endpoint_public_access_state, "disabled")
        self.assertEqual(facts.eks_endpoint_private_access_state, "enabled")
        self.assertEqual(facts.eks_public_access_cidrs, ["198.51.100.10/32"])
        self.assertEqual(facts.eks_control_plane_logging_state, "configured")
        self.assertEqual(facts.eks_enabled_cluster_log_types, ["api", "audit", "authenticator"])
        self.assertEqual(facts.eks_encryption_config_state, "configured")
        self.assertEqual(facts.eks_secrets_encryption_state, "enabled")
        self.assertEqual(facts.eks_encryption_key_arn, key_arn)
        self.assertEqual(facts.eks_encryption_resources, ["secrets"])
        self.assertEqual(
            facts.eks_encryption_config,
            [{"key_arn": key_arn, "resources": ["secrets"]}],
        )
        self.assertEqual(
            _aws_findings([_cluster({"name": "restricted", "vpc_config": [{"endpoint_public_access": False}]})]), []
        )

    def test_minimal_cluster_uses_explicit_unknown_and_not_configured_states(self) -> None:
        normalized = normalize_eks_cluster(_cluster({"name": "minimal"}, name="minimal"))
        facts = aws_facts(normalized)

        self.assertEqual(normalized.identifier, "minimal")
        self.assertFalse(normalized.public_access_configured)
        self.assertEqual(facts.eks_endpoint_public_access_state, "unknown")
        self.assertEqual(facts.eks_endpoint_private_access_state, "unknown")
        self.assertEqual(facts.eks_public_access_cidrs, [])
        self.assertEqual(facts.eks_public_access_cidrs_state, "unknown")
        self.assertEqual(facts.eks_subnet_ids, [])
        self.assertEqual(facts.eks_security_group_ids, [])
        self.assertIsNone(facts.eks_cluster_security_group_id)
        self.assertEqual(facts.eks_control_plane_logging_state, "not_configured")
        self.assertEqual(facts.eks_encryption_config_state, "not_configured")
        self.assertEqual(facts.eks_secrets_encryption_state, "disabled")
        self.assertEqual(facts.eks_access_config_state, "not_configured")
        self.assertIsNone(facts.eks_authentication_mode)
        self.assertEqual(facts.eks_posture_uncertainties, [])
        self.assertEqual(_aws_findings([_cluster({"name": "minimal"})]), [])

    def test_unresolved_values_are_preserved_as_unknown_uncertainty(self) -> None:
        normalized = normalize_eks_cluster(
            _cluster(
                {
                    "name": "unknown",
                    "vpc_config": [{}],
                    "encryption_config": [{"provider": [{}]}],
                    "access_config": [{}],
                },
                name="unknown",
                unknown_values={
                    "vpc_config": [
                        {
                            "endpoint_public_access": True,
                            "endpoint_private_access": True,
                            "public_access_cidrs": True,
                            "subnet_ids": True,
                            "security_group_ids": True,
                            "cluster_security_group_id": True,
                        }
                    ],
                    "enabled_cluster_log_types": True,
                    "encryption_config": [{"provider": [{"key_arn": True}], "resources": True}],
                    "access_config": [
                        {
                            "authentication_mode": True,
                            "bootstrap_cluster_creator_admin_permissions": True,
                        }
                    ],
                },
            )
        )
        facts = aws_facts(normalized)

        self.assertEqual(facts.eks_endpoint_public_access_state, "unknown")
        self.assertEqual(facts.eks_endpoint_private_access_state, "unknown")
        self.assertEqual(facts.eks_public_access_cidrs_state, "unknown")
        self.assertEqual(facts.eks_control_plane_logging_state, "unknown")
        self.assertEqual(facts.eks_encryption_config_state, "configured")
        self.assertEqual(facts.eks_secrets_encryption_state, "unknown")
        self.assertIsNone(facts.eks_authentication_mode)
        self.assertEqual(facts.eks_bootstrap_cluster_creator_admin_permissions_state, "unknown")
        self.assertEqual(
            facts.eks_posture_uncertainties,
            [
                "vpc_config.public_access_cidrs is unknown after planning",
                "vpc_config.subnet_ids is unknown after planning",
                "vpc_config.security_group_ids is unknown after planning",
                "enabled_cluster_log_types is unknown after planning",
                "encryption_config[0].provider.key_arn is unknown after planning",
                "encryption_config[0].resources is unknown after planning",
                "vpc_config.endpoint_public_access is unknown after planning",
                "vpc_config.endpoint_private_access is unknown after planning",
                "vpc_config.cluster_security_group_id is unknown after planning",
                "access_config.authentication_mode is unknown after planning",
                "access_config.bootstrap_cluster_creator_admin_permissions is unknown after planning",
            ],
        )

    def test_access_config_authentication_mode_is_captured(self) -> None:
        normalized = normalize_eks_cluster(
            _cluster(
                {
                    "name": "access",
                    "access_config": [
                        {
                            "authentication_mode": "API_AND_CONFIG_MAP",
                            "bootstrap_cluster_creator_admin_permissions": False,
                        }
                    ],
                },
                name="access",
            )
        )
        facts = aws_facts(normalized)

        self.assertEqual(facts.eks_access_config_state, "configured")
        self.assertEqual(facts.eks_authentication_mode, "API_AND_CONFIG_MAP")
        self.assertEqual(facts.eks_bootstrap_cluster_creator_admin_permissions_state, "disabled")
        self.assertEqual(
            facts.eks_access_config,
            {
                "authentication_mode": "API_AND_CONFIG_MAP",
                "bootstrap_cluster_creator_admin_permissions": False,
            },
        )

    def test_eks_addon_normalizes_core_addon_version_and_configuration(self) -> None:
        configuration_values = '{"env":{"ENABLE_PREFIX_DELEGATION":"true"},"resources":{"limits":{"cpu":"100m"}}}'
        normalized = normalize_eks_addon(
            _addon(
                {
                    "cluster_name": "app",
                    "addon_name": "vpc-cni",
                    "addon_version": "v1.18.1-eksbuild.1",
                    "configuration_values": configuration_values,
                    "preserve": True,
                    "service_account_role_arn": "arn:aws:iam::111122223333:role/eks-vpc-cni",
                }
            )
        )
        facts = aws_facts(normalized)

        self.assertEqual(normalized.identifier, "vpc-cni")
        self.assertEqual(normalized.attached_role_arns, ["arn:aws:iam::111122223333:role/eks-vpc-cni"])
        self.assertEqual(facts.resource_name, "vpc-cni")
        self.assertEqual(facts.eks_addon_name, "vpc-cni")
        self.assertEqual(facts.eks_addon_cluster_name, "app")
        self.assertEqual(facts.eks_addon_version, "v1.18.1-eksbuild.1")
        self.assertEqual(facts.eks_addon_configuration_values, configuration_values)
        self.assertEqual(facts.eks_addon_configuration_keys, ["env", "resources"])
        self.assertEqual(facts.eks_addon_preserve_state, "enabled")
        self.assertTrue(facts.eks_addon_preserve)
        self.assertEqual(facts.eks_addon_service_account_role_arn, "arn:aws:iam::111122223333:role/eks-vpc-cni")
        self.assertEqual(facts.eks_addon_target_class, "networking")
        self.assertEqual(facts.eks_posture_uncertainties, [])
        self.assertEqual(_aws_findings([_addon({"cluster_name": "app", "addon_name": "vpc-cni"})]), [])

    def test_eks_addon_preserves_unknown_values_without_inference(self) -> None:
        normalized = normalize_eks_addon(
            _addon(
                {"configuration_values": {}},
                name="unknown",
                unknown_values={
                    "addon_name": True,
                    "cluster_name": True,
                    "addon_version": True,
                    "configuration_values": True,
                    "preserve": True,
                    "service_account_role_arn": True,
                },
            )
        )
        facts = aws_facts(normalized)

        self.assertEqual(normalized.identifier, "aws_eks_addon.unknown")
        self.assertIsNone(facts.eks_addon_name)
        self.assertIsNone(facts.eks_addon_cluster_name)
        self.assertIsNone(facts.eks_addon_version)
        self.assertIsNone(facts.eks_addon_configuration_values)
        self.assertEqual(facts.eks_addon_configuration_keys, [])
        self.assertEqual(facts.eks_addon_preserve_state, "unknown")
        self.assertIsNone(facts.eks_addon_preserve)
        self.assertIsNone(facts.eks_addon_service_account_role_arn)
        self.assertIsNone(facts.eks_addon_target_class)
        self.assertEqual(
            facts.eks_posture_uncertainties,
            [
                "addon_name is unknown after planning",
                "cluster_name is unknown after planning",
                "addon_version is unknown after planning",
                "configuration_values is unknown after planning",
                "preserve is unknown after planning",
                "service_account_role_arn is unknown after planning",
            ],
        )

    def test_eks_addon_records_unrecognized_configuration_shape_as_uncertainty(self) -> None:
        normalized = normalize_eks_addon(
            _addon(
                {
                    "cluster_name": "app",
                    "addon_name": "coredns",
                    "configuration_values": "[1, 2, 3]",
                    "preserve": False,
                },
                name="coredns",
            )
        )
        facts = aws_facts(normalized)

        self.assertEqual(facts.eks_addon_name, "coredns")
        self.assertEqual(facts.eks_addon_target_class, "dns")
        self.assertEqual(facts.eks_addon_configuration_values, "[1, 2, 3]")
        self.assertEqual(facts.eks_addon_configuration_keys, [])
        self.assertEqual(facts.eks_addon_preserve_state, "disabled")
        self.assertFalse(facts.eks_addon_preserve)
        self.assertEqual(facts.eks_posture_uncertainties, ["configuration_values has an unrecognized JSON shape"])

    def test_aws_normalizer_supports_eks_cluster_and_addon_resource_types(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _cluster({"name": "cluster"}),
                _addon({"cluster_name": "cluster", "addon_name": "aws-ebs-csi-driver"}, name="ebs_csi"),
            ]
        )

        self.assertIn("aws_eks_cluster", SUPPORTED_AWS_TYPES)
        self.assertIn("aws_eks_addon", SUPPORTED_AWS_TYPES)
        self.assertEqual(inventory.unsupported_resources, [])
        self.assertEqual(
            [resource.address for resource in inventory.resources],
            ["aws_eks_cluster.cluster", "aws_eks_addon.ebs_csi"],
        )
        self.assertEqual(inventory.metadata["supported_resource_types"], sorted(SUPPORTED_AWS_TYPES))


if __name__ == "__main__":
    unittest.main()
