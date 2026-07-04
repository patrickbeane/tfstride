from __future__ import annotations

from collections.abc import Mapping

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.rule_definitions import RuleContribution, RuleDetector, build_rule_contribution
from tfstride.analysis.rule_registry import RuleRegistry, default_rule_registry
from tfstride.providers.aws.eks_rules import AwsEksRuleDetectors
from tfstride.providers.aws.iam_rules import AwsIamRuleDetectors
from tfstride.providers.aws.kms_rules import AwsKmsRuleDetectors
from tfstride.providers.aws.lambda_rules import AwsLambdaRuleDetectors
from tfstride.providers.aws.load_balancer_rules import AwsLoadBalancerRuleDetectors
from tfstride.providers.aws.network_data_rules import AwsNetworkDataRuleDetectors
from tfstride.providers.aws.path_chain_rules import AwsPathChainRuleDetectors
from tfstride.providers.aws.policy_trust_rules import AwsPolicyTrustRuleDetectors
from tfstride.providers.aws.posture_rules import AwsPostureRuleDetectors
from tfstride.providers.aws.rds_rules import AwsRdsPostureRuleDetectors
from tfstride.providers.aws.secrets_rules import AwsSecretsManagerPostureRuleDetectors
from tfstride.providers.aws.sensitive_endpoint_rules import AwsSensitiveEndpointRuleDetectors
from tfstride.providers.aws.storage_rules import AwsS3PostureRuleDetectors

AWS_RULE_GROUP_IDS: tuple[tuple[str, ...], ...] = (
    (
        "aws-public-compute-broad-ingress",
        "aws-lambda-public-invocation",
        "aws-load-balancer-http-public-listener",
        "aws-load-balancer-listener-tls-certificate-missing",
        "aws-load-balancer-listener-ssl-policy-weak-or-unknown",
        "aws-rds-storage-encryption-disabled",
        "aws-rds-public-endpoint-enabled",
        "aws-rds-backup-retention-insufficient",
        "aws-rds-deletion-protection-disabled",
        "aws-rds-customer-managed-kms-key-missing",
        "aws-s3-public-access",
        "aws-s3-customer-managed-encryption-missing",
        "aws-s3-versioning-disabled",
        "aws-secretsmanager-customer-managed-kms-key-missing",
        "aws-secretsmanager-recovery-window-too-short",
        "aws-secretsmanager-rotation-not-configured-or-too-long",
        "aws-kms-key-rotation-disabled-or-unknown",
        "aws-kms-key-deletion-window-too-short",
        "aws-workload-secretsmanager-vpc-endpoint-missing",
        "aws-workload-kms-vpc-endpoint-missing",
        "aws-workload-s3-vpc-endpoint-missing",
        "aws-vpc-endpoint-policy-broad-access",
        "aws-eks-api-endpoint-public-unrestricted",
        "aws-eks-private-endpoint-not-enabled",
        "aws-eks-secrets-encryption-not-configured",
        "aws-eks-control-plane-logging-incomplete",
        "aws-eks-authentication-mode-weak-or-unknown",
        "aws-eks-vpc-cni-network-policy-not-enabled",
    ),
    (
        "aws-database-permissive-ingress",
        "aws-missing-tier-segmentation",
    ),
    (
        "aws-sensitive-resource-policy-external-access",
        "aws-service-resource-policy-external-access",
    ),
    (
        "aws-iam-wildcard-permissions",
        "aws-workload-role-sensitive-permissions",
    ),
    (
        "aws-private-data-transitive-exposure",
        "aws-control-plane-sensitive-workload-chain",
    ),
    (
        "aws-role-trust-expansion",
        "aws-role-trust-missing-narrowing",
    ),
)


def build_aws_rule_contribution(
    finding_factory: FindingFactory,
    metadata_registry: RuleRegistry | None = None,
) -> RuleContribution:
    posture_detectors = AwsPostureRuleDetectors(finding_factory)
    network_data_detectors = AwsNetworkDataRuleDetectors(finding_factory)
    path_chain_detectors = AwsPathChainRuleDetectors(finding_factory)
    iam_detectors = AwsIamRuleDetectors(finding_factory)
    policy_trust_detectors = AwsPolicyTrustRuleDetectors(finding_factory)
    rds_posture_detectors = AwsRdsPostureRuleDetectors(finding_factory)
    s3_posture_detectors = AwsS3PostureRuleDetectors(finding_factory)
    secrets_manager_detectors = AwsSecretsManagerPostureRuleDetectors(finding_factory)
    kms_detectors = AwsKmsRuleDetectors(finding_factory)
    eks_detectors = AwsEksRuleDetectors(finding_factory)
    lambda_detectors = AwsLambdaRuleDetectors(finding_factory)
    load_balancer_detectors = AwsLoadBalancerRuleDetectors(finding_factory)
    sensitive_endpoint_detectors = AwsSensitiveEndpointRuleDetectors(finding_factory)
    detectors_by_rule_id: Mapping[str, RuleDetector] = {
        "aws-public-compute-broad-ingress": posture_detectors.detect_public_compute_exposure,
        "aws-lambda-public-invocation": lambda_detectors.detect_public_invocation,
        "aws-load-balancer-http-public-listener": load_balancer_detectors.detect_public_http_listener,
        "aws-load-balancer-listener-tls-certificate-missing": (load_balancer_detectors.detect_tls_certificate_missing),
        "aws-load-balancer-listener-ssl-policy-weak-or-unknown": (
            load_balancer_detectors.detect_ssl_policy_weak_or_unknown
        ),
        "aws-rds-storage-encryption-disabled": posture_detectors.detect_unencrypted_databases,
        "aws-rds-public-endpoint-enabled": rds_posture_detectors.detect_public_endpoint_enabled,
        "aws-rds-backup-retention-insufficient": rds_posture_detectors.detect_backup_retention_insufficient,
        "aws-rds-deletion-protection-disabled": rds_posture_detectors.detect_deletion_protection_disabled,
        "aws-rds-customer-managed-kms-key-missing": (rds_posture_detectors.detect_customer_managed_kms_key_missing),
        "aws-s3-public-access": posture_detectors.detect_public_object_storage,
        "aws-s3-customer-managed-encryption-missing": (s3_posture_detectors.detect_customer_managed_encryption_missing),
        "aws-s3-versioning-disabled": s3_posture_detectors.detect_versioning_disabled_or_unknown,
        "aws-secretsmanager-customer-managed-kms-key-missing": (
            secrets_manager_detectors.detect_customer_managed_kms_key_missing
        ),
        "aws-secretsmanager-recovery-window-too-short": (secrets_manager_detectors.detect_recovery_window_too_short),
        "aws-secretsmanager-rotation-not-configured-or-too-long": (
            secrets_manager_detectors.detect_rotation_not_configured_or_too_long
        ),
        "aws-kms-key-rotation-disabled-or-unknown": kms_detectors.detect_key_rotation_disabled_or_unknown,
        "aws-kms-key-deletion-window-too-short": kms_detectors.detect_deletion_window_too_short,
        "aws-workload-secretsmanager-vpc-endpoint-missing": (
            sensitive_endpoint_detectors.detect_missing_secretsmanager_endpoint
        ),
        "aws-workload-kms-vpc-endpoint-missing": sensitive_endpoint_detectors.detect_missing_kms_endpoint,
        "aws-workload-s3-vpc-endpoint-missing": sensitive_endpoint_detectors.detect_missing_s3_endpoint,
        "aws-vpc-endpoint-policy-broad-access": sensitive_endpoint_detectors.detect_broad_vpc_endpoint_policy,
        "aws-eks-api-endpoint-public-unrestricted": eks_detectors.detect_public_api_endpoint_unrestricted,
        "aws-eks-private-endpoint-not-enabled": eks_detectors.detect_private_endpoint_not_enabled,
        "aws-eks-secrets-encryption-not-configured": eks_detectors.detect_secrets_encryption_not_configured,
        "aws-eks-control-plane-logging-incomplete": eks_detectors.detect_control_plane_logging_incomplete,
        "aws-eks-authentication-mode-weak-or-unknown": eks_detectors.detect_authentication_mode_weak_or_unknown,
        "aws-eks-vpc-cni-network-policy-not-enabled": eks_detectors.detect_vpc_cni_network_policy_not_enabled,
        "aws-database-permissive-ingress": network_data_detectors.detect_database_exposure,
        "aws-missing-tier-segmentation": network_data_detectors.detect_missing_segmentation,
        "aws-sensitive-resource-policy-external-access": (
            policy_trust_detectors.detect_sensitive_resource_policy_exposure
        ),
        "aws-service-resource-policy-external-access": policy_trust_detectors.detect_service_resource_policy_exposure,
        "aws-iam-wildcard-permissions": iam_detectors.detect_wildcard_permissions,
        "aws-workload-role-sensitive-permissions": iam_detectors.detect_workload_role_sensitive_permissions,
        "aws-private-data-transitive-exposure": path_chain_detectors.detect_transitive_private_data_exposure,
        "aws-control-plane-sensitive-workload-chain": (
            path_chain_detectors.detect_control_plane_sensitive_workload_chain
        ),
        "aws-role-trust-expansion": policy_trust_detectors.detect_trust_expansion,
        "aws-role-trust-missing-narrowing": policy_trust_detectors.detect_unconstrained_trust,
    }
    resolved_metadata_registry = metadata_registry if metadata_registry is not None else default_rule_registry()
    return build_rule_contribution(
        (
            tuple((rule_id, detectors_by_rule_id[rule_id]) for rule_id in rule_group)
            for rule_group in AWS_RULE_GROUP_IDS
        ),
        resolved_metadata_registry,
    )
