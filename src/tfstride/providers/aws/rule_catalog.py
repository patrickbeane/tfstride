from __future__ import annotations

from tfstride.analysis.rule_registry import RuleMetadata
from tfstride.models import StrideCategory

AWS_RULE_METADATA = (
    RuleMetadata(
        rule_id="aws-public-compute-broad-ingress",
        title="Internet-exposed compute service permits overly broad ingress",
        category=StrideCategory.SPOOFING,
        recommended_mitigation=(
            "Restrict ingress to expected client ports, remove direct administrative exposure, "
            "and place management access behind a controlled bastion, VPN, or SSM Session Manager."
        ),
        tags=("aws", "network", "compute", "internet"),
        severity_factors=("internet_exposure", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-database-permissive-ingress",
        title="Database is reachable from overly permissive sources",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Keep databases off public paths, allow ingress only from narrowly scoped application "
            "security groups, and enforce authentication plus encryption independently of network policy."
        ),
        tags=("aws", "network", "database"),
        severity_factors=("internet_exposure", "data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-rds-storage-encryption-disabled",
        title="Database storage encryption is disabled",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Enable RDS storage encryption with a managed KMS key, enforce encryption by default in "
            "database modules, and migrate plaintext instances to encrypted replacements where needed."
        ),
        tags=("aws", "database", "encryption"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-s3-public-access",
        title="Object storage is publicly accessible",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Remove public ACL or bucket policy access, enable an S3 public access block, "
            "and serve content through a controlled CDN or origin access pattern when public distribution is required."
        ),
        tags=("aws", "storage", "public-access"),
        severity_factors=("internet_exposure", "privilege_breadth", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-sensitive-resource-policy-external-access",
        title="Sensitive resource policy allows broad or cross-account access",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Limit resource policies to exact service principals or workload roles, avoid wildcard "
            "foreign-account, and account-root principals where more specific identities are possible, "
            "and require source-account or source-ARN constraints where supported."
        ),
        tags=("aws", "resource-policy", "data"),
        severity_factors=(
            "internet_exposure",
            "privilege_breadth",
            "data_sensitivity",
            "lateral_movement",
            "blast_radius",
        ),
    ),
    RuleMetadata(
        rule_id="aws-service-resource-policy-external-access",
        title="Service resource policy allows broad or cross-account access",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Limit resource policies to exact service principals or workload roles, avoid wildcard "
            "foreign-account, and account-root principals where more specific identities are possible, "
            "and require source-account or source-ARN constraints where supported."
        ),
        tags=("aws", "resource-policy", "service"),
        severity_factors=("internet_exposure", "privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-iam-wildcard-permissions",
        title="IAM policy grants wildcard privileges",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Replace wildcard actions and resources with narrowly scoped permissions tied to the exact "
            "services, APIs, and ARNs required by the workload."
        ),
        tags=("aws", "iam", "permissions"),
        severity_factors=("privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-workload-role-sensitive-permissions",
        title="Workload role carries sensitive permissions",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Split high-privilege actions into separate roles, scope permissions to named resources, "
            "and remove role-passing or cross-role permissions from general application identities."
        ),
        tags=("aws", "iam", "workload"),
        severity_factors=("internet_exposure", "privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-missing-tier-segmentation",
        title="Private data tier directly trusts the public application tier",
        category=StrideCategory.TAMPERING,
        recommended_mitigation=(
            "Introduce tighter tier segmentation with dedicated security groups, narrow ingress to "
            "specific services and ports, and keep the data tier reachable only through controlled application paths."
        ),
        tags=("aws", "network", "segmentation"),
        severity_factors=("internet_exposure", "data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-private-data-transitive-exposure",
        title="Sensitive data tier is transitively reachable from an internet-exposed path",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Keep internet-adjacent entry points from chaining into workloads that retain database or secret access, "
            "narrow edge-to-workload and workload-to-workload trust, and isolate sensitive data access behind more "
            "deliberate service boundaries."
        ),
        tags=("aws", "network", "segmentation", "transitive-path"),
        severity_factors=("data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-control-plane-sensitive-workload-chain",
        title="Broad or cross-account control-plane path can influence a sensitive workload",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Keep external CI or deployment principals away from runtime workload roles, separate deployment "
            "and execution identities, require narrowing conditions on cross-account trust, and avoid giving "
            "data-bearing workloads broad secret or database access where a smaller brokered path would work."
        ),
        tags=("aws", "iam", "control-plane", "transitive-path"),
        severity_factors=("privilege_breadth", "data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-role-trust-expansion",
        title="Role trust relationship expands blast radius",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Limit trust policies to the exact service principals or roles required, prefer role ARNs "
            "over account root where possible, and add conditions such as `ExternalId`, source ARN, "
            "SAML audience, or OIDC audience and subject checks."
        ),
        tags=("aws", "iam", "trust"),
        severity_factors=("privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-role-trust-missing-narrowing",
        title="Cross-account or broad role trust lacks narrowing conditions",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Keep the trusted principal as specific as possible and add supported assume-role "
            "conditions such as `ExternalId`, `SourceArn`, `SourceAccount`, `SAML:aud`, or "
            "provider-specific OIDC `aud` and `sub` checks when crossing accounts or trusting "
            "broad or federated principals."
        ),
        tags=("aws", "iam", "trust", "cross-account"),
        severity_factors=("privilege_breadth", "lateral_movement", "blast_radius"),
    ),
)
