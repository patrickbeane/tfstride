from __future__ import annotations

from cloud_threat_modeler.models import (
    BoundaryType,
    Finding,
    IAMPolicyStatement,
    NormalizedResource,
    ResourceInventory,
    SecurityGroupRule,
    Severity,
    StrideCategory,
    TrustBoundary,
)


SENSITIVE_ACTION_PREFIXES = {
    "kms:Decrypt",
    "secretsmanager:GetSecretValue",
    "ssm:GetParameter",
    "ssm:GetParameters",
    "iam:PassRole",
    "sts:AssumeRole",
    "s3:*",
    "*",
}


class StrideRuleEngine:
    def evaluate(self, inventory: ResourceInventory, boundaries: list[TrustBoundary]) -> list[Finding]:
        findings: list[Finding] = []
        boundary_index = {(boundary.boundary_type, boundary.source, boundary.target): boundary for boundary in boundaries}

        findings.extend(self._detect_public_compute_exposure(inventory, boundary_index))
        findings.extend(self._detect_database_exposure(inventory, boundary_index))
        findings.extend(self._detect_public_object_storage(inventory, boundary_index))
        findings.extend(self._detect_iam_wildcards(inventory))
        findings.extend(self._detect_workload_role_risk(inventory, boundary_index))
        findings.extend(self._detect_missing_segmentation(inventory, boundary_index))
        findings.extend(self._detect_trust_expansion(inventory, boundary_index))

        severity_order = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
        findings.sort(key=lambda finding: (severity_order[finding.severity], finding.title))
        return findings

    def _detect_public_compute_exposure(
        self,
        inventory: ResourceInventory,
        boundary_index: dict[tuple[BoundaryType, str, str], TrustBoundary],
    ) -> list[Finding]:
        findings: list[Finding] = []
        for resource in inventory.by_type("aws_instance"):
            if not resource.public_exposure:
                continue
            attached_security_groups = _attached_security_groups(resource, inventory)
            risky_rules = [
                rule
                for security_group in attached_security_groups
                for rule in security_group.network_rules
                if rule.direction == "ingress"
                and rule.allows_internet()
                and (rule.is_administrative_access() or rule.is_all_ports())
            ]
            if not risky_rules:
                continue
            severity = _score_severity(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=1,
            )
            boundary = boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", resource.address))
            findings.append(
                Finding(
                    title="Internet-exposed compute service permits overly broad ingress",
                    category=StrideCategory.SPOOFING,
                    severity=severity,
                    affected_resources=[resource.address, *[sg.address for sg in attached_security_groups]],
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rule_id="aws-public-compute-broad-ingress",
                    rationale=(
                        f"{resource.display_name} is reachable from the internet and at least one attached "
                        "security group allows administrative access or all ports from 0.0.0.0/0. "
                        "That broad ingress raises the chance of unauthenticated probing and credential attacks."
                    ),
                    recommended_mitigation=(
                        "Restrict ingress to expected client ports, remove direct administrative exposure, "
                        "and place management access behind a controlled bastion, VPN, or SSM Session Manager."
                    ),
                )
            )
        return findings

    def _detect_database_exposure(
        self,
        inventory: ResourceInventory,
        boundary_index: dict[tuple[BoundaryType, str, str], TrustBoundary],
    ) -> list[Finding]:
        findings: list[Finding] = []
        public_workloads = {
            security_group_id
            for resource in inventory.resources
            if resource.public_exposure
            for security_group_id in resource.security_group_ids
        }
        for database in inventory.by_type("aws_db_instance"):
            attached_security_groups = _attached_security_groups(database, inventory)
            internet_rules = [
                rule
                for security_group in attached_security_groups
                for rule in security_group.network_rules
                if rule.direction == "ingress" and rule.allows_internet()
            ]
            public_tier_rules = [
                rule
                for security_group in attached_security_groups
                for rule in security_group.network_rules
                if rule.direction == "ingress"
                and set(rule.referenced_security_group_ids).intersection(public_workloads)
            ]
            if not internet_rules and not public_tier_rules and not database.public_exposure:
                continue
            boundary = None
            if internet_rules or database.public_exposure:
                boundary = boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", database.address))
            elif database.vpc_id:
                public_private_boundary = next(
                    (
                        item
                        for item in boundary_index.values()
                        if item.boundary_type == BoundaryType.PUBLIC_TO_PRIVATE
                    ),
                    None,
                )
                boundary = public_private_boundary
            severity = _score_severity(
                internet_exposure=bool(internet_rules or database.public_exposure),
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=1,
            )
            findings.append(
                Finding(
                    title="Database is reachable from overly permissive sources",
                    category=StrideCategory.INFORMATION_DISCLOSURE,
                    severity=severity,
                    affected_resources=[database.address, *[sg.address for sg in attached_security_groups]],
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rule_id="aws-database-permissive-ingress",
                    rationale=(
                        f"{database.display_name} is a sensitive data store, but its network controls allow either "
                        "direct internet ingress or access from internet-facing application security groups. "
                        "That weakens the expected separation between the workload tier and the data tier."
                    ),
                    recommended_mitigation=(
                        "Keep databases off public paths, allow ingress only from narrowly scoped application "
                        "security groups, and enforce authentication plus encryption independently of network policy."
                    ),
                )
            )
        return findings

    def _detect_public_object_storage(
        self,
        inventory: ResourceInventory,
        boundary_index: dict[tuple[BoundaryType, str, str], TrustBoundary],
    ) -> list[Finding]:
        findings: list[Finding] = []
        for bucket in inventory.by_type("aws_s3_bucket"):
            if not bucket.public_exposure:
                continue
            boundary = boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", bucket.address))
            severity = _score_severity(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                Finding(
                    title="Object storage is publicly accessible",
                    category=StrideCategory.INFORMATION_DISCLOSURE,
                    severity=severity,
                    affected_resources=[bucket.address],
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rule_id="aws-s3-public-access",
                    rationale=(
                        f"{bucket.display_name} appears to be public through ACLs or bucket policy. "
                        "Public object access is a common source of unintended data disclosure."
                    ),
                    recommended_mitigation=(
                        "Use private bucket ACLs, block public access, and grant object access through scoped IAM "
                        "roles or signed requests instead of anonymous principals."
                    ),
                )
            )
        return findings

    def _detect_iam_wildcards(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for policy_resource in inventory.by_type("aws_iam_policy", "aws_iam_role"):
            wildcard_statements = [
                statement
                for statement in policy_resource.policy_statements
                if statement.effect == "Allow"
                and (statement.has_wildcard_action() or statement.has_wildcard_resource())
            ]
            if not wildcard_statements:
                continue
            severity = _score_severity(
                internet_exposure=False,
                privilege_breadth=2 if any(statement.has_wildcard_action() for statement in wildcard_statements) else 1,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=2,
            )
            findings.append(
                Finding(
                    title="IAM policy grants wildcard privileges",
                    category=StrideCategory.ELEVATION_OF_PRIVILEGE,
                    severity=severity,
                    affected_resources=[policy_resource.address],
                    trust_boundary_id=None,
                    rule_id="aws-iam-wildcard-permissions",
                    rationale=(
                        f"{policy_resource.display_name} contains allow statements with wildcard actions or "
                        "resources. That makes the resulting access difficult to reason about and expands blast radius."
                    ),
                    recommended_mitigation=(
                        "Replace wildcard actions and resources with narrowly scoped permissions tied to the exact "
                        "services, APIs, and ARNs required by the workload."
                    ),
                )
            )
        return findings

    def _detect_workload_role_risk(
        self,
        inventory: ResourceInventory,
        boundary_index: dict[tuple[BoundaryType, str, str], TrustBoundary],
    ) -> list[Finding]:
        findings: list[Finding] = []
        role_index = _role_index(inventory)
        for workload in inventory.by_type("aws_instance", "aws_lambda_function"):
            role = _resolve_role(workload, role_index)
            if role is None:
                continue
            sensitive_actions = _sensitive_actions(role.policy_statements)
            if not sensitive_actions:
                continue
            boundary = boundary_index.get((BoundaryType.CONTROL_TO_WORKLOAD, role.address, workload.address))
            severity = _score_severity(
                internet_exposure=workload.public_exposure,
                privilege_breadth=2 if "*" in sensitive_actions or "s3:*" in sensitive_actions else 1,
                data_sensitivity=1,
                lateral_movement=1,
                blast_radius=2,
            )
            findings.append(
                Finding(
                    title="Workload role carries sensitive permissions",
                    category=StrideCategory.ELEVATION_OF_PRIVILEGE,
                    severity=severity,
                    affected_resources=[workload.address, role.address],
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rule_id="aws-workload-role-sensitive-permissions",
                    rationale=(
                        f"{workload.display_name} inherits sensitive privileges from {role.display_name}, including "
                        f"{', '.join(sorted(sensitive_actions))}. If the workload is compromised, those credentials "
                        "can be reused for privilege escalation, data access, or role chaining."
                    ),
                    recommended_mitigation=(
                        "Split high-privilege actions into separate roles, scope permissions to named resources, "
                        "and remove role-passing or cross-role permissions from general application identities."
                    ),
                )
            )
        return findings

    def _detect_missing_segmentation(
        self,
        inventory: ResourceInventory,
        boundary_index: dict[tuple[BoundaryType, str, str], TrustBoundary],
    ) -> list[Finding]:
        findings: list[Finding] = []
        public_security_group_map = {
            security_group_id: resource
            for resource in inventory.resources
            if resource.public_exposure
            for security_group_id in resource.security_group_ids
        }
        public_private_boundary = next(
            (boundary for boundary in boundary_index.values() if boundary.boundary_type == BoundaryType.PUBLIC_TO_PRIVATE),
            None,
        )
        for database in inventory.by_type("aws_db_instance"):
            for security_group in _attached_security_groups(database, inventory):
                risky_rules = [
                    rule
                    for rule in security_group.network_rules
                    if rule.direction == "ingress"
                    and set(rule.referenced_security_group_ids).intersection(public_security_group_map)
                ]
                if not risky_rules:
                    continue
                exposed_workloads = sorted(
                    {
                        public_security_group_map[security_group_id].address
                        for rule in risky_rules
                        for security_group_id in rule.referenced_security_group_ids
                        if security_group_id in public_security_group_map
                    }
                )
                severity = _score_severity(
                    internet_exposure=True,
                    privilege_breadth=0,
                    data_sensitivity=2,
                    lateral_movement=2,
                    blast_radius=1,
                )
                findings.append(
                    Finding(
                        title="Private data tier directly trusts the public application tier",
                        category=StrideCategory.TAMPERING,
                        severity=severity,
                        affected_resources=[database.address, *exposed_workloads, security_group.address],
                        trust_boundary_id=public_private_boundary.identifier if public_private_boundary else None,
                        rule_id="aws-missing-tier-segmentation",
                        rationale=(
                            f"{database.display_name} accepts traffic from security groups attached to internet-facing "
                            "workloads. A compromise of the public tier can therefore move laterally into the private data tier."
                        ),
                        recommended_mitigation=(
                            "Introduce tighter tier segmentation with dedicated security groups, narrow ingress to "
                            "specific services and ports, and keep the data tier reachable only through controlled application paths."
                        ),
                    )
                )
        return findings

    def _detect_trust_expansion(
        self,
        inventory: ResourceInventory,
        boundary_index: dict[tuple[BoundaryType, str, str], TrustBoundary],
    ) -> list[Finding]:
        findings: list[Finding] = []
        primary_account_id = inventory.metadata.get("primary_account_id")
        for role in inventory.by_type("aws_iam_role"):
            for principal in role.metadata.get("trust_principals", []):
                if principal.endswith(".amazonaws.com"):
                    continue
                if principal == "*":
                    severity = Severity.HIGH
                else:
                    account_id = _parse_account_id(principal)
                    severity = _score_severity(
                        internet_exposure=False,
                        privilege_breadth=1,
                        data_sensitivity=0,
                        lateral_movement=2,
                        blast_radius=2 if account_id and account_id != primary_account_id else 1,
                    )
                boundary = boundary_index.get((BoundaryType.CROSS_ACCOUNT_OR_ROLE, principal, role.address))
                findings.append(
                    Finding(
                        title="Role trust relationship expands blast radius",
                        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
                        severity=severity,
                        affected_resources=[role.address],
                        trust_boundary_id=boundary.identifier if boundary else None,
                        rule_id="aws-role-trust-expansion",
                        rationale=(
                            f"{role.display_name} can be assumed by {principal}. Broad or foreign-account trust "
                            "relationships increase the chance that compromise in one identity domain spills into another."
                        ),
                        recommended_mitigation=(
                            "Limit trust policies to the exact service principals or roles required, prefer role ARNs "
                            "over account root where possible, and add conditions such as `ExternalId` or source ARN checks."
                        ),
                    )
                )
        return findings


def _attached_security_groups(resource: NormalizedResource, inventory: ResourceInventory) -> list[NormalizedResource]:
    security_groups = []
    for security_group_id in resource.security_group_ids:
        security_group = inventory.get_by_identifier(security_group_id)
        if security_group and security_group.resource_type == "aws_security_group":
            security_groups.append(security_group)
    return security_groups


def _role_index(inventory: ResourceInventory) -> dict[str, NormalizedResource]:
    index: dict[str, NormalizedResource] = {}
    for role in inventory.by_type("aws_iam_role"):
        if role.arn:
            index[role.arn] = role
        index[role.address] = role
        if role.identifier:
            index[role.identifier] = role
    return index


def _resolve_role(
    workload: NormalizedResource,
    role_index: dict[str, NormalizedResource],
) -> NormalizedResource | None:
    for role_arn in workload.attached_role_arns:
        role = role_index.get(role_arn)
        if role:
            return role
    return None


def _sensitive_actions(statements: list[IAMPolicyStatement]) -> set[str]:
    sensitive: set[str] = set()
    for statement in statements:
        if statement.effect != "Allow":
            continue
        for action in statement.actions:
            if action in SENSITIVE_ACTION_PREFIXES:
                sensitive.add(action)
                continue
            if action.startswith("ssm:GetParameter"):
                sensitive.add("ssm:GetParameter*")
    return sensitive


def _parse_account_id(principal: str) -> str | None:
    if not principal.startswith("arn:"):
        return None
    parts = principal.split(":")
    if len(parts) < 5:
        return None
    return parts[4] or None


def _score_severity(
    *,
    internet_exposure: bool,
    privilege_breadth: int,
    data_sensitivity: int,
    lateral_movement: int,
    blast_radius: int,
) -> Severity:
    score = 0
    score += 2 if internet_exposure else 0
    score += privilege_breadth
    score += data_sensitivity
    score += lateral_movement
    score += blast_radius
    if score >= 6:
        return Severity.HIGH
    if score >= 3:
        return Severity.MEDIUM
    return Severity.LOW
