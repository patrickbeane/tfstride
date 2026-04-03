from __future__ import annotations

from cloud_threat_modeler.models import (
    BoundaryType,
    EvidenceItem,
    Finding,
    IAMPolicyStatement,
    NormalizedResource,
    ResourceInventory,
    SecurityGroupRule,
    Severity,
    SeverityReasoning,
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
        findings.extend(self._detect_unencrypted_databases(inventory))
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
                (security_group, rule)
                for security_group in attached_security_groups
                for rule in security_group.network_rules
                if rule.direction == "ingress"
                and rule.allows_internet()
                and (rule.is_administrative_access() or rule.is_all_ports())
            ]
            if not risky_rules:
                continue
            severity_reasoning = _build_severity_reasoning(
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
                    severity=severity_reasoning.severity,
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
                    evidence=_collect_evidence(
                        _evidence_item(
                            "security_group_rules",
                            [_describe_security_group_rule(security_group, rule) for security_group, rule in risky_rules],
                        ),
                        _evidence_item("public_exposure_reasons", resource.metadata.get("public_exposure_reasons", [])),
                        _evidence_item("subnet_posture", _subnet_posture(resource, inventory)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def _detect_database_exposure(
        self,
        inventory: ResourceInventory,
        boundary_index: dict[tuple[BoundaryType, str, str], TrustBoundary],
    ) -> list[Finding]:
        findings: list[Finding] = []
        # Treat security groups attached to internet-reachable workloads as the "public tier"
        # so database rules can reason about indirect exposure, not just raw 0.0.0.0/0 ingress.
        public_workloads_by_security_group: dict[str, list[NormalizedResource]] = {}
        for resource in inventory.resources:
            if not resource.public_exposure:
                continue
            for security_group_id in resource.security_group_ids:
                public_workloads_by_security_group.setdefault(security_group_id, []).append(resource)
        for database in inventory.by_type("aws_db_instance"):
            attached_security_groups = _attached_security_groups(database, inventory)
            internet_rules = [
                (security_group, rule)
                for security_group in attached_security_groups
                for rule in security_group.network_rules
                if rule.direction == "ingress" and rule.allows_internet()
            ]
            public_tier_rules: list[tuple[NormalizedResource, SecurityGroupRule, list[NormalizedResource]]] = []
            for security_group in attached_security_groups:
                for rule in security_group.network_rules:
                    if rule.direction != "ingress":
                        continue
                    matched_workloads = sorted(
                        {
                            workload.address: workload
                            for security_group_id in rule.referenced_security_group_ids
                            for workload in public_workloads_by_security_group.get(security_group_id, [])
                        }.values(),
                        key=lambda workload: workload.address,
                    )
                    if matched_workloads:
                        public_tier_rules.append((security_group, rule, matched_workloads))

            direct_internet_reachable = bool(
                database.metadata.get("direct_internet_reachable") and (internet_rules or not attached_security_groups)
            )
            if not internet_rules and not public_tier_rules and not direct_internet_reachable:
                continue
            boundary = None
            if direct_internet_reachable:
                boundary = boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", database.address))
            elif public_tier_rules:
                first_public_workload = sorted(
                    {
                        workload.address
                        for _, _, workloads in public_tier_rules
                        for workload in workloads
                    }
                )[0]
                boundary = boundary_index.get((BoundaryType.WORKLOAD_TO_DATA_STORE, first_public_workload, database.address))
            if boundary is None and database.vpc_id:
                public_private_boundary = next(
                    (
                        item
                        for item in boundary_index.values()
                        if item.boundary_type == BoundaryType.PUBLIC_TO_PRIVATE
                    ),
                    None,
                )
                boundary = public_private_boundary
            severity_reasoning = _build_severity_reasoning(
                internet_exposure=bool(internet_rules or public_tier_rules or direct_internet_reachable),
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=1,
            )
            path_signals: list[str] = []
            if direct_internet_reachable:
                path_signals.append("database is directly internet reachable")
            elif internet_rules:
                path_signals.append(
                    "database is not marked directly internet reachable, but its security groups allow internet-origin ingress"
                )
            if public_tier_rules:
                path_signals.append("database trusts security groups attached to internet-exposed workloads")
            findings.append(
                Finding(
                    title="Database is reachable from overly permissive sources",
                    category=StrideCategory.INFORMATION_DISCLOSURE,
                    severity=severity_reasoning.severity,
                    affected_resources=[database.address, *[sg.address for sg in attached_security_groups]],
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rule_id="aws-database-permissive-ingress",
                    rationale=(
                        f"{database.display_name} is a sensitive data store, but "
                        f"{_join_clauses(path_signals)}. "
                        "That weakens the expected separation between the workload tier and the data tier."
                    ),
                    recommended_mitigation=(
                        "Keep databases off public paths, allow ingress only from narrowly scoped application "
                        "security groups, and enforce authentication plus encryption independently of network policy."
                    ),
                    evidence=_collect_evidence(
                        _evidence_item(
                            "security_group_rules",
                            [
                                _describe_security_group_rule(security_group, rule)
                                for security_group, rule in internet_rules
                            ]
                            + [
                                _describe_security_group_rule(security_group, rule)
                                for security_group, rule, _ in public_tier_rules
                            ],
                        ),
                        _evidence_item(
                            "network_path",
                            path_signals
                            + [
                                f"{security_group.address} allows {', '.join(rule.referenced_security_group_ids)} attached to {', '.join(workload.address for workload in workloads)}"
                                for security_group, rule, workloads in public_tier_rules
                            ],
                        ),
                        _evidence_item("public_exposure_reasons", database.metadata.get("public_exposure_reasons", [])),
                        _evidence_item(
                            "subnet_posture",
                            [
                                posture
                                for _, _, workloads in public_tier_rules
                                for workload in workloads
                                for posture in _subnet_posture(workload, inventory)
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def _detect_unencrypted_databases(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for database in inventory.by_type("aws_db_instance"):
            if bool(database.metadata.get("storage_encrypted", False)):
                continue
            severity_reasoning = _build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                Finding(
                    title="Database storage encryption is disabled",
                    category=StrideCategory.INFORMATION_DISCLOSURE,
                    severity=severity_reasoning.severity,
                    affected_resources=[database.address],
                    trust_boundary_id=None,
                    rule_id="aws-rds-storage-encryption-disabled",
                    rationale=(
                        f"{database.display_name} stores sensitive data, but `storage_encrypted` is disabled. "
                        "That weakens data-at-rest protections for underlying storage, snapshots, and backup handling."
                    ),
                    recommended_mitigation=(
                        "Enable RDS storage encryption with a managed KMS key, enforce encryption by default in "
                        "database modules, and migrate plaintext instances to encrypted replacements where needed."
                    ),
                    evidence=_collect_evidence(
                        _evidence_item(
                            "encryption_posture",
                            [
                                "storage_encrypted is false",
                                f"engine is {database.metadata.get('engine', 'unknown')}",
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
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
            severity_reasoning = _build_severity_reasoning(
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
                    severity=severity_reasoning.severity,
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
                    evidence=_collect_evidence(
                        _evidence_item("public_exposure_reasons", bucket.metadata.get("public_exposure_reasons", [])),
                    ),
                    severity_reasoning=severity_reasoning,
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
            wildcard_actions = sorted(
                {
                    action
                    for statement in wildcard_statements
                    for action in statement.actions
                    if action == "*" or action.endswith(":*")
                }
            )
            wildcard_resources = sorted(
                {
                    resource
                    for statement in wildcard_statements
                    for resource in statement.resources
                    if resource == "*"
                }
            )
            severity_reasoning = _build_severity_reasoning(
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
                    severity=severity_reasoning.severity,
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
                    evidence=_collect_evidence(
                        _evidence_item("iam_actions", wildcard_actions),
                        _evidence_item("iam_resources", wildcard_resources),
                        _evidence_item(
                            "policy_statements",
                            [_describe_policy_statement(statement) for statement in wildcard_statements],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
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
            severity_reasoning = _build_severity_reasoning(
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
                    severity=severity_reasoning.severity,
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
                    evidence=_collect_evidence(
                        _evidence_item("iam_actions", sorted(sensitive_actions)),
                        _evidence_item(
                            "policy_statements",
                            [
                                _describe_policy_statement(statement)
                                for statement in role.policy_statements
                                if statement.effect == "Allow"
                                and _statement_matches_sensitive_actions(statement, sensitive_actions)
                            ],
                        ),
                        _evidence_item("public_exposure_reasons", workload.metadata.get("public_exposure_reasons", [])),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def _detect_missing_segmentation(
        self,
        inventory: ResourceInventory,
        boundary_index: dict[tuple[BoundaryType, str, str], TrustBoundary],
    ) -> list[Finding]:
        findings: list[Finding] = []
        public_security_group_map: dict[str, list[NormalizedResource]] = {}
        for resource in inventory.resources:
            if not resource.public_exposure:
                continue
            for security_group_id in resource.security_group_ids:
                public_security_group_map.setdefault(security_group_id, []).append(resource)
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
                        workload.address
                        for rule in risky_rules
                        for security_group_id in rule.referenced_security_group_ids
                        for workload in public_security_group_map.get(security_group_id, [])
                    }
                )
                severity_reasoning = _build_severity_reasoning(
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
                        severity=severity_reasoning.severity,
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
                        evidence=_collect_evidence(
                            _evidence_item(
                                "security_group_rules",
                                [_describe_security_group_rule(security_group, rule) for rule in risky_rules],
                            ),
                            _evidence_item(
                                "network_path",
                                [
                                    f"{security_group.address} allows {', '.join(rule.referenced_security_group_ids)} attached to {', '.join(sorted({workload.address for security_group_id in rule.referenced_security_group_ids for workload in public_security_group_map.get(security_group_id, [])}))}"
                                    for rule in risky_rules
                                ],
                            ),
                            _evidence_item(
                                "subnet_posture",
                                [
                                    posture
                                    for workload_address in exposed_workloads
                                    for posture in _subnet_posture(
                                        inventory.get_by_address(workload_address),
                                        inventory,
                                    )
                                ],
                            ),
                        ),
                        severity_reasoning=severity_reasoning,
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
                account_id = _parse_account_id(principal)
                severity_reasoning = _build_severity_reasoning(
                    internet_exposure=False,
                    privilege_breadth=2 if principal == "*" else 1,
                    data_sensitivity=0,
                    lateral_movement=2,
                    blast_radius=2 if principal == "*" or (account_id and account_id != primary_account_id) else 1,
                )
                boundary = boundary_index.get((BoundaryType.CROSS_ACCOUNT_OR_ROLE, principal, role.address))
                findings.append(
                    Finding(
                        title="Role trust relationship expands blast radius",
                        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
                        severity=severity_reasoning.severity,
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
                        evidence=_collect_evidence(
                            _evidence_item("trust_principals", [principal]),
                            _evidence_item(
                                "trust_path",
                                [_describe_trust_principal(principal, primary_account_id)],
                            ),
                        ),
                        severity_reasoning=severity_reasoning,
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


def _statement_matches_sensitive_actions(statement: IAMPolicyStatement, sensitive_actions: set[str]) -> bool:
    for action in statement.actions:
        if action in sensitive_actions:
            return True
        if action.startswith("ssm:GetParameter") and "ssm:GetParameter*" in sensitive_actions:
            return True
    return False


def _parse_account_id(principal: str) -> str | None:
    if not principal.startswith("arn:"):
        return None
    parts = principal.split(":")
    if len(parts) < 5:
        return None
    return parts[4] or None


def _build_severity_reasoning(
    *,
    internet_exposure: bool,
    privilege_breadth: int,
    data_sensitivity: int,
    lateral_movement: int,
    blast_radius: int,
) -> SeverityReasoning:
    # The v1 model is intentionally additive and explainable: each detector supplies a few
    # concrete signals and the final banding stays easy to tune without hiding logic in ML.
    internet_exposure_score = 2 if internet_exposure else 0
    score = (
        internet_exposure_score
        + privilege_breadth
        + data_sensitivity
        + lateral_movement
        + blast_radius
    )
    if score >= 6:
        severity = Severity.HIGH
    elif score >= 3:
        severity = Severity.MEDIUM
    else:
        severity = Severity.LOW
    return SeverityReasoning(
        internet_exposure=internet_exposure_score,
        privilege_breadth=privilege_breadth,
        data_sensitivity=data_sensitivity,
        lateral_movement=lateral_movement,
        blast_radius=blast_radius,
        final_score=score,
        severity=severity,
    )


def _collect_evidence(*items: EvidenceItem | None) -> list[EvidenceItem]:
    return [item for item in items if item is not None]


def _evidence_item(key: str, values: list[str]) -> EvidenceItem | None:
    deduped_values: list[str] = []
    for value in values:
        if not value:
            continue
        text = str(value)
        if text not in deduped_values:
            deduped_values.append(text)
    if not deduped_values:
        return None
    return EvidenceItem(key=key, values=deduped_values)


def _describe_security_group_rule(security_group: NormalizedResource, rule: SecurityGroupRule) -> str:
    port_range = _format_port_range(rule)
    sources = list(rule.cidr_blocks) + list(rule.ipv6_cidr_blocks)
    if rule.referenced_security_group_ids:
        sources.extend(rule.referenced_security_group_ids)
    source_text = ", ".join(sorted(sources)) if sources else "unspecified sources"
    description = f"{security_group.address} {rule.direction} {rule.protocol} {port_range} from {source_text}"
    if rule.description:
        return f"{description} ({rule.description})"
    return description


def _describe_policy_statement(statement: IAMPolicyStatement) -> str:
    actions = ", ".join(statement.actions) if statement.actions else "no actions"
    resources = ", ".join(statement.resources) if statement.resources else "no resources"
    return f"{statement.effect} actions=[{actions}] resources=[{resources}]"


def _describe_trust_principal(principal: str, primary_account_id: str | None) -> str:
    if principal == "*":
        return "trust policy allows any AWS principal"
    account_id = _parse_account_id(principal)
    if account_id and primary_account_id and account_id != primary_account_id:
        return f"trust principal belongs to foreign account {account_id}"
    if account_id:
        return f"trust principal belongs to account {account_id}"
    return f"trust policy includes principal {principal}"


def _subnet_posture(resource: NormalizedResource | None, inventory: ResourceInventory) -> list[str]:
    if resource is None:
        return []
    postures: list[str] = []
    for subnet_id in resource.subnet_ids:
        subnet = inventory.get_by_identifier(subnet_id)
        if subnet is None or subnet.resource_type != "aws_subnet":
            continue
        if subnet.metadata.get("is_public_subnet"):
            posture = f"{resource.address} sits in public subnet {subnet.address}"
        else:
            posture = f"{resource.address} sits in private subnet {subnet.address}"
        if subnet.metadata.get("has_public_route"):
            posture += " with an internet route"
        elif subnet.metadata.get("has_nat_gateway_egress"):
            posture += " with NAT-backed egress"
        postures.append(posture)
    if not postures and resource.metadata.get("public_subnet"):
        postures.append(f"{resource.address} is classified in a public subnet")
    return postures


def _format_port_range(rule: SecurityGroupRule) -> str:
    if rule.protocol == "-1":
        return "all ports"
    if rule.from_port is None or rule.to_port is None:
        return "unspecified ports"
    if rule.from_port == rule.to_port:
        return str(rule.from_port)
    return f"{rule.from_port}-{rule.to_port}"


def _join_clauses(clauses: list[str]) -> str:
    if not clauses:
        return "its network controls allow paths that should remain tighter"
    if len(clauses) == 1:
        return clauses[0]
    return f"{', '.join(clauses[:-1])}, and {clauses[-1]}"
