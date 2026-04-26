from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    describe_policy_statement,
    evidence_item,
)
from tfstride.analysis.iam_rules import IAMRuleDetectors
from tfstride.analysis.policy_conditions import (
    assess_principal,
    describe_trust_narrowing,
    trust_statement_has_effective_narrowing,
)
from tfstride.analysis.policy_trust_rules import PolicyTrustRuleDetectors
from tfstride.analysis.rule_definitions import BoundaryIndex, ExecutableRule, RuleEvaluationContext
from tfstride.analysis.rule_registry import DEFAULT_RULE_REGISTRY, RulePolicy, RuleRegistry
from tfstride.models import (
    BoundaryType,
    EvidenceItem,
    Finding,
    NormalizedResource,
    Observation,
    ResourceInventory,
    SecurityGroupRule,
    Severity,
    SeverityReasoning,
    TrustBoundary,
)
from tfstride.resource_helpers import describe_security_group_rule, policy_allows_public_access


class StrideRuleEngine:
    def __init__(self, rule_registry: RuleRegistry = DEFAULT_RULE_REGISTRY) -> None:
        self._rule_registry = rule_registry
        self._finding_factory = FindingFactory(rule_registry)
        self._iam_rule_detectors = IAMRuleDetectors(self._finding_factory)
        self._policy_trust_rule_detectors = PolicyTrustRuleDetectors(self._finding_factory)
        self._posture_rules = (
	        ExecutableRule(
               "aws-public-compute-broad-ingress",
                self._detect_public_compute_exposure,
            ),
            ExecutableRule(
                "aws-rds-storage-encryption-disabled",
                self._detect_unencrypted_databases,
            ),
            ExecutableRule(
                "aws-s3-public-access",
                self._detect_public_object_storage,
            ),
        )
        self._resource_policy_rules = (
            ExecutableRule(
                "aws-sensitive-resource-policy-external-access",
                self._policy_trust_rule_detectors.detect_sensitive_resource_policy_exposure,
            ),
            ExecutableRule(
                "aws-service-resource-policy-external-access",
                self._policy_trust_rule_detectors.detect_service_resource_policy_exposure,
	        ),
	    )
        self._iam_rules = (
            ExecutableRule(
                "aws-iam-wildcard-permissions",
                self._iam_rule_detectors.detect_wildcard_permissions,
            ),
            ExecutableRule(
                "aws-workload-role-sensitive-permissions",
                self._iam_rule_detectors.detect_workload_role_sensitive_permissions,
            ),
        )
        self._trust_rules = (
            ExecutableRule(
                "aws-role-trust-expansion",
                self._policy_trust_rule_detectors.detect_trust_expansion,
            ),
            ExecutableRule(
                "aws-role-trust-missing-narrowing",
                self._policy_trust_rule_detectors.detect_unconstrained_trust,
            ),
        )

    def evaluate(
        self,
        inventory: ResourceInventory,
        boundaries: list[TrustBoundary],
        *,
        rule_policy: RulePolicy | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        boundary_index: BoundaryIndex = {
            (boundary.boundary_type, boundary.source, boundary.target): boundary for boundary in boundaries
        }
        context = RuleEvaluationContext(
            inventory=inventory,
            boundary_index=boundary_index,
            rule_registry=self._rule_registry,
            rule_policy=rule_policy,
        )

        findings.extend(self._evaluate_rules(self._posture_rules, context))
        findings.extend(self._detect_database_exposure(inventory, boundary_index))
        findings.extend(self._evaluate_rules(self._resource_policy_rules, context))
        findings.extend(self._evaluate_rules(self._iam_rules, context))
        findings.extend(self._detect_missing_segmentation(inventory, boundary_index))
        findings.extend(self._detect_transitive_private_data_exposure(inventory, boundary_index))
        findings.extend(self._detect_control_plane_sensitive_workload_chain(inventory, boundary_index))
        findings.extend(self._evaluate_rules(self._trust_rules, context))

        severity_order = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
        findings.sort(key=lambda finding: (severity_order[finding.severity], finding.title))
        return findings

    def _build_finding(
        self,
        *,
        rule_id: str,
        severity: Severity,
        affected_resources: list[str],
        trust_boundary_id: str | None,
        rationale: str,
        evidence: list[EvidenceItem],
        severity_reasoning: SeverityReasoning | None = None,
    ) -> Finding:
        return self._finding_factory.build(
            rule_id=rule_id,
            severity=severity,
            affected_resources=affected_resources,
            trust_boundary_id=trust_boundary_id,
            rationale=rationale,
            evidence=evidence,
            severity_reasoning=severity_reasoning,
        )

    def _evaluate_rules(
        self,
        rules: tuple[ExecutableRule, ...],
        context: RuleEvaluationContext,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for rule in rules:
            findings.extend(rule.evaluate(context))
        return findings


    def observe_controls(self, inventory: ResourceInventory) -> list[Observation]:
        observations: list[Observation] = []
        observations.extend(self._observe_bucket_public_access_blocks(inventory))
        observations.extend(self._observe_narrowed_trust(inventory))
        observations.extend(self._observe_private_encrypted_databases(inventory))
        observations.sort(key=lambda observation: ((observation.category or ""), observation.title, observation.observation_id))
        return observations

    def _detect_public_compute_exposure(
        self,
        context: RuleEvaluationContext,
	    rule_id: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        inventory = context.inventory
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
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=1,
            )
            boundary = context.boundary_index.get(
	            (BoundaryType.INTERNET_TO_SERVICE, "internet", resource.address)
	        )
            findings.append(
                self._build_finding(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
 	                affected_resources=[
	                    resource.address,
	                    *[sg.address for sg in attached_security_groups],
	                ],
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{resource.display_name} is reachable from the internet and at least one attached "
                        "security group allows administrative access or all ports from 0.0.0.0/0. "
                        "That broad ingress raises the chance of unauthenticated probing and credential attacks."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "security_group_rules",
                            [describe_security_group_rule(security_group, rule) for security_group, rule in risky_rules],
                        ),
                        evidence_item("public_exposure_reasons", resource.public_exposure_reasons),
                        evidence_item("subnet_posture", _subnet_posture(resource, inventory)),
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

            direct_internet_reachable = database.direct_internet_reachable and (internet_rules or not attached_security_groups)
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
            severity_reasoning = build_severity_reasoning(
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
                self._build_finding(
                    rule_id="aws-database-permissive-ingress",
                    severity=severity_reasoning.severity,
                    affected_resources=[database.address, *[sg.address for sg in attached_security_groups]],
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{database.display_name} is a sensitive data store, but "
                        f"{_join_clauses(path_signals)}. "
                        "That weakens the expected separation between the workload tier and the data tier."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "security_group_rules",
                            [
                                describe_security_group_rule(security_group, rule)
                                for security_group, rule in internet_rules
                            ]
                            + [
                                describe_security_group_rule(security_group, rule)
                                for security_group, rule, _ in public_tier_rules
                            ],
                        ),
                        evidence_item(
                            "network_path",
                            path_signals
                            + [
                                f"{security_group.address} allows {', '.join(rule.referenced_security_group_ids)} attached to {', '.join(workload.address for workload in workloads)}"
                                for security_group, rule, workloads in public_tier_rules
                            ],
                        ),
                        evidence_item("public_exposure_reasons", database.public_exposure_reasons),
                        evidence_item(
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

    def _detect_unencrypted_databases(
	    self,
	    context: RuleEvaluationContext,
	    rule_id: str,
	) -> list[Finding]:
        findings: list[Finding] = []
        inventory = context.inventory
        for database in inventory.by_type("aws_db_instance"):
            if database.storage_encrypted:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._build_finding(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[database.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{database.display_name} stores sensitive data, but `storage_encrypted` is disabled. "
                        "That weakens data-at-rest protections for underlying storage, snapshots, and backup handling."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "encryption_posture",
                            [
                                "storage_encrypted is false",
                                f"engine is {database.engine or 'unknown'}",
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def _detect_public_object_storage(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        inventory = context.inventory
        for bucket in inventory.by_type("aws_s3_bucket"):
            if not bucket.public_exposure:
                continue
            boundary = context.boundary_index.get(
	            (BoundaryType.INTERNET_TO_SERVICE, "internet", bucket.address)
	        )
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._build_finding(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[bucket.address],
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{bucket.display_name} appears to be public through ACLs or bucket policy. "
                        "Public object access is a common source of unintended data disclosure."
                    ),
                    evidence=collect_evidence(
                        evidence_item("public_exposure_reasons", bucket.public_exposure_reasons),
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
                severity_reasoning = build_severity_reasoning(
                    internet_exposure=True,
                    privilege_breadth=0,
                    data_sensitivity=2,
                    lateral_movement=2,
                    blast_radius=1,
                )
                findings.append(
                    self._build_finding(
                        rule_id="aws-missing-tier-segmentation",
                        severity=severity_reasoning.severity,
                        affected_resources=[database.address, *exposed_workloads, security_group.address],
                        trust_boundary_id=public_private_boundary.identifier if public_private_boundary else None,
                        rationale=(
                            f"{database.display_name} accepts traffic from security groups attached to internet-facing "
                            "workloads. A compromise of the public tier can therefore move laterally into the private data tier."
                        ),
                        evidence=collect_evidence(
                            evidence_item(
                                "security_group_rules",
                                [describe_security_group_rule(security_group, rule) for rule in risky_rules],
                            ),
                            evidence_item(
                                "network_path",
                                [
                                    f"{security_group.address} allows {', '.join(rule.referenced_security_group_ids)} attached to {', '.join(sorted({workload.address for security_group_id in rule.referenced_security_group_ids for workload in public_security_group_map.get(security_group_id, [])}))}"
                                    for rule in risky_rules
                                ],
                            ),
                            evidence_item(
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

    def _detect_transitive_private_data_exposure(
        self,
        inventory: ResourceInventory,
        boundary_index: dict[tuple[BoundaryType, str, str], TrustBoundary],
    ) -> list[Finding]:
        findings: list[Finding] = []
        trusted_workload_hops = _trusted_workload_hops(inventory)
        private_data_paths = _private_workload_data_paths(boundary_index, inventory)
        seen: set[tuple[str, ...]] = set()

        internet_boundaries = sorted(
            (
                boundary
                for boundary in boundary_index.values()
                if boundary.boundary_type == BoundaryType.INTERNET_TO_SERVICE
            ),
            key=lambda boundary: (boundary.target, boundary.identifier),
        )

        for internet_boundary in internet_boundaries:
            entry = inventory.get_by_address(internet_boundary.target)
            if entry is None:
                continue

            for path_workloads, security_group_hops in _iter_transitive_workload_paths(
                entry,
                trusted_workload_hops,
                max_hops=2,
            ):
                terminal_workload = path_workloads[-1]
                for data_store, data_boundary in private_data_paths.get(terminal_workload.address, []):
                    finding_key = (
                        entry.address,
                        *[workload.address for workload in path_workloads],
                        data_store.address,
                    )
                    if finding_key in seen:
                        continue
                    seen.add(finding_key)
                    findings.append(
                        _build_transitive_private_data_finding(
                            rule_id="aws-private-data-transitive-exposure",
                            finding_factory=self._finding_factory,
                            inventory=inventory,
                            entry=entry,
                            path_workloads=path_workloads,
                            security_group_hops=security_group_hops,
                            data_store=data_store,
                            data_boundary=data_boundary,
                        )
                    )
        return findings


    def _detect_control_plane_sensitive_workload_chain(
        self,
        inventory: ResourceInventory,
        boundary_index: dict[tuple[BoundaryType, str, str], TrustBoundary],
    ) -> list[Finding]:
        findings: list[Finding] = []
        primary_account_id = inventory.primary_account_id
        control_boundaries_by_role = _control_workload_boundaries_by_role(boundary_index)
        sensitive_data_paths = _private_sensitive_controlled_data_paths(boundary_index, inventory)
        seen: set[tuple[str, str, tuple[str, ...], tuple[str, ...]]] = set()

        for role in inventory.by_type("aws_iam_role"):
            control_boundaries = control_boundaries_by_role.get(role.address, [])
            if not control_boundaries:
                continue
            for trust_statement in role.trust_statements:
                if trust_statement_has_effective_narrowing(trust_statement):
                    continue
                for principal in trust_statement.get("principals", []):
                    assessment = assess_principal(principal, primary_account_id)
                    if assessment.is_service:
                        continue
                    if not (assessment.is_foreign_account or assessment.is_wildcard):
                        continue

                    chained_paths: list[tuple[NormalizedResource, TrustBoundary, NormalizedResource, TrustBoundary]] = []
                    for control_boundary in control_boundaries:
                        workload = inventory.get_by_address(control_boundary.target)
                        if workload is None:
                            continue
                        for data_store, data_boundary in sensitive_data_paths.get(workload.address, []):
                            chained_paths.append((workload, control_boundary, data_store, data_boundary))
                    if not chained_paths:
                        continue

                    workload_addresses = tuple(sorted({workload.address for workload, _, _, _ in chained_paths}))
                    data_store_addresses = tuple(sorted({data_store.address for _, _, data_store, _ in chained_paths}))
                    finding_key = (role.address, principal, workload_addresses, data_store_addresses)
                    if finding_key in seen:
                        continue
                    seen.add(finding_key)

                    privilege_breadth = 2 if assessment.is_wildcard else 1
                    blast_radius = 2 if assessment.is_wildcard or len(data_store_addresses) > 1 else 1
                    severity_reasoning = build_severity_reasoning(
                        internet_exposure=False,
                        privilege_breadth=privilege_breadth,
                        data_sensitivity=2,
                        lateral_movement=1,
                        blast_radius=blast_radius,
                    )
                    trust_boundary = boundary_index.get((BoundaryType.CROSS_ACCOUNT_OR_ROLE, principal, role.address))
                    findings.append(
                        self._build_finding(
                            rule_id="aws-control-plane-sensitive-workload-chain",
                            severity=severity_reasoning.severity,
                            affected_resources=[
                                role.address,
                                *workload_addresses,
                                *data_store_addresses,
                            ],
                            trust_boundary_id=trust_boundary.identifier if trust_boundary else None,
                            rationale=(
                                f"{principal} can assume {role.display_name}, and that role governs workload paths into "
                                f"{', '.join(data_store.display_name for data_store in sorted({data_store.address: data_store for _, _, data_store, _ in chained_paths}.values(), key=lambda resource: resource.address))}. "
                                "A broad or foreign control-plane principal can therefore influence a workload that already "
                                "retains sensitive secret or database access."
                            ),
                            evidence=collect_evidence(
                                evidence_item("trust_principals", [principal]),
                                evidence_item("trust_scope", [assessment.scope_description] if assessment.scope_description else []),
                                evidence_item(
                                    "control_path",
                                    [
                                        f"{principal} assumes {role.address}",
                                        *[
                                            f"{control_boundary.source} governs {control_boundary.target}"
                                            for _, control_boundary, _, _ in chained_paths
                                        ],
                                        *[
                                            f"{data_boundary.source} reaches {data_boundary.target}"
                                            for _, _, _, data_boundary in chained_paths
                                        ],
                                    ],
                                ),
                                evidence_item(
                                    "boundary_rationale",
                                    [
                                        *[
                                            control_boundary.rationale
                                            for _, control_boundary, _, _ in chained_paths
                                        ],
                                        *[
                                            data_boundary.rationale
                                            for _, _, _, data_boundary in chained_paths
                                        ],
                                    ],
                                ),
                                evidence_item(
                                    "sensitive_data_targets",
                                    list(data_store_addresses),
                                ),
                                evidence_item("trust_narrowing", describe_trust_narrowing(trust_statement)),
                            ),
                            severity_reasoning=severity_reasoning,
                        )
                    )
        return findings


    def _observe_bucket_public_access_blocks(self, inventory: ResourceInventory) -> list[Observation]:
        observations: list[Observation] = []
        access_block_index = {
            access_block.bucket_name: access_block
            for access_block in inventory.by_type("aws_s3_bucket_public_access_block")
            if access_block.bucket_name
        }
        for bucket in inventory.by_type("aws_s3_bucket"):
            access_block = bucket.public_access_block
            if not access_block or bucket.public_exposure:
                continue
            mitigation_signals: list[str] = []
            acl = bucket.bucket_acl
            if acl in {"public-read", "public-read-write", "website"}:
                mitigation_signals.append(f"bucket ACL `{acl}` would otherwise grant public access")
            if policy_allows_public_access(bucket.policy_document):
                mitigation_signals.append("bucket policy would otherwise allow anonymous access")
            if not mitigation_signals:
                continue
            affected_resources = [bucket.address]
            access_block_resource = access_block_index.get(bucket.bucket_name)
            if access_block_resource is not None:
                affected_resources.append(access_block_resource.address)
            observations.append(
                Observation(
                    title="S3 public access is reduced by a public access block",
                    observation_id="aws-s3-public-access-block-observed",
                    category="data-protection",
                    affected_resources=affected_resources,
                    rationale=(
                        f"{bucket.display_name} includes public-looking ACL or policy signals, but an attached "
                        "public access block materially reduces that exposure."
                    ),
                    evidence=collect_evidence(
                        evidence_item("mitigated_public_access", mitigation_signals),
                        evidence_item(
                            "control_posture",
                            [
                                f"{key} is {str(value).lower()}"
                                for key, value in sorted(access_block.items())
                                if value
                            ],
                        ),
                    ),
                )
            )
        return observations

    def _observe_narrowed_trust(self, inventory: ResourceInventory) -> list[Observation]:
        observations: list[Observation] = []
        primary_account_id = inventory.primary_account_id
        seen: set[tuple[str, str]] = set()
        for role in inventory.by_type("aws_iam_role"):
            for trust_statement in role.trust_statements:
                if not trust_statement_has_effective_narrowing(trust_statement):
                    continue
                for principal in trust_statement.get("principals", []):
                    assessment = assess_principal(principal, primary_account_id)
                    if assessment.is_service:
                        continue
                    if assessment.scope_description is None:
                        continue
                    observation_key = (role.address, principal)
                    if observation_key in seen:
                        continue
                    seen.add(observation_key)
                    observations.append(
                        Observation(
                            title="Cross-account or broad role trust is narrowed by assume-role conditions",
                            observation_id="aws-role-trust-narrowed",
                            category="iam",
                            affected_resources=[role.address],
                            rationale=(
                                f"{role.display_name} trusts {principal}, but supported assume-role conditions narrow "
                                "when that trust can be exercised."
                            ),
                            evidence=collect_evidence(
                                evidence_item("trust_principals", [principal]),
                                evidence_item("trust_scope", [assessment.scope_description]),
                                evidence_item("trust_narrowing", describe_trust_narrowing(trust_statement)),
                            ),
                        )
                    )
        return observations

    def _observe_private_encrypted_databases(self, inventory: ResourceInventory) -> list[Observation]:
        observations: list[Observation] = []
        for database in inventory.by_type("aws_db_instance"):
            if not database.storage_encrypted:
                continue
            if database.publicly_accessible:
                continue
            if database.direct_internet_reachable:
                continue
            if database.internet_ingress_capable:
                continue
            posture_signals = [
                "publicly_accessible is false",
                "storage_encrypted is true",
                "no attached security group allows internet ingress",
            ]
            engine = database.engine
            if engine:
                posture_signals.append(f"engine is {engine}")
            observations.append(
                Observation(
                    title="RDS instance is private and storage encrypted",
                    observation_id="aws-rds-private-encrypted",
                    category="data-protection",
                    affected_resources=[database.address],
                    rationale=(
                        f"{database.display_name} is kept off direct internet paths and has storage encryption enabled, "
                        "which reduces straightforward data exposure risk."
                    ),
                    evidence=collect_evidence(
                        evidence_item("database_posture", posture_signals),
                    ),
                )
            )
        return observations


def _attached_security_groups(resource: NormalizedResource, inventory: ResourceInventory) -> list[NormalizedResource]:
    security_groups = []
    for security_group_id in resource.security_group_ids:
        security_group = inventory.get_by_identifier(security_group_id)
        if security_group and security_group.resource_type == "aws_security_group":
            security_groups.append(security_group)
    return security_groups


def _subnet_posture(resource: NormalizedResource | None, inventory: ResourceInventory) -> list[str]:
    if resource is None:
        return []
    postures: list[str] = []
    for subnet_id in resource.subnet_ids:
        subnet = inventory.get_by_identifier(subnet_id)
        if subnet is None or subnet.resource_type != "aws_subnet":
            continue
        if subnet.is_public_subnet:
            posture = f"{resource.address} sits in public subnet {subnet.address}"
        else:
            posture = f"{resource.address} sits in private subnet {subnet.address}"
        if subnet.has_public_route:
            posture += " with an internet route"
        elif subnet.has_nat_gateway_egress:
            posture += " with NAT-backed egress"
        postures.append(posture)
    if not postures and resource.in_public_subnet:
        postures.append(f"{resource.address} is classified in a public subnet")
    return postures


def _join_clauses(clauses: list[str]) -> str:
    if not clauses:
        return "its network controls allow paths that should remain tighter"
    if len(clauses) == 1:
        return clauses[0]
    return f"{', '.join(clauses[:-1])}, and {clauses[-1]}"


def _trusted_workload_hops(
    inventory: ResourceInventory,
) -> dict[str, list[tuple[NormalizedResource, NormalizedResource, SecurityGroupRule]]]:
    resources_by_security_group: dict[str, list[NormalizedResource]] = {}
    for resource in inventory.resources:
        for security_group_id in resource.security_group_ids:
            resources_by_security_group.setdefault(security_group_id, []).append(resource)

    trusted_hops: dict[str, list[tuple[NormalizedResource, NormalizedResource, SecurityGroupRule]]] = {}
    for workload in inventory.by_type("aws_instance", "aws_ecs_service"):
        for security_group in _attached_security_groups(workload, inventory):
            for rule in security_group.network_rules:
                if rule.direction != "ingress" or not rule.referenced_security_group_ids:
                    continue
                matched_sources = sorted(
                    {
                        source.address: source
                        for security_group_id in rule.referenced_security_group_ids
                        for source in resources_by_security_group.get(security_group_id, [])
                        if source.address != workload.address
                    }.values(),
                    key=lambda source: source.address,
                )
                for source in matched_sources:
                    trusted_hops.setdefault(source.address, []).append((workload, security_group, rule))
    return trusted_hops


def _iter_transitive_workload_paths(
    entry: NormalizedResource,
    trusted_workload_hops: dict[str, list[tuple[NormalizedResource, NormalizedResource, SecurityGroupRule]]],
    *,
    max_hops: int,
) -> list[tuple[list[NormalizedResource], list[tuple[NormalizedResource, SecurityGroupRule]]]]:
    discovered_paths: list[tuple[list[NormalizedResource], list[tuple[NormalizedResource, SecurityGroupRule]]]] = []
    frontier: list[tuple[NormalizedResource, list[NormalizedResource], list[tuple[NormalizedResource, SecurityGroupRule]]]] = [
        (entry, [], [])
    ]

    for _ in range(max_hops):
        next_frontier: list[tuple[NormalizedResource, list[NormalizedResource], list[tuple[NormalizedResource, SecurityGroupRule]]]] = []
        for source, path_workloads, security_group_hops in frontier:
            for downstream, security_group, rule in trusted_workload_hops.get(source.address, []):
                if downstream.address == entry.address:
                    continue
                if any(workload.address == downstream.address for workload in path_workloads):
                    continue
                new_path = [*path_workloads, downstream]
                new_hops = [*security_group_hops, (security_group, rule)]
                discovered_paths.append((new_path, new_hops))
                next_frontier.append((downstream, new_path, new_hops))
        frontier = next_frontier
        if not frontier:
            break
    return discovered_paths


def _private_workload_data_paths(
    boundary_index: dict[tuple[BoundaryType, str, str], TrustBoundary],
    inventory: ResourceInventory,
) -> dict[str, list[tuple[NormalizedResource, TrustBoundary]]]:
    data_paths: dict[str, list[tuple[NormalizedResource, TrustBoundary]]] = {}
    for boundary in boundary_index.values():
        if boundary.boundary_type != BoundaryType.WORKLOAD_TO_DATA_STORE:
            continue
        data_store = inventory.get_by_address(boundary.target)
        if data_store is None or not _is_hidden_data_store(data_store):
            continue
        data_paths.setdefault(boundary.source, []).append((data_store, boundary))
    return data_paths


def _private_sensitive_controlled_data_paths(
    boundary_index: dict[tuple[BoundaryType, str, str], TrustBoundary],
    inventory: ResourceInventory,
) -> dict[str, list[tuple[NormalizedResource, TrustBoundary]]]:
    data_paths: dict[str, list[tuple[NormalizedResource, TrustBoundary]]] = {}
    for boundary in boundary_index.values():
        if boundary.boundary_type != BoundaryType.WORKLOAD_TO_DATA_STORE:
            continue
        data_store = inventory.get_by_address(boundary.target)
        if data_store is None or not _is_control_plane_sensitive_data_store(data_store):
            continue
        data_paths.setdefault(boundary.source, []).append((data_store, boundary))
    return data_paths


def _control_workload_boundaries_by_role(
    boundary_index: dict[tuple[BoundaryType, str, str], TrustBoundary],
) -> dict[str, list[TrustBoundary]]:
    boundaries_by_role: dict[str, list[TrustBoundary]] = {}
    for boundary in boundary_index.values():
        if boundary.boundary_type != BoundaryType.CONTROL_TO_WORKLOAD:
            continue
        boundaries_by_role.setdefault(boundary.source, []).append(boundary)
    return boundaries_by_role


def _is_hidden_data_store(resource: NormalizedResource) -> bool:
    return not (
        resource.public_exposure
        or resource.direct_internet_reachable
        or resource.internet_ingress_capable
    )


def _is_control_plane_sensitive_data_store(resource: NormalizedResource) -> bool:
    return resource.resource_type in {"aws_db_instance", "aws_secretsmanager_secret"} and _is_hidden_data_store(resource)


def _build_transitive_private_data_finding(
    *,
    rule_id: str,
    finding_factory: FindingFactory,
    inventory: ResourceInventory,
    entry: NormalizedResource,
    path_workloads: list[NormalizedResource],
    security_group_hops: list[tuple[NormalizedResource, SecurityGroupRule]],
    data_store: NormalizedResource,
    data_boundary: TrustBoundary,
) -> Finding:
    terminal_workload = path_workloads[-1]
    workload_path = [entry, *path_workloads]
    hop_descriptions = [
        f"{source.display_name} can reach {target.display_name}"
        for source, target in zip(workload_path[:-1], workload_path[1:])
    ]
    data_posture = [
        f"{data_store.address} is not directly public",
    ]
    if data_store.resource_type == "aws_db_instance":
        data_posture.append("database has no direct internet ingress path")
    severity_reasoning = build_severity_reasoning(
        internet_exposure=False,
        privilege_breadth=0,
        data_sensitivity=2 if data_store.data_sensitivity == "sensitive" else 1,
        lateral_movement=2,
        blast_radius=1,
    )
    affected_resources = [entry.address, *[workload.address for workload in path_workloads], data_store.address]
    affected_resources.extend(security_group.address for security_group, _ in security_group_hops)
    return finding_factory.build(
        rule_id=rule_id,
        severity=severity_reasoning.severity,
        affected_resources=list(dict.fromkeys(affected_resources)),
        trust_boundary_id=data_boundary.identifier,
        rationale=(
            f"{data_store.display_name} is not directly public, but internet traffic can first reach {entry.display_name}, "
            f"move through {_join_clauses(hop_descriptions)}, and then cross into the private data tier through "
            f"{terminal_workload.display_name}. That creates a quieter transitive exposure path than a directly public data store."
        ),
        evidence=collect_evidence(
            evidence_item("network_path", [
                f"internet reaches {entry.address}",
                *[
                    f"{source.address} reaches {target.address}"
                    for source, target in zip(workload_path[:-1], workload_path[1:])
                ],
                f"{terminal_workload.address} reaches {data_store.address}",
            ]),
            evidence_item(
                "security_group_rules",
                [describe_security_group_rule(security_group, rule) for security_group, rule in security_group_hops],
            ),
            evidence_item("subnet_posture", [posture for workload in workload_path for posture in _subnet_posture(workload, inventory)]),
            evidence_item("data_tier_posture", data_posture),
            evidence_item("boundary_rationale", [data_boundary.rationale]),
        ),
        severity_reasoning=severity_reasoning,
    )
