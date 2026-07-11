from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding
from tfstride.providers.aws.resource_facts import AwsResourceFacts, aws_facts

_AWS_RDS_INSTANCE = "aws_db_instance"
_MIN_RDS_BACKUP_RETENTION_DAYS = 7
# tfSTRIDE records this uncertainty only when `enabled_cloudwatch_logs_exports` is
# present but has an unrecognized value shape; a missing key yields a known-empty
# list with no uncertainty, which the log-export rule treats as "no exports configured".
_RDS_CLOUDWATCH_LOG_EXPORTS_UNKNOWN = "enabled_cloudwatch_logs_exports is unknown after planning"
# Expected baseline CloudWatch log exports per RDS engine family. The log-export
# rule only fires for a recognized engine so a generic "no exports = bad" posture
# never mislabels an engine whose logs tfSTRIDE does not model.
_RDS_ENGINE_LOG_EXPORT_EXPECTATIONS = {
    "postgres": {"postgresql"},
    "aurora-postgresql": {"postgresql"},
    "mysql": {"error", "slowquery"},
    "aurora-mysql": {"error", "slowquery"},
    "mariadb": {"error", "slowquery"},
}
# RDS IAM database authentication is an engine capability, not a universal RDS
# feature: AWS supports it for MariaDB, MySQL, and PostgreSQL (and the Aurora
# variants). It is not available for Db2, Oracle, or SQL Server, so the IAM-auth
# rule skips those engines rather than flagging a capability the engine lacks.
_RDS_IAM_AUTH_SUPPORTED_ENGINES = {
    "postgres",
    "mysql",
    "mariadb",
    "aurora-postgresql",
    "aurora-mysql",
}


class AwsRdsPostureRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_endpoint_enabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for database in context.inventory.by_type(_AWS_RDS_INSTANCE):
            facts = aws_facts(database)
            if facts.rds_publicly_accessible is not True:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[database.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{database.display_name} has `publicly_accessible` enabled. That can place the RDS "
                        "endpoint on a public AWS data-plane path, so database access should rely on narrow "
                        "network controls and strong authentication rather than public reachability."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _rds_target_evidence(database, facts)),
                        evidence_item("endpoint_posture", _rds_endpoint_evidence(facts)),
                        evidence_item("posture_uncertainty", _rds_uncertainty_evidence(facts, "publicly_accessible")),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_backup_retention_insufficient(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for database in context.inventory.by_type(_AWS_RDS_INSTANCE):
            facts = aws_facts(database)
            retention_days = facts.rds_backup_retention_period
            if retention_days is None or retention_days >= _MIN_RDS_BACKUP_RETENTION_DAYS:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[database.address],
                    trust_boundary_id=None,
                    rationale=_backup_retention_rationale(database.display_name, retention_days),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _rds_target_evidence(database, facts)),
                        evidence_item("backup_posture", _rds_backup_evidence(retention_days)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_deletion_protection_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for database in context.inventory.by_type(_AWS_RDS_INSTANCE):
            facts = aws_facts(database)
            if facts.rds_deletion_protection is not False:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[database.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{database.display_name} has RDS deletion protection disabled. Accidental or malicious "
                        "delete operations can therefore remove the database instance without the additional "
                        "control-plane guardrail."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _rds_target_evidence(database, facts)),
                        evidence_item("deletion_protection", _rds_deletion_protection_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_customer_managed_kms_key_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for database in context.inventory.by_type(_AWS_RDS_INSTANCE):
            facts = aws_facts(database)
            if not database.storage_encrypted or facts.rds_kms_key_id:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=1,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[database.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{database.display_name} has encrypted RDS storage but does not show a customer-managed "
                        "KMS key in the Terraform plan. AWS-managed encryption may still apply; this finding "
                        "concerns key ownership, rotation, audit separation, and compliance posture."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _rds_target_evidence(database, facts)),
                        evidence_item("encryption_ownership", _rds_encryption_ownership_evidence(database, facts)),
                        evidence_item("posture_uncertainty", _rds_uncertainty_evidence(facts, "kms_key_id")),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_multi_az_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for database in context.inventory.by_type(_AWS_RDS_INSTANCE):
            facts = aws_facts(database)
            if facts.rds_multi_az is not False:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[database.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{database.display_name} is not deployed across multiple Availability Zones. A "
                        "single-AZ RDS instance has no standby in another AZ, so an AZ-level outage or "
                        "maintenance event can take the database offline and interrupt dependent workloads."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _rds_target_evidence(database, facts)),
                        evidence_item("multi_az_posture", _rds_multi_az_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_performance_insights_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for database in context.inventory.by_type(_AWS_RDS_INSTANCE):
            facts = aws_facts(database)
            if facts.rds_performance_insights_enabled is not False:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=1,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[database.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{database.display_name} does not have RDS Performance Insights enabled. Performance "
                        "Insights surfaces query-level load and wait events, so disabling it removes the "
                        "primary operational lens for detecting slow queries, resource contention, and "
                        "regressions before they destabilize the database."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _rds_target_evidence(database, facts)),
                        evidence_item("performance_insights_posture", _rds_performance_insights_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_cloudwatch_log_exports_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for database in context.inventory.by_type(_AWS_RDS_INSTANCE):
            facts = aws_facts(database)
            # `enabled_cloudwatch_logs_exports` returns `[]` both when the list is
            # genuinely empty/missing and when the value is unknown after planning.
            # Skip the unknown case so the rule does not treat an uncertain value
            # as "missing exports"; only a known-empty posture should fire.
            if _RDS_CLOUDWATCH_LOG_EXPORTS_UNKNOWN in facts.rds_posture_uncertainties:
                continue
            expected = _expected_rds_log_exports(facts.engine)
            if expected is None:
                continue
            if expected & set(facts.rds_enabled_cloudwatch_logs_exports):
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=1,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[database.address],
                    trust_boundary_id=None,
                    rationale=_cloudwatch_log_export_rationale(database.display_name, facts.engine, expected),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _rds_target_evidence(database, facts)),
                        evidence_item("log_export_posture", _rds_log_export_evidence(facts, expected)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_iam_database_authentication_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for database in context.inventory.by_type(_AWS_RDS_INSTANCE):
            facts = aws_facts(database)
            # IAM database authentication is an engine capability, not a universal
            # RDS feature; skip engines AWS does not support it for so the rule does
            # not flag an unsupported capability as a disabled posture.
            if not _rds_iam_database_authentication_supported(facts.engine):
                continue
            if facts.rds_iam_database_authentication_enabled is not False:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[database.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{database.display_name} does not have RDS IAM database authentication enabled. "
                        "Without IAM database authentication, database access relies on long-lived static "
                        "credentials instead of short-lived AWS-signed tokens, which weakens credential "
                        "rotation and auditability."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _rds_target_evidence(database, facts)),
                        evidence_item(
                            "iam_database_authentication_posture", _rds_iam_database_authentication_evidence(facts)
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _rds_target_evidence(database, facts: AwsResourceFacts) -> list[str]:
    values = [f"address={database.address}", f"type={database.resource_type}"]
    if database.identifier:
        values.append(f"identifier={database.identifier}")
    if facts.engine:
        values.append(f"engine={facts.engine}")
    return values


def _rds_endpoint_evidence(facts: AwsResourceFacts) -> list[str]:
    values = [f"publicly_accessible_state={facts.rds_publicly_accessible_state or 'unknown'}"]
    if facts.rds_publicly_accessible is True:
        values.append("publicly_accessible is true")
    elif facts.rds_publicly_accessible is False:
        values.append("publicly_accessible is false")
    else:
        values.append("publicly_accessible is unknown")
    return values


def _rds_backup_evidence(retention_days: int) -> list[str]:
    state = "disabled" if retention_days == 0 else "short_retention"
    return [
        f"backup_retention_state={state}",
        f"backup_retention_period={retention_days}",
        f"minimum_backup_retention_days={_MIN_RDS_BACKUP_RETENTION_DAYS}",
    ]


def _rds_deletion_protection_evidence(facts: AwsResourceFacts) -> list[str]:
    values = [f"deletion_protection_state={facts.rds_deletion_protection_state or 'unknown'}"]
    if facts.rds_deletion_protection is False:
        values.append("deletion_protection is false")
    elif facts.rds_deletion_protection is True:
        values.append("deletion_protection is true")
    else:
        values.append("deletion_protection is unknown")
    return values


def _rds_encryption_ownership_evidence(database, facts: AwsResourceFacts) -> list[str]:
    values = ["storage_encrypted is true" if database.storage_encrypted else "storage_encrypted is false"]
    if facts.rds_kms_key_id:
        values.append(f"kms_key_id={facts.rds_kms_key_id}")
    else:
        values.append("kms_key_id is unset")
    values.append("AWS-managed encryption may still apply; this finding concerns customer key control")
    return values


def _rds_uncertainty_evidence(facts: AwsResourceFacts, field_path: str) -> list[str]:
    return [uncertainty for uncertainty in facts.rds_posture_uncertainties if field_path in uncertainty]


def _backup_retention_rationale(display_name: str, retention_days: int) -> str:
    if retention_days == 0:
        return (
            f"{display_name} has RDS automated backup retention set to 0 days, which disables automated "
            "backups and weakens recovery after accidental deletion, destructive migration, or compromise."
        )
    return (
        f"{display_name} keeps RDS automated backups for {retention_days} days, below the "
        f"{_MIN_RDS_BACKUP_RETENTION_DAYS}-day baseline used by tfSTRIDE. Short retention can limit recovery "
        "after delayed detection of destructive changes."
    )


def _rds_multi_az_evidence(facts: AwsResourceFacts) -> list[str]:
    values = [f"multi_az_state={facts.rds_multi_az_state or 'unknown'}"]
    if facts.rds_multi_az is False:
        values.append("multi_az is false")
    elif facts.rds_multi_az is True:
        values.append("multi_az is true")
    else:
        values.append("multi_az is unknown")
    return values


def _rds_performance_insights_evidence(facts: AwsResourceFacts) -> list[str]:
    values = [f"performance_insights_state={facts.rds_performance_insights_enabled_state or 'unknown'}"]
    if facts.rds_performance_insights_enabled is False:
        values.append("performance_insights_enabled is false")
    elif facts.rds_performance_insights_enabled is True:
        values.append("performance_insights_enabled is true")
    else:
        values.append("performance_insights_enabled is unknown")
    return values


def _rds_iam_database_authentication_evidence(facts: AwsResourceFacts) -> list[str]:
    values = [f"iam_database_authentication_state={facts.rds_iam_database_authentication_enabled_state or 'unknown'}"]
    if facts.rds_iam_database_authentication_enabled is False:
        values.append("iam_database_authentication_enabled is false")
    elif facts.rds_iam_database_authentication_enabled is True:
        values.append("iam_database_authentication_enabled is true")
    else:
        values.append("iam_database_authentication_enabled is unknown")
    return values


def _rds_log_export_evidence(facts: AwsResourceFacts, expected: set[str]) -> list[str]:
    return [
        f"enabled_cloudwatch_logs_exports={sorted(facts.rds_enabled_cloudwatch_logs_exports)}",
        f"expected_log_exports={sorted(expected)}",
        "engine-family baseline log exports are absent",
    ]


def _expected_rds_log_exports(engine: str | None) -> set[str] | None:
    if not engine:
        return None
    normalized = engine.lower().strip()
    if normalized in _RDS_ENGINE_LOG_EXPORT_EXPECTATIONS:
        return _RDS_ENGINE_LOG_EXPORT_EXPECTATIONS[normalized]
    # RDS exposes engine editions via `sqlserver-*` and `oracle-*` prefixes that
    # share the same log-export families as their base engines.
    if normalized.startswith("sqlserver-"):
        return {"error", "agent"}
    if normalized.startswith("oracle-"):
        return {"alert", "listener", "trace"}
    return None


def _rds_iam_database_authentication_supported(engine: str | None) -> bool:
    if not engine:
        return False
    return engine.lower().strip() in _RDS_IAM_AUTH_SUPPORTED_ENGINES


def _cloudwatch_log_export_rationale(display_name: str, engine: str | None, expected: set[str]) -> str:
    return (
        f"{display_name} (engine `{engine}`) does not export any of the baseline CloudWatch Logs expected "
        f"for its engine family ({', '.join(sorted(expected))}). Without these log exports the database "
        "lacks the basic observability posture needed to investigate errors, slow queries, and audit "
        "activity from CloudWatch."
    )
