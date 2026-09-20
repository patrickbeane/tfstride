from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_ecs_cloudtrail_audit_telemetry_disruption_paths import (
    _DELETE_TRAIL,
    _STOP_LOGGING,
    _TRAIL_ARN,
    _caller_identity,
    _role,
    _statement,
    _task_definition,
    _trail,
)
from tests.providers.aws.test_aws_public_ecs_dynamodb_mutation_rules import (
    _public_edge,
    _service,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import StrideCategory, TerraformResource
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.policy_documents import parse_policy_statement
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS

_RULE_ID = "aws-public-ecs-cloudtrail-disruption"


def _runtime_resources(
    actions: str | list[str],
) -> list[TerraformResource]:
    resources = [
        *_public_edge(),
        _caller_identity(),
        _trail(),
        _role([_statement("Allow", actions, _TRAIL_ARN)]),
        _task_definition(execution_role_arn=None),
        _service(),
    ]
    for resource in resources:
        resource.provider_config_key = "aws"
    return resources


def _evaluate(resources: list[TerraformResource]):
    inventory = AwsNormalizer().normalize(resources)
    findings = _reevaluate(inventory)
    return inventory, findings


def _reevaluate(inventory):
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )


class AwsPublicEcsCloudTrailDisruptionRuleTests(unittest.TestCase):
    def test_rule_is_registered_and_operation_exact_paths_are_reported(self) -> None:
        registered = {rule_id for group in AWS_RULE_GROUP_IDS for rule_id in group}
        self.assertIn(_RULE_ID, registered)

        _, findings = _evaluate(
            _runtime_resources([_STOP_LOGGING, _DELETE_TRAIL]),
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.category, StrideCategory.REPUDIATION)
        self.assertEqual(
            finding.affected_resources,
            [
                "aws_lb.public",
                "aws_ecs_service.orders",
                "aws_ecs_task_definition.orders",
                "aws_iam_role.orders_task",
                "aws_cloudtrail.audit",
            ],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        paths = evidence["cloudtrail_audit_telemetry_disruption_paths"]
        self.assertEqual(len(paths), 2)
        self.assertTrue(any("operation=cloudtrail:StopLogging" in value for value in paths))
        self.assertTrue(any("operation=cloudtrail:DeleteTrail" in value for value in paths))
        self.assertTrue(all("target_scope=exact_cloudtrail_trail" in value for value in paths))
        self.assertTrue(all("authorization_state=allowed" in value for value in paths))
        lifecycle = evidence["cloudtrail_lifecycle_evidence"][0]
        self.assertIn("logging_state=enabled", lifecycle)
        self.assertIn("organization_trail_state=disabled", lifecycle)
        outcome = evidence["cloudtrail_disruption_outcome_evidence"][0]
        self.assertIn("successful_operation_observed=false", outcome)
        self.assertIn(
            "historical_log_object_deletion_authorized_by_operation=false",
            outcome,
        )
        self.assertIn(
            "logging_destination_deletion_authorized_by_operation=false",
            outcome,
        )
        self.assertIn("stop logging or delete trail configurations", finding.rationale)
        scope = " ".join(evidence["assessment_scope"])
        self.assertIn("Repudiation risk", scope)
        self.assertIn("disrupt future audit telemetry", scope)
        self.assertIn("weaken auditability", scope)
        self.assertNotIn("Denial of Service", scope)
        self.assertIn("does_not_establish=successful operation", scope)
        self.assertIn("historical CloudTrail log-object deletion", scope)
        self.assertIn("telemetry recovery", scope)

    def test_rationale_is_operation_specific(self) -> None:
        cases = (
            (_STOP_LOGGING, "stop logging", "delete trail configurations"),
            (_DELETE_TRAIL, "delete trail configurations", "stop logging"),
        )
        for operation, expected, excluded in cases:
            with self.subTest(operation=operation):
                _, findings = _evaluate(_runtime_resources(operation))
                self.assertEqual(len(findings), 1)
                self.assertIn(expected, findings[0].rationale)
                self.assertNotIn(excluded, findings[0].rationale)

    def test_private_service_retains_paths_but_emits_no_public_finding(self) -> None:
        resources = [
            resource
            for resource in _runtime_resources(_STOP_LOGGING)
            if resource.resource_type not in {"aws_lb", "aws_lb_listener", "aws_lb_target_group"}
        ]
        inventory, findings = _evaluate(resources)
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert service is not None

        self.assertEqual(
            len(aws_facts(service).ecs_cloudtrail_audit_telemetry_disruption_paths),
            1,
        )
        self.assertEqual(findings, [])

    def test_current_allow_removal_and_explicit_deny_suppress_cached_finding(
        self,
    ) -> None:
        inventory, findings = _evaluate(
            _runtime_resources([_STOP_LOGGING, _DELETE_TRAIL]),
        )
        self.assertEqual(len(findings), 1)
        role = inventory.get_by_address("aws_iam_role.orders_task")
        assert role is not None
        original = role.policy_statements

        role.policy_statements = ()
        self.assertEqual(_reevaluate(inventory), [])

        role.policy_statements = (
            *original,
            parse_policy_statement(
                _statement(
                    "Deny",
                    [_STOP_LOGGING, _DELETE_TRAIL],
                    _TRAIL_ARN,
                )
            ),
        )
        self.assertEqual(_reevaluate(inventory), [])

    def test_current_permissions_boundary_suppresses_cached_finding(self) -> None:
        inventory, findings = _evaluate(_runtime_resources(_STOP_LOGGING))
        self.assertEqual(len(findings), 1)
        role = inventory.get_by_address("aws_iam_role.orders_task")
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert role is not None
        assert service is not None
        self.assertEqual(
            len(aws_facts(service).ecs_cloudtrail_audit_telemetry_disruption_paths),
            1,
        )

        role.set_metadata_field(
            AwsResourceMetadata.IAM_PERMISSIONS_BOUNDARY_ARN,
            "arn:aws:iam::111122223333:policy/orders-boundary",
        )
        role.set_metadata_field(
            AwsResourceMetadata.IAM_PERMISSIONS_BOUNDARY_STATE,
            "configured",
        )

        self.assertEqual(_reevaluate(inventory), [])

    def test_current_lifecycle_and_target_drift_suppress_cached_finding(self) -> None:
        inventory, findings = _evaluate(_runtime_resources(_STOP_LOGGING))
        self.assertEqual(len(findings), 1)
        trail = inventory.get_by_address("aws_cloudtrail.audit")
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert trail is not None
        assert service is not None

        trail.set_metadata_field(
            AwsResourceMetadata.CLOUDTRAIL_ENABLE_LOGGING_STATE,
            "disabled",
        )
        self.assertEqual(_reevaluate(inventory), [])

        trail.set_metadata_field(
            AwsResourceMetadata.CLOUDTRAIL_ENABLE_LOGGING_STATE,
            "enabled",
        )
        service_facts = aws_facts(service)
        stale = dict(service_facts.ecs_cloudtrail_audit_telemetry_disruption_paths[0])
        stale["trail_address"] = "aws_cloudtrail.missing"
        service_facts.set_ecs_cloudtrail_audit_telemetry_disruption_paths([stale])
        self.assertEqual(_reevaluate(inventory), [])

    def test_unrelated_permission_expansion_refreshes_current_evidence(self) -> None:
        inventory, findings = _evaluate(_runtime_resources(_STOP_LOGGING))
        self.assertEqual(len(findings), 1)
        role = inventory.get_by_address("aws_iam_role.orders_task")
        assert role is not None

        role.policy_statements = (
            parse_policy_statement(
                _statement(
                    "Allow",
                    [_STOP_LOGGING, "cloudtrail:GetTrail"],
                    _TRAIL_ARN,
                )
            ),
        )
        findings = _reevaluate(inventory)
        self.assertEqual(len(findings), 1)
        evidence = {item.key: item.values for item in findings[0].evidence}
        path_evidence = evidence["cloudtrail_audit_telemetry_disruption_paths"][0]
        self.assertIn("matched_actions=cloudtrail:StopLogging", path_evidence)
        self.assertNotIn("cloudtrail:GetTrail", path_evidence)

    def test_duplicate_cached_paths_do_not_inflate_finding_evidence(self) -> None:
        inventory, findings = _evaluate(_runtime_resources(_DELETE_TRAIL))
        self.assertEqual(len(findings), 1)
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert service is not None
        service_facts = aws_facts(service)
        path = service_facts.ecs_cloudtrail_audit_telemetry_disruption_paths[0]
        service_facts.set_ecs_cloudtrail_audit_telemetry_disruption_paths([path, dict(path)])

        findings = _reevaluate(inventory)
        self.assertEqual(len(findings), 1)
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(
            len(evidence["cloudtrail_audit_telemetry_disruption_paths"]),
            1,
        )
        self.assertIn("across 1 exact modeled active standard CloudTrail trail", findings[0].rationale)


if __name__ == "__main__":
    unittest.main()
