"""Characterize how ECS disruption families treat wildcard resource grants.

Each family models a task role's authority to disrupt one kind of exact
resource. This table runs the same grant shapes (`*`, a covering ARN pattern, a
prefix pattern, a pattern for another account, and deny statements) through
every family and pins what each one establishes today, so the families that
still fail closed on wildcard allows are recorded and later changes move the
baseline deliberately. It records current behavior only.
"""

from __future__ import annotations

import unittest
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from tests.providers.aws import test_aws_ecs_cloudtrail_audit_telemetry_disruption_paths as cloudtrail_tests
from tests.providers.aws import test_aws_ecs_dynamodb_item_deletion_paths as dynamodb_item_tests
from tests.providers.aws import test_aws_ecs_dynamodb_table_topology_destruction_paths as dynamodb_table_tests
from tests.providers.aws import test_aws_ecs_messaging_topology_destruction_paths as messaging_tests
from tests.providers.aws import test_aws_ecs_s3_bucket_topology_destruction_paths as s3_bucket_tests
from tfstride.app import TfStride
from tfstride.providers.aws.resource_facts import aws_facts

_ACCOUNT_ID = "111122223333"
_FOREIGN_ACCOUNT_ID = "444455556666"

# One (effect, resource) pair per statement, each granting the family's operation.
_Grants = Sequence[tuple[str, str]]


def _cloudtrail_established(grants: _Grants) -> bool:
    _inventory, task, _service = cloudtrail_tests._normalize(  # pyright: ignore[reportPrivateUsage]
        [
            cloudtrail_tests._statement(effect, cloudtrail_tests._STOP_LOGGING, resource)  # pyright: ignore[reportPrivateUsage]
            for effect, resource in grants
        ]
    )
    return bool(aws_facts(task).ecs_cloudtrail_audit_telemetry_disruption_paths)


def _messaging_established(operation: str) -> Callable[[_Grants], bool]:
    def established(grants: _Grants) -> bool:
        _inventory, task, _service = messaging_tests._normalize(  # pyright: ignore[reportPrivateUsage]
            role_statements=[
                messaging_tests._statement(effect, operation, resource)  # pyright: ignore[reportPrivateUsage]
                for effect, resource in grants
            ]
        )
        return any(path["operation"] == operation for path in aws_facts(task).ecs_messaging_topology_destruction_paths)

    return established


def _dynamodb_table_established(grants: _Grants) -> bool:
    _inventory, task, _service = dynamodb_table_tests._normalize(  # pyright: ignore[reportPrivateUsage]
        role_statements=[
            dynamodb_table_tests._statement(effect, dynamodb_table_tests._DELETE_TABLE, resource)  # pyright: ignore[reportPrivateUsage]
            for effect, resource in grants
        ]
    )
    return any(
        path["operation"] == dynamodb_table_tests._DELETE_TABLE  # pyright: ignore[reportPrivateUsage]
        for path in aws_facts(task).ecs_dynamodb_table_topology_destruction_paths
    )


def _dynamodb_item_established(grants: _Grants) -> bool:
    paths, _uncertainties = dynamodb_item_tests._task_paths(  # pyright: ignore[reportPrivateUsage]
        [
            dynamodb_item_tests._table(),  # pyright: ignore[reportPrivateUsage]
            dynamodb_item_tests._role(  # pyright: ignore[reportPrivateUsage]
                "orders_task",
                dynamodb_item_tests._TASK_ROLE_ARN,  # pyright: ignore[reportPrivateUsage]
                [
                    dynamodb_item_tests._statement(effect, "dynamodb:DeleteItem", resource)  # pyright: ignore[reportPrivateUsage]
                    for effect, resource in grants
                ],
            ),
            dynamodb_item_tests._task_definition(),  # pyright: ignore[reportPrivateUsage]
            dynamodb_item_tests._service(),  # pyright: ignore[reportPrivateUsage]
        ]
    )
    return any(path["operation"] == "dynamodb:DeleteItem" for path in paths)


def _s3_bucket_established(grants: _Grants) -> bool:
    _inventory, task, _service = s3_bucket_tests._normalize(  # pyright: ignore[reportPrivateUsage]
        role_statements=[
            s3_bucket_tests._statement(effect, s3_bucket_tests._DELETE_BUCKET, resource)  # pyright: ignore[reportPrivateUsage]
            for effect, resource in grants
        ]
    )
    return any(
        path["operation"] == s3_bucket_tests._DELETE_BUCKET  # pyright: ignore[reportPrivateUsage]
        for path in aws_facts(task).ecs_s3_bucket_topology_destruction_paths
    )


@dataclass(frozen=True)
class _Family:
    name: str
    established: Callable[[_Grants], bool]
    exact: str
    covering_pattern: str
    prefix_pattern: str
    # S3 bucket ARNs carry no account, so it has no foreign-account pattern.
    foreign_pattern: str | None
    # Whether a wildcard allow establishes a path today. DynamoDB item deletion is
    # left failing closed on purpose: it copies statements from the shared DynamoDB
    # access-path model, which only accepts exact table and index ARNs and also feeds
    # the read, mutation, and index-scope findings, so it needs its own change.
    wildcard_allows_establish: bool


_FAMILIES = (
    _Family(
        "cloudtrail trail",
        _cloudtrail_established,
        cloudtrail_tests._TRAIL_ARN,  # pyright: ignore[reportPrivateUsage]
        f"arn:aws:cloudtrail:*:{_ACCOUNT_ID}:trail/*",
        f"arn:aws:cloudtrail:us-east-1:{_ACCOUNT_ID}:trail/aud*",
        f"arn:aws:cloudtrail:us-east-1:{_FOREIGN_ACCOUNT_ID}:trail/*",
        True,
    ),
    _Family(
        "s3 bucket topology",
        _s3_bucket_established,
        "arn:aws:s3:::orders-data",
        "arn:aws:s3:::*",
        "arn:aws:s3:::orders-*",
        None,
        True,
    ),
    _Family(
        "sqs queue topology",
        _messaging_established(messaging_tests._DELETE_QUEUE),  # pyright: ignore[reportPrivateUsage]
        messaging_tests._QUEUE_ARN,  # pyright: ignore[reportPrivateUsage]
        f"arn:aws:sqs:*:{_ACCOUNT_ID}:*",
        f"arn:aws:sqs:us-east-1:{_ACCOUNT_ID}:ord*",
        f"arn:aws:sqs:us-east-1:{_FOREIGN_ACCOUNT_ID}:*",
        True,
    ),
    _Family(
        "sns topic topology",
        _messaging_established(messaging_tests._DELETE_TOPIC),  # pyright: ignore[reportPrivateUsage]
        messaging_tests._TOPIC_ARN,  # pyright: ignore[reportPrivateUsage]
        f"arn:aws:sns:*:{_ACCOUNT_ID}:*",
        f"arn:aws:sns:us-east-1:{_ACCOUNT_ID}:orders-*",
        f"arn:aws:sns:us-east-1:{_FOREIGN_ACCOUNT_ID}:*",
        True,
    ),
    _Family(
        "dynamodb table topology",
        _dynamodb_table_established,
        dynamodb_table_tests._TABLE_ARN,  # pyright: ignore[reportPrivateUsage]
        f"arn:aws:dynamodb:*:{_ACCOUNT_ID}:table/*",
        f"arn:aws:dynamodb:us-east-1:{_ACCOUNT_ID}:table/ord*",
        f"arn:aws:dynamodb:us-east-1:{_FOREIGN_ACCOUNT_ID}:table/*",
        True,
    ),
    _Family(
        "dynamodb item deletion",
        _dynamodb_item_established,
        dynamodb_item_tests._TABLE_ARN,  # pyright: ignore[reportPrivateUsage]
        f"arn:aws:dynamodb:*:{_ACCOUNT_ID}:table/*",
        f"arn:aws:dynamodb:us-east-1:{_ACCOUNT_ID}:table/ord*",
        f"arn:aws:dynamodb:us-east-1:{_FOREIGN_ACCOUNT_ID}:table/*",
        False,
    ),
)


class AwsEcsWildcardAuthorityParityBaselineTests(unittest.TestCase):
    def test_exact_grants_establish_in_every_family(self) -> None:
        for family in _FAMILIES:
            with self.subTest(family=family.name):
                self.assertTrue(family.established([("Allow", family.exact)]))

    def test_wildcard_allow_baseline(self) -> None:
        for family in _FAMILIES:
            expected = family.wildcard_allows_establish
            shapes = {
                "star": family.established([("Allow", "*")]),
                "covering pattern": family.established([("Allow", family.covering_pattern)]),
                "prefix pattern": family.established([("Allow", family.prefix_pattern)]),
            }
            for shape, established in shapes.items():
                with self.subTest(family=family.name, shape=shape):
                    self.assertEqual(established, expected)

    def test_foreign_account_patterns_never_establish(self) -> None:
        for family in _FAMILIES:
            if family.foreign_pattern is None:
                continue
            with self.subTest(family=family.name):
                self.assertFalse(family.established([("Allow", family.foreign_pattern)]))

    def test_deny_statements_remove_exact_and_wildcard_allows(self) -> None:
        for family in _FAMILIES:
            with self.subTest(family=family.name, case="star deny over exact allow"):
                self.assertFalse(family.established([("Allow", family.exact), ("Deny", "*")]))
            with self.subTest(family=family.name, case="exact deny over star allow"):
                self.assertFalse(family.established([("Allow", "*"), ("Deny", family.exact)]))

    def test_baseline_families_that_fail_closed_on_wildcard_allows_are_the_known_ones(self) -> None:
        failing = sorted(family.name for family in _FAMILIES if not family.wildcard_allows_establish)
        self.assertEqual(
            failing,
            [
                "dynamodb item deletion",
            ],
        )


class AwsEcsTopologyWildcardFixtureTests(unittest.TestCase):
    def test_wildcard_fixture_reports_each_in_plan_target(self) -> None:
        fixture = (
            Path(__file__).resolve().parents[3] / "fixtures" / "aws" / "sample_aws_ecs_topology_wildcard_plan.json"
        )
        findings = {finding.rule_id: finding for finding in TfStride().analyze_plan(fixture).findings}

        table_finding = findings["aws-public-ecs-dynamodb-table-topology-disruption"]
        self.assertIn("aws_dynamodb_table.orders", table_finding.affected_resources)
        self.assertIn("aws_dynamodb_table.archive", table_finding.affected_resources)
        self.assertIn("granted through wildcard resource patterns", table_finding.rationale)

        messaging_finding = findings["aws-public-ecs-messaging-topology-disruption"]
        self.assertIn("aws_sqs_queue.orders", messaging_finding.affected_resources)
        self.assertIn("aws_sns_topic.events", messaging_finding.affected_resources)
        self.assertIn("granted through wildcard resource patterns", messaging_finding.rationale)
