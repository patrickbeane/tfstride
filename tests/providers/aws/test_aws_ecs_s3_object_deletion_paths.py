from __future__ import annotations

import json
import unittest
from typing import Any

from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _ACCOUNT_ID,
    _BUCKET_ARN,
    _EXECUTION_ROLE_ARN,
    _TASK_ROLE_ARN,
    _bucket,
    _resource,
    _role,
    _role_policy_attachment,
    _service,
    _statement,
    _task_definition,
)
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts

_FOREIGN_ACCOUNT_ID = "444455556666"
_FOREIGN_TASK_ROLE_ARN = f"arn:aws:iam::{_FOREIGN_ACCOUNT_ID}:role/orders-task"


def _bucket_policy(statements: list[dict[str, Any]]) -> TerraformResource:
    return _resource(
        "aws_s3_bucket_policy",
        "orders",
        {
            "bucket": "orders-data",
            "policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": statements,
                }
            ),
        },
    )


def _bucket_statement(
    effect: str,
    actions: str | list[str],
    resources: str | list[str],
    principal: str,
    *,
    condition: dict[str, Any] | None = None,
) -> dict[str, Any]:
    statement = _statement(effect, actions, resources, condition=condition)
    statement["Principal"] = {"AWS": principal}
    return statement


def _versioning(status: str | None, *, unknown: bool = False) -> TerraformResource:
    values: dict[str, Any] = {
        "bucket": "orders-data",
        "versioning_configuration": [{} if status is None else {"status": status}],
    }
    return TerraformResource(
        address="aws_s3_bucket_versioning.orders",
        mode="managed",
        resource_type="aws_s3_bucket_versioning",
        name="orders",
        provider_name="registry.terraform.io/hashicorp/aws",
        provider_config_key="aws",
        values=values,
        unknown_values=({"versioning_configuration": [{"status": True}]} if unknown else {}),
    )


def _object_lock(mode: str = "GOVERNANCE") -> TerraformResource:
    return TerraformResource(
        address="aws_s3_bucket_object_lock_configuration.orders",
        mode="managed",
        resource_type="aws_s3_bucket_object_lock_configuration",
        name="orders",
        provider_name="registry.terraform.io/hashicorp/aws",
        provider_config_key="aws",
        values={
            "bucket": "orders-data",
            "object_lock_enabled": "Enabled",
            "rule": [
                {
                    "default_retention": [
                        {
                            "mode": mode,
                            "days": 30,
                        }
                    ]
                }
            ],
        },
    )


def _caller_identity(account_id: str = _ACCOUNT_ID) -> TerraformResource:
    return TerraformResource(
        address="data.aws_caller_identity.current",
        mode="data",
        resource_type="aws_caller_identity",
        name="current",
        provider_name="registry.terraform.io/hashicorp/aws",
        provider_config_key="aws",
        values={
            "account_id": account_id,
            "id": account_id,
            "arn": f"arn:aws:iam::{account_id}:root",
        },
    )


def _normalize(resources: list[TerraformResource]):
    # Authorization cases in this suite assume a managed bucket with proven
    # local ownership. Ownership-absence cases exercise the normalizer directly.
    if not any(resource.resource_type == "aws_caller_identity" for resource in resources):
        resources = [_caller_identity(), *resources]
    return AwsNormalizer().normalize(resources)


def _unresolved_bucket_policy(
    name: str,
    statements: list[dict[str, Any]],
) -> TerraformResource:
    return _resource(
        "aws_s3_bucket_policy",
        name,
        {
            "bucket": f"aws_s3_bucket.{name}.id",
            "policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": statements,
                }
            ),
        },
    )


class AwsEcsS3ObjectDeletionPathTests(unittest.TestCase):
    def test_task_role_deletion_paths_preserve_scope_recovery_and_service_projection(
        self,
    ) -> None:
        inventory = _normalize(
            [
                _bucket(),
                _versioning("Enabled"),
                _object_lock(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement("Allow", "s3:DeleteObject", f"{_BUCKET_ARN}/*"),
                        _statement(
                            "Allow",
                            "s3:DeleteObjectVersion",
                            f"{_BUCKET_ARN}/private/*",
                        ),
                        _statement(
                            "Allow",
                            "s3:BypassGovernanceRetention",
                            f"{_BUCKET_ARN}/private/*",
                        ),
                        _statement(
                            "Allow",
                            [
                                "s3:DeleteObjectTagging",
                                "s3:DeleteObjectVersionTagging",
                            ],
                            f"{_BUCKET_ARN}/*",
                        ),
                    ],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert task_definition is not None
        assert service is not None

        task_paths = aws_facts(task_definition).ecs_s3_object_deletion_paths
        service_paths = aws_facts(service).ecs_s3_object_deletion_paths
        self.assertEqual(len(task_paths), 2)
        self.assertEqual(len(service_paths), 2)
        self.assertEqual(
            {path["operation"] for path in task_paths},
            {"s3:DeleteObject", "s3:DeleteObjectVersion"},
        )
        self.assertFalse(any("Tagging" in action for path in task_paths for action in path["matched_actions"]))

        logical = next(path for path in task_paths if path["operation"] == "s3:DeleteObject")
        self.assertEqual(logical["internal_operation"], "delete_current_object")
        self.assertEqual(logical["target_granularity"], "bucket_object_namespace")
        self.assertIsNone(logical["object_key"])
        self.assertEqual(logical["target_scope"], f"{_BUCKET_ARN}/*")
        self.assertEqual(logical["authorization_bases"], ["identity_policy"])
        self.assertTrue(logical["same_account"])
        self.assertEqual(
            logical["lifecycle_compatibility_state"],
            "recoverable_delete_marker",
        )
        self.assertEqual(logical["recovery_evidence"]["versioning_status"], "Enabled")
        self.assertFalse(logical["recovery_evidence"]["bypass_governance_retention_authorized"])

        version = next(path for path in task_paths if path["operation"] == "s3:DeleteObjectVersion")
        self.assertEqual(version["internal_operation"], "delete_object_version")
        self.assertEqual(
            version["target_granularity"],
            "object_prefix_version_namespace",
        )
        self.assertEqual(version["object_key"], "private/")
        self.assertIsNone(version["object_version"])
        self.assertEqual(version["target_scope"], f"{_BUCKET_ARN}/private/*")
        self.assertEqual(version["lifecycle_compatibility_state"], "unknown")
        self.assertTrue(version["recovery_evidence"]["bypass_governance_retention_authorized"])
        self.assertEqual(
            version["recovery_evidence"]["object_lock_default_retention_mode"],
            "GOVERNANCE",
        )
        self.assertIn(
            "aws_s3_bucket_object_lock_configuration.orders",
            version["target_model_evidence_addresses"],
        )

        self.assertTrue(all(path["workload_address"] == service.address for path in service_paths))
        self.assertTrue(all(path["task_definition_address"] == task_definition.address for path in service_paths))
        self.assertTrue(all(path["internet_facing_load_balancers"] == [] for path in service_paths))

    def test_exact_prefix_and_bucket_scopes_remain_distinct_for_both_operations(
        self,
    ) -> None:
        resources = [
            f"{_BUCKET_ARN}/export.json",
            f"{_BUCKET_ARN}/private/*",
            f"{_BUCKET_ARN}/*",
        ]
        inventory = _normalize(
            [
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            ["s3:DeleteObject", "s3:DeleteObjectVersion"],
                            resources,
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        paths = aws_facts(task_definition).ecs_s3_object_deletion_paths
        self.assertEqual(len(paths), 6)
        logical = {path["target_granularity"]: path for path in paths if path["operation"] == "s3:DeleteObject"}
        self.assertEqual(
            set(logical),
            {"object", "object_prefix", "bucket_object_namespace"},
        )
        self.assertEqual(logical["object"]["object_key"], "export.json")
        self.assertEqual(logical["object_prefix"]["object_key"], "private/")
        self.assertIsNone(logical["bucket_object_namespace"]["object_key"])

        versioned = {
            path["target_granularity"]: path for path in paths if path["operation"] == "s3:DeleteObjectVersion"
        }
        self.assertEqual(
            set(versioned),
            {
                "object_version_namespace",
                "object_prefix_version_namespace",
                "bucket_object_version_namespace",
            },
        )
        self.assertTrue(all(path["object_version"] is None for path in versioned.values()))

    def test_same_account_direct_bucket_policy_authorizes_exact_role(self) -> None:
        inventory = _normalize(
            [
                _bucket(),
                _role("orders_task", _TASK_ROLE_ARN),
                _bucket_policy(
                    [
                        _bucket_statement(
                            "Allow",
                            "s3:DeleteObject",
                            f"{_BUCKET_ARN}/export.json",
                            _TASK_ROLE_ARN,
                        )
                    ]
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        path = aws_facts(task_definition).ecs_s3_object_deletion_paths[0]
        self.assertEqual(path["authorization_bases"], ["bucket_policy_direct"])
        self.assertEqual(path["target_granularity"], "object")
        self.assertEqual(
            path["bucket_policy_source_addresses"],
            ["aws_s3_bucket_policy.orders"],
        )
        self.assertEqual(
            path["authorization_source_addresses"],
            ["aws_s3_bucket_policy.orders"],
        )
        self.assertEqual(path["bucket_policy_statements"][0]["principal_match"], "role")

    def test_cross_account_requires_identity_and_bucket_policy_authority(self) -> None:
        base = [
            _caller_identity(),
            _bucket(),
            _role(
                "orders_task",
                _FOREIGN_TASK_ROLE_ARN,
                [
                    _statement(
                        "Allow",
                        "s3:DeleteObject",
                        f"{_BUCKET_ARN}/export.json",
                    )
                ],
            ),
            _task_definition(
                task_role_arn=_FOREIGN_TASK_ROLE_ARN,
                execution_role_arn=None,
            ),
        ]
        allowed_inventory = _normalize(
            [
                *base,
                _bucket_policy(
                    [
                        _bucket_statement(
                            "Allow",
                            "s3:DeleteObject",
                            f"{_BUCKET_ARN}/private/*",
                            _FOREIGN_TASK_ROLE_ARN,
                        ),
                        _bucket_statement(
                            "Allow",
                            "s3:DeleteObject",
                            f"{_BUCKET_ARN}/export.json",
                            _FOREIGN_TASK_ROLE_ARN,
                        ),
                    ]
                ),
            ]
        )
        task_definition = allowed_inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None
        paths = aws_facts(task_definition).ecs_s3_object_deletion_paths
        self.assertEqual(len(paths), 1)
        self.assertFalse(paths[0]["same_account"])
        self.assertEqual(
            paths[0]["authorization_bases"],
            ["cross_account_identity_and_bucket_policy"],
        )
        self.assertEqual(paths[0]["target_scope"], f"{_BUCKET_ARN}/export.json")

        identity_only_inventory = _normalize(base)
        task_definition = identity_only_inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None
        self.assertEqual(
            aws_facts(task_definition).ecs_s3_object_deletion_paths,
            [],
        )

    def test_explicit_bucket_deny_wins_and_conditional_deny_remains_uncertain(
        self,
    ) -> None:
        role = _role(
            "orders_task",
            _TASK_ROLE_ARN,
            [_statement("Allow", "s3:DeleteObject", f"{_BUCKET_ARN}/*")],
        )
        denied_inventory = _normalize(
            [
                _bucket(),
                role,
                _bucket_policy(
                    [
                        _bucket_statement(
                            "Deny",
                            "s3:DeleteObject",
                            f"{_BUCKET_ARN}/*",
                            "*",
                        )
                    ]
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = denied_inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None
        denied_facts = aws_facts(task_definition)
        self.assertEqual(denied_facts.ecs_s3_object_deletion_paths, [])
        self.assertFalse(
            any(
                "runtime policy conditions" in uncertainty
                for uncertainty in denied_facts.ecs_s3_object_deletion_path_uncertainties
            )
        )

        conditional_inventory = _normalize(
            [
                _bucket(),
                role,
                _bucket_policy(
                    [
                        _bucket_statement(
                            "Deny",
                            "s3:DeleteObject",
                            f"{_BUCKET_ARN}/*",
                            "*",
                            condition={"StringNotEquals": {"aws:SourceVpc": "vpc-123"}},
                        )
                    ]
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = conditional_inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None
        conditional_facts = aws_facts(task_definition)
        self.assertEqual(conditional_facts.ecs_s3_object_deletion_paths, [])
        self.assertTrue(
            any(
                "condition-dependent deny evidence" in uncertainty
                for uncertainty in conditional_facts.ecs_s3_object_deletion_path_uncertainties
            )
        )

    def test_incomplete_identity_policy_and_unsupported_bucket_scope_fail_closed(
        self,
    ) -> None:
        policy_arn = "arn:aws:iam::aws:policy/ExternalS3Delete"
        incomplete_inventory = _normalize(
            [
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", "s3:DeleteObject", f"{_BUCKET_ARN}/*")],
                ),
                _role_policy_attachment(_TASK_ROLE_ARN, policy_arn),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = incomplete_inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None
        facts = aws_facts(task_definition)
        self.assertEqual(facts.ecs_s3_object_deletion_paths, [])
        self.assertTrue(
            any(
                "identity-policy evidence is incomplete" in uncertainty
                for uncertainty in facts.ecs_s3_object_deletion_path_uncertainties
            )
        )

        wildcard_inventory = _normalize(
            [
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "s3:DeleteObject",
                            "arn:aws:s3:::orders-*/*",
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = wildcard_inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None
        wildcard_facts = aws_facts(task_definition)
        self.assertEqual(wildcard_facts.ecs_s3_object_deletion_paths, [])
        self.assertTrue(
            any(
                "does not identify an exact object scope" in uncertainty
                for uncertainty in wildcard_facts.ecs_s3_object_deletion_path_uncertainties
            )
        )

    def test_conditional_allow_incomplete_bucket_policy_and_partial_deny_remain_uncertain(
        self,
    ) -> None:
        conditional_inventory = _normalize(
            [
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "s3:DeleteObject",
                            f"{_BUCKET_ARN}/export.json",
                            condition={"StringEquals": {"aws:SourceVpc": "vpc-123"}},
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = conditional_inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None
        conditional_facts = aws_facts(task_definition)
        self.assertEqual(conditional_facts.ecs_s3_object_deletion_paths, [])
        self.assertTrue(
            any(
                "depends on runtime policy conditions" in uncertainty
                for uncertainty in conditional_facts.ecs_s3_object_deletion_path_uncertainties
            )
        )

        malformed_policy = {
            "Effect": "Deny",
            "Action": "s3:DeleteObject",
            "Resource": f"{_BUCKET_ARN}/*",
            "NotPrincipal": {"AWS": _TASK_ROLE_ARN},
        }
        incomplete_inventory = _normalize(
            [
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "s3:DeleteObject",
                            f"{_BUCKET_ARN}/export.json",
                        )
                    ],
                ),
                _bucket_policy([malformed_policy]),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = incomplete_inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None
        incomplete_facts = aws_facts(task_definition)
        self.assertEqual(incomplete_facts.ecs_s3_object_deletion_paths, [])
        self.assertTrue(
            any(
                "bucket policy" in uncertainty and "incomplete" in uncertainty
                for uncertainty in incomplete_facts.ecs_s3_object_deletion_path_uncertainties
            )
        )

        partially_denied_inventory = _normalize(
            [
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement("Allow", "s3:DeleteObject", f"{_BUCKET_ARN}/*"),
                        _statement(
                            "Deny",
                            "s3:DeleteObject",
                            f"{_BUCKET_ARN}/private/*",
                        ),
                    ],
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = partially_denied_inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None
        partial_facts = aws_facts(task_definition)
        self.assertEqual(partial_facts.ecs_s3_object_deletion_paths, [])
        self.assertTrue(
            any(
                "residual object scope is not representable" in uncertainty
                for uncertainty in partial_facts.ecs_s3_object_deletion_path_uncertainties
            )
        )

    def test_unresolved_bucket_policy_target_for_task_role_remains_uncertain(self) -> None:
        unresolved_policy = _resource(
            "aws_s3_bucket_policy",
            "dynamic",
            {
                "bucket": "aws_s3_bucket.dynamic.id",
                "policy": json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            _bucket_statement(
                                "Allow",
                                "s3:DeleteObject",
                                f"{_BUCKET_ARN}/*",
                                _TASK_ROLE_ARN,
                            )
                        ],
                    }
                ),
            },
        )
        inventory = _normalize(
            [
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "s3:DeleteObject",
                            f"{_BUCKET_ARN}/*",
                        )
                    ],
                ),
                unresolved_policy,
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None
        facts = aws_facts(task_definition)
        self.assertEqual(facts.ecs_s3_object_deletion_paths, [])
        self.assertTrue(
            any(
                "unresolved S3 bucket-policy target" in uncertainty and "may affect" in uncertainty
                for uncertainty in facts.ecs_s3_object_deletion_path_uncertainties
            )
        )

    def test_unresolved_version_deletion_policy_does_not_suppress_logical_deletion(
        self,
    ) -> None:
        unresolved_policy = _unresolved_bucket_policy(
            "version_dynamic",
            [
                _bucket_statement(
                    "Allow",
                    "s3:DeleteObjectVersion",
                    f"{_BUCKET_ARN}/*",
                    _TASK_ROLE_ARN,
                )
            ],
        )
        inventory = _normalize(
            [
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "s3:DeleteObject",
                            f"{_BUCKET_ARN}/*",
                        )
                    ],
                ),
                unresolved_policy,
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None
        facts = aws_facts(task_definition)

        self.assertEqual(
            [path["operation"] for path in facts.ecs_s3_object_deletion_paths],
            ["s3:DeleteObject"],
        )
        self.assertTrue(
            any(
                unresolved_policy.address in uncertainty and "s3:DeleteObjectVersion authorization" in uncertainty
                for uncertainty in facts.ecs_s3_object_deletion_path_uncertainties
            )
        )

    def test_unresolved_logical_deletion_policy_does_not_suppress_version_deletion(
        self,
    ) -> None:
        unresolved_policy = _unresolved_bucket_policy(
            "logical_dynamic",
            [
                _bucket_statement(
                    "Allow",
                    "s3:DeleteObject",
                    f"{_BUCKET_ARN}/*",
                    _TASK_ROLE_ARN,
                )
            ],
        )
        inventory = _normalize(
            [
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "s3:DeleteObjectVersion",
                            f"{_BUCKET_ARN}/*",
                        )
                    ],
                ),
                unresolved_policy,
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None
        facts = aws_facts(task_definition)

        self.assertEqual(
            [path["operation"] for path in facts.ecs_s3_object_deletion_paths],
            ["s3:DeleteObjectVersion"],
        )
        self.assertTrue(
            any(
                unresolved_policy.address in uncertainty and "s3:DeleteObject authorization" in uncertainty
                for uncertainty in facts.ecs_s3_object_deletion_path_uncertainties
            )
        )

    def test_unresolved_bypass_policy_preserves_version_deletion_with_recovery_uncertainty(
        self,
    ) -> None:
        unresolved_policy = _unresolved_bucket_policy(
            "bypass_dynamic",
            [
                _bucket_statement(
                    "Allow",
                    "s3:BypassGovernanceRetention",
                    f"{_BUCKET_ARN}/*",
                    _TASK_ROLE_ARN,
                )
            ],
        )
        inventory = _normalize(
            [
                _bucket(),
                _object_lock(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "s3:DeleteObjectVersion",
                            f"{_BUCKET_ARN}/*",
                        )
                    ],
                ),
                unresolved_policy,
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None
        facts = aws_facts(task_definition)

        self.assertEqual(len(facts.ecs_s3_object_deletion_paths), 1)
        path = facts.ecs_s3_object_deletion_paths[0]
        self.assertEqual(path["operation"], "s3:DeleteObjectVersion")
        self.assertIsNone(path["recovery_evidence"]["bypass_governance_retention_authorized"])
        self.assertTrue(
            any(
                "s3:BypassGovernanceRetention authority is condition-dependent or unresolved" in uncertainty
                for uncertainty in path["recovery_evidence"]["uncertainties"]
            )
        )

    def test_malformed_relevant_unresolved_policy_suppresses_all_modeled_operations(
        self,
    ) -> None:
        unresolved_policy = _unresolved_bucket_policy(
            "malformed_dynamic",
            [
                {
                    "Effect": "Allow",
                    "NotAction": "s3:GetObject",
                    "Resource": f"{_BUCKET_ARN}/*",
                    "Principal": {"AWS": _TASK_ROLE_ARN},
                }
            ],
        )
        inventory = _normalize(
            [
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            ["s3:DeleteObject", "s3:DeleteObjectVersion"],
                            f"{_BUCKET_ARN}/*",
                        )
                    ],
                ),
                unresolved_policy,
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None
        facts = aws_facts(task_definition)

        self.assertEqual(facts.ecs_s3_object_deletion_paths, [])
        for action in (
            "s3:DeleteObject",
            "s3:DeleteObjectVersion",
            "s3:BypassGovernanceRetention",
        ):
            with self.subTest(action=action):
                self.assertTrue(
                    any(
                        unresolved_policy.address in uncertainty and f"{action} authorization" in uncertainty
                        for uncertainty in facts.ecs_s3_object_deletion_path_uncertainties
                    )
                )

    def test_unrelated_unresolved_bucket_policies_do_not_contaminate_exact_path(
        self,
    ) -> None:
        archive_bucket_arn = "arn:aws:s3:::orders-archive"
        other_role_arn = f"arn:aws:iam::{_ACCOUNT_ID}:role/archive-task"
        archive_policy = _resource(
            "aws_s3_bucket_policy",
            "archive_dynamic",
            {
                "bucket": "aws_s3_bucket.archive.id",
                "policy": json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            _bucket_statement(
                                "Allow",
                                "s3:DeleteObject",
                                f"{archive_bucket_arn}/*",
                                _TASK_ROLE_ARN,
                            )
                        ],
                    }
                ),
            },
        )
        other_principal_policy = _resource(
            "aws_s3_bucket_policy",
            "other_principal_dynamic",
            {
                "bucket": "aws_s3_bucket.dynamic.id",
                "policy": json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            _bucket_statement(
                                "Allow",
                                "s3:DeleteObject",
                                f"{_BUCKET_ARN}/*",
                                other_role_arn,
                            )
                        ],
                    }
                ),
            },
        )
        inventory = _normalize(
            [
                _bucket(),
                _bucket("archive", arn=archive_bucket_arn),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "s3:DeleteObject",
                            f"{_BUCKET_ARN}/*",
                        )
                    ],
                ),
                archive_policy,
                other_principal_policy,
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None
        facts = aws_facts(task_definition)

        self.assertEqual(len(facts.ecs_s3_object_deletion_paths), 1)
        self.assertEqual(
            facts.ecs_s3_object_deletion_paths[0]["bucket_address"],
            "aws_s3_bucket.orders",
        )
        self.assertFalse(
            any(
                archive_policy.address in uncertainty and "for aws_s3_bucket.orders" in uncertainty
                for uncertainty in facts.ecs_s3_object_deletion_path_uncertainties
            )
        )
        self.assertTrue(
            any(
                archive_policy.address in uncertainty and "for aws_s3_bucket.archive" in uncertainty
                for uncertainty in facts.ecs_s3_object_deletion_path_uncertainties
            )
        )
        self.assertFalse(
            any(
                other_principal_policy.address in uncertainty
                for uncertainty in facts.ecs_s3_object_deletion_path_uncertainties
            )
        )

    def test_execution_role_authority_never_becomes_runtime_deletion_path(self) -> None:
        inventory = _normalize(
            [
                _bucket(),
                _role("orders_task", _TASK_ROLE_ARN),
                _role(
                    "orders_execution",
                    _EXECUTION_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            ["s3:DeleteObject", "s3:DeleteObjectVersion"],
                            f"{_BUCKET_ARN}/*",
                        )
                    ],
                ),
                _task_definition(),
                _service(),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert task_definition is not None
        assert service is not None
        self.assertEqual(
            aws_facts(task_definition).ecs_s3_object_deletion_paths,
            [],
        )
        self.assertEqual(aws_facts(service).ecs_s3_object_deletion_paths, [])

    def test_suspended_versioning_does_not_overclaim_recoverability(self) -> None:
        inventory = _normalize(
            [
                _bucket(),
                _versioning("Suspended"),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", "s3:DeleteObject", f"{_BUCKET_ARN}/*")],
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None
        path = aws_facts(task_definition).ecs_s3_object_deletion_paths[0]
        self.assertEqual(path["lifecycle_compatibility_state"], "unknown")
        self.assertTrue(
            any("null version" in uncertainty for uncertainty in path["recovery_evidence"]["uncertainties"])
        )


if __name__ == "__main__":
    unittest.main()
