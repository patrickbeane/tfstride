from __future__ import annotations

import json
import unittest
from typing import Any, Literal

from tfstride.models import (
    TerraformReferenceProvenance,
    TerraformReferenceResolution,
    TerraformReferenceResolutionState,
    TerraformReferenceTarget,
    TerraformResource,
)
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.policy_documents import parse_policy_statement
from tfstride.providers.aws.resource_decoration.ecs_dynamodb_table_topology_destruction_paths import (
    current_ecs_dynamodb_table_topology_destruction_path,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import (
    AwsDecorationContext,
    AwsResourceIndexBuilder,
)

_ACCOUNT_ID = "111122223333"
_FOREIGN_ACCOUNT_ID = "444455556666"
_TASK_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:role/orders-task"
_EXECUTION_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:role/orders-execution"
_TABLE_ARN = f"arn:aws:dynamodb:us-east-1:{_ACCOUNT_ID}:table/orders"
_FOREIGN_TABLE_ARN = f"arn:aws:dynamodb:us-east-1:{_FOREIGN_ACCOUNT_ID}:table/orders"
_DELETE_TABLE = "dynamodb:DeleteTable"


def _resource(
    resource_type: str,
    name: str,
    values: dict[str, Any],
    *,
    provider_config_key: str | None = None,
    unknown_values: dict[str, Any] | None = None,
    reference_resolutions: tuple[TerraformReferenceResolution, ...] = (),
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        provider_config_key=provider_config_key,
        values=values,
        unknown_values=unknown_values or {},
        reference_resolutions=reference_resolutions,
    )


def _caller_identity(
    account_id: str,
    *,
    provider_config_key: str | None = None,
    name: str = "current",
) -> TerraformResource:
    resource = _resource(
        "aws_caller_identity",
        name,
        {
            "account_id": account_id,
            "id": account_id,
            "arn": f"arn:aws:iam::{account_id}:root",
        },
        provider_config_key=provider_config_key,
    )
    resource.mode = "data"
    return resource


def _statement(
    effect: str,
    actions: str | list[str],
    resources: str | list[str],
    *,
    principal: str | None = None,
    condition: dict[str, Any] | None = None,
    not_action: str | None = None,
) -> dict[str, Any]:
    statement: dict[str, Any] = {
        "Effect": effect,
        "Action": actions,
        "Resource": resources,
    }
    if principal is not None:
        statement["Principal"] = {"AWS": principal}
    if condition is not None:
        statement["Condition"] = condition
    if not_action is not None:
        statement.pop("Action")
        statement["NotAction"] = not_action
    return statement


def _role(
    statements: list[dict[str, Any]],
    *,
    arn: str | None = _TASK_ROLE_ARN,
    name: str = "orders_task",
    provider_config_key: str | None = None,
    reference_resolutions: tuple[TerraformReferenceResolution, ...] = (),
) -> TerraformResource:
    values: dict[str, Any] = {
        "name": name,
        "arn": arn,
    }
    if statements:
        values["inline_policy"] = [
            {
                "name": "dynamodb-administration",
                "policy": json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": statements,
                    }
                ),
            }
        ]
    return _resource(
        "aws_iam_role",
        name,
        values,
        provider_config_key=provider_config_key,
        reference_resolutions=reference_resolutions,
    )


def _table(
    *,
    arn: str | None = _TABLE_ARN,
    deletion_protection: Literal["enabled", "disabled", "omitted", "unknown"] = "omitted",
    pitr: Literal["enabled", "disabled", "omitted", "unknown"] = "enabled",
    provider_config_key: str | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": "orders",
        "name": "orders",
        "arn": arn,
    }
    unknown_values: dict[str, Any] = {}
    if deletion_protection == "enabled":
        values["deletion_protection_enabled"] = True
    elif deletion_protection == "disabled":
        values["deletion_protection_enabled"] = False
    elif deletion_protection == "unknown":
        unknown_values["deletion_protection_enabled"] = True
    if pitr == "enabled":
        values["point_in_time_recovery"] = [
            {
                "enabled": True,
                "recovery_period_in_days": 14,
            }
        ]
    elif pitr == "disabled":
        values["point_in_time_recovery"] = [{"enabled": False}]
    elif pitr == "unknown":
        unknown_values["point_in_time_recovery"] = True
    return _resource(
        "aws_dynamodb_table",
        "orders",
        values,
        provider_config_key=provider_config_key,
        unknown_values=unknown_values,
    )


def _resource_policy(
    statements: list[dict[str, Any]],
    *,
    target_reference: str | None = _TABLE_ARN,
    provider_config_key: str | None = None,
    unknown_policy: bool = False,
    reference_resolutions: tuple[TerraformReferenceResolution, ...] = (),
) -> TerraformResource:
    values: dict[str, Any] = {"resource_arn": target_reference}
    if not unknown_policy:
        values["policy"] = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": statements,
            }
        )
    return _resource(
        "aws_dynamodb_resource_policy",
        "orders",
        values,
        provider_config_key=provider_config_key,
        unknown_values={"policy": True} if unknown_policy else {},
        reference_resolutions=reference_resolutions,
    )


def _task_definition(
    *,
    task_role_arn: str | None = _TASK_ROLE_ARN,
    execution_role_arn: str | None = _EXECUTION_ROLE_ARN,
    provider_config_key: str | None = None,
    reference_resolutions: tuple[TerraformReferenceResolution, ...] = (),
) -> TerraformResource:
    return _resource(
        "aws_ecs_task_definition",
        "orders",
        {
            "family": "orders",
            "revision": 1,
            "network_mode": "awsvpc",
            "container_definitions": '[{"name":"orders","portMappings":[{"containerPort":8080,"protocol":"tcp"}]}]',
            "task_role_arn": task_role_arn,
            "execution_role_arn": execution_role_arn,
        },
        provider_config_key=provider_config_key,
        reference_resolutions=reference_resolutions,
    )


def _service(
    *,
    provider_config_key: str | None = None,
) -> TerraformResource:
    return _resource(
        "aws_ecs_service",
        "orders",
        {
            "name": "orders",
            "task_definition": "orders:1",
        },
        provider_config_key=provider_config_key,
    )


def _symbolic_resolution(
    path: tuple[str | int, ...],
    reference: str,
    target_address: str,
    *,
    state: TerraformReferenceResolutionState = (TerraformReferenceResolutionState.SYMBOLIC),
) -> TerraformReferenceResolution:
    return TerraformReferenceResolution(
        path=path,
        state=state,
        provenance=TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
        references=(reference,),
        targets=(
            TerraformReferenceTarget(
                address=target_address,
                reference=reference,
            ),
        ),
    )


def _normalize(
    *,
    role_statements: list[dict[str, Any]] | None = None,
    table: TerraformResource | None = None,
    role: TerraformResource | None = None,
    task_definition: TerraformResource | None = None,
    resource_policy: TerraformResource | None = None,
    provider_config_key: str | None = None,
    extra: list[TerraformResource] | None = None,
):
    resources = [
        table or _table(provider_config_key=provider_config_key),
        role
        or _role(
            role_statements or [],
            provider_config_key=provider_config_key,
        ),
    ]
    if resource_policy is not None:
        resources.append(resource_policy)
    resources.extend(
        [
            task_definition or _task_definition(provider_config_key=provider_config_key),
            _service(provider_config_key=provider_config_key),
            *(extra or []),
        ]
    )
    inventory = AwsNormalizer().normalize(resources)
    task = inventory.get_by_address("aws_ecs_task_definition.orders")
    service = inventory.get_by_address("aws_ecs_service.orders")
    assert task is not None
    assert service is not None
    return inventory, task, service


class AwsEcsDynamoDbTableTopologyDestructionPathTests(unittest.TestCase):
    def test_task_role_authority_projects_exact_table_and_recovery_evidence(
        self,
    ) -> None:
        inventory, task, service = _normalize(
            role_statements=[
                _statement(
                    "Allow",
                    [_DELETE_TABLE, "dynamodb:UpdateTable"],
                    _TABLE_ARN,
                )
            ],
        )

        task_paths = aws_facts(task).ecs_dynamodb_table_topology_destruction_paths
        service_paths = aws_facts(service).ecs_dynamodb_table_topology_destruction_paths
        self.assertEqual(len(task_paths), 1)
        self.assertEqual(len(service_paths), 1)
        path = task_paths[0]
        self.assertEqual(path["role_kind"], "ecs_task_role")
        self.assertEqual(path["credential_context"], "workload_runtime")
        self.assertEqual(path["table_address"], "aws_dynamodb_table.orders")
        self.assertEqual(path["table_arn"], _TABLE_ARN)
        self.assertEqual(path["operation"], _DELETE_TABLE)
        self.assertEqual(path["matched_actions"], [_DELETE_TABLE])
        self.assertEqual(path["grant_basis"], "same_account_identity_policy")
        self.assertEqual(path["target_scope"], "exact_dynamodb_table")
        self.assertFalse(path["explicit_deny"])
        self.assertFalse(path["conditional_evaluation_required"])
        self.assertEqual(
            path["deletion_constraint_evidence"],
            {
                "constraint_evidence_scope": ("dynamodb_table_deletion_protection"),
                "deletion_protection_state": "not_configured",
                "deletion_protection_enabled": False,
                "provider_default_applied": True,
                "deletion_compatibility_state": "compatible",
                "uncertainties": [],
            },
        )
        recovery = path["recovery_evidence"]
        self.assertEqual(recovery["pitr_state"], "enabled")
        self.assertEqual(recovery["restore_target_kind"], "new_table")
        self.assertFalse(recovery["successful_deletion_observed"])
        self.assertFalse(recovery["restoration_observed"])
        self.assertFalse(recovery["descendant_impact_evaluated"])
        self.assertFalse(recovery["out_of_plan_table_topology_evaluated"])
        self.assertIn(
            "aws_dynamodb_resource_policy",
            inventory.metadata["supported_resource_types"],
        )

    def test_execution_role_delete_authority_cannot_substitute_for_task_role(
        self,
    ) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _table(),
                _role([], name="orders_task"),
                _role(
                    [
                        _statement(
                            "Allow",
                            _DELETE_TABLE,
                            _TABLE_ARN,
                        )
                    ],
                    arn=_EXECUTION_ROLE_ARN,
                    name="orders_execution",
                ),
                _task_definition(),
                _service(),
            ]
        )
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert service is not None
        self.assertEqual(
            aws_facts(service).ecs_dynamodb_table_topology_destruction_paths,
            [],
        )

    def test_deny_conditional_incomplete_and_non_exact_authority_fail_closed(
        self,
    ) -> None:
        cases = {
            "explicit deny": _normalize(
                role_statements=[
                    _statement("Allow", _DELETE_TABLE, _TABLE_ARN),
                    _statement("Deny", _DELETE_TABLE, _TABLE_ARN),
                ],
            ),
            "conditional allow": _normalize(
                role_statements=[
                    _statement(
                        "Allow",
                        _DELETE_TABLE,
                        _TABLE_ARN,
                        condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
                    )
                ],
            ),
            "wildcard target": _normalize(
                role_statements=[
                    _statement(
                        "Allow",
                        _DELETE_TABLE,
                        f"arn:aws:dynamodb:us-east-1:{_ACCOUNT_ID}:table/*",
                    )
                ],
            ),
            "index target": _normalize(
                role_statements=[
                    _statement(
                        "Allow",
                        _DELETE_TABLE,
                        f"{_TABLE_ARN}/index/by-status",
                    )
                ],
            ),
            "unknown table policy": _normalize(
                role_statements=[_statement("Allow", _DELETE_TABLE, _TABLE_ARN)],
                resource_policy=_resource_policy(
                    [],
                    unknown_policy=True,
                ),
            ),
        }
        for case, (_inventory, task, _service_resource) in cases.items():
            with self.subTest(case=case):
                self.assertEqual(
                    aws_facts(task).ecs_dynamodb_table_topology_destruction_paths,
                    [],
                )

    def test_wildcard_action_is_operation_exact_and_replica_delete_is_separate(
        self,
    ) -> None:
        _inventory, task, _service_resource = _normalize(
            role_statements=[_statement("Allow", "dynamodb:*", _TABLE_ARN)],
        )
        paths = aws_facts(task).ecs_dynamodb_table_topology_destruction_paths
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["matched_actions"], [_DELETE_TABLE])
        self.assertEqual(
            paths[0]["authorization_statements"][0]["matching_action_patterns"],
            ["dynamodb:*"],
        )

        _inventory, task, _service_resource = _normalize(
            role_statements=[
                _statement(
                    "Allow",
                    "dynamodb:DeleteTableReplica",
                    _TABLE_ARN,
                )
            ],
        )
        self.assertEqual(
            aws_facts(task).ecs_dynamodb_table_topology_destruction_paths,
            [],
        )

    def test_same_account_resource_policy_direct_and_combined_bases_are_distinct(
        self,
    ) -> None:
        direct_policy = _resource_policy(
            [
                _statement(
                    "Allow",
                    _DELETE_TABLE,
                    _TABLE_ARN,
                    principal=_TASK_ROLE_ARN,
                )
            ]
        )
        _inventory, task, _service_resource = _normalize(
            resource_policy=direct_policy,
        )
        direct = aws_facts(task).ecs_dynamodb_table_topology_destruction_paths
        self.assertEqual(len(direct), 1)
        self.assertEqual(
            direct[0]["grant_basis"],
            "same_account_table_policy_direct",
        )
        self.assertEqual(
            direct[0]["resource_policy_principal_match"],
            "role",
        )

        _inventory, task, _service_resource = _normalize(
            role_statements=[_statement("Allow", _DELETE_TABLE, _TABLE_ARN)],
            resource_policy=_resource_policy(
                [
                    _statement(
                        "Allow",
                        _DELETE_TABLE,
                        _TABLE_ARN,
                        principal="*",
                    )
                ]
            ),
        )
        combined = aws_facts(task).ecs_dynamodb_table_topology_destruction_paths
        self.assertEqual(len(combined), 1)
        self.assertEqual(
            combined[0]["grant_basis"],
            "same_account_combined",
        )
        self.assertEqual(
            combined[0]["resource_policy_principal_match"],
            "wildcard",
        )

        _inventory, task, _service_resource = _normalize(
            resource_policy=_resource_policy(
                [
                    _statement(
                        "Allow",
                        _DELETE_TABLE,
                        _TABLE_ARN,
                        principal="*",
                    )
                ]
            ),
        )
        self.assertEqual(
            aws_facts(task).ecs_dynamodb_table_topology_destruction_paths,
            [],
        )

    def test_cross_account_delete_requires_identity_and_table_policy_allows(
        self,
    ) -> None:
        table = _table(
            arn=_FOREIGN_TABLE_ARN,
            provider_config_key="aws.foreign",
        )
        table_policy = _resource_policy(
            [
                _statement(
                    "Allow",
                    _DELETE_TABLE,
                    _FOREIGN_TABLE_ARN,
                    principal=_TASK_ROLE_ARN,
                )
            ],
            target_reference=_FOREIGN_TABLE_ARN,
            provider_config_key="aws.foreign",
        )
        role = _role(
            [
                _statement(
                    "Allow",
                    _DELETE_TABLE,
                    _FOREIGN_TABLE_ARN,
                )
            ],
            provider_config_key="aws",
        )
        inventory, task, service = _normalize(
            table=table,
            role=role,
            task_definition=_task_definition(provider_config_key="aws"),
            provider_config_key="aws",
            resource_policy=table_policy,
        )
        path = aws_facts(task).ecs_dynamodb_table_topology_destruction_paths[0]
        self.assertEqual(path["account_relationship"], "cross_account")
        self.assertFalse(path["same_account"])
        self.assertEqual(
            path["grant_basis"],
            "cross_account_identity_and_table_policy",
        )
        self.assertEqual(path["role_account_id"], _ACCOUNT_ID)
        self.assertEqual(path["table_account_id"], _FOREIGN_ACCOUNT_ID)
        self.assertEqual(
            len(aws_facts(service).ecs_dynamodb_table_topology_destruction_paths),
            1,
        )
        self.assertNotIn(
            "aws_dynamodb_resource_policy.orders",
            inventory.unsupported_resources,
        )

        _inventory, task, _service_resource = _normalize(
            table=table,
            role=role,
            task_definition=_task_definition(provider_config_key="aws"),
            provider_config_key="aws",
        )
        self.assertEqual(
            aws_facts(task).ecs_dynamodb_table_topology_destruction_paths,
            [],
        )

    def test_resource_policy_deny_and_unsupported_relevant_semantics_fail_closed(
        self,
    ) -> None:
        policies = {
            "explicit deny": _resource_policy(
                [
                    _statement(
                        "Deny",
                        _DELETE_TABLE,
                        _TABLE_ARN,
                        principal=_TASK_ROLE_ARN,
                    )
                ]
            ),
            "conditional deny": _resource_policy(
                [
                    _statement(
                        "Deny",
                        _DELETE_TABLE,
                        _TABLE_ARN,
                        principal=_TASK_ROLE_ARN,
                        condition={"StringEquals": {"aws:PrincipalArn": _TASK_ROLE_ARN}},
                    )
                ]
            ),
            "unsupported deny": _resource_policy(
                [
                    _statement(
                        "Deny",
                        _DELETE_TABLE,
                        _TABLE_ARN,
                        principal=_TASK_ROLE_ARN,
                        not_action="dynamodb:GetItem",
                    )
                ]
            ),
        }
        for case, policy in policies.items():
            with self.subTest(case=case):
                _inventory, task, _service_resource = _normalize(
                    role_statements=[_statement("Allow", _DELETE_TABLE, _TABLE_ARN)],
                    resource_policy=policy,
                )
                self.assertEqual(
                    aws_facts(task).ecs_dynamodb_table_topology_destruction_paths,
                    [],
                )

    def test_deletion_protection_gates_authority_while_pitr_only_qualifies_recovery(
        self,
    ) -> None:
        for state in ("enabled", "unknown"):
            with self.subTest(deletion_protection=state):
                _inventory, task, _service_resource = _normalize(
                    role_statements=[_statement("Allow", _DELETE_TABLE, _TABLE_ARN)],
                    table=_table(deletion_protection=state),
                )
                self.assertEqual(
                    aws_facts(task).ecs_dynamodb_table_topology_destruction_paths,
                    [],
                )
        for pitr, expected_state in (
            ("disabled", "disabled"),
            ("omitted", "not_configured"),
            ("unknown", "unknown"),
        ):
            with self.subTest(pitr=pitr):
                _inventory, task, _service_resource = _normalize(
                    role_statements=[_statement("Allow", _DELETE_TABLE, _TABLE_ARN)],
                    table=_table(
                        deletion_protection="disabled",
                        pitr=pitr,
                    ),
                )
                paths = aws_facts(task).ecs_dynamodb_table_topology_destruction_paths
                self.assertEqual(len(paths), 1)
                self.assertEqual(
                    paths[0]["recovery_evidence"]["pitr_state"],
                    expected_state,
                )
                if pitr == "unknown":
                    self.assertTrue(aws_facts(task).ecs_dynamodb_table_topology_destruction_path_uncertainties)

    def test_exact_symbolic_first_apply_table_reference_is_supported(self) -> None:
        reference = "aws_dynamodb_table.orders.arn"
        role = _role(
            [_statement("Allow", _DELETE_TABLE, reference)],
            reference_resolutions=(
                _symbolic_resolution(
                    ("inline_policy", 0, "policy"),
                    reference,
                    "aws_dynamodb_table.orders",
                ),
            ),
        )
        table = _table(arn=None)
        inventory, task, _service_resource = _normalize(
            role=role,
            table=table,
            extra=[_caller_identity(_ACCOUNT_ID)],
        )
        path = aws_facts(task).ecs_dynamodb_table_topology_destruction_paths[0]
        self.assertEqual(path["table_reference"], reference)
        self.assertIsNone(path["table_arn"])
        self.assertEqual(path["table_account_id"], _ACCOUNT_ID)

        raw_role = _role([_statement("Allow", _DELETE_TABLE, reference)])
        _inventory, raw_task, _service_resource = _normalize(
            role=raw_role,
            table=table,
            extra=[_caller_identity(_ACCOUNT_ID)],
        )
        self.assertEqual(
            aws_facts(raw_task).ecs_dynamodb_table_topology_destruction_paths,
            [],
        )
        self.assertIsNotNone(inventory.get_by_address("aws_dynamodb_table.orders"))

    def test_symbolic_resource_policy_target_requires_reference_provenance(
        self,
    ) -> None:
        reference = "aws_dynamodb_table.orders.arn"
        statement = _statement(
            "Allow",
            _DELETE_TABLE,
            reference,
            principal=_TASK_ROLE_ARN,
        )
        policy = _resource_policy(
            [statement],
            target_reference=reference,
            reference_resolutions=(
                _symbolic_resolution(
                    ("resource_arn",),
                    reference,
                    "aws_dynamodb_table.orders",
                ),
                _symbolic_resolution(
                    ("policy",),
                    reference,
                    "aws_dynamodb_table.orders",
                ),
            ),
        )
        _inventory, task, _service_resource = _normalize(
            resource_policy=policy,
        )
        paths = aws_facts(task).ecs_dynamodb_table_topology_destruction_paths
        self.assertEqual(len(paths), 1)
        self.assertEqual(
            paths[0]["grant_basis"],
            "same_account_table_policy_direct",
        )
        self.assertEqual(paths[0]["table_reference"], reference)

        raw_policy = _resource_policy(
            [statement],
            target_reference=reference,
        )
        _inventory, task, _service_resource = _normalize(
            resource_policy=raw_policy,
        )
        self.assertEqual(
            aws_facts(task).ecs_dynamodb_table_topology_destruction_paths,
            [],
        )

    def test_current_helper_recomputes_identity_and_resource_policy_authority(
        self,
    ) -> None:
        inventory, task, _service_resource = _normalize(
            role_statements=[_statement("Allow", _DELETE_TABLE, _TABLE_ARN)],
        )
        table = inventory.get_by_address("aws_dynamodb_table.orders")
        role = inventory.get_by_address("aws_iam_role.orders_task")
        assert table is not None
        assert role is not None
        context = AwsDecorationContext(index=AwsResourceIndexBuilder().build(list(inventory.resources)))
        self.assertIsNotNone(
            current_ecs_dynamodb_table_topology_destruction_path(
                task,
                table,
                context,
            )
        )
        role.policy_statements = ()
        self.assertIsNone(
            current_ecs_dynamodb_table_topology_destruction_path(
                task,
                table,
                context,
            )
        )

        inventory, task, _service_resource = _normalize(
            role_statements=[_statement("Allow", _DELETE_TABLE, _TABLE_ARN)],
            resource_policy=_resource_policy(
                [
                    _statement(
                        "Allow",
                        "dynamodb:GetItem",
                        _TABLE_ARN,
                        principal=_TASK_ROLE_ARN,
                    )
                ]
            ),
        )
        table = inventory.get_by_address("aws_dynamodb_table.orders")
        policy = inventory.get_by_address("aws_dynamodb_resource_policy.orders")
        assert table is not None
        assert policy is not None
        context = AwsDecorationContext(index=AwsResourceIndexBuilder().build(list(inventory.resources)))
        self.assertIsNotNone(
            current_ecs_dynamodb_table_topology_destruction_path(
                task,
                table,
                context,
            )
        )
        deny = _statement(
            "Deny",
            _DELETE_TABLE,
            _TABLE_ARN,
            principal=_TASK_ROLE_ARN,
        )
        policy.policy_statements = (parse_policy_statement(deny),)
        aws_facts(policy).set_policy_document(
            {
                "Version": "2012-10-17",
                "Statement": [deny],
            }
        )
        self.assertIsNone(
            current_ecs_dynamodb_table_topology_destruction_path(
                task,
                table,
                context,
            )
        )


if __name__ == "__main__":
    unittest.main()
