from __future__ import annotations

import json
import unittest
from typing import Any

from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts

_ACCOUNT_ID = "111122223333"
_REGION = "us-east-1"
_SECRET_ARN = f"arn:aws:secretsmanager:{_REGION}:{_ACCOUNT_ID}:secret:orders-db-abc123"
_SECRET_REFERENCE = f"{_SECRET_ARN}:password:AWSCURRENT:version-001"
_TASK_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:role/task"
_EXECUTION_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:role/execution"


def _resource(resource_type: str, name: str, values: dict[str, Any]) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
    )


def _role(name: str, arn: str, statements: list[dict[str, Any]] | None = None) -> TerraformResource:
    values: dict[str, Any] = {"name": name, "arn": arn}
    if statements is not None:
        values["inline_policy"] = [
            {
                "name": "secret-access",
                "policy": json.dumps({"Version": "2012-10-17", "Statement": statements}),
            }
        ]
    return _resource("aws_iam_role", name, values)


def _role_policy_attachment(role_reference: str, policy_arn: str) -> TerraformResource:
    return _resource(
        "aws_iam_role_policy_attachment",
        "external",
        {"role": role_reference, "policy_arn": policy_arn},
    )


def _statement(
    effect: str,
    actions: str | list[str],
    resources: str | list[str],
    *,
    condition: dict[str, Any] | None = None,
) -> dict[str, Any]:
    statement: dict[str, Any] = {
        "Effect": effect,
        "Action": actions,
        "Resource": resources,
    }
    if condition is not None:
        statement["Condition"] = condition
    return statement


def _task_definition(
    secret_reference: str = _SECRET_REFERENCE,
    *,
    task_role_arn: str | None = _TASK_ROLE_ARN,
    execution_role_arn: str | None = _EXECUTION_ROLE_ARN,
) -> TerraformResource:
    values: dict[str, Any] = {
        "family": "orders",
        "revision": 1,
        "container_definitions": json.dumps(
            [
                {
                    "name": "orders",
                    "secrets": [{"name": "DB_PASSWORD", "valueFrom": secret_reference}],
                }
            ]
        ),
    }
    if task_role_arn is not None:
        values["task_role_arn"] = task_role_arn
    if execution_role_arn is not None:
        values["execution_role_arn"] = execution_role_arn
    return _resource("aws_ecs_task_definition", "orders", values)


def _service(task_definition: str = "orders:1") -> TerraformResource:
    return _resource(
        "aws_ecs_service",
        "orders",
        {
            "name": "orders",
            "task_definition": task_definition,
        },
    )


def _facts(resources: list[TerraformResource]):
    inventory = AwsNormalizer().normalize(resources)
    task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
    assert task_definition is not None
    return aws_facts(task_definition)


class AwsEcsSecretAccessPathTests(unittest.TestCase):
    def test_resolved_task_definition_paths_are_projected_onto_ecs_service(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _role(
                    "execution",
                    _EXECUTION_ROLE_ARN,
                    [_statement("Allow", "secretsmanager:GetSecretValue", _SECRET_ARN)],
                ),
                _task_definition(task_role_arn=None),
                _service(),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert task_definition is not None
        assert service is not None

        task_definition_path = aws_facts(task_definition).ecs_secret_access_paths[0]
        service_path = aws_facts(service).ecs_secret_access_paths[0]
        self.assertEqual(task_definition_path["workload_address"], task_definition.address)
        self.assertEqual(service_path["workload_address"], service.address)
        self.assertEqual(service_path["workload_type"], "aws_ecs_service")
        self.assertEqual(service_path["task_definition_address"], task_definition.address)
        self.assertEqual(service_path["secret_arn"], _SECRET_ARN)
        self.assertEqual(service_path["role_address"], "aws_iam_role.execution")
        self.assertEqual(service_path["role_arn"], _EXECUTION_ROLE_ARN)
        self.assertEqual(service_path["access_state"], "allowed")
        self.assertFalse(service_path["explicit_deny"])
        self.assertFalse(service_path["conditional_evaluation_required"])
        self.assertEqual(service_path["internet_facing_load_balancers"], [])

    def test_exact_secret_reference_connects_to_execution_role_and_preserves_selectors(self) -> None:
        facts = _facts(
            [
                _role("task", _TASK_ROLE_ARN, [_statement("Allow", "secretsmanager:*", "*")]),
                _role(
                    "execution",
                    _EXECUTION_ROLE_ARN,
                    [_statement("Allow", "secretsmanager:GetSecretValue", _SECRET_ARN)],
                ),
                _task_definition(),
            ]
        )

        self.assertEqual(len(facts.ecs_secret_access_paths), 1)
        path = facts.ecs_secret_access_paths[0]
        self.assertEqual(path["workload_address"], "aws_ecs_task_definition.orders")
        self.assertEqual(path["secret_reference"], _SECRET_REFERENCE)
        self.assertEqual(path["secret_arn"], _SECRET_ARN)
        self.assertEqual(path["json_key"], "password")
        self.assertEqual(path["version_stage"], "AWSCURRENT")
        self.assertEqual(path["version_id"], "version-001")
        self.assertEqual(path["secret_reference_path"], "container_definitions[0].secrets[0].valueFrom")
        self.assertEqual(path["container_name"], "orders")
        self.assertEqual(path["setting_name"], "DB_PASSWORD")
        self.assertEqual(path["role_kind"], "ecs_task_execution_role")
        self.assertEqual(path["credential_context"], "ecs_agent_secret_delivery")
        self.assertEqual(path["role_address"], "aws_iam_role.execution")
        self.assertEqual(path["role_arn"], _EXECUTION_ROLE_ARN)
        self.assertNotEqual(path["role_arn"], _TASK_ROLE_ARN)
        self.assertEqual(path["modeled_access_state"], "allowed")
        self.assertEqual(path["access_state"], "allowed")
        self.assertEqual(path["matched_actions"], ["secretsmanager:GetSecretValue"])
        self.assertEqual(path["policy_action_patterns"], ["secretsmanager:GetSecretValue"])
        self.assertEqual(path["policy_resources"], [_SECRET_ARN])
        self.assertEqual(path["resource_scope"], "exact_secret")
        self.assertFalse(path["explicit_deny"])
        self.assertFalse(path["conditional_evaluation_required"])
        self.assertEqual(path["policy_statements"][0]["conditions"], [])
        self.assertEqual(facts.ecs_secret_access_path_uncertainties, [])

    def test_task_role_permission_does_not_create_secret_delivery_access(self) -> None:
        facts = _facts(
            [
                _role("task", _TASK_ROLE_ARN, [_statement("Allow", "secretsmanager:GetSecretValue", "*")]),
                _role("execution", _EXECUTION_ROLE_ARN),
                _task_definition(),
            ]
        )

        path = facts.ecs_secret_access_paths[0]
        self.assertEqual(path["role_address"], "aws_iam_role.execution")
        self.assertEqual(path["modeled_access_state"], "not_modeled")
        self.assertEqual(path["access_state"], "not_modeled")
        self.assertEqual(path["matched_actions"], [])
        self.assertEqual(path["policy_statements"], [])

    def test_wildcard_execution_role_grant_preserves_broad_scope(self) -> None:
        facts = _facts(
            [
                _role("execution", _EXECUTION_ROLE_ARN, [_statement("Allow", "secretsmanager:*", "*")]),
                _task_definition(task_role_arn=None),
            ]
        )

        path = facts.ecs_secret_access_paths[0]
        self.assertEqual(path["access_state"], "allowed")
        self.assertEqual(path["policy_action_patterns"], ["secretsmanager:*"])
        self.assertEqual(path["policy_resources"], ["*"])
        self.assertEqual(path["resource_scope"], "all_resources")
        self.assertEqual(path["policy_statements"][0]["actions"], ["secretsmanager:*"])
        self.assertEqual(path["policy_statements"][0]["resources"], ["*"])

    def test_explicit_deny_overrides_allow_and_remains_in_evidence(self) -> None:
        facts = _facts(
            [
                _role(
                    "execution",
                    _EXECUTION_ROLE_ARN,
                    [
                        _statement("Allow", "secretsmanager:GetSecretValue", "*"),
                        _statement("Deny", "secretsmanager:GetSecretValue", _SECRET_ARN),
                    ],
                ),
                _task_definition(task_role_arn=None),
            ]
        )

        path = facts.ecs_secret_access_paths[0]
        self.assertEqual(path["modeled_access_state"], "denied")
        self.assertEqual(path["access_state"], "denied")
        self.assertTrue(path["explicit_deny"])
        self.assertEqual(path["deny_action_patterns"], ["secretsmanager:GetSecretValue"])
        self.assertEqual(path["deny_policy_resources"], [_SECRET_ARN])
        self.assertEqual([statement["effect"] for statement in path["policy_statements"]], ["allow", "deny"])

    def test_conditional_allow_is_unknown_and_preserves_conditions(self) -> None:
        facts = _facts(
            [
                _role(
                    "execution",
                    _EXECUTION_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "secretsmanager:GetSecretValue",
                            _SECRET_ARN,
                            condition={"StringEquals": {"aws:PrincipalAccount": _ACCOUNT_ID}},
                        )
                    ],
                ),
                _task_definition(task_role_arn=None),
            ]
        )

        path = facts.ecs_secret_access_paths[0]
        self.assertEqual(path["modeled_access_state"], "unknown")
        self.assertEqual(path["access_state"], "unknown")
        self.assertTrue(path["conditional_evaluation_required"])
        self.assertEqual(
            path["policy_statements"][0]["conditions"],
            [
                {
                    "operator": "StringEquals",
                    "key": "aws:PrincipalAccount",
                    "values": [_ACCOUNT_ID],
                }
            ],
        )
        self.assertEqual(len(facts.ecs_secret_access_path_uncertainties), 1)
        self.assertIn("conditional allow statement evidence", facts.ecs_secret_access_path_uncertainties[0])

    def test_unresolved_attached_policy_keeps_modeled_allow_but_effective_access_unknown(self) -> None:
        external_policy_arn = "arn:aws:iam::aws:policy/ExternalSecretAccess"
        facts = _facts(
            [
                _role(
                    "execution",
                    _EXECUTION_ROLE_ARN,
                    [_statement("Allow", "secretsmanager:GetSecretValue", _SECRET_ARN)],
                ),
                _role_policy_attachment(_EXECUTION_ROLE_ARN, external_policy_arn),
                _task_definition(task_role_arn=None),
            ]
        )

        path = facts.ecs_secret_access_paths[0]
        self.assertEqual(path["modeled_access_state"], "allowed")
        self.assertEqual(path["access_state"], "unknown")
        self.assertFalse(path["role_policy_complete"])
        self.assertEqual(
            facts.ecs_secret_access_path_uncertainties,
            [
                "aws_ecs_task_definition.orders: aws_iam_role.execution has unresolved attached policy "
                + external_policy_arn
            ],
        )

    def test_unresolved_role_and_secret_references_remain_explicit(self) -> None:
        missing_role_facts = _facts([_task_definition(task_role_arn=None)])
        self.assertEqual(missing_role_facts.ecs_secret_access_paths, [])
        self.assertEqual(
            missing_role_facts.ecs_secret_access_path_uncertainties,
            [
                f"aws_ecs_task_definition.orders: ECS task execution role {_EXECUTION_ROLE_ARN} "
                "is not modeled in the plan"
            ],
        )

        unresolved_reference_facts = _facts(
            [
                _role("execution", _EXECUTION_ROLE_ARN),
                _task_definition(
                    "$" + "{aws_secretsmanager_secret.orders.arn}",
                    task_role_arn=None,
                ),
            ]
        )
        self.assertEqual(unresolved_reference_facts.ecs_secret_access_paths, [])
        self.assertEqual(
            unresolved_reference_facts.ecs_secret_access_path_uncertainties,
            [
                "aws_ecs_task_definition.orders: secret reference container_definitions[0].secrets[0] "
                "does not expose an exact Secrets Manager ARN for access-path modeling"
            ],
        )


if __name__ == "__main__":
    unittest.main()
