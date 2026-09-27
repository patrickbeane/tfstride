from __future__ import annotations

import json
import unittest
from typing import Any

from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts

_ACCOUNT_ID = "111122223333"
_TASK_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:role/orders-task"
_EXECUTION_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:role/orders-execution"
_ROOT_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:root"
_KEY_IDS = {
    "data": "11111111-1111-1111-1111-111111111111",
    "signing": "22222222-2222-2222-2222-222222222222",
    "mac": "33333333-3333-3333-3333-333333333333",
}
_KEY_ARNS = {name: f"arn:aws:kms:us-east-1:{_ACCOUNT_ID}:key/{key_id}" for name, key_id in _KEY_IDS.items()}


def _resource(
    resource_type: str,
    name: str,
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _statement(
    effect: str,
    actions: str | list[str],
    resources: str | list[str],
    *,
    principal: str,
) -> dict[str, Any]:
    return {
        "Effect": effect,
        "Action": actions,
        "Resource": resources,
        "Principal": {"AWS": principal},
    }


def _policy(*statements: dict[str, Any]) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": list(statements),
        }
    )


def _key(
    name: str,
    usage: str,
    policy: str,
) -> TerraformResource:
    key_id = _KEY_IDS[name]
    return _resource(
        "aws_kms_key",
        name,
        {
            "id": key_id,
            "key_id": key_id,
            "arn": _KEY_ARNS[name],
            "key_usage": usage,
            "key_spec": {
                "ENCRYPT_DECRYPT": "SYMMETRIC_DEFAULT",
                "SIGN_VERIFY": "RSA_2048",
                "GENERATE_VERIFY_MAC": "HMAC_256",
            }[usage],
            "policy": policy,
        },
    )


def _role(
    name: str,
    role_arn: str,
    statements: list[dict[str, Any]],
) -> TerraformResource:
    identity_statements: list[dict[str, Any]] = []
    for statement in statements:
        identity_statement = dict(statement)
        identity_statement.pop("Principal", None)
        identity_statements.append(identity_statement)
    return _resource(
        "aws_iam_role",
        name,
        {
            "name": name.replace("_", "-"),
            "arn": role_arn,
            "inline_policy": [
                {
                    "name": "kms-use",
                    "policy": _policy(*identity_statements),
                }
            ],
        },
    )


def _grant(
    name: str,
    key_name: str,
    operations: list[str],
    *,
    grantee_principal: str = _TASK_ROLE_ARN,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return _resource(
        "aws_kms_grant",
        name,
        {
            "id": f"grant-{name}",
            "grant_id": f"grant-{name}",
            "name": name,
            "key_id": f"aws_kms_key.{key_name}.key_id",
            "grantee_principal": grantee_principal,
            "operations": operations,
            "constraints": [
                {
                    "encryption_context_equals": {
                        "service": "orders",
                    }
                }
            ],
        },
        unknown_values=unknown_values,
    )


def _task_definition() -> TerraformResource:
    return _resource(
        "aws_ecs_task_definition",
        "orders",
        {
            "family": "orders",
            "revision": 1,
            "task_role_arn": _TASK_ROLE_ARN,
            "execution_role_arn": _EXECUTION_ROLE_ARN,
            "network_mode": "awsvpc",
            "container_definitions": '[{"name":"orders","portMappings":[{"containerPort":8080,"protocol":"tcp"}]}]',
        },
    )


def _service() -> TerraformResource:
    return _resource(
        "aws_ecs_service",
        "orders",
        {
            "name": "orders",
            "task_definition": "orders:1",
        },
    )


class AwsEcsKmsOperationPathTests(unittest.TestCase):
    def test_task_role_operations_intersect_key_usage_and_project_to_service(self) -> None:
        role_statements = [
            _statement(
                "Allow",
                ["kms:Decrypt", "kms:Encrypt"],
                _KEY_ARNS["data"],
                principal=_TASK_ROLE_ARN,
            ),
            _statement(
                "Allow",
                ["kms:Sign", "kms:Verify", "kms:GetPublicKey"],
                _KEY_ARNS["signing"],
                principal=_TASK_ROLE_ARN,
            ),
            _statement(
                "Allow",
                "kms:VerifyMac",
                _KEY_ARNS["mac"],
                principal=_TASK_ROLE_ARN,
            ),
        ]
        execution_statements = [
            _statement(
                "Allow",
                "kms:Decrypt",
                _KEY_ARNS["data"],
                principal=_EXECUTION_ROLE_ARN,
            )
        ]
        resources = [
            _key(
                "data",
                "ENCRYPT_DECRYPT",
                _policy(
                    _statement(
                        "Allow",
                        ["kms:Decrypt", "kms:Encrypt"],
                        "*",
                        principal=_TASK_ROLE_ARN,
                    ),
                    _statement(
                        "Allow",
                        "kms:Decrypt",
                        "*",
                        principal=_EXECUTION_ROLE_ARN,
                    ),
                ),
            ),
            _key(
                "signing",
                "SIGN_VERIFY",
                _policy(
                    _statement(
                        "Allow",
                        "kms:*",
                        "*",
                        principal=_ROOT_ARN,
                    )
                ),
            ),
            _key(
                "mac",
                "GENERATE_VERIFY_MAC",
                _policy(
                    _statement(
                        "Allow",
                        "kms:*",
                        "*",
                        principal=_ROOT_ARN,
                    )
                ),
            ),
            _role("orders_task", _TASK_ROLE_ARN, role_statements),
            _role("orders_execution", _EXECUTION_ROLE_ARN, execution_statements),
            _grant("mac_runtime", "mac", ["GenerateMac"]),
            _task_definition(),
            _service(),
        ]

        inventory = AwsNormalizer().normalize(resources)
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert task_definition is not None
        assert service is not None

        task_paths = aws_facts(task_definition).ecs_kms_operation_paths
        self.assertEqual(
            [(path["key_address"], path["operation"]) for path in task_paths],
            [
                ("aws_kms_key.data", "kms:Decrypt"),
                ("aws_kms_key.mac", "kms:GenerateMac"),
                ("aws_kms_key.signing", "kms:Sign"),
            ],
        )
        self.assertEqual(
            {path["authorization_basis"] for path in task_paths},
            {"key_policy_direct", "iam_via_key_policy", "grant"},
        )
        self.assertNotIn(
            _EXECUTION_ROLE_ARN,
            {path["role_arn"] for path in task_paths},
        )

        by_key = {path["key_address"]: path for path in task_paths}
        data_path = by_key["aws_kms_key.data"]
        self.assertEqual(data_path["key_arn"], _KEY_ARNS["data"])
        self.assertEqual(data_path["authorization_bases"], ["key_policy_direct"])
        self.assertEqual(data_path["policy_action_patterns"], ["kms:Decrypt"])
        self.assertEqual(
            data_path["policy_resources"],
            ["*", _KEY_ARNS["data"]],
        )

        signing_path = by_key["aws_kms_key.signing"]
        self.assertEqual(signing_path["authorization_bases"], ["iam_via_key_policy"])
        self.assertEqual(
            signing_path["policy_action_patterns"],
            ["kms:*", "kms:Sign"],
        )

        mac_path = by_key["aws_kms_key.mac"]
        self.assertEqual(mac_path["authorization_bases"], ["grant"])
        self.assertEqual(
            mac_path["grant_constraints"],
            [{"encryption_context_equals": {"service": "orders"}}],
        )
        self.assertEqual(mac_path["constraint_state"], "encryption_context")

        service_paths = aws_facts(service).ecs_kms_operation_paths
        self.assertEqual(len(service_paths), 3)
        self.assertTrue(all(path["workload_address"] == service.address for path in service_paths))
        self.assertTrue(all(path["task_definition_address"] == task_definition.address for path in service_paths))

    def test_wrong_usage_operations_remain_out_of_ecs_kms_paths(self) -> None:
        role_statements = [
            _statement(
                "Allow",
                [
                    "kms:Decrypt",
                    "kms:Encrypt",
                    "kms:Sign",
                    "kms:Verify",
                    "kms:GetPublicKey",
                    "kms:GenerateMac",
                    "kms:VerifyMac",
                ],
                [_KEY_ARNS["data"], _KEY_ARNS["signing"], _KEY_ARNS["mac"]],
                principal=_TASK_ROLE_ARN,
            )
        ]
        resources = [
            _key(
                "data",
                "ENCRYPT_DECRYPT",
                _policy(
                    _statement(
                        "Allow",
                        "kms:*",
                        "*",
                        principal=_TASK_ROLE_ARN,
                    )
                ),
            ),
            _key(
                "signing",
                "SIGN_VERIFY",
                _policy(
                    _statement(
                        "Allow",
                        "kms:*",
                        "*",
                        principal=_TASK_ROLE_ARN,
                    )
                ),
            ),
            _key(
                "mac",
                "GENERATE_VERIFY_MAC",
                _policy(
                    _statement(
                        "Allow",
                        "kms:*",
                        "*",
                        principal=_TASK_ROLE_ARN,
                    )
                ),
            ),
            _role("orders_task", _TASK_ROLE_ARN, role_statements),
            _task_definition(),
        ]

        inventory = AwsNormalizer().normalize(resources)
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        self.assertEqual(
            [path["operation"] for path in aws_facts(task_definition).ecs_kms_operation_paths],
            ["kms:Decrypt", "kms:GenerateMac", "kms:Sign"],
        )

    def test_unknown_quiet_operations_do_not_create_ecs_path_uncertainties(self) -> None:
        def conditional_policy(operation: str) -> str:
            statement = _statement(
                "Allow",
                operation,
                "*",
                principal=_TASK_ROLE_ARN,
            )
            statement["Condition"] = {
                "StringEquals": {
                    "kms:EncryptionContext:service": "orders",
                }
            }
            return _policy(statement)

        resources = [
            _key("data", "ENCRYPT_DECRYPT", conditional_policy("kms:Encrypt")),
            _key("signing", "SIGN_VERIFY", conditional_policy("kms:Verify")),
            _key("mac", "GENERATE_VERIFY_MAC", conditional_policy("kms:VerifyMac")),
            _role(
                "orders_task",
                _TASK_ROLE_ARN,
                [
                    _statement(
                        "Allow",
                        "kms:Encrypt",
                        _KEY_ARNS["data"],
                        principal=_TASK_ROLE_ARN,
                    ),
                    _statement(
                        "Allow",
                        "kms:Verify",
                        _KEY_ARNS["signing"],
                        principal=_TASK_ROLE_ARN,
                    ),
                    _statement(
                        "Allow",
                        "kms:VerifyMac",
                        _KEY_ARNS["mac"],
                        principal=_TASK_ROLE_ARN,
                    ),
                ],
            ),
            _task_definition(),
            _service(),
        ]

        inventory = AwsNormalizer().normalize(resources)
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert task_definition is not None
        assert service is not None

        self.assertEqual(aws_facts(task_definition).ecs_kms_operation_paths, [])
        self.assertEqual(aws_facts(task_definition).ecs_kms_operation_path_uncertainties, [])
        self.assertEqual(aws_facts(service).ecs_kms_operation_paths, [])
        self.assertEqual(aws_facts(service).ecs_kms_operation_path_uncertainties, [])

    def test_denied_authorization_does_not_create_ecs_kms_operation_path(self) -> None:
        resources = [
            _key(
                "data",
                "ENCRYPT_DECRYPT",
                _policy(
                    _statement(
                        "Allow",
                        "kms:Decrypt",
                        "*",
                        principal=_TASK_ROLE_ARN,
                    ),
                    _statement(
                        "Deny",
                        "kms:Decrypt",
                        "*",
                        principal=_TASK_ROLE_ARN,
                    ),
                ),
            ),
            _role(
                "orders_task",
                _TASK_ROLE_ARN,
                [
                    _statement(
                        "Allow",
                        "kms:Decrypt",
                        _KEY_ARNS["data"],
                        principal=_TASK_ROLE_ARN,
                    )
                ],
            ),
            _task_definition(),
            _service(),
        ]

        inventory = AwsNormalizer().normalize(resources)
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert task_definition is not None
        assert service is not None

        self.assertEqual(aws_facts(task_definition).ecs_kms_operation_paths, [])
        self.assertEqual(aws_facts(service).ecs_kms_operation_paths, [])

    def test_unknown_authorization_becomes_uncertainty_not_operation_path(self) -> None:
        conditional_allow = _statement(
            "Allow",
            "kms:Decrypt",
            "*",
            principal=_TASK_ROLE_ARN,
        )
        conditional_allow["Condition"] = {
            "StringEquals": {
                "kms:EncryptionContext:service": "orders",
            }
        }
        resources = [
            _key("data", "ENCRYPT_DECRYPT", _policy(conditional_allow)),
            _role(
                "orders_task",
                _TASK_ROLE_ARN,
                [
                    _statement(
                        "Allow",
                        "kms:Decrypt",
                        _KEY_ARNS["data"],
                        principal=_TASK_ROLE_ARN,
                    )
                ],
            ),
            _task_definition(),
            _service(),
        ]

        inventory = AwsNormalizer().normalize(resources)
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert task_definition is not None
        assert service is not None

        self.assertEqual(aws_facts(task_definition).ecs_kms_operation_paths, [])
        self.assertTrue(
            any(
                "has unresolved kms:Decrypt authorization" in uncertainty
                for uncertainty in aws_facts(task_definition).ecs_kms_operation_path_uncertainties
            )
        )
        self.assertEqual(aws_facts(service).ecs_kms_operation_paths, [])
        self.assertTrue(
            any(
                "has unresolved kms:Decrypt authorization" in uncertainty
                for uncertainty in aws_facts(service).ecs_kms_operation_path_uncertainties
            )
        )

    def test_unknown_grant_principal_remains_ecs_path_uncertainty(self) -> None:
        resources = [
            _key(
                "data",
                "ENCRYPT_DECRYPT",
                _policy(
                    _statement(
                        "Allow",
                        "kms:*",
                        "*",
                        principal=_ROOT_ARN,
                    )
                ),
            ),
            _role("orders_task", _TASK_ROLE_ARN, []),
            _grant(
                "data_runtime",
                "data",
                ["Decrypt"],
                unknown_values={"grantee_principal": True},
            ),
            _task_definition(),
            _service(),
        ]

        inventory = AwsNormalizer().normalize(resources)
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert task_definition is not None
        assert service is not None

        self.assertEqual(aws_facts(task_definition).ecs_kms_operation_paths, [])
        self.assertTrue(
            any(
                "authorization evidence is unresolved" in uncertainty
                for uncertainty in aws_facts(task_definition).ecs_kms_operation_path_uncertainties
            )
        )
        self.assertTrue(
            any(
                "authorization evidence is unresolved" in uncertainty
                for uncertainty in aws_facts(service).ecs_kms_operation_path_uncertainties
            )
        )

    def test_unknown_grant_operations_remain_ecs_path_uncertainty(self) -> None:
        resources = [
            _key(
                "data",
                "ENCRYPT_DECRYPT",
                _policy(
                    _statement(
                        "Allow",
                        "kms:*",
                        "*",
                        principal=_ROOT_ARN,
                    )
                ),
            ),
            _role("orders_task", _TASK_ROLE_ARN, []),
            _grant(
                "data_runtime",
                "data",
                ["Decrypt"],
                unknown_values={"operations": True},
            ),
            _task_definition(),
            _service(),
        ]

        inventory = AwsNormalizer().normalize(resources)
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert task_definition is not None
        assert service is not None

        self.assertEqual(aws_facts(task_definition).ecs_kms_operation_paths, [])
        self.assertTrue(
            any(
                "unresolved KMS grant operations" in uncertainty
                for uncertainty in aws_facts(task_definition).ecs_kms_operation_path_uncertainties
            )
        )
        self.assertTrue(
            any(
                "unresolved KMS grant operations" in uncertainty
                for uncertainty in aws_facts(service).ecs_kms_operation_path_uncertainties
            )
        )

    def test_unknown_key_usage_does_not_create_deterministic_operation_path(self) -> None:
        resources = [
            _key(
                "data",
                "ENCRYPT_DECRYPT",
                _policy(
                    _statement(
                        "Allow",
                        "kms:Decrypt",
                        "*",
                        principal=_TASK_ROLE_ARN,
                    )
                ),
            ),
            _role(
                "orders_task",
                _TASK_ROLE_ARN,
                [
                    _statement(
                        "Allow",
                        "kms:Decrypt",
                        _KEY_ARNS["data"],
                        principal=_TASK_ROLE_ARN,
                    )
                ],
            ),
            _task_definition(),
        ]
        resources[0].unknown_values["key_usage"] = True
        inventory = AwsNormalizer().normalize(resources)
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        self.assertEqual(aws_facts(task_definition).ecs_kms_operation_paths, [])
        self.assertTrue(
            any(
                "key usage is unresolved" in uncertainty
                for uncertainty in aws_facts(task_definition).ecs_kms_operation_path_uncertainties
            )
        )


if __name__ == "__main__":
    unittest.main()
