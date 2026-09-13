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
from tfstride.providers.aws.resource_decoration.ecs_cloudtrail_audit_telemetry_disruption_paths import (
    current_ecs_cloudtrail_audit_telemetry_disruption_path,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import (
    AwsDecorationContext,
    AwsResourceIndexBuilder,
)

_ACCOUNT_ID = "111122223333"
_FOREIGN_ACCOUNT_ID = "444455556666"
_PROVIDER = "aws"
_ALIAS_PROVIDER = "aws.audit"
_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:role/orders-task"
_EXECUTION_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:role/orders-execution"
_TRAIL_ARN = f"arn:aws:cloudtrail:us-east-1:{_ACCOUNT_ID}:trail/audit"
_STOP_LOGGING = "cloudtrail:StopLogging"
_DELETE_TRAIL = "cloudtrail:DeleteTrail"


def _resource(
    resource_type: str,
    name: str,
    values: dict[str, Any],
    *,
    mode: str = "managed",
    provider_config_key: str | None = _PROVIDER,
    unknown_values: dict[str, Any] | None = None,
    reference_resolutions: tuple[TerraformReferenceResolution, ...] = (),
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode=mode,
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        provider_config_key=provider_config_key,
        values=values,
        unknown_values=unknown_values or {},
        reference_resolutions=reference_resolutions,
    )


def _caller_identity(
    *,
    account_id: str = _ACCOUNT_ID,
    provider_config_key: str = _PROVIDER,
    name: str = "current",
) -> TerraformResource:
    return _resource(
        "aws_caller_identity",
        name,
        {
            "account_id": account_id,
            "id": account_id,
            "arn": f"arn:aws:iam::{account_id}:root",
        },
        mode="data",
        provider_config_key=provider_config_key,
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


def _role(
    statements: list[dict[str, Any]],
    *,
    arn: str | None = _ROLE_ARN,
    name: str = "orders_task",
    provider_config_key: str = _PROVIDER,
    permissions_boundary: str | None = None,
    permissions_boundary_unknown: bool = False,
    reference_resolutions: tuple[TerraformReferenceResolution, ...] = (),
) -> TerraformResource:
    values: dict[str, Any] = {"name": name, "arn": arn}
    if permissions_boundary is not None:
        values["permissions_boundary"] = permissions_boundary
    if statements:
        values["inline_policy"] = [
            {
                "name": "cloudtrail-control",
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
        unknown_values=({"permissions_boundary": True} if permissions_boundary_unknown else None),
        reference_resolutions=reference_resolutions,
    )


def _trail(
    *,
    arn: str | None = _TRAIL_ARN,
    logging: Literal["enabled", "disabled", "omitted", "unknown"] = "enabled",
    organization: Literal[
        "enabled",
        "disabled",
        "omitted",
        "unknown",
    ] = "disabled",
    provider_config_key: str = _PROVIDER,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": "audit",
        "name": "audit",
        "arn": arn,
    }
    unknown_values: dict[str, Any] = {}
    if logging == "enabled":
        values["enable_logging"] = True
    elif logging == "disabled":
        values["enable_logging"] = False
    elif logging == "unknown":
        unknown_values["enable_logging"] = True
    if organization == "enabled":
        values["is_organization_trail"] = True
    elif organization == "disabled":
        values["is_organization_trail"] = False
    elif organization == "unknown":
        unknown_values["is_organization_trail"] = True
    return _resource(
        "aws_cloudtrail",
        "audit",
        values,
        provider_config_key=provider_config_key,
        unknown_values=unknown_values,
    )


def _task_definition(
    *,
    task_role_arn: str | None = _ROLE_ARN,
    execution_role_arn: str | None = _EXECUTION_ROLE_ARN,
    provider_config_key: str = _PROVIDER,
) -> TerraformResource:
    return _resource(
        "aws_ecs_task_definition",
        "orders",
        {
            "family": "orders",
            "revision": 1,
            "container_definitions": "[]",
            "task_role_arn": task_role_arn,
            "execution_role_arn": execution_role_arn,
        },
        provider_config_key=provider_config_key,
    )


def _service(
    *,
    provider_config_key: str = _PROVIDER,
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


def _policy_attachment(
    *,
    provider_config_key: str = _PROVIDER,
) -> TerraformResource:
    return _resource(
        "aws_iam_role_policy_attachment",
        "cloudtrail",
        {
            "role": _ROLE_ARN,
            "policy_arn": ("arn:aws:iam::aws:policy/AWSCloudTrail_FullAccess"),
        },
        provider_config_key=provider_config_key,
    )


def _symbolic_resolution(
    reference: str,
    target_address: str,
    *,
    path: tuple[str | int, ...] = ("inline_policy", 0, "policy"),
) -> TerraformReferenceResolution:
    return TerraformReferenceResolution(
        path=path,
        state=TerraformReferenceResolutionState.SYMBOLIC,
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
    statements: list[dict[str, Any]],
    *,
    trail: TerraformResource | None = None,
    role: TerraformResource | None = None,
    task_definition: TerraformResource | None = None,
    service: TerraformResource | None = None,
    caller: TerraformResource | None = None,
    provider_config_key: str = _PROVIDER,
    extra: list[TerraformResource] | None = None,
):
    inventory = AwsNormalizer().normalize(
        [
            caller
            or _caller_identity(
                provider_config_key=provider_config_key,
            ),
            trail
            or _trail(
                provider_config_key=provider_config_key,
            ),
            role
            or _role(
                statements,
                provider_config_key=provider_config_key,
            ),
            task_definition
            or _task_definition(
                provider_config_key=provider_config_key,
            ),
            service
            or _service(
                provider_config_key=provider_config_key,
            ),
            *(extra or []),
        ]
    )
    task = inventory.get_by_address("aws_ecs_task_definition.orders")
    service = inventory.get_by_address("aws_ecs_service.orders")
    assert task is not None
    assert service is not None
    return inventory, task, service


class AwsEcsCloudTrailAuditTelemetryDisruptionPathTests(
    unittest.TestCase,
):
    def test_task_role_authority_projects_operation_exact_paths(self) -> None:
        inventory, task, service = _normalize(
            [
                _statement(
                    "Allow",
                    [_STOP_LOGGING, _DELETE_TRAIL],
                    _TRAIL_ARN,
                )
            ]
        )

        task_paths = aws_facts(task).ecs_cloudtrail_audit_telemetry_disruption_paths
        service_paths = aws_facts(service).ecs_cloudtrail_audit_telemetry_disruption_paths
        self.assertEqual(
            [path["operation"] for path in task_paths],
            [_DELETE_TRAIL, _STOP_LOGGING],
        )
        self.assertEqual(len(service_paths), 2)
        for path in task_paths:
            self.assertEqual(path["role_kind"], "ecs_task_role")
            self.assertEqual(path["credential_context"], "workload_runtime")
            self.assertEqual(path["trail_address"], "aws_cloudtrail.audit")
            self.assertEqual(path["trail_arn"], _TRAIL_ARN)
            self.assertEqual(path["trail_account_id"], _ACCOUNT_ID)
            self.assertEqual(path["caller_account_id"], _ACCOUNT_ID)
            self.assertEqual(path["role_provider_config_key"], _PROVIDER)
            self.assertTrue(path["same_account"])
            self.assertTrue(path["provider_configuration_match"])
            self.assertEqual(path["target_scope"], "exact_cloudtrail_trail")
            self.assertEqual(path["matched_actions"], [path["operation"]])
            self.assertEqual(
                path["lifecycle_evidence"]["lifecycle_compatibility_state"],
                "compatible",
            )
            self.assertFalse(path["outcome_evidence"]["historical_log_object_deletion_authorized_by_operation"])
            self.assertFalse(path["outcome_evidence"]["logging_destination_deletion_authorized_by_operation"])
            self.assertFalse(path["outcome_evidence"]["successful_operation_observed"])
        self.assertIsNotNone(inventory.get_by_address("aws_caller_identity.current"))

    def test_operation_local_deny_preserves_unrelated_operation(self) -> None:
        _inventory, task, _service_resource = _normalize(
            [
                _statement("Allow", "cloudtrail:*", _TRAIL_ARN),
                _statement("Deny", _DELETE_TRAIL, _TRAIL_ARN),
            ]
        )
        paths = aws_facts(task).ecs_cloudtrail_audit_telemetry_disruption_paths
        self.assertEqual(
            [path["operation"] for path in paths],
            [_STOP_LOGGING],
        )
        self.assertEqual(
            paths[0]["authorization_statements"][0]["matching_action_patterns"],
            ["cloudtrail:*"],
        )

    def test_execution_role_cannot_substitute_for_task_role(self) -> None:
        execution_role = _role(
            [_statement("Allow", _STOP_LOGGING, _TRAIL_ARN)],
            arn=_EXECUTION_ROLE_ARN,
            name="orders_execution",
        )
        _inventory, task, _service_resource = _normalize(
            [],
            extra=[execution_role],
        )
        self.assertEqual(
            aws_facts(task).ecs_cloudtrail_audit_telemetry_disruption_paths,
            [],
        )

    def test_conditional_incomplete_and_wildcard_authority_fail_closed(
        self,
    ) -> None:
        cases = {
            "conditional allow": _normalize(
                [
                    _statement(
                        "Allow",
                        _STOP_LOGGING,
                        _TRAIL_ARN,
                        condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
                    )
                ]
            ),
            "conditional deny": _normalize(
                [
                    _statement("Allow", _STOP_LOGGING, _TRAIL_ARN),
                    _statement(
                        "Deny",
                        _STOP_LOGGING,
                        _TRAIL_ARN,
                        condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
                    ),
                ]
            ),
            "wildcard target": _normalize(
                [
                    _statement(
                        "Allow",
                        _STOP_LOGGING,
                        (f"arn:aws:cloudtrail:us-east-1:{_ACCOUNT_ID}:trail/*"),
                    )
                ]
            ),
            "incomplete policy": _normalize(
                [_statement("Allow", _STOP_LOGGING, _TRAIL_ARN)],
                extra=[_policy_attachment()],
            ),
        }
        for case, (_inventory, task, _service_resource) in cases.items():
            with self.subTest(case=case):
                self.assertEqual(
                    aws_facts(task).ecs_cloudtrail_audit_telemetry_disruption_paths,
                    [],
                )
                self.assertTrue(aws_facts(task).ecs_cloudtrail_audit_telemetry_disruption_path_uncertainties)

    def test_configured_or_unresolved_permissions_boundary_fails_closed(
        self,
    ) -> None:
        boundary_arn = f"arn:aws:iam::{_ACCOUNT_ID}:policy/orders-permissions-boundary"
        cases = {
            "configured": _role(
                [_statement("Allow", _STOP_LOGGING, _TRAIL_ARN)],
                permissions_boundary=boundary_arn,
            ),
            "unresolved": _role(
                [_statement("Allow", _STOP_LOGGING, _TRAIL_ARN)],
                permissions_boundary_unknown=True,
            ),
        }
        for case, role_resource in cases.items():
            with self.subTest(case=case):
                inventory, task, service = _normalize([], role=role_resource)
                role = inventory.get_by_address("aws_iam_role.orders_task")
                assert role is not None

                self.assertEqual(
                    aws_facts(task).ecs_cloudtrail_audit_telemetry_disruption_paths,
                    [],
                )
                self.assertEqual(
                    aws_facts(service).ecs_cloudtrail_audit_telemetry_disruption_paths,
                    [],
                )
                uncertainties = aws_facts(task).ecs_cloudtrail_audit_telemetry_disruption_path_uncertainties
                self.assertTrue(any("permissions-boundary" in value for value in uncertainties))
                self.assertEqual(
                    aws_facts(role).iam_permissions_boundary_state,
                    "configured" if case == "configured" else "unknown",
                )
                self.assertEqual(
                    aws_facts(role).iam_permissions_boundary_arn,
                    boundary_arn if case == "configured" else None,
                )

    def test_exact_symbolic_trail_reference_requires_provenance(self) -> None:
        reference = "aws_cloudtrail.audit.arn"
        role = _role(
            [_statement("Allow", _STOP_LOGGING, reference)],
            reference_resolutions=(
                _symbolic_resolution(
                    reference,
                    "aws_cloudtrail.audit",
                ),
            ),
        )
        _inventory, task, _service_resource = _normalize(
            [],
            trail=_trail(arn=None),
            role=role,
        )
        paths = aws_facts(task).ecs_cloudtrail_audit_telemetry_disruption_paths
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["trail_reference"], reference)
        self.assertIsNone(paths[0]["trail_arn"])

        _inventory, raw_task, _service_resource = _normalize(
            [_statement("Allow", _STOP_LOGGING, reference)],
            trail=_trail(arn=None),
        )
        self.assertEqual(
            aws_facts(raw_task).ecs_cloudtrail_audit_telemetry_disruption_paths,
            [],
        )

    def test_exact_symbolic_task_role_requires_provenance(self) -> None:
        role_reference = "aws_iam_role.orders_task.arn"
        symbolic_task = _resource(
            "aws_ecs_task_definition",
            "orders",
            {
                "family": "orders",
                "revision": 1,
                "container_definitions": "[]",
            },
            unknown_values={"task_role_arn": True},
            reference_resolutions=(
                _symbolic_resolution(
                    role_reference,
                    "aws_iam_role.orders_task",
                    path=("task_role_arn",),
                ),
            ),
        )
        _inventory, task, _service_resource = _normalize(
            [_statement("Allow", _STOP_LOGGING, _TRAIL_ARN)],
            task_definition=symbolic_task,
        )
        paths = aws_facts(task).ecs_cloudtrail_audit_telemetry_disruption_paths
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["role_reference"], role_reference)

        raw_task = _task_definition(task_role_arn=role_reference)
        _inventory, task, _service_resource = _normalize(
            [_statement("Allow", _STOP_LOGGING, _TRAIL_ARN)],
            task_definition=raw_task,
        )
        self.assertEqual(
            aws_facts(task).ecs_cloudtrail_audit_telemetry_disruption_paths,
            [],
        )

    def test_provider_configuration_and_caller_ownership_are_exact(
        self,
    ) -> None:
        _inventory, mismatched_task, _service_resource = _normalize(
            [_statement("Allow", _STOP_LOGGING, _TRAIL_ARN)],
            trail=_trail(provider_config_key=_ALIAS_PROVIDER),
        )
        self.assertEqual(
            aws_facts(mismatched_task).ecs_cloudtrail_audit_telemetry_disruption_paths,
            [],
        )

        _inventory, alias_task, alias_service = _normalize(
            [_statement("Allow", _STOP_LOGGING, _TRAIL_ARN)],
            provider_config_key=_ALIAS_PROVIDER,
        )
        self.assertEqual(
            len(aws_facts(alias_task).ecs_cloudtrail_audit_telemetry_disruption_paths),
            1,
        )
        self.assertEqual(
            len(aws_facts(alias_service).ecs_cloudtrail_audit_telemetry_disruption_paths),
            1,
        )

        _inventory, foreign_task, _service_resource = _normalize(
            [_statement("Allow", _STOP_LOGGING, _TRAIL_ARN)],
            caller=_caller_identity(account_id=_FOREIGN_ACCOUNT_ID),
        )
        self.assertEqual(
            aws_facts(foreign_task).ecs_cloudtrail_audit_telemetry_disruption_paths,
            [],
        )

    def test_task_definition_may_reference_role_across_provider_aliases(
        self,
    ) -> None:
        _inventory, task, service = _normalize(
            [_statement("Allow", _STOP_LOGGING, _TRAIL_ARN)],
            task_definition=_task_definition(
                provider_config_key=_ALIAS_PROVIDER,
            ),
            service=_service(
                provider_config_key=_ALIAS_PROVIDER,
            ),
        )
        self.assertEqual(
            len(aws_facts(task).ecs_cloudtrail_audit_telemetry_disruption_paths),
            1,
        )
        self.assertEqual(
            len(aws_facts(service).ecs_cloudtrail_audit_telemetry_disruption_paths),
            1,
        )

    def test_service_does_not_resolve_weak_task_definition_reference_across_provider_aliases(
        self,
    ) -> None:
        _inventory, task, service = _normalize(
            [_statement("Allow", _STOP_LOGGING, _TRAIL_ARN)],
            task_definition=_task_definition(
                provider_config_key=_ALIAS_PROVIDER,
            ),
        )

        self.assertEqual(
            len(aws_facts(task).ecs_cloudtrail_audit_telemetry_disruption_paths),
            1,
        )
        self.assertEqual(
            aws_facts(service).ecs_cloudtrail_audit_telemetry_disruption_paths,
            [],
        )
        self.assertEqual(
            aws_facts(service).unresolved_task_definition_references,
            ["orders:1"],
        )

    def test_missing_caller_identity_fails_closed(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _trail(),
                _role([_statement("Allow", _STOP_LOGGING, _TRAIL_ARN)]),
                _task_definition(),
                _service(),
            ]
        )
        task = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task is not None
        self.assertEqual(
            aws_facts(task).ecs_cloudtrail_audit_telemetry_disruption_paths,
            [],
        )
        self.assertTrue(aws_facts(task).ecs_cloudtrail_audit_telemetry_disruption_path_uncertainties)

    def test_lifecycle_defaults_are_active_and_incompatible_states_are_quiet(
        self,
    ) -> None:
        _inventory, default_task, _service_resource = _normalize(
            [_statement("Allow", _STOP_LOGGING, _TRAIL_ARN)],
            trail=_trail(
                logging="omitted",
                organization="omitted",
            ),
        )
        self.assertEqual(
            len(aws_facts(default_task).ecs_cloudtrail_audit_telemetry_disruption_paths),
            1,
        )

        for case, trail in {
            "disabled": _trail(logging="disabled"),
            "logging unknown": _trail(logging="unknown"),
            "organization": _trail(organization="enabled"),
            "organization unknown": _trail(organization="unknown"),
        }.items():
            with self.subTest(case=case):
                _inventory, task, _service_resource = _normalize(
                    [_statement("Allow", _STOP_LOGGING, _TRAIL_ARN)],
                    trail=trail,
                )
                self.assertEqual(
                    aws_facts(task).ecs_cloudtrail_audit_telemetry_disruption_paths,
                    [],
                )
                if case != "disabled":
                    self.assertTrue(aws_facts(task).ecs_cloudtrail_audit_telemetry_disruption_path_uncertainties)

    def test_current_helper_recomputes_operation_local_authority(self) -> None:
        inventory, task, _service_resource = _normalize([_statement("Allow", _STOP_LOGGING, _TRAIL_ARN)])
        trail = inventory.get_by_address("aws_cloudtrail.audit")
        role = inventory.get_by_address("aws_iam_role.orders_task")
        assert trail is not None
        assert role is not None
        context = AwsDecorationContext(index=AwsResourceIndexBuilder().build(list(inventory.resources)))
        self.assertIsNotNone(
            current_ecs_cloudtrail_audit_telemetry_disruption_path(
                task,
                trail,
                _STOP_LOGGING,
                context,
            )
        )

        role.policy_statements = ()
        self.assertIsNone(
            current_ecs_cloudtrail_audit_telemetry_disruption_path(
                task,
                trail,
                _STOP_LOGGING,
                context,
            )
        )

        allow = _statement("Allow", _STOP_LOGGING, _TRAIL_ARN)
        deny = _statement("Deny", _STOP_LOGGING, _TRAIL_ARN)
        role.policy_statements = (
            parse_policy_statement(allow),
            parse_policy_statement(deny),
        )
        self.assertIsNone(
            current_ecs_cloudtrail_audit_telemetry_disruption_path(
                task,
                trail,
                _STOP_LOGGING,
                context,
            )
        )

    def test_service_projection_retains_modeled_paths(self) -> None:
        _inventory, task, service = _normalize([_statement("Allow", _DELETE_TRAIL, _TRAIL_ARN)])
        task_paths = aws_facts(task).ecs_cloudtrail_audit_telemetry_disruption_paths
        service_paths = aws_facts(service).ecs_cloudtrail_audit_telemetry_disruption_paths
        self.assertEqual(len(task_paths), 1)
        self.assertEqual(len(service_paths), 1)
        self.assertEqual(
            service_paths[0]["task_definition_address"],
            task.address,
        )


if __name__ == "__main__":
    unittest.main()
