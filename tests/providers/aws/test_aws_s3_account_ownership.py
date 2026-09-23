from __future__ import annotations

import json
import tempfile
import unittest
from copy import deepcopy
from itertools import permutations
from pathlib import Path

from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _ACCOUNT_ID,
    _BUCKET_ARN,
    _bucket,
    _role,
    _service,
    _statement,
    _task_definition,
)
from tests.providers.aws.test_aws_ecs_s3_object_deletion_paths import (
    _bucket_policy,
    _bucket_statement,
    _caller_identity,
)
from tests.providers.aws.test_aws_public_ecs_s3_object_disruption_rules import _runtime_resources
from tfstride.app import TfStride
from tfstride.models import ResourceInventory, TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts

FOREIGN = "444455556666"
TASK = "aws_ecs_task_definition.orders"
SERVICE = "aws_ecs_service.orders"
OBJECT_OPERATIONS = ["s3:DeleteObject", "s3:DeleteObjectVersion"]


def _scenario(
    *,
    bucket_scope: str | None = "aws",
    role_scope: str | None = "aws",
    role_account: str = _ACCOUNT_ID,
    identity_allow: bool = True,
    include_owner: bool = True,
) -> list[TerraformResource]:
    role_arn = f"arn:aws:iam::{role_account}:role/orders-task"
    bucket = _bucket()
    bucket.provider_config_key = bucket_scope
    role = _role(
        "orders_task",
        role_arn,
        [
            _statement("Allow", OBJECT_OPERATIONS, f"{_BUCKET_ARN}/*"),
            _statement("Allow", "s3:DeleteBucket", _BUCKET_ARN),
        ]
        if identity_allow
        else None,
    )
    role.provider_config_key = role_scope
    task = _task_definition(task_role_arn=role_arn, execution_role_arn=None)
    task.provider_config_key = role_scope
    service = _service()
    service.provider_config_key = role_scope
    resources = [bucket, role, task, service]
    if include_owner:
        caller = _caller_identity()
        caller.provider_config_key = bucket_scope
        resources.append(caller)
    return resources


def _grants(principal: str, *, scope: str = "aws", condition: dict | None = None) -> TerraformResource:
    policy = _bucket_policy(
        [
            _bucket_statement("Allow", OBJECT_OPERATIONS, f"{_BUCKET_ARN}/*", principal, condition=condition),
            _bucket_statement("Allow", "s3:DeleteBucket", _BUCKET_ARN, principal, condition=condition),
        ]
    )
    policy.provider_config_key = scope
    return policy


def _paths(inventory: ResourceInventory):
    result = []
    for address in (TASK, SERVICE):
        resource = inventory.get_by_address(address)
        assert resource is not None
        facts = aws_facts(resource)
        result.append((facts.ecs_s3_object_deletion_paths, facts.ecs_s3_bucket_topology_destruction_paths))
    return result


def _uncertainties(inventory: ResourceInventory) -> list[str]:
    task = inventory.get_by_address(TASK)
    assert task is not None
    facts = aws_facts(task)
    return [
        *facts.ecs_s3_object_deletion_path_uncertainties,
        *facts.ecs_s3_bucket_topology_destruction_path_uncertainties,
    ]


def _analyze_plan(resources: list[TerraformResource]):
    declarations = [
        {"address": item.address, "mode": item.mode, "type": item.resource_type, "name": item.name}
        for item in resources
    ]
    payload = {
        "terraform_version": "1.8.5",
        "planned_values": {
            "root_module": {
                "resources": [
                    {**declaration, "provider_name": item.provider_name, "values": item.values}
                    for declaration, item in zip(declarations, resources, strict=True)
                ]
            }
        },
        "configuration": {
            "root_module": {
                "resources": [
                    {**declaration, "provider_config_key": item.provider_config_key, "expressions": {}}
                    for declaration, item in zip(declarations, resources, strict=True)
                ]
            }
        },
    }
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "plan.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return TfStride().analyze_plan(path)


class AwsS3AccountOwnershipTests(unittest.TestCase):
    def assert_path_counts(self, inventory: ResourceInventory, objects: int, buckets: int) -> None:
        for object_paths, bucket_paths in _paths(inventory):
            self.assertEqual(len(object_paths), objects)
            self.assertEqual(len(bucket_paths), buckets)

    def test_unrelated_accounts_and_resource_order_preserve_established_paths(self) -> None:
        base = _scenario()
        baseline = AwsNormalizer().normalize(base)
        self.assert_path_counts(baseline, 2, 1)
        other_caller = _caller_identity(FOREIGN)
        other_caller.address = "data.aws_caller_identity.unrelated"
        other_caller.name = "unrelated"
        other_caller.provider_config_key = "aws.other"
        unrelated_role = _role("unrelated", f"arn:aws:iam::{FOREIGN}:role/unrelated", provider_config_key="aws.other")
        for extras in permutations([other_caller, unrelated_role]):
            for ordered in ([*base, *extras], [*extras, *reversed(base)]):
                inventory = AwsNormalizer().normalize(ordered)
                self.assertIsNone(inventory.primary_account_id)
                self.assertEqual(_paths(inventory), _paths(baseline))
                self.assertEqual(_uncertainties(inventory), _uncertainties(baseline))

    def test_two_aliases_for_one_account_do_not_block_either_operation_family(self) -> None:
        for role_scope in ("aws.runtime", None):
            with self.subTest(role_scope=role_scope):
                resources = _scenario(bucket_scope="aws.storage", role_scope=role_scope)
                if role_scope:
                    caller = _caller_identity()
                    caller.address = "data.aws_caller_identity.runtime"
                    caller.name = "runtime"
                    caller.provider_config_key = role_scope
                    resources.append(caller)
                for ordered in (resources, list(reversed(resources))):
                    inventory = AwsNormalizer().normalize(ordered)
                    self.assert_path_counts(inventory, 2, 1)
                    for object_paths, bucket_paths in _paths(inventory):
                        self.assertTrue(all(path["same_account"] for path in [*object_paths, *bucket_paths]))

    def test_bucket_ownership_cannot_be_inferred_from_role_or_inventory_arns(self) -> None:
        resources = _scenario(include_owner=False)
        resources.append(_role("unrelated", f"arn:aws:iam::{_ACCOUNT_ID}:role/unrelated"))
        inventory = AwsNormalizer().normalize(resources)
        self.assertEqual(inventory.primary_account_id, _ACCOUNT_ID)
        self.assert_path_counts(inventory, 0, 0)
        self.assertTrue(
            any(
                "no caller identity is modeled for provider configuration aws" in item
                for item in _uncertainties(inventory)
            )
        )

    def test_missing_unknown_conflicting_or_non_owner_evidence_is_not_repaired(self) -> None:
        cases: dict[str, list[TerraformResource]] = {}
        cases["missing configuration"] = _scenario(bucket_scope=None)
        wrong_alias = _scenario(bucket_scope="aws.storage")
        wrong_alias[-1].provider_config_key = "aws.other"
        cases["unrelated caller"] = wrong_alias
        data_lookup = _scenario()
        data_lookup[0].mode = "data"
        cases["data lookup"] = data_lookup
        for label, caller in (("unknown", _caller_identity()), ("invalid", _caller_identity("not-an-account"))):
            resources = _scenario(include_owner=False)
            if label == "unknown":
                caller.unknown_values = {"account_id": True, "id": True, "arn": True}
            resources.append(caller)
            cases[label] = resources
        conflict = _scenario()
        second_caller = _caller_identity(FOREIGN)
        second_caller.address = "data.aws_caller_identity.conflict"
        second_caller.name = "conflict"
        conflict.append(second_caller)
        cases["conflict"] = conflict
        mixed = _scenario()
        unknown_caller = _caller_identity()
        unknown_caller.address = "data.aws_caller_identity.unknown"
        unknown_caller.name = "unknown"
        unknown_caller.unknown_values = {"account_id": True, "id": True, "arn": True}
        mixed.append(unknown_caller)
        cases["known and unknown callers"] = mixed
        for label, resources in cases.items():
            with self.subTest(case=label):
                inventory = AwsNormalizer().normalize(resources)
                self.assert_path_counts(inventory, 0, 0)
                self.assertTrue(any("target account:" in item for item in _uncertainties(inventory)))
                self.assertTrue(any("ownership" in item for item in _uncertainties(inventory)))

    def test_ambiguous_role_identity_is_not_repaired_by_bucket_owner(self) -> None:
        resources = _scenario()
        resources[1].values["id"] = f"arn:aws:iam::{FOREIGN}:role/orders-task"
        inventory = AwsNormalizer().normalize(resources)
        self.assert_path_counts(inventory, 0, 0)
        self.assertTrue(any("source account: state=ambiguous" in item for item in _uncertainties(inventory)))

    def test_two_sided_policy_grants_do_not_establish_unknown_bucket_ownership(self) -> None:
        resources = _scenario(role_account=FOREIGN, include_owner=False)
        resources.append(_grants(f"arn:aws:iam::{FOREIGN}:role/orders-task"))
        inventory = AwsNormalizer().normalize(resources)
        self.assertEqual(inventory.primary_account_id, FOREIGN)
        self.assert_path_counts(inventory, 0, 0)
        self.assertTrue(any("target account: state=unknown" in item for item in _uncertainties(inventory)))

    def test_foreign_role_requires_two_sided_object_authority_even_under_same_alias(self) -> None:
        for role_scope in ("aws", "aws.foreign"):
            for identity_allow in (False, True):
                for principal in (
                    None,
                    f"arn:aws:iam::{FOREIGN}:role/orders-task",
                    f"arn:aws:iam::{FOREIGN}:root",
                    FOREIGN,
                    f"arn:aws:iam::{_ACCOUNT_ID}:root",
                ):
                    with self.subTest(scope=role_scope, identity=identity_allow, principal=principal):
                        resources = _scenario(
                            role_account=FOREIGN, role_scope=role_scope, identity_allow=identity_allow
                        )
                        if principal:
                            resources.append(_grants(principal))
                        inventory = AwsNormalizer().normalize(resources)
                        allowed = identity_allow and principal is not None and FOREIGN in principal
                        self.assert_path_counts(inventory, 2 if allowed else 0, 0)
                        for object_paths, _ in _paths(inventory):
                            for path in object_paths:
                                self.assertFalse(path["same_account"])
                                self.assertEqual(
                                    path["authorization_bases"], ["cross_account_identity_and_bucket_policy"]
                                )

    def test_direct_role_bucket_grants_remain_valid_for_same_account_across_aliases(self) -> None:
        resources = _scenario(bucket_scope="aws.storage", role_scope="aws.runtime", identity_allow=False)
        resources.append(_grants(f"arn:aws:iam::{_ACCOUNT_ID}:role/orders-task", scope="aws.storage"))
        inventory = AwsNormalizer().normalize(resources)
        self.assert_path_counts(inventory, 2, 1)
        for object_paths, _ in _paths(inventory):
            self.assertTrue(all(path["authorization_bases"] == ["bucket_policy_direct"] for path in object_paths))

    def test_cross_account_deny_conditions_and_incomplete_policies_still_fail_closed(self) -> None:
        principal = f"arn:aws:iam::{FOREIGN}:role/orders-task"
        conditional = _grants(principal, condition={"StringEquals": {"aws:PrincipalTag/team": "storage"}})
        unknown = _grants(principal)
        unknown.unknown_values = {"policy": True}
        disjoint = _grants(principal)
        # The role allows only a separate object namespace in this case.
        for label, grant in (("conditional", conditional), ("unknown", unknown), ("disjoint", disjoint)):
            with self.subTest(case=label):
                resources = _scenario(role_account=FOREIGN)
                if label == "disjoint":
                    resources[1] = _role(
                        "orders_task", principal, [_statement("Allow", OBJECT_OPERATIONS, f"{_BUCKET_ARN}/private/*")]
                    )
                    grant.values["policy"] = json.dumps(
                        {
                            "Statement": [
                                _bucket_statement("Allow", OBJECT_OPERATIONS, f"{_BUCKET_ARN}/public/*", principal)
                            ]
                        }
                    )
                inventory = AwsNormalizer().normalize([*resources, grant])
                self.assert_path_counts(inventory, 0, 0)
        denied = _grants(principal)
        policy = json.loads(denied.values["policy"])
        policy["Statement"].append(_bucket_statement("Deny", "s3:DeleteObject", f"{_BUCKET_ARN}/*", principal))
        denied.values["policy"] = json.dumps(policy)
        inventory = AwsNormalizer().normalize([*_scenario(role_account=FOREIGN), denied])
        self.assert_path_counts(inventory, 1, 0)
        self.assertEqual(_paths(inventory)[0][0][0]["operation"], "s3:DeleteObjectVersion")

    def test_cross_partition_authority_is_not_promoted(self) -> None:
        resources = _scenario()
        role = resources[1]
        role.values["arn"] = role.values["arn"].replace("arn:aws:", "arn:aws-cn:")
        resources[2].values["task_role_arn"] = role.values["arn"]
        inventory = AwsNormalizer().normalize([*resources, _grants(role.values["arn"])])
        self.assert_path_counts(inventory, 0, 0)
        self.assertTrue(any("cross-partition" in item for item in _uncertainties(inventory)))

    def test_plan_ingestion_and_downstream_finding_require_bucket_local_ownership(self) -> None:
        resources = _runtime_resources("s3:DeleteObject", versioning="disabled")
        # Separate the bucket's provider configuration from the workload's.
        for resource in resources:
            if resource.resource_type.startswith("aws_s3_") or resource.resource_type == "aws_caller_identity":
                resource.provider_config_key = "aws.storage"
        baseline = _analyze_plan(resources)
        findings = [item for item in baseline.findings if item.rule_id == "aws-public-ecs-s3-object-disruption"]
        self.assertEqual(len(findings), 1)
        caller = _caller_identity(FOREIGN)
        caller.address = "data.aws_caller_identity.unrelated"
        caller.name = "unrelated"
        caller.provider_config_key = "aws.unrelated"
        result = _analyze_plan([caller, *reversed(resources)])
        self.assertEqual(_paths(result.inventory), _paths(baseline.inventory))
        self.assertEqual(
            [item for item in result.findings if item.rule_id == "aws-public-ecs-s3-object-disruption"], findings
        )
        without_owner = [deepcopy(item) for item in resources if item.resource_type != "aws_caller_identity"]
        unknown = _analyze_plan(without_owner)
        self.assertEqual(
            [item for item in unknown.findings if item.rule_id == "aws-public-ecs-s3-object-disruption"], []
        )
        self.assert_path_counts(unknown.inventory, 0, 0)


if __name__ == "__main__":
    unittest.main()
