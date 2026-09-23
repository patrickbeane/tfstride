from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from itertools import permutations
from pathlib import Path
from typing import Any

from tfstride.input.terraform_plan import load_terraform_plan
from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.aws.account_identity import build_aws_account_identity_index
from tfstride.providers.aws.account_identity_evidence import AwsAccountResolution
from tfstride.providers.aws.account_identity_normalizers import with_account_identity_inputs
from tfstride.providers.aws.iam_normalizers import normalize_iam_role
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_index import AwsResourceIndexBuilder

ACCOUNT = "111122223333"
FOREIGN_ACCOUNT = "444455556666"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/app"


def _resource(
    resource_type: str = "aws_iam_role",
    name: str = "app",
    *,
    values: dict[str, Any] | None = None,
    scope: str | None = "aws.workload",
    mode: str = "managed",
    unknown: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"{'data.' if mode == 'data' else ''}{resource_type}.{name}",
        mode=mode,
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        provider_config_key=scope,
        values=values if values is not None else {"name": name},
        unknown_values=unknown or {},
    )


def _caller(
    account: str | None = ACCOUNT,
    name: str = "current",
    *,
    scope: str | None = "aws.workload",
    values: dict[str, Any] | None = None,
    unknown: dict[str, Any] | None = None,
) -> TerraformResource:
    return _resource(
        "aws_caller_identity",
        name,
        mode="data",
        scope=scope,
        values=values if values is not None else {"account_id": account},
        unknown=unknown,
    )


def _resolve(target: TerraformResource, *others: TerraformResource) -> AwsAccountResolution:
    inventory = AwsNormalizer().normalize([target, *others])
    normalized = next(resource for resource in inventory.resources if resource.address == target.address)
    return AwsResourceIndexBuilder().build(inventory.resources).account_identities.resolve(normalized)


class AwsAccountIdentityTests(unittest.TestCase):
    def test_strong_identity_is_independent_of_inventory_and_caller_accounts(self) -> None:
        target = _resource(values={"arn": ROLE_ARN})
        expected = _resolve(target)
        unrelated = _resource(name="foreign", values={"arn": f"arn:aws:iam::{FOREIGN_ACCOUNT}:role/foreign"})
        for caller in (_caller(FOREIGN_ACCOUNT), _caller("invalid"), _caller(None)):
            with self.subTest(caller=caller.values):
                self.assertEqual(_resolve(target, unrelated, caller), expected)
        self.assertEqual((expected.state, expected.account_id), ("resolved", ACCOUNT))
        self.assertIn(f"{target.address}.arn = {ROLE_ARN}", expected.evidence)
        self.assertIsNone(AwsNormalizer().normalize([target, unrelated]).primary_account_id)

    def test_caller_identity_fallback_is_scoped_to_exact_provider_configuration(self) -> None:
        callers = [_caller(), _caller(FOREIGN_ACCOUNT, "foreign", scope="aws.foreign")]
        for scope, account in (("aws.workload", ACCOUNT), ("aws.foreign", FOREIGN_ACCOUNT)):
            with self.subTest(scope=scope):
                bucket = _resource(
                    "aws_s3_bucket", values={"bucket": "assets", "arn": "arn:aws:s3:::assets"}, scope=scope
                )
                result = _resolve(bucket, *callers)
                self.assertEqual((result.state, result.account_id), ("resolved", account))
                self.assertTrue(any(f"provider configuration {scope}" in item for item in result.evidence))
                self.assertFalse(
                    any(
                        other in item
                        for item in result.evidence
                        for other in ([FOREIGN_ACCOUNT] if account == ACCOUNT else [ACCOUNT])
                    )
                )

    def test_unrelated_unknown_and_invalid_callers_do_not_poison_local_scope(self) -> None:
        target = _resource()
        expected = _resolve(target, _caller())
        for caller in (_caller(None, "unknown", scope="aws.foreign"), _caller("invalid", "bad", scope=None)):
            with self.subTest(caller=caller.address):
                self.assertEqual(_resolve(target, _caller(), caller), expected)

    def test_missing_configuration_never_uses_inventory_primary_account(self) -> None:
        for target_scope, caller_scope in (
            (None, None),
            (None, "aws.workload"),
            ("aws.workload", None),
            ("aws.other", "aws.workload"),
        ):
            with self.subTest(target_scope=target_scope, caller_scope=caller_scope):
                target = _resource(scope=target_scope)
                caller = _caller(scope=caller_scope)
                self.assertEqual(AwsNormalizer().normalize([target, caller]).primary_account_id, ACCOUNT)
                result = _resolve(target, caller)
                self.assertEqual((result.state, result.account_id), ("unknown", None))
                self.assertTrue(result.uncertainties)

    def test_data_lookup_does_not_inherit_provider_ownership(self) -> None:
        bucket = _resource("aws_s3_bucket", mode="data", values={"arn": "arn:aws:s3:::foreign-assets"})
        result = _resolve(bucket, _caller())
        self.assertEqual((result.state, result.account_id), ("unknown", None))
        self.assertTrue(any("does not establish resource ownership" in item for item in result.uncertainties))
        role = _resource(mode="data", values={"arn": ROLE_ARN})
        self.assertEqual(_resolve(role, _caller(FOREIGN_ACCOUNT)).account_id, ACCOUNT)

    def test_related_resource_arn_does_not_establish_ownership(self) -> None:
        for resource_type, values in (
            ("aws_iam_role_policy_attachment", {"role": "app", "policy_arn": f"arn:aws:iam::{ACCOUNT}:policy/app"}),
            ("aws_dynamodb_resource_policy", {"resource_arn": f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/app"}),
        ):
            with self.subTest(resource_type=resource_type):
                result = _resolve(_resource(resource_type, values=values), _caller())
                self.assertEqual((result.state, result.account_id), ("unknown", None))

    def test_aws_managed_policy_does_not_inherit_customer_account(self) -> None:
        target = _resource("aws_iam_policy", values={"arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"})
        result = _resolve(target, _caller())
        self.assertEqual((result.state, result.account_id), ("unknown", None))
        self.assertTrue(any("AWS-managed policy" in item for item in result.uncertainties))

    def test_unknown_arn_cannot_use_stale_planned_identity(self) -> None:
        target = _resource(values={"arn": ROLE_ARN}, unknown={"arn": True})
        self.assertEqual(_resolve(target).state, "unknown")
        result = _resolve(target, _caller(FOREIGN_ACCOUNT))
        self.assertEqual((result.state, result.account_id), ("resolved", FOREIGN_ACCOUNT))
        self.assertTrue(any("arn: unknown identity evidence" in item for item in result.uncertainties))
        self.assertFalse(any(ROLE_ARN in item for item in result.evidence))
        self.assertEqual(target.values["arn"], ROLE_ARN)
        self.assertEqual(target.unknown_values, {"arn": True})

    def test_aws_managed_policy_and_customer_identity_are_conflicting_evidence(self) -> None:
        target = _resource(
            "aws_iam_policy",
            values={
                "arn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                "id": f"arn:aws:iam::{ACCOUNT}:policy/ReadOnlyAccess",
            },
        )
        result = _resolve(target, _caller())
        self.assertEqual((result.state, result.account_id), ("ambiguous", None))

    def test_known_own_arn_identifier_can_resolve_an_unknown_arn(self) -> None:
        target = _resource(values={"arn": "stale", "id": ROLE_ARN}, unknown={"arn": True})
        result = _resolve(target)
        self.assertEqual((result.state, result.account_id), ("resolved", ACCOUNT))
        self.assertTrue(any(".id = " in item for item in result.evidence))
        self.assertTrue(any("arn: unknown identity evidence" in item for item in result.uncertainties))

    def test_conflicting_own_identity_evidence_cannot_be_repaired_by_caller(self) -> None:
        for identifier in (f"arn:aws:iam::{FOREIGN_ACCOUNT}:role/app", f"arn:aws-cn:iam::{ACCOUNT}:role/app"):
            with self.subTest(identifier=identifier):
                target = _resource(values={"arn": ROLE_ARN, "id": identifier})
                result = _resolve(target, _caller())
                self.assertEqual((result.state, result.account_id), ("ambiguous", None))
                self.assertTrue(any(ROLE_ARN in item for item in result.evidence))
                self.assertTrue(any(identifier in item for item in result.evidence))

    def test_malformed_own_identity_cannot_be_repaired_by_caller(self) -> None:
        for arn in (
            "arn:aws:iam::111122223333",
            "arn:aws:iam::111122223333:",
            "arn:aws:iam::111122223333:role/*",
            "arn:aws:iam::１１１１２２２２３３３３:role/app",
            "arn:aws:iam:us-east-1:111122223333:role/app",
            "arn:aws:iam::111122223333:policy/app",
            "arn:aws:iam::111122223333:role/",
            "arn:aws:iam::111122223333:role/app ",
        ):
            with self.subTest(arn=arn):
                result = _resolve(_resource(values={"arn": arn}), _caller())
                self.assertEqual((result.state, result.account_id), ("invalid", None))
                self.assertTrue(result.uncertainties)

    def test_non_string_own_arn_is_invalid_evidence(self) -> None:
        # Exercise the retained input independently of legacy ARN consumers.
        target = with_account_identity_inputs(normalize_iam_role)(_resource(values={"arn": 123}))
        result = build_aws_account_identity_index([]).resolve(target)
        self.assertEqual((result.state, result.account_id), ("invalid", None))

    def test_bucket_arn_with_account_segment_is_not_an_ownership_proof(self) -> None:
        bucket = _resource("aws_s3_bucket", values={"arn": f"arn:aws:s3::{ACCOUNT}:assets"})
        self.assertEqual(_resolve(bucket, _caller()).state, "invalid")

    def test_api_gateway_execution_arn_supplies_own_account(self) -> None:
        for resource_type in ("aws_api_gateway_rest_api", "aws_apigatewayv2_api"):
            with self.subTest(resource_type=resource_type):
                target = _resource(
                    resource_type,
                    values={
                        "arn": "arn:aws:apigateway:us-east-1::/restapis/api-id",
                        "execution_arn": f"arn:aws:execute-api:us-east-1:{ACCOUNT}:api-id",
                    },
                )
                self.assertEqual(_resolve(target, _caller(FOREIGN_ACCOUNT)).account_id, ACCOUNT)
                target.unknown_values = {"execution_arn": True}
                self.assertEqual(_resolve(target).state, "unknown")

    def test_conflicting_callers_in_same_scope_are_ambiguous(self) -> None:
        result = _resolve(_resource(), _caller(), _caller(FOREIGN_ACCOUNT, "conflict"))
        self.assertEqual((result.state, result.account_id), ("ambiguous", None))
        self.assertTrue(any("conflicting account" in item for item in result.uncertainties))

    def test_conflicting_fields_within_one_caller_preserve_candidate_evidence(self) -> None:
        caller = _caller(values={"account_id": ACCOUNT, "id": FOREIGN_ACCOUNT})
        result = _resolve(_resource(), caller)
        self.assertEqual((result.state, result.account_id), ("ambiguous", None))
        self.assertIn(f"{caller.address}.account_id = {ACCOUNT}", result.evidence)
        self.assertIn(f"{caller.address}.id = {FOREIGN_ACCOUNT}", result.evidence)

    def test_incomplete_or_invalid_local_caller_is_not_ignored(self) -> None:
        for caller, state in (
            (_caller(None, "unknown"), "unknown"),
            (_caller("invalid", "bad"), "invalid"),
            (_caller(name="conflict", values={"account_id": ACCOUNT, "id": FOREIGN_ACCOUNT}), "ambiguous"),
        ):
            with self.subTest(state=state):
                result = _resolve(_resource(), _caller(), caller)
                self.assertEqual((result.state, result.account_id), (state, None))
                self.assertTrue(result.uncertainties)

    def test_agreeing_callers_in_same_scope_can_establish_ownership(self) -> None:
        result = _resolve(_resource(), _caller(), _caller(name="duplicate"))
        self.assertEqual((result.state, result.account_id), ("resolved", ACCOUNT))

    def test_caller_known_account_with_unknown_arn_retains_uncertainty(self) -> None:
        caller = _caller(
            values={"account_id": ACCOUNT, "arn": f"arn:aws:iam::{FOREIGN_ACCOUNT}:user/stale"}, unknown={"arn": True}
        )
        result = _resolve(_resource(), caller)
        self.assertEqual((result.state, result.account_id), ("resolved", ACCOUNT))
        self.assertTrue(any("arn" in item for item in result.uncertainties))
        self.assertFalse(any(FOREIGN_ACCOUNT in item for item in result.evidence))

    def test_malformed_caller_arn_is_not_validated_by_its_account_segment_alone(self) -> None:
        for arn in (
            f"arn:aws:iam::{ACCOUNT}",
            f"arn:aws:iam::{ACCOUNT}:policy/app",
            f"arn:aws:sqs:us-east-1:{ACCOUNT}:app",
            f"arn:aws:sts::{ACCOUNT}:assumed-role/app",
        ):
            with self.subTest(arn=arn):
                result = _resolve(_resource(), _caller(values={"arn": arn}))
                self.assertEqual((result.state, result.account_id), ("invalid", None))

    def test_valid_caller_principal_arns_establish_scoped_identity(self) -> None:
        for partition in ("aws", "aws-cn", "aws-us-gov"):
            for suffix in (
                "iam::ACCOUNT:root",
                "iam::ACCOUNT:user/deployer",
                "sts::ACCOUNT:assumed-role/deployer/session",
                "sts::ACCOUNT:federated-user/deployer",
            ):
                arn = f"arn:{partition}:{suffix.replace('ACCOUNT', ACCOUNT)}"
                with self.subTest(arn=arn):
                    result = _resolve(_resource(), _caller(values={"arn": arn}))
                    self.assertEqual(
                        (result.state, result.account_id, result.partition), ("resolved", ACCOUNT, partition)
                    )

    def test_strong_identity_resolves_without_provider_configuration(self) -> None:
        result = _resolve(_resource(values={"arn": ROLE_ARN}, scope=None), _caller(FOREIGN_ACCOUNT))
        self.assertEqual((result.state, result.account_id), ("resolved", ACCOUNT))

    def test_plan_ingestion_retains_scope_mode_and_unknown_identity(self) -> None:
        resources = [
            _resource(values={"arn": ROLE_ARN}, unknown={"arn": True}),
            _resource("aws_s3_bucket", "lookup", mode="data", values={"arn": "arn:aws:s3:::lookup"}),
            _caller(FOREIGN_ACCOUNT),
            _caller(name="unrelated", scope="aws.other"),
        ]
        declarations = [
            {"address": item.address, "type": item.resource_type, "name": item.name, "mode": item.mode}
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
            "resource_changes": [{"address": resources[0].address, "change": {"after_unknown": {"arn": True}}}],
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
            inventory = AwsNormalizer().normalize(load_terraform_plan(path).resources)
        index = AwsResourceIndexBuilder().build(inventory.resources)
        by_address = {item.address: item for item in inventory.resources}
        result = index.account_identities.resolve(by_address[resources[0].address])
        self.assertEqual((result.state, result.account_id), ("resolved", FOREIGN_ACCOUNT))
        self.assertTrue(any("arn: unknown identity evidence" in item for item in result.uncertainties))
        self.assertEqual(index.account_identities.resolve(by_address[resources[1].address]).state, "unknown")

    def test_partition_conflicts_are_not_hidden_by_matching_account_digits(self) -> None:
        china = _caller(name="china", values={"arn": f"arn:aws-cn:sts::{ACCOUNT}:assumed-role/deployer/session"})
        standard = _caller(values={"arn": f"arn:aws:iam::{ACCOUNT}:user/deployer"})
        self.assertEqual(_resolve(_resource(), china, standard).state, "ambiguous")
        bucket = _resource("aws_s3_bucket", values={"arn": "arn:aws:s3:::assets"})
        result = _resolve(bucket, china)
        self.assertEqual((result.state, result.account_id), ("ambiguous", None))

    def test_existing_reference_resolution_selects_target_before_account_resolution(self) -> None:
        local = _resource(values={"name": "shared", "arn": ROLE_ARN})
        foreign = _resource(
            name="foreign",
            scope="aws.foreign",
            values={
                "name": "shared",
                "arn": f"arn:aws:iam::{FOREIGN_ACCOUNT}:role/shared",
            },
        )
        inventory = AwsNormalizer().normalize([local, foreign])
        index = AwsResourceIndexBuilder().build(inventory.resources)
        source = next(item for item in inventory.resources if item.address == local.address)
        selected = index.role_index.get("shared", source=source)
        self.assertIsNotNone(selected)
        assert selected is not None
        self.assertEqual(index.account_identities.resolve(selected).account_id, ACCOUNT)
        selected = index.role_index.get(foreign.values["arn"], source=source)
        self.assertIsNotNone(selected)
        assert selected is not None
        self.assertEqual(index.account_identities.resolve(selected).account_id, FOREIGN_ACCOUNT)

    def test_hand_built_resource_needs_provenance_for_caller_fallback(self) -> None:
        target = NormalizedResource(
            address="aws_iam_role.app",
            provider="aws",
            resource_type="aws_iam_role",
            name="app",
            category=ResourceCategory.IAM,
            provider_config_key="aws.workload",
        )
        callers = AwsNormalizer().normalize([_caller()]).resources
        index = build_aws_account_identity_index(callers)
        self.assertEqual(index.resolve(target).state, "unknown")
        target.arn = ROLE_ARN
        self.assertEqual(index.resolve(target).account_id, ACCOUNT)
        target.provider = "gcp"
        self.assertEqual(index.resolve(target).state, "unknown")

    def test_resource_permutations_preserve_result_and_evidence(self) -> None:
        target = _resource()
        for extra in (_caller(name="duplicate"), _caller(FOREIGN_ACCOUNT, "conflict"), _caller(None, "unknown")):
            resources = [target, _caller(), extra, _caller("invalid", "unrelated", scope="aws.unrelated")]
            expected = _resolve(target, *resources[1:])
            for ordered in permutations(resources):
                inventory = AwsNormalizer().normalize(list(ordered))
                normalized = next(item for item in inventory.resources if item.address == target.address)
                actual = AwsResourceIndexBuilder().build(inventory.resources).account_identities.resolve(normalized)
                self.assertEqual(actual, expected)

    def test_resolution_result_is_immutable(self) -> None:
        result = _resolve(_resource(), _caller())
        with self.assertRaises(FrozenInstanceError):
            result.account_id = FOREIGN_ACCOUNT


if __name__ == "__main__":
    unittest.main()
