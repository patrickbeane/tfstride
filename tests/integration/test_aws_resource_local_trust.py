from __future__ import annotations

import json
import tempfile
import unittest
from itertools import permutations
from pathlib import Path
from typing import Any

from tfstride.app import TfStride
from tfstride.models import AnalysisResult, BoundaryType, Finding, Observation, TerraformResource

ACCOUNT = "111122223333"
FOREIGN = "444455556666"
ROLE = "aws_iam_role.target"
EXPANSION = "aws-role-trust-expansion"
NARROWING = "aws-role-trust-missing-narrowing"
POLICY = "aws-sensitive-resource-policy-external-access"
SERVICE_POLICY = "aws-service-resource-policy-external-access"
GRANT = "aws-kms-grant-broad-authorization"
CHAIN = "aws-control-plane-sensitive-workload-chain"


def _resource(
    resource_type: str,
    name: str,
    values: dict[str, Any],
    *,
    scope: str | None = None,
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
        values=values,
        unknown_values=unknown or {},
    )


def _policy(
    principal: str, action: str, *, kind: str = "AWS", condition: dict[str, Any] | None = None
) -> dict[str, Any]:
    statement: dict[str, Any] = {"Effect": "Allow", "Principal": {kind: principal}, "Action": action, "Resource": "*"}
    if condition:
        statement["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [statement]}


def _role(
    principal: str | None = None,
    *,
    name: str = "target",
    account: str | None = ACCOUNT,
    kind: str = "AWS",
    condition: dict[str, Any] | None = None,
    scope: str | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {"name": name}
    if account:
        values["arn"] = f"arn:aws:iam::{account}:role/{name}"
    if principal:
        action = "sts:AssumeRole"
        if kind == "Federated":
            action = "sts:AssumeRoleWithSAML" if ":saml-provider/" in principal else "sts:AssumeRoleWithWebIdentity"
        values["assume_role_policy"] = _policy(principal, action, kind=kind, condition=condition)
    return _resource("aws_iam_role", name, values, scope=scope)


def _caller(account: str | None, scope: str, name: str = "current") -> TerraformResource:
    return _resource("aws_caller_identity", name, {"account_id": account}, scope=scope, mode="data")


def _analyze(resources: list[TerraformResource]) -> AnalysisResult:
    declarations = [
        {"address": item.address, "type": item.resource_type, "mode": item.mode, "name": item.name}
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
        "resource_changes": [
            {"address": item.address, "change": {"after_unknown": item.unknown_values}}
            for item in resources
            if item.unknown_values
        ],
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


def _findings(result: AnalysisResult, *rules: str) -> list[Finding]:
    return [item for item in result.findings if item.rule_id in rules]


def _evidence(item: Finding | Observation) -> dict[str, list[str]]:
    return {entry.key: entry.values for entry in item.evidence}


def _trust_boundary(result: AnalysisResult, target: str = ROLE):
    return next(
        item
        for item in result.trust_boundaries
        if item.boundary_type == BoundaryType.CROSS_ACCOUNT_OR_ROLE and item.target == target
    )


class AwsResourceLocalTrustTests(unittest.TestCase):
    def test_unrelated_account_cannot_change_role_findings_or_boundary(self) -> None:
        target = _role(f"arn:aws:iam::{FOREIGN}:role/deployer")
        baseline = _analyze([target])
        expected = _findings(baseline, EXPANSION, NARROWING)
        self.assertEqual(len(expected), 2)
        unrelated = _role(name="unrelated", account=FOREIGN)
        for ordered in permutations([target, unrelated]):
            result = _analyze(list(ordered))
            self.assertIsNone(result.inventory.primary_account_id)
            self.assertEqual(_findings(result, EXPANSION, NARROWING), expected)
            self.assertEqual(_trust_boundary(result), _trust_boundary(baseline))
            self.assertIn("foreign AWS account", _trust_boundary(result).rationale)

    def test_narrowing_observation_uses_same_account_evidence_as_findings(self) -> None:
        principal = f"arn:aws:iam::{FOREIGN}:role/deployer"
        unrelated = _role(name="unrelated", account=FOREIGN)
        open_result = _analyze([_role(principal), unrelated])
        condition = {"StringEquals": {"sts:ExternalId": "deployment-123"}}
        target = _role(principal, condition=condition)
        baseline = _analyze([target])
        for ordered in permutations([target, unrelated]):
            result = _analyze(list(ordered))
            self.assertEqual(_findings(result, EXPANSION, NARROWING), [])
            self.assertEqual(result.observations, baseline.observations)
            observation = next(item for item in result.observations if item.observation_id == "aws-role-trust-narrowed")
            finding = _findings(open_result, NARROWING)[0]
            for key in ("trust_scope", "target_account_resolution"):
                self.assertEqual(_evidence(observation)[key], _evidence(finding)[key])
            self.assertEqual(_trust_boundary(result), _trust_boundary(open_result))

    def test_unknown_target_does_not_borrow_summary_account_for_exact_principal(self) -> None:
        unrelated = _role(name="unrelated")
        for condition in (None, {"StringEquals": {"sts:ExternalId": "deployment-123"}}):
            result = _analyze(
                [_role(f"arn:aws:iam::{FOREIGN}:role/deployer", account=None, condition=condition), unrelated]
            )
            self.assertEqual(result.inventory.primary_account_id, ACCOUNT)
            self.assertEqual(_findings(result, EXPANSION, NARROWING), [])
            self.assertEqual(result.observations, [])
            self.assertNotIn("foreign", _trust_boundary(result).rationale)

    def test_account_roots_and_wildcards_keep_breadth_with_unknown_ownership(self) -> None:
        for account in (ACCOUNT, None):
            for principal in ("*", f"arn:aws:iam::{ACCOUNT}:root", f"arn:aws:iam::{FOREIGN}:root", FOREIGN):
                with self.subTest(account=account, principal=principal):
                    result = _analyze([_role(principal, account=account), _role(name="unrelated", account=FOREIGN)])
                    findings = _findings(result, EXPANSION, NARROWING)
                    self.assertEqual(len(findings), 2)
                    evidence = _evidence(next(item for item in findings if item.rule_id == NARROWING))
                    self.assertIn(
                        f"state={'resolved' if account else 'unknown'}", evidence["target_account_resolution"]
                    )
                    if account is None or ACCOUNT in principal or principal == "*":
                        self.assertNotIn("foreign", " ".join(evidence["trust_scope"]))
                    else:
                        self.assertIn("foreign", " ".join(evidence["trust_scope"]))
                    self.assertIsNotNone(_trust_boundary(result))

    def test_scoped_caller_identity_classifies_role_without_arn(self) -> None:
        principal = f"arn:aws:iam::{FOREIGN}:role/deployer"
        target = _role(principal, account=None, scope="aws.target")
        local = _caller(ACCOUNT, "aws.target")
        remote = _caller(FOREIGN, "aws.remote", "remote")
        for ordered in permutations([target, local, remote]):
            result = _analyze(list(ordered))
            self.assertEqual(len(_findings(result, EXPANSION, NARROWING)), 2)
        # Same names under a different provider configuration do not establish local ownership.
        self.assertEqual(_findings(_analyze([target, remote]), EXPANSION, NARROWING), [])
        self.assertEqual(
            _findings(_analyze([target, local, _caller(FOREIGN, "aws.target", "conflict")]), EXPANSION, NARROWING), []
        )

    def test_strong_target_identity_wins_over_different_caller_account(self) -> None:
        principal = f"arn:aws:iam::{FOREIGN}:role/deployer"
        target = _role(principal, scope="aws.target")
        baseline = _analyze([target])
        result = _analyze([target, _caller(FOREIGN, "aws.target")])
        self.assertEqual(result.inventory.primary_account_id, FOREIGN)
        self.assertEqual(_findings(result, EXPANSION, NARROWING), _findings(baseline, EXPANSION, NARROWING))

    def test_federated_scope_stays_resource_local_with_and_without_narrowing(self) -> None:
        providers = (
            ("saml-provider/corporate", {"StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}}),
            (
                "oidc-provider/token.actions.githubusercontent.com",
                {
                    "StringEquals": {
                        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                        "token.actions.githubusercontent.com:sub": "repo:example/app:ref:refs/heads/main",
                    }
                },
            ),
        )
        for suffix, condition in providers:
            for principal_account in (ACCOUNT, FOREIGN):
                for narrowed in (False, True):
                    with self.subTest(provider=suffix, account=principal_account, narrowed=narrowed):
                        target = _role(
                            f"arn:aws:iam::{principal_account}:{suffix}",
                            kind="Federated",
                            condition=condition if narrowed else None,
                        )
                        baseline = _analyze([target])
                        result = _analyze([_role(name="unrelated", account=FOREIGN), target])
                        self.assertEqual(
                            _findings(result, EXPANSION, NARROWING), _findings(baseline, EXPANSION, NARROWING)
                        )
                        self.assertEqual(result.observations, baseline.observations)
                        self.assertEqual(_trust_boundary(result), _trust_boundary(baseline))
                        records = result.observations if narrowed else _findings(result, NARROWING)
                        self.assertEqual(len(records), 1)
                        self.assertEqual(
                            "foreign" in " ".join(_evidence(records[0])["trust_scope"]), principal_account == FOREIGN
                        )

    def test_kms_root_treatment_requires_proven_same_account(self) -> None:
        for target_account, principal_account, partition, expected_severity in (
            (ACCOUNT, ACCOUNT, "aws", "medium"),
            (ACCOUNT, FOREIGN, "aws", "high"),
            (None, ACCOUNT, "aws", "high"),
            (ACCOUNT, ACCOUNT, "aws-cn", "high"),
        ):
            with self.subTest(target=target_account, principal=principal_account, partition=partition):
                values: dict[str, Any] = {
                    "key_id": "customer",
                    "policy": _policy(f"arn:aws:iam::{principal_account}:root", "kms:*"),
                }
                if target_account:
                    region = "cn-north-1" if partition == "aws-cn" else "us-east-1"
                    values["arn"] = f"arn:{partition}:kms:{region}:{target_account}:key/customer"
                target = _resource("aws_kms_key", "customer", values)
                result = _analyze([target, _role(name="unrelated", account=FOREIGN)])
                finding = _findings(result, POLICY)[0]
                self.assertEqual(finding.severity.value, expected_severity)
                evidence = _evidence(finding)
                self.assertIn(
                    f"state={'resolved' if target_account else 'unknown'}", evidence["target_account_resolution"]
                )
                if expected_severity == "medium":
                    self.assertIn("enables IAM policies", finding.rationale)
                    self.assertEqual(_findings(_analyze([target]), POLICY), [finding])
                self.assertIsNotNone(_trust_boundary(result, target.address))

    def test_kms_root_treatment_requires_partition_from_scoped_caller_identity(self) -> None:
        for arn_unknown in (False, True):
            with self.subTest(arn_unknown=arn_unknown):
                target = _resource(
                    "aws_kms_key",
                    "customer",
                    {"key_id": "customer", "policy": _policy(f"arn:aws-cn:iam::{ACCOUNT}:root", "kms:*")},
                    scope="aws.target",
                    unknown={"arn": True} if arn_unknown else None,
                )
                caller = _resource(
                    "aws_caller_identity",
                    "current",
                    {"account_id": ACCOUNT},
                    scope="aws.target",
                    mode="data",
                    unknown={"arn": True} if arn_unknown else None,
                )
                findings = _findings(_analyze([target, caller]), POLICY)
                self.assertEqual(len(findings), 1)
                finding = findings[0]
                evidence = _evidence(finding)["target_account_resolution"]
                self.assertIn("state=resolved", evidence)
                self.assertIn(f"account_id={ACCOUNT}", evidence)
                self.assertIn("partition=unknown", evidence)
                self.assertEqual(finding.severity.value, "high")
                self.assertNotIn("enables IAM policies", finding.rationale)

    def test_resource_policy_uses_target_account_for_sensitive_and_service_resources(self) -> None:
        for resource_type, arn, action, rule in (
            ("aws_kms_key", f"arn:aws:kms:us-east-1:{ACCOUNT}:key/customer", "kms:Decrypt", POLICY),
            ("aws_sns_topic", f"arn:aws:sns:us-east-1:{ACCOUNT}:events", "sns:Publish", SERVICE_POLICY),
        ):
            for principal_account in (ACCOUNT, FOREIGN):
                with self.subTest(resource=resource_type, account=principal_account):
                    target = _resource(
                        resource_type,
                        "target",
                        {"arn": arn, "policy": _policy(f"arn:aws:iam::{principal_account}:role/consumer", action)},
                    )
                    baseline = _analyze([target])
                    result = _analyze([target, _role(name="unrelated", account=FOREIGN)])
                    self.assertEqual(_findings(result, rule), _findings(baseline, rule))
                    self.assertEqual(len(_findings(result, rule)), int(principal_account == FOREIGN))
                    if principal_account == FOREIGN:
                        self.assertEqual(
                            _trust_boundary(result, target.address), _trust_boundary(baseline, target.address)
                        )

    def test_kms_grant_uses_key_owner_instead_of_grant_provider_account(self) -> None:
        arn = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/customer"
        target = _resource("aws_kms_key", "customer", {"arn": arn}, scope="aws.key")
        caller = _caller(FOREIGN, "aws.grant")
        for principal_account in (ACCOUNT, FOREIGN):
            grant = _resource(
                "aws_kms_grant",
                "grant",
                {
                    "key_id": arn,
                    "grantee_principal": f"arn:aws:iam::{principal_account}:role/consumer",
                    "operations": ["Decrypt"],
                },
                scope="aws.grant",
            )
            baseline = _analyze([target, grant])
            result = _analyze([target, grant, caller])
            self.assertEqual(_findings(result, GRANT), _findings(baseline, GRANT))
            self.assertEqual(len(_findings(result, GRANT)), int(principal_account == FOREIGN))
            if principal_account == FOREIGN:
                self.assertIn(
                    f"account_id={ACCOUNT}", _evidence(_findings(result, GRANT)[0])["target_account_resolution"]
                )

    def test_s3_policy_uses_scoped_caller_ownership_and_never_summary_account(self) -> None:
        for scope in ("aws.target", None):
            with self.subTest(scope=scope):
                bucket = _resource("aws_s3_bucket", "data", {"bucket": "data", "arn": "arn:aws:s3:::data"}, scope=scope)
                policy = _resource(
                    "aws_s3_bucket_policy",
                    "data",
                    {
                        "bucket": "data",
                        "policy": _policy(f"arn:aws:iam::{FOREIGN}:role/consumer", "s3:GetObject"),
                    },
                    scope=scope,
                )
                local = _caller(ACCOUNT, "aws.target")
                baseline = _analyze([bucket, policy, local])
                self.assertEqual(baseline.inventory.primary_account_id, ACCOUNT)
                expected = _findings(baseline, POLICY)
                self.assertEqual(len(expected), int(scope is not None))
                result = _analyze([bucket, policy, local, _caller(FOREIGN, "aws.remote", "remote")])
                self.assertEqual(_findings(result, POLICY), expected)
                if expected:
                    self.assertIn(f"account_id={ACCOUNT}", _evidence(expected[0])["target_account_resolution"])
                    self.assertEqual(_trust_boundary(result, bucket.address), _trust_boundary(baseline, bucket.address))

    def test_unknown_key_owner_retains_grant_root_breadth_without_claiming_foreign(self) -> None:
        target = _resource("aws_kms_key", "customer", {"key_id": "customer", "id": "customer"})
        grant = _resource(
            "aws_kms_grant",
            "root",
            {
                "key_id": "aws_kms_key.customer.key_id",
                "grantee_principal": f"arn:aws:iam::{FOREIGN}:root",
                "operations": ["Decrypt"],
            },
        )
        result = _analyze([target, grant, _role(name="unrelated")])
        finding = _findings(result, GRANT)[0]
        evidence = _evidence(finding)
        self.assertIn("state=unknown", evidence["target_account_resolution"])
        self.assertEqual(
            evidence["authorization_reasons"],
            [
                "grantee principal is an AWS account principal represented by its root ARN",
            ],
        )

    def test_ambiguous_owner_preserves_root_breadth_and_candidate_evidence(self) -> None:
        target = _role(f"arn:aws:iam::{FOREIGN}:root", account=None, scope="aws.target")
        result = _analyze([target, _caller(ACCOUNT, "aws.target"), _caller(FOREIGN, "aws.target", "conflict")])
        finding = _findings(result, NARROWING)[0]
        evidence = _evidence(finding)
        self.assertIn("state=ambiguous", evidence["target_account_resolution"])
        self.assertNotIn("foreign", " ".join(evidence["trust_scope"]))
        for account in (ACCOUNT, FOREIGN):
            self.assertTrue(any(f"account_id = {account}" in item for item in evidence["target_account_resolution"]))

    def test_trust_based_path_survives_unrelated_accounts_and_account_root_breadth(self) -> None:
        for principal in (f"arn:aws:iam::{FOREIGN}:role/deployer", f"arn:aws:iam::{ACCOUNT}:root"):
            with self.subTest(principal=principal):
                role = _role(principal)
                role.values["inline_policy"] = [
                    {
                        "name": "secret",
                        "policy": {
                            "Statement": [
                                {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}
                            ],
                        },
                    }
                ]
                workload = _resource(
                    "aws_lambda_function",
                    "worker",
                    {
                        "function_name": "worker",
                        "arn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:worker",
                        "role": role.values["arn"],
                    },
                )
                secret = _resource(
                    "aws_secretsmanager_secret",
                    "data",
                    {
                        "name": "data",
                        "arn": f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:data",
                    },
                )
                resources = [role, workload, secret]
                baseline = _analyze(resources)
                self.assertEqual(len(_findings(baseline, CHAIN)), 1)
                result = _analyze([*reversed(resources), _role(name="unrelated", account=FOREIGN)])
                self.assertEqual(_findings(result, CHAIN), _findings(baseline, CHAIN))
                self.assertEqual(_findings(result, CHAIN)[0].trust_boundary_id, _trust_boundary(result).identifier)


if __name__ == "__main__":
    unittest.main()
