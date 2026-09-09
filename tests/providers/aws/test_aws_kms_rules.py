from __future__ import annotations

import json
import unittest
from typing import Any

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.key_management import ManagedKeyLifecyclePosture
from tfstride.models import TerraformResource
from tfstride.providers.aws.kms_rules import _kms_key_lifecycle_posture
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts

_KMS_ROTATION_RULE = "aws-kms-key-rotation-disabled-or-unknown"
_KMS_DELETION_WINDOW_RULE = "aws-kms-key-deletion-window-too-short"
_KMS_LOCKOUT_SAFETY_RULE = "aws-kms-key-policy-lockout-safety-check-bypassed"
_KMS_GRANT_RULE = "aws-kms-grant-broad-authorization"
_GENERIC_EXTERNAL_POLICY_RULE = "aws-sensitive-resource-policy-external-access"
_ACCOUNT_ID = "111122223333"
_FOREIGN_ACCOUNT_ID = "444455556666"
_RUNTIME_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:role/orders-runtime"
_FOREIGN_ROLE_ARN = f"arn:aws:iam::{_FOREIGN_ACCOUNT_ID}:role/external-runtime"
_ACCOUNT_ROOT_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:root"
_MISSING = object()


def _kms_key(
    *,
    name: str = "customer",
    key_usage: object = _MISSING,
    key_spec: object = _MISSING,
    customer_master_key_spec: object = _MISSING,
    origin: object = _MISSING,
    custom_key_store_id: object = _MISSING,
    xks_key_id: object = _MISSING,
    enable_key_rotation: object = _MISSING,
    rotation_period_in_days: object = _MISSING,
    deletion_window_in_days: object = _MISSING,
    policy: object = _MISSING,
    bypass_policy_lockout_safety_check: object = _MISSING,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "id": f"key/{name}",
        "key_id": name,
        "arn": f"arn:aws:kms:us-east-1:{_ACCOUNT_ID}:key/{name}",
    }
    optional_values = {
        "key_usage": key_usage,
        "key_spec": key_spec,
        "customer_master_key_spec": customer_master_key_spec,
        "origin": origin,
        "custom_key_store_id": custom_key_store_id,
        "xks_key_id": xks_key_id,
        "enable_key_rotation": enable_key_rotation,
        "rotation_period_in_days": rotation_period_in_days,
        "deletion_window_in_days": deletion_window_in_days,
        "policy": policy,
        "bypass_policy_lockout_safety_check": bypass_policy_lockout_safety_check,
    }
    values.update({key: value for key, value in optional_values.items() if value is not _MISSING})
    return TerraformResource(
        address=f"aws_kms_key.{name}",
        mode="managed",
        resource_type="aws_kms_key",
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _kms_grant(
    name: str,
    *,
    grantee_principal: object = _RUNTIME_ROLE_ARN,
    operations: object = ("Decrypt",),
    constraints: object = _MISSING,
    key_reference: object = "aws_kms_key.customer.key_id",
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "id": f"grant-{name}",
        "grant_id": f"grant-{name}",
        "name": name,
        "key_id": key_reference,
        "grantee_principal": grantee_principal,
        "operations": list(operations) if isinstance(operations, tuple) else operations,
        "retire_on_delete": False,
    }
    if constraints is not _MISSING:
        values["constraints"] = constraints
    return TerraformResource(
        address=f"aws_kms_grant.{name}",
        mode="managed",
        resource_type="aws_kms_grant",
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _kms_key_policy(
    name: str,
    *,
    policy: object,
    bypass_policy_lockout_safety_check: object = False,
    key_reference: object = "aws_kms_key.customer.key_id",
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"aws_kms_key_policy.{name}",
        mode="managed",
        resource_type="aws_kms_key_policy",
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values={
            "id": f"policy-{name}",
            "key_id": key_reference,
            "policy": policy,
            "bypass_policy_lockout_safety_check": bypass_policy_lockout_safety_check,
        },
        unknown_values=unknown_values or {},
    )


def _policy(
    *,
    principal: str = _RUNTIME_ROLE_ARN,
    actions: tuple[str, ...] = ("kms:Decrypt", "kms:GenerateDataKey"),
) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Principal": {"AWS": principal},
                "Action": list(actions),
                "Resource": "*",
            },
        }
    )


def _findings(resources: list[TerraformResource], *rule_ids: str):
    inventory = AwsNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids or {_KMS_ROTATION_RULE})),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


def _lifecycle_posture(resource: TerraformResource) -> ManagedKeyLifecyclePosture:
    inventory = AwsNormalizer().normalize([resource])
    key = inventory.get_by_address(resource.address)
    assert key is not None
    return _kms_key_lifecycle_posture(aws_facts(key))


class AwsKmsRuleTests(unittest.TestCase):
    def test_aws_adapter_maps_provider_semantics_to_shared_lifecycle_posture(self) -> None:
        cases = (
            (
                "missing-rotation",
                _kms_key(),
                ManagedKeyLifecyclePosture(
                    "applicable",
                    "action_required",
                    issues=("rotation_disabled",),
                ),
            ),
            (
                "enabled-default-period",
                _kms_key(enable_key_rotation=True),
                ManagedKeyLifecyclePosture("applicable", "compliant"),
            ),
            (
                "enabled-at-boundary",
                _kms_key(enable_key_rotation=True, rotation_period_in_days=365),
                ManagedKeyLifecyclePosture("applicable", "compliant"),
            ),
            (
                "enabled-over-boundary",
                _kms_key(enable_key_rotation=True, rotation_period_in_days=366),
                ManagedKeyLifecyclePosture(
                    "applicable",
                    "action_required",
                    issues=("rotation_interval_too_long",),
                ),
            ),
            (
                "unresolved-rotation",
                _kms_key(unknown_values={"enable_key_rotation": True}),
                ManagedKeyLifecyclePosture(
                    "applicable",
                    "unknown",
                    uncertainties=("enable_key_rotation is unknown after planning",),
                ),
            ),
            (
                "unresolved-period",
                _kms_key(
                    enable_key_rotation=True,
                    unknown_values={"rotation_period_in_days": True},
                ),
                ManagedKeyLifecyclePosture(
                    "applicable",
                    "unknown",
                    uncertainties=("rotation_period_in_days is unknown after planning",),
                ),
            ),
            (
                "signing-key",
                _kms_key(key_usage="SIGN_VERIFY", key_spec="ECC_NIST_P256"),
                ManagedKeyLifecyclePosture("not_applicable", "not_evaluated"),
            ),
            (
                "asymmetric-encryption-key",
                _kms_key(key_spec="RSA_2048"),
                ManagedKeyLifecyclePosture("not_applicable", "not_evaluated"),
            ),
            (
                "imported-key",
                _kms_key(origin="EXTERNAL"),
                ManagedKeyLifecyclePosture("not_applicable", "not_evaluated"),
            ),
            (
                "custom-store-key",
                _kms_key(origin="AWS_KMS", custom_key_store_id="cks-1234"),
                ManagedKeyLifecyclePosture("not_applicable", "not_evaluated"),
            ),
            (
                "xks-key",
                _kms_key(origin="EXTERNAL_KEY_STORE", xks_key_id="xks-key"),
                ManagedKeyLifecyclePosture("not_applicable", "not_evaluated"),
            ),
            (
                "unresolved-origin",
                _kms_key(unknown_values={"origin": True}),
                ManagedKeyLifecyclePosture(
                    "unknown",
                    "not_evaluated",
                    uncertainties=("origin is unknown after planning",),
                ),
            ),
        )

        for case, resource, expected in cases:
            with self.subTest(case=case):
                self.assertEqual(_lifecycle_posture(resource), expected)

    def test_symmetric_customer_key_with_rotation_disabled_is_detected(self) -> None:
        findings = _findings([_kms_key(enable_key_rotation=False)])

        self.assertEqual([finding.rule_id for finding in findings], [_KMS_ROTATION_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        self.assertEqual(findings[0].affected_resources, ["aws_kms_key.customer"])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["key_posture"],
            [
                "key_usage=ENCRYPT_DECRYPT",
                "key_spec=unset",
                "customer_master_key_spec=unset",
                "origin=AWS_KMS",
                "custom_key_store_id=unset",
                "xks_key_id=unset",
                "multi_region_state=disabled",
            ],
        )
        self.assertEqual(
            evidence["rotation_posture"],
            [
                "enable_key_rotation_state=disabled",
                "rotation_period_in_days=unset",
                "default_rotation_period_days=365",
                "tfstride_rotation_baseline_max_days=365",
                "rotation_posture_state=disabled",
                "enable_key_rotation is false",
                "automatic rotation is evaluated only for symmetric ENCRYPT_DECRYPT keys with AWS_KMS origin "
                "outside custom key stores",
            ],
        )

    def test_missing_rotation_field_uses_terraform_default_disabled_posture(self) -> None:
        findings = _findings([_kms_key(customer_master_key_spec="SYMMETRIC_DEFAULT")])

        self.assertEqual([finding.rule_id for finding in findings], [_KMS_ROTATION_RULE])
        evidence = _evidence_by_key(findings[0])
        self.assertIn("enable_key_rotation_state=disabled", evidence["rotation_posture"])
        self.assertNotIn("posture_uncertainty", evidence)

    def test_unknown_rotation_is_reported_without_claiming_disabled(self) -> None:
        findings = _findings([_kms_key(unknown_values={"enable_key_rotation": True})])

        self.assertEqual([finding.rule_id for finding in findings], [_KMS_ROTATION_RULE])
        self.assertEqual(findings[0].severity.value, "low")
        self.assertNotIn("disabled", findings[0].rationale.lower())
        evidence = _evidence_by_key(findings[0])
        self.assertIn("rotation_posture_state=unknown", evidence["rotation_posture"])
        self.assertIn("enable_key_rotation is unknown", evidence["rotation_posture"])
        self.assertEqual(evidence["posture_uncertainty"], ["enable_key_rotation is unknown after planning"])

    def test_custom_rotation_period_over_annual_baseline_is_detected(self) -> None:
        findings = _findings([_kms_key(enable_key_rotation=True, rotation_period_in_days=730)])

        self.assertEqual([finding.rule_id for finding in findings], [_KMS_ROTATION_RULE])
        self.assertIn("730 days", findings[0].rationale)
        evidence = _evidence_by_key(findings[0])
        self.assertIn("rotation_posture_state=too_long", evidence["rotation_posture"])
        self.assertIn("effective_rotation_period_days=730", evidence["rotation_posture"])

    def test_enabled_default_or_bounded_custom_rotation_is_quiet(self) -> None:
        findings = _findings(
            [
                _kms_key(name="default", key_spec="SYMMETRIC_DEFAULT", enable_key_rotation=True),
                _kms_key(
                    name="bounded",
                    key_spec="SYMMETRIC_DEFAULT",
                    enable_key_rotation=True,
                    rotation_period_in_days=365,
                ),
            ]
        )

        self.assertEqual(findings, [])

    def test_unknown_custom_rotation_period_is_uncertain_not_too_long(self) -> None:
        findings = _findings(
            [
                _kms_key(
                    enable_key_rotation=True,
                    unknown_values={"rotation_period_in_days": True},
                )
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_KMS_ROTATION_RULE])
        self.assertEqual(findings[0].severity.value, "low")
        self.assertNotIn("too long", findings[0].rationale.lower())
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["posture_uncertainty"],
            ["rotation_period_in_days is unknown after planning"],
        )

    def test_noneligible_keys_are_not_told_to_enable_automatic_rotation(self) -> None:
        findings = _findings(
            [
                _kms_key(name="signing", key_usage="SIGN_VERIFY", key_spec="ECC_NIST_P256"),
                _kms_key(name="rsa", key_usage="ENCRYPT_DECRYPT", key_spec="RSA_2048"),
                _kms_key(name="imported", origin="EXTERNAL", enable_key_rotation=False),
                _kms_key(
                    name="custom_store",
                    origin="AWS_KMS",
                    custom_key_store_id="cks-1234",
                    enable_key_rotation=False,
                ),
                _kms_key(
                    name="xks",
                    origin="EXTERNAL_KEY_STORE",
                    xks_key_id="xks-key",
                    enable_key_rotation=False,
                ),
                _kms_key(
                    name="unknown_origin",
                    enable_key_rotation=False,
                    unknown_values={"origin": True},
                ),
            ]
        )

        self.assertEqual(findings, [])

    def test_short_deletion_window_is_detected_as_recovery_governance_risk(self) -> None:
        findings = _findings(
            [_kms_key(enable_key_rotation=True, deletion_window_in_days=7)],
            _KMS_DELETION_WINDOW_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_KMS_DELETION_WINDOW_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        self.assertEqual(findings[0].affected_resources, ["aws_kms_key.customer"])
        self.assertIn("key recovery governance", findings[0].rationale)
        self.assertIn("does not inspect key policies or grants", findings[0].rationale)
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["deletion_window_posture"],
            [
                "deletion_window_in_days=7",
                "minimum_deletion_window_days=14",
                "default_deletion_window_days=30",
            ],
        )

    def test_default_or_long_deletion_window_stays_quiet(self) -> None:
        findings = _findings(
            [
                _kms_key(name="default", enable_key_rotation=True),
                _kms_key(name="baseline", enable_key_rotation=True, deletion_window_in_days=14),
                _kms_key(name="long", enable_key_rotation=True, deletion_window_in_days=30),
            ],
            _KMS_DELETION_WINDOW_RULE,
        )

        self.assertEqual(findings, [])

    def test_unknown_deletion_window_is_not_overclaimed_as_short(self) -> None:
        findings = _findings(
            [
                _kms_key(
                    enable_key_rotation=True,
                    deletion_window_in_days=7,
                    unknown_values={"deletion_window_in_days": True},
                )
            ],
            _KMS_DELETION_WINDOW_RULE,
        )

        self.assertEqual(findings, [])

    def test_complete_inline_policy_with_explicit_safety_bypass_is_detected(self) -> None:
        findings = _findings(
            [
                _kms_key(
                    enable_key_rotation=True,
                    policy=_policy(),
                    bypass_policy_lockout_safety_check=True,
                )
            ],
            _KMS_LOCKOUT_SAFETY_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_KMS_LOCKOUT_SAFETY_RULE])
        self.assertEqual(findings[0].affected_resources, ["aws_kms_key.customer"])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["policy_sources"],
            [
                "source=aws_kms_key.customer; source_type=inline; configuration_state=configured; "
                "completeness_state=complete; bypass_lockout_safety_check_state=enabled; "
                "posture_uncertainties=none"
            ],
        )

    def test_complete_standalone_policy_with_explicit_safety_bypass_is_detected(self) -> None:
        findings = _findings(
            [
                _kms_key(enable_key_rotation=True),
                _kms_key_policy(
                    "customer",
                    policy=_policy(),
                    bypass_policy_lockout_safety_check=True,
                ),
            ],
            _KMS_LOCKOUT_SAFETY_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_KMS_LOCKOUT_SAFETY_RULE])
        self.assertEqual(
            findings[0].affected_resources,
            ["aws_kms_key.customer", "aws_kms_key_policy.customer"],
        )

    def test_unknown_or_malformed_policy_with_explicit_safety_bypass_is_detected(self) -> None:
        findings = _findings(
            [
                _kms_key(
                    name="unknown_policy",
                    enable_key_rotation=True,
                    bypass_policy_lockout_safety_check=True,
                    unknown_values={"policy": True},
                ),
                _kms_key(
                    name="malformed",
                    enable_key_rotation=True,
                    policy=json.dumps({"Statement": "unexpected"}),
                    bypass_policy_lockout_safety_check=True,
                ),
            ],
            _KMS_LOCKOUT_SAFETY_RULE,
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [_KMS_LOCKOUT_SAFETY_RULE, _KMS_LOCKOUT_SAFETY_RULE],
        )
        evidence_by_address = {
            finding.affected_resources[0]: _evidence_by_key(finding)["policy_sources"] for finding in findings
        }
        self.assertIn(
            "configuration_state=unknown; completeness_state=unknown; "
            "bypass_lockout_safety_check_state=enabled; "
            "posture_uncertainties=policy is unknown after planning",
            evidence_by_address["aws_kms_key.unknown_policy"][0],
        )
        self.assertIn(
            "configuration_state=configured; completeness_state=unknown; "
            "bypass_lockout_safety_check_state=enabled; "
            "posture_uncertainties=policy statements have an unrecognized value shape",
            evidence_by_address["aws_kms_key.malformed"][0],
        )
        self.assertTrue(
            all(
                "does_not_claim=the resulting policy necessarily locks out"
                in _evidence_by_key(finding)["lockout_safety_posture"][-1]
                for finding in findings
            )
        )

    def test_missing_policy_or_unknown_bypass_stays_quiet(self) -> None:
        findings = _findings(
            [
                _kms_key(
                    name="missing",
                    enable_key_rotation=True,
                    bypass_policy_lockout_safety_check=True,
                ),
                _kms_key(
                    name="unknown_bypass",
                    enable_key_rotation=True,
                    policy=_policy(),
                    bypass_policy_lockout_safety_check=True,
                    unknown_values={"bypass_policy_lockout_safety_check": True},
                ),
            ],
            _KMS_LOCKOUT_SAFETY_RULE,
        )

        self.assertEqual(findings, [])

    def test_unconstrained_create_grant_is_detected(self) -> None:
        findings = _findings(
            [
                _kms_key(enable_key_rotation=True),
                _kms_grant(
                    "delegation",
                    operations=("CreateGrant", "Decrypt"),
                ),
            ],
            _KMS_GRANT_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_KMS_GRANT_RULE])
        self.assertEqual(
            findings[0].affected_resources,
            ["aws_kms_key.customer", "aws_kms_grant.delegation"],
        )
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["authorization_reasons"],
            ["CreateGrant is allowed without an encryption-context constraint"],
        )
        self.assertIn("operations=CreateGrant, Decrypt", evidence["grant_authorization"])
        self.assertIn("Unconstrained CreateGrant authority", findings[0].rationale)

    def test_foreign_or_account_root_high_impact_grant_is_detected(self) -> None:
        findings = _findings(
            [
                _kms_key(enable_key_rotation=True),
                _kms_grant(
                    "foreign",
                    grantee_principal=_FOREIGN_ROLE_ARN,
                    operations=("Decrypt",),
                    constraints=[{"encryption_context_equals": {"service": "orders"}}],
                ),
                _kms_grant(
                    "root",
                    grantee_principal=_ACCOUNT_ROOT_ARN,
                    operations=("Decrypt",),
                ),
            ],
            _KMS_GRANT_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_KMS_GRANT_RULE, _KMS_GRANT_RULE])
        reasons_by_source = {
            _evidence_by_key(finding)["grant_authorization"][0]: _evidence_by_key(finding)["authorization_reasons"]
            for finding in findings
        }
        self.assertEqual(
            reasons_by_source["source=aws_kms_grant.foreign"],
            ["grantee principal belongs to a foreign AWS account"],
        )
        self.assertEqual(
            reasons_by_source["source=aws_kms_grant.root"],
            ["grantee principal is an AWS account principal represented by its root ARN"],
        )
        self.assertTrue(all("CreateGrant authority" not in finding.rationale for finding in findings))

    def test_exact_same_account_or_constrained_delegation_grants_stay_quiet(self) -> None:
        findings = _findings(
            [
                _kms_key(enable_key_rotation=True),
                _kms_grant("runtime", operations=("Decrypt", "GenerateDataKey")),
                _kms_grant(
                    "constrained_delegation",
                    operations=("CreateGrant", "Decrypt"),
                    constraints=[{"encryption_context_equals": {"service": "orders"}}],
                ),
                _kms_grant(
                    "foreign_metadata",
                    grantee_principal=_FOREIGN_ROLE_ARN,
                    operations=("DescribeKey",),
                ),
            ],
            _KMS_GRANT_RULE,
        )

        self.assertEqual(findings, [])

    def test_unknown_or_unresolved_grant_authorization_stays_quiet(self) -> None:
        findings = _findings(
            [
                _kms_key(enable_key_rotation=True),
                _kms_grant(
                    "unknown_principal",
                    grantee_principal=_FOREIGN_ROLE_ARN,
                    operations=("Decrypt",),
                    unknown_values={"grantee_principal": True},
                ),
                _kms_grant(
                    "unknown_operations",
                    grantee_principal=_FOREIGN_ROLE_ARN,
                    operations=("Decrypt",),
                    unknown_values={"operations": True},
                ),
                _kms_grant(
                    "unknown_constraints",
                    operations=("CreateGrant",),
                    unknown_values={"constraints": True},
                ),
                _kms_grant(
                    "external_key",
                    grantee_principal=_FOREIGN_ROLE_ARN,
                    operations=("Decrypt",),
                    key_reference="aws_kms_key.external.key_id",
                ),
            ],
            _KMS_GRANT_RULE,
        )

        self.assertEqual(findings, [])

    def test_external_key_policy_uses_existing_generic_finding_without_kms_duplicate(self) -> None:
        findings = _findings(
            [
                _kms_key(
                    enable_key_rotation=True,
                    policy=_policy(principal=_FOREIGN_ROLE_ARN),
                    bypass_policy_lockout_safety_check=False,
                )
            ],
            _GENERIC_EXTERNAL_POLICY_RULE,
            _KMS_LOCKOUT_SAFETY_RULE,
            _KMS_GRANT_RULE,
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [_GENERIC_EXTERNAL_POLICY_RULE],
        )

    def test_standalone_external_key_policy_resolves_to_one_generic_finding(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _kms_key(enable_key_rotation=True),
                _kms_key_policy(
                    "customer",
                    policy=_policy(principal=_FOREIGN_ROLE_ARN),
                ),
            ]
        )
        key = inventory.get_by_address("aws_kms_key.customer")
        policy = inventory.get_by_address("aws_kms_key_policy.customer")
        assert key is not None
        assert policy is not None

        self.assertEqual(
            aws_facts(policy).kms_key_policy_resolved_key_address,
            key.address,
        )
        self.assertEqual(
            aws_facts(key).resource_policy_source_addresses,
            [policy.address],
        )
        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset(
                    {
                        _GENERIC_EXTERNAL_POLICY_RULE,
                        _KMS_LOCKOUT_SAFETY_RULE,
                        _KMS_GRANT_RULE,
                    }
                )
            ),
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [_GENERIC_EXTERNAL_POLICY_RULE],
        )
        self.assertEqual(
            findings[0].affected_resources,
            [key.address, policy.address],
        )
        self.assertEqual(
            _evidence_by_key(findings[0])["resource_policy_sources"],
            [policy.address],
        )

    def test_ambiguous_policy_sources_do_not_synthesize_external_access(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _kms_key(
                    enable_key_rotation=True,
                    policy=_policy(),
                    bypass_policy_lockout_safety_check=False,
                ),
                _kms_key_policy(
                    "customer",
                    policy=_policy(principal=_FOREIGN_ROLE_ARN),
                ),
            ]
        )
        key = inventory.get_by_address("aws_kms_key.customer")
        assert key is not None
        self.assertEqual(aws_facts(key).kms_policy_completeness_state, "unknown")

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset(
                    {
                        _GENERIC_EXTERNAL_POLICY_RULE,
                        _KMS_LOCKOUT_SAFETY_RULE,
                        _KMS_GRANT_RULE,
                    }
                )
            ),
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
