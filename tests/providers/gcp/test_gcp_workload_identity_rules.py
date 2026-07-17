from __future__ import annotations

import unittest

from tests.providers.gcp.rule_support.iam import _project_iam_member
from tests.providers.gcp.test_gcp_workload_identity_trust_paths import (
    _IAM_ADDRESS,
    _POOL_ADDRESS,
    _PROVIDER_ADDRESS,
    _SERVICE_ACCOUNT_ADDRESS,
    _SERVICE_ACCOUNT_EMAIL,
    _iam_member,
    _pool,
    _principal,
    _principal_set,
    _provider,
    _service_account,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

_POOL_WIDE_RULE = "gcp-workload-identity-pool-wide-impersonation"
_UNCONDITIONED_PROVIDER_RULE = "gcp-workload-identity-provider-unconditioned-broad-trust"
_PRIVILEGED_ACCESS_RULE = "gcp-workload-identity-privileged-service-account-access"
_RULE_IDS = frozenset({_POOL_WIDE_RULE, _UNCONDITIONED_PROVIDER_RULE, _PRIVILEGED_ACCESS_RULE})


def _provider_without_condition() -> TerraformResource:
    provider = _provider()
    provider.values.pop("attribute_condition")
    return provider


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = GcpNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class GcpWorkloadIdentityRuleTests(unittest.TestCase):
    def test_rule_ids_are_registered(self) -> None:
        registered = {rule_id for group in GCP_RULE_GROUP_IDS for rule_id in group}

        self.assertLessEqual(_RULE_IDS, registered)

    def test_pool_wide_service_account_impersonation_is_detected(self) -> None:
        findings = _evaluate(
            [
                _pool(),
                _provider_without_condition(),
                _service_account(),
                _iam_member(_principal_set("*")),
            ],
            _POOL_WIDE_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_POOL_WIDE_RULE])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            [_SERVICE_ACCOUNT_ADDRESS, _POOL_ADDRESS, _PROVIDER_ADDRESS, _IAM_ADDRESS],
        )
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["federation_conditions"],
            [
                f"provider={_PROVIDER_ADDRESS}; attribute_condition_state=not_configured; "
                "attribute_condition=not_configured; iam_condition=not_configured"
            ],
        )
        self.assertIn("principalSet://", evidence["federation_trust_path"][0])

    def test_pool_wide_rule_requires_an_active_pool_wide_principal(self) -> None:
        narrow_findings = _evaluate(
            [_pool(), _provider_without_condition(), _service_account(), _iam_member(_principal("subject"))],
            _POOL_WIDE_RULE,
        )

        disabled_provider = _provider_without_condition()
        disabled_provider.values["disabled"] = True
        disabled_findings = _evaluate(
            [_pool(), disabled_provider, _service_account(), _iam_member(_principal_set("*"))],
            _POOL_WIDE_RULE,
        )

        self.assertEqual(narrow_findings, [])
        self.assertEqual(disabled_findings, [])

    def test_active_provider_without_attribute_condition_is_detected(self) -> None:
        findings = _evaluate(
            [
                _pool(),
                _provider_without_condition(),
                _service_account(),
                _iam_member(_principal_set("*")),
            ],
            _UNCONDITIONED_PROVIDER_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_UNCONDITIONED_PROVIDER_RULE])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(finding.affected_resources[0], _PROVIDER_ADDRESS)
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["target_service_accounts"],
            [f"address={_SERVICE_ACCOUNT_ADDRESS}; email={_SERVICE_ACCOUNT_EMAIL}"],
        )

    def test_provider_condition_must_be_deterministically_absent(self) -> None:
        configured_findings = _evaluate(
            [_pool(), _provider(), _service_account(), _iam_member(_principal_set("*"))],
            _UNCONDITIONED_PROVIDER_RULE,
        )

        unknown_provider = _provider_without_condition()
        unknown_provider.unknown_values["attribute_condition"] = True
        unknown_findings = _evaluate(
            [_pool(), unknown_provider, _service_account(), _iam_member(_principal_set("*"))],
            _UNCONDITIONED_PROVIDER_RULE,
        )

        self.assertEqual(configured_findings, [])
        self.assertEqual(unknown_findings, [])

    def test_federated_principal_to_privileged_service_account_is_detected(self) -> None:
        privileged_assignment = _project_iam_member(
            "roles/owner",
            member=f"serviceAccount:{_SERVICE_ACCOUNT_EMAIL}",
        )
        findings = _evaluate(
            [
                _pool(),
                _provider(),
                _service_account(),
                _iam_member(_principal("repo:tfstride/tfstride")),
                privileged_assignment,
            ],
            _PRIVILEGED_ACCESS_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_PRIVILEGED_ACCESS_RULE])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "high")
        self.assertIn(privileged_assignment.address, finding.affected_resources)
        evidence = _evidence_by_key(finding)
        self.assertIn("full-admin", evidence["privilege_categories"])
        self.assertEqual(evidence["permission_patterns"], ["roles/owner"])
        self.assertEqual(
            evidence["privileged_access"],
            [
                f"source={privileged_assignment.address}; role=roles/owner; scope=project; "
                "scope_value=tfstride-demo; categories=[full-admin, iam-admin, policy-admin]"
            ],
        )

    def test_privileged_chain_requires_an_exact_high_confidence_service_account_grant(self) -> None:
        resources = [
            _pool(),
            _provider(),
            _service_account(),
            _iam_member(_principal("repo:tfstride/tfstride")),
        ]

        different_service_account = _evaluate(
            [*resources, _project_iam_member("roles/owner")],
            _PRIVILEGED_ACCESS_RULE,
        )
        non_privileged_assignment = _evaluate(
            [
                *resources,
                _project_iam_member(
                    "roles/viewer",
                    member=f"serviceAccount:{_SERVICE_ACCOUNT_EMAIL}",
                ),
            ],
            _PRIVILEGED_ACCESS_RULE,
        )

        self.assertEqual(different_service_account, [])
        self.assertEqual(non_privileged_assignment, [])


if __name__ == "__main__":
    unittest.main()
