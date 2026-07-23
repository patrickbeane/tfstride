from __future__ import annotations

import unittest

from tests.providers.gcp.rule_support.serverless import (
    _cloud_run_service,
    _cloud_run_service_iam_member,
    _cloudfunctions2_function,
    _cloudfunctions2_function_iam_binding,
    _cloudfunctions_function,
    _cloudfunctions_function_iam_member,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.providers.gcp.normalizer import GcpNormalizer


class GcpServerlessRuleTests(unittest.TestCase):
    def test_public_cloud_run_invoker_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_cloud_run_service(), _cloud_run_service_iam_member()])
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-run-public-invoker"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-cloud-run-public-invoker")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(
            finding.affected_resources,
            ["google_cloud_run_v2_service.api", "google_cloud_run_v2_service_iam_member.public_invoker"],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            "internet-to-service:internet->google_cloud_run_v2_service.api",
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["public_invoker_bindings"],
            ["source=google_cloud_run_v2_service_iam_member.public_invoker; role=roles/run.invoker; member=allUsers"],
        )
        self.assertEqual(
            evidence["public_exposure_reasons"],
            ["google_cloud_run_v2_service_iam_member.public_invoker grants roles/run.invoker to allUsers"],
        )

    def test_cloud_run_public_access_supports_current_invocation_mechanisms(self) -> None:
        cases = {
            "services invoker role": [
                _cloud_run_service(),
                _cloud_run_service_iam_member(role="roles/run.servicesInvoker"),
            ],
            "invoker IAM check disabled": [
                _cloud_run_service(invoker_iam_disabled=True),
            ],
        }

        for case, resources in cases.items():
            with self.subTest(case=case):
                inventory = GcpNormalizer().normalize(resources)
                boundaries = detect_trust_boundaries(inventory)
                findings = StrideRuleEngine().evaluate(
                    inventory,
                    boundaries,
                    rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-run-public-invoker"})),
                )

                self.assertEqual(
                    [finding.rule_id for finding in findings],
                    ["gcp-cloud-run-public-invoker"],
                )

    def test_cloud_run_public_invoker_reports_constraining_iam_condition(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_run_service(),
                _cloud_run_service_iam_member(
                    condition={
                        "title": "expires_soon",
                        "expression": 'request.time < timestamp("2026-07-01T00:00:00Z")',
                    }
                ),
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-run-public-invoker"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.severity.value, "low")
        self.assertEqual(finding.severity_reasoning.blast_radius, 0)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["iam_condition"],
            [
                "category=time_limited",
                "constraining=true",
                "title=expires_soon",
                'expression=request.time < timestamp("2026-07-01T00:00:00Z")',
            ],
        )

    def test_cloud_run_public_invoker_requires_public_ingress_and_public_member(self) -> None:
        private_inventory = GcpNormalizer().normalize(
            [_cloud_run_service(public_ingress=False), _cloud_run_service_iam_member()]
        )
        non_public_inventory = GcpNormalizer().normalize(
            [
                _cloud_run_service(),
                _cloud_run_service_iam_member(member="serviceAccount:caller@example.iam.gserviceaccount.com"),
            ]
        )

        engine = StrideRuleEngine()

        self.assertEqual(
            engine.evaluate(
                private_inventory,
                detect_trust_boundaries(private_inventory),
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-run-public-invoker"})),
            ),
            [],
        )
        self.assertEqual(
            engine.evaluate(
                non_public_inventory,
                detect_trust_boundaries(non_public_inventory),
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-run-public-invoker"})),
            ),
            [],
        )

    def test_public_cloud_function_invoker_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_cloudfunctions_function(), _cloudfunctions_function_iam_member()])
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-functions-public-invoker"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-cloud-functions-public-invoker")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(
            finding.affected_resources,
            ["google_cloudfunctions_function.fn", "google_cloudfunctions_function_iam_member.public_invoker"],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            "internet-to-service:internet->google_cloudfunctions_function.fn",
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["public_invoker_bindings"],
            [
                "source=google_cloudfunctions_function_iam_member.public_invoker; "
                "role=roles/cloudfunctions.invoker; member=allUsers"
            ],
        )
        self.assertEqual(
            evidence["public_exposure_reasons"],
            [
                "google_cloudfunctions_function_iam_member.public_invoker grants "
                "roles/cloudfunctions.invoker to allUsers"
            ],
        )

    def test_public_cloudfunctions2_binding_invoker_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_cloudfunctions2_function(), _cloudfunctions2_function_iam_binding()])
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-functions-public-invoker"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(
            finding.affected_resources,
            ["google_cloudfunctions2_function.fn2", "google_cloudfunctions2_function_iam_binding.public_invokers"],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["public_invoker_bindings"],
            [
                "source=google_cloudfunctions2_function_iam_binding.public_invokers; "
                "role=roles/cloudfunctions.invoker; member=allAuthenticatedUsers"
            ],
        )

    def test_cloud_function_public_invoker_requires_public_http_and_public_member(self) -> None:
        private_inventory = GcpNormalizer().normalize(
            [_cloudfunctions_function(public=False), _cloudfunctions_function_iam_member()]
        )
        non_public_inventory = GcpNormalizer().normalize(
            [
                _cloudfunctions_function(),
                _cloudfunctions_function_iam_member(member="serviceAccount:caller@example.iam.gserviceaccount.com"),
            ]
        )

        engine = StrideRuleEngine()

        self.assertEqual(
            engine.evaluate(
                private_inventory,
                detect_trust_boundaries(private_inventory),
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-functions-public-invoker"})),
            ),
            [],
        )
        self.assertEqual(
            engine.evaluate(
                non_public_inventory,
                detect_trust_boundaries(non_public_inventory),
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-functions-public-invoker"})),
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
