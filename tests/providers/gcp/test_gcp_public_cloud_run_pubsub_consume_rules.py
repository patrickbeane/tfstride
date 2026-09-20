from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tests.providers.gcp.test_gcp_cloud_run_pubsub_access_paths import (
    _PROJECT,
    _SERVICE_ACCOUNT_MEMBER,
    _SUBSCRIPTION_ADDRESS,
    _cloud_run,
    _custom_role,
    _subscription,
    _subscription_iam_member,
    _topic,
    _topic_iam_member,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import StrideCategory, TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_types import GcpResourceType
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

_RULE_ID = "gcp-public-cloud-run-pubsub-consume-access"
_WORKLOAD_ADDRESS = "google_cloud_run_v2_service.orders"
_PUBLIC_INVOKER_ADDRESS = "google_cloud_run_v2_service_iam_member.public_invoker"
_SUBSCRIPTION_IAM_ADDRESS = "google_pubsub_subscription_iam_member.orders_access"
_CONSUME_PERMISSION = "pubsub.subscriptions.consume"


def _public_cloud_run(
    *,
    public_ingress: bool = True,
    invoker_iam_disabled: bool | None = None,
) -> TerraformResource:
    workload = _cloud_run()
    workload.values["ingress"] = "INGRESS_TRAFFIC_ALL" if public_ingress else "INGRESS_TRAFFIC_INTERNAL_ONLY"
    if invoker_iam_disabled is not None:
        workload.values["invoker_iam_disabled"] = invoker_iam_disabled
    return workload


def _public_invoker(
    *,
    member: str = "allUsers",
    role: str = "roles/run.invoker",
    condition: dict[str, str] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "name": "orders",
        "project": _PROJECT,
        "location": "us-central1",
        "role": role,
        "member": member,
    }
    if condition is not None:
        values["condition"] = [condition]
    return _terraform_resource(
        _PUBLIC_INVOKER_ADDRESS,
        GcpResourceType.CLOUD_RUN_V2_SERVICE_IAM_MEMBER,
        values,
    )


def _evaluate(resources: list[TerraformResource]):
    inventory = GcpNormalizer().normalize(resources)
    boundaries = detect_trust_boundaries(inventory)
    return StrideRuleEngine().evaluate(
        inventory,
        boundaries,
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )


def _evidence(finding):
    return {item.key: item.values for item in finding.evidence}


class GcpPublicCloudRunPubsubConsumeRuleTests(unittest.TestCase):
    def test_rule_is_registered(self) -> None:
        registered = {rule_id for group in GCP_RULE_GROUP_IDS for rule_id in group}

        self.assertIn(_RULE_ID, registered)

    def test_public_cloud_run_exact_subscription_consume_grant_is_reported(self) -> None:
        findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _topic(),
                _subscription(),
                _subscription_iam_member(),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.category, StrideCategory.INFORMATION_DISCLOSURE)
        self.assertEqual(
            finding.affected_resources,
            [
                _WORKLOAD_ADDRESS,
                _PUBLIC_INVOKER_ADDRESS,
                _SUBSCRIPTION_ADDRESS,
                _SUBSCRIPTION_IAM_ADDRESS,
            ],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            f"internet-to-service:internet->{_WORKLOAD_ADDRESS}",
        )
        self.assertIn(f"allow grant containing `{_CONSUME_PERMISSION}`", finding.rationale)
        self.assertIn("could attempt message-consumption operations", finding.rationale)
        self.assertIn("not guaranteed effective message retrieval", finding.rationale)
        self.assertIn("IAM deny and principal access boundary policies", finding.rationale)
        self.assertIn("Pub/Sub subscription itself is not public", finding.rationale)

        evidence = _evidence(finding)
        self.assertEqual(
            evidence["public_invoker_bindings"],
            [f"source={_PUBLIC_INVOKER_ADDRESS}; role=roles/run.invoker; member=allUsers; condition=none"],
        )
        self.assertIn(f"member={_SERVICE_ACCOUNT_MEMBER}", evidence["runtime_identity"][0])
        self.assertIn("role=roles/pubsub.subscriber", evidence["runtime_identity"][0])
        consume_path = evidence["pubsub_consume_paths"][0]
        self.assertIn(f"subscription_address={_SUBSCRIPTION_ADDRESS}", consume_path)
        self.assertIn(f"iam_resource={_SUBSCRIPTION_IAM_ADDRESS}", consume_path)
        self.assertIn(f"permission={_CONSUME_PERMISSION}", consume_path)
        self.assertIn("matched_permissions=built-in-role", consume_path)
        self.assertIn("resource_scope=exact_subscription", consume_path)
        self.assertIn("condition_state=not_configured", consume_path)
        self.assertEqual(
            evidence["assessment_scope"],
            [
                "establishes=unconditional IAM allow grant containing pubsub.subscriptions.consume",
                ("does_not_establish=effective access after IAM deny or principal access boundary evaluation"),
            ],
        )

    def test_custom_role_requires_exact_subscription_consume_permission(self) -> None:
        findings = _evaluate(
            [
                _public_cloud_run(),
                _public_invoker(),
                _topic(),
                _subscription(),
                _custom_role(permissions=[_CONSUME_PERMISSION, "pubsub.subscriptions.get"]),
                _subscription_iam_member(role=f"projects/{_PROJECT}/roles/cloudRunMessaging"),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        consume_path = _evidence(findings[0])["pubsub_consume_paths"][0]
        self.assertIn("role_kind=custom", consume_path)
        self.assertIn(
            "matched_permissions=pubsub.subscriptions.consume,pubsub.subscriptions.get",
            consume_path,
        )

    def test_supported_public_invocation_mechanisms_are_detected(self) -> None:
        cases = {
            "services invoker role": (
                [
                    _public_cloud_run(),
                    _public_invoker(role="roles/run.servicesInvoker"),
                    _topic(),
                    _subscription(),
                    _subscription_iam_member(),
                ],
                "public_invoker_bindings",
                "role=roles/run.servicesInvoker",
            ),
            "invoker IAM check disabled": (
                [
                    _public_cloud_run(invoker_iam_disabled=True),
                    _topic(),
                    _subscription(),
                    _subscription_iam_member(),
                ],
                "public_exposure_configuration",
                "invoker_iam_check=disabled; ingress=INGRESS_TRAFFIC_ALL",
            ),
        }

        for case, (resources, evidence_key, expected_evidence) in cases.items():
            with self.subTest(case=case):
                findings = _evaluate(resources)
                self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
                self.assertIn(expected_evidence, _evidence(findings[0])[evidence_key][0])

    def test_topic_scoped_subscriber_and_topic_admin_grants_remain_quiet(self) -> None:
        cases = {
            "topic subscriber": [
                _public_cloud_run(),
                _public_invoker(),
                _topic(),
                _topic_iam_member(role="roles/pubsub.subscriber"),
            ],
            "topic admin": [
                _public_cloud_run(),
                _public_invoker(),
                _topic(),
                _topic_iam_member(role="roles/pubsub.admin"),
            ],
        }

        for case, resources in cases.items():
            with self.subTest(case=case):
                self.assertEqual(_evaluate(resources), [])

    def test_non_consuming_and_uncertain_subscription_paths_remain_quiet(self) -> None:
        conditional = {
            "title": "business-hours",
            "expression": 'request.time < timestamp("2030-01-01T00:00:00Z")',
        }
        unknown_condition = _subscription_iam_member(name="unknown_condition")
        unknown_condition.unknown_values["condition"] = True
        unknown_public_invoker_condition = _public_invoker()
        unknown_public_invoker_condition.unknown_values["condition"] = True
        unknown_invoker_iam_check = _public_cloud_run()
        unknown_invoker_iam_check.unknown_values["invoker_iam_disabled"] = True

        cases = {
            "subscription viewer": [
                _public_cloud_run(),
                _public_invoker(),
                _topic(),
                _subscription(),
                _subscription_iam_member(role="roles/pubsub.viewer"),
            ],
            "custom topic administration only": [
                _public_cloud_run(),
                _public_invoker(),
                _topic(),
                _subscription(),
                _custom_role(permissions=["pubsub.topics.setIamPolicy"]),
                _subscription_iam_member(role=f"projects/{_PROJECT}/roles/cloudRunMessaging"),
            ],
            "conditional consume": [
                _public_cloud_run(),
                _public_invoker(),
                _topic(),
                _subscription(),
                _subscription_iam_member(condition=conditional),
            ],
            "unknown consume condition": [
                _public_cloud_run(),
                _public_invoker(),
                _topic(),
                _subscription(),
                unknown_condition,
            ],
            "unknown public invoker condition": [
                _public_cloud_run(),
                unknown_public_invoker_condition,
                _topic(),
                _subscription(),
                _subscription_iam_member(),
            ],
            "unknown invoker IAM check without public binding": [
                unknown_invoker_iam_check,
                _topic(),
                _subscription(),
                _subscription_iam_member(),
            ],
            "private ingress": [
                _public_cloud_run(public_ingress=False),
                _public_invoker(),
                _topic(),
                _subscription(),
                _subscription_iam_member(),
            ],
            "non-public invoker": [
                _public_cloud_run(),
                _public_invoker(member="serviceAccount:caller@tfstride-demo.iam.gserviceaccount.com"),
                _topic(),
                _subscription(),
                _subscription_iam_member(),
            ],
            "unresolved custom role": [
                _public_cloud_run(),
                _public_invoker(),
                _topic(),
                _subscription(),
                _subscription_iam_member(role=f"projects/{_PROJECT}/roles/externalMessagingRole"),
            ],
            "external subscription": [
                _public_cloud_run(),
                _public_invoker(),
                _subscription_iam_member(
                    subscription="projects/external/subscriptions/orders-worker",
                ),
            ],
        }

        for case, resources in cases.items():
            with self.subTest(case=case):
                self.assertEqual(_evaluate(resources), [])


if __name__ == "__main__":
    unittest.main()
