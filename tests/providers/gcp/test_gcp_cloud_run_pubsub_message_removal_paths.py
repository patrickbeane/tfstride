from __future__ import annotations

import json
import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tests.providers.gcp.test_gcp_cloud_run_pubsub_access_paths import (
    _PROJECT,
    _SERVICE_ACCOUNT_MEMBER,
    _SUBSCRIPTION_ADDRESS,
    _SUBSCRIPTION_REFERENCE,
    _TOPIC_ADDRESS,
    _cloud_run,
    _custom_role,
    _subscription,
    _subscription_iam_member,
    _topic,
)
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType


def _project_iam_member(
    *,
    project: str = _PROJECT,
    role: str = "roles/pubsub.subscriber",
    member: str = _SERVICE_ACCOUNT_MEMBER,
    name: str = "project_subscriber",
) -> object:
    return _terraform_resource(
        f"google_project_iam_member.{name}",
        GcpResourceType.PROJECT_IAM_MEMBER,
        {
            "project": project,
            "role": role,
            "member": member,
        },
    )


def _subscription_iam_binding(
    *,
    role: str = "roles/pubsub.subscriber",
    members: list[str] | None = None,
    name: str = "orders_binding",
) -> object:
    return _terraform_resource(
        f"google_pubsub_subscription_iam_binding.{name}",
        GcpResourceType.PUBSUB_SUBSCRIPTION_IAM_BINDING,
        {
            "subscription": f"{_SUBSCRIPTION_ADDRESS}.name",
            "role": role,
            "members": members or ["serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"],
        },
    )


def _subscription_iam_policy(
    *,
    bindings: list[dict[str, object]],
    name: str = "orders_policy",
) -> object:
    return _terraform_resource(
        f"google_pubsub_subscription_iam_policy.{name}",
        GcpResourceType.PUBSUB_SUBSCRIPTION_IAM_POLICY,
        {
            "subscription": f"{_SUBSCRIPTION_ADDRESS}.name",
            "policy_data": json.dumps({"bindings": bindings}),
        },
    )


def _project_iam_binding(
    *,
    role: str,
    project: str = _PROJECT,
    members: list[str] | None = None,
    name: str = "project_binding",
) -> object:
    return _terraform_resource(
        f"google_project_iam_binding.{name}",
        GcpResourceType.PROJECT_IAM_BINDING,
        {
            "project": project,
            "role": role,
            "members": members or ["serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"],
        },
    )


def _project_iam_policy(
    *,
    bindings: list[dict[str, object]],
    name: str = "project_policy",
) -> object:
    return _terraform_resource(
        f"google_project_iam_policy.{name}",
        GcpResourceType.PROJECT_IAM_POLICY,
        {
            "project": _PROJECT,
            "policy_data": json.dumps({"bindings": bindings}),
        },
    )


def _project_custom_role(
    *,
    project: str,
    role_id: str = "pubsubAck",
    address: str = "google_project_iam_custom_role.pubsub_ack",
    permissions: list[str] | None = None,
) -> object:
    return _terraform_resource(
        address,
        GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
        {
            "project": project,
            "role_id": role_id,
            "name": f"projects/{project}/roles/{role_id}",
            "permissions": permissions or ["pubsub.subscriptions.consume"],
        },
    )


def _organization_custom_role(
    *,
    organization_id: str,
    role_id: str = "pubsubAck",
) -> object:
    return _terraform_resource(
        "google_organization_iam_custom_role.pubsub_ack",
        GcpResourceType.ORGANIZATION_IAM_CUSTOM_ROLE,
        {
            "org_id": organization_id,
            "role_id": role_id,
            "name": f"organizations/{organization_id}/roles/{role_id}",
            "permissions": ["pubsub.subscriptions.consume"],
        },
    )


def _project_resource(*, project: str, organization_id: str) -> object:
    return _terraform_resource(
        f"google_project.{project}",
        GcpResourceType.PROJECT,
        {
            "project_id": project,
            "id": f"projects/{project}",
            "org_id": organization_id,
        },
    )


def _cross_project_topic_and_subscription() -> tuple[object, object]:
    topic = _topic()
    topic.values.update(
        {
            "project": "producer-project",
            "id": "projects/producer-project/topics/orders-events",
        }
    )
    subscription = _subscription()
    subscription.values.update(
        {
            "project": "consumer-project",
            "id": "projects/consumer-project/subscriptions/orders-worker",
        }
    )
    return topic, subscription


def _workload_facts(resources: list[object]):
    inventory = GcpNormalizer().normalize(resources)
    workload = inventory.get_by_address("google_cloud_run_v2_service.orders")
    assert workload is not None
    return gcp_facts(workload)


class GcpCloudRunPubsubMessageRemovalPathTests(unittest.TestCase):
    def test_subscription_subscriber_models_exact_acknowledgement_path(self) -> None:
        facts = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                _subscription(),
                _subscription_iam_member(),
            ]
        )

        self.assertEqual(len(facts.cloud_run_pubsub_message_removal_paths), 1)
        path = facts.cloud_run_pubsub_message_removal_paths[0]
        self.assertEqual(path["operation"], "pubsub.subscriptions.consume")
        self.assertEqual(path["operation_class"], "message_acknowledgement")
        self.assertEqual(path["internal_operation"], "acknowledge_messages")
        self.assertEqual(path["scope_type"], "subscription")
        self.assertEqual(path["scope"], _SUBSCRIPTION_REFERENCE)
        self.assertEqual(path["topic_address"], _TOPIC_ADDRESS)
        self.assertEqual(path["subscription_address"], _SUBSCRIPTION_ADDRESS)
        self.assertEqual(
            path["target_model_evidence_addresses"],
            [_TOPIC_ADDRESS, _SUBSCRIPTION_ADDRESS],
        )
        self.assertEqual(path["acknowledgement_id_source"], "runtime_message_delivery")
        self.assertIsNone(path["acknowledgement_id_value"])
        self.assertEqual(path["matched_permissions"], ["pubsub.subscriptions.consume"])
        self.assertEqual(path["authorization_state"], "granted")
        self.assertEqual(path["condition"], None)
        self.assertEqual(path["condition_state"], "not_configured")

    def test_project_subscriber_fans_out_only_to_exact_modeled_subscriptions(self) -> None:
        archive_address = "google_pubsub_subscription.archive"
        archive_reference = f"projects/{_PROJECT}/subscriptions/archive-worker"
        facts = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                _subscription(),
                _subscription(archive_address, name="archive", reference=archive_reference),
                _project_iam_member(),
            ]
        )

        paths = facts.cloud_run_pubsub_message_removal_paths
        self.assertEqual(len(paths), 2)
        self.assertEqual({path["scope_type"] for path in paths}, {"project"})
        self.assertEqual(
            {path["subscription_address"] for path in paths},
            {_SUBSCRIPTION_ADDRESS, archive_address},
        )
        self.assertTrue(all(path["scope"] == _PROJECT for path in paths))

    def test_cross_project_subscription_preserves_consumer_scope_and_topic_ancestry(self) -> None:
        producer_topic = _topic()
        producer_topic.values.update(
            {
                "project": "producer-project",
                "id": "projects/producer-project/topics/orders-events",
            }
        )
        consumer_subscription = _subscription()
        consumer_subscription.values.update(
            {
                "project": "consumer-project",
                "id": "projects/consumer-project/subscriptions/orders-worker",
            }
        )
        facts = _workload_facts(
            [
                _cloud_run(),
                producer_topic,
                consumer_subscription,
                _project_iam_member(project="consumer-project"),
            ]
        )

        self.assertEqual(len(facts.cloud_run_pubsub_message_removal_paths), 1)
        path = facts.cloud_run_pubsub_message_removal_paths[0]
        self.assertEqual(path["topic_project"], "producer-project")
        self.assertEqual(path["subscription_project"], "consumer-project")
        self.assertEqual(path["scope_type"], "project")
        self.assertEqual(path["scope"], "consumer-project")
        self.assertEqual(path["topic_reference"], "projects/producer-project/topics/orders-events")
        self.assertEqual(
            path["subscription_reference"],
            "projects/consumer-project/subscriptions/orders-worker",
        )

    def test_non_pull_delivery_modes_do_not_create_api_acknowledgement_paths(self) -> None:
        cases = (
            ("push", {"push_config": [{"push_endpoint": "https://worker.example.test"}]}),
            ("bigquery export", {"bigquery_config": [{"table": "projects/demo/datasets/data/tables/events"}]}),
            ("cloud storage export", {"cloud_storage_config": [{"bucket": "events-archive"}]}),
        )
        for case, values in cases:
            with self.subTest(case=case):
                subscription = _subscription()
                subscription.values.update(values)
                facts = _workload_facts([_cloud_run(), _topic(), subscription, _subscription_iam_member()])
                self.assertEqual(facts.cloud_run_pubsub_message_removal_paths, [])

        unknown = _subscription()
        unknown.unknown_values["push_config"] = True
        facts = _workload_facts([_cloud_run(), _topic(), unknown, _subscription_iam_member()])
        self.assertEqual(facts.cloud_run_pubsub_message_removal_paths, [])
        self.assertTrue(
            any(
                "delivery mode" in uncertainty
                for uncertainty in facts.cloud_run_pubsub_message_removal_path_uncertainties
            )
        )

    def test_same_role_subscription_binding_and_member_are_ambiguous(self) -> None:
        facts = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                _subscription(),
                _subscription_iam_member(),
                _subscription_iam_binding(),
            ]
        )

        self.assertEqual(facts.cloud_run_pubsub_message_removal_paths, [])
        self.assertTrue(
            any("ambiguous" in uncertainty for uncertainty in facts.cloud_run_pubsub_message_removal_path_uncertainties)
        )

    def test_project_policy_overlap_suppresses_member_acknowledgement_path(self) -> None:
        facts = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                _subscription(),
                _project_iam_member(),
                _project_iam_policy(
                    bindings=[
                        {
                            "role": "roles/pubsub.subscriber",
                            "members": ["serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"],
                        }
                    ]
                ),
            ]
        )

        self.assertEqual(facts.cloud_run_pubsub_message_removal_paths, [])
        self.assertTrue(
            any(
                "authoritative policy" in uncertainty
                for uncertainty in facts.cloud_run_pubsub_message_removal_path_uncertainties
            )
        )

    def test_unresolved_subscription_binding_role_suppresses_member_path(self) -> None:
        binding = _subscription_iam_binding()
        binding.unknown_values["role"] = True
        facts = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                _subscription(),
                _subscription_iam_member(),
                binding,
            ]
        )

        self.assertEqual(facts.cloud_run_pubsub_message_removal_paths, [])
        self.assertTrue(
            any(
                "unresolved because" in uncertainty
                for uncertainty in facts.cloud_run_pubsub_message_removal_path_uncertainties
            )
        )

    def test_unresolved_project_binding_role_suppresses_member_path(self) -> None:
        binding = _project_iam_binding(role="roles/pubsub.subscriber")
        binding.unknown_values["role"] = True
        facts = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                _subscription(),
                _project_iam_member(),
                binding,
            ]
        )

        self.assertEqual(facts.cloud_run_pubsub_message_removal_paths, [])
        self.assertTrue(
            any(
                "unresolved because" in uncertainty
                for uncertainty in facts.cloud_run_pubsub_message_removal_path_uncertainties
            )
        )

    def test_unresolved_subscription_binding_target_suppresses_member_path(self) -> None:
        binding = _subscription_iam_binding()
        binding.unknown_values["subscription"] = True
        facts = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                _subscription(),
                _subscription_iam_member(),
                binding,
            ]
        )

        self.assertEqual(facts.cloud_run_pubsub_message_removal_paths, [])
        self.assertTrue(
            any(
                "unresolved because" in uncertainty
                for uncertainty in facts.cloud_run_pubsub_message_removal_path_uncertainties
            )
        )

    def test_unresolved_project_binding_scope_suppresses_member_path(self) -> None:
        binding = _project_iam_binding(role="roles/pubsub.subscriber")
        binding.unknown_values["project"] = True
        facts = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                _subscription(),
                _project_iam_member(),
                binding,
            ]
        )

        self.assertEqual(facts.cloud_run_pubsub_message_removal_paths, [])
        self.assertTrue(
            any(
                "unresolved because" in uncertainty
                for uncertainty in facts.cloud_run_pubsub_message_removal_path_uncertainties
            )
        )

    def test_different_role_binding_and_member_remain_compatible(self) -> None:
        facts = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                _subscription(),
                _subscription_iam_member(),
                _subscription_iam_binding(role="roles/pubsub.viewer"),
            ]
        )

        self.assertEqual(len(facts.cloud_run_pubsub_message_removal_paths), 1)
        self.assertEqual(
            facts.cloud_run_pubsub_message_removal_paths[0]["role"],
            "roles/pubsub.subscriber",
        )

    def test_subscription_custom_role_aliases_are_reconciled(self) -> None:
        symbolic_role = "google_project_iam_custom_role.cloud_run_messaging.name"
        native_role = f"projects/{_PROJECT}/roles/cloudRunMessaging"
        facts = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                _subscription(),
                _custom_role(),
                _subscription_iam_member(role=symbolic_role),
                _subscription_iam_binding(role=native_role),
            ]
        )

        self.assertEqual(facts.cloud_run_pubsub_message_removal_paths, [])
        self.assertTrue(
            any("ambiguous" in uncertainty for uncertainty in facts.cloud_run_pubsub_message_removal_path_uncertainties)
        )

    def test_project_custom_role_aliases_are_reconciled(self) -> None:
        symbolic_role = "google_project_iam_custom_role.cloud_run_messaging.name"
        native_role = f"projects/{_PROJECT}/roles/cloudRunMessaging"
        facts = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                _subscription(),
                _custom_role(),
                _project_iam_member(role=symbolic_role),
                _project_iam_binding(role=native_role),
            ]
        )

        self.assertEqual(facts.cloud_run_pubsub_message_removal_paths, [])
        self.assertTrue(
            any("ambiguous" in uncertainty for uncertainty in facts.cloud_run_pubsub_message_removal_path_uncertainties)
        )

    def test_conflicting_custom_roles_do_not_create_message_removal_paths_in_either_order(self) -> None:
        role_name = f"projects/{_PROJECT}/roles/pubsubAck"
        privileged = _project_custom_role(
            project=_PROJECT,
            address="google_project_iam_custom_role.privileged",
            permissions=["pubsub.subscriptions.consume"],
        )
        benign = _project_custom_role(
            project=_PROJECT,
            address="google_project_iam_custom_role.benign",
            permissions=["pubsub.subscriptions.get"],
        )
        snapshots: list[tuple[str, ...]] = []

        for case, definitions in {
            "privileged first": [privileged, benign],
            "benign first": [benign, privileged],
        }.items():
            with self.subTest(case=case):
                facts = _workload_facts(
                    [
                        _cloud_run(),
                        _topic(),
                        _subscription(),
                        *definitions,
                        _subscription_iam_member(role=role_name),
                    ]
                )
                self.assertEqual(facts.cloud_run_pubsub_message_removal_paths, [])
                self.assertTrue(
                    any(
                        "ambiguous across multiple role definitions" in uncertainty
                        for uncertainty in facts.cloud_run_pubsub_message_removal_path_uncertainties
                    )
                )
                snapshots.append(tuple(facts.cloud_run_pubsub_message_removal_path_uncertainties))

        self.assertEqual(snapshots[0], snapshots[1])

    def test_cross_project_project_custom_role_is_not_grantable(self) -> None:
        topic, subscription = _cross_project_topic_and_subscription()
        role = _project_custom_role(project="producer-project")
        facts = _workload_facts(
            [
                _cloud_run(),
                topic,
                subscription,
                role,
                _project_iam_member(
                    project="consumer-project",
                    role="projects/producer-project/roles/pubsubAck",
                ),
            ]
        )

        self.assertEqual(facts.cloud_run_pubsub_message_removal_paths, [])
        self.assertTrue(
            any(
                "not grantable in consumer project" in uncertainty
                for uncertainty in facts.cloud_run_pubsub_message_removal_path_uncertainties
            )
        )

    def test_cross_project_subscription_custom_role_is_not_grantable(self) -> None:
        topic, subscription = _cross_project_topic_and_subscription()
        role = _project_custom_role(project="producer-project")
        facts = _workload_facts(
            [
                _cloud_run(),
                topic,
                subscription,
                role,
                _subscription_iam_member(role="projects/producer-project/roles/pubsubAck"),
            ]
        )

        self.assertEqual(facts.cloud_run_pubsub_message_removal_paths, [])
        self.assertTrue(
            any(
                "not grantable in consumer project" in uncertainty
                for uncertainty in facts.cloud_run_pubsub_message_removal_path_uncertainties
            )
        )

    def test_organization_custom_role_requires_modeled_consumer_organization(self) -> None:
        role = _organization_custom_role(organization_id="123456")
        facts = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                _subscription(),
                role,
                _subscription_iam_member(role="organizations/123456/roles/pubsubAck"),
            ]
        )

        self.assertEqual(facts.cloud_run_pubsub_message_removal_paths, [])
        self.assertTrue(
            any(
                "grant scope compatibility is unresolved" in uncertainty
                for uncertainty in facts.cloud_run_pubsub_message_removal_path_uncertainties
            )
        )

    def test_organization_custom_role_uses_modeled_consumer_organization(self) -> None:
        role = _organization_custom_role(organization_id="123456")
        facts = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                _subscription(),
                _project_resource(project=_PROJECT, organization_id="123456"),
                role,
                _subscription_iam_member(role="organizations/123456/roles/pubsubAck"),
            ]
        )

        self.assertEqual(len(facts.cloud_run_pubsub_message_removal_paths), 1)
        self.assertEqual(
            facts.cloud_run_pubsub_message_removal_paths[0]["custom_role_grant_scope_compatibility_state"],
            "compatible",
        )

    def test_topic_subscriber_does_not_become_acknowledgement_authority(self) -> None:
        facts = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                _subscription(),
                _subscription_iam_member(role="roles/pubsub.viewer"),
                _terraform_resource(
                    "google_pubsub_topic_iam_member.subscriber",
                    GcpResourceType.PUBSUB_TOPIC_IAM_MEMBER,
                    {
                        "topic": f"{_TOPIC_ADDRESS}.id",
                        "role": "roles/pubsub.subscriber",
                        "member": _SERVICE_ACCOUNT_MEMBER,
                    },
                ),
            ]
        )

        self.assertEqual(facts.cloud_run_pubsub_message_removal_paths, [])

    def test_active_custom_role_preserves_definition_lineage(self) -> None:
        role = f"projects/{_PROJECT}/roles/cloudRunMessaging"
        facts = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                _subscription(),
                _custom_role(permissions=["pubsub.subscriptions.consume"]),
                _subscription_iam_member(role=role),
            ]
        )

        path = facts.cloud_run_pubsub_message_removal_paths[0]
        self.assertEqual(path["role_kind"], "custom")
        self.assertEqual(
            path["role_definition_address"],
            "google_project_iam_custom_role.cloud_run_messaging",
        )
        self.assertEqual(path["custom_role_stage"], "GA")
        self.assertFalse(path["custom_role_deleted"])
        self.assertEqual(path["custom_role_grant_scope_compatibility_state"], "compatible")
        self.assertEqual(
            path["iam_source_addresses"],
            [
                "google_pubsub_subscription_iam_member.orders_access",
                "google_project_iam_custom_role.cloud_run_messaging",
            ],
        )

    def test_conditional_and_unresolved_topic_paths_remain_uncertain(self) -> None:
        conditional = _subscription_iam_member(
            condition={
                "title": "business-hours",
                "expression": "request.time < timestamp('2030-01-01T00:00:00Z')",
            }
        )
        unresolved = _subscription(
            "google_pubsub_subscription.unresolved",
            reference="projects/tfstride-demo/subscriptions/unresolved",
        )
        unresolved.values["topic"] = "google_pubsub_topic.missing.id"
        facts = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                _subscription(),
                unresolved,
                conditional,
                _subscription_iam_member(name="orders_unconditional"),
            ]
        )

        self.assertEqual(
            [path["subscription_address"] for path in facts.cloud_run_pubsub_message_removal_paths],
            [_SUBSCRIPTION_ADDRESS],
        )
        self.assertTrue(facts.cloud_run_pubsub_message_removal_path_uncertainties)

    def test_delivery_evidence_preserves_retention_and_replay_posture(self) -> None:
        topic = _topic()
        topic.values["message_retention_duration"] = "604800s"
        subscription = _subscription()
        subscription.values.update(
            {
                "message_retention_duration": "86400s",
                "retain_acked_messages": True,
                "dead_letter_policy": [
                    {
                        "dead_letter_topic": "projects/tfstride-demo/topics/orders-dlq",
                        "max_delivery_attempts": 5,
                    }
                ],
            }
        )
        facts = _workload_facts([_cloud_run(), topic, subscription, _subscription_iam_member()])

        delivery = facts.cloud_run_pubsub_message_removal_paths[0]["delivery_evidence"]
        self.assertEqual(delivery["acknowledged_message_replay_state"], "retained_by_subscription_and_topic")
        self.assertEqual(delivery["subscription_message_retention_seconds"], 86400)
        self.assertEqual(delivery["topic_message_retention_seconds"], 604800)
        self.assertEqual(delivery["dead_letter_policy_state"], "configured")
        self.assertFalse(delivery["replay_authority_evaluated"])
        self.assertFalse(delivery["dead_letter_policy_is_acknowledgement_recovery"])

    def test_omitted_acknowledged_message_retention_uses_provider_default(self) -> None:
        subscription = _subscription()
        subscription.values["message_retention_duration"] = "86400s"
        facts = _workload_facts([_cloud_run(), _topic(), subscription, _subscription_iam_member()])

        delivery = facts.cloud_run_pubsub_message_removal_paths[0]["delivery_evidence"]
        self.assertEqual(delivery["subscription_message_retention_state"], "configured")
        self.assertFalse(delivery["subscription_retain_acked_messages"])
        self.assertEqual(delivery["acknowledged_message_replay_state"], "not_established")

    def test_unknown_acknowledged_message_retention_keeps_replay_state_unknown(self) -> None:
        subscription = _subscription()
        subscription.values["message_retention_duration"] = "86400s"
        subscription.unknown_values["retain_acked_messages"] = True
        facts = _workload_facts([_cloud_run(), _topic(), subscription, _subscription_iam_member()])

        self.assertEqual(len(facts.cloud_run_pubsub_message_removal_paths), 1)
        delivery = facts.cloud_run_pubsub_message_removal_paths[0]["delivery_evidence"]
        self.assertEqual(delivery["subscription_message_retention_state"], "configured")
        self.assertIsNone(delivery["subscription_retain_acked_messages"])
        self.assertEqual(delivery["acknowledged_message_replay_state"], "unknown")


if __name__ == "__main__":
    unittest.main()
