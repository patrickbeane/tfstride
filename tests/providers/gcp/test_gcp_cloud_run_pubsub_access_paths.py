from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_PROJECT = "tfstride-demo"
_SERVICE_ACCOUNT_EMAIL = "orders@tfstride-demo.iam.gserviceaccount.com"
_SERVICE_ACCOUNT_MEMBER = f"serviceAccount:{_SERVICE_ACCOUNT_EMAIL}"
_WORKLOAD_ADDRESS = "google_cloud_run_v2_service.orders"
_TOPIC_ADDRESS = "google_pubsub_topic.orders"
_TOPIC_REFERENCE = f"projects/{_PROJECT}/topics/orders-events"
_SUBSCRIPTION_ADDRESS = "google_pubsub_subscription.orders"
_SUBSCRIPTION_REFERENCE = f"projects/{_PROJECT}/subscriptions/orders-worker"


def _cloud_run(*, service_account: str | None = _SERVICE_ACCOUNT_EMAIL) -> object:
    template: dict[str, object] = {}
    if service_account is not None:
        template["service_account"] = service_account
    return _terraform_resource(
        _WORKLOAD_ADDRESS,
        GcpResourceType.CLOUD_RUN_V2_SERVICE,
        {
            "name": "orders",
            "project": _PROJECT,
            "location": "us-central1",
            "template": [template],
        },
    )


def _topic(
    address: str = _TOPIC_ADDRESS,
    *,
    name: str = "orders-events",
    reference: str = _TOPIC_REFERENCE,
) -> object:
    return _terraform_resource(
        address,
        GcpResourceType.PUBSUB_TOPIC,
        {
            "name": name,
            "id": reference,
            "project": _PROJECT,
        },
    )


def _subscription(
    address: str = _SUBSCRIPTION_ADDRESS,
    *,
    name: str = "orders-worker",
    reference: str = _SUBSCRIPTION_REFERENCE,
) -> object:
    return _terraform_resource(
        address,
        GcpResourceType.PUBSUB_SUBSCRIPTION,
        {
            "name": name,
            "id": reference,
            "project": _PROJECT,
            "topic": f"{_TOPIC_ADDRESS}.id",
        },
    )


def _topic_iam_member(
    *,
    role: str = "roles/pubsub.publisher",
    member: str = _SERVICE_ACCOUNT_MEMBER,
    topic: str = f"{_TOPIC_ADDRESS}.name",
    name: str = "orders_access",
    condition: dict[str, str] | None = None,
) -> object:
    values: dict[str, object] = {"topic": topic, "role": role, "member": member}
    if condition is not None:
        values["condition"] = [condition]
    return _terraform_resource(
        f"google_pubsub_topic_iam_member.{name}",
        GcpResourceType.PUBSUB_TOPIC_IAM_MEMBER,
        values,
    )


def _subscription_iam_member(
    *,
    role: str = "roles/pubsub.subscriber",
    member: str = _SERVICE_ACCOUNT_MEMBER,
    subscription: str = f"{_SUBSCRIPTION_ADDRESS}.name",
    name: str = "orders_access",
    condition: dict[str, str] | None = None,
) -> object:
    values: dict[str, object] = {
        "subscription": subscription,
        "role": role,
        "member": member,
    }
    if condition is not None:
        values["condition"] = [condition]
    return _terraform_resource(
        f"google_pubsub_subscription_iam_member.{name}",
        GcpResourceType.PUBSUB_SUBSCRIPTION_IAM_MEMBER,
        values,
    )


def _custom_role(
    *,
    role_id: str = "cloudRunMessaging",
    permissions: list[str] | None = None,
) -> object:
    return _terraform_resource(
        "google_project_iam_custom_role.cloud_run_messaging",
        GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
        {
            "project": _PROJECT,
            "role_id": role_id,
            "name": f"projects/{_PROJECT}/roles/{role_id}",
            "permissions": permissions
            or [
                "pubsub.subscriptions.consume",
                "pubsub.topics.delete",
                "pubsub.topics.publish",
                "resourcemanager.projects.get",
            ],
        },
    )


def _workload_facts(resources: list[object]):
    inventory = GcpNormalizer().normalize(resources)
    workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
    assert workload is not None
    return gcp_facts(workload)


class GcpCloudRunPubsubAccessPathTests(unittest.TestCase):
    def test_exact_topic_publisher_grant_is_modeled_with_runtime_identity(self) -> None:
        facts = _workload_facts([_cloud_run(), _topic(), _topic_iam_member()])

        self.assertEqual(
            facts.cloud_run_pubsub_access_paths,
            [
                {
                    "workload_address": _WORKLOAD_ADDRESS,
                    "workload_type": GcpResourceType.CLOUD_RUN_V2_SERVICE,
                    "service_account_email": _SERVICE_ACCOUNT_EMAIL,
                    "service_account_member": _SERVICE_ACCOUNT_MEMBER,
                    "identity_kind": "cloud_run_service_account",
                    "credential_context": "workload_runtime",
                    "messaging_service": "pubsub",
                    "messaging_resource_kind": "topic",
                    "messaging_resource_address": _TOPIC_ADDRESS,
                    "messaging_resource_type": GcpResourceType.PUBSUB_TOPIC,
                    "messaging_resource_name": "orders-events",
                    "messaging_resource_project": _PROJECT,
                    "messaging_resource_reference": _TOPIC_REFERENCE,
                    "iam_resource_address": "google_pubsub_topic_iam_member.orders_access",
                    "role": "roles/pubsub.publisher",
                    "role_kind": "publisher",
                    "access_classes": ["publish"],
                    "custom_role_permissions": [],
                    "matched_permissions": [],
                    "grant_basis": "pubsub_topic_iam",
                    "resource_scope": "exact_topic",
                    "condition": None,
                    "condition_state": "not_configured",
                    "access_state": "granted",
                }
            ],
        )
        self.assertEqual(facts.cloud_run_pubsub_access_path_uncertainties, [])

    def test_builtin_roles_preserve_target_specific_capabilities(self) -> None:
        cases = {
            "topic publisher": (
                [_cloud_run(), _topic(), _topic_iam_member()],
                "publisher",
                ["publish"],
            ),
            "topic admin": (
                [_cloud_run(), _topic(), _topic_iam_member(role="roles/pubsub.admin")],
                "admin",
                ["read", "publish", "delete", "administrative"],
            ),
            "topic subscriber attachment": (
                [_cloud_run(), _topic(), _topic_iam_member(role="roles/pubsub.subscriber")],
                "subscriber",
                ["administrative"],
            ),
            "subscription subscriber": (
                [_cloud_run(), _topic(), _subscription(), _subscription_iam_member()],
                "subscriber",
                ["consume"],
            ),
            "subscription admin": (
                [
                    _cloud_run(),
                    _topic(),
                    _subscription(),
                    _subscription_iam_member(role="roles/pubsub.admin"),
                ],
                "admin",
                ["read", "consume", "delete", "administrative"],
            ),
        }

        for case, (resources, role_kind, access_classes) in cases.items():
            with self.subTest(case=case):
                path = _workload_facts(resources).cloud_run_pubsub_access_paths[0]
                self.assertEqual(path["role_kind"], role_kind)
                self.assertEqual(path["access_classes"], access_classes)

    def test_custom_role_permissions_are_filtered_for_each_exact_target_kind(self) -> None:
        role = f"projects/{_PROJECT}/roles/cloudRunMessaging"
        facts = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                _subscription(),
                _custom_role(),
                _topic_iam_member(role=role),
                _subscription_iam_member(role=role),
            ]
        )

        paths = {path["messaging_resource_kind"]: path for path in facts.cloud_run_pubsub_access_paths}
        self.assertEqual(paths["topic"]["access_classes"], ["publish", "delete"])
        self.assertEqual(
            paths["topic"]["matched_permissions"],
            ["pubsub.topics.delete", "pubsub.topics.publish"],
        )
        self.assertEqual(paths["subscription"]["access_classes"], ["consume"])
        self.assertEqual(paths["subscription"]["matched_permissions"], ["pubsub.subscriptions.consume"])
        self.assertEqual(
            paths["topic"]["custom_role_permissions"],
            [
                "pubsub.subscriptions.consume",
                "pubsub.topics.delete",
                "pubsub.topics.publish",
                "resourcemanager.projects.get",
            ],
        )

    def test_conditional_grant_is_preserved_without_unconditional_access_claim(self) -> None:
        condition = {
            "title": "business-hours",
            "description": "Limit publishing by request time",
            "expression": "request.time < timestamp('2030-01-01T00:00:00Z')",
        }
        facts = _workload_facts([_cloud_run(), _topic(), _topic_iam_member(condition=condition)])

        path = facts.cloud_run_pubsub_access_paths[0]
        self.assertEqual(path["condition"], condition)
        self.assertEqual(path["condition_state"], "configured")
        self.assertEqual(path["access_state"], "conditional")

    def test_unknown_condition_does_not_become_an_unconditional_grant(self) -> None:
        iam_member = _topic_iam_member()
        iam_member.unknown_values["condition"] = True
        facts = _workload_facts([_cloud_run(), _topic(), iam_member])

        path = facts.cloud_run_pubsub_access_paths[0]
        self.assertIsNone(path["condition"])
        self.assertEqual(path["condition_state"], "unknown")
        self.assertEqual(path["access_state"], "unknown")
        self.assertEqual(
            facts.cloud_run_pubsub_access_path_uncertainties,
            [
                f"{_WORKLOAD_ADDRESS}: google_pubsub_topic_iam_member.orders_access "
                "IAM condition is unknown after planning"
            ],
        )

    def test_similarly_named_or_unresolved_targets_do_not_create_false_relationships(self) -> None:
        archive_address = "google_pubsub_topic.orders_archive"
        archive_reference = f"projects/{_PROJECT}/topics/orders-events-archive"
        facts = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                _topic(archive_address, name="orders-events-archive", reference=archive_reference),
                _topic_iam_member(
                    topic=f"{archive_address}.name",
                    name="archive_access",
                ),
                _topic_iam_member(
                    topic="google_pubsub_topic.missing.name",
                    name="missing_access",
                ),
            ]
        )

        self.assertEqual(
            [path["messaging_resource_address"] for path in facts.cloud_run_pubsub_access_paths],
            [archive_address],
        )

    def test_nonmatching_or_unresolved_identity_does_not_create_access_claim(self) -> None:
        other_identity = _workload_facts(
            [
                _cloud_run(),
                _topic(),
                _topic_iam_member(member="serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"),
            ]
        )
        unresolved_identity = _workload_facts([_cloud_run(service_account=None), _topic(), _topic_iam_member()])

        self.assertEqual(other_identity.cloud_run_pubsub_access_paths, [])
        self.assertEqual(unresolved_identity.cloud_run_pubsub_access_paths, [])
        self.assertEqual(
            unresolved_identity.cloud_run_pubsub_access_path_uncertainties,
            [f"{_WORKLOAD_ADDRESS}: Cloud Run service account is unresolved"],
        )

    def test_unresolved_custom_role_permissions_are_retained_as_uncertainty(self) -> None:
        role = f"projects/{_PROJECT}/roles/externalMessagingRole"
        facts = _workload_facts([_cloud_run(), _topic(), _topic_iam_member(role=role)])

        self.assertEqual(facts.cloud_run_pubsub_access_paths, [])
        self.assertEqual(
            facts.cloud_run_pubsub_access_path_uncertainties,
            [
                f"{_WORKLOAD_ADDRESS}: google_pubsub_topic_iam_member.orders_access "
                f"custom IAM role {role} does not resolve to deterministic Pub/Sub permissions"
            ],
        )


if __name__ == "__main__":
    unittest.main()
