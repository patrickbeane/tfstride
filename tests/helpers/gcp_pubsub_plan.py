"""Deterministic scaled GCP Pub/Sub plan with mixed IAM authority shapes.

`build_pubsub_plan(count)` returns Cloud Run workloads, topics, subscriptions and
IAM resources that exercise the ways Pub/Sub disruption paths join workloads to
targets: resource-local grants, cross-target grants, project-wide grants,
overlapping authoritative and additive managers, conditions, unresolved scope
references, and custom roles. It uses no randomness, so the same `count` always
produces the same plan, which lets tests snapshot the exact analysis output.
"""

from __future__ import annotations

import json

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.models import TerraformResource
from tfstride.providers.gcp.resource_types import GcpResourceType

PROJECT = "tfstride-demo"
CUSTOM_ROLE_ID = "pubsubOperator"
CUSTOM_ROLE_NAME = f"projects/{PROJECT}/roles/{CUSTOM_ROLE_ID}"


def service_account_email(index: int) -> str:
    return f"svc{index}@{PROJECT}.iam.gserviceaccount.com"


def service_account_member(index: int) -> str:
    return f"serviceAccount:{service_account_email(index)}"


def build_pubsub_plan(count: int) -> list[TerraformResource]:
    resources: list[TerraformResource] = [_custom_role(), _authoritative_project_binding()]
    for index in range(count):
        resources.extend(_workload_resources(index, count))
    return resources


def _workload_resources(index: int, count: int) -> list[TerraformResource]:
    member = service_account_member(index)
    next_index = (index + 1) % count
    resources: list[TerraformResource] = [
        _terraform_resource(
            f"google_cloud_run_v2_service.w{index}",
            GcpResourceType.CLOUD_RUN_V2_SERVICE,
            {
                "name": f"w{index}",
                "project": PROJECT,
                "location": "us-central1",
                "template": [{"service_account": service_account_email(index)}],
            },
        ),
        _terraform_resource(
            f"google_pubsub_topic.t{index}",
            GcpResourceType.PUBSUB_TOPIC,
            {"name": f"t{index}", "id": f"projects/{PROJECT}/topics/t{index}", "project": PROJECT},
        ),
        _terraform_resource(
            f"google_pubsub_subscription.s{index}",
            GcpResourceType.PUBSUB_SUBSCRIPTION,
            {
                "name": f"s{index}",
                "id": f"projects/{PROJECT}/subscriptions/s{index}",
                "project": PROJECT,
                "topic": f"google_pubsub_topic.t{index}.id",
            },
        ),
    ]
    shape = index % 6
    if shape == 0:
        resources.append(_topic_member(f"local{index}", index, "roles/pubsub.editor", member))
    elif shape == 1:
        resources.append(_subscription_member(f"local{index}", index, "roles/pubsub.subscriber", member))
        resources.append(_subscription_member(f"cross{index}", next_index, "roles/pubsub.editor", member))
        resources.append(
            _terraform_resource(
                f"google_pubsub_subscription_iam_binding.managed{index}",
                GcpResourceType.PUBSUB_SUBSCRIPTION_IAM_BINDING,
                {
                    "subscription": f"google_pubsub_subscription.s{index}.name",
                    "role": "roles/pubsub.subscriber",
                    "members": [member, service_account_member(next_index)],
                },
            )
        )
    elif shape == 2:
        if index % 12 == 2:
            resources.append(_project_member(f"admin{index}", "roles/pubsub.admin", member))
        else:
            resources.append(_topic_member(f"local{index}", index, "roles/pubsub.admin", member))
    elif shape == 3:
        resources.append(
            _terraform_resource(
                f"google_pubsub_topic_iam_binding.managed{index}",
                GcpResourceType.PUBSUB_TOPIC_IAM_BINDING,
                {
                    "topic": f"google_pubsub_topic.t{index}.name",
                    "role": "roles/pubsub.admin",
                    "members": [member, service_account_member(next_index)],
                },
            )
        )
        resources.append(_topic_member(f"overlap{index}", index, "roles/pubsub.admin", member))
    elif shape == 4:
        resources.append(_project_member(f"custom{index}", CUSTOM_ROLE_NAME, member))
    else:
        resources.append(
            _subscription_member(
                f"conditional{index}",
                index,
                "roles/pubsub.subscriber",
                member,
                condition={"title": "temporary", "expression": "request.time < timestamp('2030-01-01T00:00:00Z')"},
            )
        )
        resources.append(
            _topic_member(
                f"conditional{index}",
                index,
                "roles/pubsub.editor",
                member,
                condition={"title": "temporary", "expression": "request.time < timestamp('2030-01-01T00:00:00Z')"},
            )
        )
        unresolved = _topic_member(f"unresolved{index}", index, "roles/pubsub.editor", member)
        unresolved.unknown_values["topic"] = True
        unresolved.values.pop("topic", None)
        resources.append(unresolved)
        unresolved_subscription = _subscription_member(f"unresolved{index}", index, "roles/pubsub.editor", member)
        unresolved_subscription.unknown_values["subscription"] = True
        unresolved_subscription.values.pop("subscription", None)
        resources.append(unresolved_subscription)
    return resources


def _topic_member(
    name: str,
    target_index: int,
    role: str,
    member: str,
    *,
    condition: dict[str, str] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {"topic": f"google_pubsub_topic.t{target_index}.name", "role": role, "member": member}
    if condition is not None:
        values["condition"] = [condition]
    return _terraform_resource(
        f"google_pubsub_topic_iam_member.{name}",
        GcpResourceType.PUBSUB_TOPIC_IAM_MEMBER,
        values,
    )


def _subscription_member(
    name: str,
    target_index: int,
    role: str,
    member: str,
    *,
    condition: dict[str, str] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "subscription": f"google_pubsub_subscription.s{target_index}.name",
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


def _project_member(name: str, role: str, member: str) -> TerraformResource:
    return _terraform_resource(
        f"google_project_iam_member.{name}",
        GcpResourceType.PROJECT_IAM_MEMBER,
        {"project": PROJECT, "role": role, "member": member},
    )


def _authoritative_project_binding() -> TerraformResource:
    return _terraform_resource(
        "google_project_iam_binding.editors",
        GcpResourceType.PROJECT_IAM_BINDING,
        {
            "project": PROJECT,
            "role": "roles/pubsub.editor",
            "members": [service_account_member(0), service_account_member(1)],
        },
    )


def _custom_role() -> TerraformResource:
    return _terraform_resource(
        "google_project_iam_custom_role.pubsub_operator",
        GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
        {
            "project": PROJECT,
            "role_id": CUSTOM_ROLE_ID,
            "name": CUSTOM_ROLE_NAME,
            "permissions": ["pubsub.subscriptions.consume", "pubsub.topics.delete", "pubsub.topics.publish"],
        },
    )


def describe_plan(resources: list[TerraformResource]) -> str:
    """Compact fingerprint of a generated plan, useful for asserting determinism."""

    return json.dumps(
        [[resource.address, resource.resource_type, resource.values] for resource in resources],
        sort_keys=True,
        default=str,
    )
