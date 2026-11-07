"""Deterministic plans for characterizing GCS context reuse before optimization."""

from __future__ import annotations

from typing import Literal

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.models import TerraformResource
from tfstride.providers.gcp.resource_types import GcpResourceType

PROJECT = "tfstride-gcs-contexts"
CASES = ("no_buckets", "mixed", "deny", "unknown_deny", "conditional_unknown", "protected_data")
CUSTOM_ROLE = f"projects/{PROJECT}/roles/storageOperator"


def service_account_member(index: int) -> str:
    return f"serviceAccount:w{index}@{PROJECT}.iam.gserviceaccount.com"


def _workload(index: int, *, unknown_identity: bool = False) -> TerraformResource:
    return _terraform_resource(
        f"google_cloud_run_v2_service.w{index}",
        GcpResourceType.CLOUD_RUN_V2_SERVICE,
        {
            "name": f"w{index}",
            "project": PROJECT,
            "location": "us-central1",
            "ingress": "INGRESS_TRAFFIC_ALL",
            "invoker_iam_disabled": True,
            "template": [
                {} if unknown_identity else {"service_account": service_account_member(index).split(":", 1)[1]}
            ],
        },
        unknown_values={"template": [{"service_account": True}]} if unknown_identity else None,
    )


def _bucket(index: int) -> TerraformResource:
    return _terraform_resource(
        f"google_storage_bucket.b{index}",
        GcpResourceType.STORAGE_BUCKET,
        {
            "name": f"{PROJECT}-b{index}",
            "project": PROJECT,
            "location": "US",
            "uniform_bucket_level_access": True,
            "versioning": [{"enabled": True}],
            "soft_delete_policy": [{"retention_duration_seconds": 604800}],
        },
    )


def _bucket_grant(name: str, workload: int, bucket: int, role: str) -> TerraformResource:
    return _terraform_resource(
        f"google_storage_bucket_iam_member.{name}",
        GcpResourceType.STORAGE_BUCKET_IAM_MEMBER,
        {"bucket": f"google_storage_bucket.b{bucket}.name", "role": role, "member": service_account_member(workload)},
    )


def _project_grant(name: str, workload: int, role: str) -> TerraformResource:
    return _terraform_resource(
        f"google_project_iam_member.{name}",
        GcpResourceType.PROJECT_IAM_MEMBER,
        {"project": PROJECT, "role": role, "member": service_account_member(workload)},
    )


def build_gcs_case(case: str) -> list[TerraformResource]:
    """Return fresh resources, including real Terraform unknown-value markers."""
    if case not in CASES:
        raise ValueError(f"Unknown GCS characterization case: {case}")
    if case == "no_buckets":
        return [_workload(0), _workload(1), _workload(2, unknown_identity=True)]
    if case == "protected_data":
        return _protected_data_resources()

    resources = [
        _workload(0),
        _workload(1),
        _workload(2, unknown_identity=case == "conditional_unknown"),
        _bucket(0),
        _bucket(1),
        _terraform_resource(
            "google_project.owner",
            GcpResourceType.PROJECT,
            {"project_id": PROJECT, "org_id": "123456"},
        ),
    ]
    if case == "conditional_unknown":
        for name in ("first", "second"):
            grant = _bucket_grant(name, 0, 0, "roles/storage.objectAdmin")
            grant.values["condition"] = [{"title": name, "expression": f"resource.name.endsWith('{name}')"}]
            resources.append(grant)
        unknown_grant = _project_grant("unknown_member", 1, "roles/storage.objectCreator")
        unknown_grant.values.pop("member")
        unknown_grant.unknown_values["member"] = True
        resources.extend(
            [
                unknown_grant,
                _bucket_grant("missing_role", 1, 1, f"projects/{PROJECT}/roles/missing"),
                _terraform_resource(
                    "google_storage_bucket_iam_policy.unknown",
                    GcpResourceType.STORAGE_BUCKET_IAM_POLICY,
                    {"bucket": "google_storage_bucket.b1.name"},
                    unknown_values={"policy_data": True},
                ),
            ]
        )
        return resources

    resources.extend(
        [
            _bucket_grant("local", 0, 0, "roles/storage.admin"),
            _project_grant("inherited", 1, "roles/storage.objectUser"),
            _project_grant("custom", 2, CUSTOM_ROLE),
            _terraform_resource(
                "google_project_iam_custom_role.storage_operator",
                GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
                {
                    "project": PROJECT,
                    "role_id": "storageOperator",
                    "name": CUSTOM_ROLE,
                    "stage": "GA",
                    "deleted": False,
                    "permissions": [
                        "storage.objects.get",
                        "storage.objects.create",
                        "storage.objects.delete",
                        "storage.buckets.delete",
                    ],
                },
            ),
        ]
    )
    if case in {"deny", "unknown_deny"}:
        resources.append(
            _terraform_resource(
                "google_iam_deny_policy.create",
                GcpResourceType.IAM_DENY_POLICY,
                {
                    "parent": f"cloudresourcemanager.googleapis.com/projects/{PROJECT}",
                    "rules": [
                        {
                            "deny_rule": [
                                {
                                    "denied_permissions": ["storage.googleapis.com/objects.create"],
                                    "denied_principals": [
                                        f"principal://iam.googleapis.com/projects/-/serviceAccounts/w1@{PROJECT}.iam.gserviceaccount.com"
                                    ],
                                }
                            ]
                        }
                    ],
                },
                unknown_values={"rules": True} if case == "unknown_deny" else None,
            )
        )
    return resources


def _protected_data_resources() -> list[TerraformResource]:
    ring = f"projects/{PROJECT}/locations/global/keyRings/application"
    key = f"{ring}/cryptoKeys/data"
    bucket = _bucket(0)
    bucket.values["encryption"] = [{"default_kms_key_name": key}]
    return [
        _workload(0),
        bucket,
        _bucket_grant("reader", 0, 0, "roles/storage.objectViewer"),
        _terraform_resource(
            "google_kms_crypto_key.data",
            GcpResourceType.KMS_CRYPTO_KEY,
            {"id": key, "name": "data", "key_ring": ring, "purpose": "ENCRYPT_DECRYPT"},
        ),
        _terraform_resource(
            "google_kms_crypto_key_version.data",
            GcpResourceType.KMS_CRYPTO_KEY_VERSION,
            {
                "crypto_key": "google_kms_crypto_key.data.id",
                "id": f"{key}/cryptoKeyVersions/1",
                "name": f"{key}/cryptoKeyVersions/1",
                "state": "ENABLED",
                "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
                "protection_level": "SOFTWARE",
                "generate_time": "2026-09-01T00:00:00Z",
            },
        ),
        _terraform_resource(
            "google_kms_crypto_key_iam_member.decrypter",
            GcpResourceType.KMS_CRYPTO_KEY_IAM_MEMBER,
            {"crypto_key_id": key, "role": "roles/cloudkms.cryptoKeyDecrypter", "member": service_account_member(0)},
        ),
    ]


def build_benchmark_resources(workloads: int, scenario: Literal["pubsub", "gcs"]) -> list[TerraformResource]:
    """Pub/Sub recreates the review's 40/120/240-resource, bucket-free workload."""
    if workloads < 1:
        raise ValueError("workloads must be positive")
    resources: list[TerraformResource] = []
    for index in range(workloads):
        resources.append(_workload(index))
        if scenario == "gcs":
            resources.extend(
                [_bucket(index), _bucket_grant(f"local{index}", index, index, "roles/storage.objectAdmin")]
            )
            continue
        resources.extend(
            [
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
                _terraform_resource(
                    f"google_pubsub_subscription_iam_member.subscriber{index}",
                    GcpResourceType.PUBSUB_SUBSCRIPTION_IAM_MEMBER,
                    {
                        "subscription": f"google_pubsub_subscription.s{index}.name",
                        "role": "roles/pubsub.subscriber",
                        "member": service_account_member(index),
                    },
                ),
            ]
        )
    return resources


def build_gcs_candidate_resources(workloads: int, buckets: int) -> list[TerraformResource]:
    """Give every workload inherited read, mutation, and deletion authority on every bucket."""
    if workloads < 1 or buckets < 1:
        raise ValueError("workloads and buckets must be positive")
    return [
        *(_workload(index) for index in range(workloads)),
        *(_bucket(index) for index in range(buckets)),
        *(_project_grant(f"admin{index}", index, "roles/storage.admin") for index in range(workloads)),
    ]
