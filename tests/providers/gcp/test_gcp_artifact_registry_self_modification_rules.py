from __future__ import annotations

import unittest
from collections import Counter
from typing import Any

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_types import GcpResourceType
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

_RULE_ID = "gcp-cloud-run-can-modify-image-repository"
_IMAGE_PIN_RULE = "gcp-cloud-run-image-not-digest-pinned"
_MUTABLE_TAG_RULE = "gcp-cloud-run-artifact-registry-mutable-tag"
_REPOSITORY_ADDRESS = "google_artifact_registry_repository.images"
_SERVICE_ACCOUNT_EMAIL = "tfstride-api@tfstride-demo.iam.gserviceaccount.com"
_SERVICE_ACCOUNT_MEMBER = f"serviceAccount:{_SERVICE_ACCOUNT_EMAIL}"
_IMAGE = "us-central1-docker.pkg.dev/tfstride-demo/images/api:stable"
_DIGEST = "sha256:" + "a" * 64


def _repository(
    *,
    immutable_tags: object = False,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return _terraform_resource(
        _REPOSITORY_ADDRESS,
        GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY,
        {
            "name": "projects/tfstride-demo/locations/us-central1/repositories/images",
            "project": "tfstride-demo",
            "location": "us-central1",
            "repository_id": "images",
            "format": "DOCKER",
            "docker_config": [{"immutable_tags": immutable_tags}],
        },
        unknown_values=unknown_values,
    )


def _cloud_run(
    *,
    image: object = _IMAGE,
    service_account: object = _SERVICE_ACCOUNT_EMAIL,
) -> TerraformResource:
    return _terraform_resource(
        "google_cloud_run_v2_service.api",
        GcpResourceType.CLOUD_RUN_V2_SERVICE,
        {
            "name": "api",
            "location": "us-central1",
            "template": [
                {
                    "containers": [{"image": image}],
                    "service_account": service_account,
                }
            ],
        },
    )


def _repository_iam_member(
    *,
    role: str = "roles/artifactregistry.writer",
    member: str = _SERVICE_ACCOUNT_MEMBER,
    condition: list[dict[str, str]] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "repository": f"{_REPOSITORY_ADDRESS}.id",
        "role": role,
        "member": member,
    }
    if condition is not None:
        values["condition"] = condition
    return _terraform_resource(
        "google_artifact_registry_repository_iam_member.assignment",
        GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY_IAM_MEMBER,
        values,
    )


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = GcpNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids or {_RULE_ID})),
    )


def _evidence(finding):
    return {item.key: item.values for item in finding.evidence}


class GcpArtifactRegistrySelfModificationRuleTests(unittest.TestCase):
    def test_rule_is_registered(self) -> None:
        registered = {rule_id for group in GCP_RULE_GROUP_IDS for rule_id in group}
        self.assertIn(_RULE_ID, registered)

    def test_runtime_service_account_writer_assignment_is_detected(self) -> None:
        findings = _evaluate([_repository(), _cloud_run(), _repository_iam_member()])

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(
            finding.affected_resources,
            [
                "google_cloud_run_v2_service.api",
                _REPOSITORY_ADDRESS,
                "google_artifact_registry_repository_iam_member.assignment",
            ],
        )
        self.assertIn("self-modification and persistence path", finding.rationale)
        evidence = _evidence(finding)
        self.assertIn(f"service_account_member={_SERVICE_ACCOUNT_MEMBER}", evidence["runtime_identity"])
        self.assertIn("role=roles/artifactregistry.writer", evidence["runtime_identity"])
        self.assertIn("role_kind=writer", evidence["runtime_identity"])
        self.assertIn("grant_basis=artifact_registry_repository_iam", evidence["artifact_registry_write_path"])
        self.assertIn("repository_scope=exact_repository_path", evidence["artifact_registry_write_path"])
        self.assertIn("docker_immutable_tags_state=disabled", evidence["artifact_registry_repository"])

    def test_repository_admin_assignment_is_detected(self) -> None:
        findings = _evaluate(
            [
                _repository(),
                _cloud_run(),
                _repository_iam_member(role="roles/artifactregistry.admin"),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        evidence = _evidence(findings[0])
        self.assertIn("role=roles/artifactregistry.admin", evidence["runtime_identity"])
        self.assertIn("role_kind=admin", evidence["runtime_identity"])

    def test_digest_pinned_image_is_quiet(self) -> None:
        findings = _evaluate(
            [
                _repository(),
                _cloud_run(
                    image="us-central1-docker.pkg.dev/tfstride-demo/images/api@" + _DIGEST,
                ),
                _repository_iam_member(),
            ]
        )

        self.assertEqual(findings, [])

    def test_implicit_default_tag_is_treated_as_unpinned(self) -> None:
        findings = _evaluate(
            [
                _repository(),
                _cloud_run(image="us-central1-docker.pkg.dev/tfstride-demo/images/api"),
                _repository_iam_member(),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        self.assertIn("tag=unset", _evidence(findings[0])["image_reference"])

    def test_immutable_or_unknown_repository_tag_posture_is_quiet(self) -> None:
        immutable = _evaluate(
            [
                _repository(immutable_tags=True),
                _cloud_run(),
                _repository_iam_member(),
            ]
        )
        unknown = _evaluate(
            [
                _repository(
                    immutable_tags=None,
                    unknown_values={"docker_config": True},
                ),
                _cloud_run(),
                _repository_iam_member(),
            ]
        )

        self.assertEqual(immutable, [])
        self.assertEqual(unknown, [])

    def test_conditional_or_nonmatching_assignment_is_quiet(self) -> None:
        conditional = _evaluate(
            [
                _repository(),
                _cloud_run(),
                _repository_iam_member(
                    condition=[
                        {
                            "title": "release-window",
                            "expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
                        }
                    ]
                ),
            ]
        )
        nonmatching = _evaluate(
            [
                _repository(),
                _cloud_run(),
                _repository_iam_member(
                    member="serviceAccount:other@tfstride-demo.iam.gserviceaccount.com",
                ),
            ]
        )

        self.assertEqual(conditional, [])
        self.assertEqual(nonmatching, [])

    def test_self_modification_finding_remains_distinct_from_integrity_findings(self) -> None:
        findings = _evaluate(
            [_repository(), _cloud_run(), _repository_iam_member()],
            _IMAGE_PIN_RULE,
            _MUTABLE_TAG_RULE,
            _RULE_ID,
        )

        self.assertEqual(
            Counter(finding.rule_id for finding in findings),
            Counter({_IMAGE_PIN_RULE: 1, _MUTABLE_TAG_RULE: 1, _RULE_ID: 1}),
        )


if __name__ == "__main__":
    unittest.main()
