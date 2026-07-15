from __future__ import annotations

import unittest
from typing import Any

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

_IMAGE_RULE = "gcp-cloud-run-image-not-digest-pinned"
_MUTABLE_TAG_RULE = "gcp-cloud-run-artifact-registry-mutable-tag"
_RULE_IDS = (_IMAGE_RULE, _MUTABLE_TAG_RULE)
_IMAGE = "us-central1-docker.pkg.dev/tfstride-demo/images/api:stable"
_REPOSITORY_PATH = "projects/tfstride-demo/locations/us-central1/repositories/images"
_DIGEST = "sha256:" + "a" * 64


def _cloud_run_service(
    image: object = _IMAGE,
    *,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return _terraform_resource(
        "google_cloud_run_v2_service.api",
        "google_cloud_run_v2_service",
        {
            "name": "api",
            "project": "tfstride-demo",
            "location": "us-central1",
            "template": [{"containers": [{"image": image}]}],
        },
        unknown_values=unknown_values,
    )


def _artifact_registry_repository(
    *,
    repository_id: str = "images",
    immutable_tags: object = False,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return _terraform_resource(
        f"google_artifact_registry_repository.{repository_id}",
        "google_artifact_registry_repository",
        {
            "name": f"projects/tfstride-demo/locations/us-central1/repositories/{repository_id}",
            "project": "tfstride-demo",
            "location": "us-central1",
            "repository_id": repository_id,
            "format": "DOCKER",
            "docker_config": [{"immutable_tags": immutable_tags}],
        },
        unknown_values=unknown_values,
    )


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = GcpNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids or _RULE_IDS)),
    )


def _evidence(finding):
    return {item.key: item.values for item in finding.evidence}


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> set[str]:
    return {rule_id for group in rule_groups for rule_id in group}


class GcpContainerRuleTests(unittest.TestCase):
    def test_cloud_run_image_integrity_rule_ids_are_registered(self) -> None:
        self.assertTrue(set(_RULE_IDS).issubset(_flatten(GCP_RULE_GROUP_IDS)))

    def test_resolved_cloud_run_image_without_digest_pin_is_detected(self) -> None:
        findings = _evaluate([_cloud_run_service()], _IMAGE_RULE)

        self.assertEqual([finding.rule_id for finding in findings], [_IMAGE_RULE])
        self.assertEqual(findings[0].affected_resources, ["google_cloud_run_v2_service.api"])
        self.assertIn("without a digest pin", findings[0].rationale)
        evidence = _evidence(findings[0])
        self.assertIn("raw=" + _IMAGE, evidence["image_reference"])
        self.assertIn("digest_pinned=False", evidence["image_reference"])

    def test_digest_pinned_cloud_run_image_is_quiet(self) -> None:
        self.assertEqual(
            _evaluate(
                [_cloud_run_service(f"us-central1-docker.pkg.dev/tfstride-demo/images/api@{_DIGEST}")],
                _IMAGE_RULE,
            ),
            [],
        )

    def test_unknown_cloud_run_image_is_not_overclaimed(self) -> None:
        self.assertEqual(
            _evaluate([_cloud_run_service(None, unknown_values={"template": True})], _IMAGE_RULE),
            [],
        )

    def test_exact_artifact_registry_repository_with_mutable_tags_is_detected(self) -> None:
        findings = _evaluate(
            [_cloud_run_service(), _artifact_registry_repository()],
            _MUTABLE_TAG_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_MUTABLE_TAG_RULE])
        self.assertEqual(
            findings[0].affected_resources,
            ["google_cloud_run_v2_service.api", "google_artifact_registry_repository.images"],
        )
        evidence = _evidence(findings[0])
        self.assertIn("artifact_registry_repository_path=" + _REPOSITORY_PATH, evidence["image_reference"])
        self.assertEqual(
            evidence["artifact_registry_repository"],
            [
                "address=google_artifact_registry_repository.images",
                f"repository_path={_REPOSITORY_PATH}",
                "format=DOCKER",
                "docker_immutable_tags_state=disabled",
                "docker_immutable_tags=false",
            ],
        )

    def test_immutable_or_unmatched_artifact_registry_repository_is_quiet(self) -> None:
        self.assertEqual(
            _evaluate(
                [_cloud_run_service(), _artifact_registry_repository(immutable_tags=True)],
                _MUTABLE_TAG_RULE,
            ),
            [],
        )
        self.assertEqual(
            _evaluate(
                [_cloud_run_service(), _artifact_registry_repository(repository_id="other")],
                _MUTABLE_TAG_RULE,
            ),
            [],
        )

    def test_non_artifact_registry_image_only_uses_digest_pin_rule(self) -> None:
        findings = _evaluate(
            [_cloud_run_service("gcr.io/tfstride-demo/api:stable")],
            *_RULE_IDS,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_IMAGE_RULE])


if __name__ == "__main__":
    unittest.main()
