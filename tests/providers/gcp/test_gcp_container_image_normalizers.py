from __future__ import annotations

import unittest
from typing import Any

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.providers.gcp.artifact_registry_normalizers import normalize_artifact_registry_repository
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.serverless_normalizers import (
    normalize_cloud_run_service,
    normalize_cloud_run_v2_service,
    normalize_cloudfunctions2_function,
)

_ARTIFACT_IMAGE = "us-central1-docker.pkg.dev/tfstride-demo/images/api:stable"
_ARTIFACT_PATH = "projects/tfstride-demo/locations/us-central1/repositories/images"


def _cloud_run_v1(
    image: object,
    *,
    unknown_values: dict[str, Any] | None = None,
):
    return _terraform_resource(
        "google_cloud_run_service.api",
        "google_cloud_run_service",
        {
            "name": "api",
            "project": "tfstride-demo",
            "location": "us-central1",
            "template": [{"spec": [{"containers": [{"image": image}]}]}],
        },
        unknown_values=unknown_values,
    )


def _cloud_run_v2(
    image: object | None = _ARTIFACT_IMAGE,
    *,
    unknown_values: dict[str, Any] | None = None,
):
    values: dict[str, Any] = {
        "name": "api",
        "project": "tfstride-demo",
        "location": "us-central1",
        "template": [{"containers": [{"image": image}]}],
    }
    if image is None:
        values["template"] = [{}]
    return _terraform_resource(
        "google_cloud_run_v2_service.api",
        "google_cloud_run_v2_service",
        values,
        unknown_values=unknown_values,
    )


def _artifact_repository(
    *,
    unknown_values: dict[str, Any] | None = None,
):
    return _terraform_resource(
        "google_artifact_registry_repository.images",
        "google_artifact_registry_repository",
        {
            "id": _ARTIFACT_PATH,
            "name": _ARTIFACT_PATH,
            "project": "tfstride-demo",
            "location": "us-central1",
            "repository_id": "images",
            "format": "DOCKER",
        },
        unknown_values=unknown_values,
    )


def _reference_evidence(reference: dict[str, Any]) -> dict[str, Any]:
    return reference


class GcpContainerImageNormalizerTests(unittest.TestCase):
    def test_cloud_run_v1_and_v2_normalize_artifact_registry_image_paths(self) -> None:
        v1 = gcp_facts(normalize_cloud_run_service(_cloud_run_v1(_ARTIFACT_IMAGE)))
        v2 = gcp_facts(normalize_cloud_run_v2_service(_cloud_run_v2()))

        for facts, path in (
            (v1, "template[0].spec[0].containers[0].image"),
            (v2, "template[0].containers[0].image"),
        ):
            with self.subTest(path=path):
                self.assertEqual(len(facts.container_image_references), 1)
                reference = _reference_evidence(facts.container_image_references[0])
                self.assertEqual(reference["source"], facts.resource.resource_type)
                self.assertEqual(reference["path"], path)
                self.assertEqual(reference["raw"], _ARTIFACT_IMAGE)
                self.assertEqual(reference["registry_host"], "us-central1-docker.pkg.dev")
                self.assertEqual(reference["repository"], "tfstride-demo/images/api")
                self.assertEqual(reference["tag"], "stable")
                self.assertIsNone(reference["digest"])
                self.assertFalse(reference["digest_pinned"])
                self.assertTrue(reference["is_resolved"])
                self.assertEqual(reference["artifact_registry_location"], "us-central1")
                self.assertEqual(reference["artifact_registry_project"], "tfstride-demo")
                self.assertEqual(reference["artifact_registry_repository_id"], "images")
                self.assertEqual(reference["artifact_registry_image_path"], "api")
                self.assertEqual(reference["artifact_registry_repository_path"], _ARTIFACT_PATH)
                self.assertEqual(facts.container_image_posture_uncertainties, [])

    def test_non_artifact_registry_and_digest_pinned_images_remain_syntax_only(self) -> None:
        digest = "sha256:" + "c" * 64
        facts = gcp_facts(normalize_cloud_run_v2_service(_cloud_run_v2(f"gcr.io/tfstride-demo/api@{digest}")))
        reference = facts.container_image_references[0]

        self.assertEqual(reference["registry_host"], "gcr.io")
        self.assertEqual(reference["repository"], "tfstride-demo/api")
        self.assertEqual(reference["digest"], digest)
        self.assertTrue(reference["digest_pinned"])
        self.assertNotIn("artifact_registry_repository_path", reference)
        self.assertEqual(facts.container_image_posture_uncertainties, [])

    def test_unknown_and_unresolved_cloud_run_images_are_preserved(self) -> None:
        unknown = gcp_facts(normalize_cloud_run_v2_service(_cloud_run_v2(None, unknown_values={"template": True})))
        self.assertEqual(unknown.container_image_references, [])
        self.assertEqual(
            unknown.container_image_posture_uncertainties,
            ["template[0].containers is unknown after planning"],
        )

        unresolved = gcp_facts(normalize_cloud_run_service(_cloud_run_v1("${var.image}")))
        self.assertEqual(unresolved.container_image_references[0]["raw"], "${var.image}")
        self.assertFalse(unresolved.container_image_references[0]["is_resolved"])
        self.assertEqual(
            unresolved.container_image_references[0]["unresolved_reason"],
            "image reference is unresolved",
        )
        self.assertEqual(
            unresolved.container_image_posture_uncertainties,
            ["template[0].spec[0].containers[0].image: image reference is unresolved"],
        )

    def test_artifact_registry_repository_preserves_exact_project_location_path(self) -> None:
        facts = gcp_facts(normalize_artifact_registry_repository(_artifact_repository()))

        self.assertEqual(facts.artifact_registry_repository_id, "images")
        self.assertEqual(facts.artifact_registry_repository_path, _ARTIFACT_PATH)

    def test_cloud_functions_do_not_claim_a_deployed_image_from_build_fields(self) -> None:
        facts = gcp_facts(
            normalize_cloudfunctions2_function(
                _terraform_resource(
                    "google_cloudfunctions2_function.worker",
                    "google_cloudfunctions2_function",
                    {
                        "name": "worker",
                        "location": "us-central1",
                        "build_config": [{"runtime": "python312", "entry_point": "handler"}],
                        "service_config": [{"uri": "https://worker.run.app"}],
                    },
                )
            )
        )

        self.assertEqual(facts.container_image_references, [])
        self.assertEqual(facts.container_image_posture_uncertainties, [])


if __name__ == "__main__":
    unittest.main()
