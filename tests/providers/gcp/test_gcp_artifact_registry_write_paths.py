from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_REPOSITORY_ADDRESS = "google_artifact_registry_repository.images"
_REPOSITORY_PATH = "projects/tfstride-demo/locations/us-central1/repositories/images"
_SERVICE_ACCOUNT_EMAIL = "tfstride-api@tfstride-demo.iam.gserviceaccount.com"
_SERVICE_ACCOUNT_MEMBER = f"serviceAccount:{_SERVICE_ACCOUNT_EMAIL}"
_IMAGE = "us-central1-docker.pkg.dev/tfstride-demo/images/api:stable"


def _repository() -> object:
    return _terraform_resource(
        _REPOSITORY_ADDRESS,
        GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY,
        {
            "project": "tfstride-demo",
            "location": "us-central1",
            "repository_id": "images",
            "format": "DOCKER",
        },
    )


def _cloud_run(*, service_account: str | None = _SERVICE_ACCOUNT_EMAIL, unknown_values=None) -> object:
    template = {
        "containers": [
            {
                "image": _IMAGE,
            }
        ]
    }
    if service_account is not None:
        template["service_account"] = service_account
    return _terraform_resource(
        "google_cloud_run_v2_service.api",
        GcpResourceType.CLOUD_RUN_V2_SERVICE,
        {
            "name": "api",
            "location": "us-central1",
            "template": [template],
        },
        unknown_values=unknown_values,
    )


def _repository_iam_member(
    *,
    role: str = "roles/artifactregistry.writer",
    member: str = _SERVICE_ACCOUNT_MEMBER,
    repository: str = f"{_REPOSITORY_ADDRESS}.id",
    condition: list[dict[str, str]] | None = None,
) -> object:
    values = {
        "repository": repository,
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


def _normalize(resources: list[object]):
    return GcpNormalizer().normalize(resources)


class GcpArtifactRegistryWritePathTests(unittest.TestCase):
    def test_cloud_run_service_account_writer_assignment_is_modeled(self) -> None:
        inventory = _normalize([_repository(), _cloud_run(), _repository_iam_member()])
        workload = inventory.get_by_address("google_cloud_run_v2_service.api")

        self.assertIsNotNone(workload)
        assert workload is not None
        facts = gcp_facts(workload)
        self.assertEqual(len(facts.artifact_registry_write_paths), 1)
        self.assertEqual(
            facts.artifact_registry_write_paths[0],
            {
                "workload_address": "google_cloud_run_v2_service.api",
                "workload_type": "google_cloud_run_v2_service",
                "service_account_email": _SERVICE_ACCOUNT_EMAIL,
                "service_account_member": _SERVICE_ACCOUNT_MEMBER,
                "image_reference": _IMAGE,
                "image_reference_path": "template[0].containers[0].image",
                "image_tag": "stable",
                "image_digest": None,
                "image_digest_pinned": False,
                "artifact_registry_repository_address": _REPOSITORY_ADDRESS,
                "artifact_registry_repository_path": _REPOSITORY_PATH,
                "iam_resource_address": "google_artifact_registry_repository_iam_member.assignment",
                "role": "roles/artifactregistry.writer",
                "role_kind": "writer",
                "grant_basis": "artifact_registry_repository_iam",
                "repository_scope": "exact_repository_path",
            },
        )
        self.assertEqual(facts.artifact_registry_write_path_uncertainties, [])

    def test_cloud_run_admin_assignment_is_modeled_as_admin(self) -> None:
        inventory = _normalize(
            [
                _repository(),
                _cloud_run(),
                _repository_iam_member(role="roles/artifactregistry.admin"),
            ]
        )
        workload = inventory.get_by_address("google_cloud_run_v2_service.api")

        self.assertIsNotNone(workload)
        assert workload is not None
        paths = gcp_facts(workload).artifact_registry_write_paths
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["role_kind"], "admin")
        self.assertEqual(paths[0]["role"], "roles/artifactregistry.admin")

    def test_nonmatching_service_account_or_repository_does_not_create_path(self) -> None:
        inventory = _normalize(
            [
                _repository(),
                _cloud_run(),
                _repository_iam_member(member="serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"),
                _repository_iam_member(
                    repository="google_artifact_registry_repository.other.id",
                    member=_SERVICE_ACCOUNT_MEMBER,
                ),
            ]
        )
        workload = inventory.get_by_address("google_cloud_run_v2_service.api")

        self.assertIsNotNone(workload)
        assert workload is not None
        self.assertEqual(gcp_facts(workload).artifact_registry_write_paths, [])

    def test_name_only_repository_reference_does_not_match_exact_repository_path(self) -> None:
        inventory = _normalize(
            [
                _repository(),
                _cloud_run(),
                _repository_iam_member(repository="images"),
            ]
        )
        workload = inventory.get_by_address("google_cloud_run_v2_service.api")

        self.assertIsNotNone(workload)
        assert workload is not None
        self.assertEqual(gcp_facts(workload).artifact_registry_write_paths, [])

    def test_conditional_writer_assignment_is_retained_as_uncertainty(self) -> None:
        inventory = _normalize(
            [
                _repository(),
                _cloud_run(),
                _repository_iam_member(
                    condition=[
                        {"title": "release-window", "expression": "request.time < timestamp('2027-01-01T00:00:00Z')"}
                    ]
                ),
            ]
        )
        workload = inventory.get_by_address("google_cloud_run_v2_service.api")

        self.assertIsNotNone(workload)
        assert workload is not None
        facts = gcp_facts(workload)
        self.assertEqual(facts.artifact_registry_write_paths, [])
        self.assertTrue(
            any(
                "conditional roles/artifactregistry.writer grant was not treated as deterministic" in uncertainty
                for uncertainty in facts.artifact_registry_write_path_uncertainties
            )
        )

    def test_unresolved_service_account_is_retained_as_uncertainty(self) -> None:
        inventory = _normalize(
            [
                _repository(),
                _cloud_run(
                    service_account=None,
                    unknown_values={"template": [{"service_account": True}]},
                ),
                _repository_iam_member(),
            ]
        )
        workload = inventory.get_by_address("google_cloud_run_v2_service.api")

        self.assertIsNotNone(workload)
        assert workload is not None
        facts = gcp_facts(workload)
        self.assertEqual(facts.artifact_registry_write_paths, [])
        self.assertEqual(
            facts.artifact_registry_write_path_uncertainties,
            ["google_cloud_run_v2_service.api: Cloud Run service account is unresolved"],
        )

    def test_unresolved_repository_assignment_is_retained_as_uncertainty(self) -> None:
        iam_resource = _terraform_resource(
            "google_artifact_registry_repository_iam_member.unknown",
            GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY_IAM_MEMBER,
            {
                "role": "roles/artifactregistry.writer",
                "member": _SERVICE_ACCOUNT_MEMBER,
            },
            unknown_values={"repository": True},
        )
        inventory = _normalize([_repository(), _cloud_run(), iam_resource])
        workload = inventory.get_by_address("google_cloud_run_v2_service.api")

        self.assertIsNotNone(workload)
        assert workload is not None
        facts = gcp_facts(workload)
        self.assertEqual(facts.artifact_registry_write_paths, [])
        self.assertIn(
            "google_cloud_run_v2_service.api: google_artifact_registry_repository_iam_member.unknown: repository is unknown after planning",
            facts.artifact_registry_write_path_uncertainties,
        )

    def test_unmodeled_repository_path_is_retained_as_uncertainty(self) -> None:
        inventory = _normalize(
            [
                _cloud_run(),
                _repository_iam_member(),
            ]
        )
        workload = inventory.get_by_address("google_cloud_run_v2_service.api")

        self.assertIsNotNone(workload)
        assert workload is not None
        self.assertEqual(
            gcp_facts(workload).artifact_registry_write_path_uncertainties,
            [f"google_cloud_run_v2_service.api: Artifact Registry repository path {_REPOSITORY_PATH} is not modeled"],
        )
