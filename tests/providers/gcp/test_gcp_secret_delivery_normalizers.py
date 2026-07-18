from __future__ import annotations

import unittest
from typing import Any

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.serverless_normalizers import (
    normalize_cloud_run_service,
    normalize_cloud_run_v2_service,
)


def _v1_service(
    env: list[dict[str, Any]],
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
            "template": [{"spec": [{"containers": [{"name": "api", "env": env}]}]}],
        },
        unknown_values=unknown_values,
    )


def _v2_service(
    env: list[dict[str, Any]],
    *,
    unknown_values: dict[str, Any] | None = None,
):
    return _terraform_resource(
        "google_cloud_run_v2_service.api",
        "google_cloud_run_v2_service",
        {
            "name": "api",
            "project": "tfstride-demo",
            "location": "us-central1",
            "template": [{"containers": [{"name": "api", "env": env}]}],
        },
        unknown_values=unknown_values,
    )


class GcpCloudRunSecretDeliveryNormalizerTests(unittest.TestCase):
    def test_v1_secret_manager_reference_preserves_name_and_version_evidence(self) -> None:
        normalized = normalize_cloud_run_service(
            _v1_service(
                [
                    {
                        "name": "DB_PASSWORD",
                        "value_from": [
                            {
                                "secret_key_ref": [
                                    {
                                        "name": "projects/tfstride-demo/secrets/orders-db",
                                        "key": "5",
                                    }
                                ]
                            }
                        ],
                    }
                ]
            )
        )

        reference = gcp_facts(normalized).cloud_run_secret_references[0]
        self.assertEqual(reference["state"], "reference")
        self.assertEqual(reference["reference_kind"], "secret_manager")
        self.assertEqual(reference["target_resolution"], "resolved")
        self.assertEqual(reference["setting_name"], "DB_PASSWORD")
        self.assertEqual(reference["secret_name"], "projects/tfstride-demo/secrets/orders-db")
        self.assertEqual(reference["secret_version"], "5")
        self.assertEqual(reference["version"], "5")
        self.assertEqual(reference["secret_version_state"], "configured")
        self.assertEqual(reference["path"], "template[0].spec[0].containers[0].env[0]")
        self.assertEqual(
            reference["secret_reference_path"],
            "template[0].spec[0].containers[0].env[0].value_from[0].secret_key_ref.name",
        )
        self.assertEqual(gcp_facts(normalized).cloud_run_secret_posture_uncertainties, [])

    def test_v2_secret_manager_reference_preserves_version_evidence(self) -> None:
        normalized = normalize_cloud_run_v2_service(
            _v2_service(
                [
                    {
                        "name": "API_KEY",
                        "value_source": [
                            {
                                "secret_key_ref": [
                                    {
                                        "secret": "projects/tfstride-demo/secrets/api-key",
                                        "version": "latest",
                                    }
                                ]
                            }
                        ],
                    }
                ]
            )
        )

        reference = gcp_facts(normalized).cloud_run_secret_references[0]
        self.assertEqual(reference["reference_kind"], "secret_manager")
        self.assertEqual(reference["secret_reference"], "projects/tfstride-demo/secrets/api-key")
        self.assertEqual(reference["secret_version"], "latest")
        self.assertEqual(
            reference["version_path"], "template[0].containers[0].env[0].value_source[0].secret_key_ref.version"
        )
        self.assertTrue(reference["is_resolved"])

    def test_sensitive_literal_is_recorded_without_preserving_value(self) -> None:
        literal = "never-store-this-password"
        normalized = normalize_cloud_run_v2_service(
            _v2_service(
                [
                    {"name": "DB_PASSWORD", "value": literal},
                    {"name": "LOG_LEVEL", "value": "info"},
                ]
            )
        )

        references = gcp_facts(normalized).cloud_run_secret_references
        self.assertEqual(len(references), 1)
        self.assertEqual(references[0]["state"], "literal")
        self.assertEqual(references[0]["normalized_setting_name"], "db_password")
        self.assertNotIn(literal, repr(references))

    def test_unresolved_reference_and_unknown_version_are_explicit(self) -> None:
        normalized = normalize_cloud_run_v2_service(
            _v2_service(
                [
                    {
                        "name": "DB_PASSWORD",
                        "value_source": [
                            {
                                "secret_key_ref": [
                                    {
                                        "secret": "$" + "{google_secret_manager_secret.db.id}",
                                        "version": "latest",
                                    }
                                ]
                            }
                        ],
                    },
                    {
                        "name": "API_TOKEN",
                        "value_source": [
                            {
                                "secret_key_ref": [
                                    {
                                        "secret": "projects/tfstride-demo/secrets/api-token",
                                        "version": "computed",
                                    }
                                ]
                            }
                        ],
                    },
                ],
                unknown_values={
                    "template": [
                        {
                            "containers": [
                                {
                                    "env": [
                                        {},
                                        {
                                            "value_source": [
                                                {
                                                    "secret_key_ref": [
                                                        {
                                                            "version": True,
                                                        }
                                                    ]
                                                }
                                            ]
                                        },
                                    ]
                                }
                            ]
                        }
                    ]
                },
            )
        )

        references = gcp_facts(normalized).cloud_run_secret_references
        self.assertEqual([reference["state"] for reference in references], ["reference", "reference"])
        self.assertEqual(references[0]["target_resolution"], "unresolved")
        self.assertEqual(references[0]["unresolved_reference"], "$" + "{google_secret_manager_secret.db.id}")
        self.assertEqual(references[0]["secret_version_state"], "configured")
        self.assertEqual(references[1]["secret_version_state"], "unknown")
        self.assertTrue(
            any(
                "version is unknown after planning" in uncertainty
                for uncertainty in gcp_facts(normalized).cloud_run_secret_posture_uncertainties
            )
        )

    def test_unknown_literal_and_unknown_source_are_preserved_without_values(self) -> None:
        normalized = normalize_cloud_run_service(
            _v1_service(
                [
                    {"name": "API_KEY", "value": "computed"},
                    {"name": "DB_PASSWORD", "value_from": [{"secret_key_ref": [{"name": "computed"}]}]},
                ],
                unknown_values={
                    "template": [
                        {
                            "spec": [
                                {
                                    "containers": [
                                        {
                                            "env": [
                                                {"value": True},
                                                {"value_from": [{"secret_key_ref": [{"name": True}]}]},
                                            ]
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                },
            )
        )

        references = gcp_facts(normalized).cloud_run_secret_references
        self.assertEqual([reference["state"] for reference in references], ["unknown", "unknown"])
        self.assertTrue(all("value" not in reference for reference in references))
        self.assertTrue(all("computed" not in repr(reference) for reference in references))
        self.assertTrue(gcp_facts(normalized).cloud_run_secret_posture_uncertainties)

    def test_unknown_container_environment_is_explicit(self) -> None:
        normalized = normalize_cloud_run_v2_service(
            _v2_service(
                [],
                unknown_values={"template": [{"containers": [{"env": True}]}]},
            )
        )

        references = gcp_facts(normalized).cloud_run_secret_references
        self.assertEqual(references[0]["state"], "unknown")
        self.assertIn("env is unknown after planning", references[0]["unresolved_reason"])


if __name__ == "__main__":
    unittest.main()
