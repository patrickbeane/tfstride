from __future__ import annotations

import unittest

from tfstride.models import TerraformResource
from tfstride.providers.azure.app_service_normalizers import (
    normalize_function_app,
    normalize_linux_function_app,
    normalize_linux_web_app,
    normalize_windows_function_app,
    normalize_windows_web_app,
)
from tfstride.providers.azure.container_registry_normalizers import normalize_container_registry
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_DIGEST = "sha256:" + "a" * 64


def _resource(
    resource_type: str,
    values: dict[str, object],
    *,
    name: str = "app",
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values=values,
        unknown_values=unknown_values or {},
    )


class AzureContainerImageNormalizerTests(unittest.TestCase):
    def test_linux_and_windows_web_apps_normalize_explicit_container_images(self) -> None:
        for resource_type, normalizer in (
            (AzureResourceType.LINUX_WEB_APP, normalize_linux_web_app),
            (AzureResourceType.WINDOWS_WEB_APP, normalize_windows_web_app),
        ):
            with self.subTest(resource_type=resource_type):
                facts = azure_facts(
                    normalizer(
                        _resource(
                            resource_type,
                            {
                                "name": "api",
                                "site_config": [
                                    {
                                        "application_stack": [
                                            {
                                                "docker_image_name": "team/api:stable",
                                                "docker_registry_url": "HTTPS://Images.AzureCR.IO/",
                                            }
                                        ]
                                    }
                                ],
                            },
                            name="api",
                        )
                    )
                )

                self.assertEqual(
                    facts.container_image_references,
                    [
                        {
                            "source": resource_type,
                            "path": "site_config.application_stack[0].docker_image_name",
                            "raw": "images.azurecr.io/team/api:stable",
                            "registry_host": "images.azurecr.io",
                            "repository": "team/api",
                            "tag": "stable",
                            "digest": None,
                            "digest_pinned": False,
                            "is_resolved": True,
                            "docker_image_name": "team/api:stable",
                            "docker_registry_url": "HTTPS://Images.AzureCR.IO/",
                            "container_registry_login_server": "images.azurecr.io",
                        }
                    ],
                )
                self.assertEqual(facts.container_image_posture_uncertainties, [])

    def test_linux_function_app_normalizes_nested_docker_configuration(self) -> None:
        facts = azure_facts(
            normalize_linux_function_app(
                _resource(
                    AzureResourceType.LINUX_FUNCTION_APP,
                    {
                        "name": "worker",
                        "site_config": [
                            {
                                "application_stack": [
                                    {
                                        "docker": [
                                            {
                                                "registry_url": "https://images.azurecr.io",
                                                "image_name": "jobs/worker",
                                                "image_tag": "2026.07",
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                    },
                    name="worker",
                )
            )
        )

        reference = facts.container_image_references[0]
        self.assertEqual(reference["raw"], "images.azurecr.io/jobs/worker:2026.07")
        self.assertEqual(reference["registry_host"], "images.azurecr.io")
        self.assertEqual(reference["repository"], "jobs/worker")
        self.assertEqual(reference["tag"], "2026.07")
        self.assertFalse(reference["digest_pinned"])
        self.assertTrue(reference["is_resolved"])
        self.assertEqual(reference["container_registry_login_server"], "images.azurecr.io")
        self.assertEqual(
            reference["path"],
            "site_config.application_stack[0].docker[0].image_name",
        )
        self.assertEqual(facts.container_image_posture_uncertainties, [])

    def test_legacy_function_app_normalizes_docker_linux_fx_version(self) -> None:
        facts = azure_facts(
            normalize_function_app(
                _resource(
                    AzureResourceType.FUNCTION_APP,
                    {
                        "name": "legacy",
                        "site_config": [{"linux_fx_version": (f"DOCKER|images.azurecr.io/functions/legacy@{_DIGEST}")}],
                    },
                    name="legacy",
                )
            )
        )

        reference = facts.container_image_references[0]
        self.assertEqual(reference["raw"], f"images.azurecr.io/functions/legacy@{_DIGEST}")
        self.assertEqual(reference["registry_host"], "images.azurecr.io")
        self.assertEqual(reference["repository"], "functions/legacy")
        self.assertEqual(reference["digest"], _DIGEST)
        self.assertTrue(reference["digest_pinned"])
        self.assertTrue(reference["is_resolved"])
        self.assertEqual(reference["container_registry_login_server"], "images.azurecr.io")
        self.assertEqual(
            reference["linux_fx_version"],
            f"DOCKER|images.azurecr.io/functions/legacy@{_DIGEST}",
        )
        self.assertEqual(facts.container_image_posture_uncertainties, [])

    def test_windows_function_and_non_container_legacy_runtime_are_quiet(self) -> None:
        windows = azure_facts(
            normalize_windows_function_app(
                _resource(
                    AzureResourceType.WINDOWS_FUNCTION_APP,
                    {
                        "name": "timer",
                        "site_config": [{"application_stack": [{"dotnet_version": "v8.0"}]}],
                    },
                    name="timer",
                )
            )
        )
        legacy = azure_facts(
            normalize_function_app(
                _resource(
                    AzureResourceType.FUNCTION_APP,
                    {
                        "name": "python",
                        "site_config": [{"linux_fx_version": "PYTHON|3.12"}],
                    },
                    name="python",
                )
            )
        )

        self.assertEqual(windows.container_image_references, [])
        self.assertEqual(windows.container_image_posture_uncertainties, [])
        self.assertEqual(legacy.container_image_references, [])
        self.assertEqual(legacy.container_image_posture_uncertainties, [])

    def test_computed_image_and_registry_values_remain_unresolved(self) -> None:
        image_unknown = azure_facts(
            normalize_linux_web_app(
                _resource(
                    AzureResourceType.LINUX_WEB_APP,
                    {
                        "name": "pending-image",
                        "site_config": [
                            {
                                "application_stack": [
                                    {
                                        "docker_image_name": None,
                                        "docker_registry_url": "https://images.azurecr.io",
                                    }
                                ]
                            }
                        ],
                    },
                    name="pending_image",
                    unknown_values={
                        "site_config": [
                            {
                                "application_stack": [
                                    {
                                        "docker_image_name": True,
                                    }
                                ]
                            }
                        ]
                    },
                )
            )
        )
        registry_unknown = azure_facts(
            normalize_linux_web_app(
                _resource(
                    AzureResourceType.LINUX_WEB_APP,
                    {
                        "name": "pending-registry",
                        "site_config": [
                            {
                                "application_stack": [
                                    {
                                        "docker_image_name": "team/api:stable",
                                        "docker_registry_url": None,
                                    }
                                ]
                            }
                        ],
                    },
                    name="pending_registry",
                    unknown_values={
                        "site_config": [
                            {
                                "application_stack": [
                                    {
                                        "docker_registry_url": True,
                                    }
                                ]
                            }
                        ]
                    },
                )
            )
        )

        image_reference = image_unknown.container_image_references[0]
        self.assertFalse(image_reference["is_resolved"])
        self.assertEqual(image_reference["unresolved_reason"], "docker image name is unknown after planning")
        self.assertNotIn("container_registry_login_server", image_reference)
        self.assertEqual(
            image_unknown.container_image_posture_uncertainties,
            ["site_config.application_stack[0].docker_image_name is unknown after planning"],
        )

        registry_reference = registry_unknown.container_image_references[0]
        self.assertFalse(registry_reference["is_resolved"])
        self.assertNotIn("container_registry_login_server", registry_reference)
        self.assertEqual(
            registry_reference["unresolved_reason"],
            "container registry URL is unknown after planning",
        )
        self.assertEqual(
            registry_unknown.container_image_posture_uncertainties,
            ["site_config.application_stack[0].docker_registry_url is unknown after planning"],
        )

    def test_explicit_image_host_must_match_configured_registry_url(self) -> None:
        facts = azure_facts(
            normalize_linux_web_app(
                _resource(
                    AzureResourceType.LINUX_WEB_APP,
                    {
                        "name": "mismatch",
                        "site_config": [
                            {
                                "application_stack": [
                                    {
                                        "docker_image_name": "other.azurecr.io/team/api:stable",
                                        "docker_registry_url": "https://images.azurecr.io",
                                    }
                                ]
                            }
                        ],
                    },
                    name="mismatch",
                )
            )
        )

        reference = facts.container_image_references[0]
        self.assertEqual(reference["registry_host"], "other.azurecr.io")
        self.assertNotIn("container_registry_login_server", reference)
        self.assertFalse(reference["is_resolved"])
        self.assertEqual(
            reference["unresolved_reason"],
            "image registry host does not match configured registry URL",
        )
        self.assertEqual(
            facts.container_image_posture_uncertainties,
            [
                "site_config.application_stack[0].docker_image_name: "
                "image registry host does not match configured registry URL"
            ],
        )

    def test_container_registry_login_server_is_normalized_for_exact_matching(self) -> None:
        facts = azure_facts(
            normalize_container_registry(
                _resource(
                    AzureResourceType.CONTAINER_REGISTRY,
                    {
                        "id": "/subscriptions/example/resourceGroups/app/providers/"
                        "Microsoft.ContainerRegistry/registries/images",
                        "name": "images",
                        "sku": "Premium",
                        "login_server": "HTTPS://Images.AzureCR.IO/",
                    },
                    name="images",
                )
            )
        )

        self.assertEqual(facts.name, "images")
        self.assertEqual(facts.container_registry_login_server, "images.azurecr.io")
        self.assertNotEqual(facts.container_registry_login_server, facts.name)

    def test_unresolved_container_registry_login_server_is_not_treated_as_a_name(self) -> None:
        facts = azure_facts(
            normalize_container_registry(
                _resource(
                    AzureResourceType.CONTAINER_REGISTRY,
                    {
                        "name": "images",
                        "sku": "Premium",
                        "login_server": "$" + "{azurerm_container_registry.images.login_server}",
                    },
                    name="images",
                )
            )
        )

        self.assertIsNone(facts.container_registry_login_server)
        self.assertIn("login_server is unresolved", facts.container_registry_posture_uncertainties)


if __name__ == "__main__":
    unittest.main()
