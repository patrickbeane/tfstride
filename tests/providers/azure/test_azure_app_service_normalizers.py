from __future__ import annotations

import unittest

from tfstride.models import ResourceCategory, TerraformResource
from tfstride.providers.azure.app_service_normalizers import (
    normalize_function_app,
    normalize_linux_function_app,
    normalize_linux_web_app,
    normalize_windows_function_app,
    normalize_windows_web_app,
)
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType


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


class AzureAppServiceNormalizerTests(unittest.TestCase):
    def test_linux_web_app_normalizes_site_config_public_network_and_system_identity(self) -> None:
        web_app = normalize_linux_web_app(
            _resource(
                AzureResourceType.LINUX_WEB_APP,
                {
                    "id": "/subscriptions/example/resourceGroups/app/providers/Microsoft.Web/sites/api",
                    "name": "api",
                    "location": "eastus",
                    "service_plan_id": "azurerm_service_plan.apps.id",
                    "virtual_network_subnet_id": "azurerm_subnet.integration.id",
                    "public_network_access_enabled": True,
                    "site_config": [{"minimum_tls_version": "1.2", "ftps_state": "FtpsOnly"}],
                    "identity": [
                        {
                            "type": "SystemAssigned",
                            "principal_id": "principal-id",
                            "tenant_id": "tenant-id",
                            "identity_ids": [],
                        }
                    ],
                },
                name="api",
            )
        )
        facts = azure_facts(web_app)

        self.assertEqual(web_app.category, ResourceCategory.COMPUTE)
        self.assertEqual(
            web_app.identifier, "/subscriptions/example/resourceGroups/app/providers/Microsoft.Web/sites/api"
        )
        self.assertTrue(web_app.public_access_configured)
        self.assertFalse(web_app.public_exposure)
        self.assertFalse(web_app.direct_internet_reachable)
        self.assertEqual(facts.name, "api")
        self.assertEqual(
            facts.app_service_id, "/subscriptions/example/resourceGroups/app/providers/Microsoft.Web/sites/api"
        )
        self.assertEqual(facts.app_service_plan_reference, "azurerm_service_plan.apps.id")
        self.assertEqual(facts.app_service_vnet_integration_subnet_id, "azurerm_subnet.integration.id")
        self.assertEqual(facts.os_type, "linux")
        self.assertTrue(facts.public_network_access_enabled)
        self.assertEqual(facts.public_network_fallback_state, "enabled")
        self.assertEqual(facts.min_tls_version, "1.2")
        self.assertEqual(facts.ftps_state, "FtpsOnly")
        self.assertTrue(facts.has_system_assigned_identity)
        self.assertFalse(facts.has_user_assigned_identity)
        self.assertEqual(facts.principal_id, "principal-id")
        self.assertEqual(facts.tenant_id, "tenant-id")
        self.assertEqual(facts.app_service_posture_uncertainties, [])
        self.assertEqual(facts.managed_identity_uncertainties, [])

    def test_windows_web_app_normalizes_disabled_public_network_and_user_identity(self) -> None:
        web_app = normalize_windows_web_app(
            _resource(
                AzureResourceType.WINDOWS_WEB_APP,
                {
                    "id": "/subscriptions/example/resourceGroups/app/providers/Microsoft.Web/sites/admin",
                    "name": "admin",
                    "location": "eastus",
                    "service_plan_id": "azurerm_service_plan.apps.id",
                    "public_network_access_enabled": False,
                    "site_config": [{"minimum_tls_version": "1.3", "ftps_state": "Disabled"}],
                    "identity": [
                        {
                            "type": "SystemAssigned, UserAssigned",
                            "principal_id": None,
                            "tenant_id": None,
                            "identity_ids": ["azurerm_user_assigned_identity.runtime.id"],
                        }
                    ],
                },
                name="admin",
                unknown_values={"identity": [{"principal_id": True, "tenant_id": True}]},
            )
        )
        facts = azure_facts(web_app)

        self.assertEqual(facts.os_type, "windows")
        self.assertFalse(web_app.public_access_configured)
        self.assertFalse(facts.public_network_access_enabled)
        self.assertEqual(facts.public_network_fallback_state, "disabled")
        self.assertEqual(facts.min_tls_version, "1.3")
        self.assertEqual(facts.ftps_state, "Disabled")
        self.assertTrue(facts.has_system_assigned_identity)
        self.assertTrue(facts.has_user_assigned_identity)
        self.assertEqual(facts.attached_identity_references, ["azurerm_user_assigned_identity.runtime.id"])
        self.assertEqual(
            facts.managed_identity_uncertainties,
            ["identity.principal_id is unknown after planning", "identity.tenant_id is unknown after planning"],
        )

    def test_function_app_variants_normalize_plan_references_and_tls_fields(self) -> None:
        legacy = normalize_function_app(
            _resource(
                AzureResourceType.FUNCTION_APP,
                {
                    "id": "/subscriptions/example/resourceGroups/app/providers/Microsoft.Web/sites/jobs",
                    "name": "jobs",
                    "app_service_plan_id": "azurerm_app_service_plan.legacy.id",
                    "site_config": [{"min_tls_version": "1.2"}],
                },
                name="jobs",
            )
        )
        linux = normalize_linux_function_app(
            _resource(
                AzureResourceType.LINUX_FUNCTION_APP,
                {
                    "name": "worker",
                    "service_plan_id": "azurerm_service_plan.functions.id",
                    "site_config": [{"minimum_tls_version": "1.2", "ftps_state": "Disabled"}],
                },
                name="worker",
            )
        )
        windows = normalize_windows_function_app(
            _resource(
                AzureResourceType.WINDOWS_FUNCTION_APP,
                {
                    "name": "timer",
                    "server_farm_id": "azurerm_service_plan.windows_functions.id",
                    "site_config": [{"minimum_tls_version": "1.2"}],
                },
                name="timer",
            )
        )

        self.assertEqual(azure_facts(legacy).app_service_plan_reference, "azurerm_app_service_plan.legacy.id")
        self.assertEqual(azure_facts(legacy).min_tls_version, "1.2")
        self.assertIsNone(azure_facts(legacy).os_type)
        self.assertEqual(azure_facts(linux).app_service_plan_reference, "azurerm_service_plan.functions.id")
        self.assertEqual(azure_facts(linux).os_type, "linux")
        self.assertEqual(azure_facts(linux).ftps_state, "Disabled")
        self.assertEqual(azure_facts(windows).app_service_plan_reference, "azurerm_service_plan.windows_functions.id")
        self.assertEqual(azure_facts(windows).os_type, "windows")

    def test_unknown_app_service_values_are_explicit_uncertainties(self) -> None:
        web_app = normalize_linux_web_app(
            _resource(
                AzureResourceType.LINUX_WEB_APP,
                {
                    "id": None,
                    "name": "pending",
                    "service_plan_id": None,
                    "virtual_network_subnet_id": None,
                    "public_network_access_enabled": None,
                    "site_config": [{"minimum_tls_version": None, "ftps_state": None}],
                    "identity": None,
                },
                name="pending",
                unknown_values={
                    "id": True,
                    "service_plan_id": True,
                    "virtual_network_subnet_id": True,
                    "public_network_access_enabled": True,
                    "site_config": [{"minimum_tls_version": True, "ftps_state": True}],
                    "identity": True,
                },
            )
        )
        facts = azure_facts(web_app)

        self.assertEqual(web_app.identifier, "pending")
        self.assertIsNone(facts.app_service_id)
        self.assertIsNone(facts.app_service_plan_reference)
        self.assertIsNone(facts.app_service_vnet_integration_subnet_id)
        self.assertIsNone(facts.public_network_access_enabled)
        self.assertEqual(facts.public_network_fallback_state, "unknown")
        self.assertIsNone(facts.min_tls_version)
        self.assertIsNone(facts.ftps_state)
        self.assertEqual(
            facts.app_service_posture_uncertainties,
            [
                "id is unknown after planning",
                "service_plan_id is unknown after planning",
                "virtual_network_subnet_id is unknown after planning",
                "public_network_access_enabled is unknown after planning",
                "site_config.minimum_tls_version is unknown after planning",
                "site_config.ftps_state is unknown after planning",
            ],
        )
        self.assertEqual(facts.managed_identity_uncertainties, ["identity is unknown after planning"])

    def test_app_service_access_restrictions_preserve_rule_evidence(self) -> None:
        web_app = normalize_linux_web_app(
            _resource(
                AzureResourceType.LINUX_WEB_APP,
                {
                    "name": "api",
                    "site_config": [
                        {
                            "ip_restriction_default_action": "Deny",
                            "scm_ip_restriction_default_action": "Deny",
                            "scm_use_main_ip_restriction": False,
                            "ip_restriction": [
                                {
                                    "name": "office",
                                    "priority": 100,
                                    "action": "Allow",
                                    "ip_address": "203.0.113.0/24",
                                    "description": "Office range",
                                    "headers": [{"x_forwarded_for": ["203.0.113.10"]}],
                                },
                                {
                                    "name": "azure-devops",
                                    "priority": 200,
                                    "action": "Allow",
                                    "service_tag": "AzureDevOps",
                                },
                            ],
                            "scm_ip_restriction": [
                                {
                                    "name": "build-subnet",
                                    "priority": 100,
                                    "action": "Allow",
                                    "virtual_network_subnet_id": "azurerm_subnet.build.id",
                                }
                            ],
                        }
                    ],
                },
                name="api",
            )
        )
        facts = azure_facts(web_app)

        self.assertEqual(facts.app_service_ip_restriction_default_action, "Deny")
        self.assertEqual(facts.app_service_scm_ip_restriction_default_action, "Deny")
        self.assertFalse(facts.app_service_scm_use_main_ip_restriction)
        self.assertEqual(
            facts.app_service_access_restrictions,
            [
                {
                    "name": "office",
                    "action": "Allow",
                    "ip_address": "203.0.113.0/24",
                    "description": "Office range",
                    "priority": 100,
                    "headers": [{"x_forwarded_for": ["203.0.113.10"]}],
                },
                {
                    "name": "azure-devops",
                    "action": "Allow",
                    "service_tag": "AzureDevOps",
                    "priority": 200,
                },
            ],
        )
        self.assertEqual(
            facts.app_service_scm_access_restrictions,
            [
                {
                    "name": "build-subnet",
                    "action": "Allow",
                    "virtual_network_subnet_id": "azurerm_subnet.build.id",
                    "priority": 100,
                }
            ],
        )
        self.assertEqual(facts.app_service_posture_uncertainties, [])

    def test_app_service_access_restriction_unknowns_are_preserved(self) -> None:
        web_app = normalize_linux_web_app(
            _resource(
                AzureResourceType.LINUX_WEB_APP,
                {
                    "name": "api",
                    "site_config": [
                        {
                            "ip_restriction": [
                                {
                                    "name": "office",
                                    "priority": None,
                                    "action": "Allow",
                                    "ip_address": None,
                                }
                            ],
                            "scm_ip_restriction": [],
                        }
                    ],
                },
                name="api",
                unknown_values={
                    "site_config": [
                        {
                            "ip_restriction_default_action": True,
                            "scm_ip_restriction_default_action": True,
                            "scm_use_main_ip_restriction": True,
                            "ip_restriction": [
                                {
                                    "priority": True,
                                    "ip_address": True,
                                    "headers": True,
                                }
                            ],
                            "scm_ip_restriction": True,
                        }
                    ]
                },
            )
        )
        facts = azure_facts(web_app)

        self.assertIsNone(facts.app_service_ip_restriction_default_action)
        self.assertIsNone(facts.app_service_scm_ip_restriction_default_action)
        self.assertIsNone(facts.app_service_scm_use_main_ip_restriction)
        self.assertEqual(
            facts.app_service_access_restrictions,
            [
                {
                    "name": "office",
                    "action": "Allow",
                    "unknown_fields": ["headers", "ip_address", "priority"],
                }
            ],
        )
        self.assertEqual(facts.app_service_scm_access_restrictions, [])
        self.assertEqual(
            facts.app_service_posture_uncertainties,
            [
                "site_config.ip_restriction_default_action is unknown after planning",
                "site_config.scm_ip_restriction_default_action is unknown after planning",
                "site_config.scm_use_main_ip_restriction is unknown after planning",
                "site_config.ip_restriction[0].ip_address is unknown after planning",
                "site_config.ip_restriction[0].priority is unknown after planning",
                "site_config.ip_restriction[0].headers is unknown after planning",
                "site_config.scm_ip_restriction is unknown after planning",
            ],
        )

    def test_azure_normalizer_supports_app_service_and_function_resource_types(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _resource(AzureResourceType.LINUX_WEB_APP, {"name": "api"}, name="api"),
                _resource(AzureResourceType.WINDOWS_WEB_APP, {"name": "admin"}, name="admin"),
                _resource(AzureResourceType.FUNCTION_APP, {"name": "jobs"}, name="jobs"),
                _resource(AzureResourceType.LINUX_FUNCTION_APP, {"name": "worker"}, name="worker"),
                _resource(AzureResourceType.WINDOWS_FUNCTION_APP, {"name": "timer"}, name="timer"),
            ]
        )

        self.assertEqual(
            [resource.address for resource in inventory.resources],
            [
                "azurerm_linux_web_app.api",
                "azurerm_windows_web_app.admin",
                "azurerm_function_app.jobs",
                "azurerm_linux_function_app.worker",
                "azurerm_windows_function_app.timer",
            ],
        )
        self.assertEqual(inventory.unsupported_resources, [])


if __name__ == "__main__":
    unittest.main()
