from __future__ import annotations

import unittest

from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_REGISTRY_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.ContainerRegistry/registries/images"
_REGISTRY_LOGIN_SERVER = "images.azurecr.io"
_SYSTEM_PRINCIPAL_ID = "system-principal-id"
_USER_PRINCIPAL_ID = "user-principal-id"
_USER_IDENTITY_ID = (
    "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.ManagedIdentity/userAssignedIdentities/runtime"
)


def _resource(
    resource_type: str,
    values: dict[str, object],
    *,
    name: str,
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


def _registry(*, login_server: object = _REGISTRY_LOGIN_SERVER) -> TerraformResource:
    return _resource(
        AzureResourceType.CONTAINER_REGISTRY,
        {
            "id": _REGISTRY_ID,
            "name": "images",
            "sku": "Premium",
            "login_server": login_server,
        },
        name="images",
    )


def _web_app(
    *,
    image: object = "team/api:stable",
    registry_url: object = "https://images.azurecr.io",
    principal_id: object = _SYSTEM_PRINCIPAL_ID,
    identity_type: str = "SystemAssigned",
    identity_ids: list[str] | None = None,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return _resource(
        AzureResourceType.LINUX_WEB_APP,
        {
            "id": "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Web/sites/api",
            "name": "api",
            "site_config": [
                {
                    "application_stack": [
                        {
                            "docker_image_name": image,
                            "docker_registry_url": registry_url,
                        }
                    ]
                }
            ],
            "identity": [
                {
                    "type": identity_type,
                    "principal_id": principal_id,
                    "tenant_id": "tenant-id",
                    "identity_ids": identity_ids or [],
                }
            ],
        },
        name="api",
        unknown_values=unknown_values,
    )


def _linux_function_app() -> TerraformResource:
    return _resource(
        AzureResourceType.LINUX_FUNCTION_APP,
        {
            "id": "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Web/sites/worker",
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
            "identity": [
                {
                    "type": "UserAssigned",
                    "identity_ids": ["azurerm_user_assigned_identity.runtime.id"],
                }
            ],
        },
        name="worker",
    )


def _user_assigned_identity() -> TerraformResource:
    return _resource(
        AzureResourceType.USER_ASSIGNED_IDENTITY,
        {
            "id": _USER_IDENTITY_ID,
            "name": "runtime",
            "principal_id": _USER_PRINCIPAL_ID,
            "client_id": "runtime-client-id",
            "tenant_id": "tenant-id",
        },
        name="runtime",
    )


def _role_assignment(
    *,
    principal_id: object = _SYSTEM_PRINCIPAL_ID,
    scope: object = "azurerm_container_registry.images.id",
    role_name: object = "AcrPush",
    role_definition_id: object = ("/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/acr-push"),
    condition: object | None = None,
    unknown_values: dict[str, object] | None = None,
    name: str = "push",
) -> TerraformResource:
    values: dict[str, object] = {
        "scope": scope,
        "role_definition_name": role_name,
        "role_definition_id": role_definition_id,
        "principal_id": principal_id,
        "principal_type": "ServicePrincipal",
    }
    if condition is not None:
        values["condition"] = condition
    return _resource(
        AzureResourceType.ROLE_ASSIGNMENT,
        values,
        name=name,
        unknown_values=unknown_values,
    )


def _role_definition(
    *,
    data_actions: list[str],
    not_data_actions: list[str] | None = None,
    actions: list[str] | None = None,
    role_definition_id: str = (
        "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/custom-acr-writer"
    ),
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return _resource(
        AzureResourceType.ROLE_DEFINITION,
        {
            "id": role_definition_id,
            "name": "Custom ACR Writer",
            "scope": "/subscriptions/sub-0001",
            "assignable_scopes": ["/subscriptions/sub-0001"],
            "permissions": [
                {
                    "actions": actions or [],
                    "not_actions": [],
                    "data_actions": data_actions,
                    "not_data_actions": not_data_actions or [],
                }
            ],
        },
        name="custom_acr_writer",
        unknown_values=unknown_values,
    )


def _normalize(resources: list[TerraformResource]):
    return AzureNormalizer().normalize(resources)


class AzureAcrWritePathTests(unittest.TestCase):
    def test_system_assigned_app_service_acr_push_path_is_modeled(self) -> None:
        inventory = _normalize([_registry(), _web_app(), _role_assignment()])
        workload = inventory.get_by_address("azurerm_linux_web_app.api")

        self.assertIsNotNone(workload)
        assert workload is not None
        facts = azure_facts(workload)
        self.assertEqual(len(facts.acr_write_paths), 1)
        self.assertEqual(
            facts.acr_write_paths[0],
            {
                "workload_address": "azurerm_linux_web_app.api",
                "workload_type": AzureResourceType.LINUX_WEB_APP,
                "identity_address": "azurerm_linux_web_app.api",
                "identity_kind": "system_assigned",
                "principal_id": _SYSTEM_PRINCIPAL_ID,
                "image_reference": "images.azurecr.io/team/api:stable",
                "image_reference_path": ("site_config.application_stack[0].docker_image_name"),
                "image_tag": "stable",
                "image_digest": None,
                "image_digest_pinned": False,
                "container_registry_address": "azurerm_container_registry.images",
                "container_registry_id": _REGISTRY_ID,
                "container_registry_login_server": _REGISTRY_LOGIN_SERVER,
                "role_assignment_address": "azurerm_role_assignment.push",
                "role_definition_name": "AcrPush",
                "role_definition_id": (
                    "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/acr-push"
                ),
                "role_kind": "writer",
                "grant_basis": "azure_registry_scoped_rbac",
                "registry_scope": "exact_container_registry",
            },
        )
        self.assertEqual(facts.acr_write_path_uncertainties, [])

    def test_user_assigned_function_identity_repository_writer_path_is_modeled(self) -> None:
        inventory = _normalize(
            [
                _registry(),
                _user_assigned_identity(),
                _linux_function_app(),
                _role_assignment(
                    principal_id=_USER_PRINCIPAL_ID,
                    role_name="Container Registry Repository Writer",
                ),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_function_app.worker")

        self.assertIsNotNone(workload)
        assert workload is not None
        paths = azure_facts(workload).acr_write_paths
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["identity_address"], "azurerm_user_assigned_identity.runtime")
        self.assertEqual(paths[0]["identity_kind"], "user_assigned")
        self.assertEqual(paths[0]["principal_id"], _USER_PRINCIPAL_ID)
        self.assertEqual(paths[0]["role_kind"], "writer")
        self.assertEqual(paths[0]["image_reference"], "images.azurecr.io/jobs/worker:2026.07")

    def test_deterministic_custom_role_content_write_path_is_modeled(self) -> None:
        role_definition_id = (
            "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/custom-acr-writer"
        )
        inventory = _normalize(
            [
                _registry(),
                _web_app(),
                _role_definition(
                    data_actions=["Microsoft.ContainerRegistry/registries/repositories/content/write"],
                    role_definition_id=role_definition_id,
                ),
                _role_assignment(
                    role_name=None,
                    role_definition_id=role_definition_id,
                ),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.api")

        self.assertIsNotNone(workload)
        assert workload is not None
        paths = azure_facts(workload).acr_write_paths
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["role_kind"], "custom_writer")
        self.assertEqual(
            paths[0]["grant_basis"],
            "azure_custom_role_registry_scoped_rbac",
        )
        self.assertEqual(
            paths[0]["role_definition_address"],
            "azurerm_role_definition.custom_acr_writer",
        )
        self.assertEqual(
            paths[0]["permission_patterns"],
            ["microsoft.containerregistry/registries/repositories/content/write"],
        )
        self.assertEqual(
            paths[0]["matched_write_actions"],
            ["microsoft.containerregistry/registries/repositories/content/write"],
        )

    def test_custom_role_deny_or_management_only_permission_does_not_create_path(self) -> None:
        role_definition_id = (
            "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/custom-acr-writer"
        )
        denied = _normalize(
            [
                _registry(),
                _web_app(),
                _role_definition(
                    data_actions=["Microsoft.ContainerRegistry/registries/*"],
                    not_data_actions=["Microsoft.ContainerRegistry/registries/*"],
                    role_definition_id=role_definition_id,
                ),
                _role_assignment(
                    role_name=None,
                    role_definition_id=role_definition_id,
                ),
            ]
        )
        management_only = _normalize(
            [
                _registry(),
                _web_app(),
                _role_definition(
                    actions=["Microsoft.ContainerRegistry/registries/write"],
                    data_actions=[],
                    role_definition_id=role_definition_id,
                ),
                _role_assignment(
                    role_name=None,
                    role_definition_id=role_definition_id,
                ),
            ]
        )

        denied_workload = denied.get_by_address("azurerm_linux_web_app.api")
        management_workload = management_only.get_by_address("azurerm_linux_web_app.api")
        assert denied_workload is not None
        assert management_workload is not None
        self.assertEqual(azure_facts(denied_workload).acr_write_paths, [])
        self.assertEqual(azure_facts(management_workload).acr_write_paths, [])

    def test_unresolved_custom_role_data_actions_do_not_create_path(self) -> None:
        role_definition_id = (
            "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/custom-acr-writer"
        )
        inventory = _normalize(
            [
                _registry(),
                _web_app(),
                _role_definition(
                    data_actions=[],
                    role_definition_id=role_definition_id,
                    unknown_values={
                        "permissions": [
                            {
                                "data_actions": True,
                            }
                        ]
                    },
                ),
                _role_assignment(
                    role_name=None,
                    role_definition_id=role_definition_id,
                ),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.api")

        self.assertIsNotNone(workload)
        assert workload is not None
        facts = azure_facts(workload)
        self.assertEqual(facts.acr_write_paths, [])
        self.assertTrue(
            any(
                "custom role azurerm_role_definition.custom_acr_writer data actions are unresolved" in uncertainty
                for uncertainty in facts.acr_write_path_uncertainties
            )
        )

    def test_login_server_scope_and_principal_must_match_exactly(self) -> None:
        login_mismatch = _normalize(
            [
                _registry(),
                _web_app(registry_url="https://other.azurecr.io"),
                _role_assignment(),
            ]
        )
        scope_mismatch = _normalize(
            [
                _registry(),
                _web_app(),
                _role_assignment(scope="/subscriptions/sub-0001/resourceGroups/app"),
            ]
        )
        principal_mismatch = _normalize(
            [
                _registry(),
                _web_app(),
                _role_assignment(principal_id="other-principal-id"),
            ]
        )

        login_workload = login_mismatch.get_by_address("azurerm_linux_web_app.api")
        scope_workload = scope_mismatch.get_by_address("azurerm_linux_web_app.api")
        principal_workload = principal_mismatch.get_by_address("azurerm_linux_web_app.api")
        assert login_workload is not None
        assert scope_workload is not None
        assert principal_workload is not None
        self.assertEqual(azure_facts(login_workload).acr_write_paths, [])
        self.assertIn(
            "ACR login server other.azurecr.io is not modeled",
            azure_facts(login_workload).acr_write_path_uncertainties[0],
        )
        self.assertEqual(azure_facts(scope_workload).acr_write_paths, [])
        self.assertEqual(azure_facts(principal_workload).acr_write_paths, [])

    def test_conditional_or_unknown_assignment_does_not_create_path(self) -> None:
        conditional = _normalize(
            [
                _registry(),
                _web_app(),
                _role_assignment(
                    condition="@Resource[Microsoft.ContainerRegistry/registries/repositories:name] stringEquals 'team/api'"
                ),
            ]
        )
        unknown = _normalize(
            [
                _registry(),
                _web_app(),
                _role_assignment(
                    role_name=None,
                    unknown_values={"role_definition_name": True},
                ),
            ]
        )

        conditional_workload = conditional.get_by_address("azurerm_linux_web_app.api")
        unknown_workload = unknown.get_by_address("azurerm_linux_web_app.api")
        assert conditional_workload is not None
        assert unknown_workload is not None
        conditional_facts = azure_facts(conditional_workload)
        unknown_facts = azure_facts(unknown_workload)
        self.assertEqual(conditional_facts.acr_write_paths, [])
        self.assertIn(
            "has a conditional ACR role assignment",
            conditional_facts.acr_write_path_uncertainties[0],
        )
        self.assertEqual(unknown_facts.acr_write_paths, [])
        self.assertIn("role is unresolved", unknown_facts.acr_write_path_uncertainties[0])

    def test_unresolved_image_or_identity_is_retained_as_uncertainty(self) -> None:
        image_unknown = _normalize(
            [
                _registry(),
                _web_app(
                    image=None,
                    unknown_values={
                        "site_config": [
                            {
                                "application_stack": [
                                    {"docker_image_name": True},
                                ]
                            }
                        ]
                    },
                ),
                _role_assignment(),
            ]
        )
        identity_unknown = _normalize(
            [
                _registry(),
                _web_app(principal_id=None),
                _role_assignment(),
            ]
        )

        image_workload = image_unknown.get_by_address("azurerm_linux_web_app.api")
        identity_workload = identity_unknown.get_by_address("azurerm_linux_web_app.api")
        assert image_workload is not None
        assert identity_workload is not None
        self.assertEqual(azure_facts(image_workload).acr_write_paths, [])
        self.assertTrue(
            any(
                "docker_image_name is unknown after planning" in uncertainty
                for uncertainty in azure_facts(image_workload).acr_write_path_uncertainties
            )
        )
        self.assertEqual(azure_facts(identity_workload).acr_write_paths, [])
        self.assertIn(
            "azurerm_linux_web_app.api: system-assigned identity principal_id is unresolved",
            azure_facts(identity_workload).acr_write_path_uncertainties,
        )


if __name__ == "__main__":
    unittest.main()
