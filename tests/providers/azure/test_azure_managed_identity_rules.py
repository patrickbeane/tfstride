from __future__ import annotations

import unittest

from tfstride.analysis.boundaries import detect_trust_boundaries
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS


def _resource(
    resource_type: str,
    name: str,
    values: dict[str, object],
    *,
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


def _role_assignment(
    name: str = "assignment",
    *,
    principal_id: object = "principal-id",
    role_definition_name: object = "Owner",
    role_definition_id: object | None = None,
    scope: object = "/subscriptions/sub-0001",
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "scope": scope,
        "role_definition_name": role_definition_name,
        "principal_id": principal_id,
        "principal_type": "ServicePrincipal",
    }
    if role_definition_id is not None:
        values["role_definition_id"] = role_definition_id
    return _resource(AzureResourceType.ROLE_ASSIGNMENT, name, values, unknown_values=unknown_values)


def _user_assigned_identity() -> TerraformResource:
    return _resource(
        AzureResourceType.USER_ASSIGNED_IDENTITY,
        "deploy",
        {
            "name": "deploy",
            "principal_id": "principal-id",
            "client_id": "client-id",
            "tenant_id": "tenant-id",
        },
    )


def _storage_account() -> TerraformResource:
    return _resource(
        AzureResourceType.STORAGE_ACCOUNT,
        "logs",
        {
            "id": "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/logs",
            "name": "logs",
            "allow_nested_items_to_be_public": False,
            "shared_access_key_enabled": False,
            "min_tls_version": "TLS1_2",
            "public_network_access_enabled": False,
            "network_rules": [{"default_action": "Deny"}],
        },
    )


def _storage_container(access_type: str = "private") -> TerraformResource:
    return _resource(
        AzureResourceType.STORAGE_CONTAINER,
        "objects",
        {
            "name": "objects",
            "storage_account_id": "azurerm_storage_account.logs.id",
            "container_access_type": access_type,
        },
    )


def _network_security_group(port: str = "443") -> TerraformResource:
    return _resource(
        AzureResourceType.NETWORK_SECURITY_GROUP,
        "web_nic",
        {
            "name": "web-nic",
            "security_rule": [
                {
                    "name": "allow-public",
                    "priority": 200,
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "source_address_prefix": "Internet",
                    "source_port_range": "*",
                    "destination_address_prefix": "*",
                    "destination_port_range": port,
                }
            ],
        },
    )


def _public_ip() -> TerraformResource:
    return _resource(
        AzureResourceType.PUBLIC_IP,
        "web",
        {
            "id": "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Network/publicIPAddresses/web",
            "name": "web",
            "ip_address": "203.0.113.44",
        },
    )


def _network_interface() -> TerraformResource:
    return _resource(
        AzureResourceType.NETWORK_INTERFACE,
        "web",
        {
            "id": "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Network/networkInterfaces/web",
            "name": "web",
            "ip_configuration": [
                {
                    "name": "primary",
                    "subnet_id": "azurerm_subnet.web.id",
                    "public_ip_address_id": "azurerm_public_ip.web.id",
                }
            ],
        },
    )


def _network_interface_nsg_association() -> TerraformResource:
    return _resource(
        AzureResourceType.NETWORK_INTERFACE_SECURITY_GROUP_ASSOCIATION,
        "web",
        {
            "network_interface_id": "azurerm_network_interface.web.id",
            "network_security_group_id": "azurerm_network_security_group.web_nic.id",
        },
    )


def _subnet() -> TerraformResource:
    return _resource(
        AzureResourceType.SUBNET,
        "web",
        {
            "id": "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Network/virtualNetworks/main/subnets/web",
            "name": "web",
            "address_prefixes": ["10.0.1.0/24"],
        },
    )


def _public_vm_with_user_assigned_identity() -> list[TerraformResource]:
    return [
        _subnet(),
        _network_security_group(),
        _public_ip(),
        _network_interface(),
        _network_interface_nsg_association(),
        _resource(
            AzureResourceType.LINUX_VIRTUAL_MACHINE,
            "web",
            {
                "id": "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Compute/virtualMachines/web",
                "name": "web",
                "network_interface_ids": ["azurerm_network_interface.web.id"],
                "identity": [
                    {
                        "type": "UserAssigned",
                        "identity_ids": ["azurerm_user_assigned_identity.deploy.id"],
                    }
                ],
            },
        ),
    ]


def _public_vm_without_identity(port: str = "22") -> list[TerraformResource]:
    return [
        _subnet(),
        _network_security_group(port),
        _public_ip(),
        _network_interface(),
        _network_interface_nsg_association(),
        _resource(
            AzureResourceType.LINUX_VIRTUAL_MACHINE,
            "web",
            {
                "id": "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Compute/virtualMachines/web",
                "name": "web",
                "network_interface_ids": ["azurerm_network_interface.web.id"],
            },
        ),
    ]


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = AzureNormalizer().normalize(resources)
    boundaries = detect_trust_boundaries(inventory)
    findings = StrideRuleEngine().evaluate(
        inventory,
        boundaries,
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )
    return inventory, boundaries, findings


def _all_azure_rule_ids() -> tuple[str, ...]:
    return tuple(rule_id for group in AZURE_RULE_GROUP_IDS for rule_id in group)


class AzureManagedIdentityRuleTests(unittest.TestCase):
    def test_managed_identity_broad_subscription_rbac_is_detected(self) -> None:
        _, _, findings = _evaluate(
            [_user_assigned_identity(), _role_assignment(role_definition_name="Owner")],
            "azure-managed-identity-broad-rbac",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-managed-identity-broad-rbac"])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            ["azurerm_user_assigned_identity.deploy", "azurerm_role_assignment.assignment"],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertIn("principal_id=principal-id", evidence["managed_identity"])
        self.assertEqual(evidence["breadth_signals"], ["subscription_scope", "broad_builtin_role"])
        self.assertIn("role=Owner", evidence["role_assignments"][0])

    def test_reader_at_resource_scope_is_not_broad_rbac(self) -> None:
        _, _, findings = _evaluate(
            [
                _storage_account(),
                _user_assigned_identity(),
                _role_assignment(
                    role_definition_name="Reader",
                    scope="azurerm_storage_account.logs.id",
                ),
            ],
            "azure-managed-identity-broad-rbac",
        )

        self.assertEqual(findings, [])

    def test_unknown_role_assignment_data_does_not_infer_broad_rbac(self) -> None:
        _, _, findings = _evaluate(
            [
                _user_assigned_identity(),
                _role_assignment(
                    role_definition_name=None,
                    unknown_values={"role_definition_name": True},
                ),
            ],
            "azure-managed-identity-broad-rbac",
        )

        self.assertEqual(findings, [])

    def test_public_user_assigned_identity_path_to_storage_is_detected(self) -> None:
        _, boundaries, findings = _evaluate(
            [
                _storage_account(),
                _user_assigned_identity(),
                *_public_vm_with_user_assigned_identity(),
                _role_assignment(
                    role_definition_name="Storage Blob Data Owner",
                    scope="azurerm_storage_account.logs.id",
                ),
            ],
            "azure-public-workload-sensitive-resource-access",
        )

        self.assertEqual(
            [boundary.identifier for boundary in boundaries],
            ["internet-to-service:internet->azurerm_linux_virtual_machine.web"],
        )
        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["azure-public-workload-sensitive-resource-access"],
        )
        finding = findings[0]
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            [
                "azurerm_linux_virtual_machine.web",
                "azurerm_user_assigned_identity.deploy",
                "azurerm_role_assignment.assignment",
                "azurerm_storage_account.logs",
            ],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            "internet-to-service:internet->azurerm_linux_virtual_machine.web",
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertIn("address=azurerm_linux_virtual_machine.web", evidence["public_workloads"][0])
        self.assertIn("target=azurerm_storage_account.logs", evidence["sensitive_resource_assignments"][0])

    def test_private_workload_sensitive_assignment_is_not_public_path(self) -> None:
        _, _, findings = _evaluate(
            [
                _storage_account(),
                _user_assigned_identity(),
                _role_assignment(
                    role_definition_name="Storage Blob Data Owner",
                    scope="azurerm_storage_account.logs.id",
                ),
            ],
            "azure-public-workload-sensitive-resource-access",
        )

        self.assertEqual(findings, [])

    def test_reader_assignment_to_sensitive_resource_is_not_sensitive_access_path(self) -> None:
        _, _, findings = _evaluate(
            [
                _storage_account(),
                _user_assigned_identity(),
                *_public_vm_with_user_assigned_identity(),
                _role_assignment(
                    role_definition_name="Reader",
                    scope="azurerm_storage_account.logs.id",
                ),
            ],
            "azure-public-workload-sensitive-resource-access",
        )

        self.assertEqual(findings, [])

    def test_public_compute_without_identity_does_not_create_duplicate_sensitive_findings(self) -> None:
        _, _, findings = _evaluate(
            _public_vm_without_identity(port="22"),
            *_all_azure_rule_ids(),
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-public-compute-broad-ingress"])

    def test_public_storage_without_identity_does_not_create_duplicate_sensitive_findings(self) -> None:
        _, _, findings = _evaluate(
            [
                _resource(
                    AzureResourceType.STORAGE_ACCOUNT,
                    "logs",
                    {
                        "id": "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/logs",
                        "name": "logs",
                        "allow_nested_items_to_be_public": True,
                        "shared_access_key_enabled": True,
                        "min_tls_version": "TLS1_1",
                        "public_network_access_enabled": True,
                    },
                ),
                _storage_container("blob"),
            ],
            *_all_azure_rule_ids(),
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [
                "azure-storage-container-public-access",
                "azure-storage-account-nested-public-access-enabled",
                "azure-storage-account-shared-key-enabled",
                "azure-storage-account-minimum-tls-below-1-2",
                "azure-storage-account-public-network-unrestricted",
            ],
        )


if __name__ == "__main__":
    unittest.main()
