from __future__ import annotations

import unittest
from unittest.mock import patch

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.analysis.rule_registry import default_rule_registry
from tfstride.models import NormalizedResource, ResourceCategory, ResourceInventory
from tfstride.providers.azure import rbac_rules as azure_rbac_rules
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.rbac_breadth import (
    AUTHORIZATION_MANAGEMENT,
    COMPUTE_MANAGEMENT,
    KEY_VAULT_DATA_PLANE,
    OWNER_LIKE_OR_WILDCARD,
    ROLE_ASSIGNMENT_CAPABLE,
    STORAGE_DATA_PLANE,
)
from tfstride.providers.azure.rbac_rules import AzureCustomRoleRuleDetectors
from tfstride.providers.azure.resource_types import AzureResourceType

_RULE_REGISTRY = default_rule_registry()
_FINDING_FACTORY = FindingFactory(_RULE_REGISTRY)
_ROLE_ID = "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/custom"
_SUBSCRIPTION_SCOPE = "/subscriptions/sub-0001"
_RESOURCE_GROUP_SCOPE = "/subscriptions/sub-0001/resourceGroups/app"


def _context(resources: list[NormalizedResource], *, provider: str = "azure") -> RuleEvaluationContext:
    return RuleEvaluationContext(
        inventory=ResourceInventory(provider=provider, resources=resources),
        boundary_index={},
        rule_registry=_RULE_REGISTRY,
    )


def _role_definition(
    name: str = "custom",
    *,
    actions: list[str] | None = None,
    data_actions: list[str] | None = None,
    breadth_signals: list[str] | None = None,
    mitigations: list[str] | None = None,
    assignable_scopes: list[str] | None = None,
    custom: bool = True,
) -> NormalizedResource:
    return NormalizedResource(
        address=f"azurerm_role_definition.{name}",
        provider="azure",
        resource_type=AzureResourceType.ROLE_DEFINITION,
        name=name,
        category=ResourceCategory.IAM,
        metadata={
            AzureResourceMetadata.NAME: name,
            AzureResourceMetadata.ROLE_DEFINITION_ID: _role_definition_id(name),
            AzureResourceMetadata.ROLE_DEFINITION_SCOPE: _SUBSCRIPTION_SCOPE,
            AzureResourceMetadata.ROLE_DEFINITION_ACTIONS: actions or [],
            AzureResourceMetadata.ROLE_DEFINITION_DATA_ACTIONS: data_actions or [],
            AzureResourceMetadata.ROLE_DEFINITION_BREADTH_SIGNALS: breadth_signals or [],
            AzureResourceMetadata.ROLE_DEFINITION_BREADTH_MITIGATIONS: mitigations or [],
            AzureResourceMetadata.ROLE_DEFINITION_ASSIGNABLE_SCOPES: assignable_scopes or [_SUBSCRIPTION_SCOPE],
            AzureResourceMetadata.CUSTOM_ROLE_DEFINITION: custom,
        },
    )


def _role_assignment(
    name: str = "assignment",
    *,
    role_name: str = "custom",
    principal_id: str | None = "principal-id",
    principal_type: str | None = "ServicePrincipal",
    scope: str = _SUBSCRIPTION_SCOPE,
    scope_kind: str = "subscription",
    resolved_principal: str | None = "azurerm_user_assigned_identity.deploy",
    target_resource: str | None = None,
    assignment_signals: list[str] | None = None,
) -> NormalizedResource:
    return NormalizedResource(
        address=f"azurerm_role_assignment.{name}",
        provider="azure",
        resource_type=AzureResourceType.ROLE_ASSIGNMENT,
        name=name,
        category=ResourceCategory.IAM,
        metadata={
            AzureResourceMetadata.ROLE_ASSIGNMENT_SCOPE: scope,
            AzureResourceMetadata.ROLE_ASSIGNMENT_SCOPE_KIND: scope_kind,
            AzureResourceMetadata.ROLE_DEFINITION_ID: _role_definition_id(role_name),
            AzureResourceMetadata.RESOLVED_ROLE_DEFINITION_ADDRESS: f"azurerm_role_definition.{role_name}",
            AzureResourceMetadata.PRINCIPAL_ID: principal_id,
            AzureResourceMetadata.PRINCIPAL_TYPE: principal_type,
            AzureResourceMetadata.RESOLVED_MANAGED_IDENTITY_ADDRESS: resolved_principal,
            AzureResourceMetadata.ROLE_ASSIGNMENT_TARGET_RESOURCE_ADDRESS: target_resource,
            AzureResourceMetadata.ROLE_ASSIGNMENT_BREADTH_SIGNALS: assignment_signals or [],
        },
    )


def _managed_identity(name: str = "deploy") -> NormalizedResource:
    return NormalizedResource(
        address=f"azurerm_user_assigned_identity.{name}",
        provider="azure",
        resource_type=AzureResourceType.USER_ASSIGNED_IDENTITY,
        name=name,
        category=ResourceCategory.IAM,
        metadata={AzureResourceMetadata.PRINCIPAL_ID: "principal-id"},
    )


def _storage_account(name: str = "logs") -> NormalizedResource:
    return NormalizedResource(
        address=f"azurerm_storage_account.{name}",
        provider="azure",
        resource_type=AzureResourceType.STORAGE_ACCOUNT,
        name=name,
        category=ResourceCategory.DATA,
    )


def _role_definition_id(name: str) -> str:
    if name == "custom":
        return _ROLE_ID
    return f"/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/{name}"


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AzureCustomRolePostureDetectorUnitTests(unittest.TestCase):
    def test_wildcard_management_plane_detector_consumes_owner_like_classification(self) -> None:
        role = _role_definition(
            actions=["*"],
            breadth_signals=[OWNER_LIKE_OR_WILDCARD],
            mitigations=["not_action=Microsoft.Authorization/elevateAccess/Action"],
        )

        findings = AzureCustomRoleRuleDetectors(_FINDING_FACTORY).detect_wildcard_management_plane(
            _context([role]),
            "azure-custom-role-wildcard-management-plane",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-custom-role-wildcard-management-plane"])
        self.assertEqual(findings[0].severity.value, "high")
        self.assertEqual(findings[0].affected_resources, ["azurerm_role_definition.custom"])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["management_actions"], ["*"])
        self.assertEqual(evidence["breadth_signals"], [OWNER_LIKE_OR_WILDCARD])
        self.assertEqual(evidence["mitigating_exclusions"], ["not_action=Microsoft.Authorization/elevateAccess/Action"])

    def test_authorization_management_detector_consumes_role_assignment_capable_classification(self) -> None:
        role = _role_definition(
            "role_admin",
            actions=["Microsoft.Authorization/roleAssignments/write"],
            breadth_signals=[AUTHORIZATION_MANAGEMENT, ROLE_ASSIGNMENT_CAPABLE],
            assignable_scopes=[_RESOURCE_GROUP_SCOPE],
        )

        findings = AzureCustomRoleRuleDetectors(_FINDING_FACTORY).detect_authorization_management(
            _context([role]),
            "azure-custom-role-authorization-management",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-custom-role-authorization-management"])
        self.assertEqual(findings[0].severity.value, "medium")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["authorization_actions"], ["Microsoft.Authorization/roleAssignments/write"])
        self.assertEqual(evidence["breadth_signals"], [AUTHORIZATION_MANAGEMENT, ROLE_ASSIGNMENT_CAPABLE])

    def test_broad_management_plane_detector_consumes_management_wildcard_classification(self) -> None:
        role = _role_definition(
            "compute_admin",
            actions=["Microsoft.Compute/virtualMachines/*"],
            breadth_signals=[COMPUTE_MANAGEMENT],
            assignable_scopes=[_RESOURCE_GROUP_SCOPE],
        )

        findings = AzureCustomRoleRuleDetectors(_FINDING_FACTORY).detect_broad_management_plane(
            _context([role]),
            "azure-custom-role-broad-management-plane",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-custom-role-broad-management-plane"])
        self.assertEqual(findings[0].severity.value, "medium")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["management_actions"], ["Microsoft.Compute/virtualMachines/*"])
        self.assertEqual(evidence["breadth_signals"], [COMPUTE_MANAGEMENT])

    def test_broad_data_plane_detector_consumes_data_plane_classification(self) -> None:
        role = _role_definition(
            "secret_operator",
            data_actions=["Microsoft.KeyVault/vaults/secrets/*"],
            breadth_signals=[KEY_VAULT_DATA_PLANE],
            mitigations=["not_data_action=Microsoft.KeyVault/vaults/secrets/delete"],
        )

        findings = AzureCustomRoleRuleDetectors(_FINDING_FACTORY).detect_broad_data_plane(
            _context([role]),
            "azure-custom-role-broad-data-plane",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-custom-role-broad-data-plane"])
        self.assertEqual(findings[0].severity.value, "high")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["data_plane_actions"], ["Microsoft.KeyVault/vaults/secrets/*"])
        self.assertEqual(evidence["breadth_signals"], [KEY_VAULT_DATA_PLANE])
        self.assertEqual(
            evidence["mitigating_exclusions"],
            ["not_data_action=Microsoft.KeyVault/vaults/secrets/delete"],
        )

    def test_subscription_assignable_scope_detector_flags_scope_without_claiming_active_assignment(self) -> None:
        role = _role_definition(
            "reader",
            actions=["Microsoft.Storage/storageAccounts/blobServices/containers/read"],
            breadth_signals=[STORAGE_DATA_PLANE],
            assignable_scopes=[_SUBSCRIPTION_SCOPE],
        )

        findings = AzureCustomRoleRuleDetectors(_FINDING_FACTORY).detect_subscription_assignable_scope(
            _context([role]),
            "azure-custom-role-subscription-assignable-scope",
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["azure-custom-role-subscription-assignable-scope"],
        )
        self.assertIn("role-definition posture only", findings[0].rationale)
        self.assertEqual(
            _evidence_by_key(findings[0])["scope_posture"], ["custom role is assignable at subscription scope"]
        )

    def test_posture_detectors_ignore_builtin_roles_even_when_metadata_has_broad_signals(self) -> None:
        role = _role_definition(
            actions=["*"],
            breadth_signals=[OWNER_LIKE_OR_WILDCARD, ROLE_ASSIGNMENT_CAPABLE],
            custom=False,
        )
        detectors = AzureCustomRoleRuleDetectors(_FINDING_FACTORY)

        self.assertEqual(
            detectors.detect_wildcard_management_plane(_context([role]), "azure-custom-role-wildcard-management-plane"),
            [],
        )
        self.assertEqual(
            detectors.detect_authorization_management(_context([role]), "azure-custom-role-authorization-management"),
            [],
        )

    def test_custom_role_index_is_reused_across_detector_methods_for_same_inventory(self) -> None:
        role = _role_definition(
            actions=["*", "Microsoft.Authorization/roleAssignments/write"],
            breadth_signals=[OWNER_LIKE_OR_WILDCARD, AUTHORIZATION_MANAGEMENT, ROLE_ASSIGNMENT_CAPABLE],
        )
        assignment = _role_assignment()
        identity = _managed_identity()
        context = _context([identity, role, assignment])
        detectors = AzureCustomRoleRuleDetectors(_FINDING_FACTORY)

        original_builder = azure_rbac_rules._build_custom_role_index
        with patch.object(azure_rbac_rules, "_build_custom_role_index", wraps=original_builder) as build_index:
            detectors.detect_wildcard_management_plane(context, "azure-custom-role-wildcard-management-plane")
            detectors.detect_authorization_management(context, "azure-custom-role-authorization-management")
            detectors.detect_assigned_custom_role_blast_radius(context, "azure-custom-role-assignment-blast-radius")

        self.assertEqual(build_index.call_count, 1)

    def test_custom_role_index_cache_invalidates_for_different_inventory(self) -> None:
        first_context = _context([_role_definition(actions=["*"], breadth_signals=[OWNER_LIKE_OR_WILDCARD])])
        second_context = _context([_role_definition("other", actions=["*"], breadth_signals=[OWNER_LIKE_OR_WILDCARD])])
        detectors = AzureCustomRoleRuleDetectors(_FINDING_FACTORY)

        original_builder = azure_rbac_rules._build_custom_role_index
        with patch.object(azure_rbac_rules, "_build_custom_role_index", wraps=original_builder) as build_index:
            detectors.detect_wildcard_management_plane(first_context, "azure-custom-role-wildcard-management-plane")
            detectors.detect_wildcard_management_plane(second_context, "azure-custom-role-wildcard-management-plane")

        self.assertEqual(build_index.call_count, 2)


class AzureAssignedCustomRoleDetectorUnitTests(unittest.TestCase):
    def test_assigned_custom_role_detector_links_role_assignment_principal_and_scope(self) -> None:
        role = _role_definition(
            "role_admin",
            actions=["Microsoft.Authorization/roleAssignments/write"],
            breadth_signals=[AUTHORIZATION_MANAGEMENT, ROLE_ASSIGNMENT_CAPABLE],
        )
        assignment = _role_assignment(role_name="role_admin", assignment_signals=["subscription_scope"])
        identity = _managed_identity()

        findings = AzureCustomRoleRuleDetectors(_FINDING_FACTORY).detect_assigned_custom_role_blast_radius(
            _context([identity, role, assignment]),
            "azure-custom-role-assignment-blast-radius",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-custom-role-assignment-blast-radius"])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            [
                "azurerm_user_assigned_identity.deploy",
                "azurerm_role_assignment.assignment",
                "azurerm_role_definition.role_admin",
            ],
        )
        self.assertIn("authorization-management permissions", finding.rationale)
        evidence = _evidence_by_key(finding)
        self.assertEqual(evidence["breadth_reasons"], ["authorization_management"])
        self.assertEqual(evidence["authorization_actions"], ["Microsoft.Authorization/roleAssignments/write"])
        self.assertEqual(evidence["role_breadth_signals"], [AUTHORIZATION_MANAGEMENT, ROLE_ASSIGNMENT_CAPABLE])
        self.assertIn("resolved_managed_identity=azurerm_user_assigned_identity.deploy", evidence["assigned_principal"])
        self.assertIn("scope_kind=subscription", evidence["role_assignment"])

    def test_assigned_custom_role_detector_includes_sensitive_target_when_scope_resolves(self) -> None:
        role = _role_definition(
            "storage_data",
            data_actions=["Microsoft.Storage/storageAccounts/blobServices/containers/*"],
            breadth_signals=[STORAGE_DATA_PLANE],
            assignable_scopes=[_RESOURCE_GROUP_SCOPE],
        )
        assignment = _role_assignment(
            role_name="storage_data",
            scope="azurerm_storage_account.logs.id",
            scope_kind="resource",
            target_resource="azurerm_storage_account.logs",
            assignment_signals=["sensitive_resource_scope", "storage_data_plane"],
        )
        identity = _managed_identity()
        storage = _storage_account()

        findings = AzureCustomRoleRuleDetectors(_FINDING_FACTORY).detect_assigned_custom_role_blast_radius(
            _context([storage, identity, role, assignment]),
            "azure-custom-role-assignment-blast-radius",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-custom-role-assignment-blast-radius"])
        self.assertEqual(
            findings[0].affected_resources,
            [
                "azurerm_user_assigned_identity.deploy",
                "azurerm_role_assignment.assignment",
                "azurerm_role_definition.storage_data",
                "azurerm_storage_account.logs",
            ],
        )
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["breadth_reasons"], ["broad_data_plane"])
        self.assertEqual(
            evidence["data_plane_actions"],
            ["Microsoft.Storage/storageAccounts/blobServices/containers/*"],
        )
        self.assertEqual(evidence["assignment_breadth_signals"], ["sensitive_resource_scope", "storage_data_plane"])
        self.assertIn("target_resource=azurerm_storage_account.logs", evidence["role_assignment"])

    def test_assigned_custom_role_detector_requires_resolved_role_and_principal_id(self) -> None:
        role = _role_definition(
            "role_admin",
            actions=["Microsoft.Authorization/roleAssignments/write"],
            breadth_signals=[AUTHORIZATION_MANAGEMENT, ROLE_ASSIGNMENT_CAPABLE],
        )
        unknown_principal = _role_assignment(role_name="role_admin", principal_id=None)
        unresolved_role = _role_assignment("unresolved", role_name="missing")

        findings = AzureCustomRoleRuleDetectors(_FINDING_FACTORY).detect_assigned_custom_role_blast_radius(
            _context([role, unknown_principal, unresolved_role]),
            "azure-custom-role-assignment-blast-radius",
        )

        self.assertEqual(findings, [])


class AzureCustomRoleDetectorProviderScopeUnitTests(unittest.TestCase):
    def test_custom_role_detectors_ignore_non_azure_inventory(self) -> None:
        role = _role_definition(actions=["*"], breadth_signals=[OWNER_LIKE_OR_WILDCARD])
        assignment = _role_assignment()
        context = _context([role, assignment], provider="gcp")
        detectors = AzureCustomRoleRuleDetectors(_FINDING_FACTORY)
        cases = (
            (detectors.detect_wildcard_management_plane, "azure-custom-role-wildcard-management-plane"),
            (detectors.detect_authorization_management, "azure-custom-role-authorization-management"),
            (detectors.detect_broad_management_plane, "azure-custom-role-broad-management-plane"),
            (detectors.detect_broad_data_plane, "azure-custom-role-broad-data-plane"),
            (detectors.detect_subscription_assignable_scope, "azure-custom-role-subscription-assignable-scope"),
            (detectors.detect_assigned_custom_role_blast_radius, "azure-custom-role-assignment-blast-radius"),
        )

        for detector, rule_id in cases:
            with self.subTest(rule_id=rule_id):
                self.assertEqual(detector(context, rule_id), [])


if __name__ == "__main__":
    unittest.main()
