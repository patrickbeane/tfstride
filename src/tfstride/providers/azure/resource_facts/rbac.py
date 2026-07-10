from __future__ import annotations

from collections.abc import Sequence

from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_facts.base import AzureBaseFacts


class AzureRbacFacts(AzureBaseFacts):
    __slots__ = ()

    @property
    def role_assignment_scope(self) -> str | None:
        return self.get(AzureResourceMetadata.ROLE_ASSIGNMENT_SCOPE)

    @property
    def role_definition_name(self) -> str | None:
        return self.get(AzureResourceMetadata.ROLE_DEFINITION_NAME)

    @property
    def role_definition_id(self) -> str | None:
        return self.get(AzureResourceMetadata.ROLE_DEFINITION_ID)

    @property
    def role_definition_scope(self) -> str | None:
        return self.get(AzureResourceMetadata.ROLE_DEFINITION_SCOPE)

    @property
    def role_definition_assignable_scopes(self) -> list[str]:
        return self.get(AzureResourceMetadata.ROLE_DEFINITION_ASSIGNABLE_SCOPES)

    @property
    def role_definition_actions(self) -> list[str]:
        return self.get(AzureResourceMetadata.ROLE_DEFINITION_ACTIONS)

    @property
    def role_definition_not_actions(self) -> list[str]:
        return self.get(AzureResourceMetadata.ROLE_DEFINITION_NOT_ACTIONS)

    @property
    def role_definition_data_actions(self) -> list[str]:
        return self.get(AzureResourceMetadata.ROLE_DEFINITION_DATA_ACTIONS)

    @property
    def role_definition_not_data_actions(self) -> list[str]:
        return self.get(AzureResourceMetadata.ROLE_DEFINITION_NOT_DATA_ACTIONS)

    @property
    def role_definition_breadth_signals(self) -> list[str]:
        return self.get(AzureResourceMetadata.ROLE_DEFINITION_BREADTH_SIGNALS)

    @property
    def role_definition_breadth_mitigations(self) -> list[str]:
        return self.get(AzureResourceMetadata.ROLE_DEFINITION_BREADTH_MITIGATIONS)

    @property
    def role_definition_permissions(self) -> list[dict]:
        return self.get(AzureResourceMetadata.ROLE_DEFINITION_PERMISSIONS)

    @property
    def role_definition_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.ROLE_DEFINITION_UNCERTAINTIES)

    @property
    def is_custom_role_definition(self) -> bool:
        return self.get(AzureResourceMetadata.CUSTOM_ROLE_DEFINITION)

    @property
    def resolved_role_definition_address(self) -> str | None:
        return self.get(AzureResourceMetadata.RESOLVED_ROLE_DEFINITION_ADDRESS)

    @property
    def role_assignment_scope_kind(self) -> str | None:
        return self.get(AzureResourceMetadata.ROLE_ASSIGNMENT_SCOPE_KIND)

    @property
    def role_assignment_breadth_signals(self) -> list[str]:
        return self.get(AzureResourceMetadata.ROLE_ASSIGNMENT_BREADTH_SIGNALS)

    @property
    def role_assignment_breadth_mitigations(self) -> list[str]:
        return self.get(AzureResourceMetadata.ROLE_ASSIGNMENT_BREADTH_MITIGATIONS)

    @property
    def role_assignment_target_resource_address(self) -> str | None:
        return self.get(AzureResourceMetadata.ROLE_ASSIGNMENT_TARGET_RESOURCE_ADDRESS)

    @property
    def role_assignment_target_resource_type(self) -> str | None:
        return self.get(AzureResourceMetadata.ROLE_ASSIGNMENT_TARGET_RESOURCE_TYPE)

    def set_resolved_role_definition_address(self, address: str) -> None:
        self.set(AzureResourceMetadata.RESOLVED_ROLE_DEFINITION_ADDRESS, address)

    def set_role_assignment_scope_context(
        self,
        *,
        scope_kind: str | None,
        breadth_signals: Sequence[str],
        breadth_mitigations: Sequence[str] = (),
        target_resource_address: str | None = None,
        target_resource_type: str | None = None,
    ) -> None:
        self.set(AzureResourceMetadata.ROLE_ASSIGNMENT_SCOPE_KIND, scope_kind)
        self.set(AzureResourceMetadata.ROLE_ASSIGNMENT_BREADTH_SIGNALS, list(breadth_signals))
        self.set(AzureResourceMetadata.ROLE_ASSIGNMENT_BREADTH_MITIGATIONS, list(breadth_mitigations))
        self.set(AzureResourceMetadata.ROLE_ASSIGNMENT_TARGET_RESOURCE_ADDRESS, target_resource_address)
        self.set(AzureResourceMetadata.ROLE_ASSIGNMENT_TARGET_RESOURCE_TYPE, target_resource_type)
