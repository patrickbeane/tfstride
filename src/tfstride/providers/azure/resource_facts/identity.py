from __future__ import annotations

from tfstride.providers.azure.metadata import AzureResourceMetadata


class AzureIdentityFacts:
    __slots__ = ()

    @property
    def principal_id(self) -> str | None:
        return self.get(AzureResourceMetadata.PRINCIPAL_ID)

    @property
    def principal_type(self) -> str | None:
        return self.get(AzureResourceMetadata.PRINCIPAL_TYPE)

    @property
    def resolved_managed_identity_address(self) -> str | None:
        return self.get(AzureResourceMetadata.RESOLVED_MANAGED_IDENTITY_ADDRESS)

    @property
    def managed_identity_role_assignments(self) -> list[dict]:
        return self.get(AzureResourceMetadata.MANAGED_IDENTITY_ROLE_ASSIGNMENTS)

    @property
    def client_id(self) -> str | None:
        return self.get(AzureResourceMetadata.CLIENT_ID)

    @property
    def tenant_id(self) -> str | None:
        return self.get(AzureResourceMetadata.TENANT_ID)

    @property
    def identity_type(self) -> str | None:
        return self.get(AzureResourceMetadata.IDENTITY_TYPE)

    @property
    def attached_identity_references(self) -> list[str]:
        return self.get(AzureResourceMetadata.ATTACHED_IDENTITY_REFERENCES)

    @property
    def managed_identity_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.MANAGED_IDENTITY_UNCERTAINTIES)

    @property
    def has_system_assigned_identity(self) -> bool:
        return _identity_type_includes(self.identity_type, "SystemAssigned")

    @property
    def has_user_assigned_identity(self) -> bool:
        return _identity_type_includes(self.identity_type, "UserAssigned")

    def set_resolved_managed_identity_address(self, address: str) -> None:
        self.set(AzureResourceMetadata.RESOLVED_MANAGED_IDENTITY_ADDRESS, address)

    def add_managed_identity_role_assignment(self, assignment: dict) -> None:
        assignments = self.managed_identity_role_assignments
        if assignment not in assignments:
            assignments.append(assignment)
            self.set(AzureResourceMetadata.MANAGED_IDENTITY_ROLE_ASSIGNMENTS, assignments)


def _identity_type_includes(identity_type: str | None, expected: str) -> bool:
    if identity_type is None:
        return False
    normalized_expected = expected.strip().lower()
    return any(
        part.strip().lower() == normalized_expected for part in identity_type.replace(",", " ").split() if part.strip()
    )
