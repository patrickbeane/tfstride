from __future__ import annotations

from collections.abc import Sequence

from tfstride.identity import PrivilegedAccessGrant, PrivilegedAccessPosture
from tfstride.providers.azure.iam_assignment_posture import deserialize_privileged_access_grants
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_facts.base import AzureBaseFacts


class AzureIdentityFacts(AzureBaseFacts):
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
    def privileged_access_grants(self) -> tuple[PrivilegedAccessGrant, ...]:
        return deserialize_privileged_access_grants(self.get(AzureResourceMetadata.PRIVILEGED_ACCESS_GRANTS))

    @property
    def iam_assignment_posture_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.IAM_ASSIGNMENT_POSTURE_UNCERTAINTIES)

    @property
    def privileged_access_posture(self) -> PrivilegedAccessPosture:
        return PrivilegedAccessPosture(
            provider="azure",
            grants=self.privileged_access_grants,
            unresolved_assignments=self.iam_assignment_posture_uncertainties,
        )

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

    def set_privileged_access_grants(self, values: Sequence[dict[str, object]]) -> None:
        self.set(AzureResourceMetadata.PRIVILEGED_ACCESS_GRANTS, list(values))

    def add_privileged_access_grants(self, values: Sequence[dict[str, object]]) -> None:
        grants = self.get(AzureResourceMetadata.PRIVILEGED_ACCESS_GRANTS)
        changed = False
        for value in values:
            if value in grants:
                continue
            grants.append(dict(value))
            changed = True
        if changed:
            self.set(AzureResourceMetadata.PRIVILEGED_ACCESS_GRANTS, grants)

    def extend_iam_assignment_posture_uncertainties(self, values: Sequence[str | None]) -> None:
        self.extend(AzureResourceMetadata.IAM_ASSIGNMENT_POSTURE_UNCERTAINTIES, values)


def _identity_type_includes(identity_type: str | None, expected: str) -> bool:
    if identity_type is None:
        return False
    normalized_expected = expected.strip().lower()
    return any(
        part.strip().lower() == normalized_expected for part in identity_type.replace(",", " ").split() if part.strip()
    )
