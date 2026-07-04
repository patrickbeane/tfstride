from __future__ import annotations

from collections.abc import Sequence

from tfstride.providers.azure.metadata import AzureResourceMetadata


class AzureKeyVaultFacts:
    __slots__ = ()

    @property
    def key_vault_id(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_ID)

    @property
    def key_vault_reference(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_REFERENCE)

    @property
    def resolved_key_vault_address(self) -> str | None:
        return self.get(AzureResourceMetadata.RESOLVED_KEY_VAULT_ADDRESS)

    @property
    def key_vault_expiration_date(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_EXPIRATION_DATE)

    @property
    def key_vault_not_before_date(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_NOT_BEFORE_DATE)

    @property
    def key_vault_certificate_validity_months(self) -> int | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_CERTIFICATE_VALIDITY_MONTHS)

    @property
    def purge_protection_enabled(self) -> bool | None:
        return self.optional_bool(AzureResourceMetadata.PURGE_PROTECTION_ENABLED)

    @property
    def rbac_authorization_enabled(self) -> bool | None:
        return self.optional_bool(AzureResourceMetadata.RBAC_AUTHORIZATION_ENABLED)

    @property
    def key_vault_access_policies(self) -> list[dict]:
        return self.get(AzureResourceMetadata.KEY_VAULT_ACCESS_POLICIES)

    @property
    def key_vault_role_assignments(self) -> list[dict]:
        return self.get(AzureResourceMetadata.KEY_VAULT_ROLE_ASSIGNMENTS)

    @property
    def key_vault_related_resource_addresses(self) -> list[str]:
        return self.get(AzureResourceMetadata.KEY_VAULT_RELATED_RESOURCE_ADDRESSES)

    @property
    def key_vault_network_ip_rules(self) -> list[str]:
        return self.get(AzureResourceMetadata.KEY_VAULT_NETWORK_IP_RULES)

    @property
    def key_vault_network_subnet_ids(self) -> list[str]:
        return self.get(AzureResourceMetadata.KEY_VAULT_NETWORK_SUBNET_IDS)

    @property
    def key_vault_network_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.KEY_VAULT_NETWORK_UNCERTAINTIES)

    @property
    def key_vault_authorization_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.KEY_VAULT_AUTHORIZATION_UNCERTAINTIES)

    @property
    def key_vault_recovery_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.KEY_VAULT_RECOVERY_UNCERTAINTIES)

    @property
    def key_vault_lifecycle_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.KEY_VAULT_LIFECYCLE_UNCERTAINTIES)

    def set_resolved_key_vault_address(self, address: str) -> None:
        self.set(AzureResourceMetadata.RESOLVED_KEY_VAULT_ADDRESS, address)

    def add_key_vault_related_resource_address(self, address: str) -> None:
        self.append(AzureResourceMetadata.KEY_VAULT_RELATED_RESOURCE_ADDRESSES, address)

    def add_key_vault_access_policy(self, policy: dict) -> None:
        policies = self.key_vault_access_policies
        if policy not in policies:
            policies.append(policy)
            self.set(AzureResourceMetadata.KEY_VAULT_ACCESS_POLICIES, policies)

    def set_key_vault_role_assignments(self, assignments: Sequence[dict]) -> None:
        self.set(AzureResourceMetadata.KEY_VAULT_ROLE_ASSIGNMENTS, list(assignments))

    def add_key_vault_role_assignment(self, assignment: dict) -> None:
        assignments = self.key_vault_role_assignments
        if assignment not in assignments:
            assignments.append(assignment)
            self.set(AzureResourceMetadata.KEY_VAULT_ROLE_ASSIGNMENTS, assignments)

    def extend_key_vault_network_uncertainties(self, uncertainties: Sequence[str | None]) -> None:
        self.extend(AzureResourceMetadata.KEY_VAULT_NETWORK_UNCERTAINTIES, uncertainties)

    def extend_key_vault_authorization_uncertainties(
        self,
        uncertainties: Sequence[str | None],
    ) -> None:
        self.extend(AzureResourceMetadata.KEY_VAULT_AUTHORIZATION_UNCERTAINTIES, uncertainties)
