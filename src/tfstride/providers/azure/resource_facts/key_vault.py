from __future__ import annotations

from collections.abc import Sequence

from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_facts.base import AzureBaseFacts


class AzureKeyVaultFacts(AzureBaseFacts):
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
    def key_vault_key_type(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_KEY_TYPE)

    @property
    def key_vault_key_size(self) -> int | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_KEY_SIZE)

    @property
    def key_vault_key_curve(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_KEY_CURVE)

    @property
    def key_vault_key_ops(self) -> list[str]:
        return self.get(AzureResourceMetadata.KEY_VAULT_KEY_OPS)

    @property
    def key_vault_rotation_policy(self) -> dict:
        return self.get(AzureResourceMetadata.KEY_VAULT_ROTATION_POLICY)

    @property
    def key_vault_rotation_policy_expire_after(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_ROTATION_POLICY_EXPIRE_AFTER)

    @property
    def key_vault_rotation_policy_notify_before_expiry(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_ROTATION_POLICY_NOTIFY_BEFORE_EXPIRY)

    @property
    def key_vault_rotation_policy_automatic_time_after_creation(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_ROTATION_POLICY_AUTOMATIC_TIME_AFTER_CREATION)

    @property
    def key_vault_rotation_policy_automatic_time_before_expiry(self) -> str | None:
        return self.get(AzureResourceMetadata.KEY_VAULT_ROTATION_POLICY_AUTOMATIC_TIME_BEFORE_EXPIRY)

    @property
    def key_vault_key_posture_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.KEY_VAULT_KEY_POSTURE_UNCERTAINTIES)

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
