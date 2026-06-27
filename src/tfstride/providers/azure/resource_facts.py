from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TypeVar

from tfstride.models import NormalizedResource, SecurityGroupRule
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.public_network import PUBLIC_NETWORK_FALLBACK_UNKNOWN
from tfstride.providers.metadata_ownership import ProviderMetadataWriteValidator
from tfstride.providers.resource_facts import NeutralProviderResourceFacts, ProviderResourceFactDomains
from tfstride.resource_metadata import MetadataField, StringListMetadataField

_MetadataValue = TypeVar("_MetadataValue")
_AZURE_METADATA_WRITE_VALIDATOR = ProviderMetadataWriteValidator.build(
    provider="azure",
    namespace=AzureResourceMetadata,
)


@dataclass(frozen=True, slots=True)
class AzureResourceFacts(NeutralProviderResourceFacts):
    """Azure-owned view over normalized metadata and relationship posture."""

    def get(self, field: MetadataField[_MetadataValue]) -> _MetadataValue:
        return self.resource.get_metadata_field(field)

    def set(self, field: MetadataField[_MetadataValue], value: _MetadataValue) -> None:
        _AZURE_METADATA_WRITE_VALIDATOR.validate(field)
        self.resource.set_metadata_field(field, value)

    def optional_bool(self, field: MetadataField[bool]) -> bool | None:
        if not self.resource.has_metadata_value(field):
            return None
        return self.get(field)

    def append(self, field: StringListMetadataField, value: str | None) -> None:
        _AZURE_METADATA_WRITE_VALIDATOR.validate(field)
        self.resource.append_metadata_field(field, value)

    def extend(self, field: StringListMetadataField, values: Sequence[str | None]) -> None:
        _AZURE_METADATA_WRITE_VALIDATOR.validate(field)
        self.resource.extend_metadata_field(field, values)

    @property
    def name(self) -> str | None:
        return self.get(AzureResourceMetadata.NAME)

    @property
    def bucket_name(self) -> str | None:
        return self.name

    @property
    def storage_account_id(self) -> str | None:
        return self.get(AzureResourceMetadata.STORAGE_ACCOUNT_ID)

    @property
    def storage_account_reference(self) -> str | None:
        return self.get(AzureResourceMetadata.STORAGE_ACCOUNT_REFERENCE)

    @property
    def resolved_storage_account_address(self) -> str | None:
        return self.get(AzureResourceMetadata.RESOLVED_STORAGE_ACCOUNT_ADDRESS)

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
    def container_access_type(self) -> str | None:
        return self.get(AzureResourceMetadata.CONTAINER_ACCESS_TYPE)

    @property
    def allow_nested_items_to_be_public(self) -> bool | None:
        return self.optional_bool(AzureResourceMetadata.ALLOW_NESTED_ITEMS_TO_BE_PUBLIC)

    @property
    def shared_access_key_enabled(self) -> bool | None:
        return self.optional_bool(AzureResourceMetadata.SHARED_ACCESS_KEY_ENABLED)

    @property
    def min_tls_version(self) -> str | None:
        return self.get(AzureResourceMetadata.MIN_TLS_VERSION)

    @property
    def public_network_access_enabled(self) -> bool | None:
        return self.optional_bool(AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED)

    @property
    def public_network_fallback_state(self) -> str:
        return self.get(AzureResourceMetadata.PUBLIC_NETWORK_FALLBACK_STATE) or PUBLIC_NETWORK_FALLBACK_UNKNOWN

    @property
    def network_default_action(self) -> str | None:
        return self.get(AzureResourceMetadata.NETWORK_DEFAULT_ACTION)

    @property
    def network_rule_source_address(self) -> str | None:
        return self.get(AzureResourceMetadata.NETWORK_RULE_SOURCE_ADDRESS)

    @property
    def public_container_addresses(self) -> list[str]:
        return self.get(AzureResourceMetadata.PUBLIC_CONTAINER_ADDRESSES)

    @property
    def storage_posture_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.STORAGE_POSTURE_UNCERTAINTIES)

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
    def role_assignment_scope(self) -> str | None:
        return self.get(AzureResourceMetadata.ROLE_ASSIGNMENT_SCOPE)

    @property
    def role_definition_name(self) -> str | None:
        return self.get(AzureResourceMetadata.ROLE_DEFINITION_NAME)

    @property
    def role_definition_id(self) -> str | None:
        return self.get(AzureResourceMetadata.ROLE_DEFINITION_ID)

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
    def role_assignment_scope_kind(self) -> str | None:
        return self.get(AzureResourceMetadata.ROLE_ASSIGNMENT_SCOPE_KIND)

    @property
    def role_assignment_breadth_signals(self) -> list[str]:
        return self.get(AzureResourceMetadata.ROLE_ASSIGNMENT_BREADTH_SIGNALS)

    @property
    def role_assignment_target_resource_address(self) -> str | None:
        return self.get(AzureResourceMetadata.ROLE_ASSIGNMENT_TARGET_RESOURCE_ADDRESS)

    @property
    def role_assignment_target_resource_type(self) -> str | None:
        return self.get(AzureResourceMetadata.ROLE_ASSIGNMENT_TARGET_RESOURCE_TYPE)

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
    def mssql_server_id(self) -> str | None:
        return self.get(AzureResourceMetadata.MSSQL_SERVER_ID)

    @property
    def mssql_firewall_start_ip(self) -> str | None:
        return self.get(AzureResourceMetadata.MSSQL_FIREWALL_START_IP)

    @property
    def mssql_firewall_end_ip(self) -> str | None:
        return self.get(AzureResourceMetadata.MSSQL_FIREWALL_END_IP)

    @property
    def mssql_vnet_subnet_id(self) -> str | None:
        return self.get(AzureResourceMetadata.MSSQL_VNET_SUBNET_ID)

    @property
    def mssql_security_alert_state(self) -> str | None:
        return self.get(AzureResourceMetadata.MSSQL_SECURITY_ALERT_STATE)

    @property
    def mssql_posture_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.MSSQL_POSTURE_UNCERTAINTIES)

    @property
    def mssql_firewall_rule_addresses(self) -> list[str]:
        return self.get(AzureResourceMetadata.MSSQL_FIREWALL_RULE_ADDRESSES)

    @property
    def mssql_vnet_rule_addresses(self) -> list[str]:
        return self.get(AzureResourceMetadata.MSSQL_VNET_RULE_ADDRESSES)

    @property
    def postgresql_server_id(self) -> str | None:
        return self.get(AzureResourceMetadata.POSTGRESQL_SERVER_ID)

    @property
    def postgresql_firewall_start_ip(self) -> str | None:
        return self.get(AzureResourceMetadata.POSTGRESQL_FIREWALL_START_IP)

    @property
    def postgresql_firewall_end_ip(self) -> str | None:
        return self.get(AzureResourceMetadata.POSTGRESQL_FIREWALL_END_IP)

    @property
    def postgresql_ssl_min_protocol_version(self) -> str | None:
        return self.get(AzureResourceMetadata.POSTGRESQL_SSL_MIN_PROTOCOL_VERSION)

    @property
    def postgresql_geo_redundant_backup_enabled(self) -> bool | None:
        return self.optional_bool(AzureResourceMetadata.POSTGRESQL_GEO_REDUNDANT_BACKUP_ENABLED)

    @property
    def postgresql_delegated_subnet_id(self) -> str | None:
        return self.get(AzureResourceMetadata.POSTGRESQL_DELEGATED_SUBNET_ID)

    @property
    def postgresql_posture_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.POSTGRESQL_POSTURE_UNCERTAINTIES)

    @property
    def postgresql_config_name(self) -> str | None:
        return self.get(AzureResourceMetadata.POSTGRESQL_CONFIG_NAME)

    @property
    def postgresql_config_value(self) -> str | None:
        return self.get(AzureResourceMetadata.POSTGRESQL_CONFIG_VALUE)

    @property
    def postgresql_config_server_id(self) -> str | None:
        return self.get(AzureResourceMetadata.POSTGRESQL_CONFIG_SERVER_ID)

    @property
    def private_endpoint_id(self) -> str | None:
        return self.get(AzureResourceMetadata.PRIVATE_ENDPOINT_ID)

    @property
    def private_service_connections(self) -> list[dict]:
        return self.get(AzureResourceMetadata.PRIVATE_SERVICE_CONNECTIONS)

    @property
    def private_connection_resource_ids(self) -> list[str]:
        return self.get(AzureResourceMetadata.PRIVATE_CONNECTION_RESOURCE_IDS)

    @property
    def private_endpoint_subresource_names(self) -> list[str]:
        return self.get(AzureResourceMetadata.PRIVATE_ENDPOINT_SUBRESOURCE_NAMES)

    @property
    def private_dns_zone_groups(self) -> list[dict]:
        return self.get(AzureResourceMetadata.PRIVATE_DNS_ZONE_GROUPS)

    @property
    def private_endpoint_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.PRIVATE_ENDPOINT_UNCERTAINTIES)

    @property
    def has_system_assigned_identity(self) -> bool:
        return _identity_type_includes(self.identity_type, "SystemAssigned")

    @property
    def has_user_assigned_identity(self) -> bool:
        return _identity_type_includes(self.identity_type, "UserAssigned")

    @property
    def virtual_network_reference(self) -> str | None:
        return self.get(AzureResourceMetadata.VIRTUAL_NETWORK_REFERENCE)

    @property
    def network_security_group_reference(self) -> str | None:
        return self.get(AzureResourceMetadata.NETWORK_SECURITY_GROUP_REFERENCE)

    @property
    def subnet_reference(self) -> str | None:
        return self.get(AzureResourceMetadata.SUBNET_REFERENCE)

    @property
    def network_interface_reference(self) -> str | None:
        return self.get(AzureResourceMetadata.NETWORK_INTERFACE_REFERENCE)

    @property
    def network_interface_references(self) -> list[str]:
        return self.get(AzureResourceMetadata.NETWORK_INTERFACE_REFERENCES)

    @property
    def public_ip_references(self) -> list[str]:
        return self.get(AzureResourceMetadata.PUBLIC_IP_REFERENCES)

    @property
    def ip_configurations(self) -> list[dict]:
        return self.get(AzureResourceMetadata.IP_CONFIGURATIONS)

    @property
    def network_security_rules(self) -> list[dict]:
        return self.get(AzureResourceMetadata.NETWORK_SECURITY_RULES)

    @property
    def public_compute_exposure_paths(self) -> list[dict]:
        return self.get(AzureResourceMetadata.PUBLIC_COMPUTE_EXPOSURE_PATHS)

    @property
    def resolved_subnet_addresses(self) -> list[str]:
        return self.get(AzureResourceMetadata.RESOLVED_SUBNET_ADDRESSES)

    @property
    def resolved_network_security_group_addresses(self) -> list[str]:
        return self.get(AzureResourceMetadata.RESOLVED_NETWORK_SECURITY_GROUP_ADDRESSES)

    @property
    def resolved_network_interface_addresses(self) -> list[str]:
        return self.get(AzureResourceMetadata.RESOLVED_NETWORK_INTERFACE_ADDRESSES)

    @property
    def resolved_public_ip_addresses(self) -> list[str]:
        return self.get(AzureResourceMetadata.RESOLVED_PUBLIC_IP_ADDRESSES)

    @property
    def public_ip_address(self) -> str | None:
        return self.get(AzureResourceMetadata.PUBLIC_IP_ADDRESS)

    @property
    def vm_size(self) -> str | None:
        return self.get(AzureResourceMetadata.VM_SIZE)

    @property
    def os_type(self) -> str | None:
        return self.get(AzureResourceMetadata.OS_TYPE)

    def set_resolved_storage_account_address(self, address: str) -> None:
        self.set(AzureResourceMetadata.RESOLVED_STORAGE_ACCOUNT_ADDRESS, address)

    def set_resolved_key_vault_address(self, address: str) -> None:
        self.set(AzureResourceMetadata.RESOLVED_KEY_VAULT_ADDRESS, address)

    def set_resolved_managed_identity_address(self, address: str) -> None:
        self.set(AzureResourceMetadata.RESOLVED_MANAGED_IDENTITY_ADDRESS, address)

    def set_role_assignment_scope_context(
        self,
        *,
        scope_kind: str | None,
        breadth_signals: Sequence[str],
        target_resource_address: str | None,
        target_resource_type: str | None,
    ) -> None:
        self.set(AzureResourceMetadata.ROLE_ASSIGNMENT_SCOPE_KIND, scope_kind)
        self.set(AzureResourceMetadata.ROLE_ASSIGNMENT_BREADTH_SIGNALS, list(breadth_signals))
        self.set(AzureResourceMetadata.ROLE_ASSIGNMENT_TARGET_RESOURCE_ADDRESS, target_resource_address)
        self.set(AzureResourceMetadata.ROLE_ASSIGNMENT_TARGET_RESOURCE_TYPE, target_resource_type)

    def set_effective_network_rule(self, default_action: str | None, source_address: str | None) -> None:
        self.set(AzureResourceMetadata.NETWORK_DEFAULT_ACTION, default_action)
        self.set(AzureResourceMetadata.NETWORK_RULE_SOURCE_ADDRESS, source_address)

    def set_resolved_virtual_network_address(self, address: str) -> None:
        self.set(AzureResourceMetadata.RESOLVED_VIRTUAL_NETWORK_ADDRESS, address)
        self.resource.vpc_id = address

    def add_resolved_subnet_address(self, address: str) -> None:
        self.append(AzureResourceMetadata.RESOLVED_SUBNET_ADDRESSES, address)

    def add_resolved_network_security_group_address(self, address: str) -> None:
        self.append(AzureResourceMetadata.RESOLVED_NETWORK_SECURITY_GROUP_ADDRESSES, address)

    def add_resolved_network_interface_address(self, address: str) -> None:
        self.append(AzureResourceMetadata.RESOLVED_NETWORK_INTERFACE_ADDRESSES, address)

    def add_resolved_public_ip_address(self, address: str) -> None:
        self.append(AzureResourceMetadata.RESOLVED_PUBLIC_IP_ADDRESSES, address)

    def add_associated_resource_address(self, address: str) -> None:
        self.append(AzureResourceMetadata.ASSOCIATED_RESOURCE_ADDRESSES, address)

    def add_standalone_rule_address(self, address: str) -> None:
        self.append(AzureResourceMetadata.STANDALONE_RULE_ADDRESSES, address)

    def add_unresolved_resource_reference(self, kind: str, reference: str | None) -> None:
        self.append(
            AzureResourceMetadata.UNRESOLVED_RESOURCE_REFERENCES,
            f"{kind}:{reference}" if reference else kind,
        )

    def merge_network_security_rules(
        self,
        rules: Sequence[SecurityGroupRule],
        records: Sequence[dict],
    ) -> None:
        self.resource.extend_network_rules(rules)
        self.set(
            AzureResourceMetadata.NETWORK_SECURITY_RULES,
            [*self.network_security_rules, *records],
        )

    def add_security_group_reference(self, reference: str) -> None:
        if reference not in self.resource.security_group_ids:
            self.resource.security_group_ids = (*self.resource.security_group_ids, reference)

    def add_subnet_reference(self, reference: str) -> None:
        if reference not in self.resource.subnet_ids:
            self.resource.subnet_ids = (*self.resource.subnet_ids, reference)

    def set_subnet_references(self, references: Sequence[str]) -> None:
        self.resource.subnet_ids = tuple(dict.fromkeys(reference for reference in references if reference))

    def inherit_network_relationships(self, resource: NormalizedResource) -> None:
        for subnet_id in resource.subnet_ids:
            self.add_subnet_reference(subnet_id)
        for security_group_id in resource.security_group_ids:
            self.add_security_group_reference(security_group_id)
        if not self.resource.vpc_id and resource.vpc_id:
            self.resource.vpc_id = resource.vpc_id

    def set_public_ip_attachment(self, *, configured: bool, reasons: Sequence[str]) -> None:
        self.resource.public_access_configured = configured
        self.resource.public_access_reasons = list(reasons)

    def set_public_compute_exposure(self, paths: list[dict], reasons: Sequence[str]) -> None:
        exposed = bool(paths)
        self.set(AzureResourceMetadata.PUBLIC_COMPUTE_EXPOSURE_PATHS, paths)
        self.resource.internet_ingress_capable = exposed
        self.resource.public_exposure = exposed
        self.resource.publicly_accessible = exposed
        self.resource.direct_internet_reachable = exposed
        self.resource.internet_ingress_reasons = [
            rule for path in paths for rule in path.get("network_security_rules", []) if rule
        ]
        self.resource.public_exposure_reasons = list(reasons) if exposed else []

    def add_storage_posture_uncertainty(self, uncertainty: str | None) -> None:
        self.append(AzureResourceMetadata.STORAGE_POSTURE_UNCERTAINTIES, uncertainty)

    def extend_storage_posture_uncertainties(self, uncertainties: Sequence[str | None]) -> None:
        self.extend(AzureResourceMetadata.STORAGE_POSTURE_UNCERTAINTIES, uncertainties)

    def add_public_container_address(self, address: str) -> None:
        self.append(AzureResourceMetadata.PUBLIC_CONTAINER_ADDRESSES, address)

    def add_key_vault_related_resource_address(self, address: str) -> None:
        self.append(AzureResourceMetadata.KEY_VAULT_RELATED_RESOURCE_ADDRESSES, address)

    def add_key_vault_access_policy(self, policy: dict) -> None:
        policies = self.key_vault_access_policies
        if policy not in policies:
            policies.append(policy)
            self.set(AzureResourceMetadata.KEY_VAULT_ACCESS_POLICIES, policies)

    def add_key_vault_role_assignment(self, assignment: dict) -> None:
        assignments = self.key_vault_role_assignments
        if assignment not in assignments:
            assignments.append(assignment)
            self.set(AzureResourceMetadata.KEY_VAULT_ROLE_ASSIGNMENTS, assignments)

    def add_managed_identity_role_assignment(self, assignment: dict) -> None:
        assignments = self.managed_identity_role_assignments
        if assignment not in assignments:
            assignments.append(assignment)
            self.set(AzureResourceMetadata.MANAGED_IDENTITY_ROLE_ASSIGNMENTS, assignments)

    def extend_key_vault_network_uncertainties(self, uncertainties: Sequence[str | None]) -> None:
        self.extend(AzureResourceMetadata.KEY_VAULT_NETWORK_UNCERTAINTIES, uncertainties)

    def extend_key_vault_authorization_uncertainties(
        self,
        uncertainties: Sequence[str | None],
    ) -> None:
        self.extend(AzureResourceMetadata.KEY_VAULT_AUTHORIZATION_UNCERTAINTIES, uncertainties)

    def add_unresolved_storage_account_reference(self, reference: str | None) -> None:
        self.append(AzureResourceMetadata.UNRESOLVED_STORAGE_ACCOUNT_REFERENCES, reference)

    def add_mssql_firewall_rule_address(self, address: str) -> None:
        self.append(AzureResourceMetadata.MSSQL_FIREWALL_RULE_ADDRESSES, address)

    def add_mssql_vnet_rule_address(self, address: str) -> None:
        self.append(AzureResourceMetadata.MSSQL_VNET_RULE_ADDRESSES, address)

    def extend_mssql_posture_uncertainties(self, uncertainties: Sequence[str | None]) -> None:
        self.extend(AzureResourceMetadata.MSSQL_POSTURE_UNCERTAINTIES, uncertainties)

    def set_public_endpoint_posture(self, *, reachable: bool, reasons: Sequence[str]) -> None:
        self.resource.public_access_configured = reachable
        self.resource.direct_internet_reachable = reachable
        self.resource.internet_ingress_capable = reachable
        self.resource.public_access_reasons = list(reasons)
        self.resource.internet_ingress_reasons = list(reasons)

    def set_public_container_posture(
        self,
        *,
        configured: bool,
        exposed: bool,
        reasons: Sequence[str],
    ) -> None:
        self.resource.public_access_configured = configured
        self.resource.public_exposure = exposed
        self.resource.publicly_accessible = exposed
        self.resource.direct_internet_reachable = exposed
        self.resource.public_access_reasons = list(reasons)
        self.resource.public_exposure_reasons = list(reasons) if exposed else []

    def set_public_container_exposure(self, reasons: Sequence[str]) -> None:
        self.resource.public_exposure = True
        self.resource.publicly_accessible = True
        self.resource.public_exposure_reasons = list(reasons)


def azure_facts(resource: NormalizedResource) -> AzureResourceFacts:
    return AzureResourceFacts(resource)


def azure_fact_domains(resource: NormalizedResource) -> ProviderResourceFactDomains:
    facts = azure_facts(resource)
    return ProviderResourceFactDomains(storage=facts, iam=facts, sql=facts, compute=facts, workload=facts)


def _identity_type_includes(identity_type: str | None, expected: str) -> bool:
    if identity_type is None:
        return False
    normalized_expected = expected.strip().lower()
    return any(
        part.strip().lower() == normalized_expected for part in identity_type.replace(",", " ").split() if part.strip()
    )
