from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TypeVar

from tfstride.models import NormalizedResource, SecurityGroupRule
from tfstride.providers.azure.metadata import AzureResourceMetadata
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

    def add_unresolved_storage_account_reference(self, reference: str | None) -> None:
        self.append(AzureResourceMetadata.UNRESOLVED_STORAGE_ACCOUNT_REFERENCES, reference)

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
