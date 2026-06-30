from __future__ import annotations

from collections.abc import Sequence

from tfstride.models import NormalizedResource, SecurityGroupRule
from tfstride.providers.azure.metadata import AzureResourceMetadata


class AzureNetworkFacts:
    __slots__ = ()

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
    def private_dns_zone_id(self) -> str | None:
        return self.get(AzureResourceMetadata.PRIVATE_DNS_ZONE_ID)

    @property
    def private_dns_zone_reference(self) -> str | None:
        return self.get(AzureResourceMetadata.PRIVATE_DNS_ZONE_REFERENCE)

    @property
    def private_dns_zone_virtual_network_link_id(self) -> str | None:
        return self.get(AzureResourceMetadata.PRIVATE_DNS_ZONE_VIRTUAL_NETWORK_LINK_ID)

    @property
    def private_dns_zone_virtual_network_reference(self) -> str | None:
        return self.get(AzureResourceMetadata.PRIVATE_DNS_ZONE_VIRTUAL_NETWORK_REFERENCE)

    @property
    def private_dns_zone_registration_state(self) -> str | None:
        return self.get(AzureResourceMetadata.PRIVATE_DNS_ZONE_REGISTRATION_STATE)

    @property
    def private_dns_zone_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.PRIVATE_DNS_ZONE_UNCERTAINTIES)

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
