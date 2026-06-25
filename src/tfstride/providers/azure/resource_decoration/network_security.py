from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_utils import clone_security_group_rules


class MergeNetworkSecurityRulesStage:
    name = "merge_network_security_rules"

    def apply(self, resources: list[NormalizedResource], context: AzureDecorationContext) -> None:
        for rule_resource in context.index.network_security_rules:
            facts = azure_facts(rule_resource)
            target = context.index.resolve(facts.network_security_group_reference)
            if target is None:
                facts.add_unresolved_resource_reference(
                    "network_security_group", facts.network_security_group_reference
                )
                continue
            azure_facts(target).merge_network_security_rules(
                clone_security_group_rules(rule_resource.network_rules),
                facts.network_security_rules,
            )
            azure_facts(target).add_standalone_rule_address(rule_resource.address)


class ResolveNetworkSecurityAssociationsStage:
    name = "resolve_network_security_associations"

    def apply(self, resources: list[NormalizedResource], context: AzureDecorationContext) -> None:
        for association in context.index.subnet_nsg_associations:
            self._apply_association(
                association,
                target_reference=azure_facts(association).subnet_reference,
                target_kind="subnet",
                context=context,
            )
        for association in context.index.nic_nsg_associations:
            self._apply_association(
                association,
                target_reference=azure_facts(association).network_interface_reference,
                target_kind="network_interface",
                context=context,
            )

    def _apply_association(
        self,
        association: NormalizedResource,
        *,
        target_reference: str | None,
        target_kind: str,
        context: AzureDecorationContext,
    ) -> None:
        facts = azure_facts(association)
        target = context.index.resolve(target_reference)
        network_security_group = context.index.resolve(facts.network_security_group_reference)
        if target is None:
            facts.add_unresolved_resource_reference(target_kind, target_reference)
        if network_security_group is None:
            facts.add_unresolved_resource_reference(
                "network_security_group",
                facts.network_security_group_reference,
            )
        if target is None or network_security_group is None:
            return
        target_facts = azure_facts(target)
        target_facts.add_security_group_reference(network_security_group.address)
        target_facts.add_resolved_network_security_group_address(network_security_group.address)
        azure_facts(network_security_group).add_associated_resource_address(target.address)
        facts.add_associated_resource_address(target.address)
        facts.add_resolved_network_security_group_address(network_security_group.address)
