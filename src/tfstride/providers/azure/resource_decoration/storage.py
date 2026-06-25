from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import AzureResourceType


class DecorateStorageRelationshipsStage:
    name = "decorate_storage_relationships"

    def apply(self, resources: list[NormalizedResource], context: AzureDecorationContext) -> None:
        self._apply_standalone_network_rules(resources, context)
        self._derive_account_network_posture(resources)
        self._resolve_containers(resources, context)

    def _apply_standalone_network_rules(
        self,
        resources: list[NormalizedResource],
        context: AzureDecorationContext,
    ) -> None:
        for network_rules in resources:
            if network_rules.resource_type != AzureResourceType.STORAGE_ACCOUNT_NETWORK_RULES:
                continue
            facts = azure_facts(network_rules)
            account = context.index.resolve(facts.storage_account_reference)
            if account is None:
                facts.add_unresolved_storage_account_reference(facts.storage_account_reference)
                continue
            facts.set_resolved_storage_account_address(account.address)
            default_action = facts.network_default_action or "Allow"
            azure_facts(account).set_effective_network_rule(default_action, network_rules.address)

    def _derive_account_network_posture(self, resources: list[NormalizedResource]) -> None:
        for account in resources:
            if account.resource_type != AzureResourceType.STORAGE_ACCOUNT:
                continue
            facts = azure_facts(account)
            public_network_enabled = facts.public_network_access_enabled is True
            default_action = (facts.network_default_action or "Allow").strip()
            reachable = public_network_enabled and default_action.lower() != "deny"
            reasons = []
            if reachable:
                reasons = [
                    "public_network_access_enabled is true",
                    f"effective network default_action is {default_action}",
                ]
            facts.set_public_endpoint_posture(reachable=reachable, reasons=reasons)

    def _resolve_containers(
        self,
        resources: list[NormalizedResource],
        context: AzureDecorationContext,
    ) -> None:
        for container in resources:
            if container.resource_type != AzureResourceType.STORAGE_CONTAINER:
                continue
            facts = azure_facts(container)
            account = context.index.resolve(facts.storage_account_reference)
            public_access_type = (facts.container_access_type or "private").strip().lower()
            configured_public = public_access_type in {"blob", "container"}
            if account is None:
                facts.add_unresolved_storage_account_reference(facts.storage_account_reference)
                facts.set_public_container_posture(
                    configured=configured_public,
                    exposed=False,
                    reasons=[f"container_access_type is {public_access_type}"] if configured_public else [],
                )
                continue

            facts.set_resolved_storage_account_address(account.address)
            account_facts = azure_facts(account)
            exposed = (
                configured_public
                and account_facts.allow_nested_items_to_be_public is True
                and account.direct_internet_reachable
            )
            reasons = [f"container_access_type is {public_access_type}"] if configured_public else []
            if exposed:
                reasons.extend(
                    [
                        f"{account.address} allows nested items to be public",
                        f"{account.address} is reachable through its public network endpoint",
                    ]
                )
                account_facts.add_public_container_address(container.address)
                account_facts.set_public_container_exposure(reasons)
            facts.set_public_container_posture(configured=configured_public, exposed=exposed, reasons=reasons)
