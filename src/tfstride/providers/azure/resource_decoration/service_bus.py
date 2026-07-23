from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import AzureResourceType


class DecorateServiceBusRelationshipsStage:
    name = "decorate_service_bus_relationships"

    def apply(self, resources: list[NormalizedResource], context: AzureDecorationContext) -> None:
        for resource in resources:
            if resource.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE_NETWORK_RULE_SET:
                self._apply_network_rule_set(resource, context)
            elif resource.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE_CUSTOMER_MANAGED_KEY:
                self._apply_customer_managed_key(resource, context)
            elif resource.resource_type in {
                AzureResourceType.SERVICE_BUS_QUEUE,
                AzureResourceType.SERVICE_BUS_TOPIC,
                AzureResourceType.SERVICE_BUS_SUBSCRIPTION,
            }:
                self._apply_entity(resource, context)

    def _apply_network_rule_set(
        self,
        network_rule_set: NormalizedResource,
        context: AzureDecorationContext,
    ) -> None:
        facts = azure_facts(network_rule_set)
        namespace = _resolve_namespace(context, facts.service_bus_namespace_reference)
        if namespace is None:
            facts.add_unresolved_service_bus_namespace_reference(facts.service_bus_namespace_reference)
            return
        facts.set_resolved_service_bus_namespace_address(namespace.address)
        namespace_facts = azure_facts(namespace)
        namespace_facts.set_effective_service_bus_network_rule(
            default_action=facts.network_default_action,
            source_address=network_rule_set.address,
            public_network_access_enabled=facts.public_network_access_enabled,
        )
        namespace_facts.extend_service_bus_posture_uncertainties(
            [f"{network_rule_set.address}: {uncertainty}" for uncertainty in facts.service_bus_posture_uncertainties]
        )

    def _apply_entity(
        self,
        entity: NormalizedResource,
        context: AzureDecorationContext,
    ) -> None:
        if entity.resource_type == AzureResourceType.SERVICE_BUS_SUBSCRIPTION:
            self._apply_subscription(entity, context)
            return

        facts = azure_facts(entity)
        namespace = _resolve_namespace(context, facts.service_bus_entity_namespace_reference)
        if namespace is None:
            facts.add_unresolved_service_bus_namespace_reference(facts.service_bus_entity_namespace_reference)
        else:
            facts.set_resolved_service_bus_namespace_address(namespace.address)

    def _apply_subscription(
        self,
        subscription: NormalizedResource,
        context: AzureDecorationContext,
    ) -> None:
        facts = azure_facts(subscription)
        topic = _resolve_topic(context, facts.service_bus_topic_reference)
        if topic is None:
            facts.add_unresolved_service_bus_topic_reference(facts.service_bus_topic_reference)
            return

        facts.set_resolved_service_bus_topic_address(topic.address)
        topic_namespace_reference = azure_facts(topic).service_bus_entity_namespace_reference
        namespace = _resolve_namespace(context, topic_namespace_reference)
        if namespace is None:
            facts.add_unresolved_service_bus_namespace_reference(topic_namespace_reference)
            return
        facts.set_resolved_service_bus_namespace_address(namespace.address)

    def _apply_customer_managed_key(
        self,
        customer_managed_key: NormalizedResource,
        context: AzureDecorationContext,
    ) -> None:
        facts = azure_facts(customer_managed_key)
        namespace = _resolve_namespace(context, facts.service_bus_namespace_reference)
        if namespace is None:
            facts.add_unresolved_service_bus_namespace_reference(facts.service_bus_namespace_reference)
            return
        facts.set_resolved_service_bus_namespace_address(namespace.address)
        namespace_facts = azure_facts(namespace)
        namespace_facts.set_service_bus_customer_managed_key(
            state=facts.service_bus_customer_managed_key_state or "unknown",
            key_vault_key_id=facts.service_bus_key_vault_key_id,
            source_address=customer_managed_key.address,
        )
        namespace_facts.extend_service_bus_posture_uncertainties(
            [
                f"{customer_managed_key.address}: {uncertainty}"
                for uncertainty in facts.service_bus_posture_uncertainties
            ]
        )


def _resolve_namespace(
    context: AzureDecorationContext,
    reference: str | None,
) -> NormalizedResource | None:
    if not _is_deterministic_namespace_reference(reference):
        return None
    namespace = context.index.resolve(reference)
    if namespace is None or namespace.resource_type != AzureResourceType.SERVICE_BUS_NAMESPACE:
        return None
    return namespace


def _resolve_topic(
    context: AzureDecorationContext,
    reference: str | None,
) -> NormalizedResource | None:
    if not _is_deterministic_topic_reference(reference):
        return None
    topic = context.index.resolve(reference)
    if topic is None or topic.resource_type != AzureResourceType.SERVICE_BUS_TOPIC:
        return None
    return topic


def _is_deterministic_namespace_reference(reference: str | None) -> bool:
    if reference is None:
        return False
    value = reference.strip()
    if value.startswith("${") and value.endswith("}"):
        value = value[2:-1].strip()
    return value.startswith("/") or value.lower().startswith(f"{AzureResourceType.SERVICE_BUS_NAMESPACE}.")


def _is_deterministic_topic_reference(reference: str | None) -> bool:
    if reference is None:
        return False
    value = reference.strip()
    if value.startswith("${") and value.endswith("}"):
        value = value[2:-1].strip()
    return value.startswith("/") or value.lower().startswith(f"{AzureResourceType.SERVICE_BUS_TOPIC}.")
