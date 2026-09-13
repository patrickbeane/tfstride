from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.azure.resource_facts import AzureResourceFacts, azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import AzureResourceType

_KEY_VAULT_CHILD_TYPES = frozenset(
    {
        AzureResourceType.KEY_VAULT_SECRET,
        AzureResourceType.KEY_VAULT_KEY,
        AzureResourceType.KEY_VAULT_CERTIFICATE,
    }
)


class DecorateKeyVaultRelationshipsStage:
    name = "decorate_key_vault_relationships"

    def apply(self, resources: list[NormalizedResource], context: AzureDecorationContext) -> None:
        self._resolve_children(resources, context)
        self._merge_access_policies(resources, context)
        self._merge_role_assignments(resources, context)
        self._derive_network_posture(resources)

    def _resolve_children(
        self,
        resources: list[NormalizedResource],
        context: AzureDecorationContext,
    ) -> None:
        for resource in resources:
            if resource.resource_type not in _KEY_VAULT_CHILD_TYPES:
                continue
            facts = azure_facts(resource)
            vault = context.index.resources_by_address.get(facts.resolved_key_vault_address or "")
            if vault is None:
                vault = context.index.resolve(
                    facts.key_vault_reference,
                    source=resource,
                    resource_types={AzureResourceType.KEY_VAULT},
                )
            if vault is None or vault.resource_type != AzureResourceType.KEY_VAULT:
                facts.add_unresolved_resource_reference("key_vault", facts.key_vault_reference)
                continue
            facts.set_resolved_key_vault_address(vault.address)
            vault_facts = azure_facts(vault)
            if vault_facts.key_vault_uri is not None:
                if facts.key_vault_uri is None:
                    facts.set_key_vault_uri(vault_facts.key_vault_uri)
                if resource.resource_type == AzureResourceType.KEY_VAULT_SECRET:
                    _derive_secret_identity(facts, vault_facts.key_vault_uri)
            if resource.resource_type == AzureResourceType.KEY_VAULT_KEY:
                _derive_key_identity(
                    facts,
                    vault_facts.key_vault_uri,
                    vault_facts.key_vault_id,
                )
            if vault_facts.key_vault_uri is None and vault_facts.key_vault_identity_uncertainties:
                facts.extend_key_vault_identity_uncertainties(
                    [f"{vault.address}: {uncertainty}" for uncertainty in vault_facts.key_vault_identity_uncertainties]
                )
            vault_facts.add_key_vault_related_resource_address(resource.address)

    def _merge_access_policies(
        self,
        resources: list[NormalizedResource],
        context: AzureDecorationContext,
    ) -> None:
        for policy_resource in resources:
            if policy_resource.resource_type != AzureResourceType.KEY_VAULT_ACCESS_POLICY:
                continue
            facts = azure_facts(policy_resource)
            vault = context.index.resolve(
                facts.key_vault_reference,
                source=policy_resource,
                resource_types={AzureResourceType.KEY_VAULT},
            )
            if vault is None or vault.resource_type != AzureResourceType.KEY_VAULT:
                facts.add_unresolved_resource_reference("key_vault", facts.key_vault_reference)
                continue
            facts.set_resolved_key_vault_address(vault.address)
            vault_facts = azure_facts(vault)
            vault_facts.add_key_vault_related_resource_address(policy_resource.address)
            for policy in facts.key_vault_access_policies:
                vault_facts.add_key_vault_access_policy(policy)
            vault_facts.extend_key_vault_authorization_uncertainties(
                [
                    f"{policy_resource.address}: {uncertainty}"
                    for uncertainty in facts.key_vault_authorization_uncertainties
                ]
            )

    def _merge_role_assignments(
        self,
        resources: list[NormalizedResource],
        context: AzureDecorationContext,
    ) -> None:
        for role_assignment in resources:
            if role_assignment.resource_type != AzureResourceType.ROLE_ASSIGNMENT:
                continue
            facts = azure_facts(role_assignment)
            vault = context.index.resources_by_address.get(facts.role_assignment_target_resource_address or "")
            if vault is None:
                vault = context.index.resolve(
                    facts.role_assignment_scope,
                    source=role_assignment,
                    resource_types={AzureResourceType.KEY_VAULT},
                )
            if vault is None or vault.resource_type != AzureResourceType.KEY_VAULT:
                if _looks_like_key_vault_reference(facts.role_assignment_scope):
                    facts.add_unresolved_resource_reference("key_vault_scope", facts.role_assignment_scope)
                continue
            facts.set_resolved_key_vault_address(vault.address)
            vault_facts = azure_facts(vault)
            vault_facts.add_key_vault_related_resource_address(role_assignment.address)
            for assignment in facts.key_vault_role_assignments:
                vault_facts.add_key_vault_role_assignment(assignment)
            vault_facts.extend_key_vault_authorization_uncertainties(
                [
                    f"{role_assignment.address}: {uncertainty}"
                    for uncertainty in facts.key_vault_authorization_uncertainties
                ]
            )

    def _derive_network_posture(self, resources: list[NormalizedResource]) -> None:
        for vault in resources:
            if vault.resource_type != AzureResourceType.KEY_VAULT:
                continue
            facts = azure_facts(vault)
            default_action = facts.network_default_action
            reachable = (
                facts.public_network_access_enabled is True
                and default_action is not None
                and default_action.strip().lower() == "allow"
            )
            reasons = []
            if reachable:
                reasons = [
                    "public_network_access_enabled is true",
                    f"effective network default_action is {default_action}",
                ]
            facts.set_public_endpoint_posture(reachable=reachable, reasons=reasons)


def _derive_secret_identity(facts: AzureResourceFacts, vault_uri: str) -> None:
    secret_name = facts.key_vault_secret_name
    if secret_name is None or not _valid_secret_path_segment(secret_name):
        return
    versionless_uri = f"{vault_uri}/secrets/{secret_name}"
    version = facts.key_vault_secret_version
    versioned_uri = f"{versionless_uri}/{version}" if version and _valid_secret_path_segment(version) else None
    facts.set_key_vault_secret_identity(
        versionless_uri=versionless_uri,
        secret_uri=versioned_uri or versionless_uri,
    )


def _derive_key_identity(
    facts: AzureResourceFacts,
    vault_uri: str | None,
    vault_id: str | None,
) -> None:
    key_name = facts.key_vault_key_name
    if key_name is None or not _valid_secret_path_segment(key_name):
        return

    versionless_uri = f"{vault_uri}/keys/{key_name}" if vault_uri is not None else None
    version = facts.key_vault_key_version
    key_uri: str | None = None
    if versionless_uri is not None and version is not None and _valid_secret_path_segment(version):
        key_uri = f"{versionless_uri}/{version}"

    versionless_resource_id, resource_id = _derive_key_resource_ids(vault_id, key_name, version)
    facts.set_key_vault_key_identity(
        versionless_uri=versionless_uri,
        key_uri=key_uri,
        version=version,
        versionless_resource_id=versionless_resource_id,
        resource_id=resource_id,
    )


def _derive_key_resource_ids(
    vault_id: str | None,
    key_name: str,
    version: str | None,
) -> tuple[str | None, str | None]:
    if vault_id is None:
        return None, None
    segments = [segment for segment in vault_id.strip().split("/") if segment]
    if (
        len(segments) != 8
        or segments[0].lower() != "subscriptions"
        or segments[2].lower() != "resourcegroups"
        or segments[4].lower() != "providers"
        or segments[5].lower() != "microsoft.keyvault"
        or segments[6].lower() != "vaults"
        or not all(segments[index] for index in (1, 3, 7))
        or not _valid_secret_path_segment(key_name)
    ):
        return None, None
    versionless_resource_id = "/" + "/".join(segments) + f"/keys/{key_name}"
    if version is None or not _valid_secret_path_segment(version):
        return versionless_resource_id, None
    return versionless_resource_id, f"{versionless_resource_id}/{version}"


def _valid_secret_path_segment(value: str) -> bool:
    return bool(value) and all(character.isalnum() or character == "-" for character in value)


def _looks_like_key_vault_reference(reference: str | None) -> bool:
    if not reference:
        return False
    normalized = reference.strip().lower()
    return normalized.startswith("azurerm_key_vault.") or "/microsoft.keyvault/vaults/" in normalized
