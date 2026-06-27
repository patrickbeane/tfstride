from __future__ import annotations

from collections.abc import Iterable

from tfstride.analysis.finding_helpers import collect_evidence, evidence_item
from tfstride.models import Observation, ResourceInventory
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import (
    AZURE_COMPUTE_RESOURCE_TYPES,
    AZURE_POSTGRESQL_RESOURCE_TYPES,
    AZURE_SQL_RESOURCE_TYPES,
    AzureResourceType,
)

_STORAGE_POSTURE_RESOURCE_TYPES = (
    AzureResourceType.STORAGE_ACCOUNT,
    AzureResourceType.STORAGE_CONTAINER,
)


def observe_azure_posture(inventory: ResourceInventory) -> list[Observation]:
    if inventory.provider != "azure":
        return []
    return [
        *_observe_managed_identity_principals(inventory),
        *observe_azure_storage_uncertainty(inventory),
        *_observe_key_vault_network_posture(inventory),
        *_observe_key_vault_authorization_posture(inventory),
        *_observe_key_vault_recovery_posture(inventory),
        *_observe_mssql_uncertainties(inventory),
        *_observe_mssql_vnet_posture(inventory),
        *_observe_postgresql_uncertainties(inventory),
        *_observe_postgresql_delegated_subnet(inventory),
    ]


def _observe_managed_identity_principals(inventory: ResourceInventory) -> list[Observation]:
    observations: list[Observation] = []
    resource_types = (*AZURE_COMPUTE_RESOURCE_TYPES, AzureResourceType.USER_ASSIGNED_IDENTITY)
    for resource in inventory.by_type(*resource_types):
        facts = azure_facts(resource)
        if facts.identity_type:
            observations.append(
                Observation(
                    title="Azure managed identity principal is modeled",
                    observation_id="azure-managed-identity-principal-observed",
                    category="iam",
                    affected_resources=[resource.address],
                    rationale=(
                        f"{resource.display_name} exposes a `{facts.identity_type}` managed identity principal. "
                        "Role assignments are connected only when principal IDs are known in the Terraform plan."
                    ),
                    evidence=collect_evidence(
                        evidence_item("identity_type", [facts.identity_type]),
                        evidence_item("principal_id", [facts.principal_id] if facts.principal_id else []),
                        evidence_item("client_id", [facts.client_id] if facts.client_id else []),
                        evidence_item("tenant_id", [facts.tenant_id] if facts.tenant_id else []),
                        evidence_item("attached_identity_references", facts.attached_identity_references),
                        evidence_item(
                            "analysis_scope",
                            [
                                "managed identity role assignments are connected when principal IDs are deterministic",
                                "transitive access findings are not emitted from managed identity assignments yet",
                            ],
                        ),
                    ),
                )
            )
        if facts.managed_identity_role_assignments:
            assignments = facts.managed_identity_role_assignments
            observations.append(
                Observation(
                    title="Azure managed identity role assignment is connected",
                    observation_id="azure-managed-identity-role-assignment-observed",
                    category="iam",
                    affected_resources=_dedupe_strings([resource.address, *_record_sources(assignments)]),
                    rationale=(
                        f"{resource.display_name} has Azure role assignments whose `principal_id` matches this "
                        "managed identity. Scope breadth is reported separately from any downstream exposure rule."
                    ),
                    evidence=collect_evidence(
                        evidence_item("role_assignment_sources", _record_sources(assignments)),
                        evidence_item("role_definition_names", _record_values(assignments, "role_definition_name")),
                        evidence_item("role_definition_ids", _record_values(assignments, "role_definition_id")),
                        evidence_item("scopes", _record_values(assignments, "scope")),
                        evidence_item("scope_kinds", _record_values(assignments, "scope_kind")),
                        evidence_item("target_resources", _record_values(assignments, "target_resource_address")),
                        evidence_item("breadth_signals", _record_breadth_signals(assignments)),
                        evidence_item(
                            "analysis_scope",
                            ["identity-to-role connection is modeled without inferring transitive data exposure"],
                        ),
                    ),
                )
            )
        if facts.managed_identity_uncertainties:
            observations.append(
                Observation(
                    title="Azure managed identity principal contains unresolved plan values",
                    observation_id="azure-managed-identity-principal-unknown",
                    category="analysis-uncertainty",
                    affected_resources=[resource.address],
                    rationale=(
                        f"{resource.display_name} has computed managed identity attributes. tfSTRIDE preserves "
                        "the known principal shape without inferring unresolved identifiers or attachments."
                    ),
                    evidence=collect_evidence(
                        evidence_item("unknown_identity_posture", facts.managed_identity_uncertainties),
                    ),
                )
            )
    return observations


def observe_azure_storage_uncertainty(inventory: ResourceInventory) -> list[Observation]:
    if inventory.provider != "azure":
        return []

    observations: list[Observation] = []
    for resource in inventory.by_type(*_STORAGE_POSTURE_RESOURCE_TYPES):
        uncertainties = azure_facts(resource).storage_posture_uncertainties
        if not uncertainties:
            continue
        observations.append(
            Observation(
                title="Azure Storage exposure posture contains unresolved plan values",
                observation_id="azure-storage-exposure-posture-unknown",
                category="analysis-uncertainty",
                affected_resources=[resource.address],
                rationale=(
                    f"{resource.display_name} has computed storage exposure attributes that are not known in "
                    "this Terraform plan. tfSTRIDE does not infer public access from those unresolved values."
                ),
                evidence=collect_evidence(
                    evidence_item("unknown_storage_posture", uncertainties),
                    evidence_item(
                        "analysis_effect",
                        ["public exposure findings are emitted only for known-positive posture signals"],
                    ),
                ),
            )
        )
    return observations


def _observe_key_vault_network_posture(inventory: ResourceInventory) -> list[Observation]:
    observations: list[Observation] = []
    for vault in inventory.by_type(AzureResourceType.KEY_VAULT):
        facts = azure_facts(vault)
        if facts.key_vault_network_uncertainties:
            observations.append(
                Observation(
                    title="Azure Key Vault network posture contains unresolved plan values",
                    observation_id="azure-key-vault-network-posture-unknown",
                    category="analysis-uncertainty",
                    affected_resources=[vault.address],
                    rationale=(
                        f"{vault.display_name} has computed network exposure attributes. tfSTRIDE does not "
                        "infer public reachability from unresolved public-network or ACL values."
                    ),
                    evidence=collect_evidence(
                        evidence_item("unknown_network_posture", facts.key_vault_network_uncertainties),
                    ),
                )
            )
            continue

        default_action = facts.network_default_action
        if facts.public_network_access_enabled is False:
            posture = ["public_network_access_enabled is false"]
        elif default_action is not None and default_action.strip().lower() == "deny":
            posture = [
                "public_network_access_enabled is true",
                f"effective network_acls.default_action is {default_action}",
                *[f"allowed IP rule is {value}" for value in facts.key_vault_network_ip_rules],
                *[f"allowed subnet is {value}" for value in facts.key_vault_network_subnet_ids],
            ]
        else:
            continue
        observations.append(
            Observation(
                title="Azure Key Vault network access is restricted",
                observation_id="azure-key-vault-network-restricted",
                category="data-protection",
                affected_resources=[vault.address],
                rationale=(
                    f"{vault.display_name} is not broadly reachable through its public endpoint. Network "
                    "controls are evaluated separately from the identities authorized to use the vault."
                ),
                evidence=collect_evidence(evidence_item("network_posture", posture)),
            )
        )
    return observations


def _observe_key_vault_authorization_posture(inventory: ResourceInventory) -> list[Observation]:
    observations: list[Observation] = []
    for vault in inventory.by_type(AzureResourceType.KEY_VAULT):
        facts = azure_facts(vault)
        if facts.key_vault_authorization_uncertainties:
            observations.append(
                Observation(
                    title="Azure Key Vault authorization posture contains unresolved plan values",
                    observation_id="azure-key-vault-authorization-posture-unknown",
                    category="analysis-uncertainty",
                    affected_resources=[vault.address],
                    rationale=(
                        f"{vault.display_name} has computed authorization attributes. tfSTRIDE reports only "
                        "known privileged access policies and role assignments."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "unknown_authorization_posture",
                            facts.key_vault_authorization_uncertainties,
                        ),
                    ),
                )
            )
        policies = facts.key_vault_access_policies
        assignments = facts.key_vault_role_assignments
        if not policies and not assignments:
            continue
        authorization_model = "Azure RBAC" if facts.rbac_authorization_enabled is True else "vault access policies"
        observations.append(
            Observation(
                title="Azure Key Vault identity authorization is modeled separately from network access",
                observation_id="azure-key-vault-authorization-model-observed",
                category="iam",
                affected_resources=[vault.address],
                rationale=(
                    f"{vault.display_name} uses {authorization_model}. Network reachability does not imply "
                    "authorization, and privileged grants are evaluated independently."
                ),
                evidence=collect_evidence(
                    evidence_item("authorization_model", [authorization_model]),
                    evidence_item("access_policy_sources", _record_sources(policies)),
                    evidence_item("role_assignment_sources", _record_sources(assignments)),
                ),
            )
        )
    return observations


def _observe_key_vault_recovery_posture(inventory: ResourceInventory) -> list[Observation]:
    observations: list[Observation] = []
    for vault in inventory.by_type(AzureResourceType.KEY_VAULT):
        uncertainties = azure_facts(vault).key_vault_recovery_uncertainties
        if not uncertainties:
            continue
        observations.append(
            Observation(
                title="Azure Key Vault recovery posture contains unresolved plan values",
                observation_id="azure-key-vault-recovery-posture-unknown",
                category="analysis-uncertainty",
                affected_resources=[vault.address],
                rationale=(
                    f"{vault.display_name} has computed recovery attributes. tfSTRIDE does not infer purge "
                    "protection posture from unresolved values."
                ),
                evidence=collect_evidence(evidence_item("unknown_recovery_posture", uncertainties)),
            )
        )
    return observations


def _observe_mssql_uncertainties(inventory: ResourceInventory) -> list[Observation]:
    observations: list[Observation] = []
    for resource in inventory.by_type(*AZURE_SQL_RESOURCE_TYPES):
        uncertainties = azure_facts(resource).mssql_posture_uncertainties
        if not uncertainties:
            continue
        observations.append(
            Observation(
                title="Azure SQL posture contains unresolved plan values",
                observation_id="azure-sql-posture-unknown",
                category="analysis-uncertainty",
                affected_resources=[resource.address],
                rationale=(
                    f"{resource.display_name} has computed SQL posture attributes. tfSTRIDE does not "
                    "infer insecure posture from unresolved values."
                ),
                evidence=collect_evidence(
                    evidence_item("unknown_sql_posture", uncertainties),
                    evidence_item(
                        "analysis_effect",
                        ["posture findings are emitted only for known-positive posture signals"],
                    ),
                ),
            )
        )
    return observations


def _observe_mssql_vnet_posture(inventory: ResourceInventory) -> list[Observation]:
    observations: list[Observation] = []
    for server in inventory.by_type(AzureResourceType.MSSQL_SERVER):
        facts = azure_facts(server)
        vnet_rules = [
            vnet_rule.address
            for vnet_rule in inventory.by_type(AzureResourceType.MSSQL_VIRTUAL_NETWORK_RULE)
            if azure_facts(vnet_rule).mssql_server_id
            and azure_facts(vnet_rule).mssql_server_id == facts.mssql_server_id
        ]
        if not vnet_rules:
            continue
        observations.append(
            Observation(
                title="Azure SQL Database VNet restriction is modeled",
                observation_id="azure-sql-vnet-restricted",
                category="data-protection",
                affected_resources=[server.address, *vnet_rules],
                rationale=(
                    f"{server.display_name} has VNet service endpoint rules that restrict network access. "
                    "VNet rules are evaluated separately from firewall and public network access posture."
                ),
                evidence=collect_evidence(
                    evidence_item("vnet_rules", vnet_rules),
                ),
            )
        )
    return observations


def _observe_postgresql_uncertainties(inventory: ResourceInventory) -> list[Observation]:
    observations: list[Observation] = []
    for resource in inventory.by_type(*AZURE_POSTGRESQL_RESOURCE_TYPES):
        uncertainties = azure_facts(resource).postgresql_posture_uncertainties
        if not uncertainties:
            continue
        observations.append(
            Observation(
                title="Azure PostgreSQL posture contains unresolved plan values",
                observation_id="azure-postgresql-posture-unknown",
                category="analysis-uncertainty",
                affected_resources=[resource.address],
                rationale=(
                    f"{resource.display_name} has computed PostgreSQL posture attributes. tfSTRIDE does not "
                    "infer insecure posture from unresolved values."
                ),
                evidence=collect_evidence(
                    evidence_item("unknown_postgresql_posture", uncertainties),
                    evidence_item(
                        "analysis_effect",
                        ["posture findings are emitted only for known-positive posture signals"],
                    ),
                ),
            )
        )
    return observations


def _observe_postgresql_delegated_subnet(inventory: ResourceInventory) -> list[Observation]:
    observations: list[Observation] = []
    for server in inventory.by_type(AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER):
        facts = azure_facts(server)
        delegated_subnet = facts.postgresql_delegated_subnet_id
        if not delegated_subnet:
            continue
        observations.append(
            Observation(
                title="Azure PostgreSQL Flexible Server delegated subnet is modeled",
                observation_id="azure-postgresql-delegated-subnet-observed",
                category="data-protection",
                affected_resources=[server.address],
                rationale=(
                    f"{server.display_name} uses a delegated subnet for VNet integration. "
                    "Private network posture is evaluated separately from public endpoint and firewall rules."
                ),
                evidence=collect_evidence(
                    evidence_item("delegated_subnet", [delegated_subnet]),
                ),
            )
        )
    return observations


def _record_sources(records: list[dict]) -> list[str]:
    return _record_values(records, "source")


def _record_values(records: list[dict], key: str) -> list[str]:
    return _dedupe_strings(str(record[key]) for record in records if record.get(key))


def _record_breadth_signals(records: list[dict]) -> list[str]:
    return _dedupe_strings(str(signal) for record in records for signal in record.get("breadth_signals", []) if signal)


def _dedupe_strings(values: Iterable[object]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value).strip()
        if text and text not in seen:
            deduped.append(text)
            seen.add(text)
    return deduped
